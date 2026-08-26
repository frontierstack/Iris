"""The upload library: every raw file on disk, across all cases, and attaching a selection to the active case.

Creating a case gives you an empty case — sources are chosen deliberately while investigating. This exposes
what has already been uploaded (including files whose case.json entry was lost) so it can be pulled in without
re-uploading. Attaching copies the bytes into the active case, so each case stays self-contained on disk and
deleting one never strands another.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel

from .. import cases, config, enrich, pool_store
from ..jobs import PROBE_BYTES, REGISTRY, probe_upload
from ..models import Source
from ..store import STORE, pool_headroom_bytes

router = APIRouter(prefix="/library", tags=["library"])

# caseId of a file that belongs to no case yet. Files under config.LIBRARY_DIR carry this instead of a
# real case id; every branch that reads bytes has to check for it before building a case path.
UNATTACHED = ""


class LibraryFile(BaseModel):
    caseId: str          # "" for an unattached file staged in the library
    fileName: str        # the name on disk (<sid>_<sanitized>)
    displayName: str     # the original upload name when we still know it
    size: int
    attached: bool       # already a source of the case it lives in
    inActiveCase: bool   # already ingested into the case you are working on
    uploadedAt: str = ""  # unattached files only
    # Detection metadata, filled at stage time for UNATTACHED files (see jobs.probe_upload) — a bounded
    # sniff of what the file LOOKS like. Staging also parses the file into the workspace pool (it is
    # analysable with no case at all); `sourceId` / `events` report that side.
    parser: str = ""
    confidence: float = 0.0
    state: str = ""       # READY | REVIEW | MAP, the same scale as Source.state
    lines: int = 0        # line/record count; an estimate for files bigger than the probe window
    linesEstimated: bool = False
    sample: str = ""
    # the pool source this staged file was parsed into ("" when it is not in the pool — e.g. an archive,
    # which is only expanded when it is attached to a case)
    sourceId: str = ""
    events: int = 0
    # NOT IN THE POOL = not searchable. The aggregate Case.poolSkipped could not say which file, how big
    # or why, and a file silently absent from search looks exactly like "no matching events".
    skipped: bool = False
    # '' | 'budget' (the pool memory cap) | 'unreadable' (bytes unreachable on disk)
    # | 'parse-error' (the parser failed — a different problem with a different fix)
    # | 'not-parsed' (a container Iris only expands when it is attached to a case)
    skipReason: str = ""
    skipDetail: str = ""     # one sentence naming the remedy
    budgetBytes: int = 0     # the pool budget in force, for 'budget' skips (bytes of source log)
    # Two-phase ingest (app/enrich.py). The Sources TABLE is built from this model, not from
    # Case.librarySources, so without this field every row read as 'enriched' and the analyst could not
    # see what was still being interpreted — which is the whole point of the per-row chip. A file with no
    # pool source yet (an unexpanded archive) has no enrich state to report and stays ''.
    enrich: str = ""         # '' | raw | queued | enriching | enriched | skipped | error
    enrichError: str = ""
    enrichedAt: str = ""


# ONE writer at a time for library/index.json. Four upload lanes stage files concurrently and
# GET /api/library rewrites the index too (it sniffs any staged file that has no `parser` entry yet),
# and every one of them used to do read -> modify -> write with no lock and ONE shared `.tmp` name.
# Two things went wrong at once: entries were silently lost (the last writer's stale copy won, so a
# freshly staged file lost its original name), and on Windows `tmp.replace()` raises PermissionError
# while another thread still has the .tmp open for writing or index.json open for reading — which
# surfaced as `POST /api/library/upload` answering 500 mid-drop. RLock: `_update_library_index`
# calls `_write_library_index` while holding it.
_INDEX_LOCK = threading.RLock()


def _library_index() -> dict[str, dict]:
    """on-disk name -> {file, size, uploadedAt}. Without it the original filename is only recoverable
    by stripping the sid prefix, which loses anything the sanitizer replaced."""
    with _INDEX_LOCK:
        try:
            data = json.loads(config.LIBRARY_INDEX.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
    return data if isinstance(data, dict) else {}


def _write_library_index(idx: dict[str, dict]) -> None:
    invalidate_library_cache()
    with _INDEX_LOCK:
        config.LIBRARY_DIR.mkdir(parents=True, exist_ok=True)
        # a PRIVATE tmp name: a shared one is a second file two writers could hold open at once
        tmp = config.LIBRARY_INDEX.with_name(f".index-{uuid.uuid4().hex[:8]}.tmp")
        tmp.write_text(json.dumps(idx, indent=2), encoding="utf-8")
        # Windows refuses to replace a file another handle has open. Readers of index.json are
        # under the same lock, but an indexer / antivirus / backup agent can hold it for a moment,
        # so retry briefly before giving up rather than failing an upload that already parsed.
        delay = 0.02
        for attempt in range(8):
            try:
                tmp.replace(config.LIBRARY_INDEX)
                break
            except PermissionError:
                if attempt == 7:
                    tmp.unlink(missing_ok=True)
                    raise
                time.sleep(delay)
                delay = min(delay * 2, 0.5)


def _update_library_index(mutate) -> dict[str, dict]:
    """Read -> `mutate(idx)` -> write, atomically with respect to every other writer.

    `mutate` returns True when it changed something; a no-op costs a read and nothing else. Callers
    must NOT hold an `idx` read earlier across this — the point is that the copy being written is the
    one on disk right now, so a concurrent lane's entry is never overwritten with a stale snapshot.
    """
    with _INDEX_LOCK:
        idx = _library_index()
        if mutate(idx):
            _write_library_index(idx)
        return idx


def library_entries() -> list[tuple[str, str]]:
    """[(on-disk name, original upload name)] for every staged file, index order first.

    store.restore_library() reads this on startup to rebuild the case-less pool, so the order is what
    decides ingest order — the index is written in staging order and preserves it.
    """
    idx = _library_index()
    try:
        on_disk = {p.name for p in config.LIBRARY_DIR.iterdir()
                   if p.is_file() and p.name != config.LIBRARY_INDEX.name}
    except OSError:
        return []
    out = [(name, str((idx.get(name) or {}).get("file") or _display_name(name, {})))
           for name in idx if name in on_disk]
    out += [(name, _display_name(name, {})) for name in sorted(on_disk - set(idx))]
    return out


def forget_staged(file_name: str) -> None:
    """Drop a staged file's index entry (the bytes are removed by the caller)."""
    _update_library_index(lambda idx: idx.pop(Path(file_name).name, None) is not None)
    invalidate_library_cache()
    # The parsed-pool cache is keyed on this file; leaving it behind would keep a copy of the events
    # of a file the analyst removed, and the entry could never be reached again to be invalidated.
    pool_store.forget(Path(file_name).name)


def _library_path(file_name: str) -> Path:
    """Resolve a library file name, refusing anything that escapes LIBRARY_DIR.

    A ':' is refused outright: on NTFS `report.log:hidden` names an ALTERNATE DATA STREAM of a real
    file, and that form passes both the basename check and the resolved-parent check — the parent of
    `library/report.log:hidden` is still `library/`. It stays confined to LIBRARY_DIR either way, but
    a name that reads and writes a stream of another file is not a library file, and no legitimate
    upload needs one (':' is not a valid character in a Windows file name to begin with).
    """
    if ":" in str(file_name):
        raise HTTPException(400, "invalid file name")
    p = config.LIBRARY_DIR / Path(file_name).name
    root = config.LIBRARY_DIR.resolve()
    try:
        if p.resolve().parent != root:
            raise HTTPException(400, "invalid file name")
    except OSError:
        raise HTTPException(400, "invalid file name")
    return p


class AttachItem(BaseModel):
    caseId: str
    fileName: str


class AttachBody(BaseModel):
    items: list[AttachItem]
    # Which case to file them into. Blank = the active one (what every existing caller means). Naming a
    # case ACTIVATES it first: the store holds exactly one case in memory, so "attach into that case"
    # and "work on that case" are the same operation — pretending otherwise would need a second,
    # half-loaded case and two answers to "what is in this case".
    targetCaseId: str = ""


def _display_name(file_name: str, known: dict[str, str]) -> str:
    if file_name in known:
        return known[file_name]
    # uploads are stored as "<8-hex sid>_<sanitized original>"; strip the prefix for display
    head, sep, tail = file_name.partition("_")
    return tail if sep and len(head) == 8 else file_name


# The listing is a directory walk plus a stat per file. On the host that is ~1 ms; through the Docker
# bind mount on Windows it measured 0.8-1.6 s EVERY time, and the Sources page asks for it on every
# mount and every invalidation — which is what "the Sources page is slow" actually was. The answer is a
# short-lived memo, not a faster walk: the underlying facts change only when Iris itself writes (stage,
# attach, detach, delete, load-anyway) or when the pool version moves, and both are announced here.
#
# That memo is one of TWO. It caps the WHOLE listing at one build per LIB_TTL; `_dir_files` below caps
# the DIRECTORY WALK — the expensive half by three orders of magnitude — at one per actual change on
# disk. Both are needed: the row memo alone still paid a full walk on every version bump, and phase-2
# enrichment bumps the version once per source it finishes, for hours.
_LIB_LOCK = threading.Lock()
_LIB_CACHE: dict[str, Any] = {"key": None, "rows": [], "at": 0.0}
LIB_TTL = 2.0          # seconds: long enough to absorb a burst of polls, short enough to feel live

# Bumped by invalidate_library_cache(). The DIRECTORY memo below keys on it as well as on the
# directory's own mtime, so an Iris-side write is never waited out.
_LIB_GEN = 0
_WALK_LOCK = threading.Lock()
_WALK_CACHE: dict[str, dict[str, Any]] = {}   # str(dir) -> {gen, stamp, at, files}
WALK_TTL = 30.0        # seconds: a backstop only — the mtime stamp is what actually decides
WALK_SETTLE = 2.0      # seconds a directory must be unchanged before its mtime is trusted (see _dir_files)


def invalidate_library_cache() -> None:
    """Drop the memo. Called by every path in Iris that changes what the listing would say."""
    global _LIB_GEN
    with _LIB_LOCK:
        _LIB_CACHE["key"] = None
        _LIB_CACHE["at"] = 0.0
        _LIB_GEN += 1


def _dir_files(d: Path, skip: str = "") -> list[tuple[str, int]]:
    """`[(name, size)]` for every FILE directly in `d`, sorted — memoised on the directory's mtime.

    This is the single most expensive thing the Sources page asks for, and it is expensive for a
    reason that is not "the disk is slow":

      * `Path.iterdir()` + `p.is_file()` + `p.stat()` is TWO stat calls per entry. On the analyst's
        681-file library that is ~1,362 filesystem syscalls per listing, measured at **1.45 s inside
        the running container while it was otherwise idle** (`json.loads` of the 900 kB library index,
        by comparison, is 12 ms).
      * Every one of those syscalls releases the GIL, and phase-2 enrichment, the detection pass and
        the search-index warm are all CPU-bound *pure Python* threads. So each syscall then has to win
        the GIL back against them, at up to one switch interval apiece. That is the amplification:
        measured on the analyst's 11.4 M-event pool with enrichment running, `/api/library` took
        21-69 s while `/api/case` — which takes the same STORE.lock — answered in 0.9 s. The store
        lock was never the dominant term; the syscalls were.

    So: stop making them. One `os.stat` of the DIRECTORY replaces all of them. A directory's mtime
    moves whenever an entry is created, removed or renamed in it, which is the only thing that can
    change this answer — a staged file's bytes are written once and never appended to. `_LIB_GEN`
    covers the Iris-side writes that announce themselves, and WALK_TTL is a backstop in case some
    filesystem somewhere does not update a directory mtime the way POSIX and NTFS both do.

    `os.scandir` rather than `iterdir` for the rebuild: `is_file()` is answered from the directory
    entry, so a rebuild costs ONE stat per file instead of two.

    The returned list is shared with the memo — callers iterate it, never mutate it.
    """
    key = str(d)
    try:
        st = os.stat(d)
        stamp = (st.st_mtime_ns, st.st_size, getattr(st, "st_ino", 0))
    except OSError:
        with _WALK_LOCK:
            _WALK_CACHE.pop(key, None)
        return []
    now = time.monotonic()
    # A directory mtime cannot resolve two changes inside its own granularity, and that granularity is
    # not always sub-microsecond (Windows lazily stamps from a clock that ticks every ~15 ms). So the
    # stamp is only trusted once the directory has been QUIET for WALK_SETTLE seconds; a directory that
    # was just written to is re-walked. The analyst's library has not changed in hours — it always
    # hits — and a test that stages a file and immediately lists never can.
    hot = (time.time() - st.st_mtime) < WALK_SETTLE
    with _LIB_LOCK:
        gen = _LIB_GEN
    with _WALK_LOCK:
        hit = _WALK_CACHE.get(key)
        if (hit is not None and not hot and hit["gen"] == gen and hit["stamp"] == stamp
                and now - hit["at"] < WALK_TTL):
            return hit["files"]
    files: list[tuple[str, int]] = []
    try:
        with os.scandir(d) as it:
            for e in it:
                if skip and e.name == skip:
                    continue
                try:
                    if not e.is_file():
                        continue
                    files.append((e.name, e.stat().st_size))
                except OSError:
                    continue
    except OSError:
        with _WALK_LOCK:
            _WALK_CACHE.pop(key, None)
        return []
    files.sort()
    with _WALK_LOCK:
        _WALK_CACHE[key] = {"gen": gen, "stamp": stamp, "at": now, "files": files}
    return files


def _store_view() -> dict[str, Any]:
    """Everything the listing needs from the store, in ONE short critical section.

    It used to be two, interleaved with the directory walk — so a listing waited on `STORE.lock`
    twice, once on each side of a walk that could itself run for tens of seconds, while phase-2
    enrichment swapped an 11.4 M-event pool. Nothing here touches the filesystem: it is ~680
    dict lookups, and the lock is released before a single byte is read from disk.
    """
    # The ACTIVE CASE's own sources — not the whole pool. Every staged library file is also a pool
    # source, so taking the names from STORE.sources marked all of them "already in this case": the
    # Add-sources drawer then said "every uploaded file is already in this case" and offered nothing,
    # which is both wrong and exactly the impression that a new case had swallowed the workspace.
    with STORE.lock:
        active_files = {STORE.sources[s].file for s in STORE.case_source_ids() if s in STORE.sources}
        # What the ACTIVE case's files actually parsed into, keyed by the name on disk. A case upload is
        # a pool source like any other, but these rows reported parser='' state='' events=0 — so a
        # perfectly parsed 62,798-event browser history read as "not parsed" everywhere this list is
        # shown. The path is the only link between the file on disk and the source it produced.
        parsed_by_path: dict[str, Any] = {}
        for sid, path in STORE.source_paths.items():
            src = STORE.sources.get(sid)
            if src is None or path is None:
                continue
            row = parsed_by_path.setdefault(Path(path).name, {"events": 0, "src": src})
            row["events"] += src.events
            # a container expands into several sources; report the first one's parser and the worst state
            if row["src"].state == "READY" and src.state != "READY":
                row["src"] = src
        # staged files and the pool sources they produced — a staged file is parsed into the workspace
        # whether or not any case exists
        pool: dict[str, list] = {}
        linked: set[str] = set()
        for sid, lib in STORE.source_library.items():
            if sid in STORE.sources:
                pool.setdefault(lib, []).append(STORE.sources[sid])
                if STORE.source_origin.get(sid) == "case":
                    linked.add(lib)
        return {"active_files": active_files, "parsed_by_path": parsed_by_path, "pool": pool,
                "linked": linked, "skips": dict(STORE.pool_skips), "loading": STORE.pool_loading}


@router.get("", response_model=list[LibraryFile])
def list_library() -> list[LibraryFile]:
    # Served from the memo for LIB_TTL regardless of the store version. During a library load the
    # version moves with every file, so keying strictly on it made the memo miss on every poll — the
    # Sources page paid the 0.8 s bind-mount walk continuously for the whole load. What the version
    # changes here (per-file event counts, states) is at most LIB_TTL stale, which is what a memo means;
    # anything that changes the SET of files goes through invalidate_library_cache() and misses at once.
    now = time.monotonic()
    rest = (STORE.case_id, STORE.pool_loading, len(STORE.sources))
    key = (STORE.version,) + rest
    # PHASE 2 does exactly what a library load does: one version bump per source it finishes, changing
    # nothing here but that source's events/state/enrich. Keying strictly on the version made the memo
    # miss on EVERY poll for the whole of a 680-source enrichment run — the same bug this comment
    # already described for the load, re-appearing for enrichment.
    drifting = STORE.pool_loading or enrich.QUEUE.working()
    with _LIB_LOCK:
        cached = _LIB_CACHE["key"]
        fresh = now - float(_LIB_CACHE["at"]) < LIB_TTL and cached is not None
        # Exact key match: nothing moved. Only the VERSION is allowed to drift, and only while a
        # background load or phase-2 enrichment is in flight, where it moves per file and only
        # per-file counts change. Outside those a version change can mean an attach/detach/load-anyway
        # that changes what the rows SAY, and those must miss at once (three tests pin exactly that);
        # the case id and the source count are never tolerated, because switching case rewrites
        # `inActiveCase` on every row.
        if fresh and (cached == key or (drifting and cached[1:] == rest)):
            return list(_LIB_CACHE["rows"])
    rows = _build_library_listing()
    with _LIB_LOCK:
        _LIB_CACHE.update(key=key, rows=rows, at=time.monotonic())
    return list(rows)


def _build_library_listing() -> list[LibraryFile]:
    out: list[LibraryFile] = []
    view = _store_view()
    active_files: set[str] = view["active_files"]
    parsed_by_path: dict[str, Any] = view["parsed_by_path"]
    pool: dict[str, list] = view["pool"]
    # staged files already linked into a case — on disk (case.json) as well as in the pool
    linked: set[str] = set(view["linked"])
    skips = view["skips"]
    loading = view["loading"]
    for cid in cases.case_ids():
        meta = cases._read_meta(cid)
        # on-disk name -> original upload name, for entries the case still knows about
        known: dict[str, str] = {}
        for s in meta.get("sources", []) or []:
            raw = str(s.get("path") or "")
            base = raw.replace("\\", "/").rsplit("/", 1)[-1]
            if base:
                known[base] = str(s.get("file") or base)
            # one pass over case.json, not two: this loop used to run a second time further down
            if isinstance(s, dict) and s.get("library"):
                linked.add(str(s["library"]))
        for name, size in _dir_files(config.upload_dir(cid)):
            display = _display_name(name, known)
            hit = parsed_by_path.get(name)
            src = hit["src"] if hit else None
            out.append(LibraryFile(caseId=cid, fileName=name, displayName=display, size=size,
                                   attached=name in known, inActiveCase=display in active_files,
                                   parser=src.parser if src else "", confidence=src.confidence if src else 0.0,
                                   state=src.state if src else "", sample=src.sample if src else "",
                                   sourceId=src.id if src else "", events=int(hit["events"]) if hit else 0,
                                   skipped=bool(src and src.state == "ERROR"),
                                   skipReason="parse-error" if src and src.state == "ERROR" else "",
                                   skipDetail=(src.error or "") if src and src.state == "ERROR" else "",
                                   enrich=getattr(src, "enrich", "") if src else "",
                                   enrichError=(getattr(src, "enrichError", "") or "") if src else "",
                                   enrichedAt=(getattr(src, "enrichedAt", "") or "") if src else ""))
    # unattached files staged in the library — these belong to no case and survive every case delete
    idx = _library_index()
    staged = _dir_files(config.LIBRARY_DIR, skip=config.LIBRARY_INDEX.name)
    dirty = False
    for name, size in staged:
        meta = idx.get(name) or {}
        display = str(meta.get("file") or _display_name(name, {}))
        if "parser" not in meta:
            # staged before detection existed (or by an older build) — sniff it once and cache the answer
            probe = _probe_file(config.LIBRARY_DIR / name, display, size)
            if probe:
                meta = {**meta, **probe}
                idx[name] = meta
                dirty = True
        srcs = pool.get(name) or []
        reason, detail, budget = _skip_state(name, display, size, srcs, skips.get(name), loading)
        out.append(LibraryFile(caseId=UNATTACHED, fileName=name, displayName=display, size=size,
                               attached=name in linked,
                               inActiveCase=any(s.origin == "case" for s in srcs) or display in active_files,
                               uploadedAt=str(meta.get("uploadedAt") or ""),
                               parser=str(meta.get("parser") or ""), confidence=float(meta.get("confidence") or 0.0),
                               state=str(meta.get("state") or ""), lines=int(meta.get("lines") or 0),
                               linesEstimated=bool(meta.get("linesEstimated")), sample=str(meta.get("sample") or ""),
                               sourceId=srcs[0].id if srcs else "", events=sum(s.events for s in srcs),
                               skipped=bool(reason), skipReason=reason, skipDetail=detail, budgetBytes=budget,
                               enrich=_worst_enrich(srcs),
                               enrichError=next((getattr(s, "enrichError", "") or "" for s in srcs
                                                 if getattr(s, "enrich", "") == "error"), ""),
                               enrichedAt=(getattr(srcs[0], "enrichedAt", "") or "") if srcs else ""))
    if dirty:
        # Merge, do not overwrite: an upload lane may have indexed a file since `idx` was read, and
        # its entry (original name, upload time) must survive this write. Only names that STILL have
        # no parser take the sniff made above.
        probed = {name: meta for name, meta in idx.items() if "parser" in meta}

        def _merge(live: dict[str, dict]) -> bool:
            changed = False
            for name, meta in probed.items():
                cur = live.get(name) or {}
                if "parser" not in cur:
                    live[name] = {**cur, **meta}
                    changed = True
            return changed
        try:
            _update_library_index(_merge)
        except OSError as exc:
            print(f"[iris] library index not updated: {config.safe_os_error(exc)}", flush=True)
    return out


# Least-finished first: one staged container can expand into several pool sources, and a row that says
# 'enriched' while one of its sources is still raw is exactly the silent-omission lie the per-row chip
# exists to prevent. 'error' outranks everything — a failure the analyst cannot see is not a report.
_ENRICH_RANK = ("error", "enriching", "queued", "raw", "skipped", "enriched")


def _worst_enrich(srcs: list) -> str:
    states = {getattr(s, "enrich", "") for s in srcs} - {""}
    if not states:
        return ""
    for state in _ENRICH_RANK:
        if state in states:
            return state
    return ""


def _skip_state(name: str, display: str, size: int, srcs: list, skip, loading: bool) -> tuple[str, str, int]:
    """Why this staged file's events are (or are not) in the pool → (reason, detail, budgetBytes).

    The three cases must never be conflated — they have three different fixes:
      * budget / unreadable  — the file was never parsed; STORE.pool_skips holds the record and the numbers.
      * parse-error          — the file WAS parsed and the parser failed. It is a real pool source in state
                               ERROR carrying the parser's own message; raising IRIS_POOL_MAX_MB fixes nothing.
      * not-parsed           — a container Iris only expands when it is attached to a case.
    """
    if skip is not None:
        return skip.reason, skip.detail, skip.budgetBytes
    errored = [s for s in srcs if s.state == "ERROR"]
    if errored and len(errored) == len(srcs):
        return "parse-error", (errored[0].error or "the parser failed on this file"), 0
    if srcs or loading:
        # loading: it is queued for this pass, so "not in the pool" is temporary, not a skip
        return "", "", 0
    return ("not-parsed",
            "staged but not parsed into the workspace: Iris only expands this container when it is "
            "attached to a case, so its contents are not searchable yet", 0)


def _probe_file(path: Path, display: str, size: int) -> dict:
    """Sniff a staged file from disk, reading at most PROBE_BYTES of it."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(PROBE_BYTES)
    except OSError:
        return {}
    return probe_upload(display, head, total_size=size)


# How much of an upload is moved at a time. The bytes are already on disk by the time a handler runs
# (Starlette spools the multipart body), so this copy is disk-to-disk — but `await f.read()` turned it
# into a full RAM copy on top, and a 3.35 GB capture bundle is 3.6 GB of allocation on a VM that
# segfaults under exactly that pressure.
UPLOAD_CHUNK = 4 * 1024 * 1024


async def _spool(f: UploadFile, dest: Path) -> int:
    """Copy an upload to `dest` a chunk at a time. Returns the bytes written.

    Both halves go off the event loop: the write is a bind-mount write on Windows (measured in seconds,
    not milliseconds) and `UploadFile.read` on a spooled file is a blocking disk read behind an async
    signature. An `async def` route that does either inline stalls every other request in the process —
    that is the whole lesson of `tests/test_upload_does_not_block.py`.
    """
    total = 0
    with open(dest, "wb") as out:
        while True:
            chunk = await f.read(UPLOAD_CHUNK)
            if not chunk:
                break
            await asyncio.to_thread(out.write, chunk)
            total += len(chunk)
    return total


async def stage_files(files: list[UploadFile], job_ids: list[str] | None = None) -> list[LibraryFile]:
    """Write uploads into LIBRARY_DIR, register them in the library index, and PARSE them into the pool.

    Shared with POST /api/sources, which stages when there is no active case: an upload must never invent
    one. It writes only to LIBRARY_DIR + its index and never to cases/ — no case directory is created and
    a pending case stays pending — but the events are real: search, timeline, detections, the graph and
    IOC extraction all work on a staged file with zero cases on disk.

    `job_ids` (positional against `files`) ties each file to a job registered with POST /api/jobs so the
    upload is visible from any tab; missing ids are created here.
    """
    if not files:
        raise HTTPException(400, "no files uploaded")
    from .jobs import resolve_job  # local import: routers.jobs imports the store, this module is imported by it

    config.LIBRARY_DIR.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ids = list(job_ids or [])
    out: list[LibraryFile] = []
    for i, f in enumerate(files):
        original = f.filename or "upload.log"
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", Path(original).name) or "upload.log"
        name = f"{uuid.uuid4().hex[:8]}_{safe}"
        dest = config.LIBRARY_DIR / name
        jid = resolve_job(ids[i] if i < len(ids) else None, original, 0, "library", UNATTACHED)
        # EVERYTHING below is blocking work — a write through the Docker bind mount, a sniff, and then
        # the PARSE, which for anything under SYNC_LIMIT (50 MB) runs inline. This handler is
        # `async def`, so doing that here ran it ON THE EVENT LOOP: every other request in the process,
        # `/api/health` included, froze until the parse finished. Measured: 17.6 s on one 44 MB file.
        # That was "the whole app locks up when ingesting". A thread is the whole fix.
        try:
            size = await _spool(f, dest)
        except OSError as exc:
            dest.unlink(missing_ok=True)
            REGISTRY.fail(jid, f"could not write the file ({config.safe_os_error(exc)})")
            raise HTTPException(500, f"could not store {original}: {config.safe_os_error(exc)}")
        REGISTRY.begin_parse(jid, size)
        # Sniff from DISK and from a bounded prefix. `probe_upload` only ever looks at the first
        # PROBE_BYTES anyway; handing it the whole file was the last place a gigabyte was materialised
        # just to read its first two megabytes.
        try:
            probe = await asyncio.to_thread(_probe_file, dest, original, size)
        except Exception as exc:  # noqa: BLE001 — a sniff must never cost the upload
            print(f"[iris] probe of {original!r} failed: {type(exc).__name__}: {exc}", flush=True)
            probe = {}
        # Index it NOW, under the index lock, on the copy that is on disk at this moment. It used to
        # be written at the end of the request from an `idx` read at the start: with four lanes in
        # flight the last one to finish overwrote everyone else's entries, and GET /api/library —
        # seeing a staged file with no entry — sniffed it again and raced the same file. A failed
        # index write is logged, never a failed upload: the bytes are staged and the parse below
        # still happens; the listing falls back to the name on disk.
        entry = {"file": original, "size": size, "uploadedAt": now, **probe}
        try:
            await asyncio.to_thread(_update_library_index, lambda idx: idx.__setitem__(name, entry) or True)
        except OSError as exc:
            print(f"[iris] library index not updated for {original}: {config.safe_os_error(exc)}", flush=True)
        # Parse it into the workspace pool. This is the one thing staging must do WITHOUT touching a
        # case: add_library_file never calls _materialise(), so nothing is written under cases/.
        # No bytes are passed: they are on disk, and the store streams them from there.
        from .sources import _ingest_reason, _report  # local import: sources imports this module
        try:
            srcs = await asyncio.to_thread(STORE.add_library_file, name, original)
        except Exception as exc:  # noqa: BLE001
            # The job carries the file's name and the reason, and the response carries the SAME
            # sentence. Before this the exception escaped as a bare 500: the registry never heard,
            # so the row sat at "parsing" forever and the tab was told "500 Internal Server Error".
            reason = _ingest_reason(exc)
            REGISTRY.fail(jid, reason)
            print(f"[iris] ingest of {original!r} failed: {reason}", flush=True)
            _update_library_index(lambda idx: idx.pop(name, None) is not None)
            dest.unlink(missing_ok=True)
            raise HTTPException(500, f"{original}: {reason}")
        if srcs:
            _report(jid, srcs)            # a >50 MB file is still PARSING in a thread — jobs.sync() finishes it
        else:
            # a container Iris refuses to expand is staged unparsed; the sniff is all we can report
            REGISTRY.finish(jid, parser=str(probe.get("parser") or ""), events=0,
                            confidence=float(probe.get("confidence") or 0.0))
        out.append(LibraryFile(caseId=UNATTACHED, fileName=name, displayName=original, size=size,
                               attached=False, inActiveCase=False, uploadedAt=now,
                               parser=str(probe.get("parser") or ""), confidence=float(probe.get("confidence") or 0.0),
                               state=str(probe.get("state") or ""), lines=int(probe.get("lines") or 0),
                               linesEstimated=bool(probe.get("linesEstimated")), sample=str(probe.get("sample") or ""),
                               sourceId=srcs[0].id if srcs else "", events=sum(s.events for s in srcs)))
    return out


@router.post("/upload", response_model=list[LibraryFile])
async def upload_unattached(files: list[UploadFile] = File(...), jobIds: str = "") -> list[LibraryFile]:
    """Stage logs that belong to no case yet.

    Deliberately does NOT touch STORE: it never ingests, never parses and never materialises a pending
    case, so it works with no case at all. Attach them to a case later with POST /api/library/attach,
    which is where parsing happens. The bytes live outside CASES_DIR, so deleting cases never removes them.
    """
    return await stage_files(files, job_ids=[j.strip() for j in (jobIds or "").split(",") if j.strip()])


@router.delete("/unattached/{file_name}")
def delete_unattached(file_name: str) -> dict:
    """Discard a staged file. Only ever touches LIBRARY_DIR — case uploads are deleted with their case."""
    p = _library_path(file_name)
    if not p.is_file():
        raise HTTPException(404, f"{file_name} is not in the library")
    # the staged file is also a source in the pool — drop its events too, or search would keep hitting a
    # file that no longer exists (delete_file=False: the bytes are removed here, once)
    with STORE.lock:
        sids = [s for s, lib in STORE.source_library.items()
                if lib == p.name and STORE.source_origin.get(s) == "library"]
    # ONE pass over the pool for the whole container, not one per member: each removal rebuilds the
    # event list, the id index and the timestamp array, which is O(pool) however few events go.
    STORE.delete_sources(sids, delete_file=False)
    p.unlink(missing_ok=True)
    forget_staged(p.name)
    STORE.clear_pool_skip(p.name)  # a file that no longer exists is not "missing from search" any more
    return {"ok": True}


@router.post("/unattached/{file_name}/load", response_model=LibraryFile)
def load_unattached(file_name: str) -> LibraryFile:
    """Load a skipped staged file into the workspace pool ANYWAY, budget or not.

    The budget is a per-machine guess (40 % of RAM ÷ 50); the file it skipped may be exactly the evidence
    the analyst needs, and "attach it to a case" is not an answer when the reason it was skipped is memory.
    So the escape hatch exists — but it is checked against live free memory first (`pool_headroom_bytes`),
    because an OOM kill would take every OTHER loaded source down with it. A refusal says how much the file
    needs and how much there is, and the file stays listed, staged and skipped rather than half-loaded.
    """
    p = _library_path(file_name)
    if not p.is_file():
        raise HTTPException(404, f"{file_name} is not in the library")
    with STORE.lock:
        already = [s for s, lib in STORE.source_library.items() if lib == p.name and s in STORE.sources]
    if already:
        return _entry(p.name)
    size = p.stat().st_size
    headroom = pool_headroom_bytes()
    if headroom and size > headroom:
        # NOT a refusal. Uploaded evidence becomes searchable — that is the contract, and a file the
        # analyst explicitly asked to load is the least ambiguous case of it. Say what it is likely to
        # cost, in the log, and load it.
        # The ratio is MEASURED on the events already in this workspace, not a global constant: the old
        # constant told the analyst a 1149 MB file needed 57.5 GB when it needed a quarter of that, and
        # a number that wrong is worse than no number. When there is nothing loaded to measure yet, the
        # line says so rather than presenting the fallback as a measurement.
        ratio, measured = STORE.pool_bytes_per_source_byte()
        how = (f"at the {ratio:.1f}x measured on this workspace's own logs" if measured
               else f"at a default {ratio:.0f}x — nothing is loaded yet to measure against")
        print(f"[iris] loading {p.name} ({size / 1e6:.0f} MB of log) may need about "
              f"{size * ratio / 1e9:.1f} GB of RAM ({how}); about "
              f"{headroom * ratio / 1e9:.1f} GB looks free.")
    display = str((_library_index().get(p.name) or {}).get("file") or _display_name(p.name, {}))
    try:
        STORE.load_pool_file(p.name, display)
    except OSError as exc:
        STORE.note_pool_skip(p.name, display, size, "unreadable", f"could not be read from disk ({config.safe_os_error(exc)})")
        raise HTTPException(500, f"could not read {file_name}: {config.safe_os_error(exc)}")
    except Exception as exc:  # a parser that blows up must not leave the file looking loaded
        raise HTTPException(500, f"{file_name} could not be parsed: {type(exc).__name__}: {exc}")
    # the row for this file now says something different (skipped -> in the pool) — see attach()
    invalidate_library_cache()
    return _entry(p.name)


def _entry(name: str) -> LibraryFile:
    """The freshly listed library row for one staged file (404 if it vanished under us)."""
    for f in list_library():
        if f.caseId == UNATTACHED and f.fileName == name:
            return f
    raise HTTPException(404, f"{name} is not in the library")


class PruneItem(BaseModel):
    caseId: str
    fileName: str
    displayName: str
    size: int
    reason: str


class PruneResult(BaseModel):
    files: list[PruneItem]
    bytes: int
    emptyCaseDirs: list[str]
    deleted: bool


def _orphans() -> tuple[list[PruneItem], list[str]]:
    """Upload files no case.json references, plus case folders with nothing in them.

    These accumulate when a case is reset or re-ingested: the bytes stay on disk but nothing points at
    them any more. They are invisible to the app except through the library, and they still count
    toward the case size on the Cases page.
    """
    items: list[PruneItem] = []
    empty_dirs: list[str] = []
    for cid in cases.case_ids():
        meta = cases._read_meta(cid)
        referenced = set()
        for s in meta.get("sources", []) or []:
            base = str(s.get("path") or "").replace("\\", "/").rsplit("/", 1)[-1]
            if base:
                referenced.add(base)
        up = config.upload_dir(cid)
        try:
            entries = sorted(p for p in up.iterdir() if p.is_file())
        except OSError:
            entries = []
        for p in entries:
            if p.name in referenced:
                continue
            try:
                size = p.stat().st_size
            except OSError:
                size = 0
            items.append(PruneItem(caseId=cid, fileName=p.name, displayName=_display_name(p.name, {}),
                                   size=size, reason="not referenced by this case"))
        # a case folder with no case.json AND no uploads is leftover scaffolding
        if not config.case_path(cid).is_file() and not entries:
            empty_dirs.append(cid)
    return items, empty_dirs


@router.get("/prune", response_model=PruneResult)
def preview_prune() -> PruneResult:
    """Dry run — what cleanup WOULD remove. Nothing is touched."""
    items, empty = _orphans()
    return PruneResult(files=items, bytes=sum(i.size for i in items), emptyCaseDirs=empty, deleted=False)


@router.post("/prune", response_model=PruneResult)
def prune(confirm: bool = False) -> PruneResult:
    """Delete unreferenced uploads and empty case folders. Requires ?confirm=true — this is irreversible."""
    items, empty = _orphans()
    if not confirm:
        raise HTTPException(400, "pass confirm=true to actually delete; GET /api/library/prune previews it")
    freed = 0
    for i in items:
        p = config.upload_dir(i.caseId) / Path(i.fileName).name
        # never follow a name out of its own case directory
        if p.resolve().parent != config.upload_dir(i.caseId).resolve():
            continue
        try:
            p.unlink(missing_ok=True)
            freed += i.size
        except OSError:
            pass
    for cid in empty:
        if cid == STORE.case_id:
            continue  # never remove the folder of the case currently loaded
        shutil.rmtree(config.case_dir(cid), ignore_errors=True)
    invalidate_library_cache()   # files left the listing and nothing bumps the store version
    return PruneResult(files=items, bytes=freed, emptyCaseDirs=empty, deleted=True)


@router.post("/attach", response_model=list[Source])
def attach(body: AttachBody) -> list[Source]:
    """Ingest already-uploaded files into a case — the active one, or `targetCaseId`.

    The picker exists because "add this log to a case" with no way to say WHICH case is only usable when
    you already happen to be on the right one. Naming a case switches to it (see AttachBody.targetCaseId)
    and the response is that case's sources.
    """
    if not body.items:
        raise HTTPException(400, "no files selected")
    target = (body.targetCaseId or "").strip()
    if target and target != STORE.case_id:
        if target not in cases.case_ids():
            raise HTTPException(404, f"no such case: {target}")
        cases.activate(target)
    elif STORE.pending:
        raise HTTPException(409, "there is no active case to file these into — create one first, or name "
                                 "an existing case with targetCaseId")
    added: list[Source] = []
    for item in body.items:
        if item.caseId == UNATTACHED:
            # Staged in the library, belonging to no case — and ALREADY PARSED into the pool. Attaching
            # MOVES that source into the case: same source id, same events, no re-parse. Re-ingesting the
            # bytes here is exactly the double count this model has to avoid.
            src_path = _library_path(item.fileName)
            if not src_path.is_file():
                raise HTTPException(404, f"{item.fileName} is not in the library")
            promoted = STORE.attach_library_source(src_path.name)
            if promoted:
                added.extend(promoted)
                continue
            display = str((_library_index().get(src_path.name) or {}).get("file") or _display_name(src_path.name, {}))
        else:
            if item.caseId not in cases.case_ids():
                raise HTTPException(404, f"case {item.caseId} not found")
            src_path = config.upload_dir(item.caseId) / Path(item.fileName).name
            if not src_path.is_file():
                raise HTTPException(404, f"{item.fileName} not found in {item.caseId}")
            known = cases._read_meta(item.caseId)
            display = _display_name(item.fileName, {
                str(s.get("path") or "").replace("\\", "/").rsplit("/", 1)[-1]: str(s.get("file") or "")
                for s in (known.get("sources") or [])
            })
        try:
            data = src_path.read_bytes()
        except OSError as exc:
            raise HTTPException(500, f"could not read {item.fileName}: {config.safe_os_error(exc)}")
        # add_file writes its own copy into the active case's uploads, so the two cases stay independent.
        # ingest_upload also expands archives and reports the ones it refuses (encrypted / bombed).
        # Attaching a large file parses in a background thread just like an upload does, so it gets a job
        # too — otherwise the analyst's longest-running ingest would be the one with no visible progress.
        jid = REGISTRY.create(display, len(data), "case", STORE.case_id).id
        REGISTRY.begin_parse(jid, len(data))
        try:
            ingested = STORE.ingest_upload(display, data)
        except Exception as exc:
            REGISTRY.fail(jid, f"{type(exc).__name__}: {exc}")
            raise
        from .sources import _report  # local import: sources imports this module
        _report(jid, ingested)
        # a file that was skipped for budget is IN the pool now (as a case source) — drop the stale record,
        # or the UI would keep warning that its events are missing from search
        if item.caseId == UNATTACHED and ingested:
            STORE.clear_pool_skip(src_path.name)
        added.extend(ingested)
    # An attach copies bytes into cases/<id>/uploads and moves a source between origins: it changes both
    # the SET of files and what every row says about them. It used to be caught only by the version key,
    # which the drift tolerance above deliberately ignores while enrichment is running — so say it.
    invalidate_library_cache()
    return added
