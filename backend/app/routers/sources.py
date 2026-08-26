"""Source upload / mapping endpoints."""
from __future__ import annotations

import asyncio
import re
import uuid

import os
import threading
from collections import Counter
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, HTTPException, Query, Response, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .. import config
from ..ai.mapping import suggest_mapping
from ..jobs import REGISTRY
from ..models import Source
from ..store import STORE
from .jobs import resolve_job
from .library import _spool, stage_files

router = APIRouter(prefix="/sources", tags=["sources"])


class Mapping(BaseModel):
    fields: list[str]
    delimiter: Optional[str] = None


@router.post("", response_model=list[Source])
async def upload_sources(response: Response, files: list[UploadFile] = File(...),
                         jobIds: str = Query("")) -> list[Source]:
    """Ingest uploads into the ACTIVE case — or, with no case, into the case-less library pool.

    With NO active case (`STORE.pending` — nothing on disk, `/api/cases` is `[]`) the bytes are STAGED IN
    THE LIBRARY: uploading a log must never conjure a case the analyst did not create. That is a supported
    destination, not a fallback — the file is still parsed into the workspace pool and is immediately
    searchable, `X-Iris-Staged-To-Library` carries the number of files staged, and POST
    /api/library/attach moves them into a case whenever the analyst opens one.

    `jobIds` (comma separated, positional against `files`) ties this request to jobs the client already
    registered with POST /api/jobs, so its progress is visible in every other tab. Callers that skip it
    still get jobs — resolve_job creates one per file.
    """
    ids = [j.strip() for j in (jobIds or "").split(",") if j.strip()]
    if STORE.pending:
        staged = await stage_files(files, job_ids=ids)
        response.headers["X-Iris-Staged-To-Library"] = str(len(staged))
        with STORE.lock:
            by_id = {s.id: s for s in STORE.sources.values()}
        return [by_id[f.sourceId] for f in staged if f.sourceId in by_id]
    out: list[Source] = []
    for i, f in enumerate(files):
        name = f.filename or "upload.log"
        jid = resolve_job(ids[i] if i < len(ids) else None, name, 0, "case", STORE.case_id)
        # Land the bytes on disk first, in chunks, and hand the store a PATH. `await f.read()` here was
        # a full copy of the upload in memory for the whole ingest — see routers/library._spool.
        staged = STORE.upload_dir / f"{uuid.uuid4().hex[:8]}_{re.sub(r'[^A-Za-z0-9._-]', '_', Path(name).name)}"
        try:
            await asyncio.to_thread(STORE.upload_dir.mkdir, parents=True, exist_ok=True)
            size = await _spool(f, staged)
        except OSError as exc:
            staged.unlink(missing_ok=True)
            REGISTRY.fail(jid, f"could not write the file ({config.safe_os_error(exc)})")
            raise HTTPException(500, f"could not store {name}: {config.safe_os_error(exc)}")
        REGISTRY.begin_parse(jid, size)
        try:
            # Archives expand here; a container Iris refuses to open (encrypted, bombed, unsupported) comes
            # back as an ERROR source carrying the reason. See Store.ingest_upload_path.
            # It parses inline under SYNC_LIMIT — off the event loop, or every other request
            # in the process waits for it (see routers/library.stage_files)
            added = await asyncio.to_thread(STORE.ingest_upload_path, name, staged)
        except Exception as exc:
            try:
                staged.unlink(missing_ok=True)
            except OSError:
                pass
            reason = _ingest_reason(exc)
            REGISTRY.fail(jid, reason)
            # The client gets the SAME sentence the job carries. A bare re-raise answered
            # "500 Internal Server Error", which is what the tab then showed for the file.
            print(f"[iris] ingest of {name!r} failed: {reason}", flush=True)
            raise HTTPException(500, f"{name}: {reason}")
        _report(jid, added)
        out.extend(added)
    # a case upload writes new bytes under cases/<id>/uploads — a new row in the library listing
    from .library import invalidate_library_cache
    invalidate_library_cache()
    return out


def _ingest_reason(exc: BaseException) -> str:
    """One sentence an analyst can act on. An OSError never carries the absolute path (that is the
    data-dir layout and the user name on a native install); anything else is its type and message,
    because `KeyError: 'x'` on its own is a library internal, not a report."""
    if isinstance(exc, OSError):
        return f"could not read or write the file ({config.safe_os_error(exc)})"
    msg = str(exc).strip()
    return f"{type(exc).__name__}: {msg}" if msg else f"{type(exc).__name__} while parsing"


def _report(job_id: str, added: list[Source]) -> None:
    """Resolve the job from what ingest produced.

    A file over store.SYNC_LIMIT comes back still PARSING in a background thread: the job stays `parsing`
    and carries its source ids, and jobs.sync() finishes it when the thread does.
    """
    sids = [s.id for s in added]
    if any(s.state == "PARSING" for s in added):
        REGISTRY.attach_sources(job_id, sids)
        return
    # each failure names ITS file — a job for a zip with three failed members read "X; Y; Z"
    errors = "; ".join(f"{s.file}: {s.error}" for s in added if s.state == "ERROR" and s.error)
    REGISTRY.finish(job_id, parser=added[0].parser if added else "",
                    events=sum(s.events for s in added), confidence=added[0].confidence if added else 0.0,
                    source_ids=sids, error=errors)


@router.get("/{sid}", response_model=Source)
def get_source(sid: str) -> Source:
    src = STORE.sources.get(sid)
    if not src:
        raise HTTPException(404, "source not found")
    return src


@router.delete("/{sid}")
def delete_source(sid: str) -> dict:
    # a library-origin source IS the staged file: removing it takes the bytes and the index entry with it,
    # otherwise the next startup would re-parse a file the analyst deleted
    with STORE.lock:
        staged = STORE.source_library.get(sid) if STORE.source_origin.get(sid) == "library" else None
    if not STORE.delete_source(sid):
        raise HTTPException(404, "source not found")
    from .library import forget_staged, invalidate_library_cache
    if staged:
        forget_staged(staged)
    # a case-origin delete unlinks the file under cases/<id>/uploads and drops its row: the library
    # listing's memo tolerates version drift while enrichment runs, so the change has to be announced
    invalidate_library_cache()
    return {"ok": True}


# ------------------------------------------------------------------- two-phase ingest (app/enrich.py)
# A text log lands as RAW LINES and is searchable at once; the parse and the normalization that cost
# 83-89 % of ingest run afterwards on one background worker. `settings.ingest.autoEnrich` decides whether
# that second phase starts on its own — these two endpoints are how the analyst drives it either way.
#
# The state rule both of them follow: 200 when the request was honoured OR when its outcome already
# holds (so a double-click, a retry or two tabs can never fail), 409 when the state asked for cannot be
# reached from the one the source is in. Nothing here is a re-parse of an already-enriched file — that is
# POST /api/sources/{id}/mapping.

@router.post("/{sid}/enrich", response_model=Source)
def enrich_source_now(sid: str) -> Source:
    """Queue this source for phase 2 NOW, whatever `ingest.autoEnrich` says.

    `raw` (never asked for), `skipped` (the analyst changed their mind) and `error` (a retry — a phase-2
    parse that failed leaves the raw lines in the pool and is worth attempting again after a field
    mapping or a rule change) are all enqueued. `queued` / `enriching` are an idempotent no-op: the
    outcome is already pending, and failing the second click would be a lie about what is happening.
    `enriched` is a **409** — there is nothing left to queue, and answering 200 would let the UI report
    "queued" for a source that will never be parsed again.
    """
    src = STORE.sources.get(sid)
    if not src:
        raise HTTPException(404, "source not found")
    if src.enrich == "enriched":
        raise HTTPException(409, f"{src.file} is already enriched — its events carry timestamps, fields "
                                 f"and detections. Re-parse it with POST /api/sources/{sid}/mapping instead.")
    # marks the source `queued` and hands it to enrich.QUEUE; the worker (started in the lifespan) picks
    # it up. Nothing parses on this request thread.
    STORE.queue_enrichment(sid)
    return STORE.sources[sid]


@router.post("/{sid}/enrich/skip", response_model=Source)
def skip_source_enrichment(sid: str) -> Source:
    """Decline phase 2 for this source: it stays in the pool as raw, searchable lines and nothing more.

    Cancels it from the queue if it was waiting. **Skipping cannot un-ring the bell**: a source that is
    already `enriching` is a **409** — the parse is running on the worker and will replace that source's
    events when it lands, so recording "skipped" would be a claim about the pool that stops being true a
    few seconds later. Wait for it to finish (it becomes `enriched`) — nothing is lost either way, because
    the raw lines were never removed. An already-`enriched` source is a 409 for the same reason: the
    interpreted events are in the pool and declining them now would describe evidence that is there.
    Skipping an already-`skipped` source is an idempotent no-op.
    """
    src = STORE.sources.get(sid)
    if not src:
        raise HTTPException(404, "source not found")
    if src.enrich == "enriching":
        raise HTTPException(409, f"{src.file} is being enriched right now and cannot be cancelled mid-parse. "
                                 "Wait for it to finish — the raw lines stay searchable throughout.")
    if src.enrich == "enriched":
        raise HTTPException(409, f"{src.file} is already enriched — its parsed events are in the pool. "
                                 "There is nothing left to decline.")
    STORE.skip_enrichment(sid)
    return STORE.sources[sid]


@router.post("/{sid}/mapping", response_model=Source)
def map_source(sid: str, body: Mapping) -> Source:
    if sid not in STORE.sources:
        raise HTTPException(404, "source not found")
    if not body.fields:
        raise HTTPException(400, "fields must not be empty")
    return STORE.remap_source(sid, body.fields, body.delimiter)


def _pending_mapping_ids() -> list[str]:
    """Sources still awaiting a field mapping — MAP (unrecognised layout) and REVIEW (low-confidence guess).

    Restricted to parsers that declare `mappable` (see parsers/base.py): a field mapping names anonymous
    COLUMNS, so it is a question only the delimited parser can be asked. A JSONL or plain text source
    that landed in REVIEW/MAP names its own fields and has none to map — and this list is not just a
    display: `POST /mapping/auto` walks it, asks the model for column names for each entry and calls
    `remap_source`, which RE-PARSES the file as delimited. On the analyst's pool that would have taken
    347 correctly-parsed JSONL sources and rewritten them column by column.
    """
    with STORE.lock:
        out: list[str] = []
        for sid in STORE.source_order:
            src = STORE.sources.get(sid)
            if src is None or src.state not in ("MAP", "REVIEW"):
                continue
            parser = STORE.source_parsers.get(sid)
            if parser is not None and not parser.mappable:
                continue  # nothing to map; a mapping would replace the fields it already produces
            out.append(sid)
        return out


@router.get("/mapping/pending")
def pending_mappings() -> dict:
    ids = _pending_mapping_ids()
    with STORE.lock:
        rows = [{"id": s, "file": STORE.sources[s].file, "state": STORE.sources[s].state,
                 "confidence": STORE.sources[s].confidence, "events": STORE.sources[s].events}
                for s in ids if s in STORE.sources]
    return {"total": len(rows), "sources": rows}


@router.post("/mapping/auto")
async def auto_map_all(apply: bool = True, minConfidence: float = 0.5) -> dict:
    """Run the AI field-mapping suggestion over every pending source and (by default) apply it.

    Sequential on purpose: each call hits the LLM, and a case can have dozens of pending sources —
    firing them all at once would hammer the provider and blow past rate limits. Each source is
    independent, so one failure never blocks the rest; per-source outcomes come back in `results`.
    """
    results: list[dict] = []
    applied = failed = skipped = 0
    for sid in _pending_mapping_ids():
        src = STORE.sources.get(sid)
        if src is None:
            continue
        row: dict = {"id": sid, "file": src.file, "state": src.state}
        try:
            suggestion = await _suggest_for(sid)
            fields = [f for f in (suggestion.get("fields") or []) if str(f).strip()]
            row["source"] = suggestion.get("source")
            row["confidence"] = suggestion.get("confidence")
            row["rationale"] = suggestion.get("rationale")
            row["fields"] = fields
            if not fields:
                row["status"] = "skipped"
                row["reason"] = "no field names returned"
                skipped += 1
            elif float(suggestion.get("confidence") or 0) < minConfidence:
                row["status"] = "skipped"
                row["reason"] = f"confidence below {minConfidence:g}"
                skipped += 1
            elif apply:
                # a remap re-parses the whole file — off the event loop, like every other parse
                updated = await asyncio.to_thread(STORE.remap_source, sid, fields, suggestion.get("delimiter"))
                row["status"] = "applied"
                row["newState"] = updated.state
                row["events"] = updated.events
                applied += 1
            else:
                row["status"] = "suggested"
        except Exception as exc:  # one bad source must not abort the batch
            row["status"] = "failed"
            row["error"] = f"{type(exc).__name__}: {exc}"
            failed += 1
        results.append(row)
    return {"total": len(results), "applied": applied, "skipped": skipped, "failed": failed, "results": results}


def _mapping_inputs(sid: str) -> tuple:
    """Everything the suggestion needs that touches the disk or the pool. Runs OFF the event loop.

    Both halves are blocking and one is unbounded: `source_head` reads a file through the Docker
    bind mount, and `_case_field_vocabulary` walks EVERY event in the workspace counting field
    names. `_suggest_for` is `async def`, so before this both ran ON the loop - the rule broken
    is the one CLAUDE.md states outright, and the symptom is every other request in the process
    stalling for the length of a pass over the pool."""
    src = STORE.sources.get(sid)
    if not src:
        raise HTTPException(404, "source not found")
    lines: list[str] = []
    if STORE.source_paths.get(sid) is not None:
        try:
            # source_head, not the raw path: for a member of a staged archive the recorded path is the
            # CONTAINER, and suggesting a field mapping from a zip's own bytes is worse than suggesting
            # nothing. Bounded either way — this only ever needs the first few lines.
            head = STORE.source_head(sid, 256 * 1024)
            lines = [l for l in head.decode("utf-8", errors="replace").splitlines() if l.strip()][:40]
        except (OSError, KeyError, ValueError):
            lines = []
    if not lines and src.sample:
        lines = [l for l in src.sample.splitlines() if l.strip()]
    parser = STORE.source_parsers.get(sid)
    current = list(getattr(parser, "mapping", None) or src.guessedFields or [])
    delimiter = src.delimiter or getattr(parser, "delimiter", None)
    return lines, current, delimiter, src.file, _case_field_vocabulary(exclude=sid)


async def _suggest_for(sid: str) -> dict:
    lines, current, delimiter, file, known = await asyncio.to_thread(_mapping_inputs, sid)
    return await suggest_mapping(lines, current, delimiter, file, known_fields=known)


def _case_field_vocabulary(exclude: str = "", limit: int = 60) -> list[str]:
    """Field names already present on events from OTHER sources, most common first.

    Correlation links events by shared field values, so a new mapping should reuse the names the case
    already uses rather than inventing a synonym that silently fails to join.
    """
    counts: Counter[str] = Counter()
    with STORE.lock:
        events = STORE.events
    for e in events:
        if e.sourceId == exclude:
            continue
        counts.update(e.fields.keys())
    return [name for name, _ in counts.most_common(limit)]


@router.post("/{sid}/mapping/suggest")
async def suggest_source_mapping(sid: str) -> dict:
    """AI-generated field mapping suggestion (not applied). Falls back to the heuristic guess when AI is off."""
    return await _suggest_for(sid)


# ----------------------------------------------------------------------------- raw log viewer
_RAW_LINE_MAX = 2000          # chars kept per line in the viewer (the full line is in the download)
_RAW_LIMIT_MAX = 2000         # lines per page
# Formats that are never line-addressable, even when the first 8 KB happens to be NUL-free.
_BINARY_EXT = {".evtx", ".dmp", ".bin", ".sqlite", ".sqlite3", ".db", ".mem", ".vmem", ".raw", ".img", ".pcap",
               ".pcapng", ".cap", ".zip", ".gz", ".7z", ".rar", ".pdf", ".xlsx", ".xls", ".docx", ".doc", ".png", ".jpg",
               ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".exe", ".dll", ".sys",
               ".tar", ".tgz", ".bz2", ".xz", ".zst", ".db3", ".sqlitedb", ".msg"}
_BINARY_HINT = ("This file is not line-addressable (binary or structured container). Iris parsed it into events — "
                "search those, or download the original bytes.")

# Line count per upload, keyed by (path, size, mtime): counting is a full read, and every page of a large
# file would otherwise pay it again. Bounded by the number of uploads; entries die with the file.
_line_counts: dict[tuple[str, int, int], int] = {}
_line_counts_lock = threading.Lock()


def _source_path(sid: str) -> tuple[Source, Path]:
    src = STORE.sources.get(sid)
    if not src:
        raise HTTPException(404, "source not found")
    path = STORE.source_paths.get(sid)
    if path is None or not path.is_file():
        raise HTTPException(404, "the original upload is no longer on disk")
    return src, path


def _member_of(sid: str) -> str:
    """The provenance path inside the container, or '' when this source IS its file.

    A member of a library-staged archive shares the container's path, so every reader that opens
    `source_paths[sid]` gets the ARCHIVE. In the pool that was outright corruption — phase 2 replaced a
    parsed syslog member with lines of decoded zip binary — and here it is "show me the raw log"
    answering with the zip's own bytes and calling the source binary.
    """
    return STORE.source_member.get(sid, "")


def _member_bytes(sid: str, src: Source) -> bytes:
    """One member, held for one request. Bounded by archives.MAX_MEMBER_BYTES; its container is not."""
    try:
        return STORE.source_bytes(sid)
    except (OSError, KeyError, ValueError) as exc:
        raise HTTPException(404, f"{src.file} could not be read back out of its archive "
                                 f"({type(exc).__name__})") from exc


def _looks_binary(path: Path, name: str) -> bool:
    if Path(name).suffix.lower() in _BINARY_EXT or path.suffix.lower() in _BINARY_EXT:
        return True
    try:
        with open(path, "rb") as fh:
            head = fh.read(8192)
    except OSError:
        return True
    return b"\x00" in head


def _lines_of(blob: bytes):
    """`_read_lines` over bytes already in hand — the archive-member form of the same walk."""
    for n, line in enumerate(blob.decode("utf-8", "replace").splitlines(), 1):
        yield n, line


def _read_lines(path: Path):
    """Yield (n, text) for every line — universal newlines, utf-8 with replacement, no trailing newline."""
    with open(path, "r", encoding="utf-8", errors="replace", newline=None) as fh:
        for n, line in enumerate(fh, 1):
            if line.endswith("\n"):
                line = line[:-1]
            yield n, line


@router.get("/{sid}/raw")
def source_raw(sid: str, offset: int = Query(0, ge=0), limit: int = Query(500, ge=1, le=_RAW_LIMIT_MAX),
               q: str = "") -> dict:
    """A page of the original upload, line-numbered, for the raw log viewer.

    `q` narrows to lines containing the substring (case-insensitive) and then offset/limit page over the
    MATCHES (`matches` is their count; `totalLines` is always the whole file). Lines are cut at
    _RAW_LINE_MAX chars — `truncatedLine` says whether any line on this page was. Binary / structured
    files (EVTX, dumps, sqlite, anything with NUL bytes up front) return binary:true with a hint.
    """
    src, path = _source_path(sid)
    member = _member_of(sid)
    binary = {"file": src.file, "size": src.size, "totalLines": 0, "matches": 0, "offset": offset,
              "limit": limit, "q": q, "lines": [], "truncatedLine": False, "binary": True,
              "hint": _BINARY_HINT}
    if member:
        blob = _member_bytes(sid, src)
        if Path(src.file.split("!")[-1]).suffix.lower() in _BINARY_EXT or b"\x00" in blob[:8192]:
            return binary
        rows, key = _lines_of(blob), (f"{path}!{member}", len(blob), 0)
    else:
        if _looks_binary(path, src.file):
            return binary
        st = path.stat()
        rows, key = _read_lines(path), (str(path), st.st_size, int(st.st_mtime_ns))
    with _line_counts_lock:
        known_total = _line_counts.get(key)

    needle = q.lower() if q else ""
    lines: list[dict] = []
    truncated = False
    matches = 0
    total = 0
    walked_all = True
    try:
        for n, text in rows:
            total = n
            if needle:
                if needle not in text.lower():
                    continue
                matches += 1
                idx = matches - 1
            else:
                idx = n - 1
            if idx < offset:
                continue
            if len(lines) < limit:
                if len(text) > _RAW_LINE_MAX:
                    text = text[:_RAW_LINE_MAX]
                    truncated = True
                lines.append({"n": n, "text": text})
            elif not needle and known_total is not None:
                # page is full and the file's length is already known — no need to walk to the end
                total = known_total
                walked_all = False
                break
    except OSError as exc:
        raise HTTPException(500, f"could not read the file ({config.safe_os_error(exc)})")

    if walked_all:
        with _line_counts_lock:
            _line_counts[key] = total
    return {"file": src.file, "size": src.size, "totalLines": total, "matches": matches if needle else total,
            "offset": offset, "limit": limit, "q": q, "lines": lines, "truncatedLine": truncated,
            "binary": False, "hint": None}


@router.get("/{sid}/download")
def source_download(sid: str):
    """The original uploaded bytes as an attachment (Content-Disposition carries the original file name).

    For a member of a staged archive that is the MEMBER, not the archive: the header names `auth.log`,
    and handing over the 3 GB zip under that name would be a different file than the one asked for.
    """
    src, path = _source_path(sid)
    name = os.path.basename(src.file.split("!")[-1]) or "upload.bin"
    if _member_of(sid):
        return Response(content=_member_bytes(sid, src), media_type="application/octet-stream",
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})
    return FileResponse(str(path), media_type="application/octet-stream", filename=name)
