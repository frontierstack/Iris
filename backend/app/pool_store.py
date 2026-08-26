"""Persist the PARSED POOL so a restart does not re-read and re-interpret every log.

The analyst's question was "why does it have to reparse every single time", and the honest answer was
that nothing about the pool was persisted — only the entity graph was. Every start re-read the staged
library (1.76 GB across 680 files on their machine), ran phase 1 over all of it, and then — because a
re-parsed source comes back `raw` — `autoEnrich` re-queued all 680 for phase 2. Hours of work whose
inputs had not changed, after every restart and every crash-restart. It also blocked the graph:
derived builds are paused while that queue runs, so the Graph screen said "waiting for source
enrichment" for as long as it took.

The unit is the staged file's MEMBER SOURCE, and the layout is a manifest plus one file per member:

    cache/pool/<hash(name)>.manifest      {format, sig, sids}
    cache/pool/<hash(name)>.<sid>.pkl     {format, sig, source, errors, events}

Two reasons for that shape, both about not paying for the cache twice:
* a member is saved with the event list the caller ALREADY HAS (the enrichment result, the parse
  result), so nothing ever scans the pool to collect a source's events — that scan is O(pool) per
  file, which on this workspace is the very cost being removed;
* a staged archive with many members rewrites one small file per member instead of a large one per
  member. A hit needs the manifest AND every member it names: a partially cached archive parses.

What makes it safe rather than merely fast:

* **The key is the file's own identity plus the pipeline's** — name, size, mtime_ns and
  `POOL_FORMAT`. Bump `POOL_FORMAT` whenever `Event`'s slots, the parsers, normalization or detection
  stamping change what a file produces. A stale entry is not a slow answer, it is fabricated
  evidence: events that no parser in this build would produce.
* **Ids come back identical**, which is what makes this legal at all: library sids and event ids are
  derived from the staged file name (`Store.library_sid` / `_member_sid` / the `l<sid>` prefix), so
  the cached ids are the ones a re-parse would have produced, and case sets, notes and indicators
  that cite them still resolve.
* **Events are packed into plain tuples**, not pickled as objects — the same reasoning as
  `graph_parallel._Row`: a list of tuples pickles at C speed while millions of slotted objects go
  through `__reduce_ex__` one at a time. Unpacking sets the slots directly (`Event.__new__`), which
  also preserves `_msg` EXACTLY; going through `__init__` would re-derive it and rewrite the message
  of every event whose `msg` equals its `raw` prefix.
* **Only a source that is finished is cached**: `enriched`, `skipped` (the analyst decided that —
  re-asking every restart is how a decision gets undone) or a source born enriched (EVTX, SQLite,
  PDF…). A `raw`/`queued`/`enriching` source is mid-flight and caching it would restore a half-state.
* **It is a cache.** A corrupt file, a foreign HMAC tag, a signature miss, a missing member or any
  exception is a MISS that falls back to parsing. `IRIS_POOL_CACHE=0` disables it, `clear-all` wipes
  the tree, and deleting `cache/` by hand is always safe.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import pickle
import time
from pathlib import Path
from typing import Callable, Optional

from . import config, sealed
from .models import Event, Source

POOL_FORMAT = 2               # bump when Event slots / parsers / normalization change what a file yields
#                             # 2: header + framed event chunks (1 was one pickled blob per member).
#                             # The LAYOUT is part of this number too — a layout change without a bump
#                             # let a v1 entry be read by the v2 reader, which found no frames, fell
#                             # back to the header's inline `events` list and would have put raw
#                             # TUPLES into the event pool. Seen live as
#                             # "unhashable type: 'list'" / "NEWOBJ class argument must be a type".
_MAGIC = b"IRISPOOL"
FINISHED = ("enriched", "skipped")


def enabled() -> bool:
    return os.environ.get("IRIS_POOL_CACHE", "1").strip().lower() not in ("0", "false", "no", "off")


def _dir() -> Path:
    return config.CACHE_DIR / "pool"


def _stem(name: str) -> str:
    # The staged name is `<8 hex>_<sanitized>`, but it comes from an uploaded file name and can be
    # long, so it is hashed rather than trusted as a path component.
    return hashlib.sha256(name.encode("utf-8")).hexdigest()[:32]


_PIPELINE: Optional[str] = None
# Files whose CONTENT decides what a parsed event looks like. A digest of them is part of every cache
# key, so changing a parser, the normalizer or the Event shape invalidates the cache automatically —
# `POOL_FORMAT` is a manual bump and the failure mode of forgetting it is serving events that no code
# in this build would produce. Content, not mtime: rebuilding the image without touching the code
# must NOT throw away a 1.7 GB pool's cache.
# What actually decides the CONTENT of a parsed event, and nothing else. This list is deliberately
# narrow, because it is the difference between "a relevant change invalidates the cache" and "every
# deploy costs a full re-parse of the library".
#
# It used to be the whole of `models.py`, `detect.py` and `enrich.py`. Adding one field to
# `EventDetail` — an API RESPONSE model that no parser touches — therefore threw away a 9.5 GB cache
# and re-parsed 11 M events, which is exactly the cost this cache exists to avoid. So:
#   * `parsers/*.py` and `normalize.py` — yes: they produce the fields, the timestamps and the
#     severities, so a change there changes what a cached event would be.
#   * `models.Event` / `models.Detection` — by SOURCE OF THE CLASS, not the whole module: those two
#     shapes are what is stored.
#   * `detect.py` — deliberately NOT included. Detections are re-stamped by the `_run_detections()`
#     pass that follows every library load, so a rule or detector change corrects itself without
#     re-parsing anything.
#   * `enrich.py` — NOT included either: it orchestrates when phase 2 runs, not what a parse yields.
_PIPELINE_FILES = ("normalize.py",)
_PIPELINE_CLASSES = ("Event", "Detection")


def pipeline_digest() -> str:
    """A short digest of the code that decides what a parsed event contains. Once per process (~ms)."""
    global _PIPELINE
    if _PIPELINE is not None:
        return _PIPELINE
    h = hashlib.sha256()
    here = Path(__file__).resolve().parent
    try:
        for p in sorted((here / "parsers").glob("*.py")) + [here / f for f in _PIPELINE_FILES]:
            h.update(p.name.encode("utf-8"))
            h.update(p.read_bytes())
        import inspect

        from . import models as _models
        for name in _PIPELINE_CLASSES:
            h.update(name.encode("utf-8"))
            h.update(inspect.getsource(getattr(_models, name)).encode("utf-8"))
    except (OSError, TypeError, AttributeError):
        # A digest nobody can reproduce means every entry misses, which is the safe direction: a
        # cache that cannot prove what produced it must not be served.
        return "unknown"
    _PIPELINE = h.hexdigest()[:16]
    return _PIPELINE


def signature(name: str) -> str:
    """What the cached events were built FROM. Same string -> same file, same pipeline."""
    try:
        st = (config.LIBRARY_DIR / name).stat()
    except OSError:
        return ""
    return f"{POOL_FORMAT}:{pipeline_digest()}:{st.st_size}:{st.st_mtime_ns}"


# --------------------------------------------------------------------------- packing
def _pack_event(e: Event) -> tuple:
    return (e.id, e.ts, e.source, e.sourceId, e.file, e.host, e.user, e._msg, e.sev, e.raw,
            e.fields, e.entities, e.detections, e._base_sev)


def _unpack_events(rows: list) -> list[Event]:
    out: list[Event] = []
    append = out.append
    cls = Event
    for r in rows:
        e = cls.__new__(cls)
        (e.id, e.ts, e.source, e.sourceId, e.file, e.host, e.user, e._msg, e.sev, e.raw,
         e.fields, e.entities, e.detections) = r[:13]
        # `__new__` leaves every slot unset and a slots class raises AttributeError on an unset one,
        # so this is not optional. A 13-wide row is one written before the field existed.
        e._base_sev = r[13] if len(r) > 13 else None
        append(e)
    return out


CHUNK = 50_000            # events per pickle frame; bounds peak memory during save AND load
_VERIFY_BLOCK = 8 << 20   # bytes per HMAC pass read


def _write(path: Path, payload: dict) -> bool:
    """Small payloads (the manifest) in one frame."""
    return _write_frames(path, payload, None)


def _write_frames(path: Path, header: dict, events: Optional[list],
                  progress: Optional[Callable[[int, int], None]] = None) -> bool:
    """Write header + the events as SEPARATE pickle frames, HMAC-tagged, without ever holding the
    whole serialised blob in memory.

    `pickle.dumps` of a million packed events is gigabytes of transient bytes on top of the pool
    itself. On the analyst's machine — 11.4 M events, a WSL2 VM that already segfaults under memory
    pressure — that is not a slow path, it is the thing that kills the process. Frames of `CHUNK`
    events keep the peak at one chunk, and the tag is written back into the reserved slot at the end
    so a reader can still verify BEFORE unpickling anything.
    """
    try:
        _dir().mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        mac = hmac.new(sealed.key(), digestmod=hashlib.sha256)

        class _Tap:
            """File-like: everything written is tagged as it goes."""
            __slots__ = ("fh",)

            def __init__(self, fh):
                self.fh = fh

            def write(self, b) -> int:
                mac.update(b)
                return self.fh.write(b)

        with open(tmp, "wb") as fh:
            fh.write(_MAGIC)
            fh.write(bytes(32))              # the tag lands here once the payload is known
            tap = _Tap(fh)
            n = len(events) if events is not None else 0
            # A FRESH Pickler per frame, deliberately. One Pickler with `clear_memo()` between dumps
            # writes memo indices the reader cannot follow — a single Unpickler reading the stream
            # back gets "NEWOBJ class argument must be a type, not str" or "unhashable type: dict" on
            # the FIRST frame after the header. That is not a corrupt disk: it is the two memos going
            # out of step, and it made every entry with more than one frame — i.e. every source over
            # CHUNK events, i.e. exactly the big files — unreadable, so they were re-parsed on every
            # single restart. A pickle is self-delimiting, so consecutive independent streams in one
            # file are read back with one `Unpickler(fh).load()` per frame.
            pickle.Pickler(tap, protocol=pickle.HIGHEST_PROTOCOL).dump(
                {**header, "chunks": (n + CHUNK - 1) // CHUNK if events is not None else 0})
            if events is not None:
                for i in range(0, n, CHUNK):
                    pickle.Pickler(tap, protocol=pickle.HIGHEST_PROTOCOL).dump(
                        [_pack_event(e) for e in events[i:i + CHUNK]])
                    if progress is not None:
                        progress(min(n, i + CHUNK), n)     # a 2 M-event cache write is minutes; say so
            fh.flush()
            fh.seek(len(_MAGIC))
            fh.write(mac.digest())
        os.replace(tmp, path)
        return True
    except Exception as exc:                      # noqa: BLE001 — a cache never breaks its caller
        _log(f"write failed for {path.name} ({type(exc).__name__}: {exc})")
        try:
            path.with_suffix(path.suffix + ".tmp").unlink(missing_ok=True)
        except OSError:
            pass
        return False


def _verify(path: Path) -> bool:
    """Check the tag by streaming the file. Nothing is unpickled until this passes."""
    try:
        mac = hmac.new(sealed.key(), digestmod=hashlib.sha256)
        with open(path, "rb") as fh:
            if fh.read(len(_MAGIC)) != _MAGIC:
                return False
            tag = fh.read(32)
            while True:
                block = fh.read(_VERIFY_BLOCK)
                if not block:
                    break
                mac.update(block)
        return hmac.compare_digest(tag, mac.digest())
    except OSError:
        return False


def _read(path: Path, sig: str) -> Optional[dict]:
    """The header frame only (manifest, or a member's metadata). None on any doubt."""
    return _read_frames(path, sig, with_events=False)


def _read_frames(path: Path, sig: str, with_events: bool) -> Optional[dict]:
    if not path.is_file():
        return None
    if not _verify(path):
        _log(f"{path.name} is unsigned or was not written by this install; re-parsing")
        return None
    try:
        with open(path, "rb") as fh:
            fh.seek(len(_MAGIC) + 32)
            header = pickle.Unpickler(fh).load()
            if (not isinstance(header, dict) or header.get("format") != POOL_FORMAT
                    or header.get("sig") != sig):
                return None
            if not with_events:
                return header
            events: list[Event] = []
            for _ in range(int(header.get("chunks") or 0)):
                # one Unpickler per frame, matching the writer — see `_write_frames`
                events.extend(_unpack_events(pickle.Unpickler(fh).load()))
            if "events" in header:
                # A v1 entry: its events live INSIDE the header as packed tuples. It must never be
                # served — the caller expects Event objects and would pool the tuples silently. The
                # format number now separates them, and this is the belt to that braces.
                _log(f"{path.name} is an older cache layout; re-parsing")
                return None
            header = dict(header)
            header["events"] = events
            return header
    except Exception as exc:                      # noqa: BLE001 — corrupt cache = miss, never a crash
        _log(f"{path.name} unreadable ({type(exc).__name__}: {exc}); re-parsing")
        return None


# --------------------------------------------------------------------------- save
def save_manifest(name: str, sids: list[str]) -> bool:
    """Which member sources a staged file expands into. Written when it is first parsed."""
    if not enabled() or not sids:
        return False
    sig = signature(name)
    return bool(sig) and _write(_dir() / f"{_stem(name)}.manifest",
                                {"format": POOL_FORMAT, "sig": sig, "sids": list(sids), "at": time.time()})


def save_member(name: str, src: Source, events: list[Event], errors: int, member: str = "",
                progress: Optional[Callable[[int, int], None]] = None) -> bool:
    """Cache ONE finished member source, with the event list the caller already holds."""
    if not enabled() or not name or src is None:
        return False
    if getattr(src, "enrich", "") not in FINISHED:
        return False
    # The entry must not disagree with its own row. `_parse_source` caches an event list only for an
    # ENRICHED source - a `skipped` one holds raw lines that are not worth megabytes of disk, which
    # is deliberate - but `skipped` is FINISHED, so a skipped source that was then field-mapped
    # arrived here with `src.events = N` and an EMPTY list. That entry is a HIT on the next boot:
    # the Sources table reports N events and search, the timeline, the graph and every citation have
    # none. A miss costs one re-parse; this costs the evidence, silently, one restart later.
    if len(events) != int(getattr(src, "events", 0) or 0):
        return False
    sig = signature(name)
    if not sig:
        return False
    return _write_frames(_dir() / f"{_stem(name)}.{src.id}.pkl",
                         {"format": POOL_FORMAT, "sig": sig, "source": src.model_dump(),
                          # Which member of the container these events came from. Without it a
                          # restored source cannot find its own bytes and every read falls back to
                          # the whole archive - see Store.load_pool_file.
                          "member": member, "errors": int(errors)}, events, progress=progress)


# --------------------------------------------------------------------------- load
def has_member(name: str, sid: str) -> bool:
    """Is there already a cache entry for this member? Existence only — not validity.

    The guard on re-saving a corrected stamp (`Store._resave_pool_cache`): rewriting an entry that is
    already there is the point, MINTING one as a side effect of a detection pass is not. A stale or
    foreign entry still counts as present — it is about to be overwritten with a good one.
    """
    if not enabled() or not name or not sid:
        return False
    try:
        return (_dir() / f"{_stem(name)}.{sid}.pkl").exists()
    except OSError:
        return False


def load(name: str) -> Optional[list[tuple[Source, list[Event], int, str]]]:
    """Every member of a staged file as it was parsed last time, or None on ANY doubt.

    The fourth element is the archive member this source came from (empty for a plain file). An
    entry written before that was recorded reads back as "" — which is what it was doing before,
    so an older cache degrades to the previous behaviour instead of failing to load."""
    if not enabled():
        return None
    sig = signature(name)
    if not sig:
        return None
    stem = _stem(name)
    man = _read(_dir() / f"{stem}.manifest", sig)
    if not man:
        return None
    out: list[tuple[Source, list[Event], int]] = []
    for sid in man.get("sids") or []:
        payload = _read_frames(_dir() / f"{stem}.{sid}.pkl", sig, with_events=True)
        if not payload:
            return None            # a partially cached archive is a miss, never a partial pool
        try:
            src = Source.model_validate(payload["source"])
            if src.enrich not in FINISHED:
                return None
            out.append((src, payload.get("events") or [], int(payload.get("errors") or 0),
                        str(payload.get("member") or "")))
        except Exception as exc:   # noqa: BLE001
            _log(f"{name}: member {sid} did not rebuild ({type(exc).__name__}: {exc}); re-parsing")
            return None
    return out or None


# --------------------------------------------------------------------------- the skip decision
# "Leave this file raw" is a decision the ANALYST made — the escape hatch on a screen blocked by the
# derived-build pause is exactly that, in bulk. A skipped source holds only raw lines, so it is not
# worth caching megabytes of them; what must survive a restart is the DECISION, or the next boot
# re-queues every source the analyst just declined and the pause they escaped starts again.
def _skips_path() -> Path:
    return _dir() / "skipped.json"


def _skips() -> set[str]:
    import json
    try:
        data = json.loads(_skips_path().read_text(encoding="utf-8"))
        return set(data) if isinstance(data, list) else set()
    except (OSError, ValueError):
        return set()


def remember_skip(sid: str, skipped: bool = True) -> None:
    import json
    if not enabled() or not sid:
        return
    cur = _skips()
    if skipped:
        cur.add(sid)
    else:
        cur.discard(sid)
    try:
        _dir().mkdir(parents=True, exist_ok=True)
        tmp = _skips_path().with_suffix(".tmp")
        tmp.write_text(json.dumps(sorted(cur)), encoding="utf-8")
        os.replace(tmp, _skips_path())
    except OSError:
        pass


def was_skipped(sid: str) -> bool:
    return bool(sid) and enabled() and sid in _skips()


# --------------------------------------------------------------- the enrich request
# The mirror image of the skip, and it was missing. `ingest.autoEnrich` ships OFF, so on a raw-first
# workspace phase 2 runs only because someone ASKED. A restart re-parses the staged files and a
# re-parsed source comes back `raw` (the pool cache only stores FINISHED sources), so a file sitting
# in the queue when the process stopped came back raw and `requeue_unenriched` left it alone - which
# is right on its own terms, "a restart is not a request", but the request had been made and nothing
# on any screen said it had been dropped. The file reads `raw` again, exactly as it did before the
# click. Both directions are the analyst's decision and both are one line of JSON.
def _requests_path() -> Path:
    return _dir() / "enrich-requested.json"


def _requests() -> set[str]:
    import json
    try:
        data = json.loads(_requests_path().read_text(encoding="utf-8"))
        return set(data) if isinstance(data, list) else set()
    except (OSError, ValueError):
        return set()


def remember_request(sid: str, requested: bool = True) -> None:
    """Record (or clear) "phase 2 was asked for on this source". Cleared when it settles."""
    import json
    if not enabled() or not sid:
        return
    cur = _requests()
    if requested:
        cur.add(sid)
    elif sid not in cur:
        return                      # the common case: nothing to write
    else:
        cur.discard(sid)
    try:
        _dir().mkdir(parents=True, exist_ok=True)
        tmp = _requests_path().with_suffix(".tmp")
        tmp.write_text(json.dumps(sorted(cur)), encoding="utf-8")
        os.replace(tmp, _requests_path())
    except OSError:
        pass


def was_requested(sid: str) -> bool:
    return bool(sid) and enabled() and sid in _requests()


def reconcile_requests(still_outstanding: "set[str]") -> None:
    """Keep only the requests that still have something to do. One write, at startup.

    A request is cleared by the source SETTLING, and doing that per completion would put a file read
    and a file write on the enrichment worker's hot path for a set that is almost always empty. The
    only moment staleness can matter is the next boot, so that is where it is reconciled - which
    also collects requests for staged files that were deleted while the app was down.
    """
    import json
    if not enabled():
        return
    cur = _requests()
    keep = cur & set(still_outstanding)
    if keep == cur:
        return
    try:
        _dir().mkdir(parents=True, exist_ok=True)
        if keep:
            tmp = _requests_path().with_suffix(".tmp")
            tmp.write_text(json.dumps(sorted(keep)), encoding="utf-8")
            os.replace(tmp, _requests_path())
        else:
            _requests_path().unlink(missing_ok=True)
    except OSError:
        pass


def forget(name: str) -> None:
    """Drop a staged file's entries (its bytes are going away, or its events were replaced)."""
    try:
        stem = _stem(name)
        for p in _dir().glob(f"{stem}.*"):
            p.unlink(missing_ok=True)
    except OSError:
        pass


def prune() -> int:
    """Delete cache entries whose staged file is gone. Returns the number of files removed.

    Every entry is keyed on a staged library file, so an entry whose file no longer exists can never
    be read again — it is pure disk. `forget()` handles the deletes Iris performs itself; this catches
    everything else: a file removed while the app was down, a rename, a half-written entry from a
    crash, and any entry left by an older key scheme. On this workspace one entry is 3.3 GB, so
    "cannot be read again" is not a rounding error.
    """
    d = _dir()
    if not d.is_dir():
        return 0
    try:
        live = {_stem(p.name) for p in config.LIBRARY_DIR.iterdir() if p.is_file()}             if config.LIBRARY_DIR.is_dir() else set()
    except OSError:
        return 0
    removed = 0
    # The bookkeeping files are not cache entries: they hold the analyst's DECISIONS, they are not
    # keyed on a staged file name, and deleting one silently undoes a choice. A name check per file
    # was how the skip was protected; a set, because the next one added is otherwise deleted on the
    # first prune and the symptom is a decision that quietly stops sticking.
    reserved = {_skips_path().name, _requests_path().name}
    for f in list(d.glob("*")):
        if f.name in reserved:
            continue
        stem = f.name.split(".", 1)[0]
        if stem in live:
            continue
        try:
            size = f.stat().st_size
            f.unlink()
            removed += 1
            _log(f"dropped {f.name} ({size >> 20} MB): its staged file is gone")
        except OSError:
            pass
    return removed


def clear() -> None:
    try:
        for p in _dir().glob("*"):
            p.unlink(missing_ok=True)
    except OSError:
        pass


def _log(msg: str) -> None:
    print(f"[iris] pool cache: {msg}")
