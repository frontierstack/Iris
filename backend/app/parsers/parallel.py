"""Normalization batching, and the multi-process parse path for large line-oriented files.

Two things live here, and they are deliberately in one module because the second is only correct if it
shares the first:

  * ``normalize_batch`` / ``merge_batches`` — the per-record work that turns ``ParsedEvent``s into
    ``Event``s, split so it can run on a SLICE of a file and be stitched back together afterwards.
    ``Store._normalize`` calls it with one batch; the parallel path calls it with one batch per chunk.
    One implementation, so single-worker and parallel output cannot drift.
  * ``parse_parallel`` — byte-range chunking of a text log across ``ProcessPoolExecutor`` workers.

Why processes and not threads: parsing is pure-Python and CPU bound (measured on a 67 MB CSV: 7.8 s
tokenizing, 25.3 s building Events — regex entity extraction is the single biggest item), so the GIL
makes ``threading`` strictly slower. Processes cost a pickle round trip of the resulting Events
(measured ~15 s per million events on the parent side), but that overlaps with the workers.

Correctness rules the design has to keep:

  * **Order and ids.** Workers return their events in RECORD order with a blank id; the parent
    concatenates the chunks in submission order, assigns ids over the whole file exactly as the
    single-worker path does, and only then sorts by timestamp (a stable sort, so equal timestamps keep
    record order either way). Ids are load-bearing — case sets reference them.
  * **Parser warm-up.** Line parsers resolve their delimiter / header / column names from the first
    ~100-200 non-blank lines. A worker holding bytes from the middle of the file has none of that, so
    every chunk is prefixed with the file's HEAD and the worker discards the records the head produces.
    The parent parses the head itself and contributes those records, so the file is covered exactly once
    and every worker warms up on identical text. This needs no per-parser support beyond the
    ``chunkable`` flag.
  * **Chunk boundaries** are snapped forward to a newline, and (for quote-aware parsers) to a newline
    with an even running count of ``"`` so a multi-line quoted CSV record is never split.
  * **Timestamps.** ``_normalize`` forward-fills missing timestamps across the whole file. A chunk can
    only fill its own; it reports how many LEADING records it could not fill plus its first/last known
    timestamp, and ``merge_batches`` carries the fill across the seam. Same for the clock-skew estimate.

Bounded memory: chunks are small (``CHUNK_BYTES``) and only ``workers + 2`` are ever in flight, so N
workers never hold N copies of the file. Results are consumed strictly in order and released as they go.

Everything degrades to the single-worker path: small file, a parser that is not ``chunkable``, a head
that is too short to warm a parser on, ``IRIS_PARSE_WORKERS=1``, or a process pool that will not start
(restricted spawn, no fork available) all just return None from ``plan_parallel``.
"""
from __future__ import annotations

import copy
import os
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from multiprocessing import get_context
from typing import Callable, Iterable, Optional

from ..models import Event
from ..normalize import extract_entities, infer_severity, to_iso
from .base import BaseParser, ParsedEvent

UTC = timezone.utc

# Lines of the file every worker is warmed up on. Must comfortably exceed the biggest per-parser
# warm-up buffer (DelimitedParser reads 200 non-blank lines, CsvParser 100).
HEAD_LINES = 400
HEAD_MAX_BYTES = 4 * 1024 * 1024
# Small chunks on purpose: a chunk's events live in the worker AND as a pickled blob in flight, so the
# chunk size is what bounds the transient memory of the parallel path (~27x the chunk in Event objects).
CHUNK_BYTES = 4 * 1024 * 1024
# Below this the process startup + pickle round trip costs more than the parse it saves.
MIN_PARALLEL_BYTES = 32 * 1024 * 1024
MAX_WORKERS = 6


# --------------------------------------------------------------------------- worker priority
def background_worker_init() -> None:
    """Runs in every spawned worker before it takes work: drop its scheduling priority.

    Measured on the analyst's machine during a 44 MB ingest: `GET /api/health` — which touches nothing —
    took 7.2 s and 3.3 s at the moments six spawn workers were starting up and parsing flat out. That is
    not lock contention, it is CPU starvation: the parse and graph pools sized themselves to
    `cpu_count - 1` at normal priority, and uvicorn's one process competed for time slices with six
    saturated interpreters. The API must win that contest every time — a parse that finishes 10 % later
    is invisible; a UI that freezes for seven seconds is "the app locked up".

    `os.nice` is a no-op on Windows (no such call); there the pool size cap does the work.
    """
    try:
        os.nice(10)  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        pass
    try:
        # Windows: BELOW_NORMAL_PRIORITY_CLASS via psutil when it is around (it is a base requirement)
        import psutil  # noqa: PLC0415
        p = psutil.Process()
        if hasattr(psutil, "BELOW_NORMAL_PRIORITY_CLASS"):
            p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
    except Exception:  # noqa: BLE001
        pass


def default_worker_count(cap: int) -> int:
    """Leave TWO logical cores to the parent: one for the request thread, one for the parent's own
    share of the work (unpickling results, merging). `cpu_count - 1` left uvicorn fighting the workers
    for the last core, and it lost."""
    return max(1, min(cap, (os.cpu_count() or 2) - 2))


def parallel_workers() -> int:
    """How many parse workers to use. 1 (or 0) disables the parallel path entirely.

    Sized by `resources.profile()` from the cores this process may use and the memory it has — the
    old `MAX_WORKERS = 6` was one host's measurement and left a 50-core machine running six."""
    env = os.environ.get("IRIS_PARSE_WORKERS", "").strip()
    if env:
        try:
            return max(0, int(env))
        except ValueError:
            pass
    try:
        from ..resources import profile
        return profile().parseWorkers
    except Exception:
        return default_worker_count(MAX_WORKERS)


def min_parallel_bytes() -> int:
    return _mb_env("IRIS_PARSE_MIN_MB", MIN_PARALLEL_BYTES)


def chunk_bytes() -> int:
    return max(64 * 1024, _mb_env("IRIS_PARSE_CHUNK_MB", CHUNK_BYTES))


def _mb_env(name: str, default: int) -> int:
    env = os.environ.get(name, "").strip()
    if env:
        try:
            return max(0, int(float(env) * 1024 * 1024))
        except ValueError:
            pass
    return default


# --------------------------------------------------------------------------- normalization batching
@dataclass
class Batch:
    """One slice of a file, normalized. Ids are blank — the parent assigns them over the whole file."""
    events: list[Event]
    lead_blank: int = 0                     # leading events whose timestamp the chunk could not fill
    first_ts: Optional[datetime] = None     # first KNOWN timestamp in the chunk
    last_ts: Optional[datetime] = None      # last known timestamp (carried across the seam)
    max_back: float = 0.0                   # largest backward jump inside the chunk, seconds
    unmapped: int = 0
    nbytes: int = 0                         # source bytes this chunk covered (progress accounting)


# Strings shorter than this are shared; longer ones are assumed unique (a URL, a user agent) and
# sharing them costs a dict entry to save nothing.
_SHARE_MAX_LEN = 64


def _shared(v: str, cache: dict[str, str]) -> str:
    """The canonical instance of `v` within this batch, so repeats cost a pointer instead of an object."""
    got = cache.get(v)
    if got is None:
        cache[v] = got = v
    return got


def normalize_batch(parsed: list[ParsedEvent], sid: str, filename: str, family: str) -> Batch:
    """ParsedEvents -> Events for ONE slice. `parsed` is consumed entry by entry (see below)."""
    n = len(parsed)
    times: list[Optional[datetime]] = [None] * n
    last: Optional[datetime] = None
    for i in range(n):
        t = parsed[i].ts
        if t is not None:
            last = t
        times[i] = last
    lead_blank = 0
    while lead_blank < n and times[lead_blank] is None:
        lead_blank += 1
    first_ts = times[lead_blank] if lead_blank < n else None
    last_ts = times[n - 1] if n else None
    # Skew estimate: the largest backward jump. The leading blank run is skipped because every one of
    # those records ends up at the same filled value, which is also times[lead_blank] — no jump there.
    max_back = 0.0
    prev: Optional[datetime] = None
    for i in range(lead_blank, n):
        t = times[i]
        if prev is not None and t is not None and t < prev:
            back = (prev - t).total_seconds()
            if back > max_back:
                max_back = back
        prev = t

    unmapped = 0
    # One entry per DISTINCT string in this batch. Scoped to the batch, never `sys.intern`:
    # interning is immortal, and a high-cardinality column (a URL, a request id) would then be a leak.
    shared: dict[str, str] = {}
    events: list[Event] = []
    for i in range(n):
        pe = parsed[i]
        # release each ParsedEvent as soon as it becomes an Event: holding the parser's output AND the
        # normalized events for a whole file doubled peak RSS on a big upload
        parsed[i] = None  # type: ignore[call-overload]
        if "parse_error" in pe.fields:
            unmapped += 1
        t = times[i]
        # Shared for the same reason as the fields: a log has a handful of hosts and accounts and it
        # repeats them on every line, and the entities extracted from those lines (addresses, users,
        # domains) repeat just as hard. Each unshared repeat is a fresh string object — ~49 bytes of
        # header before a single character of content.
        host = _shared(pe.host, shared) if pe.host else ""
        user = _shared(pe.user, shared) if pe.user else ""
        ents = [_shared(e, shared) if len(e) <= _SHARE_MAX_LEN else e for e in extract_entities(pe)]
        for ent in (host, user):
            if ent and ent not in ents and ent not in ("-", "—"):
                ents.append(ent)
        # `fields`/`entities` are passed as None when empty so the Event shares the frozen empty
        # containers instead of allocating a dict and a list per log line (models.py, rule 1).
        #
        # And the strings inside are SHARED. Every row of a CSV repeats the same column names, and a
        # log's interesting columns are mostly low-cardinality — method, status, action, verdict,
        # category, device, policy. Without sharing, one million rows of a 20-column proxy export
        # allocate twenty million string objects that are mostly the same handful of values, at ~49
        # bytes of object header each before the characters. Measured on a 20-column corpus: 3,377
        # bytes per event, of which the fields are the bulk.
        fields = {}
        for k, v in pe.fields.items():
            if v is None or v == "":
                continue
            fields[_shared(k, shared)] = _shared(v, shared) if len(v) <= _SHARE_MAX_LEN else v
        events.append(Event(
            id="", ts=(to_iso(t) if t is not None else ""), source=family, sourceId=sid, file=filename,
            host=host, user=user, msg=pe.msg or pe.raw[:200], sev=infer_severity(pe),  # type: ignore[arg-type]
            raw=pe.raw, fields=fields or None, entities=ents or None,
        ))
    return Batch(events=events, lead_blank=lead_blank, first_ts=first_ts, last_ts=last_ts,
                 max_back=max_back, unmapped=unmapped)


def merge_batches(batches: Iterable[Batch]) -> tuple[list[Event], Optional[float], int]:
    """Stitch chunks back into one file: fill timestamps across the seams, total the skew and the
    unmapped count. Ids are NOT assigned here — that needs the store's counter."""
    all_rows = list(batches)
    rows = [b for b in all_rows if b.events]
    # an empty chunk still carries its parse_error tally
    unmapped = sum(b.unmapped for b in all_rows if not b.events)
    if not rows:
        return [], None, unmapped
    # A file with NO parseable timestamp anywhere used to have every event stamped `datetime.now()` —
    # the moment of INGEST, presented as the moment of the event. Leaving it blank is the honest answer:
    # `ts=""` renders as "no timestamp" and sorts last, and nothing downstream may claim otherwise.
    global_first = next((b.first_ts for b in rows if b.first_ts is not None), None)
    events: list[Event] = []
    max_back = 0.0
    carry: Optional[datetime] = None
    for b in rows:
        fill = carry if carry is not None else global_first
        if b.lead_blank and fill is not None:
            # forward-fill across a chunk seam is a REAL timestamp from this same file (a stack trace
            # continues the line above it). With no real timestamp anywhere, `fill` is None and the
            # events stay unstamped rather than being given the ingest clock.
            stamp = to_iso(fill)
            for ev in b.events[:b.lead_blank]:
                ev.ts = stamp
        eff_first = b.first_ts if (b.lead_blank == 0 and b.first_ts is not None) else fill
        eff_last = b.last_ts if b.last_ts is not None else fill
        if carry is not None and eff_first is not None and eff_first < carry:
            max_back = max(max_back, (carry - eff_first).total_seconds())
        if b.max_back > max_back:
            max_back = b.max_back
        carry = eff_last
        events.extend(b.events)
        unmapped += b.unmapped
        b.events = []  # release the chunk's reference as we go
    return events, (max_back if max_back > 0 else None), unmapped


# ------------------------------------------------------------------------------------- chunking
def _head_slice(data: bytes) -> Optional[tuple[int, int]]:
    """(end offset of the warm-up head, non-blank lines it holds), or None if the file is too short.

    The head must contain at least HEAD_LINES non-blank lines within HEAD_MAX_BYTES, otherwise a worker
    in the middle of the file would warm up on less text than the head-only parse did and could resolve
    a different delimiter or header.
    """
    lines = 0
    pos = 0
    limit = min(len(data), HEAD_MAX_BYTES)
    while pos < limit and lines < HEAD_LINES:
        nl = data.find(b"\n", pos)
        if nl < 0:
            return None
        if data[pos:nl].strip():
            lines += 1
        pos = nl + 1
    return (pos, lines) if lines >= HEAD_LINES else None


def _chunk_ranges(data: bytes, start: int, size: int, quoted: bool) -> list[tuple[int, int]]:
    """Byte ranges from `start` to EOF, each ending just after a newline.

    `quoted` also requires an EVEN running count of double quotes at the boundary, so a CSV record with
    an embedded newline inside a quoted cell is never cut in half.
    """
    out: list[tuple[int, int]] = []
    n = len(data)
    pos = start
    odd = bool(data.count(b'"', 0, start) % 2) if quoted else False
    while pos < n:
        want = min(n, pos + size)
        end = want
        while True:
            if end >= n:
                end = n
                break
            nl = data.find(b"\n", end)
            if nl < 0:
                end = n
                break
            end = nl + 1
            if not quoted:
                break
            if not (odd ^ bool(data.count(b'"', pos, end) % 2)):
                break
        if quoted:
            odd = odd ^ bool(data.count(b'"', pos, end) % 2)
        out.append((pos, end))
        pos = end
    return out


# ------------------------------------------------------------------------------------- the workers
def _run_chunk(parser: BaseParser, head: str, chunk: bytes, skip: int, sid: str, filename: str,
               family: str, nbytes: int) -> Batch:
    """Worker entry point. Warms `parser` on `head`, discards the `skip` records the head produces and
    normalizes the rest. Module level and picklable so it works under `spawn` (Windows AND Linux)."""
    text = head + chunk.decode("utf-8", errors="replace")
    parsed: list[ParsedEvent] = []
    for i, pe in enumerate(parser.parse(text.splitlines())):
        if i >= skip:
            parsed.append(pe)
    del text
    batch = normalize_batch(parsed, sid, filename, family)
    batch.nbytes = nbytes
    return batch


def parse_whole(path, member: str, parser: BaseParser, sid: str, filename: str, family: str) -> list:
    """WORKER ENTRY POINT: parse one WHOLE small file and return its normalized batches.

    The chunked path above splits a big file across processes. This is the other shape of the
    problem: a queue of many small files, each parsed in a second, one after another on the single
    enrichment worker — pure-Python, GIL-bound, so threads could not help and the queue drained one
    core wide. Here each small file IS the unit of work: one process per file, the parent only
    commits. The bytes are read here, in the worker, so the parent never holds them.
    """
    from pathlib import Path as _P
    from . import archives
    p = _P(path)
    data = archives.read_member(p, member) if member else p.read_bytes()
    parsed = list(parser.parse_bytes(data))
    del data
    return [normalize_batch(parsed, sid, filename, family)]


@dataclass
class Plan:
    parser: BaseParser              # a pristine copy for the workers
    head: str                       # warm-up text, ends on a line boundary
    head_records: int               # records the head alone produces (workers drop these)
    ranges: list[tuple[int, int]]   # chunk byte ranges after the head
    workers: int


def prepare(parser: BaseParser, data: bytes) -> Optional[tuple[Plan, list[ParsedEvent], int]]:
    """Decide whether this file is worth parsing in parallel, and set it up.

    Returns (plan, the records the HEAD produced, head byte length) or None for "use one worker". The
    head is parsed with the CALLER's parser instance, which both warms it (the store reads
    `guessed`/`delimiter` off it afterwards, exactly as in the single-worker path) and gives the exact
    number of records every worker has to discard from its own head-prefixed chunk.
    """
    workers = parallel_workers()
    if workers < 2 or not getattr(parser, "chunkable", False) or len(data) < min_parallel_bytes():
        return None
    head = _head_slice(data)
    if head is None:
        return None
    head_end, _ = head
    ranges = _chunk_ranges(data, head_end, chunk_bytes(), bool(getattr(parser, "quoted", False)))
    if len(ranges) < 2:
        return None
    try:
        pristine = copy.deepcopy(parser)   # copied BEFORE the head parse, so workers start where it did
    except Exception:
        return None
    _reset_parser(pristine)
    head_text = data[:head_end].decode("utf-8", errors="replace")
    head_parsed = list(parser.parse(head_text.splitlines()))
    plan = Plan(parser=pristine, head=head_text, head_records=len(head_parsed), ranges=ranges,
                workers=min(workers, len(ranges)))
    return plan, head_parsed, head_end


def _reset_parser(parser: BaseParser) -> None:
    """Undo the warm-up state a head parse leaves behind, so every worker starts where chunk 0 did.

    Only touches attributes the line parsers set during `parse()`; an explicit mapping/delimiter the
    ANALYST supplied is passed in through the constructor and lives on `mapping`, which is left alone.
    """
    if getattr(parser, "mapping", None) is None:
        for attr in ("delimiter", "header"):
            if hasattr(parser, attr):
                setattr(parser, attr, None)
    if hasattr(parser, "guessed"):
        parser.guessed = []


def run_parallel(plan: Plan, data: bytes, sid: str, filename: str, family: str,
                 progress: Optional[Callable[[int], None]] = None) -> Optional[list[Batch]]:
    """Parse `data` chunk-wise across processes. Returns batches in FILE ORDER, or None if the pool
    could not be started (restricted environment) — the caller then falls back to one worker.

    Only `workers + 2` chunks are ever in flight, so the transient memory is bounded by the chunk size
    and not by the size of the file.
    """
    try:
        ctx = get_context("spawn")   # fork is not available on Windows and unsafe next to threads
        pool = ProcessPoolExecutor(max_workers=plan.workers, mp_context=ctx, initializer=background_worker_init)
    except Exception:
        return None
    ranges = plan.ranges
    out: list[Batch] = []
    inflight: list = []
    nxt = 0
    window = plan.workers + 2
    try:
        while nxt < len(ranges) and len(inflight) < window:
            s, e = ranges[nxt]
            inflight.append(pool.submit(_run_chunk, plan.parser, plan.head, data[s:e], plan.head_records,
                                        sid, filename, family, e - s))
            nxt += 1
        while inflight:
            batch = inflight.pop(0).result()
            out.append(batch)
            if progress is not None:
                progress(batch.nbytes)
            if nxt < len(ranges):
                s, e = ranges[nxt]
                inflight.append(pool.submit(_run_chunk, plan.parser, plan.head, data[s:e], plan.head_records,
                                            sid, filename, family, e - s))
                nxt += 1
    except Exception:
        for f in inflight:
            f.cancel()
        pool.shutdown(wait=False, cancel_futures=True)
        return None
    finally:
        pool.shutdown(wait=True)
    return out
