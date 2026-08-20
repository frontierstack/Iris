"""Multi-process entity extraction for the graph build.

`graph.extract()` is 75-85 % of the graph build (measured: 31.4 s of a 37.0 s build over 200 k events)
and it is regex + string slicing over Python objects — it does not vectorise and it will never move to
a GPU. Threads cannot help either: it is pure-Python and CPU bound behind the GIL. The only remaining
lever is more interpreters, which is what this module is.

Three things make that safe and worth doing, and all three are load bearing.

**Process start = `spawn`, everywhere.** The graph build runs on a daemon background thread
(`derived.AsyncCache`), which is the worst possible place to call `fork()`: fork duplicates only the
calling thread, so any lock another thread holds at that instant — the allocator's, logging's,
`STORE.lock` — is inherited *locked* and the child deadlocks on the first allocation. `spawn` starts a
fresh interpreter through `fork+exec`, so there is no inherited lock state to deadlock on, and it is
the only method Windows has. `forkserver` would also be lock-safe (its server is exec'd from a clean
state) but it buys nothing here: its server is a fresh interpreter too, so it cannot inherit the event
pool either, and it would be a Linux-only second code path. Plain `fork` is rejected for a second,
independent reason: "inheriting" 1.2 M `Event` objects copy-on-write is a fiction, because reading them
touches every refcount and therefore copies nearly every page — six workers would each grow toward a
private copy of a 1.2 GiB pool.

**Data transfer = pickled column rows, not `Event`s.** Workers cannot inherit the pool, and pickling
1.2 M pydantic `Event`s is prohibitive (~15 s per million on the receiving side alone, and it doubles
the pool's memory). Instead each chunk is packed into plain tuples of exactly the attributes extraction
reads — `ts, sev, source, file, host, user, msg, raw, fields, detection ids, id` — which pickle at C
speed because they are `str`/`dict`/`list` and nothing else. Measured: 0.8 s to pack + 0.5 s to unpack
200 k events, against 31.4 s of extraction for the same events — under 3 % overhead, and the pack runs
on the parent while the workers are busy, so most of it is hidden. That is also why this module does
NOT use `multiprocessing.shared_memory`: the measured cost is the Python-level packing, not the byte
transfer, so a shared block would remove ~0.2 s of memcpy while adding an offset index, a second copy
of `search.py`'s machinery, and a named OS resource that leaks when a worker is killed.

**Output is byte-identical.** Workers run `graph.aggregate` — the *same* function the serial path runs,
for the same reason `parsers/parallel.normalize_batch` is shared — over their chunk with the pool
offset applied, and hand back a compact partial graph. `_merge` folds partials in CHUNK ORDER, which
reproduces the serial result exactly: dict insertion order (which the node ranking's positional
tie-break, `Counter.most_common` ties and the neighbour ordering all depend on), `first`/`last`,
the strictly-greater severity rule, the per-node first-200 / last-200 event index buffers, and the
first-20 event ids per edge. `tests/test_graph_parallel.py` compares the two node by node and relation
by relation over a randomised corpus.

Everything degrades to the in-process build: a pool that will not start (a sandbox with no
subprocesses, no fork available), a worker that dies, a timeout, an unpicklable payload — every one of
them makes `build()` return False with the caller's `nodes`/`edges` untouched, and the reason is
logged once. `IRIS_GRAPH_WORKERS=1` disables the whole path.
"""
from __future__ import annotations

import os
import sys
import time
from array import array
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import get_context
from typing import Any, Callable, Optional

from .derived import BuildCancelled
from .models import SEV_ORDER

# Events per chunk. Small enough that `workers + 2` chunks in flight is bounded memory (~30 MiB of
# packed bytes) and that a straggler cannot hold up the merge for long; large enough that the fixed
# per-task cost (pickle round trip, dispatch) stays noise next to ~4 s of extraction.
CHUNK_EVENTS = 25_000
# Below this the pool startup (a fresh interpreter per worker, ~0.5-1.5 s) costs more than it saves.
MIN_PARALLEL_EVENTS = 50_000
MAX_WORKERS = 6
# A chunk is ~4 s of work. This bound exists only so a wedged worker cannot hang the build thread
# forever; hitting it is a fallback to the serial path, never a failed graph.
CHUNK_TIMEOUT = 300.0

_HEAD = 200        # must equal graph._HEAD / graph._TAIL — asserted in build()
_TAIL = 200

_reported: set[str] = set()


# The store version moved while this build was running, so its result can never be served. Shared with
# derived.AsyncCache, which turns it into "drop the status quietly" rather than "this build crashed".
GraphBuildCancelled = BuildCancelled


def _log_once(reason: str) -> None:
    if reason not in _reported:
        _reported.add(reason)
        print(f"[iris] graph: parallel extraction unavailable ({reason}); using the in-process build",
              file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- configuration
def workers() -> int:
    """How many extraction workers. 1 (or 0) disables the parallel path entirely."""
    env = os.environ.get("IRIS_GRAPH_WORKERS", "").strip()
    if env:
        try:
            return max(0, int(env))
        except ValueError:
            pass
    from .parsers.parallel import default_worker_count
    return default_worker_count(MAX_WORKERS)


def chunk_events() -> int:
    env = os.environ.get("IRIS_GRAPH_CHUNK", "").strip()
    if env:
        try:
            return max(1_000, int(env))
        except ValueError:
            pass
    return CHUNK_EVENTS


def min_parallel_events() -> int:
    env = os.environ.get("IRIS_GRAPH_PARALLEL_MIN", "").strip()
    if env:
        try:
            return max(0, int(env))
        except ValueError:
            pass
    return MIN_PARALLEL_EVENTS


def should_parallelise(n: int) -> bool:
    w = workers()
    return w >= 2 and n >= min_parallel_events() and n >= 2 * chunk_events()


# --------------------------------------------------------------------------- the wire format
class _Det:
    """Stand-in for `models.Detection` — `extract()` reads `.id`, `aggregate()` reads the count."""
    __slots__ = ("id",)

    def __init__(self, i: str) -> None:
        self.id = i


class _Row:
    """Attribute-compatible stand-in for an `Event`, holding only what extraction/aggregation read."""
    __slots__ = ("ts", "sev", "source", "file", "host", "user", "msg", "raw", "fields", "detections", "id")

    def __init__(self, ts: str, sev: str, source: str, file: str, host: str, user: str, msg: str,
                 raw: str, fields: dict, dets: list, eid: str) -> None:
        self.ts = ts
        self.sev = sev
        self.source = source
        self.file = file
        self.host = host
        self.user = user
        self.msg = msg
        self.raw = raw
        self.fields = fields
        self.detections = [_Det(d) for d in dets] if dets else []
        self.id = eid


def pack(events: list, start: int, end: int) -> list:
    """One chunk of the pool as plain tuples. `str`/`dict`/`list` only, so the pickle is C-speed."""
    return [(e.ts, e.sev, e.source, e.file, e.host, e.user, e.msg, e.raw, e.fields,
             [d.id for d in e.detections], e.id) for e in events[start:end]]


def extract_chunk(rows: list, base: int) -> tuple:
    """WORKER ENTRY POINT. Module level and picklable so it works under `spawn` (Windows and Linux).

    Runs `graph.aggregate` — the same function the serial build runs — over the chunk, then flattens the
    aggregates into a compact partial. Node ids are interned into `ids` and edges reference them by
    index, because the id strings are the bulk of the payload and every edge repeats two of them.
    """
    from . import graph

    nodes: dict[str, Any] = {}
    edges: dict[tuple[str, str, str], Any] = {}
    graph.aggregate((_Row(*r) for r in rows), nodes, edges, base)

    ids = list(nodes)
    pos = {i: k for k, i in enumerate(ids)}
    node_rows = []
    for i in ids:
        n = nodes[i]
        head = n.events
        if n.count <= _HEAD:
            tail_b = b""                     # identical to the head; do not send it twice
        else:
            rec = n.recent()                 # ascending; its last _TAIL entries are this chunk's tail
            tail_b = array("i", rec[-_TAIL:]).tobytes()
        node_rows.append((n.type, n.value, n.label, n.count, n.first, n.last, n.sev, n.detections,
                          head.tobytes(), tail_b, n.srcs, n.files))
    def ref(i: str) -> int:
        """Intern an edge endpoint. Every endpoint is a node this chunk also produced, but `graph.py`'s
        own edge-array pass guards the same lookup, so this one does too: an unexpected KeyError here
        would show up only as a silent fall back to the serial build."""
        k = pos.get(i)
        if k is None:
            k = pos[i] = len(ids)
            ids.append(i)         # past len(node_rows): an intern-table entry with no node of its own
        return k

    edge_rows = [(ref(s), ref(t), k, e.count, e.first, e.last, e.sev, e.outcomes, e.why, e.events, e.files)
                 for (s, t, k), e in edges.items()]
    return ids, node_rows, edge_rows


# --------------------------------------------------------------------------- deterministic merge
def _merge(partial: tuple, nodes: dict, edges: dict) -> None:
    """Fold one partial into the running graph. Called in CHUNK ORDER — that is the whole correctness
    argument, so the caller may never reorder or interleave partials.

    `first`/`last` are min/max (which is exactly what the serial `if </elif >` pair computes, because
    `first <= last` always holds); severity keeps the FIRST value to reach the highest rank, which the
    strictly-greater test reproduces when partials arrive in order; `srcs`/`files` keep global
    first-seen key order, which `Counter.most_common` ties depend on.

    The per-node event buffers are rebuilt rather than replayed: `events` accumulates the first _HEAD
    pool indices and `tail` is used as a rolling window of the most recent _TAIL, then `_finalise`
    turns that window back into the exact ring `_NodeAgg.add` would have left.
    """
    from .graph import _EdgeAgg, _NodeAgg

    ids, node_rows, edge_rows = partial
    # `ids` is the chunk's intern table and may be LONGER than `node_rows` (see `ref`), so walk the rows.
    for k, row in enumerate(node_rows):
        i = ids[k]
        (t, v, label, cnt, first, last, sev, dets, head_b, tail_b, srcs, files) = row
        head = array("i")
        head.frombytes(head_b)
        if tail_b:
            tail = array("i")
            tail.frombytes(tail_b)
        else:
            tail = head
        n = nodes.get(i)
        if n is None:
            n = nodes[i] = _NodeAgg(t, v, label, first, last)
            n.count = cnt
            n.sev = sev
            n.detections = dets
            n.srcs = srcs
            n.files = files
            n.events = array("i", head[:_HEAD])
            n.tail = array("i", tail[-_TAIL:])
        else:
            n.count += cnt
            if first < n.first:
                n.first = first
            if last > n.last:
                n.last = last
            if SEV_ORDER.get(sev, 0) > SEV_ORDER.get(n.sev, 0):
                n.sev = sev
            n.detections += dets
            ns = n.srcs
            for s, c in srcs.items():
                ns[s] = ns.get(s, 0) + c
            nf = n.files
            for f, c in files.items():
                nf[f] = nf.get(f, 0) + c
            room = _HEAD - len(n.events)
            if room > 0:
                n.events.extend(head[:room])
            if len(tail) >= _TAIL:
                n.tail = array("i", tail[-_TAIL:])
            else:
                n.tail.extend(tail)
                if len(n.tail) > _TAIL:
                    n.tail = n.tail[-_TAIL:]
    for (ui, vi, kind, cnt, first, last, sev, outcomes, why, evs, files) in edge_rows:
        s, t = ids[ui], ids[vi]
        key = (s, t, kind)
        ed = edges.get(key)
        if ed is None:
            ed = edges[key] = _EdgeAgg(s, t, kind, first, last)
            ed.count = cnt
            ed.sev = sev
            ed.outcomes = outcomes
            ed.why = why
            ed.events = evs[:20]
            ed.files = set(files)
            continue
        ed.count += cnt
        if first < ed.first:
            ed.first = first
        if last > ed.last:
            ed.last = last
        if SEV_ORDER.get(sev, 0) > SEV_ORDER.get(ed.sev, 0):
            ed.sev = sev
        ed.files |= files
        eo = ed.outcomes
        for o, c in outcomes.items():
            eo[o] = eo.get(o, 0) + c
        ew = ed.why
        for w, c in why.items():
            ew[w] = ew.get(w, 0) + c
        room = 20 - len(ed.events)
        if room > 0:
            ed.events.extend(evs[:room])


def _finalise(nodes: dict) -> None:
    """Turn each node's rolling last-_TAIL window back into the ring `_NodeAgg.add` would have built.

    After C occurrences the serial builder holds: `events` = the first min(C, _HEAD) indices; `tail` =
    empty for C <= _HEAD, the next C - _HEAD indices (write cursor still 0) for C <= _HEAD + _TAIL, and
    otherwise a full ring whose cursor sits at (C - _HEAD) % _TAIL. `recent()` must come back identical,
    because `node_detail` reads it.
    """
    for n in nodes.values():
        c = n.count
        window = n.tail                       # the global last min(C, _TAIL) indices, ascending
        if c <= _HEAD:
            n.tail = array("i")
            n.ti = 0
        elif c <= _HEAD + _TAIL:
            n.tail = array("i", window[-(c - _HEAD):])
            n.ti = 0
        else:
            ti = (c - _HEAD) % _TAIL
            cut = _TAIL - ti
            n.tail = array("i", window[cut:])
            n.tail.extend(window[:cut])
            n.ti = ti


# --------------------------------------------------------------------------- the driver
def build(events: list, nodes: dict, edges: dict,
          progress: Optional[Callable[[int], None]] = None,
          cancelled: Optional[Callable[[], bool]] = None) -> bool:
    """Extract `events` across processes into `nodes`/`edges`. False = "did nothing, build serially".

    `nodes`/`edges` are only written once every chunk has come back, so a mid-flight failure leaves the
    caller exactly as it found it and the serial path can just run.

    The caller's `events` list is read but never mutated, and nothing here touches `STORE` — the store
    lock is not held by this thread and must not be taken on it while workers are dispatched.
    """
    from .graph import _HEAD as G_HEAD, _TAIL as G_TAIL

    assert (_HEAD, _TAIL) == (G_HEAD, G_TAIL), "graph_parallel head/tail must track graph.py"
    n = len(events)
    w = min(workers(), max(1, (n + chunk_events() - 1) // chunk_events()))
    if w < 2:
        return False
    step = chunk_events()
    bounds = [(s, min(s + step, n)) for s in range(0, n, step)]
    try:
        ctx = get_context("spawn")            # never fork: this runs on a daemon background thread
        from .parsers.parallel import background_worker_init
        pool = ProcessPoolExecutor(max_workers=w, mp_context=ctx, initializer=background_worker_init)
    except Exception as exc:
        _log_once(f"{type(exc).__name__}: {exc}")
        return False

    # Merge into LOCAL dicts, chunk by chunk as the results arrive: holding every partial until the end
    # would keep ~50 copies of the node set alive at 1.2 M events, and the merge overlaps with the
    # workers this way. They are handed to the caller only once the whole run succeeded — a half-merged
    # graph plus the serial rebuild that follows a failure would double every count.
    m_nodes: dict = {}
    m_edges: dict = {}
    inflight: list = []
    nxt = 0
    window = w + 2
    t0 = time.perf_counter()
    done_events = 0
    try:
        while nxt < len(bounds) and len(inflight) < window:
            s, e = bounds[nxt]
            inflight.append((pool.submit(extract_chunk, pack(events, s, e), s), e - s))
            nxt += 1
        while inflight:
            if cancelled is not None and cancelled():
                raise GraphBuildCancelled()
            fut, size = inflight.pop(0)
            _merge(fut.result(timeout=CHUNK_TIMEOUT), m_nodes, m_edges)   # strictly in chunk order
            done_events += size
            if progress is not None:
                progress(done_events)
            if nxt < len(bounds):
                s, e = bounds[nxt]
                inflight.append((pool.submit(extract_chunk, pack(events, s, e), s), e - s))
                nxt += 1
    except GraphBuildCancelled:
        _shutdown(pool, inflight)
        raise
    except BaseException as exc:
        _shutdown(pool, inflight)
        _log_once(f"{type(exc).__name__}: {exc}")
        return False
    pool.shutdown(wait=True)

    _finalise(m_nodes)
    nodes.update(m_nodes)     # both are empty here, so `update` keeps the merge's insertion order
    edges.update(m_edges)
    if os.environ.get("IRIS_GRAPH_TIMING"):
        print(f"[iris] graph: parallel extraction {n:,} events, {w} workers, "
              f"{len(bounds)} chunks in {time.perf_counter() - t0:.1f}s", file=sys.stderr, flush=True)
    return True


def _shutdown(pool: ProcessPoolExecutor, inflight: list) -> None:
    """Tear the pool down without waiting. A cancelled or failed build must not leave workers burning
    CPU on chunks whose result can never be used."""
    for fut, _ in inflight:
        fut.cancel()
    try:
        pool.shutdown(wait=False, cancel_futures=True)
    except Exception:
        pass
