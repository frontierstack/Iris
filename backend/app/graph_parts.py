"""Entity-graph extraction PER SOURCE, with each source's partial graph cached — so a rebuild costs the
sources that changed, not the whole pool.

The graph used to be rebuilt from scratch on every version bump: every source re-extracted, all
13.8 M events on the analyst's workspace, 10-35 minutes with six workers pinned and the VM swapping.
But `graph.aggregate` is a FOLD — nodes and edges accumulate — and `graph_parallel._merge` already
knew how to combine partial graphs. The only thing stopping "extract just what changed" was that the
partials were cut by POOL POSITION (25 k-event chunks of a timestamp-sorted pool, every source
interleaved), so no partial belonged to any source and none could be kept.

Here the unit of extraction is the SOURCE. Each source's events are extracted (in chunks, across
workers when memory allows) into one partial keyed on that source's content signature, saved under
`cache/graph-parts/`, and the graph is the fold of every source's partial in `source_order`. A new
file arriving into a 13.8 M-event pool then costs extraction of THAT FILE; the other partials load in
milliseconds. This is the same principle that took the detection catalogue off the commit path: do the
work proportional to what changed.

Two representation decisions make a cached partial legal across pool versions:

  * **Event references are IDS, never pool indices.** A swap re-sorts the pool and every index moves;
    ids do not (`graph_store` learned this first). Partials carry id lists; indices are resolved once,
    at the final fold, against the live `event_index`, and anything that no longer resolves is dropped.
  * **The per-node head/tail are re-derived at the final fold, not replayed.** The serial build kept
    the first `_HEAD` and last `_TAIL` pool indices of each node in encounter order. The global first
    200 of a node's events is a subset of the union of its per-source first-200s (an event among the
    global first 200 is within its own source's first 200), so the fold unions the heads, resolves to
    indices, and keeps the 200 smallest; likewise the 200 largest for the tail window, which
    `_finalise` turns into the ring `_NodeAgg.add` would have built. Edge `events` (first 20) the
    same way.

What this changes about the graph, deliberately: node insertion order is now "source order, then
first appearance within the source" instead of "first appearance in timestamp order". The ranking's
positional tie-break among otherwise-equal nodes can therefore differ from a from-scratch build of the
old code. It is deterministic for a given pool and identical between the in-process and multi-process
paths, which is the property that matters (a graph that changes shape with the worker count is a bug).

Workers are sized from FREE MEMORY, not just CPU count. Each spawn worker imports the app (~250 MB)
before it does anything; six of them started into a VM with 190 MB free was the "entity graph locks
everything up" — not a lock, swap. Under memory pressure this degrades to fewer workers, then to
in-process extraction: slower, but the API keeps answering and the process stays alive.
"""
from __future__ import annotations

import os
import sys
import time
from array import array
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import get_context
from typing import Any, Callable, Iterable, Optional

import numpy as np

from .models import SEV_ORDER

# Approximate resident cost of one spawn worker once the app is imported, plus a chunk in flight.
WORKER_MB = 300
# Never let the workers eat the last of the machine: keep this much free for the API and the parent.
RESERVE_MB = 1024
MAX_WORKERS = 6
CHUNK_EVENTS = 25_000
CHUNK_TIMEOUT = 300.0
# Extract in-process below this many events in the source — a process round trip is not worth it.
MIN_PARALLEL_EVENTS = 50_000


def _log(msg: str) -> None:
    print(f"[iris] graph: {msg}", file=sys.stderr, flush=True)


_reported: set = set()


def _log_once(reason: str) -> None:
    """The fallback to in-process extraction is a supported mode, not an error — but a silent downgrade
    on a machine with a GPU and six cores reads as "the graph is slow for no reason". Once per reason."""
    if reason not in _reported:
        _reported.add(reason)
        _log(f"parallel extraction unavailable ({reason}); extracting in-process")


def _int_env(name: str, default: int, floor: int = 0) -> int:
    raw = os.environ.get(name, "").strip()
    if raw:
        try:
            return max(floor, int(raw))
        except ValueError:
            pass
    return default


def chunk_events() -> int:
    return _int_env("IRIS_GRAPH_CHUNK", CHUNK_EVENTS, 1_000)


def min_parallel_events() -> int:
    return _int_env("IRIS_GRAPH_PARALLEL_MIN", MIN_PARALLEL_EVENTS, 0)


def workers_by_memory(cap: int) -> int:
    """How many workers the machine can actually hold RIGHT NOW. Without psutil, `cap`."""
    try:
        import psutil
        avail_mb = psutil.virtual_memory().available // (1 << 20)
    except Exception:
        return cap
    room = (avail_mb - RESERVE_MB) // WORKER_MB
    return max(0, min(cap, int(room)))


def workers() -> int:
    """Extraction workers: the env pin, else CPU-derived and then capped by free memory. 0/1 = in-process."""
    env = os.environ.get("IRIS_GRAPH_WORKERS", "").strip()
    if env:
        try:
            return max(0, int(env))
        except ValueError:
            pass
    from .parsers.parallel import default_worker_count
    return workers_by_memory(default_worker_count(MAX_WORKERS))


# ----------------------------------------------------------------------------- the rows a worker sees
class _Det:
    __slots__ = ("id",)

    def __init__(self, i: str) -> None:
        self.id = i


class _Row:
    """Attribute-compatible stand-in for an `Event`, holding only what extraction/aggregation read.

    `msg` arrives as the stored `_msg`, which is None whenever the message is just `raw[:200]` — the
    common case. Deriving it HERE, in the worker, instead of packing a fresh slice of every raw line on
    the parent's one core, is the cheaper pack.
    """
    __slots__ = ("ts", "sev", "source", "file", "host", "user", "msg", "raw", "fields", "detections", "id")

    def __init__(self, ts: str, sev: str, source: str, file: str, host: str, user: str, msg: Optional[str],
                 raw: str, fields: dict, dets: list, eid: str) -> None:
        self.ts = ts
        self.sev = sev
        self.source = source
        self.file = file
        self.host = host
        self.user = user
        self.msg = msg if msg is not None else raw[:200]
        self.raw = raw
        self.fields = fields
        self.detections = [_Det(d) for d in dets] if dets else []
        self.id = eid


def pack(events: list, idx: Iterable[int]) -> list:
    """The given pool positions as plain tuples — `str`/`dict`/`list`/`None` only, so the pickle is C-speed."""
    return [(e.ts, e.sev, e.source, e.file, e.host, e.user, e._msg, e.raw, e.fields,
             [d.id for d in e.detections], e.id)
            for e in (events[i] for i in idx)]


# ----------------------------------------------------------------------------- partials
# A partial is (node_rows, edge_rows) with every event reference an EVENT ID:
#   node row: (nid, type, value, label, count, first, last, sev, detections, head_ids, tail_ids, srcs, files)
#   edge row: (src_nid, dst_nid, kind, count, first, last, sev, outcomes, why, event_ids, files)
# `head_ids` are the node's first _HEAD events IN THIS SLICE (pool order), `tail_ids` its last _TAIL.

def extract_chunk(rows: list) -> tuple:
    """WORKER ENTRY POINT (also run in-process). `graph.aggregate` over the rows, flattened to a partial."""
    from . import graph
    shims = [_Row(*r) for r in rows]
    nodes: dict[str, Any] = {}
    edges: dict[tuple[str, str, str], Any] = {}
    graph.aggregate(shims, nodes, edges, 0)
    ids = [s.id for s in shims]
    node_rows = []
    for nid, n in nodes.items():
        head = [ids[i] for i in n.events]
        tail = [ids[i] for i in n.recent()[-graph._TAIL:]] if len(n.tail) else []
        node_rows.append((nid, n.type, n.value, n.label, n.count, n.first, n.last, n.sev, n.detections,
                          head, tail, n.srcs, n.files))
    edge_rows = [(s, t, k, e.count, e.first, e.last, e.sev, e.outcomes, e.why, e.events, sorted(e.files))
                 for (s, t, k), e in edges.items()]
    return node_rows, edge_rows


class _Acc:
    """The id-based fold: partials in, one partial out. Order-preserving, so chunk order = pool order
    within a source keeps every head/tail list ascending — the final fold sorts across sources."""
    __slots__ = ("nodes", "edges")

    def __init__(self) -> None:
        self.nodes: dict[str, list] = {}
        self.edges: dict[tuple[str, str, str], list] = {}

    def fold(self, partial: tuple, head_cap: int, tail_cap: int) -> None:
        node_rows, edge_rows = partial
        nodes = self.nodes
        for row in node_rows:
            nid = row[0]
            cur = nodes.get(nid)
            if cur is None:
                nodes[nid] = [row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8],
                              list(row[9]), list(row[10]), dict(row[11]), dict(row[12])]
                continue
            cur[3] += row[4]
            if row[5] < cur[4]:
                cur[4] = row[5]
            if row[6] > cur[5]:
                cur[5] = row[6]
            if SEV_ORDER.get(row[7], 0) > SEV_ORDER.get(cur[6], 0):
                cur[6] = row[7]
            cur[7] += row[8]
            head = cur[8]
            if len(head) < head_cap:
                head.extend(row[9][:head_cap - len(head)])
            tail = cur[9]
            tail.extend(row[10] if row[10] else row[9])
            if len(tail) > tail_cap:
                del tail[:len(tail) - tail_cap]
            for s, c in row[11].items():
                cur[10][s] = cur[10].get(s, 0) + c
            for f, c in row[12].items():
                cur[11][f] = cur[11].get(f, 0) + c
        edges = self.edges
        for (s, t, k, cnt, first, last, sev, outcomes, why, evs, files) in edge_rows:
            key = (s, t, k)
            cur = edges.get(key)
            if cur is None:
                edges[key] = [cnt, first, last, sev, dict(outcomes), dict(why), list(evs), set(files)]
                continue
            cur[0] += cnt
            if first < cur[1]:
                cur[1] = first
            if last > cur[2]:
                cur[2] = last
            if SEV_ORDER.get(sev, 0) > SEV_ORDER.get(cur[3], 0):
                cur[3] = sev
            for o, c in outcomes.items():
                cur[4][o] = cur[4].get(o, 0) + c
            for w, c in why.items():
                cur[5][w] = cur[5].get(w, 0) + c
            if len(cur[6]) < 20:
                cur[6].extend(evs[:20 - len(cur[6])])
            cur[7].update(files)

    def partial(self) -> tuple:
        node_rows = [(nid, v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11])
                     for nid, v in self.nodes.items()]
        edge_rows = [(s, t, k, v[0], v[1], v[2], v[3], v[4], v[5], v[6], sorted(v[7]))
                     for (s, t, k), v in self.edges.items()]
        return node_rows, edge_rows


def materialise(acc: _Acc, index: dict, nodes: dict, edges: dict) -> None:
    """The final fold into `_NodeAgg` / `_EdgeAgg`, resolving ids to the CURRENT pool's indices."""
    from .graph import _EdgeAgg, _HEAD, _NodeAgg, _TAIL
    get = index.get
    for nid, v in acc.nodes.items():
        n = _NodeAgg(v[0], v[1], v[2], v[4], v[5])
        n.count, n.sev, n.detections = v[3], v[6], v[7]
        head = sorted({i for i in (get(x) for x in v[8]) if i is not None})[:_HEAD]
        n.events = array("i", head)
        window = sorted({i for i in (get(x) for x in v[9]) if i is not None})[-_TAIL:]
        n.tail = array("i", window)
        n.srcs, n.files = v[10], v[11]
        nodes[nid] = n
    for (s, t, k), v in acc.edges.items():
        e = _EdgeAgg(s, t, k, v[1], v[2])
        e.count, e.sev, e.outcomes, e.why, e.files = v[0], v[3], v[4], v[5], set(v[7])
        evs = sorted({i for i in (get(x) for x in v[6]) if i is not None})[:20]
        e.events = [x for x in v[6] if get(x) in set(evs)][:20] if evs else []
        edges[(s, t, k)] = e
    _finalise(nodes)


def _finalise(nodes: dict) -> None:
    """Turn each node's ascending last-_TAIL window into the ring `_NodeAgg.add` would have built —
    `recent()` must come back identical, because node detail reads it."""
    from .graph import _HEAD, _TAIL
    for n in nodes.values():
        c = n.count
        window = n.tail
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


# ----------------------------------------------------------------------------- the build
from .derived import BuildCancelled as GraphBuildCancelled  # noqa: E402  (what AsyncCache.get catches)


def groups_of(events: list) -> list[tuple[str, np.ndarray]]:
    """[(sourceId, pool positions)] in first-seen order — the fallback when the store did not say."""
    codes: dict[str, int] = {}
    order: list[str] = []
    arr = np.empty(len(events), dtype=np.int32)
    for i, e in enumerate(events):
        c = codes.get(e.sourceId)
        if c is None:
            c = codes[e.sourceId] = len(order)
            order.append(e.sourceId)
        arr[i] = c
    return [(sid, np.flatnonzero(arr == c)) for c, sid in enumerate(order)]


def build(events: list, nodes: dict, edges: dict, *,
          groups: Optional[list[tuple[str, np.ndarray]]] = None,
          sigs: Optional[dict[str, str]] = None,
          index: Optional[dict] = None,
          cache: Any = None,
          progress: Optional[Callable[[int], None]] = None,
          cancelled: Optional[Callable[[], bool]] = None,
          max_workers: Optional[int] = None) -> str:
    """Extract per source into `nodes`/`edges`. Returns a short description of what it did.

    `groups`  — [(sourceId, pool positions)]; derived from `events` when absent.
    `sigs`    — sourceId -> content signature; a partial is cached/reused only under a signature.
    `index`   — event id -> pool index for the CURRENT pool; derived when absent.
    `cache`   — object with get(sid, sig) -> partial|None and put(sid, sig, partial); None = no cache.
    """
    from .graph import _HEAD, _TAIL
    if groups is None:
        groups = groups_of(events)
    if index is None:
        index = {e.id: i for i, e in enumerate(events)}
    sigs = sigs or {}
    w = workers() if max_workers is None else max_workers
    step = chunk_events()
    total = len(events)
    done = 0
    hits = misses = 0
    used_pool = False
    acc = _Acc()
    pool = None
    t0 = time.perf_counter()

    def check() -> None:
        if cancelled is not None and cancelled():
            raise GraphBuildCancelled()

    def extract_source(idx: np.ndarray) -> tuple:
        """One source's partial, chunked; across workers when the source is big and memory allows."""
        nonlocal pool, done, w, used_pool
        src_acc = _Acc()
        bounds = [(s, min(s + step, len(idx))) for s in range(0, len(idx), step)]
        use_pool = w >= 2 and len(idx) >= min_parallel_events() and len(bounds) >= 2
        if use_pool and pool is None:
            try:
                from .parsers.parallel import background_worker_init
                pool = ProcessPoolExecutor(max_workers=w, mp_context=get_context("spawn"),
                                           initializer=background_worker_init)
            except Exception as exc:  # no subprocesses here: extract in-process
                _log_once(f"{type(exc).__name__}: {exc}")
                use_pool = False
        if not use_pool:
            for s, e in bounds:
                check()
                src_acc.fold(extract_chunk(pack(events, idx[s:e])), _HEAD, _TAIL)
                done += e - s
                if progress is not None:
                    progress(done)
            return src_acc.partial()
        used_pool = True
        inflight: list = []
        nxt = 0
        window = w + 2
        done_before = done
        try:
            while nxt < len(bounds) and len(inflight) < window:
                s, e = bounds[nxt]
                inflight.append((pool.submit(extract_chunk, pack(events, idx[s:e])), e - s))
                nxt += 1
            while inflight:
                check()
                fut, size = inflight.pop(0)
                src_acc.fold(fut.result(timeout=CHUNK_TIMEOUT), _HEAD, _TAIL)   # chunk order = pool order
                done += size
                if progress is not None:
                    progress(done)
                if nxt < len(bounds):
                    s, e = bounds[nxt]
                    inflight.append((pool.submit(extract_chunk, pack(events, idx[s:e])), e - s))
                    nxt += 1
            return src_acc.partial()
        except GraphBuildCancelled:
            raise
        except BaseException as exc:
            # A worker died, a chunk timed out, a payload would not pickle: every one of these lands
            # as "extract THIS source in-process". Nothing has been written to the caller's dicts yet
            # — the fold into `nodes`/`edges` happens once at the end — so the partial is simply
            # rebuilt, and the remaining sources go on without the pool.
            _shutdown(pool)
            pool = None
            w = 1
            used_pool = False
            _log_once(f"{type(exc).__name__}: {exc}")
            done = done_before
            src_acc = _Acc()
            for s, e in bounds:
                check()
                src_acc.fold(extract_chunk(pack(events, idx[s:e])), _HEAD, _TAIL)
                done += e - s
                if progress is not None:
                    progress(done)
            return src_acc.partial()

    try:
        for sid, idx in groups:
            check()
            sig = sigs.get(sid, "")
            part = cache.get(sid, sig) if (cache is not None and sig) else None
            if part is not None:
                hits += 1
                done += len(idx)
                if progress is not None:
                    progress(done)
            else:
                misses += 1
                part = extract_source(idx)
                if cache is not None and sig:
                    cache.put(sid, sig, part)
            acc.fold(part, _HEAD, _TAIL)
    except GraphBuildCancelled:
        _shutdown(pool)
        raise
    _shutdown(pool, wait=True)
    materialise(acc, index, nodes, edges)
    note = (f"{len(groups)} sources ({hits} from cache, {misses} extracted), {total:,} events, "
            f"{f'{w} workers' if used_pool else 'in-process'}, {time.perf_counter() - t0:.1f}s")
    if os.environ.get("IRIS_GRAPH_TIMING"):
        _log(note)
    return note


def _shutdown(pool: Optional[ProcessPoolExecutor], wait: bool = False) -> None:
    if pool is None:
        return
    try:
        pool.shutdown(wait=wait, cancel_futures=not wait)
    except Exception:
        pass
