"""Persist a built entity graph so a restart does not pay the extraction again.

The graph is ~75 % regex-and-string work over every event and it does not vectorise; on the analyst's
pool it is 55-190 s per build. Iris keeps the whole pool in memory and re-parses the library on every
start, so every restart — and every crash-restart — paid that again, and the graph is what the analyst
opens first. The pool that comes back after a restart is the SAME pool (library event ids are derived
from the staged file name, so a reload reproduces them exactly), which is what makes the build reusable.

Two things make this exact rather than merely fast:

* **The key is the pool's content, not a version counter and not source identity.** `signature()` folds
  every source's FILE, event count and time range, plus the total, plus GRAPH_FORMAT — so a parser change
  or a rule change that alters what a source produced misses. Source IDS are deliberately excluded: a case
  source is assigned a fresh `uuid4().hex[:8]` on every restore, so keying on them made the cache miss on
  every restart — it saved every time and never loaded once, which is exactly what the first version did.
* **Per-node event references are saved as EVENT IDS, never as pool indices.** A node keeps the first
  200 and the most recent 200 event positions; a pool rebuilt from the same files can order equal-
  timestamp events differently (it depends on file order and batching), so an index saved by one build
  could point at a different event in the next. Ids are resolved back to positions against the live
  `event_index` on load, and an id that no longer exists is dropped.

The file lives at `$IRIS_DATA_DIR/cache/graph-<scope>.pkl`; it is a CACHE, deletable at any time,
written atomically, and never read for anything but this. `IRIS_GRAPH_CACHE=0` disables it.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import pickle
import sys
import threading
import time
from array import array
from pathlib import Path
from typing import Any, Optional

from . import config, sealed

GRAPH_FORMAT = 3          # bump when _NodeAgg/_EdgeAgg fields or extraction rules change
_LOCK = threading.Lock()


def enabled() -> bool:
    return os.environ.get("IRIS_GRAPH_CACHE", "1").strip().lower() not in ("0", "false", "no", "off")


def _dir() -> Path:
    return config.CACHE_DIR


def _path(scope: str) -> Path:
    return _dir() / f"graph-{scope}.pkl"


# --------------------------------------------------------------------------- integrity
# The cache is a PICKLE in the bind-mounted data dir, so it is HMAC-tagged: see app/sealed.py, which
# both on-disk caches share. A foreign or edited file is a MISS (rebuild), never a load, never a crash.
_MAGIC = b"IRISGRA1"


def _seal(blob: bytes) -> bytes:
    return sealed.seal(blob, _MAGIC)


def _unseal(data: bytes) -> Optional[bytes]:
    return sealed.unseal(data, _MAGIC)


def signature(store: Any, scope: str) -> str:
    """A digest of what the graph was built FROM. Same digest -> same graph, byte for byte."""
    h = hashlib.sha256()
    h.update(f"format={GRAPH_FORMAT};scope={scope};".encode())
    with store.lock:
        # CONTENT, not identity: a case source is assigned a fresh `uuid4().hex[:8]` on every restore, so
        # a signature containing source ids could never hit across a restart — which is the only time
        # this cache matters. File name + event count + time range identifies what a source contributed;
        # the event IDS the cache stores are stable across restarts by construction (case sources keep
        # their case.json order, library sources derive theirs from the staged file name).
        srcs = sorted((s.file, s.events, s.range[0] if s.range else "", s.range[1] if s.range else "")
                      for s in store.sources.values())
        n = len(store.case_set) if scope == "case" else len(store.events)
        if scope == "case":
            for eid in sorted(store.case_set):
                h.update(eid.encode())
    for row in srcs:
        h.update(repr(row).encode())
    h.update(f";n={n}".encode())
    return h.hexdigest()


def _log(msg: str) -> None:
    print(f"[iris] graph cache: {msg}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- save
def save(store: Any, scope: str, gb: Any, sig: str) -> bool:
    """Write the builder's aggregate. Never raises — a cache write that fails is just a cache miss later."""
    if not enabled():
        return False
    from .graph import _NodeAgg, _EdgeAgg  # noqa: F401  (documented dependency, not used directly)
    t0 = time.perf_counter()
    try:
        events = store.events
        nodes_out = []
        for nid, n in gb.nodes.items():
            # positions -> ids; `recent()` is chronological, so the ring is stored as an ordered list
            head = [events[i].id for i in n.events if 0 <= i < len(events)]
            recent = [events[i].id for i in n.recent()[len(n.events):] if 0 <= i < len(events)] \
                if len(n.tail) else []
            nodes_out.append((nid, n.type, n.value, n.label, n.count, n.first, n.last, n.sev, n.detections,
                              head, recent, dict(n.srcs), dict(n.files)))
        edges_out = [(k, e.source, e.target, e.relation, e.count, e.first, e.last, e.sev,
                      dict(e.outcomes), list(e.events), dict(e.why), sorted(e.files))
                     for k, e in gb.edges.items()]
        payload = {"format": GRAPH_FORMAT, "sig": sig, "nodes": nodes_out, "edges": edges_out,
                   "savedAt": time.time()}
        _dir().mkdir(parents=True, exist_ok=True)
        tmp = _path(scope).with_suffix(".tmp")
        blob = pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL)
        with _LOCK:
            with open(tmp, "wb") as fh:
                fh.write(_seal(blob))
            os.replace(tmp, _path(scope))
        del blob
        _log(f"saved {len(nodes_out)} nodes / {len(edges_out)} relations for scope={scope} "
             f"in {time.perf_counter() - t0:.1f}s")
        return True
    except Exception as exc:  # noqa: BLE001
        _log(f"save failed ({type(exc).__name__}: {exc}); the graph is still served from memory")
        return False


# --------------------------------------------------------------------------- load
def load(store: Any, scope: str, sig: str) -> Optional[tuple[dict, dict]]:
    """(nodes, edges) rebuilt for the CURRENT pool, or None on any mismatch. Never raises."""
    if not enabled():
        return None
    p = _path(scope)
    if not p.is_file():
        return None
    from .graph import _NodeAgg, _EdgeAgg, _HEAD, _TAIL
    t0 = time.perf_counter()
    try:
        with _LOCK, open(p, "rb") as fh:
            raw = fh.read()
        blob = _unseal(raw)
        del raw
        if blob is None:
            _log("cache file is unsigned or was not written by this install; ignoring it and rebuilding")
            return None
        payload = pickle.loads(blob)
        del blob
        if not isinstance(payload, dict) or payload.get("format") != GRAPH_FORMAT or payload.get("sig") != sig:
            return None
        index = store.event_index
        nodes: dict[str, _NodeAgg] = {}
        for (nid, typ, value, label, count, first, last, sev, det, head, recent, srcs, files) in payload["nodes"]:
            n = _NodeAgg(typ, value, label, first, last)
            n.count, n.sev, n.detections = count, sev, det
            n.events = array("i", [index[i] for i in head if i in index][:_HEAD])
            tail = [index[i] for i in recent if i in index][-_TAIL:]
            n.tail = array("i", tail)
            n.ti = 0            # a full ring stored in chronological order unwraps from position 0
            n.srcs, n.files = dict(srcs), dict(files)
            nodes[nid] = n
        edges: dict[tuple[str, str, str], _EdgeAgg] = {}
        for (k, s, t, rel, count, first, last, sev, outcomes, evs, why, files) in payload["edges"]:
            e = _EdgeAgg(s, t, rel, first, last)
            e.count, e.sev = count, sev
            e.outcomes, e.events, e.why, e.files = dict(outcomes), list(evs), dict(why), set(files)
            edges[tuple(k)] = e
        _log(f"loaded {len(nodes)} nodes / {len(edges)} relations for scope={scope} "
             f"in {time.perf_counter() - t0:.1f}s (skipped a full extraction)")
        return nodes, edges
    except Exception as exc:  # noqa: BLE001
        _log(f"load failed ({type(exc).__name__}: {exc}); building from the pool instead")
        return None


def clear() -> None:
    """Remove every cached graph. NOT what `clear-all` calls — that wipes the whole `cache/` tree, so
    the pool cache and the HMAC key go with it; a cache must not outlive the data it describes."""
    try:
        for p in _dir().glob("graph-*.pkl"):
            p.unlink(missing_ok=True)
    except OSError:
        pass
