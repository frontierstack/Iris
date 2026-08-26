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


# What decides which DETECTIONS an event carries, and therefore what BOTH derived caches contain.
# `search._doc` packs every `d.id` and `d.name` into the indexed text, and the graph carries per-node
# detection ids, so a catalogue change makes both of them wrong — and neither key covered it. A rule
# edit left the persisted index in place: the version bump dropped the in-memory copy, the warm loaded
# the stale one straight back off disk, and an event that had just GAINED a detection was not in the
# candidate set. `detection:<id>` then returned 0 rows behind a green `vector` badge, which is a
# silent FALSE NEGATIVE about evidence — the confirm pass can filter a candidate out, it cannot
# conjure one the packed text never had.
#
# CONTENT, and never `RULES_STORE.rev` / `EXCLUSIONS.rev`: those counters live in memory and restart
# at 0, so keying a PERSISTED cache on them would make every boot miss both — a full re-pack (165 s /
# 4.1 GB measured) and a full graph rebuild on every single start, which is far worse than the bug.
#
# `detect.py` is hashed once per process: the shipped rules are code, code cannot change under a
# running server, and it has to be in here because a logic fix changes what fires while changing no
# rule id and no param — SIGMA-APP-0070's `_secret_real` did exactly that, 1,293 hits down to 10. The
# two JSON files are re-hashed only when their (mtime, size) moves, because the analyst edits those at
# runtime and this sits on the path every cache check takes.
_CAT_CODE: Optional[str] = None
_CAT_FILES: dict[str, tuple[int, int, str]] = {}


def _file_digest(path: Path) -> str:
    try:
        st = path.stat()
    except OSError:
        return "-"          # absent = nothing overridden; a stable, meaningful value, not an error
    cached = _CAT_FILES.get(str(path))
    if cached is not None and cached[0] == st.st_mtime_ns and cached[1] == st.st_size:
        return cached[2]
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    except OSError:
        return "-"
    _CAT_FILES[str(path)] = (st.st_mtime_ns, st.st_size, digest)
    return digest


def catalogue_digest() -> str:
    """A digest of the effective detection catalogue: the shipped rules plus the analyst's edits."""
    global _CAT_CODE
    if _CAT_CODE is None:
        try:
            _CAT_CODE = hashlib.sha256(
                (Path(__file__).resolve().parent / "detect.py").read_bytes()).hexdigest()[:16]
        except OSError:
            _CAT_CODE = "unknown"
    h = hashlib.sha256()
    h.update(_CAT_CODE.encode())
    h.update(_file_digest(config.RULES_PATH).encode())
    h.update(_file_digest(Path(config.DATA_DIR) / "exclusions.json").encode())
    return h.hexdigest()[:16]


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
    # The catalogue, because both caches embed what it produced. See catalogue_digest above.
    h.update(f";cat={catalogue_digest()}".encode())
    return h.hexdigest()


def _log(msg: str) -> None:
    print(f"[iris] graph cache: {msg}", file=sys.stderr, flush=True)


FRAME_ROWS = 4000
_FRAME_MAGIC = b"IRISGF1\n"


def _frames(nodes_out: list, edges_out: list):
    for i in range(0, len(nodes_out), FRAME_ROWS):
        yield ("nodes", nodes_out[i:i + FRAME_ROWS])
    for i in range(0, len(edges_out), FRAME_ROWS):
        yield ("edges", edges_out[i:i + FRAME_ROWS])


def _write_frames(path, header: dict, frames) -> None:
    """Magic, a pickled header, then independent pickle streams (one Pickler per frame — see the
    pool_store note: a shared pickler's memo makes the second frame unreadable), then the HMAC of
    everything before it. The tag is computed as the bytes go out; nothing is held twice."""
    import hmac as _hmac
    import hashlib
    from .sealed import key
    mac = _hmac.new(key(), digestmod=hashlib.sha256)
    with open(path, "wb") as fh:
        def put(b: bytes) -> None:
            mac.update(b)
            fh.write(b)
        put(_FRAME_MAGIC)
        put(pickle.dumps(header, protocol=pickle.HIGHEST_PROTOCOL))
        for frame in frames:
            put(pickle.dumps(frame, protocol=pickle.HIGHEST_PROTOCOL))
        fh.write(mac.digest())


def _read_frames(path):
    """(header, [frames]) or (None, None). The tag is verified over the whole file BEFORE anything is
    unpickled — a pickle in a bind-mounted directory is code execution to whoever can write there."""
    import hmac as _hmac
    import hashlib
    import io
    from .sealed import key
    size = os.path.getsize(path)
    if size < len(_FRAME_MAGIC) + 32:
        return None, None
    mac = _hmac.new(key(), digestmod=hashlib.sha256)
    with open(path, "rb") as fh:
        body_len = size - 32
        remaining = body_len
        while remaining > 0:
            chunk = fh.read(min(1 << 24, remaining))
            if not chunk:
                return None, None
            mac.update(chunk)
            remaining -= len(chunk)
        tag = fh.read(32)
    if not _hmac.compare_digest(mac.digest(), tag):
        return None, None
    with open(path, "rb") as fh:
        if fh.read(len(_FRAME_MAGIC)) != _FRAME_MAGIC:
            return None, None
        header = pickle.Unpickler(fh).load()
        frames = []
        while fh.tell() < body_len:
            frames.append(pickle.Unpickler(fh).load())
    return header, frames


class Parts:
    """The per-source partial-graph cache behind `graph_parts.build` (see that module's docstring).

    One sealed pickle per source under `cache/graph-parts/`, keyed by the source id and named inside
    by the source's content signature, so a changed source misses and an unchanged one loads in
    milliseconds instead of being re-extracted. Any doubt — a foreign tag, a wrong signature, an
    exception — is a miss; it is a cache. `clear-all` wipes the whole `cache/` tree, this included.
    """

    def _dir(self):
        return _dir() / "graph-parts"

    def _path(self, sid: str):
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in sid)
        return self._dir() / f"{safe}.pkl"

    def get(self, sid: str, sig: str):
        if not enabled():
            return None
        p = self._path(sid)
        if not p.is_file():
            return None
        try:
            with open(p, "rb") as fh:
                raw = fh.read()
            blob = _unseal(raw)
            if blob is None:
                return None
            payload = pickle.loads(blob)
            if payload.get("sig") != sig or payload.get("format") != GRAPH_FORMAT:
                return None
            return payload["nodes"], payload["edges"]
        except Exception:  # noqa: BLE001
            return None

    def put(self, sid: str, sig: str, partial) -> None:
        if not enabled():
            return
        try:
            self._dir().mkdir(parents=True, exist_ok=True)
            nodes, edges = partial
            blob = pickle.dumps({"format": GRAPH_FORMAT, "sig": sig, "nodes": nodes, "edges": edges},
                                protocol=pickle.HIGHEST_PROTOCOL)
            tmp = self._path(sid).with_suffix(".tmp")
            with open(tmp, "wb") as fh:
                fh.write(_seal(blob))
            os.replace(tmp, self._path(sid))
        except Exception as exc:  # noqa: BLE001
            _log(f"partial for {sid} not saved ({type(exc).__name__}: {exc})")

    def prune(self, keep: set) -> int:
        """Drop partials of sources no longer in the pool. Returns how many were removed."""
        d = self._dir()
        if not d.is_dir():
            return 0
        keep_names = {self._path(s).name for s in keep}
        n = 0
        for f in d.glob("*.pkl"):
            if f.name not in keep_names:
                try:
                    f.unlink()
                    n += 1
                except OSError:
                    pass
        return n


PARTS = Parts()


# --------------------------------------------------------------------------- save
def save(store: Any, scope: str, gb: Any, sig: str) -> bool:
    """Write the builder's aggregate. Never raises — a cache write that fails is just a cache miss later."""
    if not enabled():
        return False
    from .graph import _NodeAgg, _EdgeAgg, _TAIL  # noqa: F401  (documented dependency, not used directly)
    t0 = time.perf_counter()
    try:
        events = store.events
        nodes_out = []
        for nid, n in gb.nodes.items():
            # positions -> ids; `recent()` is chronological, so the ring is stored as an ordered list
            head = [events[i].id for i in n.events if 0 <= i < len(events)]
            # `recent()` is head+ring while the ring is filling and ONLY the ring once it is full, so
            # slicing off `len(events)` returned nothing for exactly the busiest nodes — they came back
            # from the cache with no recent-events window. Store the ring as `recent()` gives it
            # (ascending); load sets the cursor to 0, which unwraps to the same list.
            rec = n.recent()
            recent = [events[i].id for i in (rec if len(n.tail) >= _TAIL else rec[len(n.events):])
                      if 0 <= i < len(events)] if len(n.tail) else []
            nodes_out.append((nid, n.type, n.value, n.label, n.count, n.first, n.last, n.sev, n.detections,
                              head, recent, dict(n.srcs), dict(n.files)))
        edges_out = [(k, e.source, e.target, e.relation, e.count, e.first, e.last, e.sev,
                      dict(e.outcomes), list(e.events), dict(e.why), sorted(e.files))
                     for k, e in gb.edges.items()]
        # FRAMED, never one blob. `pickle.dumps` of the whole payload was a single multi-hundred-MB
        # (at 13.8 M events, multi-GB) transient allocation at the END of the build — on a VM that had
        # nothing left, which is the moment the process was found dead. Frames of a few thousand rows
        # each, HMAC'd as they are written, keep the peak to one frame.
        _dir().mkdir(parents=True, exist_ok=True)
        tmp = _path(scope).with_suffix(".tmp")
        header = {"format": GRAPH_FORMAT, "sig": sig, "savedAt": time.time(),
                  "nodes": len(nodes_out), "edges": len(edges_out)}
        with _LOCK:
            _write_frames(tmp, header, _frames(nodes_out, edges_out))
            os.replace(tmp, _path(scope))
        del nodes_out, edges_out
        _log(f"saved {header['nodes']} nodes / {header['edges']} relations for scope={scope} "
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
        with _LOCK:
            header, frames = _read_frames(p)
        if header is None:
            _log("cache file is unsigned, corrupt or not written by this install; ignoring it and rebuilding")
            return None
        if header.get("format") != GRAPH_FORMAT or header.get("sig") != sig:
            return None
        payload = {"nodes": [], "edges": []}
        for kind, rows in frames:
            payload[kind].extend(rows)
        del frames
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
