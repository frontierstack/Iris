"""Vectorized (GPU-capable) search over the case.

How it works
------------
* `SearchIndex` packs every event into one lower-cased byte buffer (msg, raw, host, user, source, entities,
  detections and `k=v` fields, separated by \\x1e / \\x1f, events terminated by \\x00) plus per-event
  offsets, severity codes, source codes and the timestamp array. It is (re)built lazily when the store
  version changes and moved to the GPU (cupy) when the compute backend is CUDA.
* A query AST (query.py) is lowered to boolean masks: free-text atoms → substring search implemented as
  `m` shifted equality passes over the whole buffer (embarrassingly parallel → fast on CUDA), sev/source/ts
  atoms → exact code compares. field:value atoms use the value substring as an *upper bound*; NOT over an
  approximate atom widens to all-true. The result is therefore a superset of the true matches, and the
  candidates are then confirmed with the exact Python predicate. Correctness never depends on the GPU
  path; only speed does.

Sizing
------
The index now spans the whole WORKSPACE pool (every ingested source, case-attached or staged in the
library), not one case, so it has no natural size ceiling. Two consequences are handled here:

* it is only ever built off the request path (`warm_async`, a daemon timer) — never inside the FastAPI
  lifespan, which is what made a 589 MB library block startup;
* the GPU upload is gated by GPU_INDEX_MAX_BYTES and by free device memory. A 1.16 GB buffer made cupy
  fail to allocate pinned host memory and fall back to a SYNCHRONOUS transfer — minutes at 100% CPU
  rather than an error. Too big now means "stay on numpy", decided before anything is transferred.
"""
from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import numpy as np

from . import compute, index_store
from .models import Event
from .query import Node, atom_parts, node_pred, parse_query

# The three names an event's source answers to, packed into one label per code. Kept as a named
# constant because the mask that splits it and the build that joins it must never drift apart.
_SRC_SEP = "\x1e"

_SEV_CODE = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEP = b"\x1e"
_FSEP = b"\x1f"
_END = b"\x00"
# One window of the packed buffer per comparison pass. Bounded on purpose: an unchunked compare
# allocates a bool the size of the WHOLE buffer (5.4 GB on the analyst's pool) beside the index it is
# scanning. 256 MiB is large enough that the per-call overhead is noise and small enough to never be
# the reason a query fails.
_SCAN_CHUNK = 1 << 26
# How many of the needle's rarest bytes anchor the window before any gather happens.
_ANCHORS = 3
# When the find loop stops being worth it. Two numbers, because a fixed cap got BOTH cases wrong: it
# bailed on terms it should have finished (a 247 MB buffer only breaks even at ~1.7 M hits), and when
# it did bail it had already paid for every hit up to the cap AND still had to run the scan.
#   _FIND_BYTES_PER_HIT — the crossover expressed against buffer size: the vectorised scan costs
#     ~3.1 ms/MB and a find-loop hit ~0.4 us, so one hit is "worth" ~160 bytes of buffer.
#   _FIND_PROBE — how often to project the total from the density scanned so far. A term that is
#     going to blow the cap is abandoned after about this many hits instead of after all of them,
#     which bounds the wasted work to a few tens of milliseconds.
_FIND_BYTES_PER_HIT = 160
_FIND_PROBE = 50_000
_FIND_MIN_CAP = 200_000
# How far past the requested page the SCAN path keeps counting before it reports a floor instead of a
# total. Enough that the hit count is useful ("10,000+") and small enough that a cold query answers in
# about a second rather than three minutes.
_SCAN_COUNT_AHEAD = 10_000
# Share of FREE device memory the index plus its working room may claim. Not 1.0: the driver, the
# graph's device arrays and cupy's own pools live there too, and an OOM mid-query is answered by
# falling back to a path that takes 40x longer.
_GPU_BUDGET = 0.85
# Worst case a single query needs on the device, on top of the index: one bool over the window, the
# int64 positions if EVERY byte in that window matched (a one-character needle does exactly that), and
# the copy `pos[...]` makes while narrowing. Bounded because the scan is chunked — this number is the
# whole reason the budget can be a real requirement instead of a blanket half-of-free.
_SCAN_HEADROOM = _SCAN_CHUNK * (1 + 8 + 8) + (256 << 20)

_MIN_VECTOR = 2000  # below this many events the plain Python path is faster than building masks


GPU_CAP_AUTO = -1


def _gpu_index_cap() -> int:
    """Largest index (bytes) allowed on the GPU.

    Default is AUTO: the free-device-memory check below is the real budget, because a fixed byte ceiling
    is wrong on both ends — 512 MB left a 1.16 GB index (which fits five times over in a 12 GB card) on
    numpy for no reason, and on a small card any fixed number can still be too big. `IRIS_GPU_INDEX_MAX`
    still pins it: a byte count caps it explicitly, 0 keeps the index off the GPU entirely.
    """
    raw = os.environ.get("IRIS_GPU_INDEX_MAX", "")
    if not raw.strip():
        return GPU_CAP_AUTO
    try:
        return int(raw)
    except ValueError:
        return GPU_CAP_AUTO


_gpu_note: str = ""      # last reason the GPU upload was skipped — logged once per reason, not per build


@dataclass
class SearchIndex:
    version: int
    n: int
    text: np.ndarray            # uint8 (numpy or cupy)
    offsets: np.ndarray         # int64 start offset of each event's document (n+1 entries)
    sev: np.ndarray             # int8
    source: np.ndarray          # int32 codes into `sources`
    sources: list[str] = field(default_factory=list)   # source label per code (family / file / id share a code)
    ts: Optional[np.ndarray] = None
    on_gpu: bool = False
    # Whether a GPU backend was ACTIVE when this index was built — not whether the upload succeeded.
    # Comparing on_gpu against the live backend meant an index whose transfer failed (OOM, oversized)
    # looked stale on every single request and was rebuilt every single time.
    gpu_backend: bool = False
    bytes: int = 0
    build_ms: float = 0.0
    byte_counts: Optional[np.ndarray] = None   # histogram of the buffer, picks the rarest needle byte first
    # The SAME memory as `text`, as a bytes-like object, so `bytes.find` (memmem: SIMD, several GB/s)
    # can be used instead of an elementwise numpy compare. Measured on a 240 MB buffer: a needle that
    # matches nothing costs 43-71 ms this way against 250 ms for ONE numpy pass — and the vectorised
    # scan makes several. `np.frombuffer` shares the allocation, so this costs no extra memory; it is
    # None when the index lives on the GPU, where the vector path is the right one anyway.
    raw: Optional[bytes] = None


_SEP_S = _SEP.decode("latin-1")
_FSEP_S = _FSEP.decode("latin-1")
_END_S = _END.decode("latin-1")


def _doc(e: Event) -> bytes:
    """The searchable text of one event, lower-cased and packed.

    `msg` is included ONLY when it says something `raw` does not. `Event` stores `_msg = None`
    whenever the message is just the raw line's prefix (see models.Event), which is the common case —
    and packing that prefix again duplicated a large slice of every document. It cost buffer size
    (memory, build time, every scan) and it doubled the number of hits a substring search had to walk
    for the commonest terms. Nothing is lost: a substring of a prefix of `raw` is a substring of
    `raw`, so free-text semantics are unchanged — which is the contract `query.py` and this function
    must keep between them.
    """
    # ONE `.lower()` and ONE `.encode()` per document, not one of each per part. `str.lower` and
    # UTF-8 encoding are both applied character-wise, so lowering and encoding the joined string is
    # byte-for-byte the same as joining the lowered, encoded parts — provided the separators are
    # unaffected by either, which control characters are. `tests/test_perf_equivalence.py` pins it
    # against the part-wise reference on unicode, empty fields and the msg-present/absent cases.
    # Measured at 1 M events the pack was 4.7 s of a 7.0 s index build; this is the per-event half.
    parts = [e.raw, e.host, e.user, e.source, e.file, e.id, " ".join(e.entities),
             " ".join(f"{d.id} {d.name}" for d in e.detections)]
    if e._msg is not None:
        parts.insert(0, e._msg)
    f = e.fields
    fields = _FSEP_S.join([f"{k}={v}" for k, v in f.items()]) if f else ""
    return (_SEP_S + _SEP_S.join(parts) + _SEP_S + _FSEP_S + fields + _FSEP_S + _END_S).lower().encode("utf-8", "replace")


def _note_gpu_skip(reason: str) -> None:
    """Log once per distinct reason. The CPU path is a supported mode, not an error — but a silent
    downgrade on a GPU install is exactly the kind of thing that reads as 'the GPU does nothing'."""
    global _gpu_note
    if reason != _gpu_note:
        _gpu_note = reason
        print(f"[iris] search index staying on CPU (numpy): {reason}")


def _gpu_fits(ap, need: int) -> bool:
    """Decide BEFORE transferring whether the index belongs on the GPU.

    cupy does not fail cleanly on an oversized index: it cannot allocate pinned host memory, warns, and
    falls back to a synchronous transfer that pins the process at 100% CPU for minutes. So the size check
    happens up front, against the device's actual free memory (and any explicit IRIS_GPU_INDEX_MAX).
    The transfer itself then goes through compute.to_device, which copies in 64 MB chunks — the pinned
    staging buffer is never the size of the index, which is what removed the fixed 512 MB ceiling.
    """
    cap = _gpu_index_cap()
    if cap == 0:
        _note_gpu_skip("IRIS_GPU_INDEX_MAX=0 keeps the index off the GPU")
        return False
    if cap > 0 and need > cap:
        _note_gpu_skip(f"the index is {need / 1e6:.0f} MB, over the {cap / 1e6:.0f} MB GPU cap "
                       f"(IRIS_GPU_INDEX_MAX)")
        return False
    mem = compute.device_memory()
    if mem is None:
        # No device query available. With an explicit cap that is still a decision the analyst made;
        # on AUTO there is no budget to check against, so stay on numpy rather than guess.
        if cap == GPU_CAP_AUTO:
            _note_gpu_skip("device memory could not be queried, so the index size cannot be budgeted")
            return False
        return True
    free = mem[0]
    # The index PLUS what a query needs while it runs. That used to be budgeted as "half of free",
    # because an unchunked scan allocated a bool the size of the whole buffer — on a 4.2 GB index that
    # is another 4.2 GB, so anything over half of free really could not run. `_Engine.contains` now
    # scans in `_SCAN_CHUNK` windows, so the transient is bounded and known: a bool and an int64
    # position array per window, plus the per-event masks. Budgeting the real requirement instead of a
    # blanket fraction is what lets a 4.2 GB index onto a card with 7.1 GB free — where it measured
    # ~40x faster than numpy — while still refusing an index that genuinely cannot run.
    if need + _SCAN_HEADROOM > free * _GPU_BUDGET:
        _note_gpu_skip(f"the index is {need / 1e6:.0f} MB, needs {_SCAN_HEADROOM / 1e6:.0f} MB of "
                       f"working room, and only {free / 1e6:.0f} MB of device memory is free")
        return False
    return True


_HIST_CHUNK = 64 << 20
_GPU_HIST_MIN = 32 << 20   # below this the transfer costs more than the counting saves


def _byte_histogram_gpu(ap, buf) -> np.ndarray:
    """The same 256-bin count, on the device. Exact integer counts — identical to the numpy result."""
    counts = ap.zeros(256, dtype=ap.int64)
    n = int(buf.shape[0])
    on_device = not isinstance(buf, np.ndarray)
    for s in range(0, n, _HIST_CHUNK):
        blk = buf[s:s + _HIST_CHUNK]
        dev = blk if on_device else compute.to_device(np.asarray(blk))
        counts += ap.bincount(dev.astype(ap.int32), minlength=256)
    return compute.asnumpy(counts).astype(np.int64)


def byte_histogram(buf) -> np.ndarray:
    """Counts of each of the 256 byte values in the packed buffer.

    `contains()` picks the needle's RAREST byte to scan first, so this is needed by every query — but it
    is a property of the index, not of the query, and it belongs to the background build. Measured on
    numpy: 7.5 s on a ~0.5 GB index, 18-20 s on 1.2 GB. It is a pure elementwise tally over hundreds of
    megabytes — the one part of the index build that IS GPU work — so it runs on the device when one is
    active, chunked so the host→device staging never has to be the size of the whole buffer.

    The numpy path is chunked for a different reason: np.bincount promotes its input to intp, so a single
    call over a 1.2 GB buffer materialises a ~9 GB temporary.
    """
    ap = compute.xp()
    if ap is not np and int(buf.shape[0]) >= _GPU_HIST_MIN:
        try:
            return _byte_histogram_gpu(ap, buf)
        except Exception as exc:
            _note_gpu_skip(f"the byte histogram fell back to numpy ({type(exc).__name__}: {exc})")
    host = compute.asnumpy(buf) if not isinstance(buf, np.ndarray) else buf
    counts = np.zeros(256, dtype=np.int64)
    for s in range(0, int(host.shape[0]), _HIST_CHUNK):
        counts += np.bincount(host[s:s + _HIST_CHUNK], minlength=256)
    return counts


def build_index(events: list[Event], ts: np.ndarray, version: int, sig: str = "") -> SearchIndex:
    t0 = time.perf_counter()
    n = len(events)
    _status_begin(n, version)
    # Append into ONE growing bytearray instead of materializing every document and joining them: the
    # join held the whole corpus twice at peak, which on a 1.16 GB index is 2.3 GB of transient RSS.
    # One document per event into a list, then ONE join and ONE cumsum. `packed += _doc(e)` grew a
    # bytearray by reallocation and wrote each offset in Python; the join writes the buffer once and
    # the offsets come from numpy. Measured at 1 M events: 7.0 s -> 5.0 s, identical bytes and offsets.
    docs: list[bytes] = []
    append = docs.append
    for i, e in enumerate(events):
        append(_doc(e))
        if not i % 50_000:
            _status_tick(i)
    offsets = np.zeros(n + 1, dtype=np.int64)
    if n:
        np.cumsum(np.fromiter(map(len, docs), dtype=np.int64, count=n), out=offsets[1:])
    packed = bytearray(b"".join(docs))
    del docs
    # ONE allocation, two views: `raw` is what `bytes.find` searches, `buf` is what the vector path
    # and the on-disk cache use. `bytes(packed)` would copy the whole buffer, so the bytearray is kept
    # as-is — it has `.find` too.
    raw_buf = packed
    buf = np.frombuffer(raw_buf, dtype=np.uint8) if n else np.zeros(0, dtype=np.uint8)
    sev = np.fromiter((_SEV_CODE.get(e.sev, 4) for e in events), dtype=np.int8, count=n)
    # a source code per event; family, sourceId and file map to the same code via `sources` lookups
    labels: dict[str, int] = {}
    codes = np.zeros(n, dtype=np.int32)
    src_names: list[str] = []
    for i, e in enumerate(events):
        key = e.sourceId
        c = labels.get(key)
        if c is None:
            c = len(src_names)
            labels[key] = c
            src_names.append(_SRC_SEP.join((e.source, e.file, e.sourceId)))
        codes[i] = c
    idx = SearchIndex(version=version, n=n, text=buf, offsets=offsets, sev=sev, source=codes, sources=src_names,
                      ts=ts, bytes=int(buf.nbytes), raw=raw_buf if n else b"")
    ap = compute.xp()
    idx.gpu_backend = ap is not np
    if ap is not np and n >= _MIN_VECTOR and _gpu_fits(ap, buf.nbytes + offsets.nbytes + ts.nbytes):
        try:
            # chunked, never one 1.16 GB `asarray`: see compute.to_device for why that hung
            idx.text = compute.to_device(buf)
            idx.offsets = compute.to_device(offsets)
            idx.sev = compute.to_device(sev)
            idx.source = compute.to_device(codes)
            idx.ts = compute.to_device(ts)
            idx.on_gpu = True
            idx.raw = None       # the host buffer is released; the vector path is the GPU's own path
        except Exception as exc:  # OOM or a runtime hiccup: stay on CPU, and say so once
            _note_gpu_skip(f"the transfer failed ({type(exc).__name__}: {exc})")
            idx.text, idx.offsets, idx.sev, idx.source, idx.ts, idx.on_gpu = buf, offsets, sev, codes, ts, False
    # after the transfer, so the device copy is counted rather than uploaded a second time
    idx.byte_counts = byte_histogram(idx.text if idx.on_gpu else buf)
    idx.build_ms = (time.perf_counter() - t0) * 1000.0
    # Persist from the HOST arrays, which are still alive here whether or not the device copy
    # succeeded — saving from `idx.text` would pull 5.4 GB back off the GPU to write it.
    if sig:
        index_store.save(idx, sig, {"text": buf, "offsets": offsets, "sev": sev, "source": codes,
                                    "ts": ts, "byte_counts": np.asarray(idx.byte_counts)})
    _status_done(idx)
    return idx


def index_from_cache(sig: str, events: list[Event], ts: np.ndarray, version: int) -> Optional[SearchIndex]:
    """Rebuild the index from `cache/search-index.iris` instead of re-packing the pool.

    The pool comes back byte-identical after a restart (app/pool_store.py), so the index built from it
    is the same index — and re-packing it is 165 s on the analyst's workspace, during which every
    query falls back to the 35-45 s scan path. Refuses on any mismatch: a changed pool, a changed
    packing code, a different event count.
    """
    if not sig:
        return None
    # Publish "building" BEFORE the read: restoring a 5.4 GB index off a bind mount measured 127-167 s,
    # and for all of it `index_status()` said `idle` — which every screen renders as "nothing is
    # happening" and every search reads as "no index, use the scan path". A long operation with no
    # feedback is the same bug as a long operation with no progress bar.
    _status_begin(len(events), version)
    _status["note"] = "restoring the saved index"
    hit = index_store.load(sig)
    if not hit:
        _status_reset()
        return None
    t0 = time.perf_counter()
    arr, header = hit["arrays"], hit["header"]
    n = len(events)
    if int(header.get("n") or 0) != n or arr["offsets"].size != n + 1 or arr["sev"].size != n:
        _note_index_cache_mismatch(n, header)
        _status_reset()
        return None
    idx = SearchIndex(version=version, n=n, text=arr["text"], offsets=arr["offsets"], sev=arr["sev"],
                      source=arr["source"], sources=list(header.get("sources") or []), ts=ts,
                      bytes=int(arr["text"].nbytes), raw=hit.get("raw"))
    idx.byte_counts = arr["byte_counts"]
    ap = compute.xp()
    idx.gpu_backend = ap is not np
    if ap is not np and n >= _MIN_VECTOR and _gpu_fits(ap, idx.text.nbytes + idx.offsets.nbytes + ts.nbytes):
        try:
            host_counts = idx.byte_counts
            idx.text = compute.to_device(arr["text"])
            idx.offsets = compute.to_device(arr["offsets"])
            idx.sev = compute.to_device(arr["sev"])
            idx.source = compute.to_device(arr["source"])
            idx.ts = compute.to_device(ts)
            idx.on_gpu = True
            idx.raw = None                     # host buffer released; the GPU has the vector path
            idx.byte_counts = host_counts      # a numpy histogram is what _byte_counts wants
        except Exception as exc:               # OOM or a hiccup: numpy is always correct, only slower
            _note_gpu_skip(f"the transfer failed ({type(exc).__name__}: {exc})")
            idx.text, idx.offsets = arr["text"], arr["offsets"]
            idx.sev, idx.source, idx.ts, idx.on_gpu = arr["sev"], arr["source"], ts, False
    idx.build_ms = (time.perf_counter() - t0) * 1000.0
    _status_done(idx)
    return idx


def _note_index_cache_mismatch(n: int, header: dict) -> None:
    print(f"[iris] search index cache: it holds {header.get('n')} events and the pool has {n}; rebuilding")


class _Engine:
    """Lowers a query AST to a boolean candidate mask over the index."""

    def __init__(self, idx: SearchIndex) -> None:
        self.idx = idx
        self.ap = compute.xp() if idx.on_gpu else np
        self.exact = True  # False once an approximate (upper-bound) atom is used → CPU confirmation required

    # -- primitives
    def all_true(self) -> Any:
        return self.ap.ones(self.idx.n, dtype=bool)

    def contains(self, needle: bytes) -> Any:
        """Events whose document contains `needle` (case already lowered).

        Two things decide the cost, and both were learned the hard way on the analyst's 5.4 GB index:

        * **The scan is CHUNKED.** `hay[k0:k0 + span] == b` materialises a bool array the size of the
          whole packed buffer — 5.4 GB, on a card that is already holding the 5.4 GB index. That is
          how a query on a 12 GB device ends up thrashing, and it is the same trap `byte_histogram`
          and `compute.to_device` already document. A 256 MiB window keeps every temporary bounded and
          the arithmetic identical.
        * **Up to three rare bytes anchor the window, not one.** The first pass used the single rarest
          byte, so a needle made of common characters — `45.83.140.22`, every byte of it a digit or a
          dot — produced hundreds of millions of candidate positions to gather over. ANDing the two or
          three rarest byte comparisons costs one cheap sequential pass each and cuts the candidate set
          by orders of magnitude before a single gather happens.

        The result is bit-identical to the one-byte version: the anchors are a subset of the needle's
        own bytes, and every remaining byte is still verified by gather.
        """
        ap, idx = self.ap, self.idx
        m = len(needle)
        hay = idx.text
        N = int(hay.shape[0])
        if m == 0 or idx.n == 0:
            return self.all_true()
        if N < m:
            return ap.zeros(idx.n, dtype=bool)
        # On the CPU, the C library's substring search beats anything expressible in numpy: it is
        # SIMD and it stops at the first mismatched byte, where an elementwise compare always touches
        # the whole buffer. It gives up above `_FIND_CAP` hits, where the per-hit Python cost would
        # exceed the scan it is replacing.
        if not idx.on_gpu and idx.raw is not None:
            hits = self._find_all(needle)
            if hits is not None:
                mask = np.zeros(idx.n, dtype=bool)
                if hits:
                    ev = np.searchsorted(idx.offsets, np.asarray(hits, dtype=np.int64), side="right") - 1
                    mask[ev] = True
                return mask
        nd = np.frombuffer(needle, dtype=np.uint8)
        span = N - m + 1
        counts = self._byte_counts()
        order = sorted(range(m), key=lambda k: counts[int(nd[k])])
        anchors, rest = order[:_ANCHORS], order[_ANCHORS:]

        mask = ap.zeros(idx.n, dtype=bool)
        step = max(_SCAN_CHUNK, m)
        # `int(array.shape[0])` on a device array is a HOST SYNC. Skipping the chunk early is worth a
        # sync on numpy (it is free there) and costs one on the GPU — ~84 chunks over a 5.4 GB buffer,
        # each stalling the pipeline, which is where most of a ~0.9 s device query actually went. On
        # the GPU the work is queued unconditionally instead: an empty candidate set costs a kernel
        # launch over nothing, which is far cheaper than stopping to ask whether it is empty.
        on_host = ap is np
        start = 0
        while start < span:
            stop = min(span, start + step)
            window = None
            for k in anchors:
                hit = hay[start + k:stop + k] == int(nd[k])
                window = hit if window is None else (window & hit)
            pos = ap.flatnonzero(window) + start
            del window
            for k in rest:
                if on_host and pos.shape[0] == 0:
                    break
                pos = pos[hay[pos + k] == int(nd[k])]
            if not on_host or pos.shape[0]:
                ev = ap.searchsorted(idx.offsets, pos, side="right") - 1
                mask[ev] = True
            del pos
            start = stop
        return mask

    def _find_all(self, needle: bytes) -> Optional[list[int]]:
        """Every offset of `needle` in the packed buffer, or None if there are too many to be worth it.

        `bytes.find` is memmem — the same routine `grep` leans on. The loop is the only Python in the
        hot path, which is why it has a ceiling rather than a promise.
        """
        buf = self.idx.raw
        if buf is None:
            return None
        n_bytes = len(buf)
        cap = max(_FIND_MIN_CAP, n_bytes // _FIND_BYTES_PER_HIT)
        out: list[int] = []
        append = out.append
        find = buf.find
        pos = find(needle)
        probe = _FIND_PROBE
        while pos != -1:
            append(pos)
            got = len(out)
            if got >= probe:
                # Project the total from the density so far rather than discovering it hit by hit;
                # `pos` is how far into the buffer this many hits took.
                if got * (n_bytes / max(1, pos)) > cap:
                    return None
                probe = got + _FIND_PROBE
            pos = find(needle, pos + 1)
        return out

    def _byte_counts(self) -> np.ndarray:
        # Normally precomputed by build_index (see byte_histogram): this fallback only fires for an index
        # built by an older code path. Doing it here meant the FIRST query of an index paid for a full
        # histogram of the whole buffer — 7.5 s on a 1.2 GB index against 0.74 s for every query after.
        if self.idx.byte_counts is None:
            self.idx.byte_counts = byte_histogram(compute.asnumpy(self.idx.text) if self.idx.on_gpu
                                                  else np.asarray(self.idx.text))
        return self.idx.byte_counts

    def sev_mask(self, values: set[str]) -> Any:
        codes = [_SEV_CODE[v] for v in values if v in _SEV_CODE]
        if not codes:
            return self.ap.zeros(self.idx.n, dtype=bool)
        return self.ap.isin(self.idx.sev, self.ap.asarray(np.asarray(codes, dtype=np.int8)))

    def source_mask(self, value: str) -> Any:
        """SUBSTRING over the source label — the DSL's `source:foo` semantics, an upper bound."""
        codes = [i for i, lab in enumerate(self.idx.sources) if value in lab.lower()]
        if not codes:
            return self.ap.zeros(self.idx.n, dtype=bool)
        return self.ap.isin(self.idx.source, self.ap.asarray(np.asarray(codes, dtype=np.int32)))

    def source_mask_exact(self, values: set[str]) -> Any:
        """The SOURCE FILTER (chips, `?sources=`), which is exact equality — not the DSL's substring.

        `sources[c]` is "<label><SEP><file><SEP><sourceId>" and the code is per sourceId, so comparing
        each part against the requested set reproduces the confirm loop's
        `e.source in src_set or e.sourceId in src_set or e.file in src_set` EXACTLY.

        This is worth its own method because of what the approximate one costs: a substring mask is an
        upper bound, so picking a source chip forced every candidate through the Python predicate — on
        a query matching ten million events that is a full pass over the pool for a page of 200 rows,
        which is the "search is slow" report. With an exact mask the filter is a vector op and the
        count is the popcount.
        """
        codes = [i for i, lab in enumerate(self.idx.sources)
                 if any(part in values for part in lab.split(_SRC_SEP))]
        if not codes:
            return self.ap.zeros(self.idx.n, dtype=bool)
        return self.ap.isin(self.idx.source, self.ap.asarray(np.asarray(codes, dtype=np.int32)))

    # -- lowering
    def lower(self, node: Node, negate: bool = False) -> Any:
        k = node.kind
        if k == "true":
            return self.all_true()
        if k == "not":
            return self.lower(node.children[0], negate=not negate)
        if k in ("and", "or"):
            masks = [self.lower(c, negate) for c in node.children]
            out = masks[0]
            # under negation AND/OR swap (De Morgan) because we already pushed the NOT into the leaves
            combine_and = (k == "and") != negate
            for mk in masks[1:]:
                out = (out & mk) if combine_and else (out | mk)
            return out
        assert node.tok is not None
        f, v = atom_parts(node.tok)
        if f is None:
            mask = self.contains(v.encode("utf-8", "replace"))
            return ~mask if negate else mask
        if f == "sev":
            mask = self.sev_mask({x for x in v.split(",")})
            return ~mask if negate else mask
        if f == "source" and "*" not in v:
            mask = self.source_mask(v)
            return ~mask if negate else mask
        if f == "ts":
            self.exact = False
            return self.all_true()
        # field:value → value substring anywhere in the doc is an upper bound (exact check happens on CPU)
        self.exact = False
        if negate or "*" in v or f == "id":
            return self.all_true()
        needle = v.encode("utf-8", "replace")
        if len(needle) < 2:
            return self.all_true()
        return self.contains(needle)


_lock = threading.Lock()            # guards the _index POINTER only — never held across a build
_build_lock = threading.Lock()      # one build at a time, and never on a request thread
_index: Optional[SearchIndex] = None
# Live build progress. A 2.5 M-event pool takes minutes to index and used to do it INSIDE _lock on the
# first query: the request blocked past a 60 s client timeout with nothing to show for it, which reads
# exactly like a hang. Now the request falls back to the scan and this says what is going on.
_status: dict[str, Any] = {"state": "idle", "events": 0, "target": 0, "startedTs": 0.0,
                           "version": -1, "bytes": 0, "buildMs": 0.0}


def _status_reset() -> None:
    """Drop a 'building' that is not going to finish — a restore that missed, so the caller can build."""
    with _lock:
        _status.update(state="idle", events=0, target=0, startedTs=0.0)
        _status.pop("note", None)


def _status_begin(n: int, version: int) -> None:
    with _lock:
        _status.update(state="building", events=0, target=n, startedTs=time.time(), version=version)


def _status_tick(i: int) -> None:
    with _lock:
        _status["events"] = i


def _status_done(idx: SearchIndex) -> None:
    with _lock:
        _status.update(state="ready", events=idx.n, target=idx.n, bytes=idx.bytes, buildMs=idx.build_ms)


def index_status() -> dict[str, Any]:
    """What the index is doing right now: state ('idle' | 'building' | 'ready'), how far, how long.

    Served alongside every search so a warming index is visible instead of looking like a stalled query.
    """
    with _lock:
        s = dict(_status)
        idx = _index
        ready = idx is not None
    target = int(s["target"] or 0)
    done = int(s["events"] or 0)
    elapsed = (time.time() - s["startedTs"]) if s["startedTs"] else 0.0
    building = s["state"] == "building"
    return {"state": "building" if building else ("ready" if ready else "idle"),
            # why it is building: a fresh pack, or a restore of the saved one. The screens already
            # render `note` for the derived caches; this is the same contract.
            "note": s.get("note") or "",
            "events": done, "target": target,
            "pct": round(min(100.0, done / target * 100.0), 1) if (building and target) else (100.0 if ready else 0.0),
            "elapsedSec": int(elapsed) if building else 0,
            "bytes": int(s["bytes"] or 0), "buildMs": round(float(s["buildMs"] or 0.0), 1),
            # WHY a query did not use the index. "ready" here only means a build finished — the index
            # is still rejected if the pool moved under it (`version`/`n`) or the compute backend
            # flipped since the build. Without these three fields the only visible symptom is a search
            # that says `engine: cpu` next to an index that says `ready`, which is unexplainable from
            # the outside — and that is exactly the state the analyst reported.
            "indexVersion": (idx.version if idx else None),
            "indexEvents": (idx.n if idx else None),
            "onGpu": (bool(idx.on_gpu) if idx else None),
            "gpuAtBuild": (bool(idx.gpu_backend) if idx else None),
            "gpuNow": compute.xp() is not np}


def index_ready(events: list[Event], ts: np.ndarray, version: int) -> Optional[SearchIndex]:
    """The CURRENT index, or None. Never builds — building is the request path's job to avoid, not to do."""
    with _lock:
        idx = _index
    if idx is None or idx.version != version or idx.n != len(events):
        return None
    # the compute backend flipped since the build (GPU came or went): let a background warm redo it
    if (compute.xp() is not np) != idx.gpu_backend:
        return None
    return idx


def get_index(events: list[Event], ts: np.ndarray, version: int, sig: str = "") -> SearchIndex:
    """The index, BUILDING IT IF NEEDED. Only the background warm may call this.

    `sig` (from `index_store.signature(STORE)`) enables the on-disk cache: with it, a restart reads
    the packed buffer back in seconds instead of re-packing the pool for minutes. Without it — a
    caller that has no store to ask — the behaviour is exactly as before.
    """
    global _index
    with _build_lock:
        hit = index_ready(events, ts, version)
        if hit is not None:
            return hit
        sig = _signature(sig)
        idx = index_from_cache(sig, events, ts, version) if sig else None
        if idx is None:
            idx = build_index(events, ts, version, sig=sig)
        with _lock:
            _index = idx
        return idx


def invalidate() -> None:
    global _index
    with _lock:
        _index = None
        if _status["state"] != "building":
            _status.update(state="idle", events=0, target=0)


def search(events: list[Event], ts: np.ndarray, version: int, q: str, lo: int, hi: int,
           src_set: set[str], sev_set: set[str], offset: int, limit: int, desc: bool = False) -> dict[str, Any]:
    """Return {'rows', 'total', 'engine', 'tookMs', 'candidates'} for the given filters.

    `events` is always ascending by timestamp, so newest-first is just a reversed walk — no re-sort.
    """
    t0 = time.perf_counter()
    n = len(events)
    ast = parse_query(q)
    pred = node_pred(ast)
    engine = "cpu"
    cand_idx: Optional[np.ndarray] = None
    idx: Optional[SearchIndex] = None

    # NEVER build the index here. On a 2.5 M-event pool the build takes minutes and it used to happen on
    # whichever request arrived first, under the index lock — the query simply never came back. If the
    # index is not ready this request scans (slower, but it answers) and a background warm is kicked off.
    idx = index_ready(events, ts, version) if n >= _MIN_VECTOR else None
    if n >= _MIN_VECTOR and idx is None:
        warm_async(lambda: (events, ts, version), delay=0.0)
    if idx is not None:
        eng = _Engine(idx)
        ap = eng.ap
        try:
            mask = eng.lower(ast)
            if sev_set:
                mask &= eng.sev_mask(sev_set)
            if src_set:
                mask &= eng.source_mask_exact(src_set)
            if lo > 0 or hi < n:
                rng = ap.zeros(n, dtype=bool)
                rng[lo:hi] = True
                mask &= rng
            cand = ap.flatnonzero(mask)
            cand_idx = compute.asnumpy(cand) if idx.on_gpu else np.asarray(cand)
            engine = "cuda" if idx.on_gpu else "vector"
            exact = eng.exact
        except Exception:
            cand_idx, exact = None, False
    else:
        exact = False

    rows: list[Event] = []
    total = 0
    exact_total = True
    if cand_idx is not None:
        order = cand_idx[::-1] if desc else cand_idx
        # Both filter masks are EXACT (severity by code, source by equality on the label/file/id
        # triple), so they no longer force the confirm pass. Only an approximate ATOM in the query
        # does — that is what `eng.exact` means.
        if exact:
            total = int(cand_idx.shape[0])
            for i in order[offset:offset + limit].tolist():
                rows.append(events[i])
        else:
            for i in order.tolist():
                e = events[i]
                if src_set and e.source not in src_set and e.sourceId not in src_set and e.file not in src_set:
                    continue
                if sev_set and e.sev not in sev_set:
                    continue
                if not pred(e):
                    continue
                if offset <= total < offset + limit:
                    rows.append(e)
                total += 1
    else:
        # The SCAN path: no index, so every event goes through the Python predicate. On an 11 M-event
        # pool one query measured 172 s, and it spent nearly all of it counting matches the caller
        # never asked for — a page of 25 rows was ready in the first second. It now stops once it has
        # the page AND enough beyond it to answer "how many", and says the count is a floor rather
        # than quietly rounding: `totalExact: false` with `total` = what it actually counted. A number
        # an analyst might quote has to be exact or VISIBLY not, never silently approximate.
        want = offset + limit
        budget = max(want + _SCAN_COUNT_AHEAD, _SCAN_COUNT_AHEAD)
        for i in (range(hi - 1, lo - 1, -1) if desc else range(lo, hi)):
            e = events[i]
            if src_set and e.source not in src_set and e.sourceId not in src_set and e.file not in src_set:
                continue
            if sev_set and e.sev not in sev_set:
                continue
            if not pred(e):
                continue
            if offset <= total < want:
                rows.append(e)
            total += 1
            if total >= budget:
                exact_total = False
                break
    return {"rows": rows, "total": total, "totalExact": exact_total,
            "engine": engine, "tookMs": round((time.perf_counter() - t0) * 1000.0, 1),
            "candidates": int(cand_idx.shape[0]) if cand_idx is not None else n,
            "indexBytes": idx.bytes if idx else 0,
            "index": {**index_status(), "poolVersion": version,
                      # the answer to "it says ready, so why did this query scan?"
                      "used": idx is not None}}


# How the index cache learns what pool it is indexing. `search.py` must not import the store (cycle),
# and the warm that a QUERY kicks off has no store handle to ask — so without this the on-disk index
# was only ever written by the store's own warm, which is the path that does NOT run after a restart.
# Symptom: the cache file simply never appeared, with nothing in the log to explain it.
_sig_provider: Optional[Any] = None


# Whether an expensive build may start at all. `Store.warm_search_async` has always checked this, but
# the warm a QUERY kicks off called `warm_async` directly and did not — so during an enrichment run
# every search started a 165 s re-pack that the next finished source invalidated, on repeat. Observed
# live as the index cycling ready -> idle -> building -> ready with no query ever using it.
_warm_gate: Optional[Any] = None


def set_warm_gate(fn) -> None:
    """Called once at startup by the store. `fn()` is False while an ingest/enrichment storm is on."""
    global _warm_gate
    _warm_gate = fn


def may_warm() -> bool:
    try:
        return bool(_warm_gate()) if _warm_gate else True
    except Exception:                    # noqa: BLE001 — an unanswerable gate must not stop the warm
        return True


def set_signature_provider(fn) -> None:
    """Called once at startup by the store. `fn()` returns the current index signature, or ''."""
    global _sig_provider
    _sig_provider = fn


def _signature(sig: str = "") -> str:
    if sig:
        return sig
    try:
        return _sig_provider() if _sig_provider else ""
    except Exception:                    # noqa: BLE001 — no signature just means no cache
        return ""


_warm_timer: Optional[threading.Timer] = None
_warming = False        # a build thread is scheduled or running — do not queue a second one


def warm_async(events_getter, delay: float = 1.5) -> None:
    """Build the index in the background shortly after the pool changes so no query ever pays for it.

    `events_getter` returns (events, ts, version). Debounced, and single-flight: a search that finds the
    index missing calls this too, and on a big pool several searches can arrive while it builds — each
    one must not start its own multi-minute, multi-gigabyte build.
    """
    global _warm_timer, _warming
    with _lock:
        if _warming:
            return
        if _warm_timer is not None:
            _warm_timer.cancel()
        _warming = True

    def run() -> None:
        global _warming
        try:
            # Re-checked HERE, not when the timer was set: the pause can start during the delay, and
            # what matters is whether a build is worth starting at the moment it would start.
            if not may_warm():
                return
            got = events_getter()
            # (events, ts, version) or (events, ts, version, signature) — the store passes a signature
            # so the warm can read the index off disk instead of re-packing the pool.
            events, ts, version = got[0], got[1], got[2]
            sig = got[3] if len(got) > 3 else ""
            if len(events) >= _MIN_VECTOR:
                get_index(events, ts, version, sig=sig)
        except Exception:
            pass
        finally:
            with _lock:
                _warming = False

    with _lock:
        _warm_timer = threading.Timer(max(0.0, delay), run)
        _warm_timer.daemon = True
        _warm_timer.start()
