"""The GPU and numpy paths must produce IDENTICAL results.

Every accelerated path in Iris has a numpy twin it falls back to (no GPU installed, an index over the
device budget, a transfer that failed). If the two ever disagree the app reports different evidence
depending on which machine it runs on, which is worse than being slow — so each one is pinned here.

The GPU half is skipped cleanly when there is no usable CUDA backend; the CPU-only assertions
(vectorised sliding window, chunk boundaries, budget refusals) always run.
"""
from __future__ import annotations

import numpy as np
import pytest

from app import compute, correlate, detect, search
from app.models import Detection, Event


def _gpu_or_skip():
    """The active array module when it is really cupy, else skip."""
    pytest.importorskip("cupy")
    compute.probe()
    ap = compute.xp()
    if ap is np:
        pytest.skip("no usable CUDA backend on this machine")
    return ap


# --------------------------------------------------------------------- helpers
def _ev(i: int, ts: str, msg: str, entities: list[str], sev: str = "info", det: bool = False) -> Event:
    return Event(id=f"e{i}", ts=ts, source="syslog", sourceId="s1", file="f.log", host="h1", user="u1",
                 msg=msg, sev=sev, raw=msg, fields={"k": str(i % 7)}, entities=entities,
                 detections=[Detection(name="X", id="SIGMA-TEST-0001", level="high")] if det else [])


def _pool(n: int = 3000) -> tuple[list[Event], np.ndarray]:
    events = [
        _ev(i, f"2026-03-01T00:{i // 60 % 60:02d}:{i % 60:02d}Z",
            f"login failed for user{i % 37} from 10.0.{i % 5}.{i % 251}",
            [f"user{i % 37}", f"10.0.{i % 5}.{i % 251}"], sev="high" if i % 11 == 0 else "info",
            det=(i % 13 == 0))
        for i in range(n)
    ]
    ts = np.arange(n, dtype=np.float64)
    return events, ts


# ------------------------------------------------------- compute.to_device
def test_to_device_round_trips_exactly():
    ap = _gpu_or_skip()
    for nbytes in (1024, compute.H2D_CHUNK + 7, compute.H2D_CHUNK * 2 + 3):
        host = (np.arange(nbytes, dtype=np.int64) % 251).astype(np.uint8)
        dev = compute.to_device(host)
        assert dev is not host
        assert np.array_equal(compute.asnumpy(dev), host)
        del dev
    ap.get_default_memory_pool().free_all_blocks()


def test_to_device_is_a_no_op_without_a_gpu(monkeypatch):
    monkeypatch.setattr(compute, "xp", lambda: np)
    host = np.arange(10, dtype=np.uint8)
    assert compute.to_device(host) is host


def test_gpu_fits_reports_a_reason_without_a_device(monkeypatch):
    monkeypatch.setattr(compute, "device_memory", lambda: None)
    ok, why = compute.gpu_fits(1)
    assert ok is False and why


# --------------------------------------------------------- byte histogram
def test_byte_histogram_gpu_matches_numpy():
    _gpu_or_skip()
    rng = np.random.default_rng(11)
    buf = rng.integers(0, 256, size=search._GPU_HIST_MIN * 2 + 12345, dtype=np.uint8)
    reference = np.zeros(256, dtype=np.int64)
    for s in range(0, buf.shape[0], 1 << 20):
        reference += np.bincount(buf[s:s + (1 << 20)], minlength=256)
    got = search.byte_histogram(buf)
    assert np.array_equal(got, reference)
    assert int(got.sum()) == buf.shape[0]


def test_byte_histogram_accepts_a_device_buffer():
    _gpu_or_skip()
    rng = np.random.default_rng(12)
    host = rng.integers(0, 256, size=search._GPU_HIST_MIN + 1000, dtype=np.uint8)
    dev = compute.to_device(host)
    assert np.array_equal(search.byte_histogram(dev), search.byte_histogram(host))


# ------------------------------------------------------- co-occurrence
def _random_masks(n: int, ncols: int, seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    bits = rng.integers(0, 2, size=(n, ncols), dtype=np.uint64)
    shifts = np.arange(ncols, dtype=np.uint64)
    masks = (bits << shifts).sum(axis=1).astype(np.uint64)
    return masks[masks != 0]


def test_cooccurrence_gpu_matches_numpy():
    _gpu_or_skip()
    for n, ncols in ((5000, 48), (correlate._CO_CHUNK + 137, 9)):
        masks = _random_masks(n, ncols, seed=n)
        assert np.array_equal(correlate.cooccurrence(masks, ncols),
                              correlate._cooccurrence_np(masks, ncols))


def test_cooccurrence_falls_back_when_the_device_is_full(monkeypatch):
    masks = _random_masks(1000, 12, seed=3)
    monkeypatch.setattr(correlate, "gpu_fits", lambda need, fraction=0.5: (False, "pretend the card is full"))
    assert np.array_equal(correlate.cooccurrence(masks, 12), correlate._cooccurrence_np(masks, 12))


def test_cooccurrence_is_symmetric_and_counts_events():
    masks = _random_masks(4000, 16, seed=5)
    co = correlate.cooccurrence(masks, 16)
    assert np.array_equal(co, co.T)
    for j in range(16):
        assert co[j, j] == int(((masks >> np.uint64(j)) & np.uint64(1)).sum())


# ------------------------------------------------- vectorised sliding window
def _find_bursts_reference(idx, ts, key_of, window_s, threshold):
    """The original Python sliding window, kept as the oracle for the vectorised one."""
    from collections import defaultdict
    groups: dict[str, list[int]] = defaultdict(list)
    for i in idx:
        k = key_of(i)
        if k:
            groups[k].append(i)
    out = []
    for key, members in groups.items():
        if len(members) < threshold:
            continue
        arr = np.asarray(members)
        t = ts[arr]
        order = np.argsort(t, kind="stable")
        arr, t = arr[order], t[order]
        j = 0
        best = None
        for k in range(len(arr)):
            while t[k] - t[j] > window_s:
                j += 1
            count = k - j + 1
            if count >= threshold and (best is None or count > best[1]):
                best = (int(arr[k]), count, int(arr[j]))
        if best is not None:
            out.append((key, best[0], best[1], best[2]))
    return out


@pytest.mark.parametrize("window,threshold", [(60.0, 3), (5.0, 2), (1.0, 10), (3600.0, 50)])
def test_find_bursts_matches_the_scalar_sliding_window(window, threshold):
    rng = np.random.default_rng(19)
    n = 4000
    ts = np.sort(rng.integers(0, 4000, size=n).astype(np.float64))
    keys = [f"10.0.0.{i % 17}" if i % 23 else "" for i in range(n)]
    got = detect.find_bursts(range(n), ts, lambda i: keys[i], window, threshold)
    want = _find_bursts_reference(range(n), ts, lambda i: keys[i], window, threshold)
    assert sorted(got) == sorted(want)


def test_find_bursts_handles_ties_and_empties():
    ts = np.zeros(10, dtype=np.float64)
    assert detect.find_bursts(range(10), ts, lambda i: "k", 60.0, 10) == [("k", 9, 10, 0)]
    assert detect.find_bursts([], ts, lambda i: "k", 60.0, 2) == []
    assert detect.find_bursts(range(10), ts, lambda i: "", 60.0, 2) == []


# ---------------------------------------------------------------- search
_QUERIES = ["failed", "user7", "sev:high", "10.0.3.1", "failed AND user7", "NOT user7", "k:3", "nosuchtoken"]


def test_search_results_identical_on_gpu_and_numpy(monkeypatch):
    """Same pool, same queries, index on the device vs index on the host."""
    _gpu_or_skip()
    events, ts = _pool()

    search.invalidate()
    monkeypatch.setenv("IRIS_GPU_INDEX_MAX", "0")   # 0 = never put the index on the GPU
    cpu_idx = search.get_index(events, ts, 1)
    assert cpu_idx.on_gpu is False
    cpu = {q: search.search(events, ts, 1, q, 0, len(events), set(), set(), 0, 1000) for q in _QUERIES}

    search.invalidate()
    monkeypatch.delenv("IRIS_GPU_INDEX_MAX")        # auto: budgeted against free device memory
    gpu_idx = search.get_index(events, ts, 2)
    if not gpu_idx.on_gpu:
        pytest.skip("the device declined the index (budget); nothing to compare")
    gpu = {q: search.search(events, ts, 2, q, 0, len(events), set(), set(), 0, 1000) for q in _QUERIES}

    assert np.array_equal(cpu_idx.byte_counts, gpu_idx.byte_counts)
    for q in _QUERIES:
        assert gpu[q]["engine"] == "cuda"
        assert cpu[q]["engine"] == "vector"
        assert gpu[q]["total"] == cpu[q]["total"], q
        assert [e.id for e in gpu[q]["rows"]] == [e.id for e in cpu[q]["rows"]], q
    search.invalidate()


def test_search_index_stays_on_cpu_when_the_cap_is_zero(monkeypatch):
    events, ts = _pool(2500)
    monkeypatch.setenv("IRIS_GPU_INDEX_MAX", "0")
    search.invalidate()
    idx = search.get_index(events, ts, 7)
    assert idx.on_gpu is False
    # and it still answers: the CPU path is a supported mode, not a degraded one
    assert search.search(events, ts, 7, "failed", 0, len(events), set(), set(), 0, 10)["total"] > 0
    search.invalidate()
