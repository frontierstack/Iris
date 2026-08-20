"""Startup must never wait for the workspace pool, and the index must never wait for the GPU.

Two production failures this pins:

1. A real library held 589 MB across ~40 staged files. Parsing it inside `cases.startup()` — which runs
   in the FastAPI lifespan — meant `INFO: Waiting for application startup.` for 6+ minutes,
   `/api/health` unreachable and the container marked `unhealthy`. The pool now loads in a daemon thread
   and `Case.poolLoading` / `poolPending` say so.
2. The packed search index spans the whole pool now, so it grew to 1.16 GB. cupy could not allocate
   pinned host memory for it, warned, and fell back to a SYNCHRONOUS transfer: 100 % CPU, 8 GiB RSS and
   still no API. Oversized indexes now stay on numpy, decided before anything is transferred.
"""
from __future__ import annotations

import threading
import time

import numpy as np
import pytest
from fastapi.testclient import TestClient

from app import cases, search as search_mod
from app import store as store_mod
from app.main import app
from app.store import STORE, Store
from tests.conftest import drain_enrichment

LINE = b"Jan 01 00:00:01 host sshd[1]: Accepted password for alice from 45.66.13.201 port 22 ssh2\n"


@pytest.fixture()
def c():
    with TestClient(app) as client:
        yield client


def _wipe(c) -> None:
    for cid in list(cases.case_ids()):
        c.delete(f"/api/cases/{cid}")
    for f in c.get("/api/library").json():
        if f["caseId"] == "":
            c.delete(f"/api/library/unattached/{f['fileName']}")


def _cold_process() -> None:
    """Simulate a fresh process. STORE is a module global that outlives a TestClient, so without this a
    "restart" would just find the pool already in memory and prove nothing about the restore path."""
    with STORE.lock:
        STORE._clear_memory(delete_files=False)


def _await_pool(client, timeout: float = 30.0) -> dict:
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        case = client.get("/api/case").json()
        if not case["poolLoading"]:
            return case
        time.sleep(0.02)
    raise AssertionError("the pool never finished loading")


def test_startup_does_not_block_on_the_library_pool(c, monkeypatch) -> None:
    # The pool cache is off here on purpose: with it warm the restore finishes before the first
    # request lands, so there is no "still filling" state left to observe — this test is about the
    # startup NOT blocking while a real parse runs, which is the case a cold cache produces.
    monkeypatch.setenv("IRIS_POOL_CACHE", "0")
    _wipe(c)
    for i in range(3):
        r = c.post("/api/library/upload", files=[("files", (f"pool-{i}.log", LINE * 5, "text/plain"))])
        assert r.status_code == 200, r.text
    expected = c.get("/api/events", params={"limit": 1}).json()["total"]
    assert expected == 15

    # force the background path (a real library is far over the limit) and hold the parser at the door,
    # so "the API answered while the pool was still loading" is a fact, not a timing coincidence
    gate = threading.Event()
    original = Store._add_library_members

    def held(self, *a, **kw):
        gate.wait(30)
        return original(self, *a, **kw)

    monkeypatch.setattr(store_mod, "LIBRARY_SYNC_LIMIT", 0)
    monkeypatch.setattr(Store, "_add_library_members", held)

    _cold_process()
    t0 = time.perf_counter()
    with TestClient(app) as restarted:          # runs the whole startup lifespan again
        started = time.perf_counter() - t0
        assert started < 10, f"startup blocked on the pool for {started:.1f}s"
        assert restarted.get("/api/health").json()["ok"] is True

        loading = restarted.get("/api/case").json()
        assert loading["poolLoading"] is True, "the pool must report that it is still filling"
        assert loading["poolPending"] == 3
        assert loading["poolEventCount"] == 0, "nothing parsed yet — and that is reported, not hidden"

        gate.set()
        done = _await_pool(restarted)
        assert done["poolEventCount"] == expected, "the background load lost or duplicated events"
        assert done["poolPending"] == 0 and done["poolLoaded"] == 3
        assert restarted.get("/api/events", params={"limit": 1}).json()["total"] == expected


def test_startup_is_immediate_with_an_empty_library(c) -> None:
    _wipe(c)
    _cold_process()
    t0 = time.perf_counter()
    with TestClient(app) as restarted:
        assert time.perf_counter() - t0 < 10
        case = restarted.get("/api/case").json()
        assert case["poolLoading"] is False and case["poolPending"] == 0


def test_a_small_library_is_loaded_before_the_api_answers(c) -> None:
    """Under LIBRARY_SYNC_LIMIT the load stays inline, so a normal install has no loading window."""
    _wipe(c)
    c.post("/api/library/upload", files=[("files", ("small.log", LINE * 4, "text/plain"))])
    _cold_process()
    with TestClient(app) as restarted:
        case = restarted.get("/api/case").json()
        assert case["poolLoading"] is False
        assert case["poolEventCount"] == 4


def test_the_pool_is_capped_and_says_so(c, monkeypatch) -> None:
    """A library bigger than the memory budget degrades honestly instead of being OOM-killed.

    ~35 bytes of RSS per byte of log means a 589 MB library would ask for ~20 GB. Files past the budget
    stay listed in the library and stay attachable to a case — they are just not in the pool.
    """
    _wipe(c)
    for i in range(4):
        c.post("/api/library/upload", files=[("files", (f"capped-{i}.log", LINE * 20, "text/plain"))])

    monkeypatch.setattr(store_mod, "pool_budget_bytes", lambda: len(LINE) * 25)  # room for one file only
    _cold_process()
    with TestClient(app) as restarted:
        case = _await_pool(restarted)
        assert case["poolSkipped"] == 3
        assert case["poolLoaded"] == 1 and case["poolEventCount"] == 20
        # nothing was lost: every staged file is still there and still attachable
        assert len([f for f in restarted.get("/api/library").json() if f["caseId"] == ""]) == 4


# ------------------------------------------------------------------ GPU index sizing
def _events(n: int) -> tuple[list, np.ndarray]:
    from app.models import Event

    events = [Event(id=f"e{i:x}", ts="2026-01-01T00:00:00Z", source="syslog", sourceId="s1", file="f.log",
                    host="host", user="alice" if i % 3 == 0 else "bob", msg=f"line {i} needle-{i % 7}",
                    sev="info", raw=f"raw line {i} needle-{i % 7}") for i in range(n)]
    ts = np.zeros(n, dtype=np.float64)
    return events, ts


class _FakeCupy:
    """A cupy stand-in whose device transfer fails the way an out-of-memory one does."""

    def __init__(self, memfree: int = 1 << 40) -> None:
        self.memfree = memfree
        self.transfers = 0

        class _rt:
            @staticmethod
            def memGetInfo():
                return (memfree, memfree)

        class _cuda:
            runtime = _rt

        self.cuda = _cuda

    def asarray(self, *a, **kw):
        self.transfers += 1
        raise MemoryError("cudaErrorMemoryAllocation: out of memory")


def test_an_oversized_index_never_reaches_the_gpu(monkeypatch) -> None:
    fake = _FakeCupy()
    monkeypatch.setattr(search_mod.compute, "xp", lambda: fake)
    monkeypatch.setattr(search_mod, "_gpu_index_cap", lambda: 1024)  # 1 KB cap: the index is far bigger
    events, ts = _events(2500)

    idx = search_mod.build_index(events, ts, version=1)
    assert idx.on_gpu is False
    assert fake.transfers == 0, "the size check must happen BEFORE the transfer, not after it fails"
    assert isinstance(idx.text, np.ndarray)


def test_a_failed_gpu_allocation_falls_back_to_numpy_with_correct_results(monkeypatch) -> None:
    fake = _FakeCupy()
    monkeypatch.setattr(search_mod.compute, "xp", lambda: fake)
    monkeypatch.setattr(search_mod, "_gpu_index_cap", lambda: 1 << 30)  # allowed by size…
    events, ts = _events(2500)
    search_mod.invalidate()

    # the background warm owns the build — search() itself must never do it (see test_index_warm.py)
    search_mod.get_index(events, ts, 99)
    res = search_mod.search(events, ts, 99, "needle-3", 0, len(events), set(), set(), 0, 10)
    assert fake.transfers > 0, "the transfer was attempted"          # …but the device refuses it
    assert res["engine"] == "vector", "it must degrade to the numpy vector path, not to a hang"
    expected = sum(1 for e in events if "needle-3" in e.raw)
    assert res["total"] == expected > 0
    assert all("needle-3" in r.raw for r in res["rows"])
    search_mod.invalidate()


def test_gpu_skips_when_the_device_is_nearly_full(monkeypatch) -> None:
    fake = _FakeCupy(memfree=1024)
    monkeypatch.setattr(search_mod.compute, "xp", lambda: fake)
    monkeypatch.setattr(search_mod, "_gpu_index_cap", lambda: 1 << 30)
    events, ts = _events(2500)

    idx = search_mod.build_index(events, ts, version=2)
    assert idx.on_gpu is False and fake.transfers == 0
    search_mod.invalidate()


def test_no_derived_build_starts_while_the_library_is_loading(c, monkeypatch):
    """Every file the loader lands bumps the version and invalidates the graph, the analysis and the
    anomaly roll-up; the sidebar polled the graph on every page. So during a 300 MB load Iris was starting
    a full six-worker graph extraction every few seconds and discarding each on the next bump — a memory
    and CPU storm that, on the analyst's WSL2 VM, ended in SIGSEGV. While `pool_loading` is set, the
    ready() paths must report `building` with a note and start NOTHING."""
    from app.graph import GRAPH_CACHE
    from app.store import STORE
    from app import anomalies as anom

    started = {"graph": 0}
    real = STORE._build_graph_v2

    def counted(*a, **k):
        started["graph"] += 1
        return real(*a, **k)

    monkeypatch.setattr(STORE, "_build_graph_v2", counted)
    monkeypatch.setattr(STORE, "pool_loading", True)
    try:
        r = c.get("/api/graph?limit=20").json()
        assert r["stats"]["status"]["state"] == "building"
        assert "library" in r["stats"]["status"].get("note", "")
        assert r["nodes"] == [] and started["graph"] == 0
        a = c.get("/api/anomalies?limit=5").json()
        assert a["status"]["state"] == "building" and a["anomalies"] == []
        t = c.get("/api/timeline").json()
        assert t.get("status", {}).get("state") == "building"
        assert STORE.graph_status("all")["state"] == "building"
    finally:
        monkeypatch.setattr(STORE, "pool_loading", False)
    # once the load is over the very same request builds for real. Phase-2 enrichment pauses derived
    # builds for the same reason the library load does, so let any queued source finish first —
    # otherwise this measures the enrichment pause, not the release of the library one.
    drain_enrichment()
    c.get("/api/graph?limit=20")
    for _ in range(200):
        if STORE.graph_status("all")["state"] == "ready":
            break
        time.sleep(0.05)
    assert STORE.graph_status("all")["state"] == "ready"
    assert "note" not in STORE.graph_status("all")
    assert GRAPH_CACHE.status("all", STORE._derived_key("all"))["state"] == "ready"


def test_a_bulk_load_merges_in_batches_not_once_per_file(c, monkeypatch):
    """Every merge is a sort + full reindex of the WHOLE pool. Per-file merges made a 34-file load
    quadratic and an allocation storm (34 rebuilds of a million-entry dict) — the exact churn under
    which the analyst's WSL2 VM started segfaulting the process. In bulk mode events are buffered and
    merged in batches; the result is identical, and it lands before the load ends."""
    from app.store import STORE
    from app import store as store_mod

    merges = {"n": 0}
    real = store_mod.Store._merge_into_pool

    def counted(self, events):
        merges["n"] += 1
        return real(self, events)

    monkeypatch.setattr(store_mod.Store, "_merge_into_pool", counted)
    _wipe(c)
    files = {f"f{i}.log": LINE * (10 + i) for i in range(6)}
    for name, data in files.items():
        r = c.post("/api/library/upload", files={"files": (name, data, "text/plain")})
        assert r.status_code == 200
    # a normal upload merges at once (six uploads, six merges) — that is not the bulk path
    assert merges["n"] >= 6
    ids_before = sorted(e.id for e in STORE.events)

    # now the bulk path: wipe memory and reload the same library the way startup does
    merges["n"] = 0
    STORE._clear_memory(delete_files=False, keep_library=False)
    STORE.load_library(background_ok=False)
    assert sorted(e.id for e in STORE.events) == ids_before          # identical pool
    assert merges["n"] < len(files), f"{merges['n']} merges for {len(files)} files — still per file"
    assert not STORE._pending                                        # nothing left buffered
    assert len(STORE.event_index) == len(STORE.events) == len(STORE.ts)
