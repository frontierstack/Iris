"""The entity graph and the correlation analysis are DERIVED caches, not per-request computations.

At 1,224,226 events `GET /api/graph?limit=50` took 90 s and `GET /api/timeline` 29.8 s because both
walked the whole event pool on every request whose store version had moved. They are now built once per
version, in the background (app/derived.py). Three properties have to hold, and only tests can hold them:

  1. a cache HIT must not iterate `STORE.events` at all — that is the whole point;
  2. the cache must MISS on anything that changes the pool (ingest, source delete, rule re-apply,
     clear-all) and on a case-set change for scope=case. A stale entity graph is worse than a slow one:
     an analyst acting on last version's relationships is acting on evidence that is no longer there;
  3. serving from the cache must not weaken the CLOSED-GRAPH invariant of test_graph_edges.py.
"""
from __future__ import annotations

import threading
import time

import pytest
from fastapi.testclient import TestClient

from app.correlate import ANALYSIS_CACHE
from app.derived import AsyncCache
from app.graph import GRAPH_CACHE
from app.main import app
from app.store import STORE
from tests.conftest import load_sample_case
from tests.conftest import drain_enrichment


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        load_sample_case(c)
        yield c


class _CountingList(list):
    """A list that records every full iteration of itself."""

    def __init__(self, *a):
        super().__init__(*a)
        self.iterations = 0

    def __iter__(self):
        self.iterations += 1
        return super().__iter__()


def _settle(counting, idle: float = 0.4, timeout: float = 15.0) -> None:
    """Wait until nothing is iterating STORE.events any more, then zero the counter.

    The no-scan assertions below count iterations GLOBALLY, but the app also walks the pool from unnamed
    daemon threads (the entity-count refresh in store.py, the background index warm, the library load).
    One of those still running from an earlier test gets attributed to our request and fails the assertion
    — which is exactly how this test flaked in the full suite while passing in isolation.
    """
    deadline = time.time() + timeout
    last, stable = counting.iterations, time.time()
    while time.time() < deadline:
        time.sleep(0.05)
        if counting.iterations != last:
            last, stable = counting.iterations, time.time()
        elif time.time() - stable >= idle:
            break
    counting.iterations = 0


def _anything_building() -> bool:
    """Is ANY background worker that walks STORE.events currently running?

    Not just the derived caches: the search index warm and the library pool load also scan the pool from
    their own daemon threads, and either one landing mid-measurement is attributed to the request. Missing
    them is what made the retry below give up too early and report a phantom "3x scan".
    """
    from app import search as _search
    if STORE.graph_status("all")["state"] == "building":
        return True
    if STORE.analysis_status("all")["state"] == "building":
        return True
    if _search.index_status().get("state") == "building":
        return True
    if getattr(_search, "_warming", False):
        return True
    return bool(getattr(STORE, "pool_loading", False))


def _measure_no_scan(counting, run, attempts: int = 4):
    """Run `run()` and return the iterations it caused, retrying around background interference.

    `_settle` only guarantees quiet at the moment it returns — a daemon build kicked off by an earlier
    test can start DURING the requests and be attributed to them, and the parallel graph path widened that
    window because the parent packs the whole pool before dispatching to workers. So: measure, and if the
    counter moved while a derived build was actually in flight, that reading is contaminated — settle and
    take it again. A non-zero count with nothing building is a real regression and is returned as-is.
    """
    for attempt in range(attempts):
        _settle(counting)
        run()
        n = counting.iterations
        if n == 0:
            return 0
        building = _anything_building()
        if not building or attempt == attempts - 1:
            return n
    return counting.iterations


def _warm(client):
    assert client.get("/api/graph?limit=50").status_code == 200
    assert client.get("/api/timeline").status_code == 200
    # small fixture -> built synchronously; both must report ready before the no-scan assertions
    assert STORE.graph_status("all")["state"] == "ready"
    assert STORE.analysis_status("all")["state"] == "ready"


# --------------------------------------------------------------------- no full scan on a cache hit
def test_graph_hit_does_not_iterate_the_event_pool(client, monkeypatch):
    _warm(client)
    counting = _CountingList(STORE.events)
    monkeypatch.setattr(STORE, "events", counting)
    def run():
        for params in ("limit=50", "limit=200", "types=ip,user&limit=50",
                       "relations=auth_from&limit=50", "q=10.&limit=50", "minCount=2&limit=50"):
            r = client.get(f"/api/graph?{params}")
            assert r.status_code == 200, r.text

    scans = _measure_no_scan(counting, run)
    assert scans == 0, (
        f"GET /api/graph walked the whole event pool {scans}x on a cache hit — every "
        f"filter must slice the cached graph instead of re-extracting entities")


def test_timeline_hit_does_not_iterate_the_event_pool(client, monkeypatch):
    _warm(client)
    counting = _CountingList(STORE.events)
    monkeypatch.setattr(STORE, "events", counting)
    def run():
        for _ in range(5):
            assert client.get("/api/timeline").status_code == 200

    scans = _measure_no_scan(counting, run)
    assert scans == 0, "GET /api/timeline re-ran correlation over the whole pool on a cache hit"


def test_graph_and_timeline_hits_are_fast(client):
    """A cache hit is a slice, not a build — cheap enough that the number is meaningful even here."""
    _warm(client)
    for url in ("/api/graph?limit=50", "/api/timeline"):
        times = []
        for _ in range(3):
            t0 = time.perf_counter()
            client.get(url)
            times.append(time.perf_counter() - t0)
        assert min(times) < 1.0, f"{url} took {min(times)*1000:.0f} ms from cache"


# --------------------------------------------------------------------------------- invalidation
def _graph_ids(client, **params) -> set[str]:
    r = client.get("/api/graph", params={"limit": 2000, **params})
    assert r.status_code == 200, r.text
    return {n["id"] for n in r.json()["nodes"]}


def test_ingest_invalidates_the_graph(client):
    _warm(client)
    before = _graph_ids(client)
    key_before = STORE._derived_key("all")
    body = b"Aug 17 04:11:02 cache-canary sshd[9931]: Accepted password for graphcanary from 198.51.100.77 port 51000 ssh2\n"
    r = client.post("/api/sources", files=[("files", ("cache-canary.log", body, "text/plain"))])
    assert r.status_code in (200, 201), r.text
    assert STORE._derived_key("all") != key_before, "an ingest must move the derived cache key"
    # Two-phase ingest: the parse happens on the enrichment worker, and while it is in flight
    # `Store.derived_builds_paused()` deliberately holds the derived builds off (one bump per
    # source would otherwise restart the whole extraction per file). Wait for the state the
    # analyst actually ends up looking at. The invalidation itself is asserted above.
    drain_enrichment()
    after = _graph_ids(client)
    assert after != before
    assert any(i.endswith(":198.51.100.77") or i.endswith(":graphcanary") for i in after), \
        "the newly ingested source is missing from the graph — a stale graph was served"


def test_source_delete_invalidates_the_graph(client):
    _warm(client)
    case = client.get("/api/case").json()
    sid = next(s for s in case["librarySources"] + case["sources"] if "cache-canary" in s["file"])["id"]
    assert client.delete(f"/api/sources/{sid}").status_code == 200
    after = _graph_ids(client)
    assert not any(i.endswith(":graphcanary") for i in after), \
        "a deleted source's entities are still in the graph — the cache was not invalidated"


def test_rule_reapply_invalidates_the_derived_caches(client):
    _warm(client)
    key = STORE._derived_key("all")
    n = STORE.reapply_all_rules()
    assert n >= 0
    assert STORE._derived_key("all") != key, "reapply_all_rules must bump the version the caches key on"
    assert GRAPH_CACHE.peek("all", STORE._derived_key("all")) is None, \
        "the pre-reapply graph was still reachable under the NEW key"
    # the next request must serve a graph built from the CURRENT version, never the old entry
    assert client.get("/api/graph?limit=50").status_code == 200
    assert STORE.graph_status("all")["state"] == "ready"


def test_case_set_change_invalidates_the_case_scope(client):
    eid = client.get("/api/events?limit=1").json()["rows"][0]["id"]
    client.post(f"/api/case-set/{eid}")
    assert client.get("/api/graph?scope=case&limit=50").status_code == 200
    key = STORE._derived_key("case")
    # a relabel leaves the case set the same SIZE — the key must still move
    client.post(f"/api/case-set/{eid}", json={"labels": ["pivot"]})
    assert STORE._derived_key("case") != key, "a case-set edit must move the scope=case cache key"


def test_clear_all_drops_the_cached_structures(client):
    _warm(client)
    assert GRAPH_CACHE.peek("all", STORE._derived_key("all")) is not None
    client.post("/api/admin/clear-all", json={"confirm": "DELETE ALL DATA"})
    assert GRAPH_CACHE.peek("all", STORE._derived_key("all")) is None
    assert ANALYSIS_CACHE.peek("all", STORE._derived_key("all")) is None
    g = client.get("/api/graph?limit=50").json()
    assert g["nodes"] == [] and g["edges"] == []


# ------------------------------------------------------------------- closed graph, served from cache
def test_cached_graph_is_still_closed(client):
    load_sample_case(client)
    _warm(client)
    for params in ({"limit": 10}, {"limit": 50}, {"limit": 2000}, {"types": "ip,user"},
                   {"relations": "auth_from,ran"}, {"q": "10."}, {"minCount": 2}):
        g = client.get("/api/graph", params=params).json()
        ids = {n["id"] for n in g["nodes"]}
        assert len(ids) == len(g["nodes"])
        dangling = [e["id"] for e in g["edges"] if e["source"] not in ids or e["target"] not in ids]
        assert not dangling, f"{params}: dangling edges served from the cache: {dangling[:5]}"
        eids = [e["id"] for e in g["edges"]]
        assert len(set(eids)) == len(eids), f"{params}: duplicate edge ids served from the cache"


def test_accepted_link_shows_immediately(client):
    """graph_links are OVERLAID on every response rather than baked into the cached builder, so an
    accepted AI link is visible on the very next request without rebuilding anything."""
    load_sample_case(client)
    g = client.get("/api/graph?limit=2000").json()
    ids = [n["id"] for n in g["nodes"]]
    a, b = ids[0], ids[1]
    r = client.post("/api/graph/links", json={"source": a, "target": b, "relation": "co_occurred",
                                              "why": "test", "ai": True})
    assert r.status_code == 200, r.text
    lid = r.json()["id"]
    g2 = client.get("/api/graph?limit=2000").json()
    assert any(e["id"] == lid for e in g2["edges"]), "an accepted link was not served on the next request"
    node_ids = {n["id"] for n in g2["nodes"]}
    assert all(e["source"] in node_ids and e["target"] in node_ids for e in g2["edges"])
    client.delete(f"/api/graph/links/{lid}")
    g3 = client.get("/api/graph?limit=2000").json()
    assert not any(e["id"] == lid for e in g3["edges"]), "a deleted link was still served"


# --------------------------------------------------------------------------- AsyncCache mechanics
def test_async_cache_is_single_flight():
    """A burst of requests must start exactly ONE build — at pool scale a second one is another
    90-second, multi-hundred-megabyte pass over the same events."""
    cache = AsyncCache("test", sync_limit=0)   # 0 => always background
    builds = []
    gate = threading.Event()

    def build():
        builds.append(1)
        gate.wait(5)
        return "value"

    for _ in range(25):
        assert cache.ready("all", "k1", 1000, build) is None
    gate.set()
    for _ in range(200):
        if cache.peek("all", "k1") is not None:
            break
        time.sleep(0.05)
    assert cache.peek("all", "k1") == "value"
    assert len(builds) == 1, f"{len(builds)} concurrent builds were started"


def test_async_cache_never_serves_a_stale_key():
    cache = AsyncCache("test", sync_limit=10_000)
    assert cache.get("all", "v1", 10, lambda: "first") == "first"
    assert cache.peek("all", "v1") == "first"
    assert cache.peek("all", "v2") is None, "a key from an older version must never be served"
    assert cache.status("all", "v2")["state"] != "ready"
    assert cache.get("all", "v2", 10, lambda: "second") == "second"
    assert cache.peek("all", "v1") is None, "only the newest value per slot is retained"


def test_async_cache_reports_building_progress():
    cache = AsyncCache("test", sync_limit=0)
    gate = threading.Event()

    def build():
        cache.tick("all", 500)
        gate.wait(5)
        return "v"

    assert cache.ready("all", "k", 1000, build) is None
    for _ in range(100):
        st = cache.status("all", "k")
        if st["state"] == "building" and st["events"] == 500:
            break
        time.sleep(0.05)
    st = cache.status("all", "k")
    assert st["state"] == "building"
    assert st["target"] == 1000 and st["events"] == 500 and st["pct"] == 50.0
    gate.set()
    for _ in range(100):
        if cache.status("all", "k")["state"] == "ready":
            break
        time.sleep(0.05)
    assert cache.status("all", "k")["state"] == "ready"
    assert cache.status("all", "k")["pct"] == 100.0


def test_failed_build_does_not_leave_the_status_building():
    cache = AsyncCache("test", sync_limit=10_000)

    def boom():
        raise RuntimeError("nope")

    with pytest.raises(RuntimeError):
        cache.get("all", "k", 10, boom)
    assert cache.status("all", "k")["state"] == "idle"
