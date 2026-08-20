"""The persisted entity graph: a restart must not pay the extraction again — and the reload must be EXACT.

The graph is 55-190 s of regex/string work on the analyst's pool and it is rebuilt after every restart
(and every crash-restart), because the pool is re-parsed from the same files. `graph_store` saves the
aggregate keyed on the pool's content and restores it in seconds. What is pinned:

  * a hit reproduces the serial build node-for-node and relation-for-relation, including each node's
    first-200 / most-recent-200 event references (saved as IDS, resolved against the live index);
  * any change to what a source produced misses (the key is content, not a counter);
  * a corrupt or foreign cache file is a miss, never a crash;
  * clear-all removes it.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import config, graph_store
from app.graph import GraphBuilder
from app.main import app
from app.store import STORE
from tests.conftest import load_sample_case


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        load_sample_case(c)
        yield c


def _same_graph(a: GraphBuilder, b: GraphBuilder) -> None:
    assert list(a.nodes) == list(b.nodes)                       # same nodes, same insertion order
    for nid, n in a.nodes.items():
        m = b.nodes[nid]
        assert (n.type, n.value, n.label, n.count, n.first, n.last, n.sev, n.detections) == \
               (m.type, m.value, m.label, m.count, m.first, m.last, m.sev, m.detections), nid
        assert dict(n.srcs) == dict(m.srcs) and dict(n.files) == dict(m.files), nid
        # the event references — head and ring — resolve to the same EVENTS
        ev = STORE.events
        assert [ev[i].id for i in n.events] == [ev[i].id for i in m.events], nid
        assert [ev[i].id for i in n.recent()] == [ev[i].id for i in m.recent()], nid
    assert set(a.edges) == set(b.edges)
    for k, e in a.edges.items():
        f = b.edges[k]
        assert (e.count, e.first, e.last, e.sev, dict(e.outcomes), list(e.events), dict(e.why), set(e.files)) == \
               (f.count, f.first, f.last, f.sev, dict(f.outcomes), list(f.events), dict(f.why), set(f.files)), k
    assert a.ranked_ids() == b.ranked_ids()


def test_round_trip_is_exact(client):
    events = list(STORE.events)
    fresh = GraphBuilder(events, parallel=False)
    sig = graph_store.signature(STORE, "all")
    assert graph_store.save(STORE, "all", fresh, sig)
    assert (config.DATA_DIR / "cache" / "graph-all.pkl").is_file()

    pre = graph_store.load(STORE, "all", sig)
    assert pre is not None
    restored = GraphBuilder(events, parallel=False, preloaded=pre)
    _same_graph(fresh, restored)


def test_the_store_serves_the_cached_graph_and_the_result_is_identical(client):
    fresh = GraphBuilder(list(STORE.events), parallel=False)
    sig = graph_store.signature(STORE, "all")
    graph_store.save(STORE, "all", fresh, sig)
    via_store = STORE._build_graph_v2("all")
    _same_graph(fresh, via_store)


def test_a_changed_pool_misses(client):
    sig = graph_store.signature(STORE, "all")
    assert graph_store.load(STORE, "all", sig) is not None
    # ingest one more line: a different pool, a different signature, no hit
    r = client.post("/api/sources", files={"files": ("extra.log", b'10.0.0.9 - - [11/Aug/2026:03:14:47 +0000] "GET /z HTTP/1.1" 200 1 "-" "x"\n', "text/plain")})
    assert r.status_code == 200
    sig2 = graph_store.signature(STORE, "all")
    assert sig2 != sig
    assert graph_store.load(STORE, "all", sig2) is None
    # and the next real build re-saves under the new signature
    STORE._build_graph_v2("all")
    assert graph_store.load(STORE, "all", sig2) is not None


def test_a_corrupt_cache_is_a_miss_not_a_crash(client):
    p = config.DATA_DIR / "cache" / "graph-all.pkl"
    p.write_bytes(b"not a pickle at all")
    assert graph_store.load(STORE, "all", graph_store.signature(STORE, "all")) is None
    gb = STORE._build_graph_v2("all")           # builds from the pool, then re-saves
    assert gb.nodes
    assert graph_store.load(STORE, "all", graph_store.signature(STORE, "all")) is not None


def test_clear_all_removes_the_cache(client):
    assert (config.DATA_DIR / "cache" / "graph-all.pkl").is_file()
    client.post("/api/admin/clear-all", json={})
    assert not (config.DATA_DIR / "cache" / "graph-all.pkl").exists()


def test_the_signature_survives_a_restart(client):
    """The cache only matters across restarts, and a restart re-parses the library into a pool whose
    SOURCE IDS are all new (`uuid4().hex[:8]` per case source). Keying on them made the cache miss every
    single time — it saved on every start and never loaded once. The key is what each source
    CONTRIBUTED (file, count, range), which a re-parse of the same bytes reproduces exactly."""
    from app import graph_store
    from app.store import STORE

    before = graph_store.signature(STORE, "all")
    with STORE.lock:
        originals = {sid: src.id for sid, src in STORE.sources.items()}
    try:
        with STORE.lock:
            for sid, src in STORE.sources.items():
                src.id = "restarted-" + sid            # what a restore does to every case source
        assert graph_store.signature(STORE, "all") == before, "the signature must not depend on source ids"
    finally:
        with STORE.lock:
            for sid, src in STORE.sources.items():
                src.id = originals[sid]
