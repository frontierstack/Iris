"""Graph payload invariants — the ones the canvas renderer depends on.

The analyst reported "random arrow artifacting … lines seemingly not connected to anything". A floating
edge can only come from two places:

  1. the API emitting an edge whose endpoint is not in the node list it returned (the node was ranked out
     by `limit`, filtered out by `types`/`q`, or the edge came from the persisted `graph_links`), or
  2. the renderer resolving an edge to the wrong element.

(2) was the real cause here (GraphScreen keyed edges by "source|target", which collides whenever two
relations join the same pair), but (1) is a standing invariant that must never regress, so it is asserted
here for the capped, focused, filtered and graph_links cases. `test_pairs_are_not_unique` pins the fact
that made (2) a bug: one node pair may carry several distinct edges, so a pair is NOT an edge identity.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.store import STORE
from tests.conftest import load_sample_case


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        load_sample_case(c)
        yield c


def _graph(client, **params) -> dict:
    r = client.get("/api/graph", params=params)
    assert r.status_code == 200, r.text
    return r.json()


def _assert_closed(g: dict, what: str) -> None:
    """Every edge endpoint must be a node the same response returned."""
    ids = {n["id"] for n in g["nodes"]}
    assert len(ids) == len(g["nodes"]), f"{what}: duplicate node ids"
    dangling = [(e["id"], e["source"], e["target"]) for e in g["edges"]
                if e["source"] not in ids or e["target"] not in ids]
    assert not dangling, f"{what}: {len(dangling)} edge(s) point at nodes that were not returned: {dangling[:5]}"
    dupes = [e["id"] for e in g["edges"]]
    assert len(set(dupes)) == len(dupes), f"{what}: duplicate edge ids in the response"


def test_default_graph_is_closed(client):
    _assert_closed(_graph(client), "default")


@pytest.mark.parametrize("limit", [10, 25, 50, 120, 2000])
def test_capped_graph_is_closed(client, limit):
    """The node cap ranks and truncates NODES; edges to a truncated node must be dropped with it."""
    g = _graph(client, limit=limit)
    assert len(g["nodes"]) <= limit
    _assert_closed(g, f"limit={limit}")


def test_default_limit_is_50(client):
    """The documented default node cap. The UI control must show the same number."""
    g = _graph(client)
    assert len(g["nodes"]) <= 50


def test_focus_and_hops_are_closed(client):
    gb = STORE.graph_v2("all")
    focus = max(gb.nodes, key=lambda i: gb.degree(i))
    for hops in (1, 2, 3):
        for limit in (10, 300):
            _assert_closed(_graph(client, focus=focus, hops=hops, limit=limit), f"focus={focus} hops={hops} limit={limit}")


def test_type_relation_and_query_filters_are_closed(client):
    _assert_closed(_graph(client, types="ip,user"), "types")
    _assert_closed(_graph(client, relations="auth_from,connected_to"), "relations")
    _assert_closed(_graph(client, minCount=3), "minCount")
    node = next(iter(STORE.graph_v2("all").nodes))
    _assert_closed(_graph(client, q=node.split(":", 1)[1][:6]), "q")
    _assert_closed(_graph(client, scope="case"), "scope=case")


def test_persisted_links_never_dangle(client):
    """A saved graph_link is only rendered when BOTH ends survived the cap — the AI-link case."""
    gb = STORE.graph_v2("all")
    a, b = [i for i in sorted(gb.nodes, key=lambda i: -gb.degree(i))][:2]
    r = client.post("/api/graph/links", json={"source": a, "target": b, "relation": "co_occurred",
                                              "why": "test link", "ai": True})
    assert r.status_code == 200, r.text
    link_id = r.json()["id"]
    try:
        for limit in (10, 15, 50, 300):
            g = _graph(client, limit=limit)
            _assert_closed(g, f"graph_links limit={limit}")
        # and it must not dangle when a type filter removes one of its ends either
        _assert_closed(_graph(client, types="file"), "graph_links + types=file")
        # a link whose ends were ranked out simply is not drawn
        tiny = _graph(client, limit=10)
        ids = {n["id"] for n in tiny["nodes"]}
        if not (a in ids and b in ids):
            assert link_id not in {e["id"] for e in tiny["edges"]}
    finally:
        client.delete(f"/api/graph/links/{link_id}")


def test_pairs_are_not_unique(client):
    """A node PAIR is not an edge identity: the same two entities can be joined by several relations
    (a process that both wrote and read a file, or an accepted graph_link laid on top of an extracted
    edge). The renderer must key edges by `edge.id`, never by "source|target" — that collision made two
    different links resolve to one edge object, which is how phantom lines got drawn."""
    g = _graph(client, limit=2000)
    e0 = g["edges"][0]
    a, b, rel = e0["source"], e0["target"], e0["relation"]
    other = "co_occurred" if rel != "co_occurred" else "session"
    r = client.post("/api/graph/links", json={"source": a, "target": b, "relation": other, "why": "test"})
    assert r.status_code == 200, r.text
    link_id = r.json()["id"]
    try:
        g = _graph(client, limit=2000)
        _assert_closed(g, "parallel edges")
        same_pair = [e["id"] for e in g["edges"] if {e["source"], e["target"]} == {a, b}]
        assert len(same_pair) >= 2 and len(set(same_pair)) == len(same_pair), same_pair
    finally:
        client.delete(f"/api/graph/links/{link_id}")
