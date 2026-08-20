"""`minCount` = minimum relationship strength.

The analyst reported the Graph page's "min events" control as doing nothing. It filtered `node.count`
(how many events mention the entity), which is invisible: the node ranking already puts the busiest
entities first, so at the default 50-node cap every value up to five figures returned the same picture.
It now filters EDGES by the number of events supporting the relation, and drops nodes left with none —
which is both what the control reads as and something that visibly changes the result.
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


def _closed(g: dict) -> None:
    ids = {n["id"] for n in g["nodes"]}
    assert not [e for e in g["edges"] if e["source"] not in ids or e["target"] not in ids]


def test_min_count_filters_edges_not_node_volume(client):
    base = _graph(client, limit=2000)
    counts = sorted({e["count"] for e in base["edges"]})
    assert len(counts) > 1, "fixture has no spread of edge counts to filter on"
    threshold = counts[len(counts) // 2] + 1
    filt = _graph(client, limit=2000, minCount=threshold)
    assert filt["edges"], "the filter removed everything — pick a lower threshold"
    assert all(e["count"] >= threshold for e in filt["edges"]), "an under-strength edge survived"
    assert len(filt["edges"]) < len(base["edges"]), "minCount changed nothing"
    _closed(filt)


def test_min_count_drops_nodes_left_without_an_edge(client):
    hi = max(e["count"] for e in _graph(client, limit=2000)["edges"])
    g = _graph(client, limit=2000, minCount=hi)
    linked = {e["source"] for e in g["edges"]} | {e["target"] for e in g["edges"]}
    assert set(n["id"] for n in g["nodes"]) == linked
    _closed(g)


def test_min_count_1_is_the_unfiltered_graph(client):
    a = _graph(client, limit=200)
    b = _graph(client, limit=200, minCount=1)
    assert [n["id"] for n in a["nodes"]] == [n["id"] for n in b["nodes"]]
    assert [e["id"] for e in a["edges"]] == [e["id"] for e in b["edges"]]


def test_min_count_above_everything_is_empty_and_closed(client):
    g = _graph(client, limit=2000, minCount=10_000_000)
    assert g["nodes"] == [] and g["edges"] == []


def test_min_count_composes_with_types_and_relations(client):
    for params in ({"types": "ip,user"}, {"relations": "auth_from,connected_to"}, {"focus": None}):
        params = {k: v for k, v in params.items() if v is not None}
        g = _graph(client, limit=500, minCount=2, **params)
        assert all(e["count"] >= 2 for e in g["edges"])
        _closed(g)


def test_min_count_does_not_rebuild_the_graph(client):
    """Every filter SLICES the cached builder — minCount must not become a per-request O(pool) walk."""
    before = STORE.graph_status("all")["buildMs"]
    _graph(client, limit=500, minCount=3)
    assert STORE.graph_status("all")["buildMs"] == before
