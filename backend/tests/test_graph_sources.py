"""Restricting the entity graph to chosen log files, and sending a node's events to Search exactly.

Two analyst reports, one root cause each:

* "there should be a source selector, by default no sources are selected" — a graph over every ingested
  file at once is a hairball, and the first question about any entity is which log it came from. The
  filter has to be EXACT on both sides: a node is kept when it appears in a selected file, and an edge is
  kept when a selected file actually produced it. Inferring the edge from its endpoints would draw a
  relation the chosen logs never contained, which in an evidence tool is a false claim.
* "clicking search on a node does not bring up that very specific set of events" — the button sent the
  node's value as FREE TEXT, which matches message, raw line, fields and entities by substring: node
  `10.0.0.1` returned 10.0.0.100 and every line that merely mentioned the string. The graph now hands the
  UI the query, and `entity:` matches an extracted entity exactly.
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


def graph(client, **params):
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    r = client.get(f"/api/graph?limit=400{'&' + qs if qs else ''}")
    assert r.status_code == 200, r.text
    return r.json()


def test_no_sources_means_the_whole_pool(client):
    """Omitting the parameter is 'everything' — the UI's empty selection is a UI decision, not an API one,
    and every existing caller (report, AI review) must keep seeing the whole graph."""
    assert graph(client)["stats"]["nodes"] > 0


def test_selecting_one_source_keeps_only_what_that_file_contains(client):
    with STORE.lock:
        by_file = {s.file: s.id for s in STORE.sources.values() if s.events > 0}
    assert len(by_file) >= 2, "the sample case should ingest several files"
    file_name, sid = sorted(by_file.items())[0]

    whole = graph(client)
    one = graph(client, sources=sid)
    assert one["stats"]["nodes"] <= whole["stats"]["nodes"]
    assert one["stats"]["nodes"] > 0

    # every node returned really is in that file: the builder's own per-file tally is the filter's input,
    # so assert against it rather than against the node's (top-3) "Log files" fact
    gb = STORE.graph_v2("all")
    for n in one["nodes"]:
        agg = gb.nodes.get(n["id"])
        if agg is not None:
            assert file_name in agg.files, f"{n['id']} was kept but never appears in {file_name}"
    # and the payload stays closed: no edge points at a node that was filtered out
    ids = {n["id"] for n in one["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in one["edges"])


def test_an_edge_survives_only_when_a_SELECTED_file_produced_it(client):
    """The exactness that matters. Both endpoints of an edge can appear in a file that never showed them
    related — if the filter inferred edges from endpoints, that relation would be drawn anyway."""
    gb = STORE.graph_v2("all")
    with STORE.lock:
        files = {s.file for s in STORE.sources.values() if s.events > 0}
    assert files
    # every edge in the built graph knows which files produced it, and never claims one that did not
    checked = 0
    for key, ed in list(gb.edges.items())[:500]:
        assert ed.files, f"edge {key} has no file provenance"
        assert ed.files <= files, f"edge {key} claims a file that is not a source: {ed.files - files}"
        checked += 1
    assert checked > 0

    # picking exactly the files of one edge must return that edge; picking the others must not
    key, ed = next(iter(gb.edges.items()))
    with STORE.lock:
        sids = [s.id for s in STORE.sources.values() if s.file in ed.files]
        others = [s.id for s in STORE.sources.values() if s.file not in ed.files and s.events > 0]
    got = graph(client, sources=",".join(sids), limit=2000)
    assert any(e["source"] == ed.source and e["target"] == ed.target and e["relation"] == ed.relation
               for e in got["edges"])
    if others:
        without = graph(client, sources=",".join(others), limit=2000)
        assert not any(e["source"] == ed.source and e["target"] == ed.target and e["relation"] == ed.relation
                       for e in without["edges"])


def test_an_unknown_source_id_returns_an_empty_view_not_everything(client):
    """A stale id must never silently widen the view back to the whole pool — that is the failure mode
    where an analyst believes they are looking at one log and are looking at all of them."""
    out = graph(client, sources="does-not-exist")
    assert out["stats"]["nodes"] == 0 and out["stats"]["edges"] == 0


def test_a_node_hands_the_ui_the_query_for_its_own_events(client):
    g = graph(client)
    node = max(g["nodes"], key=lambda n: n["count"])
    d = client.get(f"/api/graph/node/{node['id']}").json()
    assert d["query"].startswith('entity:"')
    # it is not a guess: running it returns events, and every one really carries that entity
    rows = client.get(f"/api/events?q={d['query']}&limit=50").json()
    assert rows["total"] > 0
    assert all(node["value"] in r["entities"] for r in rows["rows"])


def test_entity_matches_exactly_so_a_longer_value_is_not_dragged_in(client):
    """`entity:10.0.0.1` must not return 10.0.0.100. Free text still can — that is what free text is for."""
    from app.query import parse_query, node_pred
    from app.models import Event

    def ev(eid: str, entity: str) -> Event:
        return Event(id=eid, sourceId="s1", ts="2026-08-11T03:14:47Z", sev="info", source="nginx",
                     file="a.log", host="", user="", msg="hit", raw="hit", entities=[entity])

    e_short, e_long = ev("x1", "10.0.0.1"), ev("x2", "10.0.0.100")
    pred = node_pred(parse_query('entity:"10.0.0.1"'))
    assert pred(e_short) is True
    assert pred(e_long) is False
    # a wildcard still reaches both, deliberately
    wide = node_pred(parse_query('entity:"10.0.0.1*"'))
    assert wide(e_short) and wide(e_long)


def test_the_graph_search_box_searches_the_WHOLE_graph(client):
    """`q` filtered the payload AFTER select() had capped it to `limit`, so it only ever searched the
    top-N ranked nodes: a search for any entity outside them returned an empty graph, which reads as
    "no such entity" when the entity is right there. Measured on the analyst's pool: q=claude -> 0 nodes
    out of 21,676. It now runs inside select(), across every ranked node."""
    gb = STORE.graph_v2("all")
    # pick a node that is deliberately NOT in the top few by rank
    ranked = gb.ranked_ids()
    assert len(ranked) > 12, "sample pool is too small to test the cap"
    target = gb.nodes[ranked[-1]].value            # the LOWEST ranked node in the graph
    needle = target[:8]

    # a tiny limit is the whole point: the match is nowhere near the top of the ranking
    out = graph(client, q=needle, limit=10)
    assert out["stats"]["nodes"] > 0, f"searching {needle!r} returned nothing"
    values = [n["value"].lower() for n in out["nodes"]]
    assert any(needle.lower() in v for v in values), f"{needle!r} matched nothing in {values[:5]}"
    # matches come first: with a small limit the analyst must get hits, not the neighbours of hits
    assert needle.lower() in values[0], "a neighbour outranked an actual match"

    # and an unmatchable string is empty rather than "the top 10 anyway"
    assert graph(client, q="zzz-no-such-entity-zzz", limit=10)["stats"]["nodes"] == 0


def test_min_link_events_drops_weak_LINKS_and_min_connections_drops_lonely_NODES(client):
    """The two declutter controls answer different questions and must not be conflated.

    `minCount` is relationship strength (evidence behind a link); `minDegree` is how connected an
    entity is. The analyst reported the first one as if it were the second, which is exactly why
    both now exist and why this test asserts the invariants side by side.
    """
    def graph(**kw):
        r = client.get("/api/graph", params={"limit": 400, **kw})
        assert r.status_code == 200, r.text
        return r.json()

    base = graph()
    if not base["edges"]:
        pytest.skip("fixture pool produced no relations")

    # minCount: no edge below the threshold survives, and no node is left edgeless.
    strong = graph(minCount=3)
    for e in strong["edges"]:
        assert e["count"] >= 3 or e.get("ai") or e.get("manual"), e
    linked = {e["source"] for e in strong["edges"]} | {e["target"] for e in strong["edges"]}
    assert all(n["id"] in linked for n in strong["nodes"])

    # minDegree: every returned node really has that many links in the payload, and the graph stays
    # closed (no edge pointing at a node that was just hidden).
    for k in (2, 3):
        g = graph(minDegree=k)
        ids = {n["id"] for n in g["nodes"]}
        deg: dict[str, int] = {}
        for e in g["edges"]:
            assert e["source"] in ids and e["target"] in ids, "dangling edge after minDegree"
            deg[e["source"]] = deg.get(e["source"], 0) + 1
            deg[e["target"]] = deg.get(e["target"], 0) + 1
        assert all(deg.get(i, 0) >= k for i in ids), f"a node survived minDegree={k} with too few links"
        # the count the screen prints must be the count that actually happened
        assert g["stats"]["hiddenByDegree"] == len(base["nodes"]) - len(ids)

    # ...and they are genuinely different filters. Every leaf (one link) that minCount=3 keeps is
    # precisely what minDegree=2 exists to remove; if the two did the same thing this set would be empty.
    strong_deg: dict[str, int] = {}
    for e in strong["edges"]:
        strong_deg[e["source"]] = strong_deg.get(e["source"], 0) + 1
        strong_deg[e["target"]] = strong_deg.get(e["target"], 0) + 1
    leaves = [n["id"] for n in strong["nodes"] if strong_deg.get(n["id"], 0) == 1]
    assert leaves, "expected minCount to keep at least one single-link node — that is what it does"
    kept = {n["id"] for n in graph(minCount=3, minDegree=2)["nodes"]}
    assert not (set(leaves) & kept), "minDegree=2 must remove the leaves minCount kept"
