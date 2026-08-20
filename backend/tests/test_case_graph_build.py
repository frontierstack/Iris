"""The agent builds the investigation graph — and it works on a workspace that extracted nothing.

*"I want the ai assistant to be able to build a graph based on its investigation to connect things
together it sees as relevant. Have a link entity graph to cases."*

What blocked it: `add_graph_link` required both endpoints to be nodes the EXTRACTOR had found, and a
raw-first workspace extracts nothing at all — no entities, so no nodes, so every endpoint was refused
with "not a node in the graph". The agent could not draw the one thing it had actually worked out.

So an authored node is now a first-class overlay, exactly like an authored link: stored on the CASE
(`case.json` → `graph_nodes`), merged into `GET /api/graph` per request, never part of the built
structure, never counted as evidence (`count: 0`), drawn distinctly, and reverted with the write that
created it. `build_case_graph` draws a whole picture in one call, because "never call a tool once per
item" is the difference between an investigation and a budget spent on bookkeeping.

The line that must not blur: an extracted node is what the LOGS say; an authored one is what someone
CONCLUDED. They are different claims, and the payload marks which is which.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.ai.tools import REGISTRY, RunContext, ToolError
from app.config import update_settings
from app.main import app
from app.store import STORE

RAW_LOG = b"".join(
    f'"Aug 17, 2026 @ 09:{i:02d}:00.000",10.0.0.101,66.218.84.137,443,allow\n'.encode() for i in range(12))


@pytest.fixture()
def raw_case():
    """The analyst's real shape: a case, one RAW source, nothing extracted."""
    with TestClient(app) as c:
        STORE.clear_all()
        update_settings({"ingest": {"autoEnrich": False}})
        try:
            c.post("/api/cases", json={"name": "Graph build"})
            c.post("/api/sources", files={"files": ("proxy.csv", RAW_LOG, "text/csv")})
            assert not any(e.entities for e in STORE.events), "phase 1 extracts no entities"
            yield c
        finally:
            update_settings({"ingest": {"autoEnrich": True}})
            STORE.clear_all()


def ctx() -> RunContext:
    return RunContext(run_id="run-graph", model="test", max_writes=50)


def links(eid: str) -> list[dict]:
    return [
        {"source": "ip:10.0.0.101", "target": "ip:66.218.84.137", "relation": "connected_to",
         "why": "40 proxy records, TCP/443", "citedEventIds": [eid], "confidence": 0.9},
        {"source": "ip:66.218.84.137", "target": "domain:search.yahoo.com", "relation": "resolved",
         "why": "the edge server answers for this name", "citedEventIds": [eid]},
    ]


def test_the_agent_can_draw_a_graph_on_a_raw_workspace(raw_case):
    """Worth being precise about what "extracted nothing" means here.

    Phase 2 is what fills `Event.entities`, and it never ran — so `entity:"10.0.0.101"` matches nothing.
    The GRAPH extractor is a different pass: it reads the raw line, so the two IPs in it ARE nodes
    already. The domain is not (nothing in the log says it), and that is exactly the kind of thing an
    investigation concludes rather than reads. The rule the payload has to keep straight: an extracted
    node keeps its real counts, an authored one is created and marked.
    """
    eid = STORE.events[0].id
    out = REGISTRY["build_case_graph"].fn({"links": links(eid)}, ctx())

    assert out["drawn"] == 2
    assert out["createdNodes"] == ["domain:search.yahoo.com"], "only what extraction could not know"
    assert len(STORE.graph_links) == 2 and len(STORE.graph_nodes) == 1


def test_what_it_drew_comes_back_from_the_graph_endpoint(raw_case):
    eid = STORE.events[0].id
    REGISTRY["build_case_graph"].fn({"links": links(eid)}, ctx())

    body = raw_case.get("/api/graph?limit=100").json()
    ids = {n["id"] for n in body["nodes"]}
    assert {"ip:10.0.0.101", "ip:66.218.84.137", "domain:search.yahoo.com"} <= ids
    assert len(body["edges"]) == 2
    # the CLOSED-GRAPH invariant still holds — every edge endpoint is a returned node
    assert all(e["source"] in ids and e["target"] in ids for e in body["edges"])
    # and an authored node is marked as one: it is a conclusion, not an extraction
    drawn = next(n for n in body["nodes"] if n["id"] == "domain:search.yahoo.com")
    assert drawn["manual"] is True and drawn["ai"] is True and drawn["count"] == 0
    assert "answers for this name" in drawn["why"]


def test_the_whole_picture_reverts_together(raw_case):
    from app.ai.tools import undo_action

    eid = STORE.events[0].id
    out = REGISTRY["build_case_graph"].fn({"links": links(eid)}, ctx())
    assert undo_action(out["action"]) is True
    assert STORE.graph_links == []
    assert STORE.graph_nodes == [], "reverting a graph must not leave its nodes behind as loose dots"


def test_a_bad_link_does_not_lose_the_good_ones(raw_case):
    eid = STORE.events[0].id
    payload = links(eid) + [
        {"source": "ip:1.2.3.4", "target": "ip:1.2.3.4", "relation": "connected_to", "why": "self"},
        {"source": "nonsense", "target": "ip:9.9.9.9", "relation": "connected_to", "why": "x"},
        {"source": "ip:5.5.5.5", "target": "ip:6.6.6.6", "relation": "teleported_to", "why": "x"},
    ]
    out = REGISTRY["build_case_graph"].fn({"links": payload}, ctx())

    assert out["drawn"] == 2
    reasons = " ".join(r["why"] for r in out["refused"])
    assert "two different nodes" in reasons
    assert "<type>:<value>" in reasons, "a refusal has to name the shape it wanted"
    assert "relation must be one of" in reasons


def test_a_link_with_no_evidence_at_all_is_refused(raw_case):
    with pytest.raises(ToolError) as exc:
        REGISTRY["add_graph_link"].fn(
            {"source": "ip:1.1.1.1", "target": "ip:2.2.2.2", "relation": "connected_to", "why": ""}, ctx())
    assert "cite" in str(exc.value)


def test_an_invented_citation_is_still_refused(raw_case):
    with pytest.raises(ToolError):
        REGISTRY["add_graph_link"].fn(
            {"source": "ip:1.1.1.1", "target": "ip:2.2.2.2", "relation": "connected_to",
             "why": "hunch", "citedEventIds": ["e999999"]}, ctx())
    assert STORE.graph_links == []


def test_the_same_link_cannot_be_drawn_twice(raw_case):
    eid = STORE.events[0].id
    REGISTRY["build_case_graph"].fn({"links": links(eid)[:1]}, ctx())
    out = REGISTRY["build_case_graph"].fn({"links": links(eid)}, ctx())
    assert out["drawn"] == 1, "the duplicate is refused, the new one is drawn"
    assert "already exists" in out["refused"][0]["why"]


def test_the_graph_survives_a_reload_of_the_case(raw_case):
    eid = STORE.events[0].id
    REGISTRY["build_case_graph"].fn({"links": links(eid)}, ctx())
    cid = STORE.case_id

    from app import cases as cases_mod
    other = cases_mod.create_case("elsewhere").id
    cases_mod.activate(cid)

    assert len(STORE.graph_links) == 2 and len(STORE.graph_nodes) == 1, "the case graph is case.json state"
    cases_mod.activate(other)
    assert STORE.graph_links == [], "and it belongs to THAT case, not to the workspace"


def test_a_link_may_be_written_as_one_line(raw_case):
    """The compact form. A nested array-of-objects is the hardest thing for a small local model to
    emit, and getting it wrong is not graceful: the analyst's gateway answered HTTP 500 "Failed to
    parse tool call arguments as JSON" and lost the turn. One line per link cannot be malformed in
    that way, and it is validated identically."""
    eid = STORE.events[0].id
    out = REGISTRY["build_case_graph"].fn(
        {"links": [f"ip:10.0.0.101 | connected_to | ip:66.218.84.137 | 40 proxy records | {eid}"]}, ctx())

    assert out["drawn"] == 1
    link = STORE.graph_links[0]
    assert link["source"] == "ip:10.0.0.101" and link["target"] == "ip:66.218.84.137"
    assert link["relation"] == "connected_to" and link["citedEventIds"] == [eid]
    assert "40 proxy records" in link["why"]


def test_the_whole_argument_may_be_one_string(raw_case):
    eid = STORE.events[0].id
    out = REGISTRY["build_case_graph"].fn(
        {"links": f"ip:10.0.0.101 | connected_to | ip:66.218.84.137 | seen | {eid}\n"
                  f"ip:66.218.84.137 | resolved | domain:search.yahoo.com | SNI | {eid}"}, ctx())
    assert out["drawn"] == 2


def test_a_compact_line_still_has_to_make_sense(raw_case):
    """Same validation, same refusals: an invented citation is refused in either form, and a line that
    is not a link is named as one. When NOTHING could be drawn the whole call fails, with the reasons."""
    with pytest.raises(ToolError) as exc:
        REGISTRY["build_case_graph"].fn(
            {"links": ["ip:10.0.0.101 | connected_to | ip:66.218.84.137 | why | e999999",
                       "not a link at all"]}, ctx())
    msg = str(exc.value)
    assert "e999999" in msg and "do not exist" in msg
    assert "must be an object, or a line" in msg
    assert STORE.graph_links == []
