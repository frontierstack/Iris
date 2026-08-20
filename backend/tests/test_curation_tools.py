"""The curation loop: everything a tool can CREATE, a tool can also list, edit and remove — and every
removal is undoable.

The analyst's ask was blunt: "should be able to create case, post case note, edit iocs, delete notes,
iocs, etc. Edit detection rules. Edit timelines, read anomalies." That closes a real gap — an agent
that can only append leaves its own mistakes for a human to clean up by hand.

What is pinned here, because each one is a way this could go quietly wrong:

* Only MANUAL artefacts can be edited or deleted. An extracted indicator or an extracted graph edge is
  what the events say; deleting it would be a lie about the evidence that comes straight back on the
  next detection pass. The refusal must SAY that, and name the real fix (tune the rule).
* Every destructive write records the full artefact in its undo payload, so `undo_run` puts it back —
  note ids and timestamps included.
* The MCP server and the built-in investigator expose the SAME registry. There is no second list to
  keep in sync, and this test asserts that rather than trusting it.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import cases
from app.ai.tools import REGISTRY, RunContext, ToolError, undo_action
from app.main import app
from app.store import STORE
from tests.conftest import load_sample_case


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def pool(client):
    load_sample_case(client)
    return client


def call(name: str, args: dict, ctx: RunContext):
    tool = REGISTRY[name]
    tool.validate_args(args)
    return tool.fn(args, ctx)


def ctx() -> RunContext:
    return RunContext(run_id="test-run", model="test")


def some_event_ids(n: int = 2) -> list[str]:
    with STORE.lock:
        return [e.id for e in STORE.events[:n]]


# --------------------------------------------------------------------- indicators
def test_ioc_create_edit_delete_and_undo(pool):
    c = ctx()
    ids = some_event_ids()
    added = call("add_ioc", {"kind": "ipv4", "value": "203.0.113.9", "note": "first pass",
                             "citedEventIds": ids}, c)
    iid = added["ioc"]["id"]
    assert iid == "ipv4:203.0.113.9"

    listed = call("list_iocs", {"limit": 50}, c)
    assert any(i["id"] == iid for i in listed["iocs"])

    edited = call("update_ioc", {"iocId": iid, "value": "203.0.113.10", "note": "corrected octet"}, c)
    assert edited["iocId"] == "ipv4:203.0.113.10" and edited["previousId"] == iid
    assert edited["note"] == "corrected octet"

    # undo the edit → the original value is back
    assert undo_action(edited["action"]) is True
    assert any(i["value"] == "203.0.113.9" for i in call("list_iocs", {"limit": 50}, c)["iocs"])

    removed = call("delete_ioc", {"iocId": iid, "why": "false positive"}, c)
    assert removed["ok"] is True
    assert not any(i["id"] == iid for i in call("list_iocs", {"limit": 50}, c)["iocs"])

    # undo the delete → the indicator returns with its citations intact
    assert undo_action(removed["action"]) is True
    back = next(i for i in call("list_iocs", {"limit": 50}, c)["iocs"] if i["id"] == iid)
    assert back["addedBy"] == "ai"
    call("delete_ioc", {"iocId": iid}, c)


def test_an_extracted_indicator_cannot_be_edited_or_deleted(pool):
    c = ctx()
    extracted = next((i for i in call("list_iocs", {"limit": 50}, c)["iocs"] if not i["manual"]), None)
    if extracted is None:
        pytest.skip("the sample pool produced no extracted indicators")
    for tool in ("update_ioc", "delete_ioc"):
        with pytest.raises(ToolError) as exc:
            call(tool, {"iocId": extracted["id"], **({"note": "x"} if tool == "update_ioc" else {})}, c)
        msg = str(exc.value).lower()
        assert "extracted" in msg and "rule" in msg      # says WHY, and names the real fix


# --------------------------------------------------------------------- notes
def test_note_write_edit_delete_and_undo(pool):
    c = ctx()
    ids = some_event_ids(2)
    made = call("add_note", {"text": "initial finding", "citedEventIds": ids}, c)
    nid = made["noteId"]

    edited = call("update_note", {"noteId": nid, "text": "corrected finding"}, c)
    assert edited["text"] == "corrected finding" and edited["updatedAt"]
    assert undo_action(edited["action"]) is True
    assert next(n for n in call("list_notes", {}, c)["notes"] if n["id"] == nid)["text"] == "initial finding"

    # a citation that is not a real event is refused, and nothing changes
    with pytest.raises(ToolError) as exc:
        call("update_note", {"noteId": nid, "citedEventIds": ["e999999999"]}, c)
    assert "do not exist" in str(exc.value)
    assert next(n for n in call("list_notes", {}, c)["notes"] if n["id"] == nid)["text"] == "initial finding"

    deleted = call("delete_note", {"noteId": nid, "why": "superseded"}, c)
    assert not any(n["id"] == nid for n in call("list_notes", {}, c)["notes"])
    # undo restores the note verbatim — same id, same author, same text
    assert undo_action(deleted["action"]) is True
    back = next(n for n in call("list_notes", {}, c)["notes"] if n["id"] == nid)
    assert back["text"] == "initial finding" and back["author"].startswith("AI assistant")
    call("delete_note", {"noteId": nid}, c)


def test_blanking_is_not_a_way_to_delete(pool):
    c = ctx()
    nid = call("add_note", {"text": "keep me", "citedEventIds": some_event_ids(1)}, c)["noteId"]
    for args, word in (({"noteId": nid, "text": "   "}, "delete_note"),
                       ({"noteId": nid, "citedEventIds": []}, "evidence")):
        with pytest.raises(ToolError) as exc:
            call("update_note", args, c)
        assert word in str(exc.value)
    call("delete_note", {"noteId": nid}, c)


# --------------------------------------------------------------------- the case timeline
def test_annotating_a_case_set_event_is_how_the_timeline_is_written(pool):
    c = ctx()
    eid = some_event_ids(1)[0]
    call("add_events_to_case", {"eventIds": [eid], "note": "start of the chain"}, c)

    annotated = call("annotate_case_event",
                     {"eventId": eid, "labels": ["initial access"], "note": "first successful login"}, c)
    assert annotated["labels"] == ["initial access"]

    entries = call("get_case_set", {"limit": 50}, c)["entries"]
    row = next(e for e in entries if e["eventId"] == eid)
    assert row["labels"] == ["initial access"] and row["note"] == "first successful login"
    assert row["msg"]                      # the entry carries the event itself, not just its id

    # labels REPLACE, and the previous state comes back on undo
    again = call("annotate_case_event", {"eventId": eid, "labels": ["lateral movement"]}, c)
    assert again["labels"] == ["lateral movement"] and again["note"] == "first successful login"
    assert undo_action(again["action"]) is True
    assert next(e for e in call("get_case_set", {"limit": 50}, c)["entries"]
                if e["eventId"] == eid)["labels"] == ["initial access"]

    # an event that is not in the case set is refused with the fix named
    with pytest.raises(ToolError) as exc:
        call("annotate_case_event", {"eventId": some_event_ids(3)[2], "labels": ["x"]}, c)
    assert "add_events_to_case" in str(exc.value)


# --------------------------------------------------------------------- graph links
def test_graph_link_can_be_listed_and_removed(pool):
    c = ctx()
    found = call("graph_find", {"query": "", "limit": 5}, c)
    nodes = [n["id"] for n in found.get("nodes", [])][:2]
    if len(nodes) < 2:
        pytest.skip("not enough graph nodes in the sample pool")
    try:
        link = call("add_graph_link", {"source": nodes[0], "target": nodes[1], "relation": "co_occurred",
                                       "why": "same burst", "citedEventIds": some_event_ids(1)}, c)
    except ToolError as exc:
        pytest.skip(f"sample graph already links these: {exc}")
    lid = link["linkId"]
    assert any(l["id"] == lid for l in call("list_graph_links", {}, c)["links"])

    gone = call("delete_graph_link", {"linkId": lid, "why": "coincidence, not a pivot"}, c)
    assert not any(l["id"] == lid for l in call("list_graph_links", {}, c)["links"])
    assert undo_action(gone["action"]) is True
    assert any(l["id"] == lid for l in call("list_graph_links", {}, c)["links"])
    call("delete_graph_link", {"linkId": lid}, c)


# --------------------------------------------------------------------- anomalies + cases
def test_list_anomalies_is_the_rule_rollup(pool):
    out = call("list_anomalies", {"limit": 10}, ctx())
    assert out["total"] >= 1 and out["totalHits"] >= out["shown"]
    row = out["anomalies"][0]
    assert row["ruleId"] and row["hits"] >= 1 and row["sev"]
    assert all(STORE.event(i) is not None for i in row["sampleEventIds"])
    # the severity filter narrows the same list rather than re-deriving it
    high = call("list_anomalies", {"sev": row["sev"], "limit": 50}, ctx())
    assert all(a["sev"] == row["sev"] for a in high["anomalies"])


def test_list_cases_and_activate_case_round_trip(pool):
    c = ctx()
    first = STORE.case_id
    # a case is already active (the sample case), so make the second one the way the app does
    second = cases.create_case("second investigation").id
    cases.activate(second)
    assert STORE.case_id == second

    listing = call("list_cases", {}, c)
    assert listing["activeCaseId"] == second
    assert {row["id"] for row in listing["cases"]} >= {first, second}
    assert sum(1 for row in listing["cases"] if row["active"]) == 1

    switched = call("activate_case", {"caseId": first}, c)
    assert switched["caseId"] == first and STORE.case_id == first
    assert undo_action(switched["action"]) is True and STORE.case_id == second

    with pytest.raises(ToolError) as exc:
        call("activate_case", {"caseId": "CASE-9999"}, c)
    assert "no such case" in str(exc.value)
    cases.activate(first)


# --------------------------------------------------------------------- parity
def test_the_mcp_server_and_the_investigator_offer_the_same_tools(client):
    """One registry, two front doors. A second list would drift the day someone adds a tool."""
    from app.config import update_settings
    from app.routers.mcp import exposed_tools
    # A token is mandatory: enabled-with-no-token fails closed (503). See tests/test_security.py.
    tok = "parity-test-token"
    auth = {"Authorization": f"Bearer {tok}"}
    update_settings({"mcp": {"enabled": True, "allowWrites": True, "token": tok}})
    try:
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        names = {t["name"] for t in client.post("/api/mcp", json=body, headers=auth).json()["result"]["tools"]}
        assert names == set(REGISTRY)
        assert {"update_ioc", "delete_ioc", "update_note", "delete_note", "annotate_case_event",
                "delete_graph_link", "list_anomalies", "list_cases", "activate_case",
                "get_case_set", "list_graph_links"} <= names
        # and the schemas are the registry's own, not a re-declaration
        for t in client.post("/api/mcp", json=body, headers=auth).json()["result"]["tools"]:
            assert t["inputSchema"]["properties"] == REGISTRY[t["name"]].properties
            assert t["inputSchema"]["required"] == REGISTRY[t["name"]].required
        assert len(exposed_tools(allow_writes=False)) < len(exposed_tools(allow_writes=True))
    finally:
        update_settings({"mcp": {"enabled": False, "allowWrites": False, "token": ""}})


def test_every_destructive_tool_records_an_undo_payload():
    """A delete with no undo payload is unrecoverable — the reason writes are allowed to apply at once."""
    destructive = [n for n in REGISTRY if n.startswith(("delete_", "update_", "remove_")) or n == "annotate_case_event"]
    assert destructive
    import inspect
    for name in destructive:
        src = inspect.getsource(REGISTRY[name].fn)
        assert "ctx.record(" in src, f"{name} does not record an action"
        assert '"before"' in src or '"eventIds"' in src or '"ruleId"' in src, \
            f"{name} records no state to restore"
