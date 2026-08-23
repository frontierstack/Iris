"""Exclusions: suppress the claim, never the evidence — and never invisibly.

The analyst's ask was concrete: *"google dns is likely something not to detect on, so have an exclusion
section and also be able to manage these exclusions"*. A detection engine without one degrades the same
way every time — the known-benign thing fires on every ingest, the analyst learns to skim past that
rule, and the day it means something they skim past that too.

What is pinned here is the part that makes suppression safe to have at all: the event stays in the pool
and in search, nothing is excluded by default, an exclusion says how much it suppressed, and one whose
conditions cannot be evaluated against a graph node does not silently half-apply to graph findings.
"""
from __future__ import annotations

import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.detect import run_rules
from app.exclusions import EXCLUSIONS, suggestions
from app.main import app
from app.models import Event, ExclusionInput, RuleCondition
from app.store import STORE


def _ev(i: int, source: str, msg: str, fields: dict) -> Event:
    return Event(id=f"e{i:x}", ts="2026-05-01T10:00:00Z", source=source, sourceId="s1", file="evidence.log",
                 host=fields.get("host", ""), user=fields.get("user", ""), msg=msg, sev="info",
                 raw=msg, fields=fields)


def _scan_pool() -> list[Event]:
    """Two events that BOTH trip SIGMA-PCAP-0030 (TLS on a non-standard port): one is the monitoring
    stack doing what it always does, the other is a callback. That pairing is the whole point — a
    suppression has to be able to quiet the first without touching the second."""
    return [_ev(1, "network.pcap", "TLS client hello metrics.corp.internal",
                {"tls_sni": "metrics.corp.internal", "dst_port": "8081", "protocol": "TCP", "src_ip": "10.0.0.4"}),
            _ev(2, "network.pcap", "TLS client hello c2.example.io",
                {"tls_sni": "c2.example.io", "dst_port": "4444", "protocol": "TCP", "src_ip": "10.0.0.5"})]


def _run(events: list[Event], matcher=None) -> dict[str, list[str]]:
    ts = np.asarray([1.0 + i for i in range(len(events))])
    run_rules(events, ts, exclude=matcher)
    return {e.id: [d.id for d in e.detections] for e in events}


@pytest.fixture(autouse=True)
def _clean():
    EXCLUSIONS.load()
    with EXCLUSIONS.lock:
        saved = dict(EXCLUSIONS.items), list(EXCLUSIONS.order)
        EXCLUSIONS.items, EXCLUSIONS.order = {}, []
    yield
    with EXCLUSIONS.lock:
        EXCLUSIONS.items, EXCLUSIONS.order = saved[0], saved[1]
    EXCLUSIONS.rev += 1


def _add(**kw) -> str:
    body = ExclusionInput(**kw)
    return EXCLUSIONS.create(body).id


# --------------------------------------------------------------------- the core behaviour
def test_an_exclusion_suppresses_the_detection_and_keeps_the_event() -> None:
    events = _scan_pool()
    before = _run(events)
    assert "SIGMA-PCAP-0030" in before["e1"] and "SIGMA-PCAP-0030" in before["e2"]

    _add(name="internal metrics", conditions=[RuleCondition(field="tls_sni", op="ends_with", value=".corp.internal")])
    events = _scan_pool()
    after = _run(events, EXCLUSIONS.matcher())
    assert after["e1"] == [], "the excluded event kept its detection"
    assert "SIGMA-PCAP-0030" in after["e2"], "the exclusion suppressed something it was not scoped to"
    # the EVENT is untouched: an exclusion is a claim about a rule, not about the evidence
    assert len(events) == 2 and events[0].raw and events[0].fields["tls_sni"] == "metrics.corp.internal"


def test_an_exclusion_can_be_scoped_to_named_rules_only() -> None:
    """"this address is never interesting" and "not interesting FOR THIS RULE" are different claims."""
    events = _scan_pool()
    _add(name="scoped elsewhere", ruleIds=["SIGMA-PCAP-0014"],
         conditions=[RuleCondition(field="tls_sni", op="ends_with", value=".corp.internal")])
    after = _run(events, EXCLUSIONS.matcher())
    assert "SIGMA-PCAP-0030" in after["e1"], "a rule the exclusion does not name must still fire"


def test_it_reports_what_it_suppressed() -> None:
    """A suppression nobody can see is how evidence goes missing quietly."""
    eid = _add(name="internal metrics",
               conditions=[RuleCondition(field="tls_sni", op="ends_with", value=".corp.internal")])
    m = EXCLUSIONS.matcher()
    _run(_scan_pool(), m)
    counts = m.counts()
    assert counts.get(eid, 0) >= 1
    EXCLUSIONS.record(counts)
    row = next(x for x in EXCLUSIONS.all() if x.id == eid)
    assert row.suppressed == counts[eid]


def test_a_disabled_exclusion_suppresses_nothing() -> None:
    eid = _add(name="off", conditions=[RuleCondition(field="tls_sni", op="ends_with", value=".corp.internal")])
    EXCLUSIONS.toggle(eid)
    after = _run(_scan_pool(), EXCLUSIONS.matcher())
    assert "SIGMA-PCAP-0030" in after["e1"]


def test_nothing_is_excluded_by_default() -> None:
    """Iris OFFERS a library and applies none of it. Shipping suppressions enabled would mean an
    analyst's first search silently omitted evidence they never chose to omit."""
    with TestClient(app) as c:
        body = c.get("/api/exclusions").json()
        assert body["exclusions"] == []
        assert len(body["suggestions"]) >= 4
        assert all(s["why"] for s in body["suggestions"]), "a suggestion has to say WHY"
        names = [s["name"] for s in body["suggestions"]]
        assert any("DNS" in n for n in names), "the analyst's own example is not on offer"


# --------------------------------------------------------------------- validation
def test_an_exclusion_with_no_condition_is_refused() -> None:
    with TestClient(app) as c:
        r = c.post("/api/exclusions", json={"name": "everything", "conditions": []})
        assert r.status_code == 400
        assert "condition" in r.json()["detail"]


def test_a_bad_condition_is_refused_with_the_reason() -> None:
    with TestClient(app) as c:
        r = c.post("/api/exclusions", json={"name": "bad", "conditions": [
            {"field": "user", "op": "regex", "value": "([a-z"}]})
        assert r.status_code == 400 and "regex" in r.json()["detail"].lower()


def test_the_trigger_sentence_states_the_scope() -> None:
    with TestClient(app) as c:
        r = c.post("/api/exclusions", json={"name": "resolvers", "conditions": [
            {"field": "_ip", "op": "in", "value": "8.8.8.8, 1.1.1.1"}]})
        assert r.status_code == 200, r.text
        ex = r.json()
        assert "every rule" in (ex["logic"] or "")
        c.delete(f"/api/exclusions/{ex['id']}")


# --------------------------------------------------------------------- graph findings
def test_a_node_evaluable_exclusion_filters_graph_findings() -> None:
    from app.graph import GraphBuilder
    from app import graph_rules

    events = [_ev(i, "syslog", f"Accepted password for user{i} from 8.8.8.8 port 22 ssh2",
                  {"program": "sshd", "result": "Accepted", "user": f"user{i}", "src_ip": "8.8.8.8"})
              for i in range(8)]
    g = GraphBuilder(events, parallel=False)
    assert [f for f in graph_rules.evaluate(g) if f.nodeValue == "8.8.8.8"]

    _add(name="Google DNS", conditions=[RuleCondition(field="ip", op="equals", value="8.8.8.8")])
    assert not [f for f in graph_rules.evaluate(g) if f.nodeValue == "8.8.8.8"]


def test_an_exclusion_that_cannot_be_checked_against_a_node_says_so_and_is_not_applied() -> None:
    """A node has a type and a value and no fields. Half-applying a condition nobody checked would
    suppress a finding the analyst never excluded — so it is declared and left out."""
    from app.graph import GraphBuilder
    from app import graph_rules

    events = [_ev(i, "syslog", f"Accepted password for user{i} from 8.8.8.8 port 22 ssh2",
                  {"program": "sshd", "result": "Accepted", "user": f"user{i}", "src_ip": "8.8.8.8",
                   "dst_port": "22"})
              for i in range(8)]
    g = GraphBuilder(events, parallel=False)
    eid = _add(name="port 22", conditions=[RuleCondition(field="dst_port", op="equals", value="22")])
    row = next(x for x in EXCLUSIONS.all() if x.id == eid)
    assert row.appliesToGraph is False, "a field-based exclusion cannot be evaluated against a node"
    assert [f for f in graph_rules.evaluate(g) if f.nodeValue == "8.8.8.8"], \
        "it was applied to the graph anyway"


# --------------------------------------------------------------------- the API round trip
def test_manage_them_over_the_api() -> None:
    with TestClient(app) as c:
        made = c.post("/api/exclusions", json={
            "name": "Public resolvers", "note": "8.8.8.8 answers for half the internet",
            "conditions": [{"field": "_ip", "op": "in", "value": "8.8.8.8, 1.1.1.1"}]})
        assert made.status_code == 200, made.text
        eid = made.json()["id"]
        assert made.json()["enabled"] is True and made.json()["createdBy"] == "user"

        rows = c.get("/api/exclusions").json()["exclusions"]
        assert [x["id"] for x in rows] == [eid]

        upd = c.put(f"/api/exclusions/{eid}", json={
            "name": "Public resolvers (v2)", "ruleIds": ["SIGMA-PCAP-0014"],
            "conditions": [{"field": "_ip", "op": "in", "value": "8.8.8.8"}]})
        assert upd.status_code == 200 and upd.json()["name"] == "Public resolvers (v2)"
        assert "SIGMA-PCAP-0014" in (upd.json()["logic"] or "")

        assert c.post(f"/api/exclusions/{eid}/toggle").json()["enabled"] is False
        assert c.delete(f"/api/exclusions/{eid}").status_code == 200
        assert c.get("/api/exclusions").json()["exclusions"] == []


def test_they_survive_a_restart() -> None:
    with TestClient(app) as c:
        eid = c.post("/api/exclusions", json={
            "name": "keeper", "conditions": [{"field": "user", "op": "equals", "value": "svc_backup"}]}).json()["id"]
    with EXCLUSIONS.lock:                    # force a reload from disk
        EXCLUSIONS._loaded_from = None
    with TestClient(app) as c:
        rows = c.get("/api/exclusions").json()["exclusions"]
        assert eid in [x["id"] for x in rows]
        c.delete(f"/api/exclusions/{eid}")


def test_clearing_all_data_keeps_them_like_rules_and_settings() -> None:
    """They are CONFIGURATION, not evidence — the same call the Settings copy makes about rules.json."""
    with TestClient(app) as c:
        eid = c.post("/api/exclusions", json={
            "name": "keeper", "conditions": [{"field": "user", "op": "equals", "value": "svc_backup"}]}).json()["id"]
        c.post("/api/admin/clear-all", json={"confirm": "DELETE EVERYTHING"})
        rows = c.get("/api/exclusions").json()["exclusions"]
        assert eid in [x["id"] for x in rows], "clear-all removed the suppression list"
        c.delete(f"/api/exclusions/{eid}")
