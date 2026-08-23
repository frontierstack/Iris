"""Detections that read the ENTITY GRAPH.

The analyst's ask: "include some rule sets that flag on the entity graph as well, maybe things like a
single ip associated with multiple nodes". The findings below are all of that shape — one address, many
accounts; one account, many addresses; one hash, many hosts — and none of them can be expressed as a
per-event rule, because every individual line is unremarkable. That is the whole reason this exists, so
these tests build pools where NO event rule fires and assert the graph rules find the shape anyway.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import graph_findings, graph_rules
from app.detect import all_builtin_rules, RULES
from app.graph import GraphBuilder
from app.main import app
from app.models import Event
from app.rules import RULES_STORE
from app.store import STORE


def _ev(i: int, msg: str, fields: dict, ts: str = "2026-05-01T10:00:00Z") -> Event:
    return Event(id=f"e{i:x}", ts=ts, source="syslog", sourceId="s1", file="auth.log", host=fields.get("host", ""),
                 user=fields.get("user", ""), msg=msg, sev="info", raw=msg, fields=fields)


def _graph(events: list[Event]) -> GraphBuilder:
    return GraphBuilder(events, parallel=False)


@pytest.fixture(autouse=True)
def _clean_catalogue():
    """Every test here reads the SHIPPED tuning, so a leftover override from another module would make
    the thresholds mean something else."""
    RULES_STORE.load()
    with RULES_STORE.lock:
        saved = dict(RULES_STORE.builtin_overrides), set(RULES_STORE.disabled_builtins)
        RULES_STORE.builtin_overrides.clear()
        RULES_STORE.disabled_builtins.clear()
    graph_findings.invalidate()
    yield
    with RULES_STORE.lock:
        RULES_STORE.builtin_overrides = dict(saved[0])
        RULES_STORE.disabled_builtins = set(saved[1])
    graph_findings.invalidate()


# --------------------------------------------------------------------- catalogue
def test_graph_rules_are_ordinary_builtins_in_one_catalogue() -> None:
    ids = {r.id for r in all_builtin_rules()}
    assert graph_rules.rule_ids() <= ids, "graph rules are missing from the shipped catalogue"
    assert graph_rules.rule_ids().isdisjoint({r.id for r in RULES}), \
        "a graph rule must not be in detect.RULES — run_rules cannot evaluate one"
    for r in all_builtin_rules():
        if r.id in graph_rules.rule_ids():
            assert r.mechanism == "graph"
            assert r.params, f"{r.id} exposes no editable parameter"
            assert r.trigger and r.trigger.strip() != r.description.strip()


def test_the_api_serves_them_with_their_parameters() -> None:
    with TestClient(app) as c:
        rows = {r["id"]: r for r in c.get("/api/rules").json()}
        r = rows["SIGMA-GRAPH-0010"]
        assert r["mechanism"] == "graph" and r["builtin"] is True
        keys = {p["key"] for p in r["params"]}
        assert {"relations", "distinctUsers"} <= keys
        # hits is None, not 0: nothing has evaluated the graph, and "never fired" would be a claim
        assert r["hits"] is None


# --------------------------------------------------------------------- the findings themselves
def test_one_address_many_accounts_is_found_when_no_event_rule_fires() -> None:
    events = [_ev(i, f"Accepted password for user{i} from 10.9.9.9 port 22 ssh2",
                  {"program": "sshd", "result": "Accepted", "user": f"user{i}", "src_ip": "10.9.9.9",
                   "host": "bastion"})
              for i in range(8)]
    findings = graph_rules.evaluate(_graph(events))
    hit = [f for f in findings if f.ruleId == "SIGMA-GRAPH-0010"]
    assert hit, "8 accounts from one address is exactly the shape this rule exists for"
    f = hit[0]
    assert f.nodeType == "ip" and f.nodeValue == "10.9.9.9"
    assert f.metric >= 6 and "accounts" in f.metricLabel
    assert f.citedEventIds, "a finding with no citation cannot be opened"
    assert all(any(e.id == cid for e in events) for cid in f.citedEventIds), "cited ids must be real"


def test_one_account_many_addresses() -> None:
    # 198.51.100.x, not 203.0.113.x: graph.plausible_ip deliberately rejects an address with a zero
    # octet in the middle, because that is what a dotted version string looks like. A test that picked
    # the other documentation range would be testing that heuristic instead of this rule.
    events = [_ev(i, f"Accepted password for alice from 198.51.100.{i} port 22 ssh2",
                  {"program": "sshd", "result": "Accepted", "user": "alice", "src_ip": f"198.51.100.{i}",
                   "host": "web01"})
              for i in range(1, 8)]
    hits = [f for f in graph_rules.evaluate(_graph(events)) if f.ruleId == "SIGMA-GRAPH-0014"]
    assert hits and hits[0].nodeValue == "alice" and hits[0].metric >= 5


def test_a_hash_on_many_hosts() -> None:
    h = "a" * 64
    events = [_ev(i, f"file scan {h} on host{i}", {"hash": h, "host": f"host{i}"}) for i in range(4)]
    hits = [f for f in graph_rules.evaluate(_graph(events)) if f.ruleId == "SIGMA-GRAPH-0022"]
    assert hits, "the same hash on four hosts is how a tool spreading looks"
    assert hits[0].metric >= 3


def test_a_quiet_workspace_produces_no_findings() -> None:
    """The counterpart that matters most: these rules must not fire on ordinary traffic, or the section
    is noise and gets ignored — which is worse than not having it."""
    events = [_ev(i, "Accepted password for alice from 10.0.0.5 port 22 ssh2",
                  {"program": "sshd", "result": "Accepted", "user": "alice", "src_ip": "10.0.0.5",
                   "host": "web01"})
              for i in range(20)]
    assert graph_rules.evaluate(_graph(events)) == []


def test_tuning_a_parameter_changes_what_is_reported() -> None:
    """The same editability every built-in has: the threshold is a knob, not a constant in Python."""
    events = [_ev(i, f"Accepted password for user{i} from 10.9.9.9 port 22 ssh2",
                  {"program": "sshd", "result": "Accepted", "user": f"user{i}", "src_ip": "10.9.9.9",
                   "host": "bastion"})
              for i in range(4)]
    g = _graph(events)
    assert not [f for f in graph_rules.evaluate(g) if f.ruleId == "SIGMA-GRAPH-0010"], "4 < the shipped 6"

    with RULES_STORE.lock:
        RULES_STORE.builtin_overrides["SIGMA-GRAPH-0010"] = {"params": {"distinctUsers": "3"}}
    hits = [f for f in graph_rules.evaluate(g) if f.ruleId == "SIGMA-GRAPH-0010"]
    assert hits and hits[0].metric == 4, "lowering the threshold must change what is reported"


def test_a_disabled_graph_rule_reports_nothing() -> None:
    events = [_ev(i, f"Accepted password for user{i} from 10.9.9.9 port 22 ssh2",
                  {"program": "sshd", "result": "Accepted", "user": f"user{i}", "src_ip": "10.9.9.9"})
              for i in range(9)]
    g = _graph(events)
    assert [f for f in graph_rules.evaluate(g) if f.ruleId == "SIGMA-GRAPH-0010"]
    with RULES_STORE.lock:
        RULES_STORE.disabled_builtins.add("SIGMA-GRAPH-0010")
    assert not [f for f in graph_rules.evaluate(g) if f.ruleId == "SIGMA-GRAPH-0010"]


def test_a_failure_heavy_relationship_is_reported() -> None:
    events = [_ev(i, "Failed password for root from 198.51.100.7 port 22 ssh2",
                  {"program": "sshd", "result": "Failed", "user": "root", "src_ip": "198.51.100.7",
                   "host": "web01"})
              for i in range(30)]
    hits = [f for f in graph_rules.evaluate(_graph(events)) if f.ruleId == "SIGMA-GRAPH-0030"]
    assert hits, "a relation that is 100% failures is the point of this rule"
    assert "failed" in hits[0].summary or "denied" in hits[0].summary


# --------------------------------------------------------------------- the endpoint
def test_the_endpoint_never_reports_an_unbuilt_graph_as_a_clean_one() -> None:
    """`evaluated` is the whole contract: false means nobody has looked, and the screen must say so
    rather than rendering an empty list as 'no findings'."""
    with TestClient(app) as c:
        r = c.get("/api/graph/anomalies")
        assert r.status_code == 200, r.text
        body = r.json()
        assert set(body) >= {"findings", "rules", "evaluated", "status"}
        assert body["rules"] == len(graph_rules.GRAPH_RULES)
        if not body["evaluated"]:
            assert body["findings"] == []


def test_the_route_is_not_swallowed_by_the_entity_catch_all() -> None:
    """GET /api/graph/{name:path} would happily answer this path with an Entity named 'anomalies'."""
    with TestClient(app) as c:
        body = c.get("/api/graph/anomalies").json()
        assert "findings" in body, "the catch-all route captured /graph/anomalies"


def test_tuning_a_graph_rule_does_not_re_run_the_event_catalogue(monkeypatch) -> None:
    """A graph rule tags no event, so re-evaluating 65 event rules over the pool would change nothing at
    a cost of O(pool). The findings memo keys on RULES_STORE.rev, so it misses on its own."""
    from app import store as store_mod

    calls = {"n": 0}
    real = store_mod.Store._run_detections
    monkeypatch.setattr(store_mod.Store, "_run_detections",
                        lambda self: (calls.__setitem__("n", calls["n"] + 1), real(self))[1])
    with TestClient(app) as c:
        calls["n"] = 0            # startup runs one pass of its own; count only what the PUT causes
        r = c.get("/api/rules").json()
        rule = next(x for x in r if x["id"] == "SIGMA-GRAPH-0010")
        body = {"name": rule["name"], "description": rule["description"], "sev": rule["sev"],
                "enabled": True, "tags": rule["tags"], "kind": "builtin",
                "params": {"distinctUsers": "9"}}
        assert c.put("/api/rules/SIGMA-GRAPH-0010", json=body).status_code == 200
        assert calls["n"] == 0, "tuning a graph rule must not re-run the event catalogue"
        # and the change is live
        after = next(x for x in c.get("/api/rules").json() if x["id"] == "SIGMA-GRAPH-0010")
        assert next(p for p in after["params"] if p["key"] == "distinctUsers")["value"] == "9"
        c.post("/api/rules/SIGMA-GRAPH-0010/restore")
