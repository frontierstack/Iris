"""Custom rules built from CONDITIONS, not just a raw regex.

The analyst's ask: "when building a new rule, let me build on conditions as well, like the built-ins do."
So a custom rule can now be composed from typed (field, operator, value) rows joined with AND/OR, with
optional threshold semantics (count within a window, grouped by a field). These tests cover every
operator, the combinators, the threshold, save-time validation, safe degradation of a bad stored value,
and — most importantly — that a rules.json full of legacy regex rules keeps loading and firing unchanged.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.detect import CONDITION_OPS, condition_pred
from app.main import app
from app.models import Event, Rule, RuleCondition, RuleThreshold
from tests.conftest import load_sample_case


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as client:
        load_sample_case(client)
        yield client


def _ev(**kw) -> Event:
    base = dict(id="e1", ts="2026-08-11T00:00:00Z", source="nginx.access", sourceId="s1", file="access.log",
                host="edge-lb-01", user="svc_deploy", msg="GET /login 401", sev="info", raw="raw line",
                fields={"http.status": "401", "bytes": "1200", "src_ip": "203.0.113.9"})
    base.update(kw)
    return Event(**base)


def _mk(c, **body):
    payload = {"name": "cond rule", "sev": "low", "kind": "conditions", **body}
    return c.post("/api/rules", json=payload)


def _cleanup(c, *ids):
    for i in ids:
        c.delete(f"/api/rules/{i}")


# ------------------------------------------------------------------ operators
def test_every_operator_behaves_as_documented() -> None:
    e = _ev()
    cases = [
        ("http.status", "equals", "401", True), ("http.status", "equals", "500", False),
        ("http.status", "not_equals", "500", True), ("http.status", "not_equals", "401", False),
        ("msg", "contains", "/login", True), ("msg", "contains", "/admin", False),
        ("msg", "not_contains", "/admin", True), ("msg", "not_contains", "/login", False),
        ("user", "starts_with", "svc_", True), ("user", "starts_with", "adm", False),
        ("file", "ends_with", ".log", True), ("file", "ends_with", ".evtx", False),
        ("msg", "regex", r"GET\s+/log\w+", True), ("msg", "regex", r"POST\s+/", False),
        ("http.status", "in", "401, 403", True), ("http.status", "in", "500, 502", False),
        ("http.status", "not_in", "500, 502", True), ("http.status", "not_in", "401", False),
        ("bytes", "gt", "1000", True), ("bytes", "gt", "5000", False),
        ("bytes", "lt", "5000", True), ("bytes", "lt", "100", False),
        ("src_ip", "exists", "", True), ("nope", "exists", "", False),
    ]
    for field, op, value, want in cases:
        assert condition_pred(field, op, value)(e) is want, f"{field} {op} {value!r}"
    # every operator the API advertises is actually implemented
    assert set(CONDITION_OPS) == {"equals", "not_equals", "contains", "not_contains", "starts_with", "ends_with",
                                  "regex", "in", "not_in", "gt", "lt", "exists"}


def test_negative_operators_are_true_when_the_field_is_absent() -> None:
    """Same semantics as `NOT field:value` in the search DSL — documented in the API contract."""
    e = _ev()
    assert condition_pred("missing.field", "not_equals", "x")(e) is True
    assert condition_pred("missing.field", "equals", "x")(e) is False
    assert condition_pred("missing.field", "not_in", "a, b")(e) is True


def test_numeric_operators_ignore_non_numeric_values() -> None:
    e = _ev(fields={"bytes": "not-a-number"})
    assert condition_pred("bytes", "gt", "10")(e) is False
    assert condition_pred("bytes", "lt", "10")(e) is False


# ------------------------------------------------------------------ end to end
def test_a_condition_rule_fires_and_carries_a_generated_trigger(c) -> None:
    r = _mk(c, name="401 from the edge", conditions=[
        {"field": "source", "op": "equals", "value": "nginx.access"},
        {"field": "http.status", "op": "equals", "value": "401"},
    ], description="prose that matches nothing")
    assert r.status_code == 200, r.text
    rule = r.json()
    assert rule["kind"] == "conditions"
    assert rule["hits"] > 0, "the rule matched nothing in the sample case"
    # the four-piece model survives: trigger is generated, read-only and NOT the description
    assert rule["logic"] and rule["logic"] != rule["description"]
    assert "http.status equals" in rule["logic"] and "AND" in rule["logic"]
    assert rule["mechanism"] == "fields"
    _cleanup(c, rule["id"])


def test_and_narrows_where_or_widens(c) -> None:
    conds = [{"field": "http.status", "op": "equals", "value": "401"},
             {"field": "source", "op": "equals", "value": "syslog"}]
    a = _mk(c, name="and rule", conditions=conds, combinator="and").json()
    o = _mk(c, name="or rule", conditions=conds, combinator="or").json()
    assert a["hits"] == 0, "no event is both an nginx 401 and a syslog line"
    assert o["hits"] > a["hits"], "OR must match at least everything AND does"
    assert " OR " in o["logic"] and " AND " in a["logic"]
    _cleanup(c, a["id"], o["id"])


def test_a_regex_condition_is_projected_into_patterns(c) -> None:
    """`patterns` stays DERIVED from the regex conditions — never maintained separately."""
    rule = _mk(c, name="rx rule", conditions=[{"field": "msg", "op": "regex", "value": "GET|POST"}]).json()
    assert rule["patterns"] == [{"field": "msg", "pattern": "GET|POST"}]
    assert rule["mechanism"] == "regex"
    assert "regex" in rule["logic"]
    _cleanup(c, rule["id"])


def test_threshold_with_group_by_fires_on_a_burst(c) -> None:
    conds = [{"field": "source", "op": "equals", "value": "nginx.access"},
             {"field": "http.status", "op": "equals", "value": "401"}]
    plain = _mk(c, name="every 401", conditions=conds).json()
    burst = _mk(c, name="401 burst", conditions=conds,
                threshold={"count": 20, "window": 120, "groupBy": "src_ip"}).json()
    assert burst["mechanism"] == "threshold"
    assert "grouped by src_ip" in burst["logic"] and "120-second" in burst["logic"]
    # a burst tags only the anchor event of each window, so it must be far below the per-event count
    assert 0 < burst["hits"] < plain["hits"]

    # an unreachable threshold stops it firing; a trivial one brings it back
    body = {"name": "401 burst", "sev": "low", "kind": "conditions", "conditions": conds,
            "threshold": {"count": 100000, "window": 120, "groupBy": "src_ip"}}
    assert c.put(f"/api/rules/{burst['id']}", json=body).json()["hits"] == 0
    body["threshold"] = {"count": 2, "window": 3600, "groupBy": ""}
    back = c.put(f"/api/rules/{burst['id']}", json=body).json()
    assert back["hits"] > 0 and "across the whole case" in back["logic"]
    _cleanup(c, plain["id"], burst["id"])


def test_conditions_survive_a_restart(c) -> None:
    rule = _mk(c, name="persisted", conditions=[{"field": "user", "op": "starts_with", "value": "svc_"}],
               threshold={"count": 3, "window": 600, "groupBy": "host"}).json()
    from app.rules import RulesStore
    fresh = RulesStore()
    fresh.load()
    got = next(r for r in fresh.custom_rules() if r.id == rule["id"])
    assert got.kind == "conditions" and got.conditions[0].op == "starts_with"
    assert got.threshold and got.threshold.groupBy == "host"
    assert got.logic == rule["logic"], "the trigger must regenerate identically after a reload"
    _cleanup(c, rule["id"])


# ------------------------------------------------------------------ validation
def test_bad_conditions_are_rejected_at_save_time(c) -> None:
    assert _mk(c, conditions=[{"field": "msg", "op": "matches", "value": "x"}]).status_code == 400  # unknown op
    assert _mk(c, conditions=[{"field": "", "op": "equals", "value": "x"}]).status_code == 400      # no field
    assert _mk(c, conditions=[{"field": "msg", "op": "equals", "value": ""}]).status_code == 400    # no value
    assert _mk(c, conditions=[{"field": "msg", "op": "regex", "value": "unclosed("}]).status_code == 400
    assert _mk(c, conditions=[{"field": "bytes", "op": "gt", "value": "lots"}]).status_code == 400
    assert _mk(c, conditions=[{"field": "msg", "op": "in", "value": " , "}]).status_code == 400
    # threshold bounds
    assert _mk(c, conditions=[{"field": "msg", "op": "exists"}], threshold={"count": 0, "window": 60}).status_code == 400
    assert _mk(c, conditions=[{"field": "msg", "op": "exists"}], threshold={"count": 5, "window": 99999999}).status_code == 400
    # and a rule with neither a pattern nor a condition is not a rule
    assert c.post("/api/rules", json={"name": "empty", "sev": "low", "kind": "conditions"}).status_code == 400
    assert [r for r in c.get("/api/rules").json() if r["name"] in ("cond rule", "empty")] == []


def test_a_bad_stored_value_degrades_instead_of_crashing_the_engine(c, tmp_path, monkeypatch) -> None:
    """Hand-edited rules.json: an unparsable condition must disable that rule only, with an explanation."""
    from app import config
    from app.rules import RulesStore

    path = tmp_path / "rules.json"
    path.write_text(json.dumps({"rules": [
        {"id": "RULE-9001", "name": "broken", "sev": "low", "enabled": True, "kind": "conditions",
         "conditions": [{"field": "msg", "op": "regex", "value": "unclosed("}], "combinator": "and"},
        {"id": "RULE-9002", "name": "fine", "sev": "low", "enabled": True, "kind": "conditions",
         "conditions": [{"field": "http.status", "op": "equals", "value": "401"}], "combinator": "and"},
    ], "seq": 9002}), encoding="utf-8")
    monkeypatch.setattr(config, "RULES_PATH", path)
    store = RulesStore()
    events = [_ev(), _ev(id="e2", fields={"http.status": "500"})]
    assert store.apply_all(events) == 1, "the healthy rule must still fire"
    broken = next(r for r in store.custom_rules() if r.id == "RULE-9001")
    assert broken.error and "regex" in broken.error
    assert all(d.id != "RULE-9001" for e in events for d in e.detections)


def test_conditions_are_evaluated_inside_the_sandbox(monkeypatch) -> None:
    """A condition rule goes through the same guarded evaluation (and 5 s timeout) as a regex rule:
    when the sandbox abandons the pass, the rule reports it and flags nothing."""
    from app import rules as rules_mod
    from app.rules import RULES_STORE, RuleTimeout

    seen: list[str] = []

    def boom(fn, timeout: float = rules_mod.RULE_TIMEOUT_S):
        seen.append("sandboxed")
        raise RuleTimeout(f"evaluation exceeded {timeout:g}s (catastrophic pattern?)")

    monkeypatch.setattr(rules_mod, "_run_with_timeout", boom)
    r = Rule(id="RULE-SLOW", name="slow", sev="low", kind="conditions",
             conditions=[RuleCondition(field="raw", op="regex", value="(a+)+$")],
             threshold=RuleThreshold(count=2, window=60, groupBy="host"))
    ev = _ev(raw="a" * 40 + "!")
    assert RULES_STORE.apply_rule(r, [ev]) == 0
    assert seen == ["sandboxed"], "condition rules must not bypass the guarded evaluation path"
    assert RULES_STORE.errors.get("RULE-SLOW", "").startswith("evaluation exceeded")
    assert not ev.detections
    RULES_STORE.errors.pop("RULE-SLOW", None)


# ------------------------------------------------------------------ backward compatibility
def test_legacy_regex_rules_keep_loading_and_firing(c, tmp_path, monkeypatch) -> None:
    """A rules.json written before conditions existed has no `conditions` key at all — it must load as a
    plain regex rule, keep kind 'regex', and match exactly what it always did."""
    from app import config
    from app.rules import RulesStore

    path = tmp_path / "legacy.json"
    path.write_text(json.dumps({"rules": [
        {"id": "RULE-0001", "name": "root login", "description": "legacy", "sev": "high", "enabled": True,
         "builtin": False, "kind": "regex", "pattern": "GET /login", "field": "any",
         "flags": {"ignoreCase": True, "multiline": False}, "sourceFilter": "", "tags": ["legacy"],
         "createdBy": "user", "createdAt": "", "updatedAt": ""},
    ], "disabledBuiltins": [], "seq": 1}), encoding="utf-8")
    monkeypatch.setattr(config, "RULES_PATH", path)
    store = RulesStore()
    got = store.custom_rules()
    assert len(got) == 1
    r = got[0]
    assert r.kind == "regex" and r.pattern == "GET /login" and r.conditions == [] and r.threshold is None
    # it still fires, and now also explains itself with a generated trigger distinct from its description
    events = [_ev(), _ev(id="e2", msg="GET /health 200", raw="ok")]
    assert store.apply_all(events) == 1
    assert events[0].detections[0].id == "RULE-0001" and not events[1].detections
    assert r.logic and r.logic != r.description and "GET /login" in r.logic
    assert [(p.field, p.pattern) for p in r.patterns] == [("any", "GET /login")]


def test_the_legacy_create_path_is_unchanged(c) -> None:
    """POST with a bare pattern (what the old UI sends) still works and is still kind 'regex'."""
    r = c.post("/api/rules", json={"name": "legacy create", "pattern": "sshd", "field": "raw", "sev": "low",
                                   "kind": "regex"})
    assert r.status_code == 200, r.text
    rule = r.json()
    assert rule["kind"] == "regex" and rule["pattern"] == "sshd" and rule["conditions"] == []
    assert rule["hits"] > 0
    _cleanup(c, rule["id"])
