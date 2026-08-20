"""The rule editor must make it obvious what does the flagging, and Clear all must be reversible.

Both of these came straight from the analyst using the drawer: the condition used to live in the
editable Description box, so editing it looked like it should change what fires, and nothing did.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.detect import RULES, RULE_PATTERNS
from app.main import app
from tests.conftest import load_sample_case


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as client:
        load_sample_case(client)
        yield client


def test_every_builtin_states_its_trigger_separately_from_its_description() -> None:
    for r in RULES:
        assert r.trigger, f"{r.id} has no trigger — the editor would fall back to prose"
        assert r.description, f"{r.id} has no description"
        # the two must not be the same string: that is exactly the confusion being fixed
        assert r.trigger.strip() != r.description.strip(), f"{r.id}: trigger and description are identical"
        assert r.mechanism in ("regex", "fields", "threshold", "correlation"), f"{r.id}: bad mechanism {r.mechanism!r}"


def test_a_rule_that_exposes_a_regex_says_so_in_its_trigger() -> None:
    """`mechanism` names the PRIMARY method, so a threshold rule may still use a regex to choose what it
    counts (APP-0061 does). What must never happen is an editable pattern the trigger never mentions —
    the analyst would tune a box with no stated effect, which is the whole bug being fixed."""
    for r in RULES:
        if r.id in RULE_PATTERNS:
            assert "regex" in r.trigger.lower(), f"{r.id} exposes an editable regex its trigger never mentions"
        elif r.mechanism == "regex":
            pytest.fail(f"{r.id} claims mechanism 'regex' but exposes no pattern to edit")


def test_api_serves_trigger_as_logic_plus_mechanism(c) -> None:
    rules = {r["id"]: r for r in c.get("/api/rules").json()}
    web = rules["SIGMA-WEB-0058"]
    assert web["mechanism"] == "regex"
    assert "http.path" in web["logic"]
    assert web["logic"] != web["description"]
    assert web["patterns"] and web["patterns"][0]["field"] == "http.path"
    # a pure field-comparison rule still explains itself, and offers no pattern to edit
    root = rules["SIGMA-AWS-0060"]
    assert root["mechanism"] == "fields"
    assert root["patterns"] == []
    assert "userIdentity.type" in root["logic"]


def test_editing_the_description_does_not_change_what_fires(c) -> None:
    before = c.get("/api/rules").json()
    hits = {r["id"]: r["hits"] for r in before}
    rule = next(r for r in before if r["id"] == "SIGMA-WEB-0050")
    body = {**{k: rule[k] for k in ("name", "sev", "enabled", "tags")},
            "description": "totally unrelated prose that matches nothing", "kind": "builtin",
            "pattern": rule["patterns"][0]["pattern"]}
    r = c.put("/api/rules/SIGMA-WEB-0050", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["description"] == "totally unrelated prose that matches nothing"
    after = {x["id"]: x["hits"] for x in c.get("/api/rules").json()}
    assert after == hits, "changing a description changed detections — description must be documentation only"
    c.post("/api/rules/SIGMA-WEB-0050/restore")


def test_clear_all_empties_the_list_and_restore_defaults_brings_builtins_back(c) -> None:
    c.post("/api/rules", json={"name": "keeper", "pattern": "root", "field": "raw", "sev": "low", "kind": "regex"})
    assert len(c.get("/api/rules").json()) > len(RULES)

    cleared = c.post("/api/rules/clear?scope=all").json()
    assert cleared["custom"] >= 1 and cleared["builtin"] == len(RULES)
    assert c.get("/api/rules").json() == [], "clear all left rules behind"
    # and no detections survive it
    assert all(not e["detections"] for e in c.get("/api/events?limit=500").json()["rows"])

    restored = c.post("/api/rules/restore-defaults").json()
    assert restored["restored"] == len(RULES)
    back = c.get("/api/rules").json()
    assert len(back) == len(RULES), "custom rules must NOT come back — only built-ins are recoverable"
    assert sum(r["hits"] or 0 for r in back) > 0, "built-ins came back but stopped detecting"


def test_clear_custom_scope_leaves_builtins_alone(c) -> None:
    c.post("/api/rules", json={"name": "temp", "pattern": "sshd", "field": "raw", "sev": "low", "kind": "regex"})
    out = c.post("/api/rules/clear?scope=custom").json()
    assert out["custom"] == 1 and out["builtin"] == 0
    ids = [r["id"] for r in c.get("/api/rules").json()]
    assert len(ids) == len(RULES) and all(i.startswith("SIGMA-") for i in ids)


def test_clear_rejects_a_bogus_scope(c) -> None:
    assert c.post("/api/rules/clear?scope=everything").status_code == 400
