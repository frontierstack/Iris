"""Built-in conditions must be genuinely editable, not just readable.

The analyst's complaint was concrete: "Security event 4720 ... there needs to be a pattern box and the
mechanism of exactly how that is being flagged. I might need to edit it too. This isn't customizable."
So every constant in a built-in's condition is a parameter, and these tests prove that editing one
changes what the engine flags - for field rules, threshold rules and regex rules alike.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.detect import PARAMS, RULES
from app.main import app
from tests.conftest import load_sample_case


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as client:
        load_sample_case(client)
        yield client


def _rule(c, rid):
    return next(r for r in c.get("/api/rules").json() if r["id"] == rid)


def _put(c, rid, **params):
    r = _rule(c, rid)
    body = {"name": r["name"], "description": r["description"], "sev": r["sev"], "enabled": r["enabled"],
            "tags": r["tags"], "kind": "builtin", "params": params}
    return c.put(f"/api/rules/{rid}", json=body)


def test_every_builtin_exposes_its_condition_as_editable_parameters() -> None:
    for r in RULES:
        assert r.params, f"{r.id} exposes no editable parameter — its condition is a hidden constant"
        keys = [p.key for p in r.params]
        assert len(keys) == len(set(keys)), f"{r.id} has duplicate parameter keys"
        for p in r.params:
            assert p.kind in ("values", "regex", "text", "int", "seconds", "bytes"), f"{r.id}.{p.key}: {p.kind}"
            assert p.label and p.help, f"{r.id}.{p.key} is unlabelled or unexplained"
            assert p.default, f"{r.id}.{p.key} has no shipped default"


def test_api_serves_params_with_live_values(c) -> None:
    r = _rule(c, "SIGMA-WIN-0120")
    assert [p["key"] for p in r["params"]] == ["eventId"]
    p = r["params"][0]
    assert (p["value"], p["default"], p["kind"], p["field"]) == ("4720", "4720", "text", "EventID")


def test_editing_a_field_parameter_changes_what_fires(c) -> None:
    """The 4720 report, on a rule the fixture actually exercises: WIN-0091 is 4672 + a privilege list.
    Point it at a different event id and the hits follow the parameter, not the shipped constant."""
    rid = "SIGMA-WIN-0091"
    before = _rule(c, rid)["hits"]
    assert before > 0, "fixture no longer exercises this rule — pick another"

    assert _put(c, rid, eventId="4624").status_code == 200  # 4672 -> a logon event that has no PrivilegeList
    after = _rule(c, rid)
    assert after["hits"] != before, "editing the event id did not change what the rule flags"
    assert after["overridden"] is True
    assert next(p for p in after["params"] if p["key"] == "eventId")["value"] == "4624"
    assert next(p for p in after["params"] if p["key"] == "eventId")["default"] == "4672",         "the shipped default must survive an override"

    c.post(f"/api/rules/{rid}/restore")
    assert _rule(c, rid)["hits"] == before


def test_editing_a_value_list_changes_what_fires(c) -> None:
    """WIN-0120 is the analyst's example: one editable knob, the event id."""
    r = _rule(c, "SIGMA-WIN-0120")
    assert [p["key"] for p in r["params"]] == ["eventId"]
    assert _put(c, "SIGMA-WIN-0120", eventId="4672").status_code == 200
    # 4672 IS in the fixture, so pointing 'account created' at it makes the rule fire where it did not
    assert _rule(c, "SIGMA-WIN-0120")["hits"] > (r["hits"] or 0)
    c.post("/api/rules/SIGMA-WIN-0120/restore")


def test_editing_a_threshold_changes_what_fires(c) -> None:
    rid = "SIGMA-WEB-0042"  # credential stuffing: 50 x 401 inside 90 s
    before = _rule(c, rid)["hits"]
    assert before > 0

    assert _put(c, rid, threshold="100000").status_code == 200
    assert _rule(c, rid)["hits"] == 0, "an unreachable threshold should stop the rule firing"

    assert _put(c, rid, threshold="2", window="5").status_code == 200
    assert _rule(c, rid)["hits"] > 0, "a low threshold should bring it back"

    c.post(f"/api/rules/{rid}/restore")
    assert _rule(c, rid)["hits"] == before


def test_editing_a_regex_parameter_changes_what_fires(c) -> None:
    rid = "SIGMA-LNX-0030"  # anti-forensics: history markers + a removal marker
    base = _rule(c, rid)["hits"]
    assert base > 0

    assert _put(c, rid, pattern="definitely-not-in-any-log-xyzzy").status_code == 200
    assert _rule(c, rid)["hits"] == 0, "a regex that matches nothing must stop the rule firing"

    c.post(f"/api/rules/{rid}/restore")
    assert _rule(c, rid)["hits"] == base, "restore must put the shipped regex back"


def test_editing_back_to_the_default_clears_the_override(c) -> None:
    rid = "SIGMA-WIN-0104"
    assert _put(c, rid, eventId="1234").status_code == 200
    assert _rule(c, rid)["overridden"] is True
    assert _put(c, rid, eventId="1102").status_code == 200  # back to the shipped value
    assert _rule(c, rid)["overridden"] is False, "a rule edited back to stock must stop reading as edited"


def test_bad_parameter_values_are_rejected_at_save_time(c) -> None:
    """A value that cannot be parsed would silently disable the rule, so it must 400 instead."""
    c.post("/api/rules/SIGMA-WIN-0120/restore")  # independent of whatever ran before
    assert _put(c, "SIGMA-WIN-0120", eventId="").status_code == 400
    assert _put(c, "SIGMA-WEB-0042", threshold="not-a-number").status_code == 400
    assert _put(c, "SIGMA-WEB-0042", threshold="0").status_code == 400
    assert _put(c, "SIGMA-WEB-0042", window="99999999").status_code == 400          # > 7 days
    assert _put(c, "SIGMA-WEB-0050", pattern="unclosed(").status_code == 400
    assert _put(c, "SIGMA-WIN-0120", nonexistentKnob="x").status_code == 400
    # and none of that left an override behind
    assert _rule(c, "SIGMA-WIN-0120")["overridden"] is False


def test_params_survive_a_restart(c, tmp_path) -> None:
    rid = "SIGMA-AWS-0060"
    assert _put(c, rid, identityType="IAMUser").status_code == 200
    from app.rules import RULES_STORE, RulesStore
    fresh = RulesStore()
    fresh.load()
    got = next(r for r in fresh.builtin_rules() if r.id == rid)
    assert next(p for p in got.params if p.key == "identityType").value == "IAMUser"
    assert fresh.detection_params()[rid] == {"identityType": "IAMUser"}
    c.post(f"/api/rules/{rid}/restore")
    RULES_STORE.load()


def test_clear_all_and_restore_defaults_also_drop_param_overrides(c) -> None:
    assert _put(c, "SIGMA-WIN-0120", eventId="4726").status_code == 200
    c.post("/api/rules/restore-defaults")
    r = _rule(c, "SIGMA-WIN-0120")
    assert r["overridden"] is False and r["params"][0]["value"] == "4720"


def test_regex_params_are_also_exposed_as_patterns_for_the_list_view(c) -> None:
    """`patterns` is the compact projection of the regex params — the two must never disagree."""
    for r in c.get("/api/rules").json():
        if not r["builtin"]:
            continue
        rx = [(p["field"] or "raw", p["value"]) for p in r["params"] if p["kind"] == "regex"]
        assert [(p["field"], p["pattern"]) for p in r["patterns"]] == rx, r["id"]


def test_param_keys_referenced_by_the_engine_all_exist() -> None:
    """Guard against a typo in a _pt/_pl/_pn call silently falling back to "" or 0 forever."""
    import inspect
    import re as _re

    from app import detect

    src = inspect.getsource(detect.run_rules)
    for rid, key in _re.findall(r'_p[tln]\(\s*"([^"]+)",\s*"([^"]+)"', src) + \
                    _re.findall(r'_prx\(\s*"([^"]+)",\s*"([^"]+)"', src):
        assert any(p.key == key for p in PARAMS.get(rid, ())), f"run_rules reads {rid}.{key}, which is not declared"
