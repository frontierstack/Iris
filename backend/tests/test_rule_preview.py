"""Trying a rule must not cost installing one.

The analyst asked to be able to prompt the assistant into building detection rules. The tool surface for
that already existed (create / update / tune / enable); what was missing was the step in the middle. An
author who cannot try a rule has to SAVE it to find out what it does — and saving re-runs the catalogue
over the whole pool and stamps detections on the analyst's evidence, so a rule that turns out to match a
million lines is expensive to install and expensive to undo.

`POST /api/rules/preview` and the `preview_detection_rule` tool answer the question for free, through the
SAME matcher `apply_rule` uses, so a preview and the rule that follows it can never disagree.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.rules import RULES_STORE
from app.store import STORE
from tests.conftest import load_sample_case


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as client:
        load_sample_case(client)
        yield client


def _preview(c, **body):
    body.setdefault("name", "draft")
    body.setdefault("sev", "medium")
    return c.post("/api/rules/preview", json=body)


def test_a_regex_preview_reports_hits_without_saving_anything(c) -> None:
    before = len(c.get("/api/rules").json())
    r = _preview(c, pattern=r"sshd\[", field="raw", kind="regex")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["hits"] > 0 and body["sample"]
    assert "regex" in body["trigger"].lower(), "the author must see what the ENGINE will evaluate"
    assert len(c.get("/api/rules").json()) == before, "a preview must not create a rule"
    # and nothing was tagged on the evidence
    with STORE.lock:
        assert not any(d.id == "preview" for e in STORE.events for d in e.detections)


def test_a_condition_preview_agrees_with_the_rule_that_gets_saved(c) -> None:
    """The one property that makes a preview worth having: it is the same matcher."""
    cond = [{"field": "raw", "op": "contains", "value": "sshd["}]
    predicted = _preview(c, conditions=cond, kind="conditions").json()["hits"]

    made = c.post("/api/rules", json={"name": "preview-agreement", "kind": "conditions",
                                      "conditions": cond, "sev": "low"})
    assert made.status_code == 200, made.text
    rid = made.json()["id"]
    try:
        actual = next(x for x in c.get("/api/rules").json() if x["id"] == rid)["hits"]
        assert actual == predicted, "the preview and the saved rule disagreed about the same pool"
    finally:
        c.delete(f"/api/rules/{rid}")


def test_an_unsafe_pattern_is_refused_in_a_preview_exactly_as_at_save_time(c) -> None:
    r = _preview(c, pattern="(a+)+$", field="raw", kind="regex")
    assert r.status_code in (200, 400)
    if r.status_code == 200:
        assert r.json()["error"], "a catastrophic pattern must come back as an error, not as 0 hits"


def test_a_preview_with_neither_pattern_nor_conditions_is_refused(c) -> None:
    r = _preview(c, kind="regex")
    assert r.status_code == 200 and r.json()["error"], "an empty definition has to say so"


def test_the_ai_tool_previews_and_says_when_a_rule_would_match_nothing(c) -> None:
    from app.ai.tools import REGISTRY, RunContext

    ctx = RunContext(run_id="test-preview", model="test")
    out = REGISTRY["preview_detection_rule"].fn(
        {"name": "nothing at all", "pattern": "zzz-this-string-is-not-in-any-log-zzz", "field": "raw"}, ctx)
    assert out["hits"] == 0 and out["saved"] is False
    assert "matches NOTHING" in out.get("note", ""), \
        "a rule that matches nothing must SAY so — a bare 0 reads as a working rule with a quiet pool"

    out = REGISTRY["preview_detection_rule"].fn({"name": "everything", "pattern": ".", "field": "raw"}, ctx)
    assert out["hits"] > 0
    assert "5%" in out.get("note", ""), "a rule that flags the whole pool is a label, not a detection"


def test_the_preview_tool_is_a_read_and_records_no_action(c) -> None:
    """It must not be in the write surface: the AI panel draws writes differently, and a dry run changes
    nothing on the case."""
    from app.ai.tools import REGISTRY
    assert REGISTRY["preview_detection_rule"].writes is False
    assert REGISTRY["list_graph_findings"].writes is False
