"""All the logs are in scope — and the agent is told which query form reaches which of them.

The analyst: *"I noticed that the assistant is not including all log sources in its investigation, only
enriched data is being searched against. All logs should be in scope."*

The mechanism, and why it was invisible: since ingest became raw-first, most sources sit in phase 1.
A raw event has its line and its timestamp and NOTHING else — no parsed fields, no extracted entities.
`entity:"10.0.0.5"` matches extracted entities, so it silently covers only the interpreted subset,
while free text reaches every raw line. Both are correct queries; nothing in the answer said they
covered different amounts of the pool, so "64 events" read as the workspace total when it was the
total for one source.

This is the silent-absence class of bug this project keeps fighting, so the fix is stated in the
DATA — `entity_profile.coverage` carries both counts, the sources the mentions are in, and the list of
uninterpreted sources — not only in the prompt.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.ai.tools import REGISTRY, RunContext
from app.config import update_settings
from app.main import app
from app.store import STORE

# one line per record, all mentioning the same address — the shape of the analyst's proxy export
RAW_LOG = b"".join(
    f'"Aug 17, 2026 @ 09:{i // 60 % 60:02d}:{i % 60:02d}.000",10.0.0.101,66.218.84.137,443,allow\n'.encode()
    for i in range(40))


@pytest.fixture()
def raw_pool():
    """A workspace whose only source is RAW — phase 1 done, phase 2 never asked for."""
    with TestClient(app) as c:
        STORE.clear_all()
        update_settings({"ingest": {"autoEnrich": False}})
        try:
            c.post("/api/cases", json={"name": "Coverage"})
            c.post("/api/sources", files={"files": ("proxy.csv", RAW_LOG, "text/csv")})
            src = next(iter(STORE.sources.values()))
            assert src.enrich in ("raw", "queued"), f"expected a raw source, got {src.enrich}"
            assert not any(e.entities for e in STORE.events), "phase 1 must not extract entities"
            yield c
        finally:
            update_settings({"ingest": {"autoEnrich": True}})
            STORE.clear_all()


def profile(value: str) -> dict:
    return REGISTRY["entity_profile"].fn({"value": value}, RunContext(run_id="run-cov", model="test"))


def test_an_entity_only_in_raw_lines_is_reported_not_denied(raw_pool):
    out = profile("66.218.84.137")
    assert out["total"] == 0, "nothing is extracted from a raw source — that is the premise"
    cov = out["coverage"]
    assert cov["textMentions"] == 40, "every raw line mentioning it is still in the pool and findable"
    assert "NOT absence of evidence" in out["note"]
    assert "search_events" in out["note"], "the note has to name the call that reads them"


def test_the_coverage_block_names_the_uninterpreted_sources(raw_pool):
    cov = profile("66.218.84.137")["coverage"]
    files = [r["file"] for r in cov["uninterpretedSources"]]
    assert files == ["proxy.csv"]
    assert "entity" in cov["note"] and "free text" in cov["note"]
    assert cov["mentionQuery"] == '"66.218.84.137"'


def test_mentions_are_broken_down_by_source(raw_pool):
    cov = profile("66.218.84.137")["coverage"]
    assert cov["mentionsBySource"], "'which logs is it in' must be answerable from this one call"
    assert cov["mentionsBySource"][0]["count"] == 40


def test_a_value_in_no_log_at_all_is_still_a_clean_negative(raw_pool):
    out = profile("203.0.113.199")
    assert out["total"] == 0 and out["coverage"]["textMentions"] == 0
    assert "genuinely not in the ingested logs" in out["note"]


def test_the_orientation_block_flags_raw_sources(raw_pool):
    from app.ai.investigator import build_context

    ctx = build_context(STORE)
    assert "RAW — not interpreted" in ctx
    assert "SCOPE WARNING" in ctx
    assert "free text" in ctx.lower()


def test_an_interpreted_workspace_says_so_instead(raw_pool):
    """Once phase 2 has run there is no scope caveat to make — and the profile must not invent one."""
    sid = next(iter(STORE.sources))
    STORE.enrich_source(sid)
    assert STORE.sources[sid].enrich == "enriched"

    out = profile("66.218.84.137")
    assert out["total"] > 0, "the entity is extracted now"
    cov = out["coverage"]
    assert "uninterpretedSources" not in cov
    assert build_ctx_has_no_warning()


def build_ctx_has_no_warning() -> bool:
    from app.ai.investigator import build_context

    return "SCOPE WARNING" not in build_context(STORE)
