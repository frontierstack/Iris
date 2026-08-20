"""Citations may be written in the prose, but they are never invented.

The analyst watched a run get refused mid-write:

    add_note(text="…he was the flow t-end edge server (Yahoo/Verizon Media, USA). Every one of the 64
    events referencing it in this…") → refused: citedEventIds is required: a finding with no evidence
    cannot go in the case file

…and then spend more of its budget retrying — 16 tool calls in. The refusal rule is right and stays:
a finding with no evidence must not enter the case file. What was wrong is WHERE the citation had to
be. A note whose text says "e.g. `l6e2c94f91078ed`" HAS cited its evidence; only the parameter was
missing, and the round trip bought the analyst nothing.

So the ids in the text are adopted — and verified against the pool exactly like the parameter, which
is the part that must never soften: a fabricated id is still refused and still named, and a note with
no real ids anywhere is still refused.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.ai.tools import REGISTRY, RunContext, ToolError
from app.main import app
from app.store import STORE
from tests.conftest import load_sample_case


@pytest.fixture()
def pool():
    with TestClient(app) as c:
        load_sample_case(c)
        yield c


def ctx() -> RunContext:
    return RunContext(run_id="run-cite", model="test", max_writes=20)


def test_ids_written_in_the_note_are_accepted_as_its_citations(pool):
    eid = STORE.events[0].id
    out = REGISTRY["add_note"].fn(
        {"text": f"Yahoo edge server; every one of the 64 events, e.g. `{eid}`, is TCP/443."}, ctx())
    assert out["citedEventIds"] == [eid]
    assert STORE.notes[-1].refs[0].value == eid, "the citation became a real clickable reference"


def test_the_parameter_still_wins_when_it_is_given(pool):
    a, b = STORE.events[0].id, STORE.events[1].id
    out = REGISTRY["add_note"].fn({"text": f"mentions `{a}` only", "citedEventIds": [b]}, ctx())
    assert out["citedEventIds"] == [b]


def test_a_note_with_no_evidence_anywhere_is_still_refused(pool):
    with pytest.raises(ToolError) as exc:
        REGISTRY["add_note"].fn({"text": "The host looks compromised."}, ctx())
    assert "citedEventIds is required" in str(exc.value)
    assert "search_events" in str(exc.value), "the refusal has to say where real ids come from"


def test_an_invented_id_in_the_text_is_not_a_citation(pool):
    """The part that must never soften. A plausible-looking id that is not in the pool is not evidence."""
    with pytest.raises(ToolError):
        REGISTRY["add_note"].fn({"text": "Confirmed in `e999999` and `e999998`."}, ctx())


def test_an_invented_id_in_the_parameter_is_still_named(pool):
    eid = STORE.events[0].id
    with pytest.raises(ToolError) as exc:
        REGISTRY["add_note"].fn({"text": "x", "citedEventIds": [eid, "e999999"]}, ctx())
    assert "e999999" in str(exc.value)


def test_an_indicator_may_cite_from_its_note(pool):
    eid = STORE.events[0].id
    out = REGISTRY["add_ioc"].fn(
        {"kind": "ip", "value": "203.0.113.77", "note": f"seen in `{eid}`"}, ctx())
    assert out["ok"] is True
    assert eid in (STORE.manual_iocs[-1].get("citedEventIds") or [])


def test_an_indicator_with_nothing_behind_it_is_refused(pool):
    with pytest.raises(ToolError) as exc:
        REGISTRY["add_ioc"].fn({"kind": "ip", "value": "203.0.113.78", "note": "looks bad"}, ctx())
    assert "citedEventIds is required" in str(exc.value)
