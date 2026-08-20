"""A double-escaped line break must never reach the analyst as text.

Reported after a real investigation: *"posts are not being rendered clearly or nicely. the text is
large and it doesn't seem to be rendering the html, for example, I can see /n for new lines in the
post."* Both symptoms were one cause. The model had written its notes with the two characters
backslash-n where it meant a line break — a common double-escaping quirk of tool arguments — so every
note was stored as ONE line beginning `## Scope & verdict\\n\\n…`. The markdown renderer then matched
that single line against its heading rule and rendered the WHOLE note as a heading, which is why it
came out oversized as well as unformatted.

The repair is deliberately narrow, and the frontend renderer applies the identical rule at read time
(`utils/markdown.unescapeBreaks`) so notes already on disk display correctly without rewriting stored
evidence: only text with NO real line break of its own and at least two escape sequences is touched.
A backslash-n inside a quoted log line is DATA — rewriting it would corrupt what the note claims the
log said — and a model that double-escapes does it to the whole argument, so all-or-nothing is exactly
the signal.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.ai.tools import REGISTRY, RunContext, _prose
from app.main import app
from app.store import STORE
from tests.conftest import load_sample_case

ESCAPED = "## Scope & verdict\\n\\nTraffic to **66.218.84.137**\\n\\n| host | events |\\n|---|---|\\n| a | 2 |"


@pytest.fixture()
def client():
    with TestClient(app) as c:
        load_sample_case(c)
        yield c


def test_a_double_escaped_note_becomes_real_line_breaks():
    out = _prose(ESCAPED)
    assert "\\n" not in out
    assert out.startswith("## Scope & verdict\n\n")
    assert out.count("\n") == ESCAPED.count("\\n")


def test_text_that_already_has_line_breaks_is_left_exactly_alone():
    """The ambiguous case, and the one that would corrupt evidence. `C:\\new` is a PATH."""
    src = "Line one\nThe path in the log was C:\\newdir\\notes.txt\nLine three"
    assert _prose(src) == src


def test_a_single_escape_is_not_enough_to_rewrite_a_string():
    src = "the regex used was \\news+"
    assert _prose(src) == src


def test_the_query_dsl_is_never_touched():
    """`query` goes through `_s`, not `_prose`: the search DSL has its own backslash escape (`\\:`)."""
    from app.ai import tools

    src = 'host:web-1 AND raw:"10.0.0.9\\:3001"'
    assert tools._s(src) == src


def test_a_note_written_by_the_agent_is_stored_readable(client):
    ctx = RunContext(run_id="run-prose", model="test", max_writes=5)
    eid = STORE.events[0].id
    REGISTRY["add_note"].fn({"text": ESCAPED + f"\\n\\nSee `{eid}`.", "citedEventIds": [eid]}, ctx)
    note = STORE.notes[-1]
    assert "\\n" not in note.text, "the note went to disk with visible escape sequences in it"
    assert note.text.splitlines()[0] == "## Scope & verdict"
    assert "| host | events |" in note.text.splitlines()


def test_an_annotation_note_is_repaired_too(client):
    """The case TIMELINE is written with these, and it renders them as markdown."""
    ctx = RunContext(run_id="run-prose2", model="test", max_writes=5)
    eid = STORE.events[0].id
    REGISTRY["add_events_to_case"].fn({"eventIds": [eid]}, ctx)
    REGISTRY["annotate_case_event"].fn(
        {"eventId": eid, "labels": ["pivot"], "note": "First contact\\n\\n- from 10.0.0.101\\n- port 443"}, ctx)
    entry = STORE.case_set[eid]
    assert "\\n" not in entry.note
    assert entry.note.splitlines()[-1] == "- port 443"
