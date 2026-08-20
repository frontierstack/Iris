"""A report cites the FILE a line came from, not what it was parsed as.

The analyst: *"What is noted as a reference is the source field, but it's not correct for referencing
to a log."* `Event.source` is the parser family (nginx, delimited, jsonl, syslog) and several files
share one, so a timeline entry or a report row that names it points at nothing. The reference has to be
`Event.file` — that is what the analyst opens, and a report is read away from Iris by someone who has
to find the original log.

The parser is not lost, it just stops being the reference: the timeline keeps it as a hover
(`file · parsed as source`), which is the same shape Search uses.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.store import STORE
from tests.conftest import load_sample_case


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        load_sample_case(c)
        eid = STORE.events[0].id
        c.post(f"/api/case-set/{eid}", json={"labels": ["pivot"], "note": ""})
        yield c


def test_the_markdown_report_names_the_file(client):
    md = client.get("/api/report/export?format=md").text
    assert "| ts | file |" in md, "the case-set table has to be headed by the file"
    e = STORE.events[0]
    assert e.file and e.file in md
    # ...and the parser family is not what identifies the row
    header = next(line for line in md.splitlines() if line.startswith("| ts |"))
    assert "source" not in header


def test_the_json_report_still_carries_both(client):
    """The API keeps every field — this is a presentation rule, not a data change. An agent or a
    downstream tool may legitimately want the parser."""
    body = client.get("/api/report").json()
    row = body["caseSet"][0]
    assert row["file"] and row["source"]
