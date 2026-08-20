"""What a case HOLDS — the numbers the delete confirmation shows.

The analyst was about to delete a case and the dialog said `0 uploaded source files, 0 parsed events,
0 events in the case set, 0 B on disk`. Every one of those was true and the summary was still wrong:
the case held four AI-written notes and a set of indicators. The workspace is case-OPTIONAL, so a case
whose evidence stayed in the library has no sources, no events and no bytes of its own while holding
the entire investigation — and a confirmation dialog that counts only evidence tells the analyst there
is nothing to lose.

So `CaseSummary` carries the curation counts too, for the active case and for one read back off disk,
and `GET /api/cases/trash` reports them as well (what would come BACK on a restore).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.store import STORE

CSV = b"timestamp,host,message\n2026-08-19T03:14:47Z,web-1,Failed password for root\n"


@pytest.fixture()
def client():
    with TestClient(app) as c:
        STORE.clear_all()
        c.post("/api/cases", json={"name": "Curation only"})
        yield c
        STORE.clear_all()


def _active(c) -> dict:
    return next(x for x in c.get("/api/cases").json() if x["active"])


def test_a_case_with_no_files_still_reports_what_it_holds(client):
    """The reported bug, in the shape it happened: nothing uploaded, everything curated."""
    client.post("/api/sources", files={"files": ("a.csv", CSV, "text/csv")})
    eid = STORE.events[0].id
    cid = _active(client)["id"]
    assert client.post(f"/api/case-set/{eid}", json={"labels": ["pivot"], "note": ""}).status_code == 200
    assert client.post(f"/api/cases/{cid}/notes", json={"text": "The narrative", "refs": []}).status_code == 200
    assert client.post("/api/iocs", json={"kind": "ip", "value": "45.83.140.22", "note": "c2",
                                          "citedEventIds": [eid]}).status_code == 200

    row = _active(client)
    assert row["caseSet"] == 1
    assert row["noteCount"] == 1, "a note is part of what deleting this case destroys"
    assert row["iocCount"] == 1, "an indicator is too"
    assert row["graphLinkCount"] == 0


def test_the_counts_survive_a_read_from_disk(client):
    """The dialog is usually opened on a case that is NOT active, i.e. read back out of case.json."""
    eid_case = _active(client)["id"]
    client.post(f"/api/cases/{eid_case}/notes", json={"text": "note one", "refs": []})
    client.post(f"/api/cases/{eid_case}/notes", json={"text": "note two", "refs": []})
    other = client.post("/api/cases", json={"name": "Somewhere else"}).json()["id"]

    row = next(x for x in client.get("/api/cases").json() if x["id"] == eid_case)
    assert row["active"] is False
    assert row["noteCount"] == 2
    client.delete(f"/api/cases/{other}")


def test_an_empty_case_reports_zeroes_and_that_is_the_truth(client):
    row = _active(client)
    assert (row["sources"], row["events"], row["caseSet"]) == (0, 0, 0)
    assert (row["noteCount"], row["iocCount"], row["graphLinkCount"]) == (0, 0, 0)


def test_the_trash_row_says_what_would_come_back(client):
    cid = _active(client)["id"]
    client.post(f"/api/cases/{cid}/notes", json={"text": "worth restoring", "refs": []})
    client.delete(f"/api/cases/{cid}")

    entry = next(t for t in client.get("/api/cases/trash").json() if t["caseId"] == cid)
    assert entry["noteCount"] == 1, "a restore brings the notes back; the row has to say so"
    assert entry["iocCount"] == 0 and entry["caseSet"] == 0
