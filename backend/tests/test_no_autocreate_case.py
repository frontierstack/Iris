"""Uploading a log must never create a case — but it must still be analysable.

The analyst's report: with no case at all, dropping a file on the Sources screen silently conjured
"Untitled case" — a case nobody asked for, holding evidence that was never triaged into one. So
POST /api/sources with no active case stages the bytes in the library (a sibling of cases/) and leaves
the pending id untouched: nothing is written under cases/ and /api/cases stays empty.

What it is NOT is inert. A case is a curation layer, not a prerequisite for analysis, so the staged file
is parsed into the workspace pool and is immediately searchable. The case-scoped fields of /api/case
(`sources`, `eventCount`) stay empty because there is no case; the pool fields (`librarySources`,
`poolEventCount`) carry the ingest.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import cases, config
from app.main import app
from app.store import STORE

LOG = b"Jan 01 00:00:01 host sshd[1]: Accepted password for alice from 10.0.0.5 port 22 ssh2\n"


@pytest.fixture()
def c():
    with TestClient(app) as client:
        yield client


def _wipe_cases(c) -> None:
    for cid in list(cases.case_ids()):
        c.delete(f"/api/cases/{cid}")


def test_uploading_with_no_case_stages_instead_of_creating_one(c) -> None:
    _wipe_cases(c)
    assert c.get("/api/cases").json() == []
    pending_id = c.get("/api/case").json()["id"]
    before = set(cases.case_ids())

    r = c.post("/api/sources", files=[("files", ("orphan.log", LOG, "text/plain"))])

    # (a) it succeeds — the bytes are never rejected, only redirected to the case-less pool
    assert r.status_code == 200, r.text
    assert r.headers.get("X-Iris-Staged-To-Library") == "1"
    [src] = r.json()
    assert src["origin"] == "library" and src["events"] > 0

    # (b)+(c) still no case: none listed, none on disk, and the reserved id is untouched
    assert c.get("/api/cases").json() == []
    assert set(cases.case_ids()) == before == set()
    assert not config.case_dir(pending_id).exists(), "the upload materialised the pending case"
    assert not config.case_path(pending_id).exists()
    active = c.get("/api/case").json()
    assert active["pending"] is True and active["id"] == pending_id
    assert active["eventCount"] == 0 and active["sources"] == [], "there is no case, so nothing is IN one"
    assert STORE.pending is True

    # (b2) …and yet it is analysable: the pool carries it and search finds it with zero cases on disk
    assert active["poolEventCount"] > 0
    assert "orphan.log" in [s["file"] for s in active["librarySources"]]
    assert c.get("/api/events", params={"q": "alice"}).json()["total"] > 0

    # (d) the bytes are in the library, listed as unattached, and attachable once a case exists
    staged = [f for f in c.get("/api/library").json() if f["displayName"] == "orphan.log"]
    assert staged, "the upload was lost — it is in neither a case nor the library"
    entry = staged[0]
    assert entry["caseId"] == "" and entry["size"] == len(LOG)
    assert (config.LIBRARY_DIR / entry["fileName"]).read_bytes() == LOG

    made = c.post("/api/cases", json={"name": "Created deliberately"}).json()
    assert c.post("/api/library/attach",
                  json={"items": [{"caseId": "", "fileName": entry["fileName"]}]}).status_code == 200
    now = c.get("/api/case").json()
    assert now["id"] == made["id"] and now["pending"] is False and now["eventCount"] > 0


def test_the_pending_case_stays_invisible_after_an_upload(c) -> None:
    """Every case-scoped view must keep rendering "no case", not a phantom one."""
    _wipe_cases(c)
    c.post("/api/sources", files=[("files", ("ghost.log", LOG, "text/plain"))])
    pending_id = c.get("/api/case").json()["id"]

    assert c.get("/api/cases").json() == []
    assert c.get(f"/api/cases/{pending_id}").status_code == 404
    assert c.get(f"/api/cases/{pending_id}/notes").status_code == 404


def test_upload_still_ingests_normally_when_a_case_is_active(c) -> None:
    _wipe_cases(c)
    made = c.post("/api/cases", json={"name": "Real case"}).json()
    r = c.post("/api/sources", files=[("files", ("real.log", LOG, "text/plain"))])
    assert r.status_code == 200 and len(r.json()) == 1
    assert "X-Iris-Staged-To-Library" not in r.headers
    assert c.get("/api/case").json()["eventCount"] > 0
    assert config.case_path(made["id"]).is_file()
