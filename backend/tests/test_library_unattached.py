"""Logs can be staged without a case, then linked to one later — and a case delete must not touch them.

Also covers the sibling report: after deleting every case there is no active case, so a pending id must
not answer as though it were one.
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


def test_upload_needs_no_case_at_all(c) -> None:
    _wipe_cases(c)
    assert c.get("/api/cases").json() == []
    assert STORE.pending is True

    r = c.post("/api/library/upload", files=[("files", ("staged.log", LOG, "text/plain"))])
    assert r.status_code == 200, r.text
    [f] = r.json()
    assert f["caseId"] == "" and f["displayName"] == "staged.log" and f["size"] == len(LOG)
    assert f["uploadedAt"]

    # staging must not have invented a case or ingested anything
    assert c.get("/api/cases").json() == []
    assert c.get("/api/case").json()["pending"] is True
    assert c.get("/api/case").json()["eventCount"] == 0

    # and the bytes live OUTSIDE the cases tree, so no case delete can reach them
    p = config.LIBRARY_DIR / f["fileName"]
    assert p.is_file()
    assert config.CASES_DIR.resolve() not in p.resolve().parents


def test_staged_file_is_listed_then_links_to_a_case_later(c) -> None:
    _wipe_cases(c)
    up = c.post("/api/library/upload", files=[("files", ("later.log", LOG, "text/plain"))]).json()[0]

    listed = [f for f in c.get("/api/library").json() if f["fileName"] == up["fileName"]]
    assert listed and listed[0]["caseId"] == "" and listed[0]["attached"] is False

    made = c.post("/api/cases", json={"name": "Linked later"})
    assert made.status_code == 200, made.text
    r = c.post("/api/library/attach", json={"items": [{"caseId": "", "fileName": up["fileName"]}]})
    assert r.status_code == 200, r.text
    assert c.get("/api/case").json()["eventCount"] > 0

    # the staged copy survives attaching, so it can be linked to a second case too
    assert (config.LIBRARY_DIR / up["fileName"]).is_file()
    second = c.post("/api/cases", json={"name": "Second"}).json()
    assert c.post("/api/library/attach", json={"items": [{"caseId": "", "fileName": up["fileName"]}]}).status_code == 200
    assert c.get("/api/case").json()["id"] == second["id"]
    assert c.get("/api/case").json()["eventCount"] > 0


def test_deleting_every_case_leaves_unattached_files_and_takes_attached_ones(c) -> None:
    """A file never filed into a case survives every delete — the library is case-less. A file the case
    had ATTACHED leaves with the case: it is in the trash entry, not in the library any more, so its
    events (and their detections) do not come straight back into the pool on the next library load.
    That resurrection was reported as "deleting a case does not clear its anomalies" — see
    tests/test_case_delete_clears_derived.py."""
    _wipe_cases(c)
    up = c.post("/api/library/upload", files=[("files", ("survivor.log", LOG, "text/plain"))]).json()[0]
    loose = c.post("/api/library/upload", files=[("files", ("loose.log", LOG, "text/plain"))]).json()[0]
    c.post("/api/cases", json={"name": "Doomed"})
    c.post("/api/library/attach", json={"items": [{"caseId": "", "fileName": up["fileName"]}]})

    _wipe_cases(c)
    assert c.get("/api/cases").json() == []
    names = [f["fileName"] for f in c.get("/api/library").json()]
    assert loose["fileName"] in names and (config.LIBRARY_DIR / loose["fileName"]).is_file()
    assert up["fileName"] not in names and not (config.LIBRARY_DIR / up["fileName"]).is_file()
    trash = c.get("/api/cases/trash").json()
    assert any(t["name"] == "Doomed" for t in trash), "the attached file's bytes live in the trash entry now"


def test_prune_never_touches_unattached_files(c) -> None:
    up = c.post("/api/library/upload", files=[("files", ("keepme.log", LOG, "text/plain"))]).json()[0]
    preview = c.get("/api/library/prune").json()
    assert all(i["fileName"] != up["fileName"] for i in preview["files"])
    c.post("/api/library/prune?confirm=true")
    assert (config.LIBRARY_DIR / up["fileName"]).is_file()


def test_unattached_delete_and_traversal_guard(c) -> None:
    up = c.post("/api/library/upload", files=[("files", ("gone.log", LOG, "text/plain"))]).json()[0]
    assert c.delete(f"/api/library/unattached/{up['fileName']}").status_code == 200
    assert not (config.LIBRARY_DIR / up["fileName"]).is_file()
    assert c.delete(f"/api/library/unattached/{up['fileName']}").status_code == 404
    # a traversal attempt must not escape the library. 405 = the encoded slashes stop it matching the
    # route at all, which is just as good as the explicit guard — what matters is the file survives.
    assert c.delete("/api/library/unattached/..%2F..%2Fcases%2Findex.json").status_code in (400, 404, 405)
    assert config.CASES_DIR.joinpath("index.json").is_file()


def test_attaching_a_missing_staged_file_404s(c) -> None:
    r = c.post("/api/library/attach", json={"items": [{"caseId": "", "fileName": "deadbeef_nope.log"}]})
    assert r.status_code == 404


def test_no_active_case_after_deleting_them_all(c) -> None:
    """The reported bug: an 'active case' still showed once every case was gone."""
    _wipe_cases(c)
    assert c.get("/api/cases").json() == []

    case = c.get("/api/case").json()
    assert case["pending"] is True, "the UI keys 'no active case' off this flag"
    assert case["eventCount"] == 0 and case["sources"] == []

    # the reserved id is not a case, so it must not answer as one
    assert c.get(f"/api/cases/{case['id']}").status_code == 404
    assert c.get(f"/api/cases/{case['id']}/notes").status_code == 404


def test_creating_a_case_after_the_wipe_clears_pending(c) -> None:
    _wipe_cases(c)
    made = c.post("/api/cases", json={"name": "Fresh start"}).json()
    active = c.get("/api/case").json()
    assert active["pending"] is False and active["id"] == made["id"]
    assert c.get(f"/api/cases/{made['id']}").status_code == 200
