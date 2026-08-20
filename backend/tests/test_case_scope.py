"""A case is a CURATION layer: it starts empty and only ever holds what the analyst put in it.

The bug this locks down, reported verbatim: "When I created a case, it automatically assumed all logs
into the case when it should not do that. I will choose what logs become in scope for a case."

Two halves:
  * creating a case must attach nothing — no sources, no case set — and must leave the workspace pool
    exactly as it was, including the event totals the case reports for itself (Store.snapshot() used to
    put `len(pool)` in CaseSnapshot.events, so the case detail screen displayed every ingested log as
    the new case's own);
  * choosing scope has to work in BOTH directions: attach a pool source explicitly, take it back out
    again, with no event ever counted twice and nothing dropped out of search.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import config
from app.main import app
from app.store import STORE

NGINX = b"""198.51.100.12 - - [11/Aug/2026:02:00:11 +0000] "GET /a HTTP/1.1" 200 12 "-" "curl/8"
198.51.100.13 - - [11/Aug/2026:02:00:12 +0000] "GET /b HTTP/1.1" 404 12 "-" "curl/8"
198.51.100.14 - - [11/Aug/2026:02:00:13 +0000] "GET /c HTTP/1.1" 500 12 "-" "curl/8"
"""
SYSLOG = b"""Aug 11 02:00:20 bastion-1 sshd[2211]: Failed password for root from 203.0.113.9 port 40 ssh2
Aug 11 02:00:21 bastion-1 sshd[2211]: Accepted password for ops from 203.0.113.9 port 41 ssh2
"""


@pytest.fixture()
def client():
    with TestClient(app) as c:
        # start from a clean workspace: no cases, no library, no pool
        c.post("/api/admin/clear-all", json={"resetSettings": False})
        yield c
        c.post("/api/admin/clear-all", json={"resetSettings": False})


def _stage(client, name: str, data: bytes) -> str:
    r = client.post("/api/library/upload", files={"files": (name, data, "text/plain")})
    assert r.status_code == 200, r.text
    return r.json()[0]["fileName"]


def test_creating_a_case_absorbs_nothing(client):
    """Files staged with no case stay in the pool; a new case is empty and says so."""
    _stage(client, "edge.log", NGINX)
    _stage(client, "bastion.log", SYSLOG)
    pool = client.get("/api/case").json()
    assert pool["poolEventCount"] == 5
    assert len(pool["librarySources"]) == 2 and pool["sources"] == []

    cid = client.post("/api/cases", json={"name": "Probe"}).json()["id"]

    # the case itself
    summary = client.get("/api/cases").json()[0]
    assert summary["sources"] == 0 and summary["events"] == 0 and summary["caseSet"] == 0
    detail = client.get(f"/api/cases/{cid}").json()
    assert detail["sourceList"] == []
    assert detail["caseSet"] == 0
    # the whole point: the case's own event total is 0, NOT the pool's 5
    assert detail["snapshot"]["events"] == 0
    assert detail["snapshot"]["sev"] == {} and detail["snapshot"]["range"] is None

    # the pool is untouched — analysis still sees everything
    after = client.get("/api/case").json()
    assert after["poolEventCount"] == 5
    assert [s["file"] for s in after["librarySources"]] == [s["file"] for s in pool["librarySources"]]
    assert after["sources"] == [] and after["eventCount"] == 0
    assert client.get("/api/events").json()["total"] == 5

    # and the case's own view is EMPTY, not the pool
    assert client.get("/api/events?scope=case").json()["total"] == 0


def test_attach_then_detach_a_pool_source(client):
    """Scope is chosen explicitly in both directions, and never duplicates or loses events."""
    staged = _stage(client, "edge.log", NGINX)
    _stage(client, "bastion.log", SYSLOG)
    cid = client.post("/api/cases", json={"name": "Scoped"}).json()["id"]

    ids_before = [r["id"] for r in client.get("/api/events?limit=500").json()["rows"]]

    # --- attach: the case now covers exactly one of the two staged files
    added = client.post("/api/library/attach", json={"items": [{"caseId": "", "fileName": staged}]})
    assert added.status_code == 200, added.text
    sid = added.json()[0]["id"]

    c = client.get("/api/case").json()
    assert [s["file"] for s in c["sources"]] == ["edge.log"]
    assert c["eventCount"] == 3
    assert c["poolEventCount"] == 5                      # no re-parse, no double count
    assert [s["file"] for s in c["librarySources"]] == ["bastion.log"]
    assert [r["id"] for r in client.get("/api/events?limit=500").json()["rows"]] == ids_before

    d = client.get(f"/api/cases/{cid}").json()
    assert [s["file"] for s in d["sourceList"]] == ["edge.log"]
    assert d["sourceList"][0]["fromLibrary"] is True     # detachable: the staged copy is still there
    assert d["snapshot"]["events"] == 3                  # the case's own events, not the pool's 5

    # attaching the same file twice is a no-op, not a second copy
    client.post("/api/library/attach", json={"items": [{"caseId": "", "fileName": staged}]})
    assert client.get("/api/case").json()["poolEventCount"] == 5
    assert client.get("/api/case").json()["eventCount"] == 3

    # --- detach: back out of the case, still in the pool
    out = client.post(f"/api/cases/{cid}/sources/{sid}/detach")
    assert out.status_code == 200, out.text
    assert [s["file"] for s in out.json()] == ["edge.log"]

    c = client.get("/api/case").json()
    assert c["sources"] == [] and c["eventCount"] == 0
    assert c["poolEventCount"] == 5                       # nothing was deleted
    assert sorted(s["file"] for s in c["librarySources"]) == ["bastion.log", "edge.log"]
    assert [r["id"] for r in client.get("/api/events?limit=500").json()["rows"]] == ids_before
    assert (config.LIBRARY_DIR / staged).is_file()        # the staged copy is what survives
    assert not (config.upload_dir(cid) / staged).exists()  # the case's copy is gone with the claim

    d = client.get(f"/api/cases/{cid}").json()
    assert d["sourceList"] == [] and d["snapshot"]["events"] == 0


def test_pool_files_are_offerable_to_a_new_case(client):
    """The Add-sources picker must offer the pool. `inActiveCase` is about the CASE, not the pool.

    It was derived from every source in STORE.sources, so each staged file — which is also a pool
    source — came back `inActiveCase: true`: the drawer said "every uploaded file is already in this
    case" and disabled every row, which is both wrong and exactly what "the case absorbed all my logs"
    looks like from the UI.
    """
    staged = _stage(client, "edge.log", NGINX)
    _stage(client, "bastion.log", SYSLOG)
    cid = client.post("/api/cases", json={"name": "Picker"}).json()["id"]

    lib = client.get("/api/library").json()
    assert len(lib) == 2
    assert all(f["inActiveCase"] is False for f in lib), lib
    assert all(f["caseId"] == "" for f in lib)

    client.post("/api/library/attach", json={"items": [{"caseId": "", "fileName": staged}]})
    by_name = {f["displayName"]: f for f in client.get("/api/library").json()}
    assert by_name["edge.log"]["inActiveCase"] is True     # now genuinely in the case
    assert by_name["bastion.log"]["inActiveCase"] is False  # still only in the pool

    sid = client.get(f"/api/cases/{cid}").json()["sourceList"][0]["id"]
    client.post(f"/api/cases/{cid}/sources/{sid}/detach")
    assert all(f["inActiveCase"] is False for f in client.get("/api/library").json())


def test_a_file_uploaded_into_the_case_is_staged_on_its_way_out(client):
    """Taking a source out of a case must never require deleting the evidence.

    A file uploaded straight into the case has no library copy to fall back to, and refusing there left
    "remove from case" and "destroy the file" as the same button. The bytes are staged into the library
    first, so the source becomes case-less exactly like any other library file: same events, same ids,
    still searchable, and attachable to a different case afterwards.
    """
    from app import config

    cid = client.post("/api/cases", json={"name": "Direct"}).json()["id"]
    up = client.post("/api/sources", files={"files": ("direct.log", NGINX, "text/plain")})
    assert up.status_code == 200, up.text
    sid = up.json()[0]["id"]
    assert STORE.source_origin.get(sid) == "case"
    ids_before = [e.id for e in STORE.events if e.sourceId == sid]

    r = client.post(f"/api/cases/{cid}/sources/{sid}/detach")
    assert r.status_code == 200, r.text
    assert STORE.source_origin.get(sid) == "library"
    # the case no longer claims it, the pool still has every event, and no id moved
    assert client.get(f"/api/cases/{cid}").json()["sourceList"] == []
    assert client.get("/api/case").json()["eventCount"] == 0
    assert client.get("/api/case").json()["poolEventCount"] == 3
    assert [e.id for e in STORE.events if e.sourceId == sid] == ids_before

    # it is a real staged file now: on disk, in the index under its ORIGINAL name, and attachable again
    staged = STORE.source_library.get(sid)
    assert staged and (config.LIBRARY_DIR / staged).is_file()
    lib = {f["displayName"]: f for f in client.get("/api/library").json()}
    assert "direct.log" in lib and lib["direct.log"]["caseId"] == ""
    back = client.post("/api/library/attach", json={"items": [{"caseId": "", "fileName": staged}]})
    assert back.status_code == 200 and client.get("/api/case").json()["eventCount"] == 3


def test_switching_cases_leaves_the_pool_alone(client):
    """The pool belongs to the workspace: creating a second case and switching must not move anything."""
    _stage(client, "edge.log", NGINX)
    a = client.post("/api/cases", json={"name": "A"}).json()["id"]
    b = client.post("/api/cases", json={"name": "B"}).json()["id"]
    for cid in (a, b, a):
        client.post(f"/api/cases/{cid}/activate")
        c = client.get("/api/case").json()
        assert c["poolEventCount"] == 3
        assert c["sources"] == [] and c["eventCount"] == 0
        assert client.get(f"/api/cases/{cid}").json()["snapshot"]["events"] == 0
