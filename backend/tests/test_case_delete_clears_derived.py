"""Deleting a case takes its evidence OUT of every derived view — anomalies, graph findings, the pool count.

Reported: *"when deleting a case, associated Anomalies detections / graph detections etc do not clear"*.
The derived caches were keyed correctly; what came back was the EVIDENCE. Attaching a staged library
file to a case leaves the staged copy in `library/`, and once the case was deleted (its uploads moved to
the trash, its sources cleared from memory) the next `load_library()` found that copy with no case
claiming it and parsed it straight back in as a library source — detections and all. The delete now
releases the staged copy (`cases._release_library_copies`); the trash entry holds the bytes and a
restore brings them back into the restored case.
"""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from app.main import app
from tests.conftest import load_sample_case

LOG = b"".join(f"Jan 01 00:00:{i:02d} host sshd[1]: Failed password for root from 10.0.0.5 port 22 ssh2\n".encode()
               for i in range(40))


@pytest.fixture()
def c():
    with TestClient(app) as client:
        yield client


def _anoms(c):
    r = {}
    for _ in range(200):
        r = c.get("/api/anomalies").json()
        if (r.get("status") or {}).get("state") != "building":
            return r
        time.sleep(0.05)
    return r


def _baseline(c) -> tuple[int, int]:
    """(pool events, anomalies) before the test adds anything — other tests may leave library files behind,
    and those legitimately survive every case delete."""
    return c.get("/api/case").json()["poolEventCount"], _anoms(c)["total"]


def test_deleting_the_last_case_clears_anomalies_and_search(c):
    pool0, anom0 = _baseline(c)
    hits0 = c.get("/api/events", params={"q": "sshd", "limit": 5}).json()["total"]
    load_sample_case(c)
    case = c.get("/api/case").json()
    assert case["poolEventCount"] > pool0 and _anoms(c)["total"] > anom0
    assert c.delete(f"/api/cases/{case['id']}").status_code == 200
    after = c.get("/api/case").json()
    assert after["pending"] and after["poolEventCount"] == pool0
    assert _anoms(c)["total"] == anom0
    assert c.get("/api/graph/anomalies").json()["findings"] == []
    assert c.get("/api/events", params={"q": "sshd", "limit": 5}).json()["total"] == hits0


def test_deleting_a_case_while_another_remains(c):
    pool0, anom0 = _baseline(c)
    c.post("/api/cases", json={"name": "other"})
    cid = c.post("/api/cases", json={"name": "victim"}).json()["id"]
    assert c.post("/api/sources", files=[("files", ("victim.log", LOG, "text/plain"))]).status_code == 200
    assert _anoms(c)["total"] > anom0
    assert c.delete(f"/api/cases/{cid}").status_code == 200
    time.sleep(0.5)
    assert c.get("/api/case").json()["poolEventCount"] == pool0
    assert _anoms(c)["total"] == anom0


def test_an_attached_library_file_leaves_with_its_case_and_comes_back_on_restore(c):
    pool0, anom0 = _baseline(c)
    c.post("/api/cases", json={"name": "other2"})
    cid = c.post("/api/cases", json={"name": "victim2"}).json()["id"]
    up = c.post("/api/library/upload", files=[("files", ("staged.log", LOG, "text/plain"))])
    assert up.status_code == 200, up.text
    name = up.json()[0]["fileName"]
    r = c.post("/api/library/attach", json={"items": [{"caseId": "", "fileName": name}]})
    assert r.status_code == 200, r.text
    assert c.get("/api/case").json()["eventCount"] == 40
    assert _anoms(c)["total"] > anom0

    assert c.delete(f"/api/cases/{cid}").status_code == 200
    time.sleep(0.5)
    after = c.get("/api/case").json()
    assert after["poolEventCount"] == pool0, "the attached file came back through the library"
    assert _anoms(c)["total"] == anom0
    # the staged copy is gone from the library: the trash entry is its home now
    assert not any(f["fileName"] == name for f in c.get("/api/library").json())

    entry = next(t["entry"] for t in c.get("/api/cases/trash").json() if t["caseId"] == cid)
    assert c.post(f"/api/cases/trash/{entry}/restore").status_code == 200
    assert c.post(f"/api/cases/{cid}/activate").status_code == 200
    time.sleep(0.5)
    restored = c.get("/api/case").json()
    assert restored["id"] == cid and restored["eventCount"] == 40
    assert _anoms(c)["total"] > anom0
