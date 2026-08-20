"""Multi-case store: create/activate/switch/delete + legacy migration."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app import config
from tests.conftest import drain_enrichment
from app.main import app


@pytest.fixture()
def client():
    with TestClient(app) as c:
        # deleting the last case now leaves NO case at all, so re-establish a baseline for tests
        # that assume one exists (the delete-everything tests assert the empty state themselves)
        if not c.get("/api/cases").json():
            c.post("/api/cases", json={"name": "Untitled case"})
        c.post("/api/case/reset")
        yield c


CSV_A = b"timestamp,host,message\n2026-08-11T03:14:47Z,web-1,alpha one\n2026-08-11T03:15:00Z,web-2,alpha two\n"
CSV_B = b"timestamp,host,message\n2026-08-12T10:00:00Z,db-1,bravo one\n"


def _active(c):
    return next(x for x in c.get("/api/cases").json() if x["active"])


def test_cases_list_and_create(client):
    rows = client.get("/api/cases").json()
    assert any(r["active"] for r in rows)
    r = client.post("/api/cases", json={"name": "Second case", "analyst": "Bob"})
    assert r.status_code == 200
    body = r.json()
    assert body["active"] is True and body["name"] == "Second case" and body["analyst"] == "Bob"
    case = client.get("/api/case").json()
    assert case["id"] == body["id"] and case["name"] == "Second case"
    # cleanup
    client.delete(f"/api/cases/{body['id']}")


def test_switch_preserves_both_cases(client):
    # Every count here is a PHASE-2 count (parsed rows), and an upload returns after phase 1 (raw
    # lines — one more, because the CSV header is a line). Asserting straight after the POST was a
    # race on the enrichment worker: it passed when the worker won and read 3-instead-of-2 when it
    # did not, which is what TODO recorded as an intermittent failure. Waiting for the queue is not
    # weakening the test — the assertions are unchanged; it is the difference between testing the
    # parse and testing the scheduler.
    a = _active(client)["id"]
    client.post("/api/sources", files={"files": ("a.csv", CSV_A, "text/csv")})
    drain_enrichment()
    assert client.get("/api/case").json()["eventCount"] == 2
    b = client.post("/api/cases", json={"name": "Case B"}).json()["id"]
    assert client.get("/api/case").json()["eventCount"] == 0
    client.post("/api/sources", files={"files": ("b.csv", CSV_B, "text/csv")})
    drain_enrichment()
    assert client.get("/api/case").json()["eventCount"] == 1
    # first case's files must still exist on disk
    assert any(config.upload_dir(a).iterdir())
    # summaries for the non-active case come from its case.json
    rows = {r["id"]: r for r in client.get("/api/cases").json()}
    assert rows[a]["events"] == 2 and rows[a]["sources"] == 1 and rows[a]["active"] is False
    assert rows[a]["sizeBytes"] > 0
    assert rows[b]["events"] == 1 and rows[b]["active"] is True
    # switch back: case A restored from disk
    r = client.post(f"/api/cases/{a}/activate")
    assert r.status_code == 200 and r.json()["eventCount"] == 2
    # and B survived on disk
    rows = {r["id"]: r for r in client.get("/api/cases").json()}
    assert rows[b]["events"] == 1 and rows[b]["active"] is False
    client.delete(f"/api/cases/{b}")


def test_reset_only_resets_active(client):
    a = _active(client)["id"]
    client.post("/api/sources", files={"files": ("a.csv", CSV_A, "text/csv")})
    b = client.post("/api/cases", json={"name": "Other"}).json()["id"]
    client.post("/api/sources", files={"files": ("b.csv", CSV_B, "text/csv")})
    client.post("/api/case/reset")
    assert client.get("/api/case").json()["eventCount"] == 0
    assert not any(f.is_file() for f in config.upload_dir(b).iterdir())
    rows = {r["id"]: r for r in client.get("/api/cases").json()}
    assert rows[a]["events"] == 2  # untouched
    client.post(f"/api/cases/{a}/activate")
    assert client.get("/api/case").json()["eventCount"] == 2
    client.delete(f"/api/cases/{b}")


def test_patch_non_active_case(client):
    a = _active(client)["id"]
    b = client.post("/api/cases", json={"name": "B"}).json()["id"]
    r = client.patch(f"/api/cases/{a}", json={"name": "Renamed A"})
    assert r.status_code == 200 and r.json()["name"] == "Renamed A"
    client.post(f"/api/cases/{a}/activate")
    assert client.get("/api/case").json()["name"] == "Renamed A"
    client.delete(f"/api/cases/{b}")


def test_delete_active_activates_remaining(client):
    a = _active(client)["id"]
    client.post("/api/sources", files={"files": ("a.csv", CSV_A, "text/csv")})
    b = client.post("/api/cases", json={"name": "Doomed"}).json()["id"]
    assert _active(client)["id"] == b
    r = client.delete(f"/api/cases/{b}")
    assert r.json()["ok"] is True
    assert not config.case_dir(b).exists()
    act = _active(client)
    assert act["id"] == a
    assert client.get("/api/case").json()["eventCount"] == 2




def test_legacy_migration(tmp_path, monkeypatch):
    from app import cases as cases_mod
    from app.store import STORE
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "CASES_DIR", tmp_path / "cases")
    monkeypatch.setattr(config, "CASES_INDEX", tmp_path / "cases" / "index.json")
    monkeypatch.setattr(config, "LEGACY_UPLOAD_DIR", tmp_path / "uploads")
    monkeypatch.setattr(config, "LEGACY_CASE_PATH", tmp_path / "case.json")
    # startup() also rebuilds the case-less library pool, so that has to point at tmp_path too or the
    # real test dir's staged files would be counted into this case's event total
    monkeypatch.setattr(config, "LIBRARY_DIR", tmp_path / "library")
    monkeypatch.setattr(config, "LIBRARY_INDEX", tmp_path / "library" / "index.json")
    up = tmp_path / "uploads"
    up.mkdir()
    (up / "s1_a.csv").write_bytes(CSV_A)
    (tmp_path / "case.json").write_text(json.dumps({
        "case_id": "CASE-0001", "name": "Legacy case", "analyst": "Old Analyst",
        "created_at": "2026-08-01T00:00:00+00:00", "pinned": [],
        "sources": [{"id": "s1", "file": "a.csv", "path": str(up / "s1_a.csv"), "mapping": None, "delimiter": None}],
    }), encoding="utf-8")
    try:
        active = cases_mod.startup()
        assert active == "CASE-0001"
        assert not (tmp_path / "case.json").exists()
        assert not up.exists()
        assert (tmp_path / "cases" / "CASE-0001" / "uploads" / "s1_a.csv").is_file()
        assert STORE.name == "Legacy case"
        assert len(STORE.events) == 2
        assert json.loads((tmp_path / "cases" / "index.json").read_text())["active"] == "CASE-0001"
    finally:
        monkeypatch.undo()
        cases_mod.startup()  # restore the real test data dir state for other tests


def test_deleted_ids_are_never_handed_out_again(client):
    """Regression: ids were reused, so deleting your only case recreated CASE-0001 and the Cases page
    looked unchanged — the delete read as broken even though it had really happened."""
    before = client.get("/api/cases").json()
    deleted = {c["id"] for c in before}
    for c in before:
        client.delete(f"/api/cases/{c['id']}")

    assert client.get("/api/cases").json() == []
    fresh = client.post("/api/cases", json={"name": "next one"}).json()
    assert fresh["id"] not in deleted, "a deleted id must never be handed out again"


def test_ids_are_never_reused_after_delete(client):
    a = client.post("/api/cases", json={"name": "a"}).json()
    client.delete(f"/api/cases/{a['id']}")
    b = client.post("/api/cases", json={"name": "b"}).json()
    assert b["id"] != a["id"], "a deleted id must never come back"


def test_deleting_the_last_case_leaves_none(client):
    """Deleting the last case must NOT invent a replacement — the Cases list goes empty.

    It used to auto-create "Untitled case", so a delete looked like it had opened a blank case
    the analyst never asked for.
    """
    for c in client.get("/api/cases").json():
        client.delete(f"/api/cases/{c['id']}")

    assert client.get("/api/cases").json() == [], "no case should exist after deleting them all"

    # the app still answers — it holds a reserved-but-unwritten case so every screen can render
    case = client.get("/api/case").json()
    assert case["pending"] is True
    assert case["eventCount"] == 0 and case["sources"] == []

    # and nothing was written to disk for it
    from app import config
    assert not config.case_path(case["id"]).exists(), "a pending case must not create case.json"


def test_a_pending_case_materialises_on_first_real_write(client):
    for c in client.get("/api/cases").json():
        client.delete(f"/api/cases/{c['id']}")
    pending_id = client.get("/api/case").json()["id"]
    assert client.get("/api/cases").json() == []

    # naming it is enough to bring it into existence
    client.patch("/api/case", json={"name": "Real investigation"})
    listed = client.get("/api/cases").json()
    assert [c["id"] for c in listed] == [pending_id]
    assert listed[0]["name"] == "Real investigation"
    assert client.get("/api/case").json()["pending"] is False


def test_prune_previews_before_it_deletes(client, tmp_path):
    """Cleanup must be a dry run first: GET reports, POST without confirm refuses."""
    from app import config

    # an upload nothing references — exactly what accumulates after a reset or re-ingest
    up = config.upload_dir(client.get("/api/case").json()["id"])
    up.mkdir(parents=True, exist_ok=True)
    stray = up / "deadbeef_orphan.log"
    stray.write_bytes(b"unreferenced bytes\n")

    preview = client.get("/api/library/prune").json()
    assert preview["deleted"] is False
    assert any(f["fileName"] == stray.name for f in preview["files"])
    assert preview["bytes"] >= stray.stat().st_size
    assert stray.is_file(), "a preview must not touch anything"

    assert client.post("/api/library/prune").status_code == 400, "deleting requires confirm=true"
    assert stray.is_file()

    done = client.post("/api/library/prune?confirm=true").json()
    assert done["deleted"] is True
    assert not stray.exists()


def test_prune_leaves_referenced_uploads_alone(client):
    from app import config

    client.post("/api/sources", files=[("files", ("keep.csv", CSV_A, "text/csv"))])
    cid = client.get("/api/case").json()["id"]
    before = {p.name for p in config.upload_dir(cid).iterdir() if p.is_file()}
    assert before, "the ingest should have written a file"

    client.post("/api/library/prune?confirm=true")
    after = {p.name for p in config.upload_dir(cid).iterdir() if p.is_file()}
    assert after == before, "a file a case still references must never be pruned"
