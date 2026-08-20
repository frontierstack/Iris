"""Deleting a case must be recoverable.

A case folder holds the ONLY copy of its uploads, so the old rmtree made a delete an unrecoverable loss
of evidence — from a misclick, a bug, or a script pointed at the wrong data directory. Deletes now move
the folder aside instead.
"""
from __future__ import annotations

import threading

import pytest
from fastapi.testclient import TestClient

from app import cases, config
from app.main import app

LOG = b"Jan 01 00:00:01 host sshd[1]: Accepted password for root from 10.0.0.5 port 22 ssh2\n"


@pytest.fixture()
def c():
    with TestClient(app) as client:
        yield client


def _fresh_case_with_a_source(c, name: str) -> str:
    cid = c.post("/api/cases", json={"name": name}).json()["id"]
    r = c.post("/api/sources", files=[("files", (f"{name}.log", LOG, "text/plain"))])
    assert r.status_code == 200, r.text
    return cid


def test_delete_moves_the_case_to_the_trash_with_its_uploads(c) -> None:
    cid = _fresh_case_with_a_source(c, "recoverable")
    uploads = sorted(p.name for p in config.upload_dir(cid).iterdir())
    assert uploads

    assert c.delete(f"/api/cases/{cid}").status_code == 200
    assert cid not in [x["id"] for x in c.get("/api/cases").json()]
    assert not config.case_dir(cid).exists()

    trash = c.get("/api/cases/trash").json()
    mine = [t for t in trash if t["caseId"] == cid]
    assert mine, "a deleted case must be recoverable, not destroyed"
    entry = mine[0]
    assert entry["name"] == "recoverable" and entry["sources"] == len(uploads) and entry["sizeBytes"] > 0
    # the bytes really are still there
    assert sorted(p.name for p in (config.TRASH_DIR / entry["entry"] / "uploads").iterdir()) == uploads


def test_restore_brings_the_case_and_its_events_back(c) -> None:
    cid = _fresh_case_with_a_source(c, "bring me back")
    events = c.get("/api/case").json()["eventCount"]
    assert events > 0

    c.delete(f"/api/cases/{cid}")
    entry = next(t for t in c.get("/api/cases/trash").json() if t["caseId"] == cid)

    r = c.post(f"/api/cases/trash/{entry['entry']}/restore")
    assert r.status_code == 200, r.text
    back = r.json()["id"]
    assert back in [x["id"] for x in c.get("/api/cases").json()]

    c.post(f"/api/cases/{back}/activate")
    active = c.get("/api/case").json()
    assert active["eventCount"] == events, "restored case did not re-parse its uploads"
    assert active["name"] == "bring me back"
    # and it is out of the trash
    assert all(t["entry"] != entry["entry"] for t in c.get("/api/cases/trash").json())


def test_restore_under_a_new_id_when_the_original_was_reused(c) -> None:
    cid = _fresh_case_with_a_source(c, "will collide")
    c.delete(f"/api/cases/{cid}")
    entry = next(t for t in c.get("/api/cases/trash").json() if t["caseId"] == cid)

    # force the id back into use by writing a case folder at it
    config.upload_dir(cid).mkdir(parents=True, exist_ok=True)
    cases._write_meta(cid, {"case_id": cid, "name": "squatter", "sources": [], "event_count": 0})
    assert cid in cases.case_ids()

    restored = c.post(f"/api/cases/trash/{entry['entry']}/restore").json()["id"]
    assert restored != cid, "restoring must not overwrite whatever now holds that id"
    names = {x["id"]: x["name"] for x in c.get("/api/cases").json()}
    assert names[cid] == "squatter" and names[restored] == "will collide"


def test_trash_is_pruned_oldest_first(c, monkeypatch) -> None:
    """The safety net holds whole uploads, so it cannot grow without bound."""
    monkeypatch.setattr(config, "TRASH_KEEP", 2)
    made = []
    for i in range(4):
        cid = c.post("/api/cases", json={"name": f"prune {i}"}).json()["id"]
        made.append(cid)
        c.delete(f"/api/cases/{cid}")
    kept = c.get("/api/cases/trash").json()
    assert len(kept) <= 2, "trash was not pruned"
    # what survives is the most recent, not an arbitrary pair
    assert {t["caseId"] for t in kept} <= set(made[-2:])


def test_restore_rejects_a_path_outside_the_trash(c) -> None:
    assert c.post("/api/cases/trash/nope-20200101T000000Z/restore").status_code == 404
    with pytest.raises(KeyError):
        cases.restore_trash("../cases")


def test_trash_never_shows_up_as_a_case(c) -> None:
    cid = _fresh_case_with_a_source(c, "hidden")
    c.delete(f"/api/cases/{cid}")
    ids = cases.case_ids()
    assert all(not i.startswith(".") for i in ids)
    assert config.TRASH_DIR.resolve().parent == config.DATA_DIR.resolve(), \
        "the trash must sit beside cases/, not inside it, or case_ids() would list it"


def test_deleting_a_case_returns_without_waiting_for_the_next_one_to_load(c, monkeypatch) -> None:
    """A delete is a click, not a job.

    Deleting the ACTIVE case hands the slot to another one, and that case is restored by re-parsing
    its uploads — seconds to minutes on a real case. Doing that inside the delete meant the request
    sat there, and on a busy workspace it read as "I cannot delete this case". The index moves
    immediately; the restore happens behind it.
    """
    import time

    from app import cases as cases_mod

    first = cases_mod.create_case("first").id
    second = cases_mod.create_case("second").id       # active

    slow = threading.Event()

    def slow_activate(cid, **kw):
        slow.wait(10.0)                                # a case that takes ages to come back

    monkeypatch.setattr(cases_mod.STORE, "activate", slow_activate)
    t0 = time.perf_counter()
    cases_mod.delete_case(second)
    took = time.perf_counter() - t0
    slow.set()

    # The contract is the BOUND, not zero: a small case is waited for (callers expect it to be there),
    # a slow one is not. This activation takes 10 s and the delete must not.
    assert took < cases_mod.ACTIVATE_AFTER_DELETE_WAIT + 2.0,         f"the delete waited {took:.1f}s for the replacement case to load"
    assert second not in cases_mod.case_ids()
    assert first in cases_mod.case_ids()


def test_a_delete_does_not_queue_behind_the_store_lock(c) -> None:
    """Deleting a case must not wait on whatever the pool is doing.

    Measured on the analyst's 11.1 M-event workspace: 101 seconds to delete a case with NO sources,
    all of it spent acquiring `STORE.lock` so the in-memory case could be cleared — a lock the delete
    did not need, held briefly but constantly by the background load. The trash move is a filesystem
    rename; it goes first, and the memory clear only happens if that rename fails (the Windows
    open-handle case).
    """
    import threading
    import time

    from app import cases as cases_mod
    from app.store import STORE

    doomed = cases_mod.create_case("busy-store").id
    held = threading.Event()
    release = threading.Event()

    def hog():
        with STORE.lock:
            held.set()
            release.wait(15.0)

    t = threading.Thread(target=hog, daemon=True)
    t.start()
    assert held.wait(5.0), "could not take the store lock for the test"
    try:
        t0 = time.perf_counter()
        cases_mod.delete_case(doomed)
        took = time.perf_counter() - t0
    finally:
        release.set()
        t.join(5.0)

    assert took < 5.0, f"the delete waited {took:.1f}s for a lock it does not need"
    assert doomed not in cases_mod.case_ids()
    assert any(e["caseId"] == doomed for e in cases_mod.list_trash()), "the case must still be recoverable"
