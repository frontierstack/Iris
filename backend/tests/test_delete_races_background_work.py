"""A delete, and a case.json write, must not lose a race with background work.

Both failures pinned here were found as an intermittent `test_case_trash.py` failure in the full
suite (~1 run in 3 on Windows) and both are product bugs, not test artefacts:

* **Deleting a case raced whatever had a file open inside `cases/<id>/`.** Phase-2 enrichment reads a
  case upload (`Store.enrich_source`) and every `Store.bump()` writes `cases/<id>/case.tmp` through
  `save_meta()` — which the enrichment worker does once per source it finishes, library sources
  included. Windows will not rename a directory while any file inside it is open, so `shutil.move`
  raised, its copytree+rmtree fallback left the case BOTH in the trash and in `cases/` (a delete the
  Cases page shows as a no-op) — and when the COPY was the half that failed, the handler's `rmtree`
  destroyed the only copy of the uploads. Measured, from the real suite:

      trash move FAILED for CASE-0005: [Errno 13] Permission denied: cases\\CASE-0005\\case.json
      after rmtree: case_dir exists=False

* **`save_meta()` builds `meta` under the store lock and writes it outside**, so two concurrent saves
  could land in the opposite order to the one they were built in and the older snapshot would win —
  silently reverting case.json past a case-set entry, a note or an indicator.
"""
from __future__ import annotations

import json
import os
import shutil
import threading
import time

import pytest
from fastapi.testclient import TestClient

from app import cases, config
from app.main import app
from app.store import STORE

LOG = b"".join(
    b"Jan 01 00:00:%02d host sshd[%d]: Accepted password for root from 10.0.0.5 port 22 ssh2\n" % (i % 60, i)
    for i in range(12)
)


@pytest.fixture()
def c():
    with TestClient(app) as client:
        yield client


def _fresh_case_with_a_source(c, name: str) -> str:
    cid = c.post("/api/cases", json={"name": name}).json()["id"]
    r = c.post("/api/sources", files=[("files", (f"{name}.log", LOG, "text/plain"))])
    assert r.status_code == 200, r.text
    return cid


def _disk_case_set() -> list[dict]:
    return json.loads(STORE.case_path.read_text(encoding="utf-8"))["case_set"]


# --------------------------------------------------------------- deleting a case
def test_delete_wins_against_a_file_held_open_inside_the_case(c) -> None:
    """The exact interleaving behind the flake, made deterministic by holding the handle ourselves.

    Windows-shaped: on POSIX a directory renames happily with files open inside it, so there this
    only asserts that nothing else broke. `test_a_delete_that_cannot_be_moved_never_destroys_the_
    uploads` below is the platform-independent half.
    """
    cid = _fresh_case_with_a_source(c, "held open")
    uploads = sorted(p.name for p in config.upload_dir(cid).iterdir())
    assert uploads
    path = config.upload_dir(cid) / uploads[0]

    started = threading.Event()

    def holder() -> None:
        # exactly what Store.enrich_source's `path.read_bytes()` holds, only for longer
        with open(path, "rb") as fh:
            started.set()
            fh.read(1)
            time.sleep(0.4)

    t = threading.Thread(target=holder, name="handle-holder", daemon=True)
    t.start()
    assert started.wait(5.0)
    try:
        assert c.delete(f"/api/cases/{cid}").status_code == 200
    finally:
        t.join(10.0)

    assert cid not in [x["id"] for x in c.get("/api/cases").json()], "the delete read as a no-op"
    assert not config.case_dir(cid).exists()
    mine = [x for x in c.get("/api/cases/trash").json() if x["caseId"] == cid]
    assert mine, "a deleted case must be recoverable, not destroyed"
    assert sorted(p.name for p in (config.TRASH_DIR / mine[0]["entry"] / "uploads").iterdir()) == uploads


def test_a_delete_that_cannot_be_moved_never_destroys_the_uploads(c, monkeypatch) -> None:
    """When the case cannot reach the trash AT ALL, it stays where it is.

    The folder holds the only copy of its uploads. Removing it because the move failed is the one
    outcome that cannot be undone — and it is what the old `except OSError: rmtree(case_dir)` did,
    including when `shutil.move`'s copytree fallback had only got half of the case across.
    """
    cid = _fresh_case_with_a_source(c, "immovable")
    uploads = sorted(p.name for p in config.upload_dir(cid).iterdir())
    assert uploads
    src = str(config.case_dir(cid))

    # keep the retry budget out of the test's runtime; the refusal below never relents anyway
    monkeypatch.setattr(cases, "TRASH_MOVE_RETRY_SECONDS", 0.05)

    # every route out of cases/<id>: the rename, the old shutil.move, and the copy fallback
    for mod, attr in ((os, "replace"), (os, "rename"), (shutil, "move"), (shutil, "copytree")):
        real = getattr(mod, attr)

        def refuse(a, b, *rest, _real=real, **kw):
            if str(a) == src:
                raise PermissionError(13, "the file is being used by another process")
            return _real(a, b, *rest, **kw)

        monkeypatch.setattr(mod, attr, refuse)

    c.delete(f"/api/cases/{cid}")

    assert config.case_dir(cid).is_dir(), "a case that could not be trashed was deleted anyway"
    assert sorted(p.name for p in config.upload_dir(cid).iterdir()) == uploads, \
        "the only copy of the uploads was destroyed by a failed delete"

    # ... and once nothing refuses any more, the delete the analyst asked for still works
    monkeypatch.undo()
    assert c.delete(f"/api/cases/{cid}").status_code == 200
    assert not config.case_dir(cid).exists()


# --------------------------------------------------------------- writing case.json
def test_a_slow_background_save_cannot_revert_case_json(c) -> None:
    """A save built BEFORE an edit must never land after it.

    `bump()` -> `save_meta()` runs on the enrichment worker for every source it finishes, so this
    overlaps ordinary curation constantly. The stale save is gated between building its snapshot and
    writing the file — the window that exists in save_meta by construction.
    """
    _fresh_case_with_a_source(c, "no lost updates")
    ids = [e.id for e in STORE.events if e.sourceId in set(STORE.case_source_ids())]
    assert len(ids) >= 3

    reached, release = threading.Event(), threading.Event()
    # `config.case_path` is resolved between building the snapshot and writing the file, and outside
    # the store lock — i.e. exactly the window in which a save can be overtaken.
    real_case_path = config.case_path

    def gated(case_id: str):
        p = real_case_path(case_id)
        if threading.current_thread().name == "stale-save":
            reached.set()
            release.wait(20.0)
        return p

    t = threading.Thread(target=STORE.save_meta, name="stale-save", daemon=True)
    try:
        config.case_path = gated  # type: ignore[assignment]
        t.start()
        assert reached.wait(20.0), "the stale save never reached the write"

        # ... and now the edit it must not undo
        STORE.add_many_to_case(ids[:3], ["kept"], None)
        assert len(_disk_case_set()) == 3, "the edit did not reach disk at all"

        release.set()
        t.join(20.0)
        assert not t.is_alive()
    finally:
        release.set()
        config.case_path = real_case_path  # type: ignore[assignment]
        t.join(20.0)

    assert [e["eventId"] for e in _disk_case_set()] == ids[:3], \
        "a save built before the edit overwrote it — case.json reverted"
