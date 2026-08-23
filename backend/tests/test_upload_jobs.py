"""Server-side upload/parse jobs: progress that survives a tab switch, a refresh and a restart.

The analyst's report: uploading a 263 MB CSV shows a progress bar, and switching tabs or refreshing
throws every trace of it away — parse state lived only in the browser tab that started it. These tests
pin the server-side registry: a job readable from a SEPARATE request, a threaded parse reporting
`parsing` then `ready`, a failed parse keeping its message, survival across a simulated restart, and
pruning so jobs.json cannot grow forever.
"""
from __future__ import annotations

import threading
import time

import pytest
from fastapi.testclient import TestClient

from app import cases, config, jobs as jobs_mod
from app import store as store_mod
from app.jobs import REGISTRY
from app.main import app
from app.store import STORE

from tests.conftest import drain_enrichment

LOG = b"".join(f"Jan 01 00:00:{i:02d} host sshd[1]: Accepted password for alice from 10.0.0.5 port 22 ssh2\n".encode()
               for i in range(30))


@pytest.fixture()
def c():
    with TestClient(app) as client:
        yield client


def _job(client, job_id: str) -> dict:
    rows = client.get("/api/jobs?limit=500").json()["jobs"]
    match = [j for j in rows if j["id"] == job_id]
    assert match, f"job {job_id} is not in the registry"
    return match[0]


def _wait_for(client, job_id: str, state: str, timeout: float = 10.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        j = _job(client, job_id)
        if j["state"] == state:
            return j
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} never reached {state}: {_job(client, job_id)}")


def test_a_job_is_visible_from_another_request(c) -> None:
    """The whole point: a second tab (a separate request) sees the same upload."""
    made = c.post("/api/jobs", json={"files": [{"file": "auth.log", "size": len(LOG)}], "target": "case"})
    assert made.status_code == 200, made.text
    job = made.json()["jobs"][0]
    assert job["state"] == "queued" and job["target"] == "case" and job["caseId"] == STORE.case_id

    # a different HTTP request — as another tab would — already sees the declared upload
    assert _job(c, job["id"])["state"] == "queued"

    # bytes in flight are client knowledge; the tab pushes them so every other tab can render them
    c.patch(f"/api/jobs/{job['id']}", json={"received": len(LOG) // 2})
    mid = _job(c, job["id"])
    assert mid["state"] == "uploading" and mid["received"] == len(LOG) // 2

    r = c.post(f"/api/sources?jobIds={job['id']}", files=[("files", ("auth.log", LOG, "text/plain"))])
    assert r.status_code == 200, r.text
    drain_enrichment()   # the job covers BOTH ingest phases now — it is ready when the source is enriched
    # Resolve it here, before the second client: entering another TestClient runs the lifespan, which
    # re-restores the case from disk — every restored source is `raw` again until the worker has been
    # through it, so an UNRESOLVED job would legitimately still read `parsing` there.
    assert _wait_for(c, job["id"], "ready")["events"] == 30

    with TestClient(app) as other_tab:      # a genuinely separate client
        done = _job(other_tab, job["id"])
    assert done["state"] == "ready"
    assert done["events"] == 30 and done["parser"] and done["received"] == len(LOG)
    assert done["sourceIds"] == [r.json()[0]["id"]]


def test_an_upload_without_a_declared_job_still_gets_one(c) -> None:
    """curl, an old tab, a test — ingest that happens must never be invisible."""
    before = {j["id"] for j in c.get("/api/jobs?limit=500").json()["jobs"]}
    c.post("/api/sources", files=[("files", ("undeclared.log", LOG, "text/plain"))])
    drain_enrichment()
    fresh = [j for j in c.get("/api/jobs?limit=500").json()["jobs"]
             if j["id"] not in before and j["file"] == "undeclared.log"]
    assert len(fresh) == 1 and fresh[0]["state"] == "ready" and fresh[0]["events"] == 30


def test_the_job_covers_both_ingest_phases(c, monkeypatch) -> None:
    """A job is not done when the RAW lines land — it is done when the source is enriched.

    Ingest is two phases now (app/enrich.py): phase 1 splits the file into raw lines in milliseconds and
    phase 2 (the real parser + normalization) runs on the enrichment worker. `PARSING` is therefore no
    longer observable for a text log — the state the analyst is actually waiting on is `Source.enrich`.
    The job has to follow it there, or "ready" would mean "the lines are in the pool", while the file
    still has no timestamps, no fields and no detections, and a phase-2 failure would arrive after the
    job had already claimed success.
    """
    gate = threading.Event()
    original = store_mod.Store.enrich_source

    def gated(self, sid):
        gate.wait(15)
        return original(self, sid)

    monkeypatch.setattr(store_mod.Store, "enrich_source", gated)

    job = c.post("/api/jobs", json={"files": [{"file": "big.log", "size": len(LOG)}]}).json()["jobs"][0]
    r = c.post(f"/api/sources?jobIds={job['id']}", files=[("files", ("big.log", LOG, "text/plain"))])
    assert r.status_code == 200
    src = r.json()[0]
    assert src["enrich"] in ("raw", "queued", "enriching"), "the raw phase must not claim to be enriched"

    parsing = _job(c, job["id"])
    assert parsing["state"] == "parsing", "the job resolved while the source was still un-enriched"
    assert parsing["sourceIds"] == [src["id"]]

    gate.set()
    done = _wait_for(c, job["id"], "ready")
    assert done["events"] == 30
    assert c.get(f"/api/sources/{src['id']}").json()["enrich"] == "enriched"


def test_a_failed_parse_records_the_message(c, monkeypatch) -> None:
    """A parse that fails in PHASE 2 is still a failed parse — the job and the source must both say so.

    This is the analyst's only signal that a file did not parse. The raw lines stay in the pool and stay
    searchable (that is the point of the split), but nothing may present the file as parsed.
    """
    def explode(self, sid, src, parser, data):
        raise ValueError("unreadable byte at 0x41")

    monkeypatch.setattr(store_mod.Store, "_parse_batches", explode)
    job = c.post("/api/jobs", json={"files": [{"file": "broken.log", "size": len(LOG)}]}).json()["jobs"][0]
    c.post(f"/api/sources?jobIds={job['id']}", files=[("files", ("broken.log", LOG, "text/plain"))])
    drain_enrichment()

    failed = _job(c, job["id"])
    assert failed["state"] == "error"
    assert "unreadable byte" in failed["error"]
    src = c.get(f"/api/sources/{failed['sourceIds'][0]}").json()
    assert src["state"] == "ERROR" and "unreadable byte" in (src["error"] or "")
    assert src["enrich"] == "error"


def test_jobs_survive_a_restart_and_stop_claiming_to_run(c) -> None:
    """A process that dies mid-parse must not leave a job running forever."""
    finished = c.post("/api/jobs", json={"files": [{"file": "finished.log", "size": len(LOG)}]}).json()["jobs"][0]
    c.post(f"/api/sources?jobIds={finished['id']}", files=[("files", ("finished.log", LOG, "text/plain"))])
    drain_enrichment()
    inflight = REGISTRY.create("half-sent.log", 999_999, "case", STORE.case_id)
    REGISTRY.progress(inflight.id, 1234)
    assert config.DATA_DIR.joinpath("jobs.json").is_file(), "the registry was never persisted"

    # simulate a restart: re-read jobs.json from disk, then reconcile like main.lifespan does
    buried = REGISTRY.reconcile()
    assert buried >= 1

    survivor = _job(c, finished["id"])
    assert survivor["state"] == "ready" and survivor["events"] == 30, "a finished job lost its result"
    killed = _job(c, inflight.id)
    assert killed["state"] == "error" and killed["interrupted"] is True
    assert "restart" in killed["error"]
    assert killed["received"] == 1234, "the bytes it had received were lost"


def test_finished_jobs_are_pruned_and_the_list_is_capped(c, monkeypatch) -> None:
    old = REGISTRY.create("ancient.log", 10, "library", "")
    REGISTRY.finish(old.id, parser="plaintext", events=0)
    assert _job(c, old.id)["state"] == "ready", "a just-finished job must still be visible after a refresh"

    # Retention is now per outcome: a ready job ages out on READY_RETAIN_SEC, a failure on RETAIN_SEC.
    monkeypatch.setattr(jobs_mod, "RETAIN_SEC", 1)
    monkeypatch.setattr(jobs_mod, "READY_RETAIN_SEC", 1)
    with REGISTRY.lock:
        REGISTRY.get(old.id).updated_ts = time.time() - 5  # type: ignore[union-attr]
    rows = c.get("/api/jobs?limit=500").json()["jobs"]
    assert old.id not in {j["id"] for j in rows}

    monkeypatch.setattr(jobs_mod, "MAX_JOBS", 5)
    ids = []
    for i in range(9):
        j = REGISTRY.create(f"bulk-{i}.log", 1, "library", "")
        REGISTRY.finish(j.id, parser="plaintext")
        ids.append(j.id)
    kept = {j["id"] for j in c.get("/api/jobs?limit=500").json()["jobs"]}
    assert len(kept) <= 5
    assert ids[-1] in kept and ids[0] not in kept, "pruning must drop the OLDEST jobs, not the newest"


def test_a_successful_job_clears_itself_and_a_failed_one_does_not(c) -> None:
    """The analyst should not have to press "Clear finished" after every ingest.

    A ready job is a duplicate of the Sources row underneath it — same file, same parser, same event
    count — so it ages out in seconds. A FAILURE is the one thing on that panel that is restated
    nowhere else in a form they can act on, and auto-clearing it would silently discard the report
    that evidence never made it into the pool. Both halves are the test.
    """
    done = REGISTRY.create("settled.log", 10, "library", "")
    REGISTRY.finish(done.id, parser="plaintext", events=3)
    failed = REGISTRY.create("broken.log", 10, "library", "")
    REGISTRY.fail(failed.id, "the parser could not read a record")

    live = {j["id"] for j in c.get("/api/jobs?limit=500").json()["jobs"]}
    assert done.id in live and failed.id in live, "both must survive long enough to be seen"

    # Age both past READY_RETAIN_SEC but nowhere near RETAIN_SEC.
    assert jobs_mod.READY_RETAIN_SEC < jobs_mod.RETAIN_SEC
    aged = time.time() - (jobs_mod.READY_RETAIN_SEC + 5)
    with REGISTRY.lock:
        REGISTRY.get(done.id).updated_ts = aged      # type: ignore[union-attr]
        REGISTRY.get(failed.id).updated_ts = aged    # type: ignore[union-attr]

    rows = c.get("/api/jobs?limit=500").json()["jobs"]
    ids = {j["id"] for j in rows}
    assert done.id not in ids, "a finished upload must clear itself"
    assert failed.id in ids, "a failure must stay until it is dismissed"
    assert "could not read" in next(j for j in rows if j["id"] == failed.id)["error"]


def test_a_running_job_is_never_aged_out(c) -> None:
    """Whatever the clock says, work still in flight stays on the panel."""
    job = REGISTRY.create("uploading.log", 5_000_000, "library", "")
    REGISTRY.progress(job.id, 1000)
    with REGISTRY.lock:
        REGISTRY.get(job.id).updated_ts = time.time() - (jobs_mod.READY_RETAIN_SEC + 5)  # type: ignore[union-attr]
    assert _job(c, job.id)["state"] in ("queued", "uploading")


def test_a_stalled_upload_is_not_reported_as_running_forever(c, monkeypatch) -> None:
    job = REGISTRY.create("abandoned.log", 5_000_000, "case", STORE.case_id)
    REGISTRY.progress(job.id, 10)
    monkeypatch.setattr(jobs_mod, "STALE_UPLOAD_SEC", -1)
    stalled = _job(c, job.id)
    assert stalled["state"] == "error" and "stopped" in stalled["error"]


# ------------------------------------------------------------------ library uploads (no case at all)
def _wipe_cases(client) -> None:
    # Settle phase 2 FIRST. An enrichment landing while these deletes run ends in Store.save_meta(),
    # which writes cases/<id>/case.json — recreating the directory of a case that has just been moved
    # to the trash. `cases.list_cases()` then reports a case that was deleted and the store is no longer
    # `pending`, so the next upload files itself into a case instead of the library. That is a genuine
    # product hazard (noted in TODO.md); here it is a test that must not race with a worker.
    drain_enrichment()
    for cid in list(cases.case_ids()):
        client.delete(f"/api/cases/{cid}")


def test_library_upload_gets_a_job_and_never_creates_a_case(c) -> None:
    _wipe_cases(c)
    pending_id = c.get("/api/case").json()["id"]
    job = c.post("/api/jobs", json={"files": [{"file": "staged.log", "size": len(LOG)}], "target": "library"}).json()["jobs"][0]
    assert job["target"] == "library" and job["caseId"] == ""

    r = c.post(f"/api/library/upload?jobIds={job['id']}", files=[("files", ("staged.log", LOG, "text/plain"))])
    assert r.status_code == 200, r.text
    drain_enrichment()

    with TestClient(app) as other_tab:
        done = _job(other_tab, job["id"])
    assert done["state"] == "ready" and done["target"] == "library" and done["parser"]

    # the guarantee from test_no_autocreate_case must hold: no case, on disk or in the list
    assert c.get("/api/cases").json() == []
    assert not config.case_dir(pending_id).exists()
    assert STORE.pending is True


def test_staged_files_carry_detection_metadata(c) -> None:
    _wipe_cases(c)
    c.post("/api/library/upload", files=[("files", ("probe-me.log", LOG, "text/plain"))])
    entry = [f for f in c.get("/api/library").json() if f["displayName"] == "probe-me.log"][0]
    assert entry["caseId"] == "" and entry["parser"], "a staged file must say what it is"
    assert entry["state"] in ("READY", "REVIEW", "MAP")
    assert entry["lines"] == 30 and entry["linesEstimated"] is False
    assert entry["sample"]
    assert 0.0 <= entry["confidence"] <= 1.0


def test_detection_of_a_big_file_is_bounded(monkeypatch) -> None:
    """Sniffing must read a prefix, never the whole file — and then say the count is an estimate."""
    data = LOG * 40
    monkeypatch.setattr(jobs_mod, "PROBE_BYTES", 512)
    out = jobs_mod.probe_upload("huge.log", data)
    assert out["parser"] and out["linesEstimated"] is True
    assert out["lines"] > 0


def test_uploading_with_no_case_still_stages_and_tracks(c) -> None:
    """POST /api/sources with no case: staged in the library, tracked, and still no case created."""
    _wipe_cases(c)
    before = {j["id"] for j in c.get("/api/jobs?limit=500").json()["jobs"]}
    r = c.post("/api/sources", files=[("files", ("no-case.log", LOG, "text/plain"))])
    drain_enrichment()
    # staged in the library and parsed into the case-less pool — the Source reported back says so
    assert r.status_code == 200 and [s["origin"] for s in r.json()] == ["library"]
    assert r.headers.get("X-Iris-Staged-To-Library") == "1"
    fresh = [j for j in c.get("/api/jobs?limit=500").json()["jobs"]
             if j["id"] not in before and j["file"] == "no-case.log"]
    assert len(fresh) == 1 and fresh[0]["target"] == "library" and fresh[0]["state"] == "ready"
    assert c.get("/api/cases").json() == []
