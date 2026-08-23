"""Test bootstrap.

The suite is DESTRUCTIVE: load_sample_case calls POST /api/case/reset (which deletes every uploaded
file of the active case) and the multi-case tests delete cases outright. So the data dir is forced to
a throwaway temp directory here, BEFORE app.config is imported and freezes its paths.

This used to be os.environ.setdefault(...), which silently deferred to an IRIS_DATA_DIR already in the
environment — running the tests from a shell that pointed at a real data dir wiped that case's uploads.
Never weaken this to setdefault, and never let a test write outside _TEST_DATA_DIR.
"""
import atexit
import os
import time
import shutil
import tempfile
from pathlib import Path

import pytest

_TEST_DATA_DIR = tempfile.mkdtemp(prefix="iris-test-")
_REQUESTED = os.environ.get("IRIS_DATA_DIR")
os.environ["IRIS_DATA_DIR"] = _TEST_DATA_DIR  # override, never setdefault
# marker: only a directory created by THIS bootstrap may ever receive fixture data
(Path(_TEST_DATA_DIR) / ".iris-test-dir").write_text("created by tests/conftest.py - safe to wipe", encoding="utf-8")

# A pre-set IRIS_DATA_DIR is almost always someone running the tests against a live install by accident.
if _REQUESTED and Path(_REQUESTED).resolve() != Path(_TEST_DATA_DIR).resolve():
    print(f"\n[tests] IGNORING IRIS_DATA_DIR={_REQUESTED!r} — the suite is destructive; "
          f"using {_TEST_DATA_DIR} instead.")

atexit.register(lambda: shutil.rmtree(_TEST_DATA_DIR, ignore_errors=True))


def test_data_dir_is_isolated() -> None:
    """Guard: the app must be pointed at the throwaway dir, not a real install."""
    from app import config

    assert Path(config.DATA_DIR).resolve() == Path(_TEST_DATA_DIR).resolve(), (
        f"tests are pointed at {config.DATA_DIR} — refusing to run against a real data directory"
    )


def _assert_throwaway_data_dir() -> None:
    """Refuse to touch anything that is not the per-run temp dir.

    load_sample_case RESETS the active case and ingests fixture logs. Run against a real install it
    silently replaces the analyst's case with sample data - which has actually happened. So it checks
    the LIVE config (not just the env var, which a test could re-point) every single time.
    """
    from app import config
    live = Path(config.DATA_DIR).resolve()
    want = Path(_TEST_DATA_DIR).resolve()
    if live != want:
        raise RuntimeError(
            f"REFUSING to load the sample case: app.config.DATA_DIR is {live}, not the throwaway "
            f"test dir {want}. Something imported app.config before conftest could isolate it, or a "
            f"test re-pointed DATA_DIR. Fix the isolation - do not bypass this guard.")
    # belt and braces: the marker file conftest drops proves this dir was created BY the test run
    if not (want / ".iris-test-dir").is_file():
        raise RuntimeError(f"REFUSING to load the sample case: {want} carries no test-run marker.")


@pytest.fixture(autouse=True)
def _an_active_case_exists():
    """Give every test a real case to ingest into.

    Uploading no longer materialises a case: with none active, POST /api/sources stages the bytes in the
    library instead (an upload must never invent a case). A fresh data dir starts with NO case at all, so
    tests that ingest need one created explicitly. Tests that assert the empty state wipe the cases
    themselves inside the test, so creating one here first is harmless.
    """
    from app import cases, config
    from app.store import STORE

    # The SHIPPED default is raw-first (`IngestSettings.autoEnrich = False`): an ingest reads the
    # timestamp and nothing else, because the interpreted form costs 3x the memory and 15x the ingest
    # time (see tests/test_raw_first_ingest.py, which pins the default itself). Almost every test in
    # this suite is about the INTERPRETED pipeline — parsed fields, entities, detections, timelines —
    # so the suite turns phase 2 on and the tests that care about raw turn it off again explicitly.
    config.update_settings({"ingest": {"autoEnrich": True}})
    if not cases.case_ids():
        cases.create_case("Untitled case")
    yield
    # Two-phase ingest queues phase 2 on a background worker (app/enrich.py). An enrichment that is still
    # running when a test ends REPLACES a source's events in the middle of the next one — and, because it
    # ends with save_meta(), can write a case.json for a case the next test is asserting does not exist.
    # Drain it for the same reason as the detection refresh below.
    #
    # The worker itself is started by the FastAPI lifespan, so a test that ingested outside a
    # `with TestClient(app)` block leaves work nobody is servicing. Start one here and let it FINISH:
    # a source left `raw` is otherwise picked up by the next test's lifespan (Store.requeue_unenriched)
    # and enriches in the middle of it. Doing it here costs milliseconds and nothing is looking.
    # (A queue with no worker at all is cleared and returns at once — see EnrichQueue.drain. Waiting on
    # one is what burned 30 s per test and turned a two-minute suite into a 68-minute one.)
    from app import enrich as _enrich

    _enrich.QUEUE.start(STORE)
    _enrich.QUEUE.drain(15.0)
    # A source delete hands its detection refresh to a background thread that bumps the store version
    # when it lands (store._refresh_detections_async). Left running past the end of a test, that bump
    # lands in the MIDDLE of the next one — a derived key moves between two lines, a graph reports
    # 'building' where 'ready' was asserted. Drain it here so no test inherits another's background work.
    # A background library load schedules its detection pass only when the LOAD ends, so a teardown
    # that checked `_detect_busy` alone could look between the two and hand the next test a pass that
    # starts in its middle. Wait for the load, then for the pass.
    for _ in range(300):
        if not getattr(STORE, "pool_loading", False):
            break
        time.sleep(0.05)
    for _ in range(200):
        if not getattr(STORE, "_detect_busy", False):
            break
        time.sleep(0.05)


def drain_enrichment(timeout: float = 60.0) -> None:
    """Block until every queued source has been enriched. Test-only — see EnrichQueue.drain."""
    from app import enrich as _enrich
    from app.store import STORE

    _enrich.QUEUE.start(STORE)
    assert _enrich.QUEUE.drain(timeout), "enrichment did not finish"
    # The windowed-rule correction runs on its own thread after the commit. A burst or a spray, or any
    # hit count over the whole pool, is that thread's output — so "enrichment finished" has to include it.
    assert STORE.wait_detections(timeout), "the background detection pass did not finish"


def load_sample_case(c):
    """Upload the bundled sample logs through the real ingest endpoint (replaces the removed /api/demo)."""
    _assert_throwaway_data_dir()
    # ingest needs a real case: with none active the upload is staged in the library, not parsed
    if c.get("/api/case").json().get("pending"):
        c.post("/api/cases", json={"name": "Untitled case"})
    d = Path(__file__).resolve().parent / "fixtures" / "sample_case"
    names = ["edge-lb-01_access.log", "WIN-FS01_Security.evtx.xml", "cloudtrail_20260811.json", "k8s_audit_20260811.jsonl",
             "bastion-1_syslog", "payments-api_app.jsonl", "fw-edge-2.pipe.log"]
    c.post("/api/case/reset")
    files = [("files", (n, (d / n).read_bytes(), "application/octet-stream")) for n in names]
    r = c.post("/api/sources", files=files)
    assert r.status_code == 200, r.text
    # Ingest is TWO phases now (app/enrich.py): the lines are in the pool immediately, the parse and the
    # normalization follow on a worker. Everything below this line — detections, entities, timestamps —
    # is phase 2's output, so wait for it. Tests that care about the raw phase drive it explicitly.
    drain_enrichment()
    c.patch("/api/case", json={"name": "Suspected credential stuffing → data egress"})
    # curate the key evidence into the case set like the old demo pinned it
    ids = []
    for e in c.get("/api/events?limit=5000").json()["rows"]:
        if any(d["id"] in {"SIGMA-AUTH-0111", "SIGMA-AWS-0031", "SIGMA-K8S-0004", "SIGMA-APP-0055", "SIGMA-NET-0022"} for d in e["detections"]):
            ids.append(e["id"])
    for i in ids:
        c.post(f"/api/case-set/{i}")
    return c.get("/api/case").json()
