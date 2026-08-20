"""Driving phase 2 of the ingest by hand — and knowing how much of it is outstanding.

Two-phase ingest (app/enrich.py) lands a text log as RAW LINES immediately and does the expensive
interpretation — timestamps, severity, fields, entities, detections — afterwards on one background
worker. Until this file existed the queue was driven ONLY automatically: there was no way for the
analyst to ask for a source to be enriched, to decline one, to retry one that failed, or to see how much
of the pool was still raw. Every screen that reads a timestamp, a field or a detection is answering over
PART of the corpus while any source is still raw, so "how much is outstanding" is not a nicety.

What is pinned here:
  * `POST /api/sources/{id}/enrich` enqueues raw / skipped / error sources, is idempotent while the work
    is already pending, and 409s on an already-enriched one.
  * `POST /api/sources/{id}/enrich/skip` marks it skipped and cancels it from the queue — and REFUSES
    (409) mid-enrichment, because that bell cannot be un-rung.
  * `GET /api/case` reports the per-state counts, what is running, and the two different numbers
    `pending` (work in flight) and `outstanding` (my answer is incomplete) — WITHOUT walking the pool.
  * `ingest.autoEnrich` round-trips through the settings API and, when off, genuinely means nothing
    enriches on its own.
"""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from app import enrich
from app.main import app
from app.store import STORE
from tests.conftest import drain_enrichment

# an SSH burst: enough shape that enrichment has something to say (timestamps, host, user, fields)
LOG = b"".join(
    b"Jan 01 00:00:%02d host sshd[1%02d]: Failed password for root from 45.66.13.201 port 22 ssh2\n" % (i, i)
    for i in range(1, 13)
)
N = len(LOG.splitlines())


@pytest.fixture()
def c():
    with TestClient(app) as client:
        yield client


@pytest.fixture()
def manual(c):
    """Enrichment strictly on demand: autoEnrich OFF for the duration of the test, restored afterwards.

    Restoring matters — settings.json lives in the per-run data dir and is shared by every test that
    follows, so leaking `autoEnrich:false` would silently stop the rest of the suite ever enriching.
    """
    assert c.put("/api/settings", json={"ingest": {"autoEnrich": False}}).status_code == 200
    assert c.get("/api/settings").json()["ingest"]["autoEnrich"] is False
    yield
    assert c.put("/api/settings", json={"ingest": {"autoEnrich": True}}).status_code == 200


@pytest.fixture()
def paused(monkeypatch):
    """Hold the queue still so a `queued` source stays queued long enough to be asserted about.

    The worker is fast and the fixture logs are tiny, so a real submit is enriched before the next line
    of the test runs. Submissions are recorded instead, which is also the only way to prove that `skip`
    CANCELS rather than merely relabelling.
    """
    submitted: list[str] = []
    monkeypatch.setattr(enrich.QUEUE, "submit", lambda sid: submitted.append(sid))
    monkeypatch.setattr(enrich.QUEUE, "cancel", lambda sid: bool(submitted) and _drop(submitted, sid))
    return submitted


def _drop(seq: list[str], sid: str) -> bool:
    if sid in seq:
        seq.remove(sid)
        return True
    return False


def _upload(c, name: str = "raw.log", data: bytes = LOG) -> dict:
    r = c.post("/api/sources", files=[("files", (name, data, "text/plain"))])
    assert r.status_code == 200, r.text
    return r.json()[0]


def _source(c, sid: str) -> dict:
    r = c.get(f"/api/sources/{sid}")
    assert r.status_code == 200, r.text
    return r.json()


# ------------------------------------------------------------------ the raw phase, on its own
def test_a_text_log_lands_raw_and_searchable_before_it_is_enriched(c, manual) -> None:
    src = _upload(c, "unenriched.log")
    assert src["enrich"] == "raw", src
    assert src["events"] == N, "the lines are in the pool immediately"
    assert src["range"] is None, "nothing has been timestamped yet and nothing may pretend otherwise"

    # searchable at once — that is the whole point of the split
    assert c.get("/api/events", params={"q": "45.66.13.201"}).json()["total"] == N
    rows = c.get("/api/events", params={"q": "45.66.13.201", "limit": 1}).json()["rows"]
    # The timestamp IS read in phase 1 — it is the one thing a later look at the line cannot
    # recover a PLACE IN TIME for (see tests/test_raw_first_ingest.py). Everything else a parse
    # would produce is still absent, and that is what "raw" means here.
    assert rows[0]["ts"] == "2026-01-01T00:00:12Z", "phase 1 reads the time off the line"
    assert rows[0]["fields"] == {}, "raw must not invent a field"


# ------------------------------------------------------------------ POST /enrich
def test_enrich_enqueues_and_then_actually_interprets_the_source(c, manual) -> None:
    sid = _upload(c, "enrich-me.log")["id"]
    r = c.post(f"/api/sources/{sid}/enrich")
    assert r.status_code == 200, r.text
    # the worker is live and these logs are tiny, so it may already have started (or finished) by the
    # time the response is built — what must never happen is the source still reading `raw`
    assert r.json()["enrich"] in ("queued", "enriching", "enriched"), r.json()

    drain_enrichment()
    after = _source(c, sid)
    assert after["enrich"] == "enriched"
    assert after["enrichedAt"] and after["enrichError"] is None
    assert after["range"] is not None, "enrichment is what gives the source a time range"
    row = c.get("/api/events", params={"q": "45.66.13.201", "limit": 1}).json()["rows"][0]
    assert row["ts"] and row["fields"], "phase 2 produced timestamps and fields"


def test_enrich_ignores_autoenrich_being_off(c, manual, paused) -> None:
    """The setting governs what happens AUTOMATICALLY. An explicit request is not automatic."""
    sid = _upload(c, "on-demand.log")["id"]
    assert _source(c, sid)["enrich"] == "raw"
    assert c.post(f"/api/sources/{sid}/enrich").status_code == 200
    assert paused == [sid], "the source was handed to the enrichment worker"


def test_enrich_is_idempotent_while_the_work_is_already_pending(c, manual, paused) -> None:
    sid = _upload(c, "double-click.log")["id"]
    assert c.post(f"/api/sources/{sid}/enrich").status_code == 200
    # a second click, another tab, a retry after a dropped response — none of them may fail
    r = c.post(f"/api/sources/{sid}/enrich")
    assert r.status_code == 200, r.text
    assert r.json()["enrich"] == "queued"


def test_enrich_refuses_an_already_enriched_source(c) -> None:
    sid = _upload(c, "already.log")["id"]
    drain_enrichment()
    assert _source(c, sid)["enrich"] == "enriched"
    r = c.post(f"/api/sources/{sid}/enrich")
    assert r.status_code == 409, r.text
    assert "already enriched" in r.json()["detail"]
    assert "mapping" in r.json()["detail"], "the refusal must name the real way to re-parse a file"


def test_enrich_unknown_source_is_a_404(c) -> None:
    assert c.post("/api/sources/nope/enrich").status_code == 404
    assert c.post("/api/sources/nope/enrich/skip").status_code == 404


def test_enrich_retries_a_source_whose_phase_2_failed(c, manual, monkeypatch) -> None:
    """A failed phase-2 parse leaves the raw lines in the pool. Retrying it must be one call."""
    sid = _upload(c, "flaky.log")["id"]

    real = type(STORE)._parse_batches
    monkeypatch.setattr(type(STORE), "_parse_batches",
                        lambda self, *a, **kw: (_ for _ in ()).throw(RuntimeError("parser exploded")))
    assert c.post(f"/api/sources/{sid}/enrich").status_code == 200
    drain_enrichment()

    failed = _source(c, sid)
    assert failed["enrich"] == "error" and "parser exploded" in (failed["enrichError"] or "")
    assert failed["state"] == "ERROR", "a phase-2 failure IS the parse failing and the source must say so"
    assert c.get("/api/events", params={"q": "45.66.13.201"}).json()["total"] >= N, "raw lines survive"

    monkeypatch.setattr(type(STORE), "_parse_batches", real)
    r = c.post(f"/api/sources/{sid}/enrich")
    assert r.status_code == 200, r.text
    assert r.json()["enrich"] in ("queued", "enriching", "enriched"), r.json()
    assert r.json()["enrichError"] is None, "the retry clears the previous failure"
    drain_enrichment()
    assert _source(c, sid)["enrich"] == "enriched"


# ------------------------------------------------------------------ POST /enrich/skip
def test_skip_marks_skipped_and_cancels_it_from_the_queue(c, manual, paused) -> None:
    sid = _upload(c, "declined.log")["id"]
    assert c.post(f"/api/sources/{sid}/enrich").status_code == 200
    assert paused == [sid]

    r = c.post(f"/api/sources/{sid}/enrich/skip")
    assert r.status_code == 200, r.text
    assert r.json()["enrich"] == "skipped"
    assert paused == [], "skip must CANCEL the queued work, not merely relabel the source"


def test_skip_a_raw_source_that_was_never_queued(c, manual) -> None:
    sid = _upload(c, "never-wanted.log")["id"]
    r = c.post(f"/api/sources/{sid}/enrich/skip")
    assert r.status_code == 200 and r.json()["enrich"] == "skipped"
    # and it stays skipped through a drain — nothing picks it back up
    drain_enrichment()
    assert _source(c, sid)["enrich"] == "skipped"
    assert c.get("/api/events", params={"q": "45.66.13.201"}).json()["total"] >= N


def test_skip_is_idempotent(c, manual) -> None:
    sid = _upload(c, "twice-declined.log")["id"]
    assert c.post(f"/api/sources/{sid}/enrich/skip").status_code == 200
    r = c.post(f"/api/sources/{sid}/enrich/skip")
    assert r.status_code == 200 and r.json()["enrich"] == "skipped"


def test_skip_refuses_mid_enrichment_and_says_why(c, manual, paused) -> None:
    """The bell cannot be un-rung: the parse is running and will replace the events when it lands."""
    sid = _upload(c, "in-flight.log")["id"]
    with STORE.lock:
        STORE.sources[sid].enrich = "enriching"
    try:
        r = c.post(f"/api/sources/{sid}/enrich/skip")
        assert r.status_code == 409, r.text
        assert "cannot be cancelled mid-parse" in r.json()["detail"]
        assert _source(c, sid)["enrich"] == "enriching", "a refusal must change nothing"
    finally:
        with STORE.lock:
            STORE.sources[sid].enrich = "skipped"


def test_skip_refuses_an_enriched_source(c) -> None:
    sid = _upload(c, "done.log")["id"]
    drain_enrichment()
    r = c.post(f"/api/sources/{sid}/enrich/skip")
    assert r.status_code == 409, r.text
    assert "nothing left to decline" in r.json()["detail"]
    assert _source(c, sid)["enrich"] == "enriched"


def test_a_skipped_source_can_be_asked_for_later(c, manual) -> None:
    sid = _upload(c, "changed-my-mind.log")["id"]
    assert c.post(f"/api/sources/{sid}/enrich/skip").json()["enrich"] == "skipped"
    assert c.post(f"/api/sources/{sid}/enrich").json()["enrich"] != "skipped"
    drain_enrichment()
    assert _source(c, sid)["enrich"] == "enriched"


# ------------------------------------------------------------------ GET /api/case
def _wipe(c) -> None:
    from app import cases
    for cid in list(cases.case_ids()):
        c.delete(f"/api/cases/{cid}")
    for f in c.get("/api/library").json():
        if f["caseId"] == "":
            c.delete(f"/api/library/unattached/{f['fileName']}")
    c.post("/api/cases", json={"name": "Enrichment"})


def test_case_reports_the_enrichment_state_of_the_whole_pool(c, manual) -> None:
    _wipe(c)
    raw = _upload(c, "still-raw.log")["id"]
    declined = _upload(c, "declined-2.log")["id"]
    done = _upload(c, "finished.log")["id"]
    assert c.post(f"/api/sources/{declined}/enrich/skip").status_code == 200
    assert c.post(f"/api/sources/{done}/enrich").status_code == 200
    drain_enrichment()

    e = c.get("/api/case").json()["enrichment"]
    counts = e["counts"]
    assert counts["raw"] == 1 and counts["skipped"] == 1 and counts["enriched"] == 1, e
    assert counts["queued"] == 0 and counts["enriching"] == 0 and counts["error"] == 0, e
    assert sum(counts.values()) == 3, "every source in the pool is in exactly one state"
    assert e["running"] == "", "nothing is in flight once the queue has drained"
    assert e["pending"] == 0, "pending is work IN FLIGHT — there is none"
    assert e["outstanding"] == 1, "one source is still raw, so timeline/graph/anomalies are incomplete"
    assert raw and done  # (named for readability of the states above)


def test_a_skipped_source_is_not_outstanding(c, manual) -> None:
    """A deliberate decline must not raise a warning that can never be cleared."""
    _wipe(c)
    sid = _upload(c, "noise.log")["id"]
    assert c.get("/api/case").json()["enrichment"]["outstanding"] == 1
    assert c.post(f"/api/sources/{sid}/enrich/skip").status_code == 200
    e = c.get("/api/case").json()["enrichment"]
    assert e["outstanding"] == 0 and e["pending"] == 0
    assert e["counts"]["skipped"] == 1


def test_queued_work_is_pending_and_outstanding(c, manual, paused) -> None:
    _wipe(c)
    sid = _upload(c, "waiting.log")["id"]
    assert c.post(f"/api/sources/{sid}/enrich").status_code == 200
    e = c.get("/api/case").json()["enrichment"]
    assert e["counts"]["queued"] == 1
    assert e["pending"] == 1, "there is work in flight"
    assert e["outstanding"] == 1, "and the answer is still incomplete"
    # tidy up: the queue was paused, so nothing would ever pick this up
    assert c.post(f"/api/sources/{sid}/enrich/skip").status_code == 200


class _CountingList(list):
    """A list that records every full iteration of itself (same device as test_derived_cache.py)."""

    def __init__(self, *a):
        super().__init__(*a)
        self.iterations = 0

    def __iter__(self):
        self.iterations += 1
        return super().__iter__()


def test_case_reports_enrichment_without_walking_the_event_pool(c, manual, monkeypatch) -> None:
    """GET /api/case must stay O(1) in the EVENT count.

    It took 15-20 s on a 2.5 M-event pool because it recounted parse coverage and distinct entities over
    every event on every request. The enrichment block is derived from `Source.enrich` — a few dozen
    entries — for exactly that reason, and this is the guard that keeps it that way.
    """
    _wipe(c)
    _upload(c, "counted.log")
    drain_enrichment()
    c.get("/api/case")           # warm the cached entity count for this version

    # settle: the entity count refreshes on a daemon thread, and its scan would be attributed to us
    deadline = time.time() + 15
    while time.time() < deadline:
        if not getattr(STORE, "_entities_busy", False) and STORE._entities_version == STORE.version:
            break
        time.sleep(0.05)

    counting = _CountingList(STORE.events)
    monkeypatch.setattr(STORE, "events", counting)
    for _ in range(3):
        body = c.get("/api/case").json()
        assert "enrichment" in body
    assert counting.iterations == 0, f"GET /api/case iterated the pool {counting.iterations}x"


# ------------------------------------------------------------------ settings.ingest.autoEnrich
def test_auto_enrich_round_trips_through_the_settings_api(c) -> None:
    try:
        assert c.get("/api/settings").json()["ingest"]["autoEnrich"] is True, "default is on"
        assert c.put("/api/settings", json={"ingest": {"autoEnrich": False}}).json()["ingest"]["autoEnrich"] is False
        assert c.get("/api/settings").json()["ingest"]["autoEnrich"] is False, "PUT must not be dropped"
        assert c.put("/api/settings", json={"ingest": {"autoEnrich": True}}).json()["ingest"]["autoEnrich"] is True
    finally:
        c.put("/api/settings", json={"ingest": {"autoEnrich": True}})


def test_auto_enrich_off_means_nothing_enriches_on_its_own(c, manual) -> None:
    sid = _upload(c, "left-alone.log")["id"]
    drain_enrichment()          # give any stray submission every chance to run
    assert _source(c, sid)["enrich"] == "raw", "an upload must not queue itself while autoEnrich is off"
    assert c.get("/api/case").json()["enrichment"]["counts"]["raw"] >= 1

    # and a restart does not quietly change its mind either
    with TestClient(app) as again:
        drain_enrichment()
        assert _source(again, sid)["enrich"] == "raw"


def test_auto_enrich_on_enriches_an_upload_by_itself(c) -> None:
    sid = _upload(c, "automatic.log")["id"]
    drain_enrichment()
    assert _source(c, sid)["enrich"] == "enriched"


def test_the_enrichment_status_says_what_is_running_and_what_needs_a_person(c) -> None:
    """`40 of 679 not interpreted · 1 running · 39 queued` was the analyst's complaint: it counts what
    is wrong, never says what is usable, and on a big pool the numbers move once a minute so it reads
    as frozen. The status now carries the running file with its live percentage, and separates work in
    flight (patience) from work only a person can move (a decision)."""
    from app.models import CaseEnrichment

    e = STORE.enrichment()
    assert isinstance(e, CaseEnrichment)
    for field in ("runningFile", "runningPct", "runningPhase", "runningEtaSec", "needsAction"):
        assert hasattr(e, field)
    # nothing running -> no half-filled detail claiming a file is being interpreted
    if not e.running:
        assert e.runningFile == "" and e.runningPct is None


def test_needs_action_counts_only_what_a_person_can_move(c) -> None:
    """A queued source needs patience; a raw source with nothing in flight needs a click. Conflating
    them is what made the banner unactionable."""
    from app import config

    config.update_settings({"ingest": {"autoEnrich": False}})
    try:
        c.post("/api/library/upload", files=[("files", ("needs-me.log", LOG, "text/plain"))])
        e = STORE.enrichment()
        if e.counts.raw:
            assert e.pending == 0
            assert e.needsAction >= e.counts.raw
    finally:
        config.update_settings({"ingest": {"autoEnrich": True}})
