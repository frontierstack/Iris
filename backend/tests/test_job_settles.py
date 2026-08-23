"""A transfer panel may only claim work is in flight when work is in flight.

Reported as "the parsing indicator spins a long time and says number in progress, but there's nothing
happening". Nothing was hanging. `ingest.autoEnrich` was off, so phase 2 is strictly on demand: seven
captures finished phase 1 with 11.2 M events already in the pool and searchable, every source settled at
`raw`, the enrichment queue empty — and `jobs.sync()` refused to resolve a job whose sources are `raw`,
so all seven stayed `parsing` forever with a synthesised 0 % bar underneath them.

`raw` means "phase 2 has not started". Whether that is WORK IN FLIGHT depends entirely on whether
anything is going to start it, and Iris already draws exactly this distinction for the analyst:
`CaseEnrichment.pending` (queued + enriching) is work in flight, `.outstanding` (plus raw) is "my answer
is incomplete". A job asks the first question.
"""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from app import config, jobs as jobs_mod
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


@pytest.fixture()
def auto_enrich_off():
    before = config.get_settings().ingest.autoEnrich
    config.update_settings({"ingest": {"autoEnrich": False}})
    yield
    config.update_settings({"ingest": {"autoEnrich": before}})


@pytest.fixture()
def auto_enrich_on():
    before = config.get_settings().ingest.autoEnrich
    config.update_settings({"ingest": {"autoEnrich": True}})
    yield
    config.update_settings({"ingest": {"autoEnrich": before}})


def _job(client, job_id: str) -> dict:
    rows = client.get("/api/jobs?limit=500").json()["jobs"]
    hit = [j for j in rows if j["id"] == job_id]
    assert hit, f"job {job_id} is not in the registry"
    return hit[0]


def test_a_raw_source_settles_its_job_when_nothing_will_enrich_it(c, auto_enrich_off) -> None:
    """The report. With phase 2 on demand, `raw` is a finished ingest waiting for a person — not a
    parse in progress, and never a 0 % bar that runs for hours."""
    job = c.post("/api/jobs", json={"files": [{"file": "settles.log", "size": len(LOG)}],
                                    "target": "library"}).json()["jobs"][0]
    r = c.post(f"/api/library/upload?jobIds={job['id']}",
               files=[("files", ("settles.log", LOG, "text/plain"))])
    assert r.status_code == 200, r.text

    row = _job(c, job["id"])
    assert row["state"] == "ready", f"the job never settled: {row}"
    assert row["events"] == 30
    # and the source really is still un-interpreted — the job settling is not a claim that it was
    sid = row["sourceIds"][0]
    assert STORE.sources[sid].enrich == "raw"


def test_a_queued_source_still_holds_its_job_open(c, auto_enrich_on) -> None:
    """The guarantee that must not be lost: phase 2 IS coming, so the job may not report success until
    it lands. A parse that fails in phase 2 arriving after "ready" is the whole reason jobs exist."""
    job = REGISTRY.create("holding.log", 100, "library", "")
    sid = "s-queued-1"
    with STORE.lock:
        from app.models import Source

        STORE.sources[sid] = Source(id=sid, file="holding.log", parser="syslog", state="READY",
                                    size=100, events=3, origin="library", enrich="queued")
        STORE.source_order.append(sid)
        STORE.source_origin[sid] = "library"
    REGISTRY.begin_parse(job.id, 100)
    REGISTRY.attach_sources(job.id, [sid])
    try:
        assert _job(c, job.id)["state"] == "parsing"
        with STORE.lock:
            STORE.sources[sid].enrich = "enriching"
        assert _job(c, job.id)["state"] == "parsing"
        with STORE.lock:
            STORE.sources[sid].enrich = "enriched"
        assert _job(c, job.id)["state"] == "ready"
    finally:
        with STORE.lock:
            STORE.sources.pop(sid, None)
            STORE.source_origin.pop(sid, None)
            if sid in STORE.source_order:
                STORE.source_order.remove(sid)


def test_with_auto_enrich_on_a_raw_source_still_waits(c, auto_enrich_on) -> None:
    """`raw` with autoEnrich ON is the split second between the lines landing and the queue taking
    them. Resolving there would report a finished ingest before phase 2 had a chance to fail."""
    job = REGISTRY.create("about-to-queue.log", 100, "library", "")
    sid = "s-raw-on-1"
    with STORE.lock:
        from app.models import Source

        STORE.sources[sid] = Source(id=sid, file="about-to-queue.log", parser="syslog", state="READY",
                                    size=100, events=3, origin="library", enrich="raw")
        STORE.source_order.append(sid)
        STORE.source_origin[sid] = "library"
    REGISTRY.begin_parse(job.id, 100)
    REGISTRY.attach_sources(job.id, [sid])
    try:
        assert _job(c, job.id)["state"] == "parsing"
    finally:
        with STORE.lock:
            STORE.sources.pop(sid, None)
            STORE.source_origin.pop(sid, None)
            if sid in STORE.source_order:
                STORE.source_order.remove(sid)


def test_a_parsing_job_stops_showing_a_zero_percent_bar_nobody_is_producing(c, monkeypatch) -> None:
    """The other half of "there's nothing happening": a `parsing` job with no tracker row synthesised
    `pct: 0.0`. Brief, that is the honest gap before the parse thread registers; unbounded, it is a
    progress bar for work that does not exist."""
    job = REGISTRY.create("placeholder.log", 5_000_000, "library", "")
    REGISTRY.begin_parse(job.id, 5_000_000)
    fresh = _job(c, job.id)
    assert fresh["progress"] is not None and fresh["progress"]["pct"] == 0.0

    monkeypatch.setattr(jobs_mod, "PROGRESS_PLACEHOLDER_SEC", -1)
    aged = _job(c, job.id)
    assert aged["state"] == "parsing"
    assert aged["progress"] is None, "a 0 % bar outlived the moment it was honest for"


def test_a_real_parse_still_reports_progress(c) -> None:
    """The placeholder timing out must never suppress a REAL tracker row."""
    from app.jobs import PARSE_PROGRESS

    job = REGISTRY.create("real.log", 1000, "library", "")
    REGISTRY.begin_parse(job.id, 1000)
    REGISTRY.attach_sources(job.id, ["s-real-1"])
    PARSE_PROGRESS.start("s-real-1", "real.log", 1000)
    PARSE_PROGRESS.advance("s-real-1", done=400, events=12, phase="reading")
    try:
        row = _job(c, job.id)
        assert row["progress"]["pct"] == pytest.approx(40.0, abs=0.2)
        assert row["progress"]["events"] == 12
    finally:
        PARSE_PROGRESS.finish("s-real-1")
