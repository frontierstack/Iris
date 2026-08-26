"""Real parse progress, parallel parsing, and an index warm that never blocks a query.

Three analyst reports, one theme — a long operation with no feedback reads as a hang:

  1. "I see one log is still parsing and unsure of its progress." The job registry only knew the coarse
     state `parsing`, so a 263 MB CSV sat there for ten minutes looking dead.
  2. `GET /api/case` took ~15-20 s on a big pool, at rest as well as during ingest, because it re-counted
     parse coverage and distinct entities over every event on every single request.
  3. A search right after a big ingest never came back: the vectorised index was being built ON the
     request thread, under the index lock.

The correctness test that matters most is `test_parallel_and_single_worker_agree`: event ids are
load-bearing (case sets reference them), so the multi-process path has to produce byte-identical output.
"""
from __future__ import annotations

import threading
import time

import numpy as np
import pytest
from fastapi.testclient import TestClient

from app import search as search_mod
from app.jobs import PARSE_PROGRESS, REGISTRY
from app.main import app
from app.parsers import parallel as par
from app.models import Source
from app.store import STORE, Store

from tests.conftest import drain_enrichment


def _csv(rows: int, start: int = 0) -> bytes:
    head = b"timestamp,host,action,src,dst,proto,bytes,user\n"
    out = [head]
    for i in range(start, start + rows):
        n = i % 1000
        out.append(
            f"2026-03-01T{(i // 3600) % 24:02d}:{(i // 60) % 60:02d}:{i % 60:02d},"
            f"fw-edge-0{n % 3},{'allow' if i % 2 else 'deny'},"
            f"10.0.{n % 250}.{(i * 7) % 250}:{1024 + n},192.168.1.{n % 200}:443,tcp,"
            f"{1000 + n},user{n % 17}\n".encode())
    return b"".join(out)


# ------------------------------------------------------------------ 3. parallel == single worker
@pytest.mark.parametrize("workers", [2, 4])
def test_parallel_and_single_worker_agree(tmp_path, monkeypatch, workers: int) -> None:
    """Same file, same events: count, ORDER, ids, timestamps, severities and entities all identical.

    Ids follow record order and only then is the list sorted (stable), which is the whole reason the
    chunked path can be trusted — a case set that references `e12ab` must still mean the same line.
    """
    data = _csv(6000)
    monkeypatch.setenv("IRIS_PARSE_MIN_MB", "0.05")   # force the parallel path on a small file
    monkeypatch.setenv("IRIS_PARSE_CHUNK_MB", "0.06")  # …split into many chunks

    def digest(nworkers: int) -> list[tuple]:
        monkeypatch.setenv("IRIS_PARSE_WORKERS", str(nworkers))
        st = Store()
        st.pending = False
        path = tmp_path / f"w{nworkers}.csv"
        path.write_bytes(data)
        with st.bulk_load():
            st.add_file("flows.csv", data, background_ok=False, sid="aaaa1111", path=path)
        assert st.sources["aaaa1111"].state in ("READY", "REVIEW"), st.sources["aaaa1111"].error
        return [(e.id, e.ts, e.sev, e.msg, e.host, e.user, tuple(e.entities), e.raw) for e in st.events]

    one = digest(1)
    many = digest(workers)
    assert len(one) == len(many) > 5000
    assert one == many, "the parallel path must reproduce the single-worker events exactly"


def test_the_parallel_path_is_actually_taken(tmp_path, monkeypatch) -> None:
    """Guard against the test above passing because parallelism silently never engaged."""
    monkeypatch.setenv("IRIS_PARSE_MIN_MB", "0.05")
    monkeypatch.setenv("IRIS_PARSE_CHUNK_MB", "0.06")
    monkeypatch.setenv("IRIS_PARSE_WORKERS", "3")
    from app.parsers.csv import CsvParser

    plan = par.prepare(CsvParser(), _csv(6000))
    assert plan is not None, "a chunkable parser over a big enough file must produce a plan"
    assert len(plan[0].ranges) > 2 and plan[0].workers > 1
    assert plan[0].head_records > 0


def test_small_files_and_unchunkable_parsers_stay_single_worker(monkeypatch) -> None:
    from app.parsers.csv import CsvParser
    from app.parsers.jsonl import JsonlParser

    monkeypatch.setenv("IRIS_PARSE_WORKERS", "4")
    monkeypatch.delenv("IRIS_PARSE_MIN_MB", raising=False)
    assert par.prepare(CsvParser(), _csv(6000)) is None, "a small file must not pay for a process pool"
    monkeypatch.setenv("IRIS_PARSE_MIN_MB", "0.05")
    # jsonl accumulates multi-line documents, so a byte-range chunk could split a record
    assert JsonlParser().chunkable is False
    assert par.prepare(JsonlParser(), _csv(6000)) is None


def test_chunk_boundaries_respect_quoted_newlines() -> None:
    """A CSV cell may contain a newline inside quotes — a chunk must never start in the middle of one."""
    data = b'a,b\n1,"x\ny"\n2,"p\nq"\n3,plain\n' * 40
    ranges = par._chunk_ranges(data, 0, 16, quoted=True)
    assert ranges[0][0] == 0 and ranges[-1][1] == len(data)
    for start, end in ranges:
        assert data[:start].count(b'"') % 2 == 0, "a chunk began inside a quoted cell"
        assert start == 0 or data[start - 1:start] == b"\n"


# ------------------------------------------------------------------ 1. visible parse progress
@pytest.fixture()
def c():
    with TestClient(app) as client:
        yield client


def test_progress_is_visible_from_another_request_and_reaches_100(c, monkeypatch) -> None:
    """A parse must be observable — with real numbers — from a request other than the one that started it.

    Ingest is two phases now (app/enrich.py) and both publish into PARSE_PROGRESS: phase 1 ticks
    `reading` while it splits the file into raw lines, phase 2 ticks while the parser and the
    normalization run on the enrichment worker. Two things follow, and this test pins both:

      * `jobs.PROGRESS_EVERY_RECORDS` is the cadence for BOTH phases — one knob, read at call time by
        `enrich.raw_events` and by `store._parse_source`. It was two constants that had to be kept in
        step by hand, and turning only one of them down is why this test once read "progress never
        advanced past zero";
      * what CROSSES the API is `Job.live()`. It merges the tracker rows of the job's sourceIds, and
        the job only learns those when the ingest request returns — so phase 1 is covered by the
        registry ADOPTING an unclaimed tracker row by file name (`JobRegistry._adopt_locked`, pinned by
        `test_raw_phase_progress_is_visible_before_the_job_learns_its_source_ids`), and phase 2 by the
        source ids themselves. This test watches phase 2, the long one, on the worker.
    """
    monkeypatch.setattr("app.store.SYNC_LIMIT", 1)      # force the threaded path where one is taken
    monkeypatch.setattr("app.jobs.PROGRESS_EVERY_RECORDS", 200)
    data = _csv(9000)
    jid = c.post("/api/jobs", json={"files": [{"file": "flows.csv", "size": len(data)}], "target": "case"}
                 ).json()["jobs"][0]["id"]

    seen: list[dict] = []
    stop = threading.Event()
    # Deterministic hand-off. Asserting "the poller saw progress" is otherwise a race: a 9000-row parse
    # can finish inside a single 10 ms poll gap, which it does whenever the rest of the suite is competing
    # for CPU. So the worker blocks on its first OBSERVABLE tick until the poller has actually seen one.
    # One-shot (`handshook`), so a poller that never sees anything costs one timeout rather than one per
    # tick, and the assertions below still fail honestly instead of hanging.
    observed, handshook = threading.Event(), threading.Event()
    _real_advance = PARSE_PROGRESS.advance
    published: list[dict] = []          # every tick as the TRACKER saw it, both phases

    def _advance(key, **kw):  # type: ignore[no-untyped-def]
        _real_advance(key, **kw)
        row = PARSE_PROGRESS.get(key)
        if not row:
            return
        published.append(row)
        # phase 2 is the half a second tab can see (the job carries the source id by then)
        if row["phase"] == "enriching" and row["bytesDone"] > 0 and not handshook.is_set():
            observed.wait(timeout=10)
            handshook.set()

    monkeypatch.setattr(PARSE_PROGRESS, "advance", _advance)

    def poll() -> None:
        # a SEPARATE client — a different connection entirely, which is the point: this is server-side
        # state, not something the uploading tab is holding on to. No `with`: running the lifespan again
        # would reconcile the very job we are watching into `interrupted`.
        other = TestClient(app)
        while not stop.is_set():
            for j in other.get("/api/jobs").json()["jobs"]:
                if j["id"] == jid and j["state"] == "parsing" and j["progress"]:
                    seen.append(j["progress"])
                    if j["progress"]["bytesDone"] > 0:
                        # release the worker only once a NON-ZERO reading has actually crossed the API:
                        # `Job.live()` publishes a 0 % placeholder as soon as a job starts parsing, and
                        # releasing on that let the whole parse finish inside the next poll gap
                        observed.set()
            time.sleep(0.01)

    watcher = threading.Thread(target=poll, daemon=True)
    watcher.start()
    r = c.post(f"/api/sources?jobIds={jid}", files=[("files", ("flows.csv", data, "text/csv"))])
    assert r.status_code == 200, r.text
    drain_enrichment()          # the job only resolves once phase 2 has run — see jobs.sync
    deadline = time.time() + 30
    while time.time() < deadline:
        job = [j for j in c.get("/api/jobs").json()["jobs"] if j["id"] == jid][0]
        if job["state"] in ("ready", "error"):
            break
        time.sleep(0.05)
    stop.set()
    watcher.join(timeout=5)

    assert job["state"] == "ready", job.get("error")
    assert job["events"] > 0
    assert seen, "no in-flight progress was ever visible to another request"
    for p in seen:
        assert p["bytesTotal"] == len(data)
        assert 0 <= p["pct"] <= 100
    assert max(p["bytesDone"] for p in seen) > 0, "progress never advanced past zero"
    # both phases published real numbers, and the file was never presented as parsed while it was not
    assert "reading" in {p["phase"] for p in published}, "the raw phase never published progress"
    assert "enriching" in {p["phase"] for p in seen}, "phase 2 was invisible to another request"
    # it has to REACH 100, not stop at the last cadence tick — an ingest that finishes at 97 % is the
    # same "is it hung?" question as one with no bar at all
    assert max(p["pct"] for p in published) == 100.0, "progress never reached 100 %"
    # …and once it is done the live progress is gone, not stuck at 99 %
    assert PARSE_PROGRESS.get(job["sourceIds"][0]) is None


def test_raw_phase_progress_is_visible_before_the_job_learns_its_source_ids(monkeypatch) -> None:
    """Phase 1 must be watchable from another request too — not only phase 2.

    A job learns its source ids from `_report`, which runs when the ingest request RETURNS. For the
    whole raw split it therefore has none, `Job.live()` had nothing to merge, and every other tab got
    the 0 % placeholder. That is milliseconds at 9 k rows and the entire "is it hung?" window on the
    analyst's 1.07 GB / 10 M-row CSV — the exact harm two-phase ingest exists to prevent, and CLAUDE.md
    lists live parse progress as one of two things that may never disappear from the Sources page.
    `JobRegistry._adopt_locked` closes it by matching an UNCLAIMED tracker row to the job by file name.

    Two things make this a real test rather than a lucky poll:
      * the file is big enough to publish at the SHIPPED cadence (`jobs.PROGRESS_EVERY_RECORDS` is NOT
        turned down here). A 30-line fixture passes against the placeholder-only code, because both the
        placeholder and the truth read zero;
      * the raw phase blocks on its first published tick until the poller has taken a reading, so the
        observation is genuinely mid-flight and the test cannot pass by finishing first.
    """
    data = _csv(60_000)                     # ~6.5 MB → three ticks at the shipped 20 000-record cadence
    assert len(data) > 4 * 1024 * 1024, "shrinking this file would stop it exercising the gap"
    st = Store()
    st.pending = False
    job = REGISTRY.create("flows.csv", len(data), "library", "")
    REGISTRY.begin_parse(job.id, len(data))     # exactly what the ingest routers do before they block

    released = threading.Event()
    _real_advance = PARSE_PROGRESS.advance

    def _advance(key, **kw):  # type: ignore[no-untyped-def]
        _real_advance(key, **kw)
        row = PARSE_PROGRESS.get(key)
        if row and row["phase"] == "reading" and row["bytesDone"] > 0:
            released.wait(timeout=20)

    monkeypatch.setattr(PARSE_PROGRESS, "advance", _advance)

    def ingest() -> None:
        with st.bulk_load():
            st.add_file("flows.csv", data, background_ok=False, sid="raw55555")

    worker = threading.Thread(target=ingest, daemon=True)
    worker.start()
    try:
        seen = None
        deadline = time.time() + 20
        while time.time() < deadline and seen is None:
            for row in REGISTRY.snapshot()["jobs"]:
                if row["id"] != job.id or row["state"] != "parsing":
                    continue
                if row["progress"] and row["progress"]["bytesDone"] > 0:
                    seen = row
            time.sleep(0.01)
    finally:
        released.set()
        worker.join(timeout=60)

    assert seen is not None, "the raw phase was invisible to another request — only the 0 % placeholder"
    assert not seen["sourceIds"], (
        "the job already carried its source ids, so this run did not exercise the phase-1 gap")
    p = seen["progress"]
    assert p["bytesTotal"] == len(data)
    assert 0 < p["pct"] < 100, p
    assert p["events"] > 0, p
    assert p["phase"] == "reading", p
    # a job the registry adopted a row for must never be RESOLVED by it: adoption is display only
    assert seen["state"] == "parsing"
    REGISTRY.fail(job.id, "test cleanup")       # never leave a `parsing` job for the next test to adopt


def test_adopted_progress_is_never_double_counted_and_never_persisted() -> None:
    """The safety rules around adoption, without going near the store.

    Matching a tracker row to a job by file name is a GUESS, so it is fenced: a row another job already
    owns is off limits (its bytes belong to that job's file), one row is shown under at most one job,
    and nothing is written to `sourceIds` — which is what keeps `sync()`, `reconcile()` and jobs.json
    out of it, so a wrong guess can never resolve a job or report a parse that failed as ready.
    """
    a = REGISTRY.create("dup.log", 100, "library", "")
    b = REGISTRY.create("dup.log", 100, "library", "")
    owner = REGISTRY.create("dup.log", 100, "library", "")
    for j in (a, b, owner):
        REGISTRY.begin_parse(j.id, 100)
    REGISTRY.attach_sources(owner.id, ["owned1"])
    PARSE_PROGRESS.start("owned1", "dup.log", 100)
    PARSE_PROGRESS.advance("owned1", done=40, events=4)
    PARSE_PROGRESS.start("free1", "dup.log", 100)
    PARSE_PROGRESS.advance("free1", done=10, events=1)
    try:
        rows = {r["id"]: r for r in REGISTRY.snapshot()["jobs"]}
        got = [r for r in (rows[a.id], rows[b.id]) if r["progress"] and r["progress"]["bytesDone"] > 0]
        assert len(got) == 1, "one tracker row was displayed under two different jobs"
        assert got[0]["progress"]["bytesDone"] == 10, "a row another job already owns was adopted"
        assert rows[owner.id]["progress"]["bytesDone"] == 40, "the owning job lost its own progress"
        assert not rows[a.id]["sourceIds"] and not rows[b.id]["sourceIds"], "adoption wrote sourceIds"
        assert all(rows[j.id]["state"] == "parsing" for j in (a, b, owner))
    finally:
        PARSE_PROGRESS.finish("owned1")
        PARSE_PROGRESS.finish("free1")
        for j in (a, b, owner):
            REGISTRY.fail(j.id, "test cleanup")


def test_progress_advances_over_time(monkeypatch) -> None:
    """The number must MOVE while a single big file parses, not jump from 0 to 100 — and it must be
    readable from a DIFFERENT thread while the parse holds the interpreter.

    This is the RAW phase (phase 1 of app/enrich.py): what a text log spends its ingest request in, and
    on a gigabyte it is minutes of work, so it publishes on the tracker's cadence
    (`jobs.PROGRESS_EVERY_RECORDS` records) exactly as the old single-phase parse did. Phase 1 is far
    cheaper per line than the parse it replaced, so a 20 000-row file can now go by inside one 5 ms poll
    gap under load: each of the
    first few ticks therefore waits for the watcher to actually take a reading. Without that hand-off
    this test asserts nothing more than "the machine was not busy".
    """
    monkeypatch.setattr("app.jobs.PROGRESS_EVERY_RECORDS", 100)   # one knob, and it governs phase 1 too
    data = _csv(20000)
    st = Store()
    st.pending = False
    samples: list[int] = []
    phases: set[str] = set()
    stop = threading.Event()

    def watch() -> None:
        while not stop.is_set():
            p = PARSE_PROGRESS.get("bbbb2222")
            if p:
                samples.append(p["bytesDone"])
                phases.add(p["phase"])
            time.sleep(0.005)

    _real_advance = PARSE_PROGRESS.advance
    ticks = {"n": 0}

    def _advance(key, **kw):  # type: ignore[no-untyped-def]
        _real_advance(key, **kw)
        ticks["n"] += 1
        if ticks["n"] <= 3:                      # hand the first few ticks to the watcher
            was = len(samples)
            deadline = time.time() + 5
            while len(samples) == was and time.time() < deadline:
                time.sleep(0.002)

    monkeypatch.setattr(PARSE_PROGRESS, "advance", _advance)

    w = threading.Thread(target=watch, daemon=True)
    w.start()
    with st.bulk_load():
        st.add_file("flows.csv", data, background_ok=False, sid="bbbb2222")
    stop.set()
    w.join(timeout=5)
    assert ticks["n"] > 2, "the parse published progress fewer than three times"
    assert len(set(samples)) > 1, f"progress never changed while parsing ({samples[:5]})"
    assert max(samples) <= len(data)
    assert "reading" in phases, f"the raw phase never named itself ({phases})"


def test_pool_progress_reports_bytes_not_just_a_file_count() -> None:
    st = Store()
    st.pool_loading = True
    st.pool_bytes_total = 300_000_000
    st.pool_bytes_done = 75_000_000
    st.pool_loaded, st.pool_pending = 3, 5
    st.pool_started_ts = time.time() - 10
    p = st._pool_progress()
    assert p is not None
    assert p.bytesTotal == 300_000_000 and p.bytesDone == 75_000_000
    assert p.pct == 25.0 and p.filesDone == 3 and p.filesTotal == 8
    assert p.bytesPerSec > 0 and p.etaSec is not None
    st.pool_loading = False
    assert st._pool_progress() is None


# ------------------------------------------------------------------ 2. /api/case stays responsive
# ------------------------------------------------- the Sources table's own progress
# "When a log is parsing, all that happens is a spinner but there is no % indicator." The numbers were
# already there — jobs.PARSE_PROGRESS is keyed by SOURCE id and has been feeding the transfer panel all
# along — but nothing carried them onto the source rows, which is where a parse is actually watched:
# the transfer row ages out 20 s after the upload resolves, and phase 2 then runs for another twenty
# minutes on a big capture with `Source.state` sitting at READY the whole time.
def test_a_parsing_source_carries_its_own_progress(c) -> None:
    src_id, other_id = "s-parsing-1", "s-done-1"
    PARSE_PROGRESS.start(src_id, "huge.pcap", 209_236_002)
    PARSE_PROGRESS.advance(src_id, done=52_309_000, events=180_000, phase="reading")
    # a tracker row can outlive the work by a moment; a finished source must never show a live percentage
    PARSE_PROGRESS.start(other_id, "settled.log", 1000)
    PARSE_PROGRESS.advance(other_id, done=1000, events=10)
    try:
        with STORE.lock:
            STORE.sources[src_id] = Source(id=src_id, file="huge.pcap", parser="pcap", state="PARSING",
                                           size=209_236_002, origin="library", enrich="raw")
            STORE.sources[other_id] = Source(id=other_id, file="settled.log", parser="syslog", state="READY",
                                             size=1000, events=10, origin="library", enrich="enriched")
            STORE.source_order.extend([src_id, other_id])
            STORE.source_origin[src_id] = "library"
            STORE.source_origin[other_id] = "library"

        rows = {s["id"]: s for s in c.get("/api/case").json()["librarySources"]}
        prog = rows[src_id]["progress"]
        assert prog is not None, "a PARSING source must report how far along it is"
        assert prog["pct"] == pytest.approx(25.0, abs=0.2)
        assert prog["events"] == 180_000 and prog["phase"] == "reading"
        assert prog["bytesTotal"] == 209_236_002
        assert rows[other_id]["progress"] is None, "a settled source must not claim live progress"
    finally:
        PARSE_PROGRESS.finish(src_id)
        PARSE_PROGRESS.finish(other_id)
        with STORE.lock:
            for sid in (src_id, other_id):
                STORE.sources.pop(sid, None)
                STORE.source_origin.pop(sid, None)
                if sid in STORE.source_order:
                    STORE.source_order.remove(sid)


def test_a_source_in_phase_two_carries_its_progress_too(c) -> None:
    """Phase 2 is where a big file spends its time, and `state` stays READY throughout it — so the
    percentage has to ride on the source whose ENRICH state is 'enriching', not only on 'PARSING'."""
    src_id = "s-enriching-1"
    PARSE_PROGRESS.start(src_id, "flows.csv", 400_000)
    PARSE_PROGRESS.advance(src_id, done=300_000, events=900_000, phase="enriching")
    try:
        with STORE.lock:
            STORE.sources[src_id] = Source(id=src_id, file="flows.csv", parser="csv", state="READY",
                                           size=400_000, origin="library", enrich="enriching")
            STORE.source_order.append(src_id)
            STORE.source_origin[src_id] = "library"
        row = {s["id"]: s for s in c.get("/api/case").json()["librarySources"]}[src_id]
        assert row["progress"]["phase"] == "enriching"
        assert row["progress"]["pct"] == pytest.approx(75.0, abs=0.2)
    finally:
        PARSE_PROGRESS.finish(src_id)
        with STORE.lock:
            STORE.sources.pop(src_id, None)
            STORE.source_origin.pop(src_id, None)
            if src_id in STORE.source_order:
                STORE.source_order.remove(src_id)


def test_attaching_progress_never_mutates_the_stored_source(c) -> None:
    """It is attached to a COPY. Stamping the percentage onto `STORE.sources` would leave a finished
    file claiming 84 % for the rest of the process's life — and that number is never persisted."""
    src_id = "s-copy-1"
    PARSE_PROGRESS.start(src_id, "x.log", 100)
    PARSE_PROGRESS.advance(src_id, done=84, events=7)
    try:
        with STORE.lock:
            STORE.sources[src_id] = Source(id=src_id, file="x.log", parser="syslog", state="PARSING",
                                           size=100, origin="library", enrich="raw")
            STORE.source_order.append(src_id)
            STORE.source_origin[src_id] = "library"
        assert c.get("/api/case").json()["librarySources"][-1]["progress"]["pct"] > 0
        with STORE.lock:
            assert STORE.sources[src_id].progress is None
    finally:
        PARSE_PROGRESS.finish(src_id)
        with STORE.lock:
            STORE.sources.pop(src_id, None)
            STORE.source_origin.pop(src_id, None)
            if src_id in STORE.source_order:
                STORE.source_order.remove(src_id)


def test_case_endpoint_does_not_rescan_the_pool(c, monkeypatch) -> None:
    """The two O(events) scans in case() are gone: coverage is a per-source tally and the distinct
    entity count is cached. Both used to run, under the store lock, on every poll."""
    data = _csv(4000)
    assert c.post("/api/sources", files=[("files", ("flows.csv", data, "text/csv"))]).status_code == 200
    # Phase 2 replaces this source's events and bumps the version. Left running, it moves the version
    # under the assertion below and /api/case legitimately re-counts — measuring "does the endpoint
    # rescan the pool" while the pool is being rewritten measures nothing.
    drain_enrichment()
    first = c.get("/api/case").json()          # may kick off the entity refresh
    assert first["poolEventCount"] >= 4000
    STORE._entity_count()                      # let the background refresh settle
    for _ in range(50):
        if STORE._entities_version == STORE.version:
            break
        time.sleep(0.05)

    scans = {"n": 0}
    real_events = STORE.events

    class _CountingList(list):
        def __iter__(self):
            scans["n"] += 1
            return super().__iter__()

    monkeypatch.setattr(STORE, "events", _CountingList(real_events))
    body = c.get("/api/case").json()
    monkeypatch.setattr(STORE, "events", real_events)
    assert body["poolEventCount"] == len(real_events)
    assert scans["n"] == 0, f"/api/case still walks every event ({scans['n']} full scans)"


def test_parse_coverage_still_reports_unparsed_lines(c) -> None:
    """The incremental tally has to agree with what the scan used to say."""
    good = _csv(500)
    bad = good + b"\x00\x01\x02 not a row at all\n"
    assert c.post("/api/sources", files=[("files", ("mixed.log", bad, "text/plain"))]).status_code == 200
    case = c.get("/api/case").json()
    coverage = [p for p in case["posture"] if p["label"] == "Parse coverage"][0]
    expected = 100.0 * (len(STORE.events) - sum(STORE.source_parse_errors.values())) / max(1, len(STORE.events))
    assert abs(coverage["pct"] - round(expected, 1)) < 0.2
    scanned = 100.0 * sum(1 for e in STORE.events if "parse_error" not in e.fields) / max(1, len(STORE.events))
    assert abs(coverage["pct"] - round(scanned, 1)) < 0.2, "the tally disagrees with a real scan"


# ------------------------------------------------------------------ the index never blocks a query
def _events_for_index(n: int):
    from app.models import Event

    evs = [Event(id=f"e{i}", ts="2026-03-01T00:00:00Z", source="syslog", sourceId="s1", file="f",
                 host="h", user="u", msg=f"line {i} needle-{i % 7}", sev="info", raw=f"line {i} needle-{i % 7}",
                 fields={}, entities=[], detections=[]) for i in range(n)]
    return evs, np.zeros(n, dtype=np.float64)


def test_search_never_builds_the_index_on_the_request_path(monkeypatch) -> None:
    """The 60 s "hang": the first query after a big ingest built the whole index inline, holding the lock."""
    events, ts = _events_for_index(3000)
    search_mod.invalidate()
    built = {"n": 0}
    real = search_mod.build_index

    def counting(*a, **kw):
        built["n"] += 1
        return real(*a, **kw)

    monkeypatch.setattr(search_mod, "build_index", counting)
    monkeypatch.setattr(search_mod, "warm_async", lambda *a, **kw: None)  # no background build either
    res = search_mod.search(events, ts, 4242, "needle-3", 0, len(events), set(), set(), 0, 10)
    assert built["n"] == 0, "the request thread built the index"
    assert res["engine"] == "cpu", "with no index the query must scan and answer, not block"
    assert res["total"] == sum(1 for e in events if "needle-3" in e.raw) > 0
    assert res["index"]["state"] in ("idle", "building")
    search_mod.invalidate()


def test_the_index_reports_that_it_is_warming(monkeypatch) -> None:
    events, ts = _events_for_index(3000)
    search_mod.invalidate()
    assert search_mod.index_status()["state"] == "idle"
    search_mod.get_index(events, ts, 4243)
    st = search_mod.index_status()
    assert st["state"] == "ready" and st["pct"] == 100.0 and st["bytes"] > 0
    res = search_mod.search(events, ts, 4243, "needle-3", 0, len(events), set(), set(), 0, 10)
    assert res["engine"] in ("vector", "cuda") and res["index"]["state"] == "ready"
    search_mod.invalidate()


def test_a_search_response_carries_the_index_state(c) -> None:
    c.post("/api/sources", files=[("files", ("flows.csv", _csv(300), "text/csv"))])
    body = c.get("/api/events?q=allow&limit=1").json()
    assert "index" in body and body["index"]["state"] in ("idle", "building", "ready")
    assert body["engine"] in ("cpu", "vector", "cuda")


# --------------------------------------------------------------------- parse throughput accounting
def test_throughput_moves_while_a_file_is_being_parsed_not_only_when_it_finishes():
    """`events/s` was credited once per FINISHED file, so a 1.1 GB CSV read 0 events/s for minutes and
    then claimed ten million in one 2 s sample. The analyst watching a big ingest sees the number that
    answers "is it hung?", so it has to move while the file is being read."""
    from app import jobs, metrics

    metrics.record_progress("", 0, 0)                     # no-op, and proves an empty key is ignored
    before = metrics.sample_once()["totalParsedEvents"]

    jobs.PARSE_PROGRESS.start("src-a", "big.csv", total=1_000)
    jobs.PARSE_PROGRESS.advance("src-a", done=100, events=40)
    mid = metrics.sample_once()
    assert mid["totalParsedEvents"] == before + 40
    assert mid["eventsPerSec"] > 0                         # it moved WITHOUT the file finishing

    jobs.PARSE_PROGRESS.advance("src-a", done=400, events=160)
    assert metrics.sample_once()["totalParsedEvents"] == before + 160   # the DELTA, not 40 + 160

    metrics.finish_progress("src-a", 175, 1_000)           # the tail the ticks never reached
    jobs.PARSE_PROGRESS.finish("src-a")
    assert metrics.sample_once()["totalParsedEvents"] == before + 175


def test_a_second_pass_over_the_same_source_is_credited_as_new_work():
    """Phase 2 re-parses a source the raw phase already counted: its running total restarts at zero,
    which must re-baseline rather than credit a negative delta and make the counter go backwards."""
    from app import metrics

    start = metrics.sample_once()["totalParsedEvents"]
    metrics.record_progress("src-b", 500, 5_000)
    metrics.record_progress("src-b", 10, 100)              # phase 2 begins again from the top
    metrics.record_progress("src-b", 90, 900)
    total = metrics.sample_once()["totalParsedEvents"]
    assert total == start + 500 + 90
    metrics.finish_progress("src-b", 90, 900)
    assert metrics.sample_once()["totalParsedEvents"] == total


def test_a_source_that_never_ticks_is_still_credited_in_full():
    """A file too small to reach the publish cadence produces no ticks at all."""
    from app import metrics

    start = metrics.sample_once()["totalParsedEvents"]
    metrics.finish_progress("src-c", 7, 700)
    assert metrics.sample_once()["totalParsedEvents"] == start + 7


def test_repeated_field_strings_are_shared_within_a_batch():
    """A log repeats its column names on every row and its interesting columns are mostly
    low-cardinality — method, status, action, verdict. Without sharing, a million rows of a 20-column
    export allocate twenty million string objects that are mostly the same handful of values, at ~49
    bytes of object header each before a single character. Measured: 3,377 -> 2,941 bytes per event.

    Sharing is per BATCH and never `sys.intern`: interning is immortal, so a high-cardinality column
    (a URL, a request id) would turn it into a leak.
    """
    from app.store import STORE

    rows = [b"ts,method,status,host,url"]
    for i in range(400):
        rows.append(f"2026-08-19T10:00:{i % 60:02d}Z,GET,200,web-{i % 3},https://example.com/p/{i}".encode())
    STORE.add_file("shared.csv", b"\n".join(rows) + b"\n", background_ok=False)
    sid = next(s for s, src in STORE.sources.items() if src.file == "shared.csv")
    if STORE.sources[sid].enrich in ("raw", "queued"):
        STORE.enrich_source(sid)

    events = [e for e in STORE.events if e.sourceId == sid and e.fields]
    assert len(events) > 100

    keys = {id(k) for e in events for k in e.fields}
    assert len(keys) <= 8, f"{len(keys)} distinct key objects for a handful of column names"

    methods = {id(e.fields["method"]) for e in events if "method" in e.fields}
    assert len(methods) == 1, "every row says GET; that should be one string object, not four hundred"

    # ...and a value that really is unique per row is NOT forced into the cache forever
    urls = {id(e.fields["url"]) for e in events if "url" in e.fields}
    assert len(urls) > 100, "unique values should not be pretending to be shared"


# --------------------------------------------------------------- the bar must actually move
# "the parsing indicator in sources ... it's just showing as 0%". Progress was published ONLY on
# `n % PROGRESS_EVERY_RECORDS == 0` (20,000), so a 5,000-line file never reached the modulo and
# published NOTHING between start and done: the bar read 0 % for the whole parse and then jumped to
# complete. A 25,000-line file ticked exactly once, at 80 %. On a library of 617 mostly-small files
# that is every file. Bytes are what `pct` is computed from, so the cadence steps in bytes too.
#
# Driven through a fresh Store like its neighbours above, at the SHIPPED cadence: nothing here turns
# PROGRESS_EVERY_RECORDS down, because the whole point is that the record count alone never fires.
def _mid_parse_pcts(monkeypatch, rows: int) -> list[float]:
    data = _csv(rows)
    seen: list[float] = []
    real = PARSE_PROGRESS.advance

    def _advance(key, **kw):  # type: ignore[no-untyped-def]
        real(key, **kw)
        row = PARSE_PROGRESS.get(key)
        if row and row["bytesTotal"] and row["phase"] != "merging" and 0 < row["pct"] < 100:
            seen.append(row["pct"])

    monkeypatch.setattr(PARSE_PROGRESS, "advance", _advance)
    st = Store()
    st.pending = False
    with st.bulk_load():
        st.add_file(f"bar{rows}.csv", data, background_ok=False, sid=f"bar{rows}")
    return seen


@pytest.mark.parametrize("rows", [5_000, 25_000])
def test_a_small_file_publishes_real_progress_not_just_zero(rows, monkeypatch) -> None:
    pcts = _mid_parse_pcts(monkeypatch, rows)
    assert len(pcts) >= 5, (
        f"{rows} rows published only {len(pcts)} mid-parse update(s) {pcts}: the bar sits at 0 % for "
        f"the whole parse. Progress must not depend on a record count alone.")
    # It has to MOVE, not merely exist: a run of identical values is the same blank bar.
    assert len(set(pcts)) >= 5, f"progress did not advance: {pcts}"
    assert max(pcts) > 50.0, f"progress never passed halfway before completion: {pcts}"
    assert pcts == sorted(pcts), f"progress went backwards: {pcts}"


def test_the_publish_cadence_scales_with_the_file() -> None:
    """~100 publishes whatever the size, with a floor so a small file still moves and a big one does
    not take the tracker lock per record."""
    from app.jobs import progress_step

    assert progress_step(400 * 1024) == 32 * 1024, "a small file needs the floor, not total//100"
    for size in (5 << 20, 50 << 20, 1024 << 20):
        publishes = size // progress_step(size)
        assert 50 <= publishes <= 150, f"{size >> 20} MB would publish {publishes} times"


def _csv_multiline(rows: int) -> bytes:
    """A CSV whose message column carries an embedded newline — an ordinary export shape (any log with
    a stack trace, a request body or a multi-line message in a column looks like this)."""
    out = [b"timestamp,host,message\n"]
    for i in range(rows):
        out.append(('2026-03-01T00:00:%02d,h%d,"first part\nsecond part %d"\n'
                    % (i % 60, i % 3, i)).encode())
    return b"".join(out)


def _head_slice_by_lines(data: bytes):
    """The pre-fix head: newline counting only, quote parity ignored."""
    lines, pos = 0, 0
    limit = min(len(data), par.HEAD_MAX_BYTES)
    while pos < limit and lines < par.HEAD_LINES:
        nl = data.find(b"\n", pos)
        if nl < 0:
            return None
        if data[pos:nl].strip():
            lines += 1
        pos = nl + 1
    return (pos, lines) if lines >= par.HEAD_LINES else None


def _chunked_records(data: bytes, head_slice) -> list[str]:
    """Every record the CHUNKED path yields, the way `_run_chunk` yields it: each worker parses
    `head + chunk` from a pristine parser and discards the records the head alone produced."""
    import copy

    from app.parsers.csv import CsvParser

    parser = CsvParser()
    head_end, _ = head_slice
    pristine = copy.deepcopy(parser)
    par._reset_parser(pristine)
    head_text = data[:head_end].decode("utf-8", errors="replace")
    head_parsed = list(parser.parse(head_text.splitlines()))
    skip = len(head_parsed)
    out = [pe.raw for pe in head_parsed]
    for s, e in par._chunk_ranges(data, head_end, par.chunk_bytes(), True):
        worker = copy.deepcopy(pristine)
        text = head_text + data[s:e].decode("utf-8", errors="replace")
        out.extend(pe.raw for i, pe in enumerate(worker.parse(text.splitlines())) if i >= skip)
    return out


def test_the_warm_up_head_never_ends_inside_a_quoted_cell() -> None:
    """A CSV cell may contain a newline, so counting newlines alone can cut the head mid-cell.

    The first assertion keeps this honest: it proves the fixture really does trip the old behaviour,
    so a green result means the fix works rather than that nothing was exercised.
    """
    data = _csv_multiline(4000)
    old_end, _ = _head_slice_by_lines(data)
    new_end, lines = par._head_slice(data, True)
    assert data.count(b'"', 0, old_end) % 2 == 1, "the fixture no longer cuts inside a quoted cell"
    assert data.count(b'"', 0, new_end) % 2 == 0, "the head still ends on an open quote"
    assert new_end > old_end and lines >= par.HEAD_LINES


def test_a_head_cut_mid_cell_loses_records_and_the_fix_stops_it(monkeypatch) -> None:
    """The chunked path must yield exactly what one worker over the whole file yields.

    With the head cut inside an open quote, that quote swallows the first line of every chunk: the
    head's dangling record and the chunk's first record merge into one, and discarding `head_records`
    of them discards a real line of evidence per chunk. Silently — the source still reads READY, just
    with fewer events.
    """
    monkeypatch.setenv("IRIS_PARSE_CHUNK_MB", "0.06")
    from app.parsers.csv import CsvParser

    data = _csv_multiline(4000)
    whole = [pe.raw for pe in CsvParser().parse(data.decode().splitlines())]

    broken = _chunked_records(data, _head_slice_by_lines(data))
    fixed = _chunked_records(data, par._head_slice(data, True))

    assert fixed == whole, "the quote-aware head must reproduce the single-worker records exactly"
    assert broken != whole, "the fixture did not actually exercise the old failure"
