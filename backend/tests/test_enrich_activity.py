"""Phase 2 says WHAT it is waiting on, and stays answerable while it does it.

The analyst, with one 16.9 MB file queued and nothing visibly happening for minutes:

    "there need to be more detailed messaging on what's being waited on and more advanced
     status updates"

They were right twice over. The file was queued behind `_swap_many` — the deferred batch merge for two
large binetflows that had just finished — which is O(THE WHOLE POOL) however little changed: rebuild a
13.8 M-event list, sort it, build a 13.8 M-entry id index, build a timestamp array. Minutes at that
size. Every state below rendered as the same four words, "1 queued to interpret":

  * a source being parsed          (this one at least had a percentage)
  * a batch merge rebuilding the pool
  * the worker yielding to a library load
  * no worker servicing the queue at all

The second half — why the status endpoint could not answer DURING the wait — is memory thrashing plus a
saturated core plus `list.sort` comparing precomputed keys in C without releasing the GIL. That one is
not fixable by yielding, so the answer is to publish what the merge is doing and how long it has been
doing it, and to say it plainly rather than pretend the wait can be chunked away.
"""
from __future__ import annotations

import threading
import time

import pytest
from fastapi.testclient import TestClient

from app import enrich as enrich_mod
from app.main import app
from app.models import Event, Source
from app.store import STORE, Store, _build_index


@pytest.fixture()
def c():
    with TestClient(app) as client:
        yield client


def _activity(client) -> dict:
    return client.get("/api/case").json()["enrichment"]["activity"]


@pytest.fixture(autouse=True)
def _clean_merge():
    yield
    enrich_mod.MERGE.finish()


# ----------------------------------------------------------------- the index build
def test_the_id_index_keeps_key_value_and_insertion_order() -> None:
    """The graph's ranking uses dict order as a positional tie-break, so a reordered index is not a
    cosmetic difference. (This helper was briefly chunked to "release the GIL"; see the note on
    `_build_index` for why that reasoning was wrong and was backed out.)"""
    events = [Event(id=f"e{i:x}", raw=f"line {i}") for i in range(5000)]
    expected = {e.id: i for i, e in enumerate(events)}
    got = _build_index(events)
    assert got == expected
    assert list(got) == list(expected), "insertion order changed"




def test_an_empty_pool_indexes_cleanly() -> None:
    assert _build_index([]) == {}


# ----------------------------------------------------------------- the activity report
def test_a_merge_is_reported_as_a_merge_and_not_as_a_queue(c) -> None:
    """The exact reported state: something queued, nothing enriching, a merge underway."""
    enrich_mod.MERGE.start(2, 13_830_977)
    enrich_mod.MERGE.step("indexing")
    a = _activity(c)
    assert a["kind"] == "merging"
    assert a["sources"] == 2 and a["events"] == 13_830_977
    assert a["stage"] == "indexing"
    assert a["stageIndex"] == 4 and a["stageCount"] == 6
    # the sentence has to name the thing being waited on, not just its existence
    assert "Merging 2 interpreted sources" in a["detail"]
    assert "13,830,977 events" in a["detail"]
    assert "indexing" in a["detail"]


def test_the_merge_reports_how_long_it_has_been_running(c) -> None:
    """Elapsed is the difference between waiting and worrying."""
    enrich_mod.MERGE.start(1, 100)
    enrich_mod.MERGE.started = time.time() - 254
    a = _activity(c)
    assert a["kind"] == "merging"
    assert 250 <= a["elapsedSec"] <= 260


def test_a_merge_outranks_a_stale_running_source(c, monkeypatch) -> None:
    """A batch's members are already `enriched` while it merges, so the queue's `running` is a finished
    file. The merge is the true answer and must win."""
    monkeypatch.setattr(enrich_mod.QUEUE, "status",
                        lambda: {"running": "whatever", "queued": ["z1"], "pending": 2,
                                 "committing": True, "phase": "parsing", "phaseElapsedSec": 9})
    enrich_mod.MERGE.start(3, 500)
    assert _activity(c)["kind"] == "merging"


def test_an_abandoned_queue_says_nobody_is_servicing_it(c, monkeypatch) -> None:
    """`submit()` already logs this. The analyst cannot read the server log."""
    monkeypatch.setattr(enrich_mod.QUEUE, "status",
                        lambda: {"running": "", "queued": ["z1"], "pending": 1, "committing": False,
                                 "phase": "noWorker", "phaseElapsedSec": 30})
    a = _activity(c)
    assert a["kind"] == "noWorker"
    assert "stay raw" in a["detail"] and "searchable" in a["detail"]


def test_yielding_to_the_library_load_is_its_own_sentence(c, monkeypatch) -> None:
    """"Queued" and "queued behind the library load" have different answers to "how long?"."""
    monkeypatch.setattr(enrich_mod.QUEUE, "status",
                        lambda: {"running": "", "queued": ["z1"], "pending": 1, "committing": False,
                                 "phase": "waitingForPool", "phaseElapsedSec": 12})
    a = _activity(c)
    assert a["kind"] == "waitingForPool"
    assert "library" in a["detail"]


def test_an_idle_worker_with_a_queue_does_not_imply_a_file_is_being_read(c, monkeypatch) -> None:
    """Between items is a real state; claiming a parse there is what "nothing is happening" meant."""
    sid = "z-act-queued"
    with STORE.lock:
        STORE.sources[sid] = Source(id=sid, file="waiting.csv", parser="csv", state="REVIEW",
                                    size=100, events=5, origin="library", enrich="queued")
        STORE.source_order.append(sid)
        STORE.source_origin[sid] = "library"
    monkeypatch.setattr(enrich_mod.QUEUE, "status",
                        lambda: {"running": "", "queued": [sid], "pending": 1, "committing": False,
                                 "phase": "idle", "phaseElapsedSec": 3})
    try:
        a = _activity(c)
        assert a["kind"] == "idle"
        assert "waiting for the interpretation worker" in a["detail"]
        assert a["file"] == ""
    finally:
        with STORE.lock:
            STORE.sources.pop(sid, None)
            STORE.source_origin.pop(sid, None)
            if sid in STORE.source_order:
                STORE.source_order.remove(sid)


def test_a_real_parse_is_reported_with_its_file_and_percentage(c, monkeypatch) -> None:
    from app.jobs import PARSE_PROGRESS

    sid = "z-act-parsing"
    with STORE.lock:
        STORE.sources[sid] = Source(id=sid, file="reading.csv", parser="csv", state="REVIEW",
                                    size=1000, events=5, origin="library", enrich="enriching")
        STORE.source_order.append(sid)
        STORE.source_origin[sid] = "library"
    PARSE_PROGRESS.start(sid, "reading.csv", 1000)
    PARSE_PROGRESS.advance(sid, done=420, events=99, phase="enriching")
    monkeypatch.setattr(enrich_mod.QUEUE, "status",
                        lambda: {"running": sid, "queued": [], "pending": 1, "committing": False,
                                 "phase": "parsing", "phaseElapsedSec": 4})
    try:
        a = _activity(c)
        assert a["kind"] == "parsing"
        assert a["file"] == "reading.csv"
        assert a["pct"] == pytest.approx(42.0, abs=0.5)
        assert "Interpreting reading.csv" in a["detail"]
    finally:
        PARSE_PROGRESS.finish(sid)
        with STORE.lock:
            STORE.sources.pop(sid, None)
            STORE.source_origin.pop(sid, None)
            if sid in STORE.source_order:
                STORE.source_order.remove(sid)


def test_nothing_happening_is_reported_as_nothing_happening(c) -> None:
    a = _activity(c)
    assert a["kind"] == "idle"


def test_the_merge_progress_clears_itself(c) -> None:
    """A merge record left behind would report a merge forever — the same class of bug as a `running`
    that names a finished file."""
    enrich_mod.MERGE.start(1, 10)
    assert enrich_mod.MERGE.snapshot()
    enrich_mod.MERGE.finish()
    assert enrich_mod.MERGE.snapshot() == {}
    assert _activity(c)["kind"] != "merging"


def test_a_real_swap_publishes_and_clears_its_merge(tmp_path, monkeypatch) -> None:
    """End to end through `_swap_many` itself: the record appears during the merge and is gone after."""
    st = Store()
    seen: list[dict] = []
    real_step = enrich_mod.MERGE.step

    def spy(stage, events=-1):
        real_step(stage, events)
        snap = enrich_mod.MERGE.snapshot()
        if snap:
            seen.append(snap)

    monkeypatch.setattr(enrich_mod.MERGE, "step", spy)
    sid = "s1"
    st.sources[sid] = Source(id=sid, file="a.log", parser="syslog", state="READY", size=10, events=1)
    st.source_order.append(sid)
    st.events = [Event(id="e1", sourceId=sid, raw="old", ts="2026-01-01T00:00:00Z")]
    st.event_index = {"e1": 0}
    st._swap_many({sid: [Event(id="e1", sourceId=sid, raw="new", ts="2026-01-01T00:00:00Z")]}, {})
    stages = [x["stage"] for x in seen]
    assert stages[:5] == ["detecting", "filtering", "sorting", "indexing", "timestamps"]         or stages[:4] == ["filtering", "sorting", "indexing", "timestamps"], stages
    assert all(s["sources"] == 1 for s in seen)
    assert enrich_mod.MERGE.snapshot() == {}, "the merge record outlived the merge"
    assert [e.raw for e in st.events] == ["new"]


def test_the_background_detection_pass_is_reported_while_it_runs(c) -> None:
    """A pool-wide pass nobody can see is the same class of bug as a merge nobody can see."""
    with STORE.lock:
        STORE._detect_busy = True
        STORE._detect_started = time.time() - 130
    try:
        e = c.get("/api/case").json()["enrichment"]
        assert e["detectionsRefreshing"] is True
        assert 125 <= e["detectionsRefreshSec"] <= 140
    finally:
        with STORE.lock:
            STORE._detect_busy = False
    e = c.get("/api/case").json()["enrichment"]
    assert e["detectionsRefreshing"] is False and e["detectionsRefreshSec"] == 0
