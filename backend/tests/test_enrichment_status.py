"""The enrichment status may never contradict itself.

Reported from the live workspace, both lines on screen at the same moment:

    14 of 14 sources interpreted
    Interpreting capture20110811.binetflow · 2 waiting behind it

Every number there was wrong, in three different ways, and the API had already said so:

    counts   {'raw': 0, 'queued': 3, 'enriching': 0, 'enriched': 11}
    running  '334cb4c4'   (capture20110811.binetflow — enrich: 'enriched')

  * `14 of 14 interpreted` came from `total - raw`, which calls a QUEUED source interpreted. That is
    the number an analyst reads to decide the workspace is ready to answer over.
  * `running` named a source that had finished. The queue holds the name of what it popped through the
    batch COMMIT that follows — real work, O(the whole pool), but every source in it is already
    `enriched`, so nothing in `counts` describes it and the screen blamed the last file.
  * `2 waiting behind it` was `pending - 1`, on the assumption that `running` was one of the three
    queued. It was not.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import enrich as enrich_mod
from app.main import app
from app.models import Source
from app.store import STORE


@pytest.fixture()
def c():
    with TestClient(app) as client:
        yield client


@pytest.fixture()
def pool():
    """A workspace shaped like the report: some enriched, some queued, none actually enriching."""
    made = []

    def add(sid: str, state: str, enrich: str, events: int = 10):
        with STORE.lock:
            STORE.sources[sid] = Source(id=sid, file=f"{sid}.csv", parser="csv", state=state,
                                        size=1000, events=events, origin="library", enrich=enrich)
            STORE.source_order.append(sid)
            STORE.source_origin[sid] = "library"
        made.append(sid)

    yield add
    with STORE.lock:
        for sid in made:
            STORE.sources.pop(sid, None)
            STORE.source_origin.pop(sid, None)
            if sid in STORE.source_order:
                STORE.source_order.remove(sid)


def _enrichment(client) -> dict:
    return client.get("/api/case").json()["enrichment"]


def test_a_queued_source_is_not_reported_as_interpreted(c, pool) -> None:
    """`counts.enriched` is what "interpreted" means. The UI reads this and nothing else."""
    pool("z-enriched-1", "READY", "enriched")
    pool("z-enriched-2", "READY", "enriched")
    pool("z-queued-1", "REVIEW", "queued")
    e = _enrichment(c)
    assert e["counts"]["queued"] >= 1
    # the number the banner prints must exclude everything still to come
    assert e["counts"]["enriched"] + e["counts"]["queued"] + e["counts"]["enriching"] + e["counts"]["raw"] \
        <= len(STORE.sources)
    assert e["pending"] >= 1, "queued work must count as pending"
    assert e["outstanding"] >= 1


def test_running_never_names_a_source_that_has_finished(c, pool, monkeypatch) -> None:
    """The exact live symptom: the queue still held `334cb4c4` while its source was `enriched`."""
    pool("z-done-1", "REVIEW", "enriched")
    pool("z-wait-1", "REVIEW", "queued")
    pool("z-wait-2", "REVIEW", "queued")
    monkeypatch.setattr(enrich_mod.QUEUE, "status",
                        lambda: {"running": "z-done-1", "queued": ["z-wait-1", "z-wait-2"],
                                 "pending": 3, "committing": True})
    e = _enrichment(c)
    assert e["running"] == "", f"a finished source was reported as running: {e}"
    assert e["runningFile"] == ""
    assert e["committing"] is True, "the commit is real work and must be reported as itself"


def test_running_is_reported_while_a_source_really_is_enriching(c, pool, monkeypatch) -> None:
    """The reconciliation must not throw away a true answer — that would be the opposite bug."""
    pool("z-live-1", "REVIEW", "enriching")
    monkeypatch.setattr(enrich_mod.QUEUE, "status",
                        lambda: {"running": "z-live-1", "queued": [], "pending": 1, "committing": False})
    e = _enrichment(c)
    assert e["running"] == "z-live-1"
    assert e["runningFile"] == "z-live-1.csv"
    assert e["counts"]["enriching"] == 1


def test_a_running_source_that_vanished_is_not_reported(c, monkeypatch) -> None:
    """A source deleted mid-enrichment leaves the queue holding a sid nothing can resolve."""
    monkeypatch.setattr(enrich_mod.QUEUE, "status",
                        lambda: {"running": "no-such-source", "queued": [], "pending": 1,
                                 "committing": False})
    assert _enrichment(c)["running"] == ""


def test_committing_defaults_to_false_and_is_always_present(c) -> None:
    """The field is what the banner switches on; absent would render as 'nothing is happening'."""
    e = _enrichment(c)
    assert "committing" in e and isinstance(e["committing"], bool)


def test_the_queue_reports_its_commit(c) -> None:
    """`status()` is the only place the commit is visible — it belongs to no source."""
    st = enrich_mod.QUEUE.status()
    assert "committing" in st
    assert set(st) >= {"running", "queued", "pending", "committing"}
