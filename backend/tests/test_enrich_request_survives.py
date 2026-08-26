"""An explicit "Interpret this file" survives a restart, exactly as "skip it" already does.

`ingest.autoEnrich` ships OFF, so with a raw-first workspace phase 2 only ever runs because someone
ASKED for it. `pool_store` already persists the opposite decision — a skip — with the reasoning that
"what must survive a restart is the DECISION, or the next boot re-queues every source the analyst
just declined". The request half was never persisted: a source is re-parsed on startup and a
re-parsed source comes back `raw`, and the pool cache only stores FINISHED sources, so a file sitting
in the queue when the process stopped came back raw and `requeue_unenriched` (correctly, on its own
terms — "a restart is not a request") left it alone. The analyst's click was silently dropped, and
nothing on any screen said so: the file reads `raw` again, which is exactly what it read before they
clicked.

Both decisions are the analyst's, both are cheap to record, and losing either one silently is the
same bug.
"""
from __future__ import annotations

import pytest

from fastapi.testclient import TestClient

from app import config, enrich
from app.main import app
from app.store import STORE


@pytest.fixture()
def c():
    with TestClient(app) as client:
        yield client


@pytest.fixture()
def raw_only():
    before = config.get_settings().ingest.autoEnrich
    config.update_settings({"ingest": {"autoEnrich": False}})
    yield
    config.update_settings({"ingest": {"autoEnrich": before}})


@pytest.fixture()
def no_worker(monkeypatch):
    """Hold the queue still, so `queued` is observable instead of racing to `enriched`."""
    monkeypatch.setattr(enrich.QUEUE, "submit", lambda sid: None)


def _stage(c, name: str = "auth.log") -> str:
    """Through the real staging endpoint: the bytes have to land in `library/` for the sid to be
    DERIVED from the file name, which is what makes it the same sid after a restart."""
    blob = "".join("2026-08-26T00:00:%02dZ host sshd: Failed password for bob" % (i % 60) + chr(10)
                   for i in range(40)).encode()
    r = c.post("/api/library/upload", files=[("files", (name, blob, "text/plain"))])
    assert r.status_code == 200, r.text
    sid = next(k for k, v in STORE.source_library.items() if v.endswith(name))
    assert sid in STORE.sources, (sid, list(STORE.sources))
    return sid


def _restart() -> None:
    """What `cases.startup()` does: drop the in-memory pool, then read the library back off disk."""
    STORE._clear_memory(delete_files=False, keep_library=False)
    STORE.restore_library()


def test_an_enrich_request_is_still_queued_after_a_restart(c, raw_only, no_worker) -> None:
    STORE.clear_all()
    sid = _stage(c)
    assert STORE.sources[sid].enrich == "raw"

    assert STORE.queue_enrichment(sid) is True
    assert STORE.sources[sid].enrich == "queued"

    _restart()
    assert STORE.sources[sid].enrich == "raw", "a re-parsed source starts raw — that is the premise"
    assert STORE.requeue_unenriched() == 1, "the analyst asked for this file and the request was lost"
    assert STORE.sources[sid].enrich == "queued"


def test_skipping_after_asking_still_wins(c, raw_only, no_worker) -> None:
    """The two decisions are opposites and the LAST one has to hold, in both directions."""
    STORE.clear_all()
    sid = _stage(c)
    STORE.queue_enrichment(sid)
    assert STORE.skip_enrichment(sid) is True

    _restart()
    assert STORE.sources[sid].enrich == "skipped", "the skip decision already survives a restart"
    assert STORE.requeue_unenriched() == 0, "a skip after a request must not be re-queued"

    # ...and back again: asking after skipping wins too (that direction already worked)
    STORE.queue_enrichment(sid)
    _restart()
    assert STORE.requeue_unenriched() == 1


def test_an_honoured_request_does_not_accumulate(c, raw_only, no_worker) -> None:
    """The record is a decision that is still outstanding, not a log of every click ever made."""
    from app import pool_store

    STORE.clear_all()
    sid = _stage(c)
    STORE.queue_enrichment(sid)
    assert pool_store.was_requested(sid) is True

    _restart()
    assert STORE.requeue_unenriched() == 1           # honours it: the source is queued again
    assert pool_store.was_requested(sid) is True     # still outstanding, so still recorded

    STORE.sources[sid].enrich = "enriched"           # what the worker does when it lands
    assert STORE.requeue_unenriched() == 0
    assert pool_store.was_requested(sid) is False, "a settled request is still on disk"
