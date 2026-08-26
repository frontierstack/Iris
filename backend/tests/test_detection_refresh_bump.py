"""A correction pass that corrects nothing must not invalidate the derived layer.

`Store._refresh_detections_async` re-runs the whole rule catalogue in the background after a library
load and after a source delete, and it used to end in an unconditional `bump()`. A bump drops the
search index, the entity graph, the correlation analysis and the anomaly roll-up: the first two then
re-read themselves off disk, the last two rebuild from nothing.

Most of the time that pass corrects NOTHING. After a restart the pool comes back from the parsed-pool
cache carrying the detections it was saved with, and the pass re-stamps them identically. Observed on
the analyst's own 281,805-event workspace, from an idle start with no ingest at all:

    01:36:27  search index cache: loaded 281,805 events in 2.5s
    01:36:45  graph cache: loaded 3354 nodes / 5208 relations in 1.2s
    01:36:49  search index cache: loaded 281,805 events in 2.2s   <- the same file, again
    01:37:06  graph cache: loaded 3354 nodes / 5208 relations in 0.1s

Only one `search-index.iris` exists on disk, so both loads used the same key — the pool had not
changed. At 11 M events that second round is a 4.1 GB re-read (measured 2.2 s/GB for the HMAC pass
alone) plus a from-scratch analysis and anomaly rebuild, for a pass whose output was identical.

So `_run_detections` now reports whether it changed anything, by comparing a fingerprint of the pool's
detections before and after (`_detections_fingerprint`), and the background pass bumps only when it
did. Both directions are pinned here: a pass that changes nothing must be silent, and a pass that
changes ANYTHING must still invalidate — a stale derived layer is the far worse failure.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import Detection
from app.store import STORE
from tests.conftest import drain_enrichment, load_sample_case


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        load_sample_case(c)
        drain_enrichment()
        yield c


def _settle() -> int:
    """Run the catalogue to a fixed point and return the store version once nothing is in flight."""
    assert STORE.wait_detections(60)
    with STORE._detect_lock:
        STORE._run_detections()
    assert STORE.wait_detections(60)
    return STORE.version


def test_a_repeated_pass_reports_no_change(client):
    _settle()
    with STORE._detect_lock:
        assert STORE._run_detections() is False, "re-stamping the same catalogue is not a change"


def test_a_pass_that_changes_the_stamp_reports_it(client):
    _settle()
    victim = next(e for e in STORE.events if not e.detections)
    victim.detections = [Detection(name="planted", id="TEST-0000", level="info")]
    with STORE._detect_lock:
        assert STORE._run_detections() is True, "the pass wiped a detection — that IS a change"
    assert not victim.detections
    with STORE._detect_lock:
        assert STORE._run_detections() is False   # and back to quiet


def test_the_background_refresh_does_not_bump_when_it_corrects_nothing(client):
    v0 = _settle()
    STORE._refresh_detections_async()
    assert STORE.wait_detections(60)
    assert STORE.version == v0, (
        "the correction pass invalidated the search index, the graph, the analysis and the anomaly "
        "roll-up without changing a single detection"
    )


def test_the_background_refresh_still_bumps_when_a_detection_changes(client):
    v0 = _settle()
    victim = next(e for e in STORE.events if not e.detections)
    victim.detections = [Detection(name="planted", id="TEST-0000", level="info")]
    STORE._refresh_detections_async()
    assert STORE.wait_detections(60)
    assert STORE.version > v0, "a pass that changed the pool MUST invalidate the derived layer"


def test_the_fingerprint_notices_a_severity_override(client):
    """Not just which rules fired: an analyst re-rating a rule changes what the anomaly rows say."""
    _settle()
    victim = next((e for e in STORE.events if e.detections), None)
    if victim is None:
        pytest.skip("no detections in the sample pool")
    before = STORE._detections_fingerprint()
    d0 = victim.detections[0]
    victim.detections = [Detection(name=d0.name, id=d0.id, level="critical" if d0.level != "critical" else "low")]
    assert STORE._detections_fingerprint() != before
