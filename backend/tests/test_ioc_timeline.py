"""Indicators as timeline markers, and the provenance an indicator now carries.

The point of the feature: "when did we first see this indicator" must be answerable from the incident
chronology, and an indicator recorded by the AI must be distinguishable from one the analyst typed.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.store import STORE
from tests.conftest import load_sample_case


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        load_sample_case(c)
        yield c


def test_extracted_indicators_are_on_the_timeline_in_order(client):
    r = client.get("/api/timeline/iocs")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == len(body["iocs"]) and body["iocs"], "the sample case has detections, so it has indicators"
    ts = [m["ts"] for m in body["iocs"]]
    assert ts == sorted(ts)
    for m in body["iocs"]:
        assert m["ts"], "a marker with no timestamp cannot be placed and must not be emitted"
        assert m["addedBy"] in ("extracted", "analyst", "ai")
        if m["eventId"]:
            assert STORE.event(m["eventId"]) is not None    # every marker links to a real event


def test_a_manual_indicator_is_placed_by_the_events_it_cites(client):
    """A value that appears nowhere verbatim still gets a place in time from its citation."""
    eid = STORE.events[3].id
    ev = STORE.event(eid)
    r = client.post("/api/iocs", json={"kind": "other", "value": "APT-CASE-MARKER-XYZ",
                                       "note": "from threat intel", "citedEventIds": [eid]})
    assert r.status_code == 200, r.text
    ioc = r.json()
    assert ioc["addedBy"] == "analyst" and ioc["citedEventIds"] == [eid]
    assert ioc["firstSeen"] == ev.ts and [h["eventId"] for h in ioc["hits"]] == [eid]

    markers = client.get("/api/timeline/iocs").json()["iocs"]
    mine = next(m for m in markers if m["value"] == "APT-CASE-MARKER-XYZ")
    assert mine["ts"] == ev.ts and mine["eventId"] == eid and mine["addedBy"] == "analyst"

    client.delete(f"/api/iocs/{ioc['id']}")


def test_citations_that_do_not_resolve_are_never_stored(client):
    r = client.post("/api/iocs", json={"kind": "domain", "value": "phantom.example",
                                       "citedEventIds": ["e999999", "not-an-id"]})
    assert r.status_code == 200
    assert r.json()["citedEventIds"] == []
    client.delete("/api/iocs/domain:phantom.example")


def test_scope_case_narrows_the_markers(client):
    all_markers = client.get("/api/timeline/iocs").json()
    case_markers = client.get("/api/timeline/iocs?scope=case").json()
    assert case_markers["total"] <= all_markers["total"]


def test_clusters_endpoint_is_unchanged(client):
    """The markers are a SEPARATE request on purpose — /api/timeline must not grow an O(pool) IOC pass."""
    body = client.get("/api/timeline").json()
    assert set(body) == {"stats", "clusters", "status"}


def test_every_file_an_indicator_claims_has_a_hit_to_click() -> None:
    """The `files` list and the `hits` list must not disagree.

    The sample was the first five matches in time order, so a busy log crowded the others out: an
    indicator listing `Sophos Web Proxy.csv` and `DNS Logs.csv` showed five Sophos hits and nothing
    for DNS — which reads as "the DNS reference was wrong". A display cap must never look like a
    statement about the evidence.
    """
    from app.models import IOC
    from app.report import MAX_IOC_HITS, sample_hit

    class _E:
        def __init__(self, i, file):
            self.id, self.ts, self.sourceId, self.file = f"e{i}", f"2026-08-19T00:00:{i % 60:02d}Z", file[:3], file

    ioc = IOC(kind="ipv4", value="10.0.0.1")
    busy = [_E(i, "busy.log") for i in range(50)]
    for e in busy:
        ioc.files.append(e.file) if e.file not in ioc.files else None
        sample_hit(ioc, e)
    rare = _E(99, "quiet.log")
    ioc.files.append(rare.file)
    sample_hit(ioc, rare)

    assert set(ioc.files) == {"busy.log", "quiet.log"}
    assert {h.file for h in ioc.hits} == set(ioc.files), "a file with no clickable hit reads as a bad reference"
    assert len(ioc.hits) <= MAX_IOC_HITS + len(ioc.files)
