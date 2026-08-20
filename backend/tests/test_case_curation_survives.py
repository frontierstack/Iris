"""Leaving a case and coming back must not empty it — or quietly re-point it at the wrong log line.

The analyst, twice: *"When viewing a case, and leaving, the timeline events disappear and do not show
up again, that is a major issue"* — and the same for the entity graph. Both live in the same file
(`case.json` → `case_set`, `graph_links`, `graph_nodes`), which was the clue: this was not two screens
losing state, it was one file being written empty.

TWO defects, and the second is the dangerous one:

1. `Store.restore` DROPPED every curated entry whose event id was not in the pool, and `save_meta()`
   ran a few lines later — so a reload in which the ids came out different deleted the analyst's
   timeline and persisted the deletion. Nothing could put it back.
2. Event ids are assigned from a counter that depends on what else is in the pool, so a re-parse both
   MOVES them and REUSES them. Measured here: an entry citing `e4` came back resolving cleanly to the
   CSV header row. A timeline pointing at the wrong evidence with no sign of trouble is worse than one
   pointing at nothing.

So a curated entry is ANCHORED to its line (`file` + `rawHash`), the anchor is authoritative, and the
id is treated as a pointer that may go stale or be reused. What these tests assert is therefore about
the LINE, not the id: the same evidence, with the analyst's labels and note, comes back.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app import config
from app.main import app
from app.store import STORE, raw_hash
from tests.conftest import drain_enrichment

CSV = (b"timestamp,host,message\n"
       b"2026-08-19T03:14:47Z,web-1,Failed password for root\n"
       b"2026-08-19T03:15:02Z,web-1,Accepted password for root\n")


@pytest.fixture()
def client():
    with TestClient(app) as c:
        STORE.clear_all()
        c.post("/api/cases", json={"name": "Curation survives"})
        c.post("/api/sources", files={"files": ("a.csv", CSV, "text/csv")})
        drain_enrichment()      # curate against the FINAL ids, not mid-phase-2 ones
        yield c
        STORE.clear_all()


def _curate(c) -> tuple[str, str]:
    """Put one event on the timeline and one link on the graph, the way the UI does.
    Returns (caseId, the RAW LINE that was curated) — the line is the identity, not the id."""
    cid = next(x for x in c.get("/api/cases").json() if x["active"])["id"]
    # a real log line, not the CSV header: the header is not a record, so phase 2 legitimately removes
    # it and an entry pointing at it is unresolvable for a reason that has nothing to do with this test
    ev = next(e for e in STORE.events if "Failed password" in e.raw)
    assert c.post(f"/api/case-set/{ev.id}",
                  json={"labels": ["pivot"], "note": "first contact"}).status_code == 200
    assert c.post("/api/graph/links", json={"source": "host:web-1", "target": "user:root",
                                            "relation": "auth_from", "why": "same line"}).status_code == 200
    return cid, ev.raw


def _timeline_lines(c) -> list[str]:
    """The raw lines the timeline currently points at — '(unresolved)' for an entry whose event is gone."""
    body = c.get("/api/case-set").json()
    by_id = {e["id"]: e for e in body["events"]}
    return [by_id[e["eventId"]]["raw"] if e["eventId"] in by_id else "(unresolved)"
            for e in body["entries"]]


def test_the_timeline_is_still_there_after_looking_at_other_screens(client):
    cid, line = _curate(client)
    for path in ("/api/events?limit=10", "/api/sources", "/api/graph?limit=50", "/api/cases",
                 f"/api/cases/{cid}", "/api/case"):
        client.get(path)

    assert _timeline_lines(client) == [line], "the case timeline emptied while the analyst was elsewhere"
    assert len(STORE.graph_links) == 1, "and so did the graph"


def test_it_survives_a_switch_to_another_case_and_back(client):
    cid, line = _curate(client)
    other = client.post("/api/cases", json={"name": "Somewhere else"}).json()["id"]
    assert _timeline_lines(client) == [], "the other case has its own (empty) timeline"

    client.post(f"/api/cases/{cid}/activate")
    assert _timeline_lines(client) == [line], "coming back must restore the timeline from case.json"
    entry = client.get("/api/case-set").json()["entries"][0]
    assert entry["labels"] == ["pivot"] and entry["note"] == "first contact"
    assert len(STORE.graph_links) == 1
    client.delete(f"/api/cases/{other}")


def test_an_entry_never_points_at_a_different_line_than_the_one_curated(client):
    """The silent version of the bug: the id resolved, to the wrong evidence."""
    cid, line = _curate(client)
    other = client.post("/api/cases", json={"name": "Elsewhere"}).json()["id"]
    client.post(f"/api/cases/{cid}/activate")

    body = client.get("/api/case-set").json()
    entry = body["entries"][0]
    ev = next(e for e in body["events"] if e["id"] == entry["eventId"])
    assert ev["raw"] == line
    assert raw_hash(ev["raw"]) == entry["rawHash"], "the pointer and the anchor must agree"
    client.delete(f"/api/cases/{other}")


def test_it_survives_a_restart(client):
    from app import cases as cases_mod

    cid, line = _curate(client)
    on_disk = json.loads(config.case_path(cid).read_text(encoding="utf-8"))
    assert len(on_disk["case_set"]) == 1 and on_disk["case_set"][0]["rawHash"]
    assert len(on_disk["graph_links"]) == 1

    cases_mod.startup()          # what the lifespan does
    assert _timeline_lines(client) == [line]


def test_a_save_that_lands_mid_switch_cannot_empty_the_file(client):
    """A save_meta() from another thread — the enrichment worker finishing a source, a detection pass
    bumping the version — used to land while `activate` had cleared memory and not yet read the case
    back, writing an EMPTY case set over a case that had one."""
    cid, line = _curate(client)
    other = client.post("/api/cases", json={"name": "Elsewhere"}).json()["id"]

    with STORE.lock:
        STORE._switching = True          # exactly what `activate` sets while it reloads
        STORE._clear_memory(delete_files=False, keep_library=True)
        STORE.pending = False
        STORE.case_id = cid
    STORE.save_meta()                    # <-- the write that used to destroy the case
    with STORE.lock:
        STORE._switching = False

    on_disk = json.loads(config.case_path(cid).read_text(encoding="utf-8"))
    assert len(on_disk["case_set"]) == 1, "an empty store overwrote the case file"
    assert len(on_disk["graph_links"]) == 1

    # finish the switch the way `activate` would have (force: the store already carries this id, in
    # the half-loaded state this test put it in)
    # save_current=False: this test deliberately corrupted memory, and asking the store to
    # persist THAT before reloading is not something the real switch path ever does
    STORE.activate(cid, save_current=False, force=True)
    assert _timeline_lines(client) == [line]
    client.delete(f"/api/cases/{other}")


def test_deleting_the_source_does_take_its_timeline_entries(client):
    """The one case where curation IS removed, and the distinction that matters.

    Deleting a source is an explicit, confirmed, destructive act — the dialog says it removes the
    events from the workspace and the file from disk — so its curated entries go with it. Everything
    else in this file is the opposite case: a RELOAD, which the analyst did not ask for and which must
    never cost them work.
    """
    cid, _line = _curate(client)
    sid = next(iter(STORE.sources))
    client.delete(f"/api/sources/{sid}")

    assert _timeline_lines(client) == []
