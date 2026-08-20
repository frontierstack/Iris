"""The Graph screen went blank after the background-cache change. These pin the two ways that happened.

The screen only polls while `stats.status.state == 'building'`; an `idle` state with zero nodes is
rendered as "no entities extracted yet" and the poll stops. So a background build MUST never leave a
window in which the endpoint says `idle` while there is work outstanding. Two windows existed:

  1. `ready()` spawned the build thread and let THAT thread publish `building`. The handler read the
     status back in the same request, so it could answer idle+empty and the screen would give up.
  2. `Store.bump()` → `_drop_derived()` → `AsyncCache.invalidate()` cleared `_status` for a slot whose
     build was still running, and left the single-flight guard set. Every poll for the next several
     minutes then reported `idle` and started nothing. That is the total outage the analyst saw: an
     ingest, a rule edit or a case-set change landing during a build killed the graph until restart.
"""
from __future__ import annotations

import threading
import time

import pytest
from fastapi.testclient import TestClient

from app.derived import AsyncCache
from app.graph import GRAPH_CACHE
from app.main import app
from app.store import STORE
from tests.conftest import load_sample_case


# --------------------------------------------------------------------------- AsyncCache unit level
def _slow_cache(delay: float = 0.4):
    started = threading.Event()
    release = threading.Event()

    def build():
        started.set()
        release.wait(delay + 5.0)
        return {"built": True}

    return AsyncCache("t", sync_limit=0), build, started, release


def test_ready_reports_building_in_the_same_call_no_idle_window():
    """No race with the build thread: the request that SCHEDULES the build already sees 'building'."""
    for _ in range(50):
        c, build, started, release = _slow_cache()
        release.set()                              # build returns immediately — the tightest race there is
        assert c.ready("all", "k1", 1000, build) is None
        st = c.status("all", "k1")
        assert st["state"] != "idle", st           # never 'idle' + empty payload; ready is fine (it won)
        for _ in range(200):                       # and it does land
            if c.status("all", "k1")["state"] == "ready":
                break
            time.sleep(0.01)
        assert c.status("all", "k1")["state"] == "ready"


def test_invalidate_during_a_build_keeps_the_state_building():
    c, build, started, release = _slow_cache()
    assert c.ready("all", "v1", 1000, build) is None
    assert started.wait(5.0)
    c.invalidate()                                  # <- what Store.bump() does on every ingest / rule edit
    assert c.status("all", "v2")["state"] == "building"
    assert c.status("all", "v1")["state"] == "building"
    release.set()
    for _ in range(500):
        if c.status("all", "v1")["state"] == "ready":
            break
        time.sleep(0.01)
    # the finished build belonged to the superseded key, so v2 is still not ready — but asking for it
    # must START a build rather than answering idle forever (the single-flight guard has to be released).
    assert c.status("all", "v1")["state"] == "ready"
    c2_started = threading.Event()

    def build2():
        c2_started.set()
        return {"built": 2}

    c.ready("all", "v2", 1000, build2)
    assert c2_started.wait(5.0), "a build for the new key never started — single-flight guard leaked"
    assert c.status("all", "v2")["state"] in ("building", "ready")


def test_failed_build_releases_the_guard_and_retries():
    c = AsyncCache("t", sync_limit=0)
    calls = []

    def boom():
        calls.append(1)
        raise RuntimeError("nope")

    c.ready("all", "k", 1000, boom)
    for _ in range(500):
        if c.status("all", "k")["state"] != "building":
            break
        time.sleep(0.01)
    assert c.status("all", "k")["state"] == "idle"
    c.ready("all", "k", 1000, boom)                 # the next request must retry, not sit on a stuck guard
    for _ in range(500):
        if len(calls) >= 2:
            break
        time.sleep(0.01)
    assert len(calls) >= 2


# --------------------------------------------------------------------------- end to end
@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        load_sample_case(c)
        yield c


def test_graph_endpoint_never_answers_idle_and_empty(client, monkeypatch):
    """Forced onto the background path, /api/graph must always be either populated or 'building'."""
    monkeypatch.setattr(GRAPH_CACHE, "sync_limit", 0)
    GRAPH_CACHE.invalidate()
    seen = set()
    for _ in range(200):
        g = client.get("/api/graph?limit=50").json()
        st = g["stats"]["status"]["state"]
        seen.add(st)
        assert not (st == "idle" and not g["nodes"]), f"blank graph with no build in flight: {g['stats']}"
        if st == "ready" and g["nodes"]:
            break
        time.sleep(0.05)
    assert "ready" in seen, seen
    assert STORE.graph_status("all")["state"] == "ready"


def test_a_bump_mid_build_does_not_blank_the_graph(client, monkeypatch):
    """An ingest / rule edit / case-set change during a build must leave the screen polling, not empty."""
    monkeypatch.setattr(GRAPH_CACHE, "sync_limit", 0)
    GRAPH_CACHE.invalidate()
    assert client.get("/api/graph?limit=50").json()["stats"]["status"]["state"] == "building"
    STORE.bump()                                     # drops the derived caches mid-flight
    for _ in range(300):
        g = client.get("/api/graph?limit=50").json()
        st = g["stats"]["status"]["state"]
        assert not (st == "idle" and not g["nodes"]), f"blank graph after a bump: {g['stats']}"
        if st == "ready" and g["nodes"]:
            return
        time.sleep(0.05)
    pytest.fail(f"graph never recovered after a mid-build bump: {STORE.graph_status('all')}")
