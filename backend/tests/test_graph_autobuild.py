"""The entity graph starts building on its own, and refreshes when the workspace changes.

*"The entity graph only starts building when you visit the entity graph page, but it should start that
process automatically and refreshes automatically when a new source is added."*

It was exactly that: a build starts when something ASKS for the graph, and only the Graph screen and a
few AI tools ask. The obvious fix — ask more often — is the one that must not be made: the sidebar used
to poll `/api/graph` on every page, which turned a 300 MB library load into a full six-worker
extraction every few seconds and ended in SIGSEGV on this machine (see `Store.derived_builds_paused`).

So there is a watcher that asks ONCE, and only when the workspace has settled. What is pinned here is
the restraint as much as the trigger.
"""
from __future__ import annotations

import pytest

from app.autobuild import GraphAutoBuilder


class FakeStore:
    def __init__(self, version=1, events=(1,), paused=False):
        self.version = version
        self.events = list(events)
        self.paused = paused
        self.asked: list[str] = []

    def derived_builds_paused(self) -> bool:
        return self.paused

    def graph_v2_ready(self, scope="all"):
        self.asked.append(scope)
        return None


def _watcher(store) -> GraphAutoBuilder:
    w = GraphAutoBuilder()
    w._store = store
    return w


QUIET = 25.0     # comfortably past the default quiet window


def test_it_builds_once_the_workspace_has_been_quiet(monkeypatch):
    store = FakeStore()
    w = _watcher(store)
    assert w.tick(now=100.0, seen_version=1, changed_at=100.0 - QUIET) is True
    assert store.asked == ["all"]


def test_it_does_not_build_while_the_version_is_still_moving():
    """A burst of uploads bumps the version once per file. Building per file and throwing all but the
    last away is the same storm, through a different door."""
    store = FakeStore()
    w = _watcher(store)
    assert w.tick(now=100.0, seen_version=1, changed_at=99.0) is False   # 1 s of quiet, not enough
    assert store.asked == []


def test_it_never_builds_while_a_load_or_an_enrichment_run_is_in_flight():
    store = FakeStore(paused=True)
    w = _watcher(store)
    assert w.tick(now=100.0, seen_version=1, changed_at=100.0 - QUIET) is False
    assert store.asked == []


def test_it_asks_once_per_version_not_once_per_tick():
    store = FakeStore()
    w = _watcher(store)
    assert w.tick(now=100.0, seen_version=1, changed_at=100.0 - QUIET) is True
    assert w.tick(now=200.0, seen_version=1, changed_at=100.0 - QUIET) is False
    assert store.asked == ["all"], "a settled workspace must cost nothing at all"


def test_a_new_source_makes_it_build_again():
    """The refresh half of the request: the version moves when a source lands."""
    store = FakeStore()
    w = _watcher(store)
    w.tick(now=100.0, seen_version=1, changed_at=100.0 - QUIET)
    store.version = 2                                    # a source was added
    assert w.tick(now=300.0, seen_version=2, changed_at=300.0 - QUIET) is True
    assert store.asked == ["all", "all"]


def test_an_empty_workspace_is_not_worth_a_build():
    store = FakeStore(events=())
    w = _watcher(store)
    assert w.tick(now=100.0, seen_version=1, changed_at=100.0 - QUIET) is False
    assert store.asked == []


def test_it_can_be_turned_off(monkeypatch):
    monkeypatch.setenv("IRIS_GRAPH_AUTOBUILD", "0")
    w = GraphAutoBuilder()
    w.start(FakeStore())
    assert w._thread is None, "IRIS_GRAPH_AUTOBUILD=0 must mean no watcher at all"
