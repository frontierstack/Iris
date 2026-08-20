"""Switching cases must not re-run the detection catalogue over an unchanged pool.

`Store.activate` ended with an unconditional `_run_detections()`. That pass is O(the WHOLE pool) —
pure-Python regex over every event — and on the analyst's 11.1 M-event workspace it was minutes of
work and enough allocation churn to SEGFAULT the process. It fired even for `create_case`, which
adds an EMPTY case and cannot change a single event: the AI investigator called it mid-run and took
the app down with it.

The justification for the pass is real but narrow: windowed BURST rules read the density of the whole
pool, so if the set of events changed (a case's own sources left, a new case's sources arrived) the
result can legitimately differ. If nothing entered or left, every event still carries the detections
it already matched and there is nothing to recompute.
"""
from __future__ import annotations

import pytest

from app import cases as cases_mod
from app.store import STORE

CSV = b"timestamp,host,message\n2026-08-19T03:14:47Z,web-1,Failed password for root\n"


@pytest.fixture(autouse=True)
def _clean():
    STORE.clear_all()
    yield
    STORE.clear_all()


def _count_passes(monkeypatch) -> dict:
    seen = {"n": 0}
    from app import store as store_mod

    real = store_mod.Store._run_detections

    def counted(self, *a, **k):
        seen["n"] += 1
        return real(self, *a, **k)

    monkeypatch.setattr(store_mod.Store, "_run_detections", counted)
    return seen


def test_creating_a_case_does_not_re_run_detections_over_the_pool(monkeypatch):
    """The crash. A new case is empty, so the pool is byte for byte what it was."""
    passes = _count_passes(monkeypatch)
    cases_mod.create_case("Fresh case")
    assert passes["n"] == 0, "an empty new case re-ran the whole detection catalogue"


def test_switching_back_to_a_case_with_events_does_re_run_them(monkeypatch):
    """The narrow case the pass exists for: the pool really did change."""
    a = STORE.case_id
    STORE.add_file("a.csv", CSV, background_ok=False)
    assert STORE.events
    b = cases_mod.create_case("Case B").id
    assert not STORE.events, "case A's events left the pool with case A"

    passes = _count_passes(monkeypatch)
    cases_mod.activate(a)
    assert STORE.events
    # >= 1, not == 1: re-parsing the case's own file runs a pass of its own. What is pinned here is
    # that a real change is never SKIPPED — the zero above is the assertion that matters.
    assert passes["n"] >= 1, "case A's events came back and their bursts were never re-evaluated"
    cases_mod.activate(b)


def test_the_signature_is_not_a_walk_of_the_events():
    """It has to be cheap or it is the same cost in a different place."""
    STORE.add_file("a.csv", CSV, background_ok=False)

    class Counting(list):
        iters = 0

        def __iter__(self):
            Counting.iters += 1
            return super().__iter__()

    real = STORE.events
    try:
        STORE.events = Counting(real)          # type: ignore[assignment]
        STORE._pool_signature()
        assert Counting.iters == 0
    finally:
        STORE.events = real                    # type: ignore[assignment]
