"""Selecting a source chip must not cost a full pass over the pool.

The analyst's report was "searching needs speed improvements", and this is the mechanism behind the
worst case. The vector path builds a boolean mask, and when the mask is EXACT the answer is the
popcount plus a slice — no Python per candidate. But the source filter was lowered with
`source_mask`, which matches the source LABEL by SUBSTRING: an upper bound. So any search with a
source chip selected fell back to confirming every candidate through the Python predicate — on a
query matching ten million events, a full pass over the pool to return a page of 200 rows.

The index stores a source code per `sourceId` and the label "<source><SEP><file><SEP><sourceId>", so
the filter can be lowered EXACTLY — the same three-way equality the confirm loop applies. These tests
pin that the two paths agree, because a filter mask that is subtly wider or narrower than the
predicate is a silent evidence bug: rows that should have matched, missing, with no error anywhere.
"""
from __future__ import annotations

import numpy as np
import pytest

from app import search as se
from app.models import Event

pytestmark = pytest.mark.usefixtures()

SOURCES = [
    ("nginx access", "access.log", "aaa11111"),
    ("nginx access", "other-access.log", "bbb22222"),   # same LABEL, different file and id
    ("syslog", "auth.log", "ccc33333"),
]


# Above `search._MIN_VECTOR` (2000) on purpose: below it `search()` never builds a mask at all, so a
# smaller corpus would compare the scan path against ITSELF and pass no matter what the mask did.
def _pool(n_each: int = 800) -> tuple[list[Event], np.ndarray]:
    events: list[Event] = []
    k = 0
    for source, file, sid in SOURCES:
        for i in range(n_each):
            k += 1
            events.append(Event(
                id=f"e{k}", ts=f"2026-08-19T{(k // 3600) % 24:02d}:{(k // 60) % 60:02d}:{k % 60:02d}Z", source=source, sourceId=sid,
                file=file, host=f"host{i % 3}", user="alice" if i % 2 else "bob",
                msg=f"failed login attempt {i}" if i % 4 == 0 else f"ok request {i}",
                sev="high" if i % 4 == 0 else "info",
                raw=f"{source} {file} failed={i % 4 == 0} id={k}",
            ))
    ts = np.array([se_epoch(e.ts) for e in events], dtype=np.float64)
    return events, ts


def se_epoch(iso: str) -> float:
    from app.store import _iso_to_epoch

    return float(_iso_to_epoch(iso) or 0.0)


def _both_ways(events, ts, q: str, src_set: set[str], sev_set: set[str] | None = None) -> tuple[dict, dict]:
    """The same query answered by the vector path and by the scan path."""
    sev_set = sev_set or set()
    version = 991
    se.invalidate()
    se.get_index(events, ts, version)          # the vector path, with the index in place
    fast = se.search(events, ts, version, q, 0, len(events), src_set, sev_set, 0, 50)
    se.invalidate()
    # ...and the scan path, which is the definition of the right answer. `search()` never builds, so
    # with the index gone it walks the pool with the exact Python predicate.
    slow = se.search(events, ts, version, q, 0, len(events), src_set, sev_set, 0, 50)
    se.invalidate()
    return fast, slow


@pytest.mark.parametrize("src", [
    {"aaa11111"},                        # by source id — what the UI chips send
    {"access.log"},                      # by file name
    {"nginx access"},                    # by label: BOTH nginx sources
    {"aaa11111", "ccc33333"},
])
def test_the_source_filter_gives_the_same_answer_either_way(src):
    events, ts = _pool()
    fast, slow = _both_ways(events, ts, "failed", src)
    assert fast["engine"] in ("vector", "cuda") and slow["engine"] == "cpu"
    assert fast["total"] == slow["total"]
    assert [e.id for e in fast["rows"]] == [e.id for e in slow["rows"]]
    assert fast["total"] > 0


def test_a_source_that_matches_nothing_returns_nothing_not_everything():
    """The old substring lowering would match a chip value that is merely PART of a label. The
    predicate never accepted that, so the rows were dropped later — but an exact mask has to refuse it
    up front rather than widening the candidate set."""
    events, ts = _pool()
    fast, slow = _both_ways(events, ts, "", {"no-such-source"})
    assert fast["total"] == slow["total"] == 0


def test_a_partial_source_name_matches_nothing_in_both_paths():
    """`access` is a substring of two labels and equal to none. Both paths must agree — and they agree
    on NOTHING, because the source filter is equality (the DSL's `source:access` is the substring one)."""
    events, ts = _pool()
    fast, slow = _both_ways(events, ts, "", {"access"})
    assert fast["total"] == slow["total"] == 0


def test_the_severity_filter_still_agrees():
    events, ts = _pool()
    fast, slow = _both_ways(events, ts, "", {"aaa11111"}, {"high"})
    assert fast["total"] == slow["total"] > 0
    assert all(e.sev == "high" for e in fast["rows"])


def test_a_filtered_search_no_longer_walks_every_candidate():
    """The point of the change: with an exact mask the engine answers a page from the popcount, so a
    filtered query does not touch the Python predicate at all. Counting predicate calls is how that is
    proved — timing would be a flake."""
    events, ts = _pool()
    version = 992
    se.invalidate()
    se.get_index(events, ts, version)

    calls = {"n": 0}
    real = se.node_pred

    def counting(ast):
        inner = real(ast)

        def pred(e):
            calls["n"] += 1
            return inner(e)

        return pred

    se.node_pred = counting            # type: ignore[assignment]
    try:
        res = se.search(events, ts, version, "failed", 0, len(events), {"aaa11111"}, set(), 0, 20)
    finally:
        se.node_pred = real            # type: ignore[assignment]
    assert res["total"] > 0
    assert res["engine"] in ("vector", "cuda")
    assert calls["n"] == 0, f"the predicate ran {calls['n']} times for a filtered page"
