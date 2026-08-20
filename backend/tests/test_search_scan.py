"""The substring scan: chunked, multi-anchor, and bit-identical to a naive search.

Two changes were made for speed on the analyst's 5.4 GB index and BOTH could silently change what a
search finds, which in an evidence tool is worse than being slow:

* the scan walks the packed buffer in windows instead of comparing it whole (an unchunked compare
  allocates a bool the size of the buffer, next to the buffer);
* up to three of the needle's rarest bytes anchor a candidate position before any gather, instead of
  one — a needle of common characters (`45.83.140.22`) otherwise produces hundreds of millions of
  candidates to gather over.

So these tests do not measure time. They pin that the engine finds exactly what a plain Python
`in` finds, including across window boundaries, which is where a chunked scan loses matches.
"""
from __future__ import annotations

import numpy as np
import pytest

from app import search as se
from app.models import Event


def _pool(n: int = 2600, seed: int = 7) -> tuple[list[Event], np.ndarray]:
    rng = np.random.default_rng(seed)
    words = ["failed", "accepted", "sudo", "45.83.140.22", "10.0.0.5", "dns", "proxy", "GET /admin",
             "user=alice", "user=bob", "status=200", "status=503", "sshd", "kernel"]
    events: list[Event] = []
    for i in range(n):
        picked = " ".join(str(words[int(rng.integers(0, len(words)))]) for _ in range(4))
        events.append(Event(
            id=f"e{i}", ts=f"2026-08-19T{i // 3600 % 24:02d}:{i // 60 % 60:02d}:{i % 60:02d}Z",
            source="syslog", sourceId="s1", file="auth.log", host=f"h{i % 5}",
            user="alice" if i % 2 else "bob", msg=picked, sev="info", raw=f"{i} {picked}",
        ))
    ts = np.arange(len(events), dtype=np.float64)
    return events, ts


def _naive(events: list[Event], needle: str) -> set[str]:
    n = needle.lower()
    return {e.id for e in events if n in se._doc(e).decode("utf-8", "replace").lower()}


@pytest.fixture()
def indexed():
    events, ts = _pool()
    se.invalidate()
    idx = se.get_index(events, ts, 4242)
    yield events, idx
    se.invalidate()


@pytest.mark.parametrize("needle", [
    "failed", "45.83.140.22", "status=503", "user=alice", "sshd", "GET /admin",
    "zzz-not-present", "e", "10.0.0.5",
])
def test_the_scan_finds_exactly_what_a_plain_search_finds(indexed, needle):
    events, idx = indexed
    eng = se._Engine(idx)
    mask = eng.contains(needle.lower().encode("utf-8"))
    got = {events[i].id for i in np.flatnonzero(np.asarray(se.compute.asnumpy(mask)))}
    assert got == _naive(events, needle)


def test_a_match_that_straddles_a_window_boundary_is_still_found(monkeypatch, indexed):
    """The failure mode of a chunked scan: a needle whose first byte is in one window and the rest in
    the next. A tiny window forces that case on every match."""
    events, idx = indexed
    monkeypatch.setattr(se, "_SCAN_CHUNK", 8)
    eng = se._Engine(idx)
    for needle in ("45.83.140.22", "status=503", "failed"):
        mask = eng.contains(needle.encode("utf-8"))
        got = {events[i].id for i in np.flatnonzero(np.asarray(se.compute.asnumpy(mask)))}
        assert got == _naive(events, needle), needle


def test_every_anchor_count_agrees(monkeypatch, indexed):
    """The anchors are an optimisation, so the answer must not depend on how many are used."""
    events, idx = indexed
    eng = se._Engine(idx)
    baselines = {}
    for anchors in (1, 2, 3, 5):
        monkeypatch.setattr(se, "_ANCHORS", anchors)
        for needle in ("45.83.140.22", "user=alice", "sudo"):
            mask = eng.contains(needle.encode("utf-8"))
            got = frozenset(int(i) for i in np.flatnonzero(np.asarray(se.compute.asnumpy(mask))))
            baselines.setdefault(needle, got)
            assert got == baselines[needle], f"{needle} changed with {anchors} anchors"


def test_a_search_through_the_public_api_agrees_with_the_scan_path(indexed):
    """End to end: the vector answer and the no-index answer are the same rows in the same order."""
    events, idx = indexed
    ts = np.arange(len(events), dtype=np.float64)
    fast = se.search(events, ts, 4242, "45.83.140.22", 0, len(events), set(), set(), 0, 25)
    se.invalidate()
    slow = se.search(events, ts, 4242, "45.83.140.22", 0, len(events), set(), set(), 0, 25)
    assert fast["engine"] in ("vector", "cuda") and slow["engine"] == "cpu"
    assert fast["total"] == slow["total"] > 0
    assert [e.id for e in fast["rows"]] == [e.id for e in slow["rows"]]


def test_the_find_path_and_the_vector_path_agree(indexed):
    """Two implementations of one question, so they must answer identically.

    On the CPU the engine uses `bytes.find` (memmem) over the packed buffer; on the GPU, and when a
    term is too common for a Python loop, it uses the vectorised scan. Measured on a 247 MB index the
    find path is 3-8x faster — but a fast path that finds a different set of events is an evidence
    bug, not an optimisation.
    """
    events, idx = indexed
    eng = se._Engine(idx)
    assert idx.raw is not None, "a CPU index must expose the packed buffer for the find path"

    for needle in ("failed", "45.83.140.22", "user=alice", "sshd", "zzz-not-present", "e"):
        nd = needle.encode("utf-8")
        via_find = eng.contains(nd)
        hits = eng._find_all(nd)
        assert hits is not None, f"{needle} should be within the find cap on this fixture"

        idx.raw, saved = None, idx.raw          # force the vectorised path on the same index
        try:
            via_scan = eng.contains(nd)
        finally:
            idx.raw = saved
        assert np.array_equal(np.asarray(se.compute.asnumpy(via_find)),
                              np.asarray(se.compute.asnumpy(via_scan))), needle


def test_a_term_too_common_for_the_loop_falls_back_and_is_still_right(monkeypatch, indexed):
    """The find loop gives up above a hit density where the scan is cheaper. The ANSWER must not
    depend on which side of that line a term lands, so force the bail-out and compare."""
    events, idx = indexed
    eng = se._Engine(idx)
    needle = b"failed"

    full = eng.contains(needle)
    monkeypatch.setattr(se, "_FIND_MIN_CAP", 1)
    monkeypatch.setattr(se, "_FIND_BYTES_PER_HIT", 10**9)   # cap of 1 -> every term "too common"
    monkeypatch.setattr(se, "_FIND_PROBE", 1)
    assert eng._find_all(needle) is None, "the loop should have given up"
    assert np.array_equal(np.asarray(se.compute.asnumpy(eng.contains(needle))),
                          np.asarray(se.compute.asnumpy(full)))


def test_a_derived_message_is_not_packed_twice(indexed):
    """`Event` sets `_msg = None` when the message is just the raw prefix; packing it again duplicated
    a large slice of every document, costing buffer size and doubling the hits a scan walks. Dropping
    it changes nothing semantically — a substring of a prefix of `raw` is a substring of `raw`."""
    from app.models import Event

    derived = Event(id="d1", raw="sshd: Failed password for root", msg="sshd: Failed password for root")
    assert derived._msg is None
    doc = se._doc(derived)
    assert doc.count(b"failed password for root") == 1

    distinct = Event(id="d2", raw="raw text here", msg="a real summary")
    assert distinct._msg is not None
    body = se._doc(distinct)
    assert b"a real summary" in body and b"raw text here" in body


def test_the_scan_path_stops_counting_once_it_has_the_page(monkeypatch):
    """No index means every event goes through the Python predicate. On an 11 M-event pool that
    measured 172 s per query — nearly all of it counting matches nobody asked for, long after the page
    of 25 rows was ready. The count becomes a FLOOR, and says so."""
    events, ts = _pool(3000)
    se.invalidate()                                   # force the scan path
    monkeypatch.setattr(se, "_SCAN_COUNT_AHEAD", 50)

    res = se.search(events, ts, 77, "failed", 0, len(events), set(), set(), 0, 10)
    assert res["engine"] == "cpu"
    assert len(res["rows"]) == 10                     # the page is complete
    assert res["totalExact"] is False                 # ...and the count is honest about being partial
    assert res["total"] <= 60                         # it stopped early rather than counting them all


def test_a_small_result_set_is_still_counted_exactly(monkeypatch):
    """The floor only appears when the scan actually stopped early. A query whose every match fits
    inside the budget must report an exact total — otherwise every count grows a '+' that means
    nothing."""
    events, ts = _pool(3000)
    se.invalidate()
    monkeypatch.setattr(se, "_SCAN_COUNT_AHEAD", 10_000)

    res = se.search(events, ts, 78, "45.83.140.22", 0, len(events), set(), set(), 0, 10)
    assert res["engine"] == "cpu"
    assert res["totalExact"] is True
    assert res["total"] == len(_naive(events, "45.83.140.22"))


def test_the_indexed_path_always_reports_an_exact_total():
    """The index counts with a popcount, so there is never a reason to approximate there."""
    events, ts = _pool(3000)
    se.invalidate()
    se.get_index(events, ts, 79)
    try:
        res = se.search(events, ts, 79, "failed", 0, len(events), set(), set(), 0, 10)
        assert res["engine"] in ("vector", "cuda")
        assert res["totalExact"] is True
        assert res["total"] == len(_naive(events, "failed"))
    finally:
        se.invalidate()
