"""Logs that roll in mid-ingest must stay searchable at index speed.

Every merge bumps the store version, and the version is what `index_ready` compares — so ONE new
source, however small, threw away the whole packed index and every query fell to the scan path until
a rebuild landed. Measured here on a 400,000-event pool: three queries took 113 ms with the index and
853 ms immediately after a 5,000-event file landed, and the scan path stops counting at
`_SCAN_COUNT_AHEAD`, so the hit count degrades to a floor at the same moment. At the analyst's
11 M-event scale the same step is sub-second against 35-45 s, for the whole duration of an ingest.

The index does not have to be wrong, though. A merge whose new events all sort at or after the last
event already in the pool leaves positions `0..n` exactly where they were, so the index still
describes them — it is simply SHORT. `note_append` records that, and a search answers the covered
prefix from the index and walks the uncovered tail with the same exact predicate that confirms index
candidates anyway. Bounded by `_TAIL_MAX`, because that walk is Python per event.

What these tests are really pinning is that the short index never changes an ANSWER: same totals,
same rows, same paging, same order as a full rebuild — and that anything which is not a pure append
(a reorder, a re-stamped detection) still invalidates.
"""
from __future__ import annotations

import numpy as np
import pytest

from app import config, search as se
from app.models import Detection, Event


def _ev(k: int, ts: str, raw: str, **kw) -> Event:
    return Event(id=f"e{k}", ts=ts, source="nginx access", file="access.log", sourceId="aaa11111",
                 host=f"host{k % 3}", user="alice" if k % 2 else "bob", msg=raw, sev="info",
                 raw=raw, fields={"n": str(k % 10)}, entities=[], **kw)


def _stamp(k: int) -> str:
    return f"2026-08-19T{(k // 3600) % 24:02d}:{(k // 60) % 60:02d}:{k % 60:02d}Z"


def _pool(n: int = 3000) -> list[Event]:
    # above search._MIN_VECTOR (2000) — below it no mask is ever built and the test would be
    # comparing the scan path against itself
    return [_ev(k, _stamp(k), f"GET /x/{k % 50} status={403 if k % 7 == 0 else 200} id={k}")
            for k in range(1, n + 1)]


def _ts(events: list[Event]) -> np.ndarray:
    from app.store import _epochs
    return _epochs(events)


def _tail(base: list[Event], n: int = 40) -> list[Event]:
    """New events that all sort AFTER everything in `base` — a rolling log."""
    start = len(base) + 1
    return [_ev(start + i, f"2026-08-20T00:{i // 60:02d}:{i % 60:02d}Z",
                f"GET /new/{i} status=418 quokka id={start + i}") for i in range(n)]


def _search(events, ts, version, q, **kw):
    kw.setdefault("offset", 0)
    kw.setdefault("limit", 200)
    return se.search(events, ts, version, q, 0, len(events), set(), set(), **kw)


@pytest.fixture(autouse=True)
def _clean():
    se.invalidate()
    yield
    se.invalidate()


def _grown(n_base: int = 3000, n_tail: int = 40):
    base = _pool(n_base)
    idx = se.get_index(base, _ts(base), 1)
    assert idx.n == len(base) and idx.version == 1
    tail = _tail(base, n_tail)
    grown = base + tail
    return base, tail, grown, _ts(grown)


def test_the_index_is_kept_and_the_new_events_are_still_found() -> None:
    base, tail, grown, ts = _grown()
    assert se.note_append(1, 2, len(base), len(grown)) is True

    res = _search(grown, ts, 2, "quokka")
    assert res["engine"] in ("vector", "cuda"), "a rolling append dropped the whole index"
    assert res["total"] == len(tail) and res["totalExact"] is True
    assert {e.id for e in res["rows"]} == {e.id for e in tail}


def test_a_short_index_answers_exactly_what_a_full_rebuild_would() -> None:
    """The whole risk of this optimisation: an answer that is quietly different."""
    base, tail, grown, ts = _grown()
    assert se.note_append(1, 2, len(base), len(grown)) is True
    short = {q: _search(grown, ts, 2, q) for q in
             ("status=403", "status=418", "alice", "/x/7", "quokka", "host1", "no-such-token")}

    se.invalidate()
    se.get_index(grown, ts, 3)                      # the rebuild the background warm would do
    for q, got in short.items():
        want = _search(grown, ts, 3, q)
        assert got["total"] == want["total"], f"{q}: {got['total']} != {want['total']}"
        assert [e.id for e in got["rows"]] == [e.id for e in want["rows"]], q
        assert got["engine"] in ("vector", "cuda") and want["engine"] in ("vector", "cuda")


def test_paging_and_newest_first_are_right_across_the_boundary() -> None:
    base, tail, grown, ts = _grown()
    assert se.note_append(1, 2, len(base), len(grown)) is True
    # a query that matches on BOTH sides of the seam
    q = "status="
    pages = [_search(grown, ts, 2, q, offset=o, limit=25) for o in (0, 25, 2980, 3005)]
    desc = _search(grown, ts, 2, q, limit=25, desc=True)

    se.invalidate()
    se.get_index(grown, ts, 3)
    for i, o in enumerate((0, 25, 2980, 3005)):
        want = _search(grown, ts, 3, q, offset=o, limit=25)
        assert [e.id for e in pages[i]["rows"]] == [e.id for e in want["rows"]], f"offset {o}"
        assert pages[i]["total"] == want["total"]
    want_desc = _search(grown, ts, 3, q, limit=25, desc=True)
    assert [e.id for e in desc["rows"]] == [e.id for e in want_desc["rows"]]
    assert desc["rows"][0].id == tail[-1].id, "newest-first must start in the tail"


def test_a_reorder_is_refused_and_so_is_an_oversized_tail() -> None:
    base, tail, grown, ts = _grown()
    # the index describes 3000 events; claiming it covers a pool that is SHORTER is a reorder
    assert se.note_append(1, 2, len(base) - 5, len(grown)) is False
    assert se.note_append(99, 2, len(base), len(grown)) is False, "a version it never saw"
    assert se.note_append(1, 2, len(base), len(base) + se._TAIL_MAX + 1) is False


def test_a_case_scoped_subset_never_answers_from_a_short_index() -> None:
    """A short index describes POOL positions; a scope=case list is a DIFFERENT list that merely
    happens to be at least as long. Serving it from the pool's index would return the right rows for
    the wrong events, which is why the subset path still demands an exact count."""
    base, tail, grown, ts = _grown()
    assert se.note_append(1, 2, len(base), len(grown)) is True
    subset = grown[:-1]                       # 3039 events against an index that describes 3000
    assert len(subset) > se._index.n
    sub_ts = _ts(subset)
    res = se.search(subset, sub_ts, 2, "quokka", 0, len(subset), set(), set(), 0, 200,
                    whole_pool=False)
    assert res["engine"] == "cpu", "a subset was answered from the whole-pool index"
    assert res["total"] == sum(1 for e in subset if "quokka" in e.raw)


def test_a_re_stamped_detection_must_not_be_served_from_the_old_index() -> None:
    """`_doc` packs each event's detection ids, so re-running the catalogue invalidates the prefix."""
    base, tail, grown, ts = _grown()
    assert se.note_append(1, 2, len(base), len(grown)) is True
    assert _search(grown, ts, 2, "SIGMA-TEST-0001")["total"] == 0

    base[0].detections = [Detection(id="SIGMA-TEST-0001", name="test rule", level="high")]
    se.invalidate()                                  # what Store.bump does when there is no hint
    got = _search(grown, ts, 3, "SIGMA-TEST-0001")
    assert got["total"] == 1 and got["rows"][0].id == base[0].id


# --------------------------------------------------------------- through the real ingest path
def _write(path, n: int, day: int, off: int) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for i in range(n):
            fh.write(f"2026-08-{day}T{(i // 3600) % 24:02d}:{(i // 60) % 60:02d}:{i % 60:02d}Z "
                     f"host{i % 8} user=alice status={403 if i % 7 == 0 else 200} id={off + i}\n")


@pytest.fixture()
def raw_only():
    """The suite turns phase 2 on for everyone (see conftest). This test must turn it off: an
    enrichment landing between the upload and the assertion REPLACES that source's events, which
    invalidates the index for a reason that has nothing to do with what is being pinned here."""
    before = config.get_settings().ingest.autoEnrich
    config.update_settings({"ingest": {"autoEnrich": False}})
    yield
    config.update_settings({"ingest": {"autoEnrich": before}})


def test_a_rolling_ingest_keeps_the_index_and_a_backfill_still_drops_it(tmp_path, raw_only) -> None:
    """The wiring: a real upload, not a hand-made call to note_append.

    Both halves matter. A file whose lines are NEWER than everything in the pool is the rolling
    case this exists for, and the index has to survive it. A file that lands INSIDE the pool's
    existing time range reorders the events the index describes, and there the only correct answer
    is to throw it away — a kept-but-wrong index would return the right rows for the wrong lines.
    """
    from app.store import STORE

    STORE.clear_all()
    big, roll, back = tmp_path / "big.log", tmp_path / "roll.log", tmp_path / "back.log"
    _write(big, 3000, 20, 0)
    _write(roll, 50, 21, 900_000)      # strictly newer
    _write(back, 50, 20, 800_000)      # same day: interleaves

    STORE.add_file("big.log", path=big, origin="library", background_ok=False)
    n_big = len(STORE.events)
    assert n_big >= 3000
    se.get_index(STORE.events, STORE.ts, STORE.version)

    STORE.add_file("roll.log", path=roll, origin="library", background_ok=False)
    assert se._index is not None, "a rolling append threw the index away"
    assert se._index.n == n_big and se._index.version == STORE.version
    res = _search(STORE.events, STORE.ts, STORE.version, "900010")
    assert res["engine"] in ("vector", "cuda") and res["total"] == 1

    STORE.add_file("back.log", path=back, origin="library", background_ok=False)
    assert se._index is None, "a backfill reorders the indexed positions and must invalidate"
