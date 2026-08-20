"""The packed search index survives a restart (app/index_store.py).

Measured on the analyst's workspace: 11.18 M events, a 5.4 GB packed buffer, **164.7 s to build** —
a pure-Python `packed += _doc(e)` loop that does not vectorise. Until it lands every query takes the
scan path, which measured 35-45 s on that pool. So after every restart there was a multi-minute
window in which every search was slow, which is what "constantly pending with the spinner" was.

The pool comes back byte-identical (app/pool_store.py), so the index built from it is the same index.
These tests pin the part that matters: a restored index answers EXACTLY like a rebuilt one, and every
reason to distrust the file — a changed pool, a changed packing code, an edited byte, a short file —
rebuilds instead of serving it.
"""
from __future__ import annotations

import numpy as np
import pytest

from app import config, index_store
from app import search as se
from app.models import Event

QUERIES = ["failed", "45.83.140.22", "user=alice", "status=503", "nothing-here"]


def _pool(n: int = 2600) -> tuple[list[Event], np.ndarray]:
    rng = np.random.default_rng(11)
    words = ["failed", "accepted", "45.83.140.22", "10.0.0.5", "user=alice", "user=bob",
             "status=200", "status=503", "sshd", "dns", "proxy"]
    events = []
    for i in range(n):
        picked = " ".join(str(words[int(rng.integers(0, len(words)))]) for _ in range(4))
        events.append(Event(id=f"e{i}", ts=f"2026-08-19T00:00:{i % 60:02d}Z", source="syslog",
                            sourceId="s1", file="auth.log", host=f"h{i % 4}",
                            user="alice" if i % 2 else "bob", msg=picked, sev="info",
                            raw=f"{i} {picked}"))
    return events, np.arange(n, dtype=np.float64)


def _answers(events, ts, version, sig="") -> dict[str, tuple[int, tuple[str, ...]]]:
    out = {}
    for q in QUERIES:
        r = se.search(events, ts, version, q, 0, len(events), set(), set(), 0, 25)
        out[q] = (r["total"], tuple(e.id for e in r["rows"]), r["engine"])
    return out


@pytest.fixture(autouse=True)
def _clean():
    index_store.clear()
    se.invalidate()
    yield
    index_store.clear()
    se.invalidate()


def test_a_restored_index_answers_exactly_like_a_built_one():
    events, ts = _pool()
    sig = "test-sig-1"
    built = se.get_index(events, ts, 1, sig=sig)
    assert built.n == len(events)
    before = _answers(events, ts, 1)

    se.invalidate()                      # the restart: memory gone, the file on disk stays
    restored = se.get_index(events, ts, 1, sig=sig)
    assert restored.n == len(events)
    assert _answers(events, ts, 1) == before


def test_the_restore_does_not_repack_the_pool(monkeypatch):
    events, ts = _pool()
    sig = "test-sig-2"
    se.get_index(events, ts, 1, sig=sig)
    se.invalidate()

    monkeypatch.setattr(se, "_doc", lambda e: pytest.fail("the pool was re-packed instead of restored"))
    idx = se.get_index(events, ts, 1, sig=sig)
    assert idx.n == len(events)
    assert idx.bytes > 0


def test_a_different_signature_rebuilds():
    events, ts = _pool()
    se.get_index(events, ts, 1, sig="sig-A")
    se.invalidate()
    idx = se.get_index(events, ts, 1, sig="sig-B")      # e.g. a source changed, or the parser did
    assert idx.n == len(events)
    assert _answers(events, ts, 1)["failed"][0] > 0


def test_an_edited_file_is_a_miss_not_a_wrong_answer():
    """A corrupted index does not fail loudly — it silently changes which events a query finds."""
    events, ts = _pool()
    se.get_index(events, ts, 1, sig="sig-C")
    truth = _answers(events, ts, 1)
    se.invalidate()

    p = index_store._path()
    blob = bytearray(p.read_bytes())
    blob[-40] ^= 0x01                                   # one byte, inside the packed buffer
    p.write_bytes(bytes(blob))

    idx = se.get_index(events, ts, 1, sig="sig-C")      # rebuilt from the pool
    assert idx.n == len(events)
    assert _answers(events, ts, 1) == truth


def test_a_truncated_file_is_a_miss():
    events, ts = _pool()
    se.get_index(events, ts, 1, sig="sig-D")
    se.invalidate()
    p = index_store._path()
    blob = p.read_bytes()
    p.write_bytes(blob[: len(blob) // 2])
    assert index_store.load("sig-D") is None
    assert se.get_index(events, ts, 1, sig="sig-D").n == len(events)


def test_a_pool_with_a_different_event_count_is_refused():
    events, ts = _pool()
    se.get_index(events, ts, 1, sig="sig-E")
    se.invalidate()
    fewer, fewer_ts = events[:-100], ts[:-100]
    idx = se.get_index(fewer, fewer_ts, 1, sig="sig-E")
    assert idx.n == len(fewer)                          # rebuilt for the pool it was actually given


def test_the_cache_can_be_switched_off(monkeypatch):
    monkeypatch.setenv("IRIS_INDEX_CACHE", "0")
    events, ts = _pool()
    se.get_index(events, ts, 1, sig="sig-F")
    assert not index_store._path().exists()


def test_no_signature_anywhere_means_no_cache_and_no_crash(monkeypatch):
    """`get_index` is still callable when nothing can say what pool this is.

    The app installs a signature PROVIDER at startup (that is what lets a query-triggered warm use the
    cache, which is the path that runs after a restart), so "no signature" now means the provider is
    absent too — not merely that the caller omitted the argument."""
    monkeypatch.setattr(se, "_sig_provider", None)
    events, ts = _pool()
    idx = se.get_index(events, ts, 1)
    assert idx.n == len(events)
    assert not index_store._path().exists()


def test_the_provider_supplies_the_signature_when_the_caller_has_none():
    """The bug this closes: only the store's own warm passed a signature, so the index cache was never
    written by the warm a QUERY starts — and that is the one that runs after a restart. The file
    simply never appeared, with nothing in the log to explain it."""
    events, ts = _pool()
    se.set_signature_provider(lambda: "provided-sig")
    try:
        se.get_index(events, ts, 1)
        assert index_store._path().exists()
        se.invalidate()
        assert index_store.load("provided-sig") is not None
    finally:
        se.set_signature_provider(None)


def test_the_signature_covers_the_packing_code_and_the_pool():
    """Two different things must both invalidate it: what was indexed, and the code that packed it."""
    from app.store import STORE

    sig = index_store.signature(STORE)
    assert sig and sig.startswith(f"{index_store.INDEX_FORMAT}:")
    assert index_store._code_digest() in sig


def test_a_restore_reports_itself_as_building(monkeypatch):
    """Restoring a multi-gigabyte index takes minutes off a bind mount (127-167 s measured). For all
    of it `index_status()` used to say `idle`, which every screen renders as "nothing is happening"
    and every search reads as "no index" — a long operation with no feedback."""
    events, ts = _pool()
    se.get_index(events, ts, 1, sig="sig-status")
    se.invalidate()

    seen: list[dict] = []
    real = index_store.load

    def watched(sig):
        seen.append(se.index_status())          # what a request would see mid-restore
        return real(sig)

    monkeypatch.setattr(index_store, "load", watched)
    se.get_index(events, ts, 1, sig="sig-status")
    assert seen and seen[0]["state"] == "building"
    assert "restor" in seen[0]["note"].lower()


def test_a_missed_restore_does_not_leave_the_status_stuck_building(monkeypatch):
    """The 'building' published before the read must be cleared when the read turns out to be a miss,
    or the screens wait for a build that nobody started."""
    events, ts = _pool()
    monkeypatch.setattr(index_store, "load", lambda sig: None)
    assert se.index_from_cache("sig-miss", events, ts, 1) is None
    assert se.index_status()["state"] != "building"
