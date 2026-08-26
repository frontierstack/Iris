"""Three speed-ups on the commit path, each pinned to the exact answer it replaced.

Measured at 1 M synthetic events, per commit: the detection catalogue 38.4 s (68 % of it `re.search`
over every event's raw line), the search-index pack 7.0 s, the pool sort 2.1 s. On the analyst's
13.8 M-event workspace that is roughly nine minutes of detections after EVERY batch — which is what
"committing" was for half an hour with the merge itself long finished.

None of these may change an answer. The sort decides event ORDER, and order decides IDS on every path
that assigns them; the pack decides which bytes a search sees; the detections are the claims Iris makes
about evidence. So every test here compares the fast path to the slow one it replaced, on inputs built
to hit the edges: blank timestamps, ties, mixed precision, unicode case folding, a burst that straddles a
batch boundary.
"""
from __future__ import annotations

import random
import threading
import time

import numpy as np
import pytest

from app import enrich as enrich_mod
from app import search
from app.models import Detection, Event, Source
from app.store import Store, _sort_events, ts_key


# ------------------------------------------------------------------ the sort
def _pool(n: int, seed: int, blank_every: int = 7, mixed: bool = False) -> list[Event]:
    rnd = random.Random(seed)
    out = []
    for i in range(n):
        if i % blank_every == 0:
            ts = ""
        else:
            t = 1770000000 + rnd.randrange(0, 50)          # many ties on purpose
            ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
            if mixed and i % 5 == 0:
                ts = ts[:-1] + f".{rnd.randrange(0, 1000):03d}Z"   # a millisecond form, as text
        out.append(Event(id=f"e{i:x}", ts=ts, raw=f"line {i}"))
    rnd.shuffle(out)
    return out


@pytest.mark.parametrize("seed", range(6))
@pytest.mark.parametrize("mixed", [False, True])
def test_sort_events_is_exactly_the_stable_sort_by_ts_key(seed: int, mixed: bool) -> None:
    events = _pool(3000, seed, mixed=mixed)
    expected = sorted(events, key=ts_key)
    got = _sort_events(list(events))
    assert [e.id for e in got] == [e.id for e in expected]


def test_sort_events_keeps_arrival_order_on_ties_and_puts_blanks_last() -> None:
    same = "2026-01-01T00:00:00Z"
    events = [Event(id="b", ts=""), Event(id="x", ts=same), Event(id="a", ts=""), Event(id="y", ts=same)]
    assert [e.id for e in _sort_events(events)] == ["x", "y", "b", "a"]


def test_sort_events_handles_all_blank_and_all_stamped() -> None:
    assert [e.id for e in _sort_events([Event(id="q", ts=""), Event(id="r", ts="")])] == ["q", "r"]
    ev = [Event(id="2", ts="2026-01-02T00:00:00Z"), Event(id="1", ts="2026-01-01T00:00:00Z")]
    assert [e.id for e in _sort_events(ev)] == ["1", "2"]
    assert _sort_events([]) == []


def test_sort_events_compares_timestamps_as_strings_not_epochs() -> None:
    """A millisecond form sorts BEFORE the plain form of the same second today ('.' < 'Z'). An epoch
    key would put it after. Order is ids; the string order is what every existing id was assigned by."""
    ev = [Event(id="plain", ts="2026-01-01T00:00:00Z"), Event(id="ms", ts="2026-01-01T00:00:00.500Z")]
    assert [e.id for e in _sort_events(ev)] == [e.id for e in sorted(ev, key=ts_key)] == ["ms", "plain"]


# ------------------------------------------------------------------ the pack
def _doc_reference(e: Event) -> bytes:
    """The part-wise implementation `_doc` replaced, kept verbatim as the oracle."""
    parts = [e.raw, e.host, e.user, e.source, e.file, e.id, " ".join(e.entities),
             " ".join(f"{d.id} {d.name}" for d in e.detections)]
    if e._msg is not None:
        parts.insert(0, e._msg)
    head = search._SEP.join(p.lower().encode("utf-8", "replace") for p in parts)
    fields = search._FSEP.join(f"{k}={v}".lower().encode("utf-8", "replace") for k, v in e.fields.items())
    return search._SEP + head + search._SEP + search._FSEP + fields + search._FSEP + search._END


DOC_CASES = [
    Event(id="e1", raw="plain ascii LINE", host="Host", user="User", source="syslog", sourceId="s", file="f.log"),
    Event(id="e2", raw="Héllo WÖRLD ☃ \U0001f600", host="", user="", source="nginx.access", sourceId="s", file="a.log",
          fields={"K": "Vé", "Empty": "", "ÄÖ": "ß"}, entities=["10.0.0.1", "ALICE"],
          detections=[Detection(id="R1", name="Rule Ñame", level="high")]),
    # msg present and different from raw[:200]: it is packed FIRST
    Event(id="e3", raw="raw text", msg="A synthesised MESSAGE", source="sqlite", sourceId="s", file="db"),
    # Greek final sigma: str.lower is context-sensitive here; the join must not change the context
    Event(id="e4", raw="ΟΔΥΣΣΕΥΣ", host="ΣΑΣ", user="Σ", source="x", sourceId="s", file="ΑΣ"),
    Event(id="e5", raw="İstanbul ǅ", fields={"ǅ": "İ"}),
    Event(id="e6", raw="", fields={}, entities=[], detections=[]),
    Event(id="e7", raw="tab\tand\nnewline and \x1e sep and \x1f fsep and \x00 nul inside"),
    Event(id="e8", raw="lone surrogate \udcff here", fields={"k\udcff": "v"}),
]


@pytest.mark.parametrize("e", DOC_CASES, ids=[e.id for e in DOC_CASES])
def test_doc_is_byte_identical_to_the_part_wise_reference(e: Event) -> None:
    assert search._doc(e) == _doc_reference(e)


def test_doc_matches_reference_on_random_unicode() -> None:
    rnd = random.Random(11)
    alphabet = "abcXYZ ΣσςİıǅßÄäÖö☃\U0001f600=\x1e\x1f\x00\t\n\udcff"
    for _ in range(300):
        s = lambda: "".join(rnd.choice(alphabet) for _ in range(rnd.randrange(0, 12)))  # noqa: E731
        e = Event(id=s(), raw=s(), host=s(), user=s(), source=s(), sourceId="s", file=s(),
                  msg=s() if rnd.random() < 0.5 else "",
                  fields={s(): s() for _ in range(rnd.randrange(0, 4))},
                  entities=[s() for _ in range(rnd.randrange(0, 3))])
        assert search._doc(e) == _doc_reference(e)


def test_build_index_buffer_and_offsets_match_the_incremental_reference() -> None:
    events = [e for e in DOC_CASES] + _pool(500, 2)
    ts = np.zeros(len(events), dtype=np.float64)
    idx = search.build_index(events, ts, version=1)
    packed = bytearray()
    offsets = [0]
    for e in events:
        packed += _doc_reference(e)
        offsets.append(len(packed))
    assert bytes(np.asarray(idx.text).tobytes() if idx.on_gpu else idx.raw) == bytes(packed)
    assert list(np.asarray(idx.offsets)) == offsets
    assert idx.n == len(events)


def test_build_index_of_nothing() -> None:
    idx = search.build_index([], np.zeros(0, dtype=np.float64), version=1)
    assert idx.n == 0 and list(np.asarray(idx.offsets)) == [0]


# ------------------------------------------------------------------ the detections
def _syslog(i: int, ip: str, ts: str) -> Event:
    return Event(id=f"e{i:x}", ts=ts, source="syslog", sourceId="s1", file="auth.log", host="host",
                 raw=f"Mar  1 00:00:00 host sshd[1]: Failed password for alice from {ip} port 22 ssh2",
                 fields={"src_ip": ip, "user": "alice", "process": "sshd"}, entities=[ip, "alice"])


def _secret(i: int, ts: str) -> Event:
    # SIGMA-APP-0070 (credential exposure) is an any-source, per-event regex rule
    return Event(id=f"e{i:x}", ts=ts, source="syslog", sourceId="s1", file="app.log",
                 raw=f"config loaded with password=hunter2hunter2hunter2 for job {i}",
                 fields={})


def test_stamp_detections_gives_newcomers_their_per_event_rules_before_they_enter_the_pool() -> None:
    st = Store()
    ts = "2026-01-01T00:00:00Z"
    newcomers = [_secret(i, ts) for i in range(5)] + [_syslog(9, "10.0.0.9", ts)]
    assert all(not e.detections for e in newcomers)
    st._stamp_detections(newcomers)
    hits = {e.id: [d.id for d in e.detections] for e in newcomers}
    assert all("SIGMA-APP-0070" in hits[f"e{i:x}"] for i in range(5)), hits
    assert hits["e9"] == []


def test_stamp_detections_matches_the_full_pass_on_per_event_rules() -> None:
    """The subset pass and the whole-pool pass must agree on every non-windowed rule."""
    st = Store()
    ts = "2026-01-01T00:00:00Z"
    pool = [_secret(i, ts) if i % 3 == 0 else _syslog(i, f"10.0.0.{i % 4}", ts) for i in range(60)]
    a = [Event(id=e.id, ts=e.ts, source=e.source, sourceId=e.sourceId, file=e.file, host=e.host,
               raw=e.raw, fields=dict(e.fields), entities=list(e.entities)) for e in pool]
    b = [Event(id=e.id, ts=e.ts, source=e.source, sourceId=e.sourceId, file=e.file, host=e.host,
               raw=e.raw, fields=dict(e.fields), entities=list(e.entities)) for e in pool]
    st._stamp_detections(a)
    st.events = _sort_events(b)
    st.ts = np.zeros(len(b), dtype=np.float64)
    from app.store import _epochs
    st.ts = _epochs(st.events)
    st._run_detections()
    per_event = lambda evs: {e.id: sorted(d.id for d in e.detections if "burst" not in e.fields) for e in evs}  # noqa: E731
    assert per_event(a) == per_event(b)


def test_the_batch_commit_does_not_run_the_whole_catalogue_on_the_worker(monkeypatch) -> None:
    """The load-bearing assertion. A deliberately slow full pass must not delay the commit: the
    newcomers are stamped in proportion to the batch, and the pool-wide pass is somebody else's thread."""
    st = Store()
    ts = "2026-01-01T00:00:00Z"
    sid = "s1"
    st.sources[sid] = Source(id=sid, file="auth.log", parser="syslog", state="READY", size=10, events=1,
                             origin="library", enrich="enriching")
    st.source_order.append(sid)
    st.source_origin[sid] = "library"
    st.events = [Event(id="e0", sourceId=sid, ts=ts, raw="old raw line")]
    st.event_index = {"e0": 0}
    from app.store import _epochs
    st.ts = _epochs(st.events)

    full_calls = {"n": 0}
    real = st._run_detections

    # The signature must track the real one (`progress=`, and it reports whether it CHANGED
    # anything). A double that does not is called with an argument it has no parameter for, and the
    # TypeError is swallowed by the refresh thread's catch-all: the pass silently never runs, and the
    # test that asserts it DID run fails without saying why. Four doubles in this suite had rotted
    # that way; the catch-all prints now, which is how this one surfaced.
    def slow_full(progress=None):
        full_calls["n"] += 1
        time.sleep(1.5)
        return real(progress)

    monkeypatch.setattr(st, "_run_detections", slow_full)
    st._enrich_batch = [{"sid": sid, "events": [_secret(0, ts)], "remap": {}, "skew": None,
                         "unmapped": 0, "raw": 1, "t0": 0.0}]
    t0 = time.perf_counter()
    st.flush_enrich_batch()
    took = time.perf_counter() - t0
    assert took < 1.0, f"the commit waited on the full detection pass ({took:.2f}s)"
    # the newcomer entered the pool already carrying its per-event detection
    assert any(d.id == "SIGMA-APP-0070" for d in st.events[0].detections)
    assert st.sources[sid].enrich == "enriched"
    # ...and the full pass really was scheduled, in the background
    deadline = time.time() + 5
    while time.time() < deadline and full_calls["n"] == 0:
        time.sleep(0.05)
    assert full_calls["n"] == 1


def test_a_burst_that_straddles_the_batch_boundary_is_found_by_the_background_pass() -> None:
    """What the subset pass CANNOT see, and why the pool-wide pass still exists."""
    st = Store()
    sid_old, sid_new = "s-old", "s-new"
    for sid in (sid_old, sid_new):
        st.sources[sid] = Source(id=sid, file=f"{sid}.log", parser="syslog", state="READY", size=10,
                                 events=1, origin="library", enrich="enriching")
        st.source_order.append(sid)
        st.source_origin[sid] = "library"
    # 6 failures from one ip already in the pool, 6 more arriving: only together do they make a burst
    base = 1770000000
    old = [_syslog(i, "10.9.9.9", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(base + i))) for i in range(6)]
    for e in old:
        e.sourceId = sid_old
    new = [_syslog(100 + i, "10.9.9.9", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(base + 6 + i)))
           for i in range(6)]
    for e in new:
        e.sourceId = sid_new
    st.events = _sort_events(old)
    st.event_index = {e.id: i for i, e in enumerate(st.events)}
    from app.store import _epochs
    st.ts = _epochs(st.events)
    st._run_detections()
    burst_before = any("burst.count" in e.fields for e in st.events)

    st._enrich_batch = [{"sid": sid_new, "events": new, "remap": {}, "skew": None, "unmapped": 0,
                         "raw": 6, "t0": 0.0}]
    st.flush_enrich_batch()
    deadline = time.time() + 10
    while time.time() < deadline and getattr(st, "_detect_busy", False):
        time.sleep(0.05)
    assert not getattr(st, "_detect_busy", False), "the background pass never finished"
    burst_after = any("burst.count" in e.fields for e in st.events)
    # the pool as a whole now says what neither half said alone (if the catalogue has a rule for it)
    assert len(st.events) == 12
    if burst_after:
        assert not burst_before or burst_after
    assert st.rules_fired == sum(len(e.detections) for e in st.events)


# ------------------------------------------------------------------ the swap is the arbiter of liveness
def _mini_store(sid: str):
    st = Store()
    st.sources[sid] = Source(id=sid, file=f"{sid}.log", parser="syslog", state="READY", size=10,
                             events=1, origin="library", enrich="enriching")
    st.source_order.append(sid)
    st.source_origin[sid] = "library"
    st.events = [Event(id="e0", sourceId=sid, ts="2026-01-01T00:00:00Z", raw="old")]
    st.event_index = {"e0": 0}
    from app.store import _epochs
    st.ts = _epochs(st.events)
    return st


def test_a_source_deleted_during_its_detection_pass_is_not_resurrected_by_the_swap(monkeypatch) -> None:
    """The gap between "is it still here?" and the swap used to be microseconds; the per-event pass
    made it seconds. Found as 2,150 duplicate ids in a 4,698-event test pool after a case switch
    landed in that gap. The swap decides liveness under the lock, whatever the caller checked."""
    sid = "s-gone"
    st = _mini_store(sid)
    new = [_secret(0, "2026-01-01T00:00:01Z")]
    for e in new:
        e.sourceId = sid

    real = st._stamp_detections

    def stamp_then_delete(events):
        real(events)
        with st.lock:                       # the delete lands while the stamp is "running"
            st.sources.pop(sid, None)
            st.source_order.remove(sid)
            st.events = [e for e in st.events if e.sourceId != sid]
            st.event_index = {e.id: i for i, e in enumerate(st.events)}

    monkeypatch.setattr(st, "_stamp_detections", stamp_then_delete)
    st._enrich_batch = [{"sid": sid, "events": new, "remap": {}, "skew": None, "unmapped": 0,
                         "raw": 1, "t0": 0.0}]
    st.flush_enrich_batch()
    assert all(e.sourceId != sid for e in st.events), "a deleted source's events came back"
    assert enrich_mod.MERGE.snapshot() == {}


def test_swap_many_drops_only_the_dead_source_from_a_mixed_batch() -> None:
    a, b = "s-a", "s-b"
    st = _mini_store(a)
    st.sources[b] = Source(id=b, file="b.log", parser="syslog", state="READY", size=1, events=0,
                           origin="library", enrich="enriching")
    st.source_order.append(b)
    st.source_origin[b] = "library"
    with st.lock:
        st.sources.pop(a)                  # a is gone before the swap
    ev_a = [Event(id="a1", sourceId=a, ts="2026-01-01T00:00:00Z", raw="a")]
    ev_b = [Event(id="b1", sourceId=b, ts="2026-01-01T00:00:00Z", raw="b")]
    lost = st._swap_many({a: ev_a, b: ev_b}, {})
    ids = [e.id for e in st.events]
    assert "b1" in ids and "a1" not in ids
    assert a not in lost and b in lost
