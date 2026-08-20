"""Raw ingest with timestamps — the default, and why.

The analyst's words: *"I just want the raw events... The only thing that might need to be parsed out
is the timestamp."* That is now what an ingest does. Measured on a 20-column proxy export:

| | raw | interpreted |
|---|---|---|
| per event | 534 B | 1,617 B |
| search index | 286 B/event | 770 B/event |
| whole pool | 3.4 bytes of RAM per byte of log | 16.5 |
| ingest | 0.7 s | 10.7 s |

Almost all of the difference is a per-event dict holding one string per column — the same line stored
again, in pieces. So phase 2 is opt-in per source, and phase 1 reads the one thing that cannot be
recovered later by looking at the line again: WHEN it happened. Without a timestamp an event has no
place in a time window, a timeline or a burst rule, and no later question can put it there.

The rule that governs this file: a raw event's timestamp is READ, never inferred. A line whose time
cannot be recognised keeps `ts=""` and sorts last — it does not get a guess, and it does not get the
ingest's clock.
"""
from __future__ import annotations

import pytest

from app.enrich import raw_events
from app.normalize import leading_ts


@pytest.mark.parametrize("line,expect", [
    ("2026-08-19T10:00:00Z host1 sshd[11]: Failed password", "2026-08-19T10:00:00Z"),
    ("2026-08-19 10:00:00 host1 something", "2026-08-19T10:00:00Z"),
    ('"Aug 17, 2026 @ 09:32:52.000","-","150.171.28.10"', "2026-08-17T09:32:52Z"),
    ("Aug 17 09:32:52 host sshd[1]: x", "2026-08-17T09:32:52Z"),
    ('10.0.0.1 - - [17/Aug/2026:09:32:52 +0000] "GET / HTTP/1.1" 200', "2026-08-17T09:32:52Z"),
    ("2026-08-19T10:00:00+02:00 host", "2026-08-19T08:00:00Z"),
])
def test_the_shapes_a_log_line_actually_starts_with_are_read(line, expect):
    assert leading_ts(line) == expect


@pytest.mark.parametrize("line", [
    "no timestamp anywhere in this line",
    "ERROR something went wrong",
    "1.6.3 version string",
    "",
    "192.168.0.1 connected",
    "id=12345678 action=allow",
])
def test_a_line_with_no_recognisable_time_gets_no_time(line):
    """The honesty rule. A guessed timestamp puts an event at a moment it may not belong to, and every
    time filter, timeline and burst rule downstream would treat that as fact."""
    assert leading_ts(line) == ""


def test_the_cache_returns_the_same_answer_as_a_cold_read():
    """Runs of lines share a second in any real export, so the parse is cached — but a cache that
    answers differently from a fresh parse would be a silent evidence bug."""
    cache: dict[str, str] = {}
    lines = [f'"Aug 17, 2026 @ 09:32:{s:02d}.000",data' for s in range(30)] * 4
    cached = [leading_ts(l, cache) for l in lines]
    cold = [leading_ts(l) for l in lines]
    assert cached == cold
    assert all(cached)
    assert len(cache) == 30


LOG = b"".join(
    f'"Aug 17, 2026 @ 09:{i // 60 % 60:02d}:{i % 60:02d}.000",10.0.0.{i % 200},GET,200,allow\n'.encode()
    for i in range(500)
)


def test_a_raw_ingest_produces_timestamps_and_nothing_else():
    events = raw_events("s1", "proxy.csv", "delimited", LOG, "l1")
    assert len(events) == 500
    assert all(e.ts for e in events), "every one of these lines starts with a time"
    assert all(e.raw for e in events)
    # ...and none of the expensive interpretation
    assert all(not e.fields for e in events), "raw ingest must not build a per-event field dict"
    assert all(not e.entities for e in events)
    assert all(e.host == "" and e.user == "" for e in events)


def test_a_header_row_gets_no_timestamp_rather_than_a_wrong_one():
    data = b"timestamp,src_ip,method\n" + LOG
    events = raw_events("s2", "proxy.csv", "delimited", data, "l2")
    assert events[0].raw.startswith("timestamp,")
    assert events[0].ts == "", "a header line has no time; inventing one puts it in the timeline"
    assert all(e.ts for e in events[1:])


def test_raw_events_stay_cheap():
    """The whole point. A regression here is a regression in how much evidence fits on the machine."""
    import sys

    events = raw_events("s3", "proxy.csv", "delimited", LOG, "l3")
    e = events[len(events) // 2]
    naive = sys.getsizeof(e) + sys.getsizeof(e.raw) + sys.getsizeof(e.ts)
    assert naive < 700, f"{naive} B for a raw event of a {len(e.raw)}-char line"
    # the containers are the SHARED frozen empties, not per-event allocations
    assert events[0].fields is events[1].fields
    assert events[0].entities is events[1].entities


def test_ingest_defaults_to_raw():
    """`autoEnrich` defaults off: interpreting is per source, on demand."""
    from app.models import IngestSettings

    assert IngestSettings().autoEnrich is False
