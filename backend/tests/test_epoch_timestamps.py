"""Logs whose only timestamp is an epoch — seconds, milliseconds, microseconds or nanoseconds.

"Some logs have just epoch." The old shape accepted 10 digits (with a fraction) or exactly 13, so a
16-digit microsecond stamp, a 19-digit nanosecond one and `1724580000123.456` all read as text and
the event was timestampless — sorted last, matching no window. The unit is decided by the integer
digit count (normalize.epoch_to_datetime), in integer arithmetic so the low digits survive.
"""
from __future__ import annotations

import io

from app.normalize import leading_ts, parse_ts
from app.parsers.csv import CsvParser
from app.parsers.jsonl import JsonlParser
from app.parsers.plaintext import PlaintextParser

T = "2024-08-25T10:00:00"


def test_every_epoch_unit_parses_to_the_same_instant():
    assert parse_ts("1724580000").isoformat().startswith(T)
    assert parse_ts("1724580000123").isoformat() == T + ".123000+00:00"
    assert parse_ts("1724580000123456").isoformat() == T + ".123456+00:00"
    assert parse_ts("1724580000123456789").isoformat() == T + ".123456+00:00"
    assert parse_ts("1724580000.5").isoformat() == T + ".500000+00:00"
    assert parse_ts("1724580000123.456").isoformat() == T + ".123456+00:00"


def test_a_number_that_is_not_an_epoch_is_not_a_timestamp():
    assert parse_ts("17245800001") is None            # 11 digits: neither unit
    assert parse_ts("1724580000123456789012") is None
    assert parse_ts("123") is None


def test_the_raw_phase_reads_a_leading_epoch_of_any_unit():
    assert leading_ts("1724580000123 host sshd: x") == T + "Z"
    assert leading_ts("1724580000123456789 y") == T + "Z"
    assert leading_ts('"1724580000.25",host,x') == T + "Z"
    assert leading_ts("12345 no") == ""


def test_plaintext_jsonl_and_csv_all_take_an_epoch():
    plain = list(PlaintextParser().parse(io.StringIO("1724580000123 host sshd[1]: hello\n")))
    assert plain[0].ts.isoformat().startswith(T) and plain[0].msg == "host sshd[1]: hello"
    js = list(JsonlParser().parse(io.StringIO('{"epoch_ms":1724580000123,"msg":"hi"}\n'
                                              '{"unix_time":1724580000.75,"message":"yo"}\n')))
    assert [e.ts.isoformat() for e in js] == [T + ".123000+00:00", T + ".750000+00:00"]
    csv = list(CsvParser().parse(io.StringIO("epoch_ms,host,msg\n1724580000123,h1,a\n1724580000999,h2,b\n")))
    assert [(e.ts.isoformat(), e.host) for e in csv] == [(T + ".123000+00:00", "h1"), (T + ".999000+00:00", "h2")]
