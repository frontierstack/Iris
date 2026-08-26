"""Two entity regexes scan the whole raw line on every event, at ingest — behind a literal gate now.

`AKIA_RE` and `KEYFP_RE` are the only patterns in `extract_entities` that scan the full line with no
cheap necessary condition in front of them. Neither is case-insensitive and each has a mandatory
literal, so the gate is exact by construction: a line without "AKIA"/"ASIA", or without "SHA256:",
cannot match. Measured on an ordinary 195-char proxy line that matches neither, 7.8 us against
0.23 us — ~80 s per 10 M events of normalization, which is paid on every phase-2 parse.

The risk is the same as any pre-filter: a key that no longer extracts is an entity missing from the
graph, from `entity:` search and from every profile, with nothing reporting it. So the test is that
real keys still come out, in the awkward positions too.
"""
from __future__ import annotations

import pytest

from app.normalize import extract_entities
from app.parsers.base import ParsedEvent

KEY = "AKIAIOSFODNN7EXAMPLE"          # AWS's own documented example key
TEMP = "ASIA" + "Z" * 16
FP = "SHA256:abcdefghijklmnopqrstuvwxyz0123456789+/AAAA"


def _ev(raw: str) -> ParsedEvent:
    return ParsedEvent(ts="2026-08-26T00:00:00Z", msg=raw, raw=raw, fields={})


@pytest.mark.parametrize("wanted,raw", [
    (KEY, f"config loaded aws_key={KEY} region=us-east-1"),
    (KEY, '{"aws_key":"' + KEY + '"}'),
    (KEY, KEY),                                   # the whole line
    (KEY, f"prefix {KEY}"),                       # at the end, no trailing boundary character
    (TEMP, f"assumed role token {TEMP} expires soon"),
    (FP, f"sshd: Accepted publickey for alice: RSA {FP}"),
    (FP, FP),
])
def test_a_gated_pattern_still_extracts_its_key(wanted: str, raw: str) -> None:
    assert wanted in extract_entities(_ev(raw)), raw


def test_both_keys_on_one_line() -> None:
    ents = extract_entities(_ev(f"login key={KEY} fingerprint={FP} done"))
    assert KEY in ents and FP in ents


def test_ordinary_traffic_extracts_neither() -> None:
    """The gate has to actually reject, or it is a correct filter that saves nothing."""
    line = ('10.0.0.5 - - "GET /api/v1/items/42?page=3&sort=desc HTTP/1.1" 200 1234 "-" '
            '"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"')
    ents = extract_entities(_ev(line))
    assert not [e for e in ents if e.startswith(("AKIA", "ASIA", "SHA256:"))]
    assert "10.0.0.5" in ents, "the rest of extraction must be untouched"
