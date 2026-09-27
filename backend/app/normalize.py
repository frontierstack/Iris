"""Normalization: timestamps → UTC, severity inference, entity extraction."""
from __future__ import annotations

import ipaddress
import re
import time
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Optional

from dateutil import parser as dtparser
from dateutil import tz as dttz

from .parsers.base import ParsedEvent

UTC = timezone.utc

# The `regex` module is a pinned requirement (rules.py runs the sandbox on it) and its charset scan is
# 3-7x faster than `re`'s on the one pattern that runs over EVERY raw line at ingest (see
# `ipv4_findall`). Guarded like every optional import here: without it the `re` spelling of the same
# pattern is used and the answer is the same, only slower.
try:  # pragma: no cover - depends on the environment
    import regex as _regex
except ImportError:  # pragma: no cover
    _regex = None

# ---------------------------------------------------------------- timestamps

_ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,9}))?\s*(Z|[+-]\d{2}:?\d{2})?$"
)
_NGINX_RE = re.compile(r"^(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?$")
_SYSLOG_RE = re.compile(r"^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$")
# "26-Sep-2026 10:00:01.123" - BIND (named) query and general logs. No zone is written; like syslog
# it is read as UTC. dateutil would take it too, but only via the fallback that dominates ingest, and
# the raw phase never reaches the fallback - so without this a BIND log was entirely undated.
_BIND_RE = re.compile(r"^(\d{1,2})-([A-Za-z]{3})-(\d{4})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?$")
# "Aug 17, 2026 @ 09:32:52.000" — how Kibana / OpenSearch / Elastic Discover write a time when you
# export a search to CSV, and therefore how a great many exported logs arrive. dateutil is the last
# resort here and `fuzzy=False` refuses the " @ ", so without this the whole file lands with NO
# timestamp: on the analyst's workspace that was 11.1 M of 11.4 M events (a 10 M-row DNS export and a
# 1.1 M-row proxy export), i.e. 98 % of the pool invisible to every time filter, the timeline and
# every windowed detection — while looking perfectly parsed everywhere else.
_KIBANA_RE = re.compile(
    r"^([A-Za-z]{3,9})\s+(\d{1,2}),\s*(\d{4})\s*@\s*(\d{1,2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?"
    r"\s*(Z|[+-]\d{2}:?\d{2})?$")
# Epoch in SECONDS (10 digits, optional fraction), MILLISECONDS (13), MICROSECONDS (16) or NANOSECONDS
# (19). "Some logs have just epoch": a Suricata/Zeek export, a Kafka dump or a firewall CSV carries
# nothing but `1724580000123` per line, and the old shape (10 digits or exactly 13) read a 16-digit
# value as text and a `1724580000123.456` as nothing at all. The unit is decided by the INTEGER digit
# count in `epoch_to_datetime`, never by magnitude guessing past that.
_EPOCH_RE = re.compile(r"^(\d{10}|\d{13}|\d{16}|\d{19})(\.\d+)?$")
_MONTHS = {m: i + 1 for i, m in enumerate(["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"])}
# "08/21/2024 1:14 pm", "21/08/2024 10:14:02" - the Windows / Excel / US export shape, and the one common
# stamp that had NO fast path: it fell all the way to dateutil at ~150 us a call, i.e. ~40 % of a plain
# text parse whose lines carry it. `_us_datetime` reproduces dateutil's reading of exactly this shape
# (dayfirst=False: the first number is the month unless it is over 12; a 12-hour clock refuses an hour
# over 12, `12 am` is midnight, `h pm` adds twelve below noon; an impossible date is a failure) and
# DEFERS to dateutil for anything it is not certain of (a year under 1000, a first or second number
# over 31, any other separator). `tests/test_parse_speed.py` fuzzes it against dateutil itself, which
# is the only oracle that counts here.
_US_RE = re.compile(r"^(\d{1,2})/(\d{1,2})/(\d{4}) (\d{1,2}):(\d{2})(?::(\d{2}))?(?: ?([AaPp])[Mm])?$")
_DEFER = object()


def _us_datetime(m: "re.Match[str]"):
    a, b, y, h, mi, s, ap = m.groups()
    a, b, y, h, mi = int(a), int(b), int(y), int(h), int(mi)
    if y < 1000 or a > 31 or b > 31:
        return _DEFER
    if a > 12:
        day, month = a, b
    else:
        month, day = a, b
    if ap is not None:
        if h > 12:
            return None
        if ap in "aA":
            if h == 12:
                h = 0
        elif h < 12:
            h += 12
    try:
        return datetime(y, month, day, h, mi, int(s) if s is not None else 0, tzinfo=UTC)
    except ValueError:
        return None
# "looks like a date" gate for the dateutil fallback. THREE number groups joined by separators, a clock
# time, or a month name — one separator is not enough, or the version string "1.6" parses as 6 January.
_DATEISH_RE = re.compile(
    r"\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4}"
    r"|\d{1,2}:\d{2}"
    r"|(?i:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)"
)


def _tz_from(text: Optional[str]) -> timezone:
    if not text or text == "Z":
        return UTC
    sign = 1 if text[0] == "+" else -1
    digits = text[1:].replace(":", "")
    hh, mm = int(digits[:2]), int(digits[2:4])
    return timezone(sign * timedelta(hours=hh, minutes=mm))


# The window a real log timestamp can fall in. Anything outside it is a MISPARSE, not a log from the
# future: `_EPOCH_RE` matches any bare 10-digit number and `dateutil` will read almost any digit soup as
# a date, so a line of minified JavaScript produced events stamped 2034, 2042 and 2096 — which then sat
# at the head of the analyst's timeline. An unknown timestamp is honest; an invented one is evidence
# corruption, so an implausible parse is thrown away and the event goes unstamped.
_TS_MIN_YEAR = 1990
_TS_FUTURE_SLACK = timedelta(days=2)   # clock skew and genuinely-ahead-of-UTC hosts, nothing more


def _plausible(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    try:
        if dt.year < _TS_MIN_YEAR or dt > datetime.now(UTC) + _TS_FUTURE_SLACK:
            return None
    except (ValueError, OverflowError):
        return None
    return dt


# One pass over the head of a line to find a timestamp, for the RAW phase — where the whole point is
# to spend almost nothing per line. It matches only the shapes that actually lead a log line, and it
# never reaches the dateutil fallback (that is what makes `parse_ts` expensive enough to dominate
# ingest). Anchored at the start, after at most a few punctuation/quote characters, because a
# timestamp in the middle of a line is as likely to be something else's.
_LEAD_TS = re.compile(
    r"^[\"'\[( \t]{0,3}("
    r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?'      # ISO-8601
    r'|[A-Za-z]{3,9}\s+\d{1,2},\s*\d{4}\s*@\s*\d{1,2}:\d{2}:\d{2}(?:\.\d{1,6})?'        # Kibana export
    r'|\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s[+-]\d{4})?'                          # nginx
    r'|[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'                                          # syslog
    r'|\d{1,2}-[A-Za-z]{3}-\d{4}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?'                            # BIND named
    r'|\d{10}(?:\d{3}|\d{6}|\d{9})?(?:\.\d{1,9})?(?!\d)'                                     # epoch s / ms / us / ns
    r')')
_LEAD_SCAN = 48          # a leading timestamp is always within this many characters
# The one shape worth SEARCHING for rather than anchoring: an access log puts the client address
# first and the time in brackets after it. `[17/Aug/2026:09:32:52 +0000]` cannot plausibly be
# anything else, so finding it a little way into the line is not a guess.
_BRACKET_TS = re.compile(r'\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s[+-]\d{4})?)\]')
_BRACKET_SCAN = 120


def leading_ts(line: str, cache: Optional[dict] = None) -> str:
    """The ISO-8601 UTC timestamp a line STARTS with, or "" — cheap enough for every line of a GB.

    Returns text, not a datetime, because that is what `Event.ts` holds. A `cache` keyed on the
    matched text is worth passing when whole runs of lines share a second (a DNS or proxy export is
    mostly that), which turns the parse into a dict hit.

    This reads the line; it does not GUESS. Anything it cannot recognise returns "" and the event is
    honestly timestampless — see the raw-phase rule in CLAUDE.md.
    """
    m = _LEAD_TS.match(line, 0, _LEAD_SCAN) or _BRACKET_TS.search(line, 0, _BRACKET_SCAN)
    if m is None:
        return ""
    text = m.group(1)
    if cache is not None:
        got = cache.get(text)
        if got is not None:
            return got
    dt = parse_ts(text)
    out = to_iso(dt) if dt is not None else ""
    if cache is not None:
        cache[text] = out
    return out


_YEAR_CACHE: list = [0, 0.0]        # [year, epoch at which it stops being the current year]


def _now_year() -> int:
    """`datetime.now(UTC).year`, for ~0.1 us instead of ~0.6: re-derived only past the next New Year."""
    t = time.time()
    if t >= _YEAR_CACHE[1]:
        y = datetime.now(UTC).year
        _YEAR_CACHE[0] = y
        _YEAR_CACHE[1] = datetime(y + 1, 1, 1, tzinfo=UTC).timestamp()
    return _YEAR_CACHE[0]


# (text, year) -> datetime | None for text that does NOT parse. Consecutive log lines share a second,
# an export shares a second across dozens of rows, and every parser asks for the same stamp again on
# every line of it, so on a real corpus most calls are a dict hit (~0.15 us) instead of a regex
# dispatch plus a datetime construction (~2-3 us) or, for the dateutil fallback, ~150 us. Keyed on the
# RESOLVED year, because the syslog shape and the dateutil default read it, so a process that crosses
# New Year cannot serve last year's answer. Two kinds of result are never stored: a stamp `_plausible`
# refused (that verdict depends on the clock - a stamp two days ahead is refused today and accepted
# next week) and nothing else; an unparseable string IS stored, because "-" and a header cell repeat
# as hard as a real stamp. Bounded by clearing: a pool of distinct stamps cannot grow it without limit.
_TS_MEMO: dict = {}
_TS_MEMO_MAX = 200_000
_MISS = object()


def parse_ts(text: str, default_year: Optional[int] = None) -> Optional[datetime]:
    """Parse many timestamp formats into an aware UTC datetime. Returns None on failure.

    "Failure" INCLUDES a successful parse of something that cannot be a log timestamp — see `_plausible`.
    """
    year = default_year or _now_year()
    key = (text, year)
    got = _TS_MEMO.get(key, _MISS)
    if got is not _MISS:
        return got
    dt = _parse_ts_raw(text, year)
    out = _plausible(dt)
    if dt is None or out is not None:
        if len(_TS_MEMO) >= _TS_MEMO_MAX:
            _TS_MEMO.clear()
        _TS_MEMO[key] = out
    return out


def _parse_ts_raw(text: str, default_year: Optional[int] = None) -> Optional[datetime]:
    if not text:
        return None
    text = text.strip()
    # An exported CSV cell can still carry its quotes by the time it reaches here (a delimited parser
    # that did not strip them, a value pulled straight out of `raw`). One strip is cheaper than every
    # branch below having to cope.
    if len(text) > 1 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1].strip()
    m = _ISO_RE.match(text)
    if m:
        y, mo, d, h, mi, s, frac, tzs = m.groups()
        us = int((frac or "0")[:6].ljust(6, "0"))
        try:
            return datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), us, tzinfo=_tz_from(tzs)).astimezone(UTC)
        except ValueError:
            return None
    m = _NGINX_RE.match(text)
    if m:
        d, mon, y, h, mi, s, tzs = m.groups()
        try:
            return datetime(int(y), _MONTHS[mon.lower()], int(d), int(h), int(mi), int(s), tzinfo=_tz_from(tzs)).astimezone(UTC)
        except (ValueError, KeyError):
            return None
    m = _BIND_RE.match(text)
    if m:
        d, mon, y, h, mi, sec, frac = m.groups()
        try:
            return datetime(int(y), _MONTHS[mon.lower()], int(d), int(h), int(mi), int(sec),
                            int((frac or "0").ljust(6, "0")), tzinfo=UTC)
        except (ValueError, KeyError):
            return None
    m = _SYSLOG_RE.match(text)
    if m:
        mon, d, h, mi, s = m.groups()
        year = default_year or datetime.now(UTC).year
        try:
            return datetime(year, _MONTHS[mon.lower()], int(d), int(h), int(mi), int(s), tzinfo=UTC)
        except (ValueError, KeyError):
            return None
    m = _KIBANA_RE.match(text)
    if m:
        mon, d, y, h, mi, sec, frac, tzs = m.groups()
        try:
            return datetime(int(y), _MONTHS[mon[:3].lower()], int(d), int(h), int(mi), int(sec),
                            int((frac or "0")[:6].ljust(6, "0")), tzinfo=_tz_from(tzs)).astimezone(UTC)
        except (ValueError, KeyError):
            return None
    m = _EPOCH_RE.match(text)
    if m:
        return epoch_to_datetime(m.group(1), m.group(2) or "")
    m = _US_RE.match(text)
    if m:
        dt = _us_datetime(m)
        if dt is not _DEFER:
            return dt
    # dateutil is the last resort and by far the loosest: it happily reads "1.6", "2096" or a version
    # string as a date. Require a separator-bearing shape (2026-08-18, 18/08/2026, 08.18.26 …) or a month
    # name before handing it the string at all.
    if not _DATEISH_RE.search(text):
        return None
    try:
        dt = dtparser.parse(text, fuzzy=False, default=datetime(default_year or datetime.now(UTC).year, 1, 1, tzinfo=UTC))
    except (ValueError, OverflowError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    try:
        return dt.astimezone(UTC)
    except (ValueError, OverflowError):
        return None


def epoch_to_datetime(digits: str, frac: str = "") -> Optional[datetime]:
    """An epoch of 10 / 13 / 16 / 19 integer digits -> aware UTC datetime, or None.

    The unit comes from the digit count: seconds, milliseconds, microseconds, nanoseconds. A written
    fraction (`1724580000.123`, `1724580000123.456`) is kept at whatever precision the unit leaves
    room for. Integer arithmetic on purpose: `float(<19 digits>)` loses the low digits, and a
    nanosecond stamp that round-trips to the wrong millisecond is a silently wrong timestamp on an
    evidence line.
    """
    scale = {10: 1, 13: 1_000, 16: 1_000_000, 19: 1_000_000_000}.get(len(digits))
    if scale is None:
        return None
    try:
        secs, rem = divmod(int(digits), scale)
        micro = (rem * 1_000_000) // scale
        # the fraction's digits are sub-UNIT: seconds leave six of them for microseconds, ms three, us none
        keep = {1: 6, 1_000: 3}.get(scale, 0)
        if frac and keep:
            micro += int(frac[1:1 + keep].ljust(keep, "0"))
        return datetime.fromtimestamp(secs, tz=UTC).replace(microsecond=min(micro, 999_999))
    except (OverflowError, OSError, ValueError):
        return None


def to_iso(dt: datetime) -> str:
    """The one format `Event.ts` is ever written in. Byte-identical to the `strftime` it replaced.

    This is called once per STAMPED event, on every parse, every re-parse and every pool-cache miss,
    so it sits directly in the ingest hot loop. `strftime` re-derives the whole `struct_time` and
    walks a format string in the C library for it: measured on this machine, **4.79 us per call
    against 1.59 us** for the same characters built from the datetime's own integer fields — ~6 % of
    `normalize_batch` end to end (49.9 -> 46.8 us/event on a 20-column proxy CSV), and ~36 s of pure
    formatting per pass over the analyst's 11.4 M-event pool.

    Two details are load-bearing, and both are what make it byte-identical rather than merely close:

      * `astimezone(UTC)` is SKIPPED only when `dt.tzinfo is UTC` — an identity test, not `==`. A
        naive datetime must still go through `astimezone`, which reads it as LOCAL time; changing
        that would silently re-date every event from a parser that hands back a naive stamp. Another
        object that merely compares equal to UTC (`dateutil`'s `tzutc()`, a `timezone(timedelta(0))`)
        also still goes through it, which costs a conversion that is a no-op and cannot be wrong.
      * The year is padded to four digits. `%Y` is the one field `strftime` delegates to the platform,
        and glibc does NOT pad a year below 1000 where the Windows CRT does — so the old function was
        platform-dependent exactly there. `_plausible` refuses anything before 1990, so no parsed log
        timestamp can reach it; four digits is the ISO-8601 answer and it is now the same on both.

    `tests/test_to_iso_equivalence.py` fuzzes this against the original expression over 20,000 random
    stamps across naive, UTC, fixed-offset, half-hour, 45-minute and DST-carrying zones. `Event.ts`
    is how every event is ordered, dated, windowed and cited, and `store._iso_to_epoch` slices this
    exact layout at fixed offsets: a changed format here is an evidence change, not a formatting one.
    """
    if dt.tzinfo is not UTC:
        dt = dt.astimezone(UTC)
    return (f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}T"
            f"{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}Z")


def iso_ms(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


# --------------------------------------------------------------- severity

_LEVEL_MAP = {
    "emerg": "critical", "emergency": "critical", "fatal": "critical", "crit": "critical", "critical": "critical",
    "alert": "critical", "panic": "critical",
    "err": "high", "error": "high", "severe": "high",
    "warn": "medium", "warning": "medium",
    "notice": "low", "info": "info", "information": "info", "informational": "info",
    "debug": "info", "trace": "info", "verbose": "info",
}
_KEYWORDS_HIGH_SRC = r"\b(denied|failed|failure|unauthorized|forbidden|invalid|attack|malware|exploit|breach|compromise|segfault|panic|kill(?:ed)?)\b"
_KEYWORDS_MED_SRC = r"\b(warn(?:ing)?|retry|timeout|timed out|deprecated|refused|throttl|rate.?limit|slow)\b"
_KEYWORDS_HIGH = re.compile(_KEYWORDS_HIGH_SRC, re.I)
_KEYWORDS_MED = re.compile(_KEYWORDS_MED_SRC, re.I)
# The same two alternations WITHOUT re.I, run over `msg.lower()` when `msg` is ASCII. `re.I` on a long
# alternation is where the time goes (measured here: 8.4 us a search on a 200-char JSON line, 1.2 us
# case-sensitive over the lowered text). On ASCII text the two are the same question: every pattern
# letter is lower-case, `str.lower` folds ASCII exactly as re.I does, and no ASCII character folds to
# or from anything outside ASCII. Non-ASCII text keeps the re.I search - the Kelvin sign and the long s
# fold onto `k` and `s` under re.I and not under `lower()` (see the DOMAIN_RE lesson in CLAUDE.md), and
# `str.isascii()` is an O(1) flag read. `tests/test_parse_speed.py` fuzzes the two paths against each other.
_KEYWORDS_HIGH_L = re.compile(_KEYWORDS_HIGH_SRC)
_KEYWORDS_MED_L = re.compile(_KEYWORDS_MED_SRC)
# One literal per alternative that the alternative cannot match without (`fail` covers failed AND
# failure, `kill` covers kill/killed, `rate` covers rate.?limit). A lowered line containing none of
# them cannot match the regex, and a dozen C substring tests (~1 us) are cheaper than sre attempting
# the alternation at 200 positions (~4 us) - which is what a line with no keyword costs, i.e. most
# lines. Gate-true lines still run the regex, so `\b` is judged exactly as before.
_KW_HIGH_GATE = ("denied", "fail", "unauthorized", "forbidden", "invalid", "attack", "malware", "exploit",
                 "breach", "compromise", "segfault", "panic", "kill")
_KW_MED_GATE = ("warn", "retry", "timeout", "timed out", "deprecated", "refused", "throttl", "rate", "slow")


def _any_in(needles: tuple[str, ...], hay: str) -> bool:
    for w in needles:
        if w in hay:
            return True
    return False


def infer_severity(ev: ParsedEvent) -> str:
    if ev.sev:
        s = ev.sev.lower()
        if s in ("critical", "high", "medium", "low", "info"):
            return s
        if s in _LEVEL_MAP:
            return _LEVEL_MAP[s]
    lvl = (ev.fields.get("level") or ev.fields.get("severity") or ev.fields.get("log.level") or "").lower()
    if lvl in _LEVEL_MAP:
        base = _LEVEL_MAP[lvl]
    else:
        base = None
    status = ev.fields.get("http.status") or ev.fields.get("status") or ""
    if status.isdigit():
        code = int(status)
        if code >= 500:
            return "high"
        if code in (401, 403):
            return "medium"
        if code >= 400:
            return "low"
        if base is None:
            return "info"
    if base is not None:
        return base
    text = ev.msg
    if text.isascii():
        low = text.lower()
        if _any_in(_KW_HIGH_GATE, low) and _KEYWORDS_HIGH_L.search(low):
            return "medium"
        if _any_in(_KW_MED_GATE, low) and _KEYWORDS_MED_L.search(low):
            return "low"
        return "info"
    if _KEYWORDS_HIGH.search(text):
        return "medium"
    if _KEYWORDS_MED.search(text):
        return "low"
    return "info"


# ---------------------------------------------------------------- entities

IPV4_RE = re.compile(r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])")
IPV6_RE = re.compile(r"(?<![:\w])((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4})(?![:\w])")
AKIA_RE = re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")
KEYFP_RE = re.compile(r"\b(SHA256:[A-Za-z0-9+/…\.]{6,64})")
POD_RE = re.compile(r"\b([a-z0-9]+(?:-[a-z0-9]+)*-[a-f0-9]{4,10}(?:-[a-z0-9]{5})?)\b")
PATH_RE = re.compile(r"(?<![\w/])(/(?:tmp|root|home|etc|var|opt|usr|dev|srv|mnt|data)/[\w./-]+)")

USER_FIELDS = ("user", "user.name", "username", "userName", "TargetUserName", "SubjectUserName", "actor",
               "userIdentity.userName", "user.username", "principal", "account", "remote_user", "uid_name")
HOST_FIELDS = ("host", "hostname", "Computer", "computer", "svc", "service", "node", "instance")
IP_FIELDS = ("src_ip", "src", "dst", "dst_ip", "sourceIPAddress", "IpAddress", "client_ip", "remote_addr", "ip",
             "sourceIPs", "source.ip", "destination.ip", "client.ip", "server.ip")
# frozensets of the same names: `extract_entities` asks "does this event carry ANY of these?" once per
# group with `dict.keys().isdisjoint`, instead of one `.get` per name per event (36 lookups on a
# 20-column CSV whose columns are called "Source IP"). The tuples above still drive the ORDER in which
# hits are added, so the entity list comes out the same.
_USER_FIELDS_SET = frozenset(USER_FIELDS)
_HOST_FIELDS_SET = frozenset(HOST_FIELDS)
_IP_FIELDS_SET = frozenset(IP_FIELDS)

IOC_FIELDS = ("url", "email", "domain", "onion", "registry_key")

_ENTITY_STOP = {"", "-", "—", "unknown", "none", "null", "n/a", "root?"}
_KIND_HINTS = {"kind", "type"}
_POD_SUFFIX_RE = re.compile(r"(-[a-f0-9]{4,10})?(-[a-z0-9]{5})?$")

# ---- IPv4 over a whole raw line, the single largest regex cost of normalization.
# `IPV4_RE.findall(raw)` runs over every line at ingest and measured 15 us on a 280-char proxy line and
# 40 us on a 680-char JSON line (~45 % of `extract_entities`). The cost is sre attempting the octet
# alternation at every position. The same set of matches falls out of a plain dotted-quad scan plus a
# Python check of the octet grammar, because BOTH patterns can only match a maximal digit run: an
# octet followed by another digit fails `\.`, and the trailing `(?![\d.])` refuses a run longer than
# three digits. So the spans agree, and the only thing the alternation adds is the VALUE grammar
# (`25[0-5]|2[0-4]\d|1?\d?\d`: any 1-2 digits, or 100-255), which `_octets_ok` reproduces.
#
# `[0-9]` stands in for `\d` only because the fast path is taken for ASCII text alone: `\d` also
# matches Unicode digits, and a line carrying one goes through the original pattern untouched.
# `tests/test_parse_speed.py` fuzzes `ipv4_findall` against `IPV4_RE.findall`.
_IPV4_FAST_SRC = r"(?<![0-9.])([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?![0-9.])"
_IPV4_FAST = (_regex.compile(_IPV4_FAST_SRC) if _regex is not None else re.compile(_IPV4_FAST_SRC))
_IPV4_FAST_FINDALL = _IPV4_FAST.findall


def _octets_ok(quad: str) -> bool:
    for o in quad.split("."):
        if len(o) == 3 and not (o[0] == "1" or "200" <= o <= "255"):
            return False
    return True


def ipv4_findall(text: str) -> list[str]:
    """Exactly `IPV4_RE.findall(text)`, several times faster on a long ASCII line.

    Below ~40 characters (a field VALUE - one address, an address:port) the original is the faster
    one: measured 0.57 us against 1.42 for the fast path, whose isascii + listcomp + octet check
    outweigh the scan it saves. Long text is where the scan dominates (4.5 us against 41 on a
    680-char JSON line), so the switch is on length, and both branches answer the same.
    """
    if len(text) < 40 or not text.isascii():
        return IPV4_RE.findall(text)
    return [q for q in _IPV4_FAST_FINDALL(text) if _octets_ok(q)]


# Both of these are asked the same few thousand questions over and over — the detection pass alone
# called is_public_ip 216 k times on a 1.2 M-event pool, and `ipaddress.ip_address` builds a whole
# object per call (3.4 s of that run). The answer is a pure function of the string, so cache it.
# Bounded so a pool full of distinct addresses cannot grow it without limit.
@lru_cache(maxsize=131072)
def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved


@lru_cache(maxsize=131072)
def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


_PCT_RE = re.compile(r"%[0-9A-Fa-f]{2}")


def pct_decode(s: str) -> str:
    """`s` with its %xx escapes decoded (UTF-8), twice when it was encoded twice (%2540 -> %40 -> @).

    A value that came out of a URL is percent-encoded: an account taken from a query string is
    `name%40domain`, not `name@domain`, and searching `user:name@domain` found nothing. Applied to the
    event's user and host and to the entities built from them, and to what the entity graph reads for
    domains / emails / URLs (see graph.extract). The raw line and the parsed fields are never changed.
    A string with no valid %xx escape is returned as it is — the common case costs one substring test.
    """
    if not s or "%" not in s or not _PCT_RE.search(s):
        return s
    from urllib.parse import unquote
    d = unquote(s, errors="replace")
    if "%" in d and _PCT_RE.search(d):
        d = unquote(d, errors="replace")
    return d


# Fields whose VALUE is a URL, a piece of one, or an address — the ones a log writes percent-encoded.
# Decided per word of the field name (`http_referer`, `cs-uri-stem`, `userEmail`), never by substring:
# "security" contains "uri".
_KEY_WORD_RE = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")
_DECODED_WORDS = frozenset({"url", "urls", "uri", "uris", "referer", "referrer", "href", "link", "email",
                            "emails", "mail", "query", "querystring", "qs", "stem", "request", "redirect"})


@lru_cache(maxsize=8192)
def decodes_field(key: str) -> bool:
    """Is `key` a url / email field, whose value is searchable only once its %xx escapes are decoded?"""
    return any(w.lower() in _DECODED_WORDS for w in _KEY_WORD_RE.findall(key or ""))


def extract_entities(ev: ParsedEvent) -> list[str]:
    """Return an ordered, de-duplicated list of entity names for an event."""
    found: list[str] = []
    seen: set[str] = set()      # mirrors `found` so membership is a hash lookup, not a list scan
    fields = ev.fields
    keys = fields.keys()

    def add(x: str) -> None:
        x = x.strip()
        if x and x not in seen and len(x) <= 128 and x.lower() not in _ENTITY_STOP:
            seen.add(x)
            found.append(x)

    if not keys.isdisjoint(_IP_FIELDS_SET):
        for f in IP_FIELDS:
            v = fields.get(f)
            if v:
                for ip in ipv4_findall(v):
                    add(ip)
                for ip in IPV6_RE.findall(v):
                    if not ip.startswith("::"):
                        add(ip)
    text = ev.raw if len(ev.raw) < 4000 else ev.raw[:4000]
    for ip in ipv4_findall(text):
        if ip not in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
            add(ip)
    # users and hosts decoded (see pct_decode): an account out of a URL is `name%40domain`
    if ev.user:
        add(pct_decode(ev.user))
    if not keys.isdisjoint(_USER_FIELDS_SET):
        for f in USER_FIELDS:
            v = fields.get(f)
            if v and len(v) < 64 and " " not in v:
                add(pct_decode(v))
    if ev.host:
        add(pct_decode(ev.host))
    if not keys.isdisjoint(_HOST_FIELDS_SET):
        for f in HOST_FIELDS:
            v = fields.get(f)
            if v and len(v) < 64 and " " not in v:
                add(pct_decode(v))
    # Both of these scan the WHOLE raw line, on every event, at ingest. Neither is case-insensitive
    # and each has a mandatory literal prefix, so a line without it cannot match - and `in` is a C
    # memmem while `findall` is Python re retrying at every position. Measured on an ordinary
    # 195-char proxy line that matches neither: 3.8 us + 4.1 us, i.e. ~80 s per 10 M events of pure
    # normalization, against ~0.15 us for the two substring tests.
    if "AKIA" in text or "ASIA" in text:
        for k in AKIA_RE.findall(text):
            add(k)
    if "SHA256:" in text:
        for k in KEYFP_RE.findall(text):
            add(k)
    pod = fields.get("pod") or fields.get("objectRef.name") or fields.get("kubernetes.pod_name")
    if pod:
        add(pod)
        base = _POD_SUFFIX_RE.sub("", pod)
        if base and base != pod:
            add(base)
    pid = fields.get("pid") or fields.get("process.pid")
    if pid and pid.isdigit() and fields.get("program"):
        add(f"{fields['program']}[{pid}]")
    # IOC-style fields produced by the strings / document parsers (comma-joined lists)
    for f in IOC_FIELDS:
        v = fields.get(f)
        if v:
            for item in v.split(",")[:5]:
                add(item)
    return found


def entity_kind(name: str, hint: str = "") -> str:
    if IPV4_RE.fullmatch(name):
        return "IPv4 · internal" if is_private_ip(name) else "IPv4 · external"
    if IPV6_RE.fullmatch(name):
        return "IPv6"
    if AKIA_RE.fullmatch(name):
        return "AWS access key"
    if name.startswith("SHA256:"):
        return "SSH key fingerprint"
    if re.fullmatch(r"[\w.-]+\[\d+\]", name):
        return "Process"
    if re.match(r"(?:https?|ftp|ftps|smb|ldap|wss?)://", name, re.I):
        return "URL"
    if re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", name):
        return "Email"
    if re.fullmatch(r"[a-z0-9-]+\.onion", name, re.I):
        return "Onion service"
    if re.match(r"(?:HKEY_|HKLM|HKCU|HKCR|HKU|\\REGISTRY)", name, re.I):
        return "Registry key"
    if hint:
        return hint
    if re.fullmatch(r"[A-Z][A-Z0-9-]{2,}", name):
        return "Host · Windows"
    if re.fullmatch(r"[a-z][a-z0-9-]*-[a-f0-9]{4,10}", name):
        return "Pod"
    if "-" in name and re.fullmatch(r"[a-z][a-z0-9-]*\d[a-z0-9-]*", name):
        return "Host"
    if name in ("root", "admin", "administrator", "system"):
        return "OS account"
    if name.startswith(("svc_", "svc-", "ci-", "sa-")):
        return "Service account"
    if re.fullmatch(r"[a-z][a-z0-9_.-]{1,31}", name):
        return "Account"
    return "Entity"


# ---------------------------------------------------------------- clock skew

def clock_skew_note(offsets_seconds: list[float]) -> str:
    if not offsets_seconds:
        return "no skew detected"
    mx = max(abs(o) for o in offsets_seconds)
    return f"{len(offsets_seconds)} skews, max {int(round(mx))}s"
