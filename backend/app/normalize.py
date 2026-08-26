"""Normalization: timestamps → UTC, severity inference, entity extraction."""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Optional

from dateutil import parser as dtparser
from dateutil import tz as dttz

from .parsers.base import ParsedEvent

UTC = timezone.utc

# ---------------------------------------------------------------- timestamps

_ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,9}))?\s*(Z|[+-]\d{2}:?\d{2})?$"
)
_NGINX_RE = re.compile(r"^(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?$")
_SYSLOG_RE = re.compile(r"^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$")
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


def parse_ts(text: str, default_year: Optional[int] = None) -> Optional[datetime]:
    """Parse many timestamp formats into an aware UTC datetime. Returns None on failure.

    "Failure" INCLUDES a successful parse of something that cannot be a log timestamp — see `_plausible`.
    """
    return _plausible(_parse_ts_raw(text, default_year))


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
_KEYWORDS_HIGH = re.compile(r"\b(denied|failed|failure|unauthorized|forbidden|invalid|attack|malware|exploit|breach|compromise|segfault|panic|kill(?:ed)?)\b", re.I)
_KEYWORDS_MED = re.compile(r"\b(warn(?:ing)?|retry|timeout|timed out|deprecated|refused|throttl|rate.?limit|slow)\b", re.I)


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

IOC_FIELDS = ("url", "email", "domain", "onion", "registry_key")

_ENTITY_STOP = {"", "-", "—", "unknown", "none", "null", "n/a", "root?"}
_KIND_HINTS = {"kind", "type"}


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


def extract_entities(ev: ParsedEvent) -> list[str]:
    """Return an ordered, de-duplicated list of entity names for an event."""
    found: list[str] = []

    def add(x: str) -> None:
        x = x.strip()
        if x and x.lower() not in _ENTITY_STOP and x not in found and len(x) <= 128:
            found.append(x)

    for f in IP_FIELDS:
        v = ev.fields.get(f)
        if v:
            for ip in IPV4_RE.findall(v):
                add(ip)
            for ip in IPV6_RE.findall(v):
                if not ip.startswith("::"):
                    add(ip)
    text = ev.raw if len(ev.raw) < 4000 else ev.raw[:4000]
    for ip in IPV4_RE.findall(text):
        if ip not in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
            add(ip)
    if ev.user:
        add(ev.user)
    for f in USER_FIELDS:
        v = ev.fields.get(f)
        if v and len(v) < 64 and " " not in v:
            add(v)
    if ev.host:
        add(ev.host)
    for f in HOST_FIELDS:
        v = ev.fields.get(f)
        if v and len(v) < 64 and " " not in v:
            add(v)
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
    pod = ev.fields.get("pod") or ev.fields.get("objectRef.name") or ev.fields.get("kubernetes.pod_name")
    if pod:
        add(pod)
        base = re.sub(r"(-[a-f0-9]{4,10})?(-[a-z0-9]{5})?$", "", pod)
        if base and base != pod:
            add(base)
    pid = ev.fields.get("pid") or ev.fields.get("process.pid")
    if pid and pid.isdigit() and ev.fields.get("program"):
        add(f"{ev.fields['program']}[{pid}]")
    # IOC-style fields produced by the strings / document parsers (comma-joined lists)
    for f in IOC_FIELDS:
        v = ev.fields.get(f)
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
