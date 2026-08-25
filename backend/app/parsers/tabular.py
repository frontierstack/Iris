"""Shared helpers for header-driven tabular sources (CSV, XLSX) and line-oriented documents (PDF, DOCX, OCR)."""
from __future__ import annotations

import re
from typing import Optional

from ..normalize import parse_ts
from .base import ParsedEvent, clean

TS_NAMES = ("ts", "time", "timestamp", "@timestamp", "date", "datetime", "eventtime", "event_time", "created", "created_at",
            "logged", "logged_at", "occurred", "start_time", "starttime", "when", "generated", "receipttime", "receipt_time",
            "date_time", "date/time", "time_generated", "timegenerated", "utc", "epoch", "epoch_ms", "epochmillis",
            "epoch_millis", "unix_time", "unixtime", "unix_ts", "timestamp_ms", "ts_ms", "time_ms", "_time", "time_t")
HOST_NAMES = ("host", "hostname", "computer", "computername", "computer_name", "device", "devicename", "device_name", "server",
              "machine", "node", "system", "src_host", "source_host", "workstation", "asset", "sensor")
USER_NAMES = ("user", "username", "user_name", "account", "accountname", "account_name", "userid", "user_id", "actor", "principal",
              "login", "logon", "subject", "samaccountname", "upn", "email", "target_user", "targetusername", "owner")
MSG_NAMES = ("msg", "message", "event", "description", "desc", "text", "details", "detail", "summary", "log", "body", "content",
             "action", "activity", "eventname", "event_name", "title", "reason", "note", "notes", "comment", "info")
LEVEL_NAMES = ("level", "severity", "sev", "priority", "loglevel", "log_level", "risk", "criticality")

TS_IN_TEXT = [
    re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"),
    re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2})\b"),
    re.compile(r"(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?)"),
    re.compile(r"((?:[A-Z][a-z]{2}\s+){1,2}\d{1,2},?\s+(?:\d{4}\s+)?\d{2}:\d{2}:\d{2})"),
    re.compile(r"(\d{1,2}/\d{1,2}/\d{4}[ ,T]+\d{1,2}:\d{2}(?::\d{2})?(?:\s*[AP]M)?)", re.I),
    re.compile(r"(\d{4}/\d{2}/\d{2}[ ,T]+\d{2}:\d{2}:\d{2})"),
    re.compile(r"\b(\d{10}(?:\d{3}|\d{6}|\d{9})?(?:\.\d{1,9})?)\b"),
]
_LEVEL_RE = re.compile(r"\b(EMERG|FATAL|CRIT(?:ICAL)?|ALERT|ERR(?:OR)?|WARN(?:ING)?|NOTICE|INFO|DEBUG|TRACE)\b", re.I)


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9@/_]", "", name.strip().lower().replace(" ", "_").replace("-", "_"))


def _find(header: list[str], names: tuple[str, ...]) -> Optional[int]:
    normed = [_norm(h) for h in header]
    for cand in names:
        for i, h in enumerate(normed):
            if h == cand:
                return i
    for cand in names:
        for i, h in enumerate(normed):
            if len(cand) > 3 and (h.endswith("_" + cand) or h.startswith(cand + "_") or h.endswith("." + cand)):
                return i
    return None


class ColumnRoles:
    """Indices of the timestamp / host / user / msg / level columns inferred from a header row."""

    def __init__(self, header: list[str]) -> None:
        self.header = header
        self.ts = _find(header, TS_NAMES)
        self.host = _find(header, HOST_NAMES)
        self.user = _find(header, USER_NAMES)
        self.msg = _find(header, MSG_NAMES)
        self.level = _find(header, LEVEL_NAMES)

    def event(self, raw: str, cells: list[str], extra: Optional[dict[str, str]] = None) -> ParsedEvent:
        fields: dict[str, str] = dict(extra or {})
        for i, cell in enumerate(cells):
            name = self.header[i] if i < len(self.header) and self.header[i] else f"col{i + 1}"
            v = clean(cell)
            if v != "":
                fields[name] = v

        def col(i: Optional[int]) -> str:
            return clean(cells[i]) if i is not None and i < len(cells) else ""

        ts_text = col(self.ts)
        ts = parse_ts(ts_text) if ts_text else None
        if ts is None:
            # fall back to any timestamp-looking cell
            for c in cells:
                c = clean(c)
                if len(c) < 40:
                    for p in TS_IN_TEXT[:1] + TS_IN_TEXT[2:]:
                        m = p.fullmatch(c)
                        if m:
                            ts, ts_text = parse_ts(c), c
                            break
                if ts is not None:
                    break
        msg = col(self.msg)
        if not msg:
            body = [clean(c) for i, c in enumerate(cells) if i != self.ts and clean(c)]
            msg = " ".join(body)
        level = col(self.level)
        if level:
            fields.setdefault("level", level)
        return ParsedEvent(raw=raw, msg=msg[:300], ts=ts, ts_text=ts_text, host=col(self.host), user=col(self.user), fields=fields)


def looks_like_header(row: list[str], next_row: Optional[list[str]]) -> bool:
    """A header row is short-ish text without timestamps/numbers, ideally distinct from the data row below."""
    cells = [clean(c) for c in row]
    if not cells or not any(cells):
        return False
    filled = [c for c in cells if c]
    if len(set(filled)) < len(filled):  # duplicate names are unusual for headers
        return False
    for c in filled:
        if len(c) > 64:
            return False
        if re.fullmatch(r"[-+]?\d[\d.,:/-]*", c):
            return False
        if any(p.search(c) for p in TS_IN_TEXT):
            return False
        if not re.fullmatch(r"[A-Za-z_@#][\w .@/#()%-]*", c):
            return False
    if next_row is not None:
        nxt = [clean(c) for c in next_row]
        if nxt == cells:
            return False
        if any(re.search(r"\d", c) for c in nxt):
            return True
    normed = {_norm(c) for c in filled}
    known = normed & set(TS_NAMES + HOST_NAMES + USER_NAMES + MSG_NAMES + LEVEL_NAMES)
    return bool(known) or next_row is None


def line_event(text: str, extra: dict[str, str]) -> ParsedEvent:
    """Turn a free-text line (PDF/DOCX/OCR) into an event with a best-effort timestamp + level."""
    ts_text = ""
    ts = None
    for p in TS_IN_TEXT:
        m = p.search(text)
        if m:
            cand = m.group(1)
            ts = parse_ts(cand)
            if ts is not None:
                ts_text = cand
                break
    fields = dict(extra)
    lm = _LEVEL_RE.search(text)
    if lm:
        fields["level"] = lm.group(1).lower()
    return ParsedEvent(raw=text, msg=text[:300], ts=ts, ts_text=ts_text, fields=fields)
