"""Fallback plaintext parser: extracts a leading/embedded timestamp and level keyword."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterable, Iterator

from ..normalize import parse_ts
from .base import BaseParser, ParsedEvent

_TS_PATTERNS = [
    re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"),
    re.compile(r"(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?)"),
    re.compile(r"((?:[A-Z][a-z]{2}\s+){1,2}\d{1,2}\s+\d{2}:\d{2}:\d{2})"),
    re.compile(r"(\d{2}/\d{2}/\d{4}[ ,]+\d{2}:\d{2}:\d{2})"),
    re.compile(r"\b(\d{10}(?:\.\d{1,6})?)\b"),
]
_LEVEL = re.compile(r"\b(EMERG|FATAL|CRIT(?:ICAL)?|ALERT|ERR(?:OR)?|WARN(?:ING)?|NOTICE|INFO|DEBUG|TRACE)\b", re.I)
_BRACKET_LEVEL = re.compile(r"\[(EMERG|FATAL|CRIT(?:ICAL)?|ALERT|ERR(?:OR)?|WARN(?:ING)?|NOTICE|INFO|DEBUG|TRACE)\]", re.I)


class PlaintextParser(BaseParser):
    name = "plain text"
    family = "text"
    chunkable = True   # strictly one record per line, no cross-line state
    # The terminal choice: every line becomes a record, nothing ever fails, and there are no columns to
    # name. Its sniff tops out at 0.5 and READY starts at 0.9, so without this every plain text file in
    # the pool sat in MAP for ever — 38 of the analyst's 680 staged files — asking for a field mapping
    # that does not exist and holding the case posture's "Unmapped fields" open. See registry.state_for.
    fallback = True

    def sniff(self, sample: list[str], filename: str = "", head: bytes = b"") -> float:
        lines = [l for l in sample if l.strip()][:200]
        if not lines:
            return 0.05
        ts_hits = sum(1 for l in lines if any(p.search(l) for p in _TS_PATTERNS))
        return round(0.2 + 0.3 * ts_hits / len(lines), 3)

    def parse(self, lines: Iterable[str]) -> Iterator[ParsedEvent]:
        year = datetime.now(timezone.utc).year
        for line in lines:
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            ts_text = ""
            for p in _TS_PATTERNS:
                m = p.search(line)
                if m:
                    ts_text = m.group(1)
                    break
            fields: dict[str, str] = {}
            lm = _BRACKET_LEVEL.search(line) or _LEVEL.search(line)
            if lm:
                fields["level"] = lm.group(1).lower()
            msg = line
            if ts_text and line.startswith(ts_text):
                msg = line[len(ts_text):].strip(" :-[]")
            yield ParsedEvent(raw=line, msg=msg[:300], ts=parse_ts(ts_text, default_year=year) if ts_text else None,
                              ts_text=ts_text, fields=fields)
