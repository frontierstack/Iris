"""nginx / Apache combined & common access log parser."""
from __future__ import annotations

import re
from typing import Iterable, Iterator

from ..normalize import parse_ts
from .base import BaseParser, ParsedEvent

_LINE = re.compile(
    r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)?\s?(?P<path>[^" ]*)\s?(?P<proto>HTTP/[\d.]+)?"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
    r'(?P<extra>.*)$'
)
_KV = re.compile(r'(\w+)=("[^"]*"|\S+)')

# Fraction of sampled lines that must actually match the combined/common access-log shape before this
# parser claims a file. An access log is access-log-shaped on essentially every line; a file that merely
# contains the odd request line is a different format, and every other line of it would be written out as
# `parse_error: unmatched`. Same reasoning — and the same constant — as syslog.MIN_MATCH_RATIO.
MIN_MATCH_RATIO = 0.5


class NginxParser(BaseParser):
    name = "nginx combined"
    family = "nginx.access"
    chunkable = True   # strictly one record per line, no cross-line state

    def sniff(self, sample: list[str], filename: str = "", head: bytes = b"") -> float:
        lines = [l for l in sample if l.strip()]
        if not lines:
            return 0.0
        hits = sum(1 for l in lines[:200] if _LINE.match(l))
        ratio = hits / len(lines[:200])
        # The floor below is 0.55 and plain text tops out at 0.5, so ONE access-log-shaped line in 200
        # used to outscore the fallback outright and claim the whole file. The trial parse in
        # registry.fingerprint would now demote it, but the SCORE is what the Sources drawer shows the
        # analyst, and 0.552 for a file that is 0.5 % nginx is a lie about the evidence. Demand a
        # majority; a sub-majority match is what the plain text parser is for.
        if ratio < MIN_MATCH_RATIO:
            return 0.0
        conf = 0.55 + 0.44 * ratio
        if "access" in filename.lower():
            conf = min(1.0, conf + 0.02)
        return round(conf, 3)

    def parse(self, lines: Iterable[str]) -> Iterator[ParsedEvent]:
        for line in lines:
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            m = _LINE.match(line)
            if not m:
                yield ParsedEvent(raw=line, msg=line[:200], fields={"parse_error": "unmatched"})
                continue
            g = m.groupdict()
            fields = {
                "src_ip": g["ip"],
                "http.method": g["method"] or "",
                "http.path": g["path"] or "",
                "http.proto": g["proto"] or "",
                "http.status": g["status"],
                "bytes": "0" if g["bytes"] in (None, "-") else g["bytes"],
            }
            if g["referer"] and g["referer"] != "-":
                fields["referer"] = g["referer"]
            if g["ua"]:
                fields["user_agent"] = g["ua"]
            user = "" if g["user"] in ("-", None) else g["user"]
            if user:
                fields["user.name"] = user
            for k, v in _KV.findall(g["extra"] or ""):
                fields[k] = v.strip('"')
            ts = parse_ts(g["ts"])
            path = g["path"] or ""
            msg = f"{g['method'] or '-'} {path[:120]} {g['status']}"
            yield ParsedEvent(raw=line, msg=msg, ts=ts, ts_text=g["ts"], user=user, fields=fields)
