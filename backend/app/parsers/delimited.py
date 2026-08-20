"""Delimited (pipe / comma / tab / semicolon) parser for unknown formats with role guessing."""
from __future__ import annotations

import re
from collections import Counter
from typing import Iterable, Iterator, Optional

from ..normalize import IPV4_RE, parse_ts
from .base import BaseParser, ParsedEvent

DELIMS = ["|", "\t", ",", ";"]
_ACTIONS = {"allow", "deny", "drop", "accept", "reject", "block", "permit", "alert", "pass", "allowed", "denied", "blocked"}
_PROTOS = {"tcp", "udp", "icmp", "gre", "esp", "http", "https", "dns", "tls", "ssh"}
_IPPORT = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?$")
_KV = re.compile(r"^([A-Za-z_][\w.-]*)=(.*)$")
_TS_LIKE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}|^\d{2}/[A-Za-z]{3}/\d{4}|^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}|^\d{10}(\.\d+)?$")
_HOST_LIKE = re.compile(r"^[A-Za-z][\w-]*(?:\.[\w-]+)*$")
_NUM = re.compile(r"^\d+$")

ROLE_TIMESTAMP, ROLE_HOST, ROLE_ACTION, ROLE_SRC, ROLE_DST, ROLE_PROTO, ROLE_BYTES, ROLE_USER = (
    "timestamp", "host", "action", "src", "dst", "proto", "bytes", "user")


def guess_delimiter(lines: list[str]) -> Optional[str]:
    best, best_score = None, 0.0
    for d in DELIMS:
        counts = [l.count(d) for l in lines if l.strip()]
        if not counts:
            continue
        c = Counter(counts)
        common, freq = c.most_common(1)[0]
        if common < 2:
            continue
        score = (freq / len(counts)) * (1 + min(common, 8) / 10)
        if score > best_score:
            best, best_score = d, score
    return best


def guess_roles(rows: list[list[str]]) -> list[str]:
    if not rows:
        return []
    ncol = max(len(r) for r in rows)
    roles: list[str] = []
    for i in range(ncol):
        col = [r[i] for r in rows if len(r) > i and r[i] != ""]
        if not col:
            roles.append(f"field{i + 1}")
            continue
        n = len(col)
        ts_hits = sum(1 for v in col if _TS_LIKE.match(v))
        act_hits = sum(1 for v in col if v.lower() in _ACTIONS)
        proto_hits = sum(1 for v in col if v.lower() in _PROTOS)
        ip_hits = sum(1 for v in col if _IPPORT.match(v))
        num_hits = sum(1 for v in col if _NUM.match(v))
        kv_hits = sum(1 for v in col if _KV.match(v))
        host_hits = sum(1 for v in col if _HOST_LIKE.match(v) and not v.isdigit())
        role = f"field{i + 1}"
        if ts_hits / n > 0.8:
            role = ROLE_TIMESTAMP
        elif act_hits / n > 0.6:
            role = ROLE_ACTION
        elif proto_hits / n > 0.6:
            role = ROLE_PROTO
        elif ip_hits / n > 0.7:
            role = ROLE_DST if ROLE_SRC in roles else ROLE_SRC
        elif kv_hits / n > 0.7:
            keys = Counter(_KV.match(v).group(1).lower() for v in col if _KV.match(v))
            k = keys.most_common(1)[0][0]
            role = ROLE_BYTES if k in ("len", "bytes", "size", "length") else k
        elif num_hits / n > 0.8:
            role = ROLE_BYTES if ROLE_BYTES not in roles else f"num{i + 1}"
        elif host_hits / n > 0.8:
            if ROLE_HOST not in roles:
                role = ROLE_HOST
            elif ROLE_USER not in roles and all(len(v) < 32 for v in col):
                role = ROLE_USER
        while role in roles:
            role = role + "_"
        roles.append(role)
    return roles


class DelimitedParser(BaseParser):
    name = "delimited (unknown)"
    family = "delimited"
    chunkable = True   # one record per line; delimiter + column names come from the head (see parallel.py)
    mappable = True    # anonymous columns: MAP is a real question, and `guessed` is the answer offered

    def __init__(self, fields: Optional[list[str]] = None, delimiter: Optional[str] = None, family: Optional[str] = None):
        self.mapping = fields
        self.delimiter = delimiter
        self.guessed: list[str] = []
        self.header: Optional[list[str]] = None
        if family:
            self.family = family
        if fields:
            self.name = "delimited (mapped)"

    def sniff(self, sample: list[str], filename: str = "", head: bytes = b"") -> float:
        lines = [l for l in sample if l.strip()][:200]
        if not lines:
            return 0.0
        if any(l.lstrip().startswith(("{", "<")) for l in lines[:5]):
            return 0.0
        d = self.delimiter or guess_delimiter(lines)
        if not d:
            return 0.0
        rows = [l.split(d) for l in lines]
        widths = Counter(len(r) for r in rows)
        common, freq = widths.most_common(1)[0]
        consistency = freq / len(rows)
        roles = guess_roles(rows[:200])
        known = sum(1 for r in roles if not r.startswith(("field", "num")))
        conf = 0.35 + 0.35 * consistency + 0.15 * min(known, 4) / 4
        if ROLE_TIMESTAMP in roles:
            conf += 0.05
        return round(min(0.86, conf), 3)

    def parse(self, lines: Iterable[str]) -> Iterator[ParsedEvent]:
        it = iter(lines)
        buffer: list[str] = []
        for line in it:
            if line.strip():
                buffer.append(line.rstrip("\r\n"))
            if len(buffer) >= 200:
                break
        d = self.delimiter or guess_delimiter(buffer) or "|"
        self.delimiter = d
        rows = [l.split(d) for l in buffer]
        header: Optional[list[str]] = None
        if rows and self.mapping is None:
            first = rows[0]
            if all(re.fullmatch(r"[A-Za-z_][\w .-]*", c.strip()) for c in first) and not any(_TS_LIKE.match(c) for c in first):
                if len(rows) > 1 and any(_TS_LIKE.match(c) or _IPPORT.match(c) for c in rows[1]):
                    header = [c.strip() for c in first]
        if self.mapping:
            names = list(self.mapping)
        elif header:
            names = header
        else:
            names = guess_roles(rows[:200])
        self.header = header
        self.guessed = names
        start = 1 if header else 0
        for row_text in buffer[start:]:
            yield self._make(row_text, row_text.split(d), names)
        for line in it:
            l = line.rstrip("\r\n")
            if not l.strip():
                continue
            yield self._make(l, l.split(d), names)

    def _make(self, raw: str, cells: list[str], names: list[str]) -> ParsedEvent:
        fields: dict[str, str] = {}
        for i, cell in enumerate(cells):
            name = names[i] if i < len(names) else f"field{i + 1}"
            cell = cell.strip()
            m = _KV.match(cell)
            if m and name.startswith(("field", "num")):
                name = m.group(1)
                cell = m.group(2)
            elif m and name in (ROLE_BYTES,) and m.group(1).lower() in ("len", "bytes", "size", "length"):
                cell = m.group(2)
            if name in (ROLE_SRC, ROLE_DST):
                mm = _IPPORT.match(cell)
                if mm:
                    fields[name] = mm.group(1)
                    if mm.group(2):
                        fields[f"{name}_port"] = mm.group(2)
                    continue
            fields[name] = cell
        ts_text = fields.get(ROLE_TIMESTAMP, "")
        host = fields.get(ROLE_HOST, "")
        user = fields.get(ROLE_USER, "")
        action = fields.get(ROLE_ACTION, "")
        src, dst = fields.get(ROLE_SRC, ""), fields.get(ROLE_DST, "")
        if src and dst:
            sp, dp = fields.get("src_port"), fields.get("dst_port")
            msg = f"{action or 'flow'} {src}{':' + sp if sp else ''} → {dst}{':' + dp if dp else ''}"
            if fields.get(ROLE_PROTO):
                msg += f" {fields[ROLE_PROTO]}"
            b = fields.get(ROLE_BYTES)
            if b and b.isdigit() and int(b) >= 1_000_000:
                msg += f" — {_fmt_bytes(int(b))}"
        else:
            body = [c for i, c in enumerate(cells) if names[i] != ROLE_TIMESTAMP] if len(names) >= len(cells) else cells
            msg = " ".join(c.strip() for c in body)[:300]
        sev = None
        if action.lower() in ("deny", "drop", "reject", "block", "denied", "blocked"):
            sev = "low"
        return ParsedEvent(raw=raw, msg=msg, ts=parse_ts(ts_text) if ts_text else None, ts_text=ts_text,
                           host=host, user=user, sev=sev, fields=fields)


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.2f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024  # type: ignore[assignment]
    return f"{n} B"
