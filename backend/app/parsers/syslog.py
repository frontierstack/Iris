"""Syslog parser: RFC3164 (BSD) and RFC5424."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterable, Iterator

from ..normalize import parse_ts
from .base import BaseParser, ParsedEvent

_PRI = re.compile(r"^<(\d{1,3})>")
_RFC3164 = re.compile(
    r"^(?:<\d{1,3}>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)
_RFC5424 = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?1\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<pid>\S+)\s+(?P<msgid>\S+)\s+"
    r"(?P<sd>-|(?:\[[^\]]*\])+)\s?(?P<msg>.*)$"
)
_SD_KV = re.compile(r'(\w[\w.@-]*)="([^"]*)"')
# modern systemd/journald: "2026-03-30T21:48:38.820117-05:00 HOST program[pid]: message" (no <pri>, no version)
_ISO_SYSLOG = re.compile(
    r"^(?:<\d{1,3}>)?(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<prog>[A-Za-z][\w.\-/]*)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)

_SSH_ACCEPTED = re.compile(r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2: (?P<keytype>\S+) (?P<fp>\S+))?")
_SSH_FAILED = re.compile(r"Failed (?P<method>\w+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_SSH_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")
_SUDO = re.compile(r"^\s*(?P<user>\S+) : .*COMMAND=(?P<cmd>.*)$")
_PAM = re.compile(r"session (?P<state>opened|closed) for user (?P<user>\S+)")
_AUDIT_KV = re.compile(r'(\w+)=("[^"]*"|\S+)')

_SEV_BY_PRI = {0: "critical", 1: "critical", 2: "critical", 3: "high", 4: "medium", 5: "low", 6: "info", 7: "info"}

# Fraction of sampled lines that must actually match a syslog record shape before this parser claims a
# file. Real syslog carries the odd continuation line; a log that merely resembles syslog on a minority
# of its lines is a different format and belongs to whichever parser can read the rest of it.
MIN_MATCH_RATIO = 0.5


class SyslogParser(BaseParser):
    name = "syslog (RFC3164/5424)"
    family = "syslog"
    chunkable = True   # strictly one record per line, no cross-line state

    def sniff(self, sample: list[str], filename: str = "", head: bytes = b"") -> float:
        lines = [l for l in sample if l.strip()][:200]
        if not lines:
            return 0.0
        hits = 0
        for l in lines:
            if _RFC3164.match(l) or _RFC5424.match(l) or _ISO_SYSLOG.match(l):
                hits += 1
        ratio = hits / len(lines)
        # A syslog file is syslog on nearly every line. The floor below is 0.55, so ANY hit at all used to
        # beat plain text (max 0.5) outright: dpkg.log matched on 30 % of its lines — `install
        # base-passwd:amd64 …` reads as `host program:` to _ISO_SYSLOG — and was claimed at 0.674 while
        # the other 70 % became `parse_error: unmatched`. Demand a majority before claiming the file; a
        # sub-majority match is what the plain text parser is for.
        if ratio < MIN_MATCH_RATIO:
            return 0.0
        conf = 0.55 + 0.42 * ratio
        if "syslog" in filename.lower() or "messages" in filename.lower() or "auth.log" in filename.lower():
            conf = min(1.0, conf + 0.03)
        return round(conf, 3)

    def parse(self, lines: Iterable[str]) -> Iterator[ParsedEvent]:
        year = datetime.now(timezone.utc).year
        for line in lines:
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            m = _RFC5424.match(line)
            if m:
                g = m.groupdict()
                fields: dict[str, str] = {"program": g["app"], "msgid": g["msgid"] if g["msgid"] != "-" else ""}
                if g["pid"] and g["pid"] != "-":
                    fields["pid"] = g["pid"]
                if g["sd"] and g["sd"] != "-":
                    for k, v in _SD_KV.findall(g["sd"]):
                        fields[k] = v
                sev = None
                if g["pri"]:
                    pri = int(g["pri"])
                    fields["facility"] = str(pri // 8)
                    fields["severity_num"] = str(pri % 8)
                    sev = _SEV_BY_PRI.get(pri % 8)
                msg = g["msg"] or ""
                user = self._enrich(fields, g["app"], msg)
                yield ParsedEvent(raw=line, msg=f"{g['app']}: {msg}"[:300], ts=parse_ts(g["ts"]), ts_text=g["ts"],
                                  host=g["host"], user=user, sev=sev, fields=fields)
                continue
            m = _RFC3164.match(line)
            if m:
                g = m.groupdict()
                fields = {"program": g["prog"]}
                if g["pid"]:
                    fields["pid"] = g["pid"]
                sev = None
                pm = _PRI.match(line)
                if pm:
                    pri = int(pm.group(1))
                    fields["facility"] = str(pri // 8)
                    sev = _SEV_BY_PRI.get(pri % 8)
                msg = g["msg"] or ""
                user = self._enrich(fields, g["prog"], msg)
                yield ParsedEvent(raw=line, msg=f"{g['prog']}: {msg}"[:300], ts=parse_ts(g["ts"], default_year=year),
                                  ts_text=g["ts"], host=g["host"], user=user, sev=sev, fields=fields)
                continue
            m = _ISO_SYSLOG.match(line)
            if m:
                g = m.groupdict()
                fields = {"program": g["prog"]}
                if g.get("pid"):
                    fields["pid"] = g["pid"]
                msg = g["msg"] or ""
                user = self._enrich(fields, g["prog"], msg)
                yield ParsedEvent(raw=line, msg=f"{g['prog']}: {msg}"[:300], ts=parse_ts(g["ts"]),
                                  ts_text=g["ts"], host=g["host"], user=user, sev=None, fields=fields)
                continue
            yield ParsedEvent(raw=line, msg=line[:300], fields={"parse_error": "unmatched"})

    @staticmethod
    def _enrich(fields: dict[str, str], prog: str, msg: str) -> str:
        user = ""
        p = prog.lower()
        if p == "sshd":
            m = _SSH_ACCEPTED.search(msg)
            if m:
                fields.update({"result": "Accepted", "method": m.group("method"), "user": m.group("user"),
                               "src_ip": m.group("ip"), "port": m.group("port")})
                if m.group("fp"):
                    fields["key.fp"] = m.group("fp")
                    fields["key.type"] = m.group("keytype") or ""
                return m.group("user")
            m = _SSH_FAILED.search(msg)
            if m:
                fields.update({"result": "Failed", "method": m.group("method"), "user": m.group("user"),
                               "src_ip": m.group("ip"), "port": m.group("port")})
                return m.group("user")
            m = _SSH_INVALID.search(msg)
            if m:
                fields.update({"result": "Invalid", "user": m.group("user"), "src_ip": m.group("ip")})
                return m.group("user")
        elif p == "sudo":
            m = _SUDO.match(msg)
            if m:
                fields.update({"user": m.group("user"), "command": m.group("cmd").strip()})
                return m.group("user")
        elif p == "audit" or p == "auditd":
            for k, v in _AUDIT_KV.findall(msg):
                fields[k] = v.strip('"')
            if "path" not in fields and "name" in fields:
                fields["path"] = fields["name"]
        m = _PAM.search(msg)
        if m:
            fields["user"] = m.group("user")
            fields["result"] = m.group("state")
            fields.setdefault("pam", "session")
            return m.group("user")
        return user
