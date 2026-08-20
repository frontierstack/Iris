"""Windows EVTX parser (binary via python-evtx, or exported XML)."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Iterable, Iterator, Optional

from ..normalize import parse_ts
from .base import BaseParser, ParsedEvent

EVENT_ID_MESSAGES: dict[int, str] = {
    1102: "The audit log was cleared",
    4608: "Windows is starting up",
    4624: "An account was successfully logged on",
    4625: "An account failed to log on",
    4634: "An account was logged off",
    4647: "User initiated logoff",
    4648: "A logon was attempted using explicit credentials",
    4672: "Special privileges assigned to new logon",
    4688: "A new process has been created",
    4689: "A process has exited",
    4697: "A service was installed in the system",
    4698: "A scheduled task was created",
    4720: "A user account was created",
    4722: "A user account was enabled",
    4724: "An attempt was made to reset an account's password",
    4726: "A user account was deleted",
    4728: "A member was added to a security-enabled global group",
    4732: "A member was added to a security-enabled local group",
    4740: "A user account was locked out",
    4768: "A Kerberos authentication ticket (TGT) was requested",
    4769: "A Kerberos service ticket was requested",
    4771: "Kerberos pre-authentication failed",
    4776: "The computer attempted to validate the credentials for an account",
    5140: "A network share object was accessed",
    5145: "A network share object was checked to see whether client can be granted desired access",
    7045: "A new service was installed",
}
LOGON_TYPES = {"2": "interactive", "3": "network", "4": "batch", "5": "service", "7": "unlock",
               "8": "network cleartext", "9": "new credentials", "10": "remote interactive", "11": "cached interactive"}

_NS_RE = re.compile(r"\{[^}]+\}")
_EVENT_SPLIT = re.compile(r"(?=<Event[\s>])")


def _strip_ns(tag: str) -> str:
    return _NS_RE.sub("", tag)


class EvtxParser(BaseParser):
    name = "Windows EVTX"
    family = "windows.evtx"
    binary = True

    def sniff(self, sample: list[str], filename: str = "", head: bytes = b"") -> float:
        if head.startswith(b"ElfFile"):
            return 1.0
        lines = sample[:200]
        text = "\n".join(lines)
        # An exported EVTX is an XML DOCUMENT. Merely CONTAINING "<Event" is not evidence of that: any
        # file that QUOTES event XML — a chat transcript, a source file, a ticket export — matched here,
        # and a 400 KB JSONL agent log scored 0.97 and came back as four `parse_error` records. Require
        # the sample to actually start as markup, which every real export does (`<?xml …`, `<Events>`,
        # or one `<Event …>` per line from `wevtutil qe /f:xml`).
        first = next((l.lstrip("\ufeff \t") for l in lines if l.strip()), "")
        if first.startswith("<") and "<Event" in text and ("<EventID" in text or "<System>" in text):
            conf = 0.9
            if "schemas.microsoft.com/win/2004/08/events/event" in text:
                conf = 0.97
            return conf
        if filename.lower().endswith(".evtx"):
            return 0.6
        return 0.0

    def parse_bytes(self, data: bytes) -> Iterator[ParsedEvent]:
        if data.startswith(b"ElfFile"):
            yield from self._parse_binary(data)
        else:
            yield from self.parse(data.decode("utf-8", errors="replace").splitlines())

    def _parse_binary(self, data: bytes) -> Iterator[ParsedEvent]:
        try:
            from Evtx.Evtx import FileHeader  # type: ignore
        except Exception as exc:  # pragma: no cover
            yield ParsedEvent(raw="", msg=f"python-evtx not available: {exc}", fields={"parse_error": "no-evtx-lib"})
            return
        fh = FileHeader(data, 0)
        for chunk in fh.chunks():
            for record in chunk.records():
                try:
                    xml = record.xml()
                except Exception:
                    continue
                ev = self._parse_xml(xml)
                if ev:
                    yield ev

    def parse(self, lines: Iterable[str]) -> Iterator[ParsedEvent]:
        text = "\n".join(lines)
        for chunk in _EVENT_SPLIT.split(text):
            if "<Event" not in chunk:
                continue
            end = chunk.rfind("</Event>")
            if end < 0:
                continue
            xml = chunk[: end + len("</Event>")]
            ev = self._parse_xml(xml)
            if ev:
                yield ev

    def _parse_xml(self, xml: str) -> Optional[ParsedEvent]:
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            return ParsedEvent(raw=xml[:2000], msg="unparseable EVTX record", fields={"parse_error": "xml"})
        fields: dict[str, str] = {}
        system = None
        for child in root:
            if _strip_ns(child.tag) == "System":
                system = child
                break
        ts_text = ""
        host = ""
        event_id = ""
        if system is not None:
            for el in system:
                tag = _strip_ns(el.tag)
                if tag == "TimeCreated":
                    ts_text = el.attrib.get("SystemTime", "")
                elif tag == "Computer":
                    host = (el.text or "").strip()
                elif tag == "EventID":
                    event_id = (el.text or "").strip()
                elif tag == "Provider":
                    fields["Provider"] = el.attrib.get("Name", "")
                elif tag == "Channel":
                    fields["Channel"] = (el.text or "").strip()
                elif tag == "Level":
                    fields["Level"] = (el.text or "").strip()
                elif tag == "EventRecordID":
                    fields["EventRecordID"] = (el.text or "").strip()
                elif tag == "Execution":
                    if "ProcessID" in el.attrib:
                        fields["Execution.ProcessID"] = el.attrib["ProcessID"]
        for child in root:
            if _strip_ns(child.tag) in ("EventData", "UserData"):
                for el in child.iter():
                    tag = _strip_ns(el.tag)
                    if tag == "Data":
                        name = el.attrib.get("Name")
                        val = (el.text or "").strip()
                        if name:
                            fields[name] = val
                    elif tag not in ("EventData", "UserData") and el.text and el.text.strip() and len(list(el)) == 0:
                        fields[tag] = el.text.strip()
        fields["EventID"] = event_id
        fields["Computer"] = host
        eid = int(event_id) if event_id.isdigit() else -1
        base = EVENT_ID_MESSAGES.get(eid, f"Event {event_id}")
        user = fields.get("TargetUserName") or fields.get("SubjectUserName") or ""
        if user.endswith("$"):
            user = fields.get("SubjectUserName", user) if fields.get("SubjectUserName") and not fields["SubjectUserName"].endswith("$") else user
        parts = [f"{event_id} — {base}"]
        sev: Optional[str] = None
        if eid == 4624:
            lt = fields.get("LogonType", "")
            ip = fields.get("IpAddress", "")
            parts = [f"4624 — logon type {lt} ({LOGON_TYPES.get(lt, 'unknown')})" + (f" from {ip}" if ip and ip != "-" else "")]
            if lt:
                fields["LogonType"] = f"{lt} ({LOGON_TYPES.get(lt, 'unknown')})"
            fields["result"] = "Success"
        elif eid == 4625:
            parts = [f"4625 — failed logon for {user}" + (f" from {fields.get('IpAddress')}" if fields.get("IpAddress") not in (None, "-") else "")]
            fields["result"] = "Failure"
            sev = "medium"
        elif eid == 4672:
            parts = ["4672 — special privileges assigned to new logon"]
            for p in (fields.get("PrivilegeList") or "").replace("\n", " ").split():
                fields[p] = "granted"
            fields["result"] = "Success"
        elif eid == 4688:
            parts = [f"4688 — process created: {fields.get('NewProcessName', '')}"]
        elif eid == 4720:
            parts = [f"4720 — user account created: {fields.get('TargetUserName', '')}"]
            sev = "medium"
        elif eid == 1102:
            parts = ["1102 — audit log cleared"]
            sev = "high"
        elif eid in (4728, 4732):
            parts = [f"{eid} — member added to group {fields.get('TargetUserName', '')}"]
            sev = "medium"
        elif eid == 4740:
            sev = "medium"
        msg = " ".join(parts)
        if fields.get("Level") in ("1", "2"):
            sev = sev or "high"
        elif fields.get("Level") == "3":
            sev = sev or "medium"
        return ParsedEvent(raw=xml.strip(), msg=msg, ts=parse_ts(ts_text) if ts_text else None, ts_text=ts_text,
                           host=host, user=user, sev=sev, fields=fields)
