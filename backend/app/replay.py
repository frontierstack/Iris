"""What the case timeline REPLAY says about each moment (GET /api/case-set/replay).

The replay plays the curated events back at the pace they really happened. Two things make that more
than a list being revealed, and both are computed here, on the server, because only the server has
the pool:

1. **The exact instant.** `Event.ts` is normalised to whole seconds, while many logs record the
   millisecond (`Sep 17, 2026 @ 18:49:22.927`). Two events in the same second are then played as
   simultaneous when one really came 900 ms after the other. The fraction is recovered here from the
   event's own timestamp field or raw line. It is only taken when the minutes and seconds beside it
   match the normalised stamp, so a local-time field in another zone can never lend its fraction
   to the wrong second. The normaliser is deliberately NOT changed for this: it is hashed into the
   parsed-pool cache key, and touching it would re-parse the whole library.

2. **What changed at that moment**: the "beats" the analyst reads while it plays. They are:
   - *the action*, read from the event's typed fields: a download, a process start, a DLL load, an
     account logon, a service installed, a log cleared. Each has to be stated by a field or a
     documented event id; nothing is inferred from a word appearing somewhere in the line.
   - *first sightings across the WHOLE POOL*: "first traffic to 52.85.12.49 in any log". The
     earliest event carrying the value is found with the search engine, the same path Search
     uses. When the value was already active before the timeline begins, that is said too, with
     when and where: an attacker address first seen three hours before the curated start is a
     finding about the timeline itself.
   - *detections* the event fired.

A first sighting is only claimed when it was checked. `entity:"v"` is exact but covers only
interpreted sources; when it finds nothing, a free-text search is tried and its hit is confirmed
with a word-bounded match, because free text for `10.0.0.1` also matches `10.0.0.100`. If neither
confirms, no beat is made. Claiming "first" without checking is the silent-evidence bug this project
keeps fighting.
"""
from __future__ import annotations

import calendar
import re
import threading
from typing import Any, Optional

from .graph import clean_domain, plausible_ip
from .store import STORE

# Values examined per request, across all events. Each is one indexed search.
MAX_VALUES = 80
BEATS_PER_EVENT = 7
_NONE = frozenset({"", "-", "--", "null", "none", "n/a", "(null)", "unknown"})
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_ISO = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?")

_cache: dict[tuple, dict[str, Any]] = {}
_cache_lock = threading.Lock()


def _real(v: Any) -> str:
    s = str(v).strip() if v is not None else ""
    return "" if s.lower() in _NONE else s


class _F:
    """Case-insensitive, placeholder-blind access to an event's fields."""

    def __init__(self, fields: dict[str, Any]):
        self.m = {}
        for k, v in (fields or {}).items():
            r = _real(v)
            if r:
                self.m[k.lower()] = r

    def get(self, *keys: str) -> str:
        for k in keys:
            v = self.m.get(k.lower())
            if v:
                return v
        return ""


def _base(path: str) -> str:
    return re.split(r"[\\/]", path)[-1] if path else ""


# ───────────────────────── the exact instant ─────────────────────────

def precise_ms(e: Any) -> tuple[Optional[int], str]:
    """(epoch milliseconds, 'ms' | 's') or (None, '') for an unstamped event."""
    m = _ISO.match(e.ts or "")
    if not m:
        return None, ""
    y, mo, d, hh, mi, ss, frac = m.groups()
    base = calendar.timegm((int(y), int(mo), int(d), int(hh), int(mi), int(ss))) * 1000
    if frac:
        return base + int(frac[:3].ljust(3, "0")), "ms"
    # The fraction the normaliser dropped: HH:MM:SS followed by a fraction, where MM:SS match the stamp.
    pat = re.compile(r"\d{2}:" + mi + ":" + ss + r"[.,](\d{1,9})(?!\d)")
    f = _F(e.fields)
    sources = [v for k, v in f.m.items() if "time" in k or "date" in k or k in ("ts", "@timestamp")]
    sources.append(e.raw or "")
    for text in sources:
        hit = pat.search(text)
        if hit:
            return base + int(hit.group(1)[:3].ljust(3, "0")), "ms"
    return base, "s"


# ───────────────────────── the action ─────────────────────────

_WIN_IDS: dict[str, tuple[str, str]] = {
    # id: (kind, template) — {user}, {target}, {proc}, {svc}, {task}, {group}, {ip}
    "4624": ("access", "Account logged on: {target}{from_ip}"),
    "4625": ("auth-fail", "Failed logon for {target}{from_ip}"),
    "4648": ("access", "Logon with explicit credentials: {target}"),
    "4672": ("privilege", "Special privileges assigned to {target}"),
    "4688": ("process", "Process created: {proc}"),
    "4697": ("persistence", "Service installed: {svc}"),
    "7045": ("persistence", "Service installed: {svc}"),
    "4698": ("persistence", "Scheduled task created: {task}"),
    "4702": ("persistence", "Scheduled task updated: {task}"),
    "4720": ("account", "Account created: {target}"),
    "4722": ("account", "Account enabled: {target}"),
    "4724": ("account", "Password reset for {target}"),
    "4728": ("privilege", "Added to a security group: {target} → {group}"),
    "4732": ("privilege", "Added to a local group: {target} → {group}"),
    "4756": ("privilege", "Added to a universal group: {target} → {group}"),
    "1102": ("anti-forensics", "Security audit log cleared"),
    "104": ("anti-forensics", "Event log cleared"),
    "4104": ("execution", "PowerShell script block executed"),
}
_SYSMON_IDS: dict[str, tuple[str, str]] = {
    "1": ("process", "Process created: {proc}"),
    "3": ("network", "Network connection to {dst}"),
    "11": ("file", "File created: {file}"),
    "12": ("registry", "Registry key changed: {reg}"),
    "13": ("registry", "Registry value set: {reg}"),
    "22": ("dns", "Name resolved: {query}"),
}
_RUN_KEY = re.compile(r"\\(?:Run|RunOnce|Winlogon|Services)\\", re.I)

_SSH_OK = re.compile(r"Accepted (password|publickey|keyboard-interactive\S*) for (\S+) from (\S+)")
_SSH_FAIL = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
_SESSION = re.compile(r"session opened for user (\S+?)(?:\(|\s|$)")
_SUDO = re.compile(r"sudo:\s+(\S+)\s*:.*COMMAND=(.+)$")


def _fmt(tpl: str, **kv: str) -> str:
    return tpl.format_map({k: (v or "?") for k, v in kv.items()}).strip()


def action_beats(e: Any) -> list[dict[str, str]]:
    f = _F(e.fields)
    out: list[dict[str, str]] = []

    def add(kind: str, text: str) -> None:
        out.append({"kind": kind, "text": text})

    user = _real(e.user)
    # Windows event ids (Security / System / Sysmon)
    eid = f.get("EventID", "event.code", "EventCode", "winlog.event_id", "event_id")
    channel = (f.get("Channel", "winlog.channel", "LogName", "provider", "winlog.provider_name") or "").lower()
    if eid:
        table = _SYSMON_IDS if "sysmon" in channel else _WIN_IDS
        hit = table.get(eid)
        if hit:
            kind, tpl = hit
            ip = f.get("IpAddress", "source.ip", "SourceIp")
            reg = f.get("TargetObject", "registry.path")
            text = _fmt(tpl, target=f.get("TargetUserName", "SubjectUserName", "user.name") or user,
                        from_ip=f" from {ip}" if ip and ip not in ("::1", "127.0.0.1") else "",
                        proc=_base(f.get("NewProcessName", "Image", "process.executable", "process.name")),
                        svc=f.get("ServiceName", "service.name"), task=f.get("TaskName"),
                        group=f.get("TargetSid", "MemberName", "group.name", "TargetUserName"),
                        dst=":".join(x for x in (f.get("DestinationIp", "destination.ip"),
                                                 f.get("DestinationPort", "destination.port")) if x),
                        file=f.get("TargetFilename", "file.path"), reg=reg, query=f.get("QueryName"))
            add(kind, text)
            if kind == "registry" and reg and _RUN_KEY.search(reg):
                add("persistence", "Autorun location written: " + reg)

    # Elastic Endpoint / ECS datasets
    ds = (f.get("data_stream.dataset", "event.dataset") or "").lower()
    act = f.get("event.action", "event.type")
    if ds.endswith(".process") or ds == "process":
        name = f.get("process.name") or _base(f.get("process.executable"))
        parent = f.get("process.parent.name") or _base(f.get("process.parent.executable"))
        verb = {"start": "started", "exec": "executed", "fork": "forked", "end": "exited"}.get((act or "").lower(), act or "event")
        if name:
            add("process", f"Process {verb}: {name}" + (f", launched by {parent}" if parent and verb != "exited" else ""))
        cmd = f.get("process.command_line")
        if cmd and len(cmd) > len(name) + 3:
            add("command", "Command line: " + cmd[:180])
    elif ds.endswith(".file") or ds == "file":
        path = f.get("file.path") or f.get("file.name")
        by = f.get("process.name")
        if path:
            add("file", f"File {(act or 'event').replace('_', ' ')}: {path}" + (f" by {by}" if by else ""))
        signer = f.get("file.code_signature.subject_name")
        if signer:
            trusted = f.get("file.code_signature.trusted")
            add("signature", f"Signed by {signer}" + (" (trusted)" if trusted == "true" else " (NOT trusted)" if trusted == "false" else ""))
    elif ds.endswith(".library"):
        dll = f.get("dll.name") or _base(f.get("dll.path"))
        into = f.get("process.name")
        if dll:
            add("library", f"DLL loaded: {dll}" + (f" into {into}" if into else ""))
    elif ds.endswith(".network"):
        dst = ":".join(x for x in (f.get("destination.ip"), f.get("destination.port")) if x)
        if dst:
            add("network", f"Network {(act or 'connection').replace('_', ' ')}: {dst}" + (f" by {f.get('process.name')}" if f.get("process.name") else ""))
    elif ds.endswith(".registry"):
        reg = f.get("registry.path")
        if reg:
            add("registry", f"Registry {(act or 'change').replace('_', ' ')}: {reg}")
            if _RUN_KEY.search(reg):
                add("persistence", "Autorun location written: " + reg)
    elif ds.endswith(".security") or "authentication" in (f.get("event.category") or "").lower():
        outcome = (f.get("event.outcome") or "").lower()
        who = f.get("user.name") or user
        if who:
            add("auth-fail" if outcome == "failure" else "access",
                ("Failed sign-in for " if outcome == "failure" else "Account accessed: ") + who)

    # Web proxy: a download, or a request
    dl = f.get("download_file_name", "file_name", "filename")
    domain = f.get("domain", "url.domain", "destination.domain", "cs-host", "http.host")
    verdict = (f.get("log_subtype", "action", "event.outcome") or "").lower()
    blocked = verdict in ("denied", "blocked", "deny", "block", "dropped")
    if dl and (domain or f.get("url")):
        add("download", f"{'Download BLOCKED' if blocked else 'Downloaded'}: {dl}" + (f" from {domain}" if domain else "")
            + (f" ({f.get('download_file_type')})" if f.get("download_file_type") else ""))
    elif domain and f.get("url") and not out:
        add("web", f"Web request {'blocked' if blocked else 'to'} {domain}")

    # DNS
    q = f.get("dns.question.name", "query", "QueryName", "qname")
    if q and not any(b["kind"] == "dns" for b in out):
        add("dns", f"Name resolved: {q}")

    # Unix / cloud sign-ins, read from the message the daemon writes
    msg = e.msg or e.raw or ""
    m = _SSH_OK.search(msg)
    if m:
        add("access", f"Account accessed: {m.group(2)} from {m.group(3)} (SSH, {m.group(1)})")
    m = _SSH_FAIL.search(msg)
    if m:
        add("auth-fail", f"Failed SSH password for {m.group(1)} from {m.group(2)}")
    m = _SESSION.search(msg)
    if m and not out:
        add("access", f"Session opened for {m.group(1)}")
    m = _SUDO.search(msg)
    if m:
        add("privilege", f"sudo by {m.group(1)}: {m.group(2).strip()[:120]}")
    if f.get("eventName") == "ConsoleLogin":
        ok = "success" in (f.get("responseElements.ConsoleLogin", "responseElements") or "").lower()
        add("access" if ok else "auth-fail", f"AWS console sign-in {'succeeded' if ok else 'failed'}: {user or f.get('userIdentity.arn')}")

    for d in e.detections:
        out.append({"kind": "detection", "text": f"Detection fired: {d.name}", "sev": d.level})
    return out


# ───────────────────────── first sightings ─────────────────────────

# (fields, role) in priority order. Roles decide the wording of a first sighting.
_ROLE_FIELDS: list[tuple[tuple[str, ...], str]] = [
    (("dst_ip", "destination.ip", "dest_ip", "DestinationIp", "dst", "dstip"), "to"),
    (("src_ip", "source.ip", "SourceIp", "IpAddress", "client_ip", "c-ip", "srcip"), "from"),
    (("domain", "url.domain", "destination.domain", "dns.question.name", "QueryName", "cs-host"), "domain"),
    (("process.name",), "process"),
    (("download_file_name", "file.name", "TargetFilename"), "file"),
    (("process.hash.sha256", "file.hash.sha256", "hash.sha256", "sha256"), "hash"),
]

_FIRST_TEXT = {
    "to": "First traffic to {v} in any log",
    "from": "First activity from {v} in any log",
    "domain": "First sighting of {v} in any log",
    "account": "First activity by account {v} in any log",
    "host": "First activity on host {v} in any log",
    "process": "First execution of {v} in any log",
    "file": "First appearance of {v} in any log",
    "hash": "First sighting of hash {v} in any log",
    "ip": "First sighting of {v} in any log",
}
_ROLE_NOUN = {"to": "", "from": "", "domain": "", "account": "account ", "host": "host ",
              "process": "", "file": "", "hash": "hash ", "ip": ""}


def _candidates(e: Any) -> list[tuple[str, str]]:
    f = _F(e.fields)
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    def put(v: str, role: str) -> None:
        v = v.strip()
        if not v or v.lower() in seen or len(v) > 300:
            return
        # A FIELD named dst_ip says what its value is; the version-string guard is for untyped entities.
        if role == "ip" and not plausible_ip(v):
            return
        if role == "domain":
            v = clean_domain(v) or ""
            if not v:
                return
        if role == "process" and v.lower() in ("-", "system", "idle"):
            return
        seen.add(v.lower())
        out.append((v, role))

    for keys, role in _ROLE_FIELDS:
        for k in keys:
            v = f.get(k)
            if v:
                put(v, role)
    if _real(e.user):
        put(e.user, "account")
    if _real(e.host):
        put(e.host, "host")
    text = " ".join([e.raw or "", *f.m.values()])
    for ent in e.entities:
        if _IPV4.match(ent):
            # The extractor also takes the version in `ReasonLabs-x64-v5.1.3.7z` for an address. An
            # address stands on its own in the line; a version is glued to a word.
            if re.search(r"(?<![\w.\-])" + re.escape(ent) + r"(?![\w\-]|\.\w)", text):
                put(ent, "ip")
        elif _SHA256.match(ent):
            put(ent, "hash")
        elif "/" not in ent and ":" not in ent and clean_domain(ent) and not re.fullmatch(r"[\d.]+", ent):
            put(ent, "domain")
    return out


def _first_seen(value: str) -> Optional[dict[str, Any]]:
    """The earliest event in the pool carrying `value`, and how many do. None when unconfirmed."""
    from . import search as search_engine
    if '"' in value or "\\" in value:
        return None
    with STORE.lock:
        events, ts, version = STORE.events, STORE.ts, STORE.version
    n = len(events)
    if not n:
        return None
    res = search_engine.search(events, ts, version, f'entity:"{value}"', 0, n, set(), set(), 0, 1)
    rows = res.get("rows") or []
    how = "entity"
    if not rows:
        # Free text reaches raw, un-interpreted sources too; its hit must be CONFIRMED word-bounded.
        res = search_engine.search(events, ts, version, f'"{value}"', 0, n, set(), set(), 0, 25)
        bound = re.compile(r"(?<![\w.\-])" + re.escape(value) + r"(?![\w\-]|\.\w)", re.I)
        rows = [r for r in (res.get("rows") or [])
                if bound.search(r.raw or "") or bound.search(r.msg or "")
                or any(bound.search(str(v)) for v in (r.fields or {}).values())][:1]
        how = "mention"
    if not rows:
        return None
    first = rows[0]
    if not first.ts:
        return None
    return {"id": first.id, "ts": first.ts, "file": first.file, "total": int(res.get("total") or 0),
            "totalExact": bool(res.get("totalExact", True)), "how": how}


def build(entries: list[Any]) -> dict[str, Any]:
    events = [(en, STORE.event(en.eventId)) for en in entries]
    stamped = [(en, e) for en, e in events if e is not None and e.ts]
    stamped.sort(key=lambda p: p[1].ts)
    key = (STORE.version, STORE.case_set_rev, tuple(en.eventId for en, _ in stamped),
           tuple(len(en.note or "") for en, _ in stamped))
    with _cache_lock:
        hit = _cache.get(key)
    if hit is not None:
        return hit

    first_cache: dict[str, Optional[dict[str, Any]]] = {}
    checked = 0
    reported: set[str] = set()     # a value's "already active earlier" is said once, on its first timeline event
    out_events: list[dict[str, Any]] = []
    for en, e in stamped:
        t_ms, precision = precise_ms(e)
        beats = action_beats(e)
        firsts: list[dict[str, Any]] = []
        for value, role in _candidates(e):
            k = value.lower()
            if k not in first_cache:
                if checked >= MAX_VALUES:
                    continue
                checked += 1
                first_cache[k] = _first_seen(value)
            fs = first_cache[k]
            if fs is None:
                continue
            total = f"{fs['total']:,}{'' if fs['totalExact'] else '+'}"
            if fs["id"] == e.id or fs["ts"][:19] >= e.ts[:19]:
                if k in reported:
                    continue
                reported.add(k)
                shown = value[:16] + "…" if role == "hash" else value
                text = _FIRST_TEXT.get(role, _FIRST_TEXT["ip"]).format(v=shown)
                if fs["how"] == "mention":
                    # Found in a raw line rather than an extracted field: a mention, not an execution.
                    text = f"First mention of {shown} in any log"
                firsts.append({"kind": "first", "role": role, "value": value,
                               "text": text + (f" — {total} events carry it" if fs["total"] > 1 else " — the only event that carries it")})
            elif k not in reported:
                reported.add(k)
                firsts.append({"kind": "earlier", "role": role, "value": value, "firstTs": fs["ts"],
                               "firstFile": fs["file"], "firstId": fs["id"],
                               "text": f"{_ROLE_NOUN.get(role, '')}{value[:16] + '…' if role == 'hash' else value} was already active before this — first seen "
                                       f"{fs['ts'][:19].replace('T', ' ')} UTC in {fs['file']}"})
        beats = (beats + firsts)[:BEATS_PER_EVENT]
        out_events.append({"eventId": en.eventId, "tMs": t_ms, "precision": precision, "beats": beats})

    result = {"events": out_events, "valuesChecked": checked,
              "valuesCapped": checked >= MAX_VALUES,
              "note": ("First sightings are checked against every loaded log: exactly for interpreted "
                       "sources, and by a confirmed word match in raw ones. A value that could not be "
                       "confirmed makes no claim.")}
    with _cache_lock:
        if len(_cache) > 16:
            _cache.clear()
        _cache[key] = result
    return result
