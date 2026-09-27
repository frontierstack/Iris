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


# ───────────────────────── one action per event (the replay's map draws EVERY event) ─────────────────────────
# `action_beats` above reports what it can PROVE and says nothing otherwise, which is right for the
# observations. The map needs more: every event on the timeline has to appear on it as something —
# "everything that is an event needs to show", as the analyst put it — so each event is classified
# into ONE action and the thing it acted on. Typed fields first, in the order of specificity; then the
# analyst's own note (its first `quoted value` is, by the note's own convention, the object); then the
# event's first entity. `kind: 'event'` is the honest bottom: the event is shown, unclassified.

_DELETE_RE = re.compile(r"delet|remov|unlink|wipe|shred|purge|erase", re.I)
_RENAME_RE = re.compile(r"renam|mov", re.I)
_TICK_RE = re.compile(r"`([^`]{1,200})`")
_URL_HOST = re.compile(r"^[a-z][a-z0-9+.-]*://([^/:?#]+)", re.I)


_API_CALL = re.compile(r"^\s*([A-Za-z_][\w.]*)\s*\((.*)\)\s*$", re.S)
_WEB_APIS = ("winhttp", "internetopenurl", "internetconnect", "httpopenrequest", "httpsendrequest",
             "urldownloadto", "urlopenstream")
_HTTP_METHODS = {"GET", "POST", "PUT", "HEAD", "DELETE", "PATCH", "OPTIONS", "CONNECT"}
_INJECT_APIS = {"ntqueueapcthread", "queueuserapc", "writeprocessmemory", "ntwritevirtualmemory",
                "createremotethread", "ntcreatethreadex", "setthreadcontext", "ntsetcontextthread",
                "virtualallocex", "ntmapviewofsection", "ntallocatevirtualmemory"}


def _api_call(summary: str) -> Optional[tuple[str, list[str]]]:
    """`WinHttpOpenRequest( https://x/sync, POST )` -> ('WinHttpOpenRequest', ['https://x/sync', 'POST'])."""
    m = _API_CALL.match(summary or "")
    if not m:
        return None
    args = [_real(a) for a in m.group(2).split(",")]
    return m.group(1), [a for a in args if a and a.upper() != "NULL"]


def _verb(act: str, default: str) -> str:
    a = (act or "").replace("_", " ").strip().lower()
    return a or default


def action_of(e: Any, note: str = "") -> dict[str, str]:
    """{kind, verb, object, actor} for ONE event — never empty, because every event is drawn.

    `actor` is the PROCESS behind the action: for a process start, its parent; for a file write, a DLL
    load, a connection or a lookup, the process that did it. It is how the map links a child process
    to the one that spawned it — reported as "a child process wasn't linked to anything": the two
    share no file, hash or address, only the relationship, and the relationship is in these fields.
    """
    f = _F(e.fields)
    act = f.get("event.action", "Action", "action", "operation", "Operation", "EventType", "event.type",
                "OperationName", "eventName")
    ds = (f.get("data_stream.dataset", "event.dataset", "event.category", "log_type", "category") or "").lower()
    msg = f"{e.msg or ''} {act}"

    proc = f.get("process.name") or _base(f.get("process.executable", "Image", "NewProcessName"))
    parent = f.get("process.parent.name") or _base(f.get("process.parent.executable", "ParentImage",
                                                           "ParentProcessName"))

    def out(kind: str, verb: str, obj: str) -> dict[str, str]:
        obj = (obj or "").strip()[:300]
        actor = parent if kind == "process" else (proc if proc and proc.lower() != obj.lower() else "")
        return {"kind": kind, "verb": verb, "object": obj, "actor": actor or ""}

    # A deletion is a deletion whatever produced it — the one action most worth never missing.
    target = f.get("file.path", "TargetFilename", "file.name", "Path", "ObjectName", "path", "filename",
                   "registry.path", "TargetObject")
    if (act and _DELETE_RE.search(act)) or (not act and _DELETE_RE.search(e.msg or "") and target):
        what = "registry" if ("registry" in ds or f.get("registry.path") or f.get("TargetObject")) else "file"
        return out("delete", f"{what} deleted", _base(target) or target or (e.msg or "")[:80])

    # Windows event ids (Security / System / Sysmon)
    eid = f.get("EventID", "event.code", "EventCode", "winlog.event_id", "event_id")
    channel = (f.get("Channel", "winlog.channel", "LogName", "provider", "winlog.provider_name") or "").lower()
    if eid:
        who = f.get("TargetUserName", "SubjectUserName", "user.name") or _real(e.user)
        if "sysmon" in channel:
            sysmon = {"1": ("process", "process started", _base(f.get("Image", "process.executable"))),
                      "3": ("network", "connection", f.get("DestinationIp", "DestinationHostname")),
                      "11": ("file", "file created", _base(f.get("TargetFilename"))),
                      "12": ("registry", "registry key changed", _base(f.get("TargetObject"))),
                      "13": ("registry", "registry value set", _base(f.get("TargetObject"))),
                      "22": ("dns", "DNS lookup", f.get("QueryName")),
                      "23": ("delete", "file deleted", _base(f.get("TargetFilename"))),
                      "26": ("delete", "file deleted", _base(f.get("TargetFilename")))}.get(eid)
            if sysmon and sysmon[2]:
                return out(*sysmon)
        win = {"4624": ("access", "logon", who), "4625": ("auth-fail", "failed logon", who),
               "4648": ("access", "explicit-credential logon", who), "4672": ("privilege", "special privileges", who),
               "4688": ("process", "process created", _base(f.get("NewProcessName", "process.executable"))),
               "4697": ("persistence", "service installed", f.get("ServiceName")),
               "7045": ("persistence", "service installed", f.get("ServiceName")),
               "4698": ("persistence", "scheduled task created", f.get("TaskName")),
               "4720": ("account", "account created", who), "4726": ("delete", "account deleted", who),
               "4732": ("privilege", "added to group", who), "4728": ("privilege", "added to group", who),
               "1102": ("anti-forensics", "audit log cleared", channel or "Security"),
               "104": ("anti-forensics", "event log cleared", channel or "log"),
               "4104": ("execution", "PowerShell script block", f.get("Path") or "script")}.get(eid)
        if win and win[2]:
            return out(*win)

    # Elastic Endpoint API telemetry: `process.Ext.api.summary` is `Function( arg, arg, … )`, and the
    # function says what the process DID — a WinHttp call to a URL is a web request, an APC queued into
    # another process is an injection. Without this every such row was an unclassified "event" whose
    # object was the process itself, which is why the map showed a column of identical boxes.
    if ds.endswith(".api"):
        api = _api_call(f.get("process.Ext.api.summary", "process.Ext.api.name", "api.summary"))
        if api:
            fn, args = api
            first = args[0] if args else ""
            if fn.lower().startswith(_WEB_APIS) and _URL_HOST.match(first):
                method = next((a.upper() for a in args[1:] if a.upper() in _HTTP_METHODS), "")
                return out("web", f"{fn}{' ' + method if method else ''}", _URL_HOST.match(first).group(1))
            if fn.lower() in _INJECT_APIS and first:
                return out("injection", f"{fn} into", _base(first))
            return out("api", fn, _base(first) if first and len(first) < 120 else fn)
    if ds.endswith(".alerts") or ds.endswith(".alert"):
        cat = f.get("rule.name", "kibana.alert.rule.name", "event.category", "message")
        return out("alert", "alert" + (f": {cat.split(',')[0].strip()}" if cat else ""), proc or _real(e.host))

    # Elastic Endpoint / ECS datasets
    if ds.endswith(".process") or ds == "process":
        name = f.get("process.name") or _base(f.get("process.executable"))
        if name:
            # ECS may record several actions at once ("start, end" = a short-lived process).
            words = {"start": "started", "exec": "executed", "fork": "forked", "end": "ended"}
            acts = [x.strip() for x in (act or "").lower().split(",") if x.strip()]
            v = ("process " + " & ".join(words.get(x, x) for x in acts)) if acts else "process"
            return out("process", v, name)
    if ds.endswith(".file") or ds == "file":
        path = f.get("file.path") or f.get("file.name")
        if path:
            words = {"creation": "created", "create": "created", "open": "opened", "modification": "modified",
                     "overwrite": "overwritten", "rename": "renamed", "write": "written", "read": "read"}
            acts = [x.strip() for x in (act or "").lower().replace("_", " ").split(",") if x.strip()]
            v = ("file " + " & ".join(words.get(x, x) for x in acts)) if acts else "file"
            if acts and _RENAME_RE.search(v):
                v = "file renamed"
            return out("file", v, _base(path))
    if ds.endswith(".library"):
        dll = f.get("dll.name") or _base(f.get("dll.path"))
        if dll:
            return out("library", "DLL loaded", dll)
    if ds.endswith(".network") or "network" in ds:
        dst = f.get("destination.ip", "dst_ip", "DestinationIp", "dest_ip")
        if dst:
            port = f.get("destination.port", "dst_port", "DestinationPort")
            return out("network", _verb(act, "connection"), dst + (f":{port}" if port else ""))
    if ds.endswith(".registry") or "registry" in ds:
        reg = f.get("registry.path", "TargetObject")
        if reg:
            return out("registry", _verb(act, "registry change"), _base(reg))
    if ds.endswith(".security") or "authentication" in ds:
        who = f.get("user.name") or _real(e.user)
        if who:
            failed = (f.get("event.outcome") or "").lower() == "failure"
            return out("auth-fail" if failed else "access", "failed sign-in" if failed else "sign-in", who)

    # Web proxy / DNS
    dl = f.get("download_file_name")
    domain = f.get("domain", "url.domain", "destination.domain", "cs-host", "http.host", "host_header")
    url = f.get("url", "url.full", "cs-uri", "request_url")
    blocked = (f.get("log_subtype", "action", "event.outcome", "disposition") or "").lower() in (
        "denied", "blocked", "deny", "block", "dropped")
    if dl:
        return out("download", "download blocked" if blocked else "download", dl)
    q = f.get("dns.question.name", "query", "QueryName", "qname", "dns_query")
    if q:
        return out("dns", "DNS lookup", q)
    # A DNS log that names its question `domain` says it is one by its verb or its record type.
    if domain and not url and (f.get("query_type", "qtype", "dns.question.type", "record_type")
                               or (act or "").lower() in ("queried", "query", "resolved", "lookup")):
        return out("dns", "DNS lookup", domain)
    if domain or url:
        host = domain or (_URL_HOST.match(url).group(1) if url and _URL_HOST.match(url) else url)
        return out("web", "web request blocked" if blocked else "web request", host)
    dst = f.get("dst_ip", "destination.ip", "dest_ip", "DestinationIp")
    if dst:
        port = f.get("dst_port", "destination.port", "dest_port")
        return out("network", "connection", dst + (f":{port}" if port else ""))

    # Unix / cloud sign-ins, read from what the daemon wrote
    m = _SSH_OK.search(msg)
    if m:
        return out("access", "SSH logon", m.group(2))
    m = _SSH_FAIL.search(msg)
    if m:
        return out("auth-fail", "failed SSH logon", m.group(1))
    m = _SUDO.search(msg)
    if m:
        return out("privilege", "sudo", m.group(1))
    if f.get("eventName"):
        return out("cloud", _verb(f.get("eventName"), "API call"), _real(e.user) or f.get("userIdentity.arn"))

    # The analyst's note: its first quoted value is, by the note's own convention, the object.
    t = _TICK_RE.search(note or "")
    label = ""
    if t:
        label = t.group(1)
        return out("event", "event", _base(label) if ("\\" in label or "/" in label) else label)
    if e.entities:
        return out("event", "event", str(e.entities[0]))
    return out("event", "event", _real(e.host) or _real(e.user) or (e.msg or e.raw or "")[:60])


# ───────────────────────── relations: what ties two events together ─────────────────────────
# "Often I see nodes just show by themselves when there is clearly connectors that should connect."
# The screen used to guess links from two strings — the action's `actor` NAME against the object of
# an earlier process start, and a shared entity value — so a process's own API calls (whose object
# was the process itself) linked to nothing, a child whose parent had no "process" row linked to
# nothing, and a proxy row naming the domain a process had just called linked to nothing. The pool
# knows far more than that: PIDs, parent PIDs, image paths, URLs, DNS answers, logon ids. Each rule
# below links two events only on a value BOTH of them carry, and says which value.
#
# A link always runs from an EARLIER event to a later one, and for each value to the MOST RECENT
# earlier carrier, so a value that recurs reads as a chain rather than a fan. Two events tied by
# several values keep the one most specific reason (a spawn over a shared domain).

_PID_KEYS = ("process.pid", "ProcessId", "pid", "process_id", "ProcessID")
_PPID_KEYS = ("process.parent.pid", "ParentProcessId", "ppid", "parent_pid", "ParentProcessID")
_EXE_KEYS = ("process.executable", "Image", "NewProcessName", "process.path", "exe")
_PEXE_KEYS = ("process.parent.executable", "ParentImage", "ParentProcessName", "process.parent.path")
_PNAME_KEYS = ("process.parent.name", "ParentName")
_SESSION_KEYS = ("TargetLogonId", "SubjectLogonId", "LogonId", "logon_id", "session.id", "session_id",
                 "process.Ext.authentication_id", "user.session_id")
_RESOLVED_KEYS = ("dns.resolved_ip", "dns.answers.data", "answer", "answers", "QueryResults",
                  "resolved_ip", "dns.answer")
_FILE_KEYS = ("file.path", "TargetFilename", "file.name", "download_file_name", "dll.path")
_HASH_KEYS = ("process.hash.sha256", "file.hash.sha256", "hash.sha256", "sha256", "dll.hash.sha256",
              "process.hash.md5", "file.hash.md5", "md5", "Hashes")
_DOMAIN_KEYS = ("domain", "url.domain", "destination.domain", "dns.question.name", "QueryName", "query",
                "qname", "dns_query", "cs-host", "http.host", "host_header", "DestinationHostname")
_URL_KEYS = ("url", "url.full", "cs-uri", "request_url", "url.original")
_DST_IP_KEYS = ("dst_ip", "destination.ip", "dest_ip", "DestinationIp", "dstip")
_IP_ANY = re.compile(r"(?<![\w.\-])((?:\d{1,3}\.){3}\d{1,3})(?![\w\-]|\.\w)")

# (rule, kind, rank) — rank orders "most specific"; kind decides how the map draws it:
# 'actor' = causation (a process did it), 'shared' = the two touched the same thing.
REL_RANK = {"spawned": 0, "executed": 1, "same-process": 2, "injected": 3, "hash": 4, "file": 5,
            "resolved": 6, "domain": 7, "session": 8, "address": 9}
REL_KIND = {"spawned": "actor", "executed": "actor", "same-process": "actor"}


def _pid(v: str) -> str:
    """'13,192' -> '13192'. A log's thousands separator is not part of a PID; anything that is not a
    number after that is not one."""
    s = re.sub(r"[,\s_]", "", v or "")
    return s if s.isdigit() and s != "0" else ""


def _typed_ip(v: str) -> bool:
    return bool(_IPV4.match(v)) and all(int(x) < 256 for x in v.split(".")) and v not in (
        "0.0.0.0", "127.0.0.1", "255.255.255.255")


def _norm_path(v: str) -> str:
    return (v or "").strip().strip('"').replace("/", "\\").lower()


class _Facts:
    """What ONE event says about the things it could be tied to. Read once, compared many times."""

    __slots__ = ("host", "pid", "exe", "name", "shown", "ppid", "pexe", "pname", "is_start", "domains", "ips",
                 "resolved", "files", "hashes", "session", "user", "target")

    def __init__(self, e: Any, action: dict[str, str]):
        f = _F(e.fields)
        self.host = _real(e.host).lower() or f.get("host.name", "hostname", "Computer", "host").lower()
        self.pid = _pid(f.get(*_PID_KEYS))
        self.exe = _norm_path(f.get(*_EXE_KEYS))
        self.shown = f.get("process.name") or _base(f.get(*_EXE_KEYS))
        self.name = self.shown.lower()
        self.ppid = _pid(f.get(*_PPID_KEYS))
        self.pexe = _norm_path(f.get(*_PEXE_KEYS))
        self.pname = (f.get(*_PNAME_KEYS) or _base(self.pexe)).lower()
        self.is_start = action.get("kind") == "process"
        self.target = (action.get("object") or "").lower() if action.get("kind") == "injection" else ""
        doms: set[str] = set()
        for k in _DOMAIN_KEYS:
            v = f.get(k)
            if v:
                d = clean_domain(v)
                if d and not _IPV4.match(d):
                    doms.add(d.lower())
        for k in _URL_KEYS:
            v = f.get(k)
            if v:
                m = _URL_HOST.match(v)
                d = clean_domain(m.group(1) if m else v.split("/")[0])
                if d and not _IPV4.match(d):
                    doms.add(d.lower())
        api = _api_call(f.get("process.Ext.api.summary"))
        if api and api[1] and _URL_HOST.match(api[1][0]):
            d = clean_domain(_URL_HOST.match(api[1][0]).group(1))
            if d and not _IPV4.match(d):
                doms.add(d.lower())
        if action.get("kind") in ("web", "dns", "download"):
            d = clean_domain(action.get("object") or "")
            if d and not _IPV4.match(d):
                doms.add(d.lower())
        self.domains = doms
        # A FIELD named dst_ip says what its value is: `plausible_ip` is the version-string guard for
        # untyped text and would drop a real 203.0.113.9 for its zero octet.
        self.ips = {v for k in _DST_IP_KEYS if (v := f.get(k)) and _typed_ip(v)}
        self.resolved = {ip for k in _RESOLVED_KEYS if (v := f.get(k)) for ip in _IP_ANY.findall(v) if _typed_ip(ip)}
        self.files = {_norm_path(v) for k in _FILE_KEYS if (v := f.get(k))}
        self.hashes = {v.lower() for k in _HASH_KEYS if (v := f.get(k)) and re.fullmatch(r"[0-9a-fA-F]{32,128}", v)}
        sess = f.get(*_SESSION_KEYS)
        self.session = sess.lower() if sess and sess not in ("0x0", "0x3e7", "0x3e4", "0x3e5") else ""
        self.user = _real(e.user).lower()
        if not e.fields:
            # A RAW line (its source not interpreted yet) still honestly carries its addresses and
            # hashes; it cannot say which process did anything, so no process rule applies to it.
            for v, role in _raw_candidates(e):
                (self.ips if role == "ip" else self.hashes).add(v.lower())

    def proc_key(self) -> str:
        """The process this event belongs to: host + PID, with the image as a guard against PID reuse."""
        if self.pid:
            return f"{self.host}|pid:{self.pid}|{self.name}"
        return f"{self.host}|exe:{self.exe}" if self.exe else ""


def relations(rows: list[tuple[str, Any, dict[str, str]]]) -> list[dict[str, Any]]:
    """Links between the timeline's events. `rows` is (eventId, event, action) in PLAY order.

    Returns `{a, b, rel, kind, rank, label, detail}` with `a` earlier than `b`, one per pair (the most
    specific reason wins). Nothing is inferred: every rule compares a value present on both events.
    """
    facts = [_Facts(e, act) for _, e, act in rows]
    last_proc: dict[str, int] = {}          # proc_key -> latest event of that process
    by_pid: dict[str, list[int]] = {}       # host|pid -> events of processes with that pid
    by_exe: dict[str, list[int]] = {}       # host|exe path -> events
    by_name: dict[str, list[int]] = {}      # host|image name -> events
    last_val: dict[str, int] = {}           # "domain:x" / "file:x" / ... -> latest carrier
    written: dict[str, int] = {}            # file path -> the event that produced it
    best: dict[tuple[int, int], dict[str, Any]] = {}

    def link(a: int, b: int, rel: str, label: str, detail: str) -> None:
        if a >= b:
            return
        cur = best.get((a, b))
        if cur is None or REL_RANK[rel] < cur["rank"]:
            best[(a, b)] = {"a": rows[a][0], "b": rows[b][0], "rel": rel, "kind": REL_KIND.get(rel, "shared"),
                            "rank": REL_RANK[rel], "label": label, "detail": detail}

    def latest(lst: Optional[list[int]], ok=lambda j: True) -> Optional[int]:
        for j in reversed(lst or []):
            if ok(j):
                return j
        return None

    for i, fx in enumerate(facts):
        act = rows[i][2]
        what = act.get("object") or act.get("verb") or "it"
        # 1. The PARENT process: a process start whose parent PID (or, with no PID, parent image) is
        #    the process of an earlier event on the same host.
        if fx.is_start and (fx.ppid or fx.pexe or fx.pname):
            j = None
            how = ""
            if fx.ppid:
                j = latest(by_pid.get(f"{fx.host}|{fx.ppid}"),
                           lambda k: not (fx.pname and facts[k].name and facts[k].name != fx.pname))
                how = f"parent PID {fx.ppid}"
            if j is None and fx.pexe and not fx.ppid:
                j = latest(by_exe.get(f"{fx.host}|{fx.pexe}"))
                how = "parent image path"
            if j is None and not fx.ppid and not fx.pexe and fx.pname:
                j = latest(by_name.get(f"{fx.host}|{fx.pname}"))
                how = "parent image name"
            if j is not None:
                parent = facts[j].shown or "the parent"
                link(j, i, "spawned", "spawned", f"{parent} spawned {fx.shown or what} (matched on {how})")
        # 2. A file an earlier event wrote or downloaded, now run as this process's image.
        if fx.is_start and fx.exe and fx.exe in written:
            link(written[fx.exe], i, "executed", "ran file", f"the file {_base(fx.exe)} written earlier was executed")
        # 3. The same process again: its own later activity (and a repeated start record of it).
        pk = fx.proc_key()
        if pk and pk in last_proc:
            j = last_proc[pk]
            link(j, i, "same-process", "same process",
                 f"both by {fx.shown or 'the same process'}" + (f" (PID {fx.pid})" if fx.pid else ""))
        # 4. This event acts ON an earlier process (an APC queued into it, memory written to it).
        if fx.target:
            j = latest(by_name.get(f"{fx.host}|{fx.target}"))
            if j is not None:
                link(j, i, "injected", "injected into",
                     f"{fx.shown or 'a process'} acted on {facts[j].shown or fx.target}: {act.get('verb', '')}")
        # 5. Values both carry: hash, file, what a lookup resolved to, domain, logon session, address.
        vals: list[tuple[str, str, str]] = []
        vals += [("hash", f"hash:{h}", h) for h in fx.hashes]
        vals += [("file", f"file:{p}", p) for p in fx.files]
        vals += [("domain", f"domain:{d}", d) for d in fx.domains]
        if fx.session:
            vals.append(("session", f"session:{fx.host}|{fx.session}", fx.session))
        vals += [("address", f"ip:{ip}", ip) for ip in fx.ips]
        for rel, key, shown in vals:
            j = last_val.get(key)
            if j is not None:
                noun = {"hash": "hash", "file": "file", "domain": "domain", "session": "logon session",
                        "address": "address"}[rel]
                link(j, i, rel, f"same {noun}", f"both involve {noun} {_base(shown) if rel == 'file' else shown}")
        # ...and a connection to an address an earlier lookup resolved.
        for ip in fx.ips:
            j = last_val.get(f"resolved:{ip}")
            if j is not None:
                link(j, i, "resolved", "resolved to", f"{ip} was the answer to an earlier DNS lookup")
        # record this event as the latest carrier of everything it holds
        for _, key, _ in vals:
            last_val[key] = i
        for ip in fx.resolved:
            last_val[f"resolved:{ip}"] = i
        if act.get("kind") in ("file", "download") and fx.files:
            for p in fx.files:
                written[p] = i
        if pk:
            last_proc[pk] = i
        if fx.pid:
            by_pid.setdefault(f"{fx.host}|{fx.pid}", []).append(i)
        if fx.exe:
            by_exe.setdefault(f"{fx.host}|{fx.exe}", []).append(i)
        if fx.name:
            by_name.setdefault(f"{fx.host}|{fx.name}", []).append(i)
    return sorted(best.values(), key=lambda r: (r["rank"], r["a"], r["b"]))


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
    api = _api_call(f.get("process.Ext.api.summary"))
    if api and api[1] and _URL_HOST.match(api[1][0]):
        # the server a process's own HTTP call named: the value its proxy and DNS rows carry too
        put(_URL_HOST.match(api[1][0]).group(1), "domain")
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


# ───────────────────────── what a RAW line can give ─────────────────────────
# After a restart a source is re-read RAW until phase 2 runs: no fields, no entities. That was why the
# replay's map drew no links after a restart ("the connected lines are not drawing") - every link is
# built from an event's actor or entities, and a raw event had neither. A raw line still honestly
# carries the addresses and hashes written in it, so those are read here (word-bounded, the same guard
# `_candidates` uses against version strings). What it cannot give is WHICH PROCESS did something:
# that needs the parser, and the response says so rather than drawing nothing in silence.
_RAW_IP = re.compile(r"(?<![\w.\-])((?:\d{1,3}\.){3}\d{1,3})(?![\w\-]|\.\w)")
_RAW_SHA = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{64})(?![0-9a-fA-F])")


def _raw_candidates(e: Any) -> list[tuple[str, str]]:
    text = (e.raw or "")[:4000]
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for rx, role in ((_RAW_IP, "ip"), (_RAW_SHA, "hash")):
        for v in rx.findall(text):
            if v.lower() in seen or (role == "ip" and (not plausible_ip(v) or v in ("0.0.0.0", "127.0.0.1"))):
                continue
            seen.add(v.lower())
            out.append((v, role))
    return out


def _interpreted(e: Any) -> bool:
    """Has this event's source been through phase 2? A raw event has no fields to read an action,
    an actor or a typed value from."""
    src = STORE.sources.get(getattr(e, "sourceId", "") or "")
    if src is not None:
        return getattr(src, "enrich", "enriched") == "enriched"
    return bool(e.fields or e.entities)


def build(entries: list[Any]) -> dict[str, Any]:
    order = {en.eventId: i for i, en in enumerate(entries)}
    events = [(en, STORE.event(en.eventId)) for en in entries]
    missing = sum(1 for _, e in events if e is None)
    stamped = [(en, e) for en, e in events if e is not None and e.ts]
    # ONE order, the screen's: the exact instant (milliseconds recovered from the line), then the
    # timeline's own order. Sorting on the whole-second `ts` put two events of one second in curation
    # order, so "first seen" could land on the one that happened 800 ms LATER.
    instants = {en.eventId: precise_ms(e)[0] or 0 for en, e in stamped}
    stamped.sort(key=lambda p: (instants[p[0].eventId], order[p[0].eventId]))
    srcs = sorted({e.sourceId for _, e in stamped if getattr(e, "sourceId", "")})
    enrich_state = tuple((s, getattr(STORE.sources.get(s), "enrich", "")) for s in srcs)
    key = (STORE.version, STORE.case_set_rev, tuple(en.eventId for en, _ in stamped),
           tuple(len(en.note or "") for en, _ in stamped), enrich_state, missing,
           bool(getattr(STORE, "pool_loading", False)))
    with _cache_lock:
        hit = _cache.get(key)
    if hit is not None:
        return hit

    first_cache: dict[str, Optional[dict[str, Any]]] = {}
    checked = 0
    reported: set[str] = set()     # a value's "already active earlier" is said once, on its first timeline event
    out_events: list[dict[str, Any]] = []
    raw_events = 0
    awaiting = 0            # raw events whose source is being interpreted right now
    actions = {en.eventId: action_of(e, en.note or "") for en, e in stamped}
    links = relations([(en.eventId, e, actions[en.eventId]) for en, e in stamped])
    for en, e in stamped:
        t_ms, precision = precise_ms(e)
        beats = action_beats(e)
        interpreted = _interpreted(e)
        if not interpreted:
            raw_events += 1
            if getattr(STORE.sources.get(e.sourceId), "enrich", "") in ("queued", "enriching"):
                awaiting += 1
        cands = _candidates(e)
        if not interpreted:
            have = {v.lower() for v, _ in cands}
            cands += [(v, r) for v, r in _raw_candidates(e) if v.lower() not in have]
        firsts: list[dict[str, Any]] = []
        for value, role in cands:
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
        out_events.append({"eventId": en.eventId, "tMs": t_ms, "precision": precision, "beats": beats,
                           "action": actions[en.eventId], "interpreted": interpreted,
                           # EVERY value the event carries, not only the ones a beat reported: the map
                           # links events that share a file, process, hash, domain or address, and a
                           # value is reported as a beat only on the first event that carries it.
                           "entities": [{"role": r, "value": v} for v, r in cands]})

    pool_loading = bool(getattr(STORE, "pool_loading", False))
    # `complete` is the screen's cue to ASK AGAIN: while the pool is still loading, an entry's event is
    # not in it yet, or a source is still raw, the answer will change - and the old screen fetched once
    # and kept the links-less answer for good.
    result = {"events": out_events, "links": links, "valuesChecked": checked, "version": STORE.version,
              "missing": missing, "rawEvents": raw_events, "awaiting": awaiting, "poolLoading": pool_loading,
              "complete": not (pool_loading or missing or raw_events),
              "valuesCapped": checked >= MAX_VALUES,
              "note": ("First sightings are checked against every loaded log: exactly for interpreted "
                       "sources, and by a confirmed word match in raw ones. A value that could not be "
                       "confirmed makes no claim.")}
    with _cache_lock:
        if len(_cache) > 16:
            _cache.clear()
        _cache[key] = result
    return result
