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

3. **What ties the events together** (`relations`, and the `story` line on each event): the map
   draws every event and links each to the event that most plausibly CAUSED it — the parent process,
   the file it ran, the connection that preceded a logon on the host it reached, the logon session a
   command ran in. An event nothing ties to is reported as a THREAD START with the reason, never
   left silently unlinked. Authored links (`Store.event_links`, what the analyst or the assistant
   CONCLUDED) ride along and take precedence over an inferred one for the same pair.

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
# Windows logon types, for the verb of a 4624/4625: "RDP logon" says far more than "logon".
_LOGON_TYPES = {"2": "interactive", "3": "network", "4": "batch", "5": "service", "7": "unlock",
                "8": "network cleartext", "9": "runas", "10": "RDP", "11": "cached"}


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


def _eid_of(f: _F) -> tuple[str, str]:
    eid = f.get("EventID", "event.code", "EventCode", "winlog.event_id", "event_id")
    channel = (f.get("Channel", "winlog.channel", "LogName", "provider", "winlog.provider_name") or "").lower()
    return eid, channel


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

    proc = f.get("process.name") or _base(f.get("process.executable", "Image", "SourceImage", "NewProcessName"))
    parent = f.get("process.parent.name") or _base(f.get("process.parent.executable", "ParentImage",
                                                           "ParentProcessName"))

    def out(kind: str, verb: str, obj: str) -> dict[str, str]:
        obj = (obj or "").strip()[:300]
        actor = parent if kind == "process" else (proc if proc and proc.lower() != obj.lower() else "")
        actor = _not_ua(actor)
        return {"kind": kind, "verb": verb, "object": obj, "actor": actor or ""}

    # A deletion is a deletion whatever produced it — the one action most worth never missing.
    target = f.get("file.path", "TargetFilename", "file.name", "Path", "ObjectName", "path", "filename",
                   "registry.path", "TargetObject")
    if (act and _DELETE_RE.search(act)) or (not act and _DELETE_RE.search(e.msg or "") and target):
        what = "registry" if ("registry" in ds or f.get("registry.path") or f.get("TargetObject")) else "file"
        return out("delete", f"{what} deleted", _base(target) or target or (e.msg or "")[:80])

    # Windows event ids (Security / System / Sysmon)
    eid, channel = _eid_of(f)
    if eid:
        who = f.get("TargetUserName", "SubjectUserName", "user.name") or _real(e.user)
        if "sysmon" in channel:
            sysmon = {"1": ("process", "process started", _base(f.get("Image", "process.executable"))),
                      "3": ("network", "connection", f.get("DestinationIp", "DestinationHostname")),
                      "7": ("library", "DLL loaded", _base(f.get("ImageLoaded"))),
                      "8": ("injection", "remote thread into", _base(f.get("TargetImage"))),
                      "10": ("injection", "process memory read", _base(f.get("TargetImage"))),
                      "11": ("file", "file created", _base(f.get("TargetFilename"))),
                      "12": ("registry", "registry key changed", _base(f.get("TargetObject"))),
                      "13": ("registry", "registry value set", _base(f.get("TargetObject"))),
                      "15": ("file", "file stream created", _base(f.get("TargetFilename"))),
                      "17": ("api", "named pipe created", f.get("PipeName")),
                      "18": ("api", "named pipe connected", f.get("PipeName")),
                      "22": ("dns", "DNS lookup", f.get("QueryName")),
                      "23": ("delete", "file deleted", _base(f.get("TargetFilename"))),
                      "26": ("delete", "file deleted", _base(f.get("TargetFilename")))}.get(eid)
            if sysmon and sysmon[2]:
                return out(*sysmon)
        lt = _LOGON_TYPES.get(f.get("LogonType"), "")
        logon = f"{lt} logon" if lt else "logon"
        win = {"4624": ("access", logon, who), "4625": ("auth-fail", f"failed {logon}", who),
               "4634": ("access", "logoff", who), "4647": ("access", "logoff", who),
               "4648": ("access", "explicit-credential logon", who), "4672": ("privilege", "special privileges", who),
               "4688": ("process", "process created", _base(f.get("NewProcessName", "process.executable"))),
               "4697": ("persistence", "service installed", f.get("ServiceName")),
               "7045": ("persistence", "service installed", f.get("ServiceName")),
               "4698": ("persistence", "scheduled task created", f.get("TaskName")),
               "4702": ("persistence", "scheduled task updated", f.get("TaskName")),
               "4699": ("delete", "scheduled task deleted", f.get("TaskName")),
               "4720": ("account", "account created", who), "4726": ("delete", "account deleted", who),
               "4722": ("account", "account enabled", who), "4724": ("account", "password reset", who),
               "4738": ("account", "account changed", who), "4740": ("account", "account locked out", who),
               "4732": ("privilege", "added to group", who), "4728": ("privilege", "added to group", who),
               "4756": ("privilege", "added to group", who),
               "4768": ("access", "Kerberos TGT requested", who), "4769": ("access", "Kerberos service ticket", f.get("ServiceName") or who),
               "4776": ("access", "NTLM authentication", who), "4771": ("auth-fail", "Kerberos pre-auth failed", who),
               "5140": ("share", "share accessed", f.get("ShareName")), "5145": ("share", "share accessed", f.get("ShareName")),
               "4663": ("file", "object accessed", _base(f.get("ObjectName"))), "4656": ("file", "handle requested", _base(f.get("ObjectName"))),
               "4657": ("registry", "registry value modified", _base(f.get("ObjectName"))),
               "4719": ("anti-forensics", "audit policy changed", channel or "Security"),
               "1102": ("anti-forensics", "audit log cleared", channel or "Security"),
               "104": ("anti-forensics", "event log cleared", channel or "log"),
               "4104": ("execution", "PowerShell script block", f.get("Path") or "script"),
               "4103": ("execution", "PowerShell command", f.get("Payload", "CommandName") or "command")}.get(eid)
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

    # Mail (parsers/eml): the message is the object, the sender the actor.
    if f.get("subject") and (f.get("from") or f.get("email")):
        return {"kind": "mail", "verb": "mail from " + (f.get("from") or f.get("email"))[:60], "object": f.get("subject")[:120],
                "actor": ""}

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
    # A web SERVER's access log (nginx): the request line is the action, its path the object.
    hp = f.get("http.path", "path", "cs-uri-stem", "uri", "request_path")
    if hp and f.get("http.method", "method", "cs-method", "http.status", "status"):
        method = (f.get("http.method", "method", "cs-method") or "HTTP").upper()
        status = f.get("http.status", "status")
        return out("web", f"{method} request" + (f" → {status}" if status else ""), hp[:120])
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
    m = _SESSION.search(msg)
    if m:
        return out("access", "session opened", m.group(1))
    m = _SUDO.search(msg)
    if m:
        return out("privilege", "sudo", m.group(1))
    # Kubernetes audit: verb + resource, on the named object.
    if f.get("verb") and f.get("resource"):
        who = _real(e.user) or f.get("user")
        return {"kind": "cloud", "verb": f"k8s {f.get('verb')} {f.get('resource')}", "object": f.get("pod", "name") or f.get("namespace") or who,
                "actor": ""}
    if f.get("eventName"):
        obj = f.get("requestParameters.bucketName", "requestParameters.roleArn", "requestParameters.userName",
                    "requestParameters.instanceId", "requestParameters.functionName") or _real(e.user) or f.get("userIdentity.arn")
        return out("cloud", _verb(f.get("eventName"), "API call"), obj)

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
#
# THE CAUSAL PREFERENCE. "Make sure it's clear on the story of what has happened": an event should
# link to the event that most plausibly CAUSED it, and the rules are ordered so that it does —
#   spawned      the parent process (PID, else parent image) is an earlier event's process
#   executed     a file an earlier event wrote or downloaded is this process's image, the command in
#                its command line, a service's image path or a scheduled task's command
#   same-process the same process again (host + PID + image)
#   injected     this event acts ON an earlier process (memory read, APC, remote thread)
#   lateral      a logon / share access on host B from host A, tied to A's connection to B (or to
#                the latest activity on A) — the one link a lateral move NEEDS, and the one nothing
#                else could draw: the two events share no process, file or hash, only a hop
#   in-session   a command, privilege or persistence in the logon session an earlier logon opened
#   hash, file, filename, resolved, domain, session, account-move, address — shared VALUES
# and a fallback (a same-user-on-same-host tie, an account moving hosts) is only drawn when nothing
# else linked the event, because those are the ties that make a hairball when drawn everywhere.

_PID_KEYS = ("process.pid", "ProcessId", "pid", "process_id", "ProcessID")
_PPID_KEYS = ("process.parent.pid", "ParentProcessId", "ppid", "parent_pid", "ParentProcessID")
_EXE_KEYS = ("process.executable", "Image", "NewProcessName", "process.path", "exe", "SourceImage")
_PEXE_KEYS = ("process.parent.executable", "ParentImage", "ParentProcessName", "process.parent.path")
_PNAME_KEYS = ("process.parent.name", "ParentName")
_SESSION_KEYS = ("TargetLogonId", "SubjectLogonId", "LogonId", "logon_id", "session.id", "session_id",
                 "process.Ext.authentication_id", "user.session_id", "userIdentity.accessKeyId", "accessKeyId")
_RESOLVED_KEYS = ("dns.resolved_ip", "dns.answers.data", "answer", "answers", "QueryResults",
                  "resolved_ip", "dns.answer")
_FILE_KEYS = ("file.path", "TargetFilename", "file.name", "download_file_name", "dll.path", "ImageLoaded",
              "ObjectName")
_HASH_KEYS = ("process.hash.sha256", "file.hash.sha256", "hash.sha256", "sha256", "dll.hash.sha256",
              "process.hash.md5", "file.hash.md5", "md5", "Hashes")
_DOMAIN_KEYS = ("domain", "url.domain", "destination.domain", "dns.question.name", "QueryName", "query",
                "qname", "dns_query", "cs-host", "http.host", "host_header", "DestinationHostname")
_URL_KEYS = ("url", "url.full", "cs-uri", "request_url", "url.original")
_DST_IP_KEYS = ("dst_ip", "destination.ip", "dest_ip", "DestinationIp", "dstip")
# The REMOTE end of a logon / share access / inbound request: where it came FROM.
_SRC_IP_KEYS = ("IpAddress", "source.ip", "src_ip", "SourceIp", "ClientAddress", "client_ip", "c-ip", "srcip",
                "sourceIPAddress")
_RUNS_KEYS = ("CommandLine", "process.command_line", "ImagePath", "ServiceFileName", "TaskContent", "Details",
              "process.args")
_IP_ANY = re.compile(r"(?<![\w.\-])((?:\d{1,3}\.){3}\d{1,3})(?![\w\-]|\.\w)")
_WIN_PATH = re.compile(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n\s]+?\.(?:exe|dll|ps1|psm1|bat|cmd|vbs|vbe|js|jse|hta|scr|msi|py|jar|wsf|lnk|dmp|conf|dat|bin|docm|docx|doc|xlsm|xlsx|xls|pptx|pdf|rtf|zip|7z|rar|iso|img|one)\b", re.I)
_UNIX_PATH = re.compile(r"(?<![\w.])(/(?:usr|bin|sbin|tmp|var|etc|home|opt|dev|root|srv|mnt)/[\w./+-]*[\w+-])")
_HASH_TOKEN = re.compile(r"(?:^|[=:,;\s])([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})(?![0-9a-fA-F])")
_SHARE_KINDS = frozenset({"access", "auth-fail", "share"})
_INBOUND_KINDS = frozenset({"access", "auth-fail", "share"})

# (rule, kind, rank) — rank orders "most specific"; kind decides how the map draws it:
# 'actor' = causation (a process did it, a hop reached it), 'shared' = the two touched the same thing.
REL_RANK = {"spawned": 0, "executed": 1, "same-process": 2, "injected": 3, "lateral": 4, "in-session": 5,
            "hash": 6, "file": 7, "filename": 8, "resolved": 9, "domain": 10, "session": 11,
            "account-move": 12, "address": 13, "same-user": 14}
REL_KIND = {"spawned": "actor", "executed": "actor", "same-process": "actor", "lateral": "actor", "in-session": "actor"}
# A link the ANALYST or the assistant drew (Store.event_links): it outranks every inferred one.
AUTHORED_RANK = -1


def _pid(v: str) -> str:
    """'13,192' -> '13192', '0x1a2c' -> '6716'. A log's thousands separator is not part of a PID, and
    the Windows Security log writes PIDs in HEX (4688's NewProcessId / ProcessId), while Sysmon writes
    the same process in decimal — without this the two never met. Anything else is not a PID."""
    s = re.sub(r"[,\s_]", "", v or "")
    if s.lower().startswith("0x"):
        try:
            n = int(s, 16)
        except ValueError:
            return ""
        return str(n) if n else ""
    return s if s.isdigit() and s != "0" else ""


def _typed_ip(v: str) -> bool:
    return bool(_IPV4.match(v)) and all(int(x) < 256 for x in v.split(".")) and v not in (
        "0.0.0.0", "127.0.0.1", "255.255.255.255")


def _clean_ip(v: str) -> str:
    """'::ffff:10.0.0.5' -> '10.0.0.5'; anything that is not a usable IPv4 -> ''."""
    s = (v or "").strip()
    if s.lower().startswith("::ffff:"):
        s = s[7:]
    return s if _typed_ip(s) else ""


def _norm_path(v: str) -> str:
    return (v or "").strip().strip('"').replace("/", "\\").lower()


class _Facts:
    """What ONE event says about the things it could be tied to. Read once, compared many times."""

    __slots__ = ("host", "pid", "exe", "name", "shown", "ppid", "pexe", "pname", "pshown", "is_start", "domains", "ips",
                 "resolved", "files", "fnames", "runs", "hashes", "session", "user", "target", "kind", "src_ip",
                 "wsname", "dst_host", "self_ip", "port", "logon_type", "eid", "has_fields", "dst")

    def __init__(self, e: Any, action: dict[str, str]):
        f = _F(e.fields)
        self.kind = action.get("kind") or "event"
        self.has_fields = bool(e.fields)
        self.host = _real(e.host).lower() or f.get("host.name", "hostname", "Computer", "host").lower()
        self.eid, channel = _eid_of(f)
        self.pid = _pid(f.get(*_PID_KEYS))
        self.exe = _norm_path(f.get(*_EXE_KEYS))
        self.shown = f.get("process.name") or _base(f.get(*_EXE_KEYS))
        self.ppid = _pid(f.get(*_PPID_KEYS))
        self.pexe = _norm_path(f.get(*_PEXE_KEYS))
        if self.eid == "4688" and "sysmon" not in channel:
            # Security 4688: `NewProcessId` is the child, `ProcessId` is the CREATOR. Sysmon's own event 1
            # uses ProcessId/ParentProcessId, so the generic keys above read 4688 backwards.
            self.pid = _pid(f.get("NewProcessId")) or ""
            self.ppid = _pid(f.get("ProcessId", "ParentProcessId"))
        self.pname = (f.get(*_PNAME_KEYS) or _base(self.pexe)).lower()
        self.pshown = f.get(*_PNAME_KEYS) or _base(f.get(*_PEXE_KEYS))
        self.name = self.shown.lower()
        self.is_start = self.kind == "process"
        self.target = (action.get("object") or "").lower() if self.kind == "injection" else ""
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
        if self.kind in ("web", "dns", "download"):
            d = clean_domain(action.get("object") or "")
            if d and not _IPV4.match(d):
                doms.add(d.lower())
        self.domains = doms
        # A FIELD named dst_ip says what its value is: `plausible_ip` is the version-string guard for
        # untyped text and would drop a real 203.0.113.9 for its zero octet.
        self.ips = {ip for k in _DST_IP_KEYS if (ip := _clean_ip(f.get(k)))}
        self.dst = next(iter(sorted(self.ips)), "")
        self.port = f.get("DestinationPort", "destination.port", "dst_port", "dest_port")
        self.dst_host = (f.get("DestinationHostname", "destination.domain") or "").lower().split(".")[0]
        self.resolved = {ip for k in _RESOLVED_KEYS if (v := f.get(k)) for ip in _IP_ANY.findall(v) if _typed_ip(ip)}
        # Where an inbound event came FROM (a logon's IpAddress, an SSH daemon's "from"), and this
        # host's OWN address (an outbound connection's SourceIp) — the two halves of a lateral move.
        self.src_ip = ""
        self.self_ip = ""
        if self.kind in _INBOUND_KINDS or self.kind in ("cloud", "web", "download"):
            self.src_ip = _clean_ip(f.get(*_SRC_IP_KEYS))
        elif self.kind == "network":
            self.self_ip = _clean_ip(f.get("SourceIp", "source.ip", "src_ip"))
        self.wsname = (f.get("WorkstationName", "source.domain") or "").lower().split(".")[0]
        self.logon_type = _LOGON_TYPES.get(f.get("LogonType"), "")
        self.files = {p for k in _FILE_KEYS if (p := _norm_path(f.get(k)))}
        # What this event RUNS or points at: the image of a process start, the paths in its command
        # line, a service's image path, a scheduled task's <Command>, a Run key's data.
        runs: set[str] = set()
        if self.is_start and self.exe:
            runs.add(self.exe)
        for k in _RUNS_KEYS:
            v = f.get(k)
            if v:
                runs.update(_norm_path(p) for p in _WIN_PATH.findall(v))
        self.runs = runs
        self.hashes = {v.lower() for k in _HASH_KEYS if (v := f.get(k)) and re.fullmatch(r"[0-9a-fA-F]{32,128}", v)}
        hs = f.get("Hashes")
        if hs:
            # Sysmon: `SHA256=…,MD5=…` — the hashes are inside the value.
            self.hashes.update(h.lower() for h in _HASH_TOKEN.findall(hs))
        sess = f.get(*_SESSION_KEYS)
        self.session = sess.lower() if sess and sess.lower() not in ("0x0", "0x3e7", "0x3e4", "0x3e5") else ""
        self.user = _real(e.user).lower()
        msg = e.msg or e.raw or ""
        m = _SSH_OK.search(msg) or _SSH_FAIL.search(msg)
        if m and not self.src_ip:
            self.src_ip = _clean_ip(m.group(m.lastindex or 1))
            if not self.user:
                self.user = (m.group(2) if m.re is _SSH_OK else m.group(1)).lower()
        m = _SUDO.search(msg)
        if m:
            # The unix paths in the command: the file curl wrote, chmod touched and the shell then ran.
            self.files.update(_norm_path(p) for p in _UNIX_PATH.findall(m.group(2)))
            self.runs.update(_norm_path(p) for p in _UNIX_PATH.findall(m.group(2).split()[0] if m.group(2).split() else ""))
            if not self.user:
                self.user = m.group(1).lower()
        if e.entities and self.has_fields:
            # An address the extractor found in an INTERPRETED line (a sudo command's URL) is an address
            # the event carries; word-bounded, so a version string never becomes one. The event's OWN
            # source address is not: every event of a host carries it, and linking on it is a hairball.
            own = {_clean_ip(f.get(k)) for k in ("SourceIp", "source.ip", "src_ip", "IpAddress", "client_ip", "c-ip", "srcip")}
            text = " ".join([e.raw or "", *f.m.values()])
            for ent in e.entities:
                s = str(ent)
                if s in own or not (_IPV4.match(s) and _typed_ip(s)):
                    continue
                if re.search(r"(?<![\w.\-])" + re.escape(s) + r"(?![\w\-]|\.\w)", text):
                    self.ips.add(s)
        if not e.fields:
            # A RAW line (its source not interpreted yet) still honestly carries its addresses and
            # hashes; it cannot say which process did anything, so no process rule applies to it.
            for v, role in _raw_candidates(e):
                (self.ips if role == "ip" else self.hashes).add(v.lower())
        self.fnames = {_base(p) for p in self.files | self.runs if _base(p)}

    def proc_key(self) -> str:
        """The process this event belongs to: host + PID, with the image as a guard against PID reuse."""
        if self.pid:
            return f"{self.host}|pid:{self.pid}|{self.name}"
        return f"{self.host}|exe:{self.exe}" if self.exe else ""


def facts_of(rows: list[tuple[str, Any, dict[str, str]]]) -> list["_Facts"]:
    return [_Facts(e, act) for _, e, act in rows]


def relations(rows: list[tuple[str, Any, dict[str, str]]], facts: Optional[list["_Facts"]] = None) -> list[dict[str, Any]]:
    """Links between the timeline's events. `rows` is (eventId, event, action) in PLAY order.

    Returns `{a, b, rel, kind, rank, label, detail}` with `a` earlier than `b`, one per pair (the most
    specific reason wins). Nothing is inferred: every rule compares a value present on both events.
    """
    facts = facts if facts is not None else facts_of(rows)
    last_proc: dict[str, int] = {}          # proc_key -> latest event of that process
    by_pid: dict[str, list[int]] = {}       # host|pid -> events of processes with that pid
    by_exe: dict[str, list[int]] = {}       # host|exe path -> events
    by_name: dict[str, list[int]] = {}      # host|image name -> events
    by_host: dict[str, list[int]] = {}      # host -> its events
    conn_to: dict[str, list[int]] = {}      # destination ip -> the connections made to it
    last_val: dict[str, int] = {}           # "domain:x" / "file:x" / ... -> latest carrier
    written: dict[str, int] = {}            # file path -> the event that produced it
    written_name: dict[str, int] = {}       # file NAME -> the event that produced it (a download names no path)
    host_of_ip: dict[str, str] = {}         # an address -> the host that owns it (learned as the timeline plays)
    ips_of_host: dict[str, set[str]] = {}
    last_access: dict[tuple[str, str], int] = {}    # (host, user) -> the latest logon of that user there
    last_user_host: dict[str, tuple[str, int]] = {}  # user -> (host, event) of the user's latest activity
    session_open: dict[str, int] = {}       # "session:host|id" -> the LOGON that opened it
    host_label: dict[str, str] = {}         # lower-cased host -> the name as the log wrote it
    has_in: set[int] = set()
    has_actor_in: set[int] = set()
    best: dict[tuple[int, int], dict[str, Any]] = {}

    def link(a: int, b: int, rel: str, label: str, detail: str) -> None:
        if a >= b:
            return
        has_in.add(b)
        if REL_KIND.get(rel) == "actor":
            has_actor_in.add(b)
        cur = best.get((a, b))
        if cur is None or REL_RANK[rel] < cur["rank"]:
            best[(a, b)] = {"a": rows[a][0], "b": rows[b][0], "rel": rel, "kind": REL_KIND.get(rel, "shared"),
                            "rank": REL_RANK[rel], "label": label, "detail": detail}

    def latest(lst: Optional[list[int]], ok=lambda j: True) -> Optional[int]:
        for j in reversed(lst or []):
            if ok(j):
                return j
        return None

    def parent_of(lst: Optional[list[int]], ok=lambda j: True) -> Optional[int]:
        """The parent PROCESS's own start when it is on the timeline (that node IS the process), else
        its latest activity — so 'WINWORD.EXE spawned powershell.exe' lands on Word's start, not on
        whatever Word happened to do last."""
        for j in lst or []:
            if ok(j) and facts[j].is_start:
                return j
        return latest(lst, ok)

    def named(fx: "_Facts", act: dict[str, str]) -> str:
        return fx.shown or act.get("object") or act.get("verb") or "it"

    def with_pid(fx: "_Facts") -> str:
        return f"{fx.shown}{f' (pid {fx.pid})' if fx.pid else ''}" if fx.shown else (fx.name or "the process")

    for i, fx in enumerate(facts):
        act = rows[i][2]
        what = act.get("object") or act.get("verb") or "it"
        host_shown = _real(rows[i][1].host) or fx.host
        if fx.host and fx.host not in host_label:
            host_label[fx.host] = host_shown
        if fx.wsname and fx.wsname not in host_label:
            host_label[fx.wsname] = _F(rows[i][1].fields).get("WorkstationName", "source.domain") or fx.wsname
        if fx.dst_host and fx.dst_host not in host_label:
            host_label[fx.dst_host] = (_F(rows[i][1].fields).get("DestinationHostname", "destination.domain") or fx.dst_host).split(".")[0]
        # 1. The PARENT process: a process start whose parent PID (or, with no PID, parent image) is
        #    the process of an earlier event on the same host.
        if fx.is_start and (fx.ppid or fx.pexe or fx.pname):
            j = None
            how = ""
            if fx.ppid:
                j = parent_of(by_pid.get(f"{fx.host}|{fx.ppid}"),
                              lambda k: not (fx.pname and facts[k].name and facts[k].name != fx.pname))
                how = f"parent PID {fx.ppid}"
            if j is None and fx.pexe:
                j = parent_of(by_exe.get(f"{fx.host}|{fx.pexe}"))
                how = "parent image path"
            if j is None and fx.pname:
                # The parent's own start is not on the timeline (or its PID is), but the same image has
                # been seen on this host: the weakest form of the same claim, and said as such.
                j = parent_of(by_name.get(f"{fx.host}|{fx.pname}"))
                how = "parent image name"
            if j is not None:
                link(j, i, "spawned", "spawned",
                     f"{with_pid(facts[j]) if facts[j].shown else fx.pshown or 'the parent'} spawned {with_pid(fx) if fx.shown else what} (matched on {how})")
        # 2. A file an earlier event wrote or downloaded, now run: as this process's image, in its command
        #    line, as a service's image or a scheduled task's command.
        for p in sorted(fx.runs):
            j = written.get(p)
            how = "path"
            if j is None:
                j = written_name.get(_base(p))
                how = "name"
            if j is None or j == i:
                continue
            src = facts[j]
            if src.kind == "download":
                made = "downloaded" + (f" from {next(iter(sorted(src.domains)))}" if src.domains else "")
            else:
                made = f"written by {with_pid(src)}" if src.shown else "written earlier"
            if fx.is_start and p == fx.exe:
                detail = f"{_base(p)}, {made}, is now running{f' as pid {fx.pid}' if fx.pid else ''} (matched on file {how})"
            elif fx.is_start:
                detail = f"{with_pid(fx)} opened {_base(p)}, {made} (matched on file {how})"
            elif fx.kind == "persistence":
                detail = f"{what} runs {_base(p)}, {made} — persistence for it (matched on file {how})"
            elif fx.kind == "registry":
                detail = f"{act.get('verb', 'registry value')} {what} points at {_base(p)}, {made} (matched on file {how})"
            else:
                detail = f"{with_pid(fx) if fx.shown else what} runs {_base(p)}, {made} (matched on file {how})"
            link(j, i, "executed", "ran file", detail)
        # 3. The same process again: its own later activity (and a repeated start record of it).
        pk = fx.proc_key()
        if pk and pk in last_proc:
            j = last_proc[pk]
            link(j, i, "same-process", "same process",
                 f"{with_pid(fx)} again: {act.get('verb', 'activity')}" + (f" {what}" if what and what.lower() != fx.name else ""))
        # 4. This event acts ON an earlier process (an APC queued into it, memory written to it).
        if fx.target:
            j = latest(by_name.get(f"{fx.host}|{fx.target}"))
            if j is not None:
                link(j, i, "injected", "injected into",
                     f"{fx.shown or 'a process'} acted on {facts[j].shown or fx.target}: {act.get('verb', '')}")
        # 5. LATERAL: a logon / share access here from another host, tied to that host's connection
        #    to this one (the RDP / SSH / SMB session that carried it), else to the latest activity there.
        if fx.kind in _INBOUND_KINDS and (fx.src_ip or fx.wsname):
            my_ips = ips_of_host.get(fx.host, set())
            rhost = fx.wsname or host_of_ip.get(fx.src_ip, "")
            j = None
            if rhost and rhost != fx.host:
                j = latest(by_host.get(rhost), lambda k: facts[k].kind == "network" and (
                    facts[k].dst_host == fx.host or bool(facts[k].ips & my_ips)))
                if j is None:
                    j = latest(by_host.get(rhost))
            if j is None:
                # No name for the other end: the connection that reached THIS host's address.
                for ip in my_ips:
                    j = latest(conn_to.get(ip))
                    if j is not None:
                        break
            if j is not None and facts[j].host != fx.host:
                who = fx.user or what
                came = host_label.get(rhost, rhost) if rhost else fx.src_ip
                verb = act.get("verb", "logon")
                if facts[j].kind == "network":
                    detail = (f"{who}: {verb} on {host_shown} from {came}, right after {with_pid(facts[j])} on {came} connected to "
                              f"{next(iter(facts[j].ips), fx.host)}{':' + facts[j].port if facts[j].port else ''}")
                else:
                    detail = f"{who}: {verb} on {host_shown} from {came}, where the previous step ({facts[j].kind}: {rows[j][2].get('object', '')}) happened"
                link(j, i, "lateral", "reached from", detail)
            if fx.wsname and fx.src_ip:
                host_of_ip.setdefault(fx.src_ip, fx.wsname)
                ips_of_host.setdefault(fx.wsname, set()).add(fx.src_ip)
        # 6. Values both carry: hash, file, what a lookup resolved to, domain, logon session, address.
        vals: list[tuple[str, str, str]] = []
        vals += [("hash", f"hash:{h}", h) for h in sorted(fx.hashes)]
        for p in sorted(fx.files):
            if f"file:{p}" in last_val:
                vals.append(("file", f"file:{p}", p))
            elif _base(p) and f"fname:{_base(p)}" in last_val:
                vals.append(("filename", f"fname:{_base(p)}", _base(p)))
        vals += [("domain", f"domain:{d}", d) for d in sorted(fx.domains)]
        if fx.session:
            vals.append(("session", f"session:{fx.host}|{fx.session}", fx.session))
        vals += [("address", f"ip:{ip}", ip) for ip in sorted(fx.ips)]
        for rel, key, shown in vals:
            if rel == "session" and fx.kind != "access" and key in session_open:
                # The logon that OPENED this session is the cause of what ran in it — the LOGON itself,
                # not whichever event of the session happened to come last.
                j = session_open[key]
                link(j, i, "in-session", "in that logon",
                     f"{named(fx, act)} ran in the logon session {facts[j].user or 'the account'} opened on {host_shown} (logon id {shown})")
                continue
            j = last_val.get(key)
            if j is None:
                continue
            noun = {"hash": "hash", "file": "file", "filename": "file name", "domain": "domain", "session": "logon session",
                    "address": "address"}[rel]
            link(j, i, rel, f"same {noun}", f"both involve {noun} {_base(shown) if rel == 'file' else shown}")
        # ...and a connection to an address an earlier lookup resolved.
        for ip in fx.ips:
            j = last_val.get(f"resolved:{ip}")
            if j is not None:
                link(j, i, "resolved", "resolved to", f"{ip} was the answer to an earlier DNS lookup")
        # 7. Fallbacks, ONLY when nothing above tied the event: the logon this user's activity on this
        #    host belongs to (no logon id in the log), and an account turning up on a new host.
        if fx.user and fx.host:
            if i not in has_actor_in and fx.kind not in ("access", "auth-fail"):
                j = last_access.get((fx.host, fx.user))
                if j is not None:
                    link(j, i, "in-session", "in that logon",
                         f"{named(fx, act)} by {fx.user}, who logged on to {host_shown} at the earlier step")
            if i not in has_in and fx.kind == "access":
                prev = last_user_host.get(fx.user)
                if prev and prev[0] != fx.host:
                    link(prev[1], i, "account-move", "same account",
                         f"account {fx.user} was last active on {prev[0]} and now logs on to {host_shown}")
            if i not in has_in:
                # LAST resort, and said as such: the same account's previous activity on this host. Weak,
                # but it keeps the thread of one operator on one machine readable instead of scattering
                # every event whose process start is not on the timeline as a new thread.
                prev = last_user_host.get(fx.user)
                if prev and prev[0] == fx.host:
                    link(prev[1], i, "same-user", "same account here",
                         f"{fx.user}'s previous activity on {host_shown} — nothing more specific ties the two")
        # record this event as the latest carrier of everything it holds
        for rel, key, _ in vals:
            last_val[key] = i
        for p in fx.files:
            last_val[f"file:{p}"] = i
            if _base(p):
                last_val[f"fname:{_base(p)}"] = i
        for h in fx.hashes:
            last_val[f"hash:{h}"] = i
        for d in fx.domains:
            last_val[f"domain:{d}"] = i
        if fx.session:
            last_val[f"session:{fx.host}|{fx.session}"] = i
            if fx.kind == "access":
                session_open.setdefault(f"session:{fx.host}|{fx.session}", i)
        for ip in fx.ips:
            last_val[f"ip:{ip}"] = i
            conn_to.setdefault(ip, []).append(i)
        for ip in fx.resolved:
            last_val[f"resolved:{ip}"] = i
        if fx.kind in ("file", "download") and fx.files:
            for p in fx.files:
                written[p] = i
                if _base(p):
                    written_name[_base(p)] = i
        if pk:
            last_proc[pk] = i
        if fx.pid:
            by_pid.setdefault(f"{fx.host}|{fx.pid}", []).append(i)
        if fx.exe:
            by_exe.setdefault(f"{fx.host}|{fx.exe}", []).append(i)
        if fx.name:
            by_name.setdefault(f"{fx.host}|{fx.name}", []).append(i)
        if fx.host:
            by_host.setdefault(fx.host, []).append(i)
            if fx.self_ip:
                host_of_ip.setdefault(fx.self_ip, fx.host)
                ips_of_host.setdefault(fx.host, set()).add(fx.self_ip)
            if fx.dst_host and fx.ips:
                for ip in fx.ips:
                    host_of_ip.setdefault(ip, fx.dst_host)
                    ips_of_host.setdefault(fx.dst_host, set()).add(ip)
            if fx.kind == "access" and fx.user:
                last_access[(fx.host, fx.user)] = i
            if fx.user:
                last_user_host[fx.user] = (fx.host, i)
    return sorted(best.values(), key=lambda r: (r["rank"], r["a"], r["b"]))


# ───────────────────────── the story: one line per event, actor → verb → object ─────────────────────────

_UA_RE = re.compile(r"^(?:mozilla|opera|curl|wget|python-requests|go-http-client|java|okhttp|dalvik|microsoft-cryptoapi|windows-update-agent)/", re.I)


def _not_ua(s: str) -> str:
    """A user-agent is not an ACTOR. Proxy exports put the UA in a column the parser may map to user or
    process, and the story then read "Mozilla/5.0 (Windows NT 10.0 ...) requested x.fun". Refuse any
    string shaped like one (a product/version token, or long with a parenthesised platform)."""
    s = (s or "").strip()
    if not s:
        return ""
    if _UA_RE.match(s) or (len(s) > 40 and "(" in s and "/" in s):
        return ""
    return s


def story_of(e: Any, act: dict[str, str], fx: "_Facts") -> str:
    """What happened, in plain words, from the fields the classification already read. It is the line
    the stream card and the focused node show, so it names the ACTOR: 'WINWORD.EXE (pid 3320) spawned
    powershell.exe (pid 4412) on WS01', not 'process started: powershell.exe'."""
    kind, verb, obj = act.get("kind", "event"), act.get("verb", ""), act.get("object", "")
    host = _real(e.host)
    user = _not_ua(_real(e.user) or fx.user)
    on = f" on {host}" if host else ""
    shown = _not_ua(fx.shown)
    proc = f"{shown}{f' (pid {fx.pid})' if fx.pid else ''}" if shown else ""
    by = f" by {proc}" if proc and proc.split(" ")[0].lower() != obj.lower() else ""
    f = _F(e.fields)
    src = fx.src_ip or ""
    came = f" from {fx.wsname.upper() if fx.wsname else src}" if (fx.wsname or src) else ""
    if kind == "process":
        parent = f"{fx.pshown}{f' (pid {fx.ppid})' if fx.ppid else ''}" if fx.pshown else ""
        me = proc or obj
        s = f"{parent} spawned {me}" if parent else f"{me} started"
        cmd = f.get("CommandLine", "process.command_line")
        return s + on + (f": {cmd[:90]}" if cmd and len(cmd) > len(obj) + 3 else "")
    if kind in ("file", "delete"):
        return f"{proc or user or 'something'} {verb.replace('file ', '').replace('registry ', 'registry ')}: {obj}{on}"
    if kind == "network":
        dst = fx.dst or obj
        tgt = f"{dst}{':' + fx.port if fx.port else ''}" + (f" ({fx.dst_host})" if fx.dst_host and fx.dst_host != dst else "")
        return f"{proc or user or host or 'a host'} connected to {tgt}{on if proc else ''}"
    if kind == "dns":
        ans = ", ".join(sorted(fx.resolved)[:2])
        return f"{proc or user or host or 'a host'} looked up {obj}" + (f" → {ans}" if ans else "")
    if kind == "download":
        dom = next(iter(sorted(fx.domains)), "")
        who = user or src or host or "a client"
        return f"{who} downloaded {obj}" + (f" from {dom}" if dom else "") + (" (blocked)" if "blocked" in verb else "")
    if kind == "web":
        who = proc or user or src or host or "a client"
        return f"{who} requested {obj}" + (" (blocked)" if "blocked" in verb else "")
    if kind == "library":
        return f"{proc or 'a process'} loaded {obj}{on}"
    if kind == "registry":
        return f"{proc or user or 'something'} {verb}: {obj}{on}"
    if kind == "persistence":
        names = [_base(p) for p in sorted(fx.runs) if _base(p) and _base(p).lower() != obj.lower()]
        run = next((n for n in names if re.search(r"\.(exe|dll|ps1|bat|cmd|vbs|js|hta|scr|msi|py|sh)$", n, re.I)), names[0] if names else "")
        return f"{verb} {obj}{on}" + (f", running {run}" if run else "") + (f" (by {user})" if user else "")
    if kind == "access":
        if verb in ("logoff",):
            return f"{obj or user} logged off{on}"
        to = f" to {host}" if host else ""
        return f"{obj or user} logged on{to}{came}" + (f" ({fx.logon_type})" if fx.logon_type else (" (SSH)" if "SSH" in verb else ""))
    if kind == "auth-fail":
        return f"failed {fx.logon_type + ' ' if fx.logon_type else ''}logon for {obj or user}{on}{came}"
    if kind == "privilege":
        if verb == "sudo":
            m = _SUDO.search(e.msg or e.raw or "")
            return f"{obj or user} ran as root{on}: {m.group(2).strip()[:100] if m else ''}"
        return f"{obj or user} {verb}{on}"
    if kind == "injection":
        return f"{proc or 'a process'} {verb} {obj}{on}"
    if kind == "anti-forensics":
        return f"{user or 'someone'} — {verb} ({obj}){on}"
    if kind == "share":
        return f"{user or 'an account'} accessed share {obj}{on}{came}"
    if kind == "account":
        return f"{verb}: {obj}{on}" + (f" (by {user})" if user and user.lower() != obj.lower() else "")
    if kind == "cloud":
        return f"{user or 'a principal'} — {verb}" + (f" {obj}" if obj and obj != user else "")
    if kind == "mail":
        return f"{verb}: {obj}"
    if kind in ("api", "alert", "execution"):
        return f"{proc or user or host or ''} {verb} {obj}".strip()
    return f"{verb}: {obj}".strip(": ") if obj else (e.msg or e.raw or "")[:120]


def thread_start_reason(i: int, fx: "_Facts", interpreted: bool, hosts_seen: set[str]) -> str:
    if i == 0:
        return "the first event of the timeline"
    if not interpreted:
        return ("its source is not interpreted yet — only the addresses and hashes written in the raw line could be "
                "matched, and none of them appears in an earlier event")
    new_host = fx.host and fx.host not in hosts_seen
    base = "nothing earlier on the timeline shares a process, file, hash, domain, address or logon session with it"
    return base + (f" — the first activity on host {fx.host}" if new_host else "")


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


def _authored_links(order: dict[str, int]) -> list[dict[str, Any]]:
    """The case's AUTHORED event links (Store.event_links) as replay links: `a` is the one that plays
    first, `rank` AUTHORED_RANK so the pair keeps the analyst's reason over an inferred one, and the
    verb is the label. A link whose ends are not both on the (stamped) timeline is left out here —
    the stream card still lists it from the case set — never re-pointed."""
    out: list[dict[str, Any]] = []
    for l in list(getattr(STORE, "event_links", []) or []):
        s, t = str(l.get("source") or ""), str(l.get("target") or "")
        if s not in order or t not in order or s == t:
            continue
        a, b = (s, t) if order[s] <= order[t] else (t, s)
        verb = str(l.get("verb") or "").strip() or ("caused" if l.get("kind") == "causal" else "related")
        why = str(l.get("why") or "").strip()
        detail = f"{verb}: {why}" if why else verb
        if a != s:
            detail += " (the link points back in time: its source plays after its target)"
        out.append({"a": a, "b": b, "rel": "authored", "kind": "authored", "rank": AUTHORED_RANK, "label": verb[:40],
                    "detail": detail, "id": str(l.get("id") or ""), "source": s, "target": t,
                    "linkKind": l.get("kind") or "related", "ai": bool(l.get("ai"))})
    return out


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
    authored_sig = tuple(sorted((str(l.get("id") or ""), str(l.get("verb") or ""), str(l.get("why") or "")[:80])
                                for l in (getattr(STORE, "event_links", []) or [])))
    key = (STORE.version, STORE.case_set_rev, tuple(en.eventId for en, _ in stamped),
           tuple(len(en.note or "") for en, _ in stamped), enrich_state, missing,
           bool(getattr(STORE, "pool_loading", False)), authored_sig)
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
    rows = [(en.eventId, e, actions[en.eventId]) for en, e in stamped]
    facts = facts_of(rows)
    play = {eid: i for i, (eid, _, _) in enumerate(rows)}
    links = _authored_links(play) + relations(rows, facts)
    incoming: dict[str, dict[str, Any]] = {}
    for l in links:                 # sorted most specific first: the first seen per target is its cause
        incoming.setdefault(l["b"], l)
    hosts_seen: set[str] = set()
    for i, (en, e) in enumerate(stamped):
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
        fx = facts[i]
        cause = incoming.get(en.eventId)
        linked = ({"from": cause["a"], "rel": cause["rel"], "kind": cause["kind"], "why": cause["detail"]}
                  if cause else None)
        # An event nothing ties to is SAID to be a thread start, with why - never left silently alone.
        thread_start = "" if cause else thread_start_reason(i, fx, interpreted, hosts_seen)
        if fx.host:
            hosts_seen.add(fx.host)
        out_events.append({"eventId": en.eventId, "tMs": t_ms, "precision": precision, "beats": beats,
                           "action": actions[en.eventId], "interpreted": interpreted,
                           "story": story_of(e, actions[en.eventId], fx)[:200],
                           "linked": linked, "threadStart": thread_start,
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
              "eventLinks": [dict(l) for l in (getattr(STORE, "event_links", []) or [])],
              "threadStarts": sum(1 for x in out_events if x["threadStart"]),
              "note": ("First sightings are checked against every loaded log: exactly for interpreted "
                       "sources, and by a confirmed word match in raw ones. A value that could not be "
                       "confirmed makes no claim.")}
    with _cache_lock:
        if len(_cache) > 16:
            _cache.clear()
        _cache[key] = result
    return result
