"""Entity graph v2: typed nodes joined by typed relations, extracted deterministically per event.

The v1 graph asked one question — "which names appeared in the same event?" — so an IP, a username, a PID
and a file were indistinguishable blobs joined by one meaningless edge. This module asks a different one:
*what happened between which things*. Each event yields relations like `user ←auth_from— ip`,
`user —ran→ process[pid]`, `process —wrote→ file`, `ip —connected_to→ ip:port`, and because nodes are keyed
by (type, value) the same PID or hash in two different log lines becomes one node, chaining events together.

Everything here is deterministic. The AI reviewer (ai/graph_review.py) layers *proposed* links on top —
it never mutates this graph, and its output is flagged so the analyst can tell them apart.
"""
from __future__ import annotations

import os
import re
from array import array
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

import numpy as np

from .derived import AsyncCache, BuildCancelled, DEFAULT_SYNC_LIMIT
from .models import Event, GraphEdge, GraphNode, SEV_ORDER
from .normalize import AKIA_RE, IPV4_RE, IPV6_RE, KEYFP_RE, is_private_ip

# ----------------------------------------------------------------------------- vocab
NODE_TYPES = ("ip", "user", "host", "process", "pid", "file", "hash", "domain", "url", "port", "email", "key",
              "session", "pod", "service", "registry", "other")
RELATIONS = ("auth_from", "connected_to", "ran", "spawned", "wrote", "read", "deleted", "resolved", "requested",
             "used_key", "on_host", "session", "co_occurred")

# Default node cap for a graph request. 50 keeps the canvas legible and the SVG cheap to animate; the UI
# control (GraphScreen "max nodes") starts at the same number and the analyst can raise it to 2000.
# routers/graph.py MUST use this as its `limit` Query default so the two never drift.
DEFAULT_LIMIT = 50

# ------------------------------------------------------------------ field vocabularies
# Which normalized field names carry which entity type. Broad on purpose: sources are mapped by many hands
# (AI mapping, heuristics, vendors), and a field the extractor does not recognise is a relation it cannot draw.
F_SRC_IP = ("src_ip", "src", "sourceIPAddress", "IpAddress", "client_ip", "remote_addr", "source.ip", "client.ip",
            "sourceIPs", "srcip", "source_ip", "clientip", "c_ip", "SourceAddress", "src_addr", "ipAddress")
F_DST_IP = ("dst_ip", "dst", "destination.ip", "server.ip", "dstip", "dest_ip", "destination_ip", "d_ip",
            "DestAddress", "dst_addr", "remote_ip", "target_ip")
F_SRC_PORT = ("src_port", "sport", "source.port", "srcport", "SourcePort", "s_port", "client_port")
F_DST_PORT = ("dst_port", "dport", "destination.port", "dstport", "DestPort", "d_port", "port", "server_port", "target_port")
F_USER = ("user", "user.name", "username", "userName", "TargetUserName", "SubjectUserName", "actor",
          "userIdentity.userName", "userIdentity.arn", "user.username", "principal", "account", "remote_user",
          "uid_name", "acct", "login", "AccountName", "sAMAccountName", "requestor", "identity")
F_HOST = ("host", "hostname", "Computer", "computer", "node", "instance", "WorkstationName", "device", "hostName",
          "agent.hostname", "host.name", "machine", "server", "src_host", "dst_host", "dest_host", "device_name")
F_PROC = ("process", "process.name", "process_name", "program", "ProcessName", "NewProcessName", "Image", "exe",
          "app", "application", "comm", "cmd", "command", "process.command_line", "CommandLine", "commandline",
          "ParentProcessName", "ParentImage", "parent_process", "parent")
F_PID = ("pid", "process.pid", "ProcessId", "NewProcessId", "process_id", "ppid", "ParentProcessId", "parent_pid",
         "process.parent.pid", "SubjectLogonId")
F_FILE = ("file", "file.path", "path", "filename", "file_name", "TargetFilename", "ObjectName", "target_path",
          "dest", "destination", "filepath", "TargetObject", "object", "name", "key")
F_HASH = ("hash", "sha256", "sha1", "md5", "file.hash", "Hashes", "file_hash", "imphash")
F_DOMAIN = ("domain", "query", "dns.question.name", "qname", "hostname_queried", "fqdn", "server_name", "sni", "dns_query")
F_URL = ("url", "uri", "http.path", "path", "request", "http.url", "request_uri", "cs_uri", "target_url", "location")
F_EMAIL = ("email", "mail", "sender", "recipient", "from", "to", "mail_from", "rcpt_to")
F_SESSION = ("session", "session_id", "sessionId", "logon_id", "LogonId", "TargetLogonId", "sid", "SessionId",
             "session.id", "request_id", "requestID", "correlation_id", "trace_id")
F_KEY = ("accessKeyId", "access_key", "key_id", "api_key_id", "AccessKeyId")
F_ACTION = ("action", "eventName", "event", "op", "operation", "verb", "type", "EventID", "event_id", "outcome",
            "result", "status", "http.status", "auth", "level", "method", "http.method", "disposition")
# sub-vocabularies extract() needs separately: a process and its PARENT are different nodes, and only some
# of F_URL carries a real URL. Declared here so they go through the same one-pass field bucketing.
F_PROC_SELF = ("process", "process.name", "process_name", "program", "ProcessName", "NewProcessName", "Image",
               "exe", "app", "application", "comm", "process.command_line", "CommandLine", "commandline")
F_PROC_PARENT = ("ParentProcessName", "ParentImage", "parent_process", "parent")
F_PID_SELF = ("pid", "process.pid", "ProcessId", "NewProcessId", "process_id")
F_PID_PARENT = ("ppid", "ParentProcessId", "parent_pid", "process.parent.pid")
F_URL_ONLY = ("url", "uri", "http.url", "request_uri", "cs_uri", "target_url", "location")
F_POD = ("pod", "objectRef.name", "kubernetes.pod_name", "pod_name")
F_SERVICE = ("svc", "service", "service_name", "app_name")

# ------------------------------------------------------------------ one-pass field bucketing
# `_all`/`_first` used to walk their whole vocabulary per call — ~17 vocabularies × ~20 names per event,
# i.e. 7.4 M dict lookups per 30 k events and the single biggest cost in the build after the regexes.
# `_bucket` inverts it: ONE pass over the fields an event actually has, using a precomputed
# name -> (vocabulary, position) index. Values come back in vocabulary order, so `_all`/`_first` keep
# byte-identical semantics.
_VOCABS: dict[str, tuple[str, ...]] = {
    "src_ip": F_SRC_IP, "dst_ip": F_DST_IP, "src_port": F_SRC_PORT, "dst_port": F_DST_PORT, "user": F_USER,
    "host": F_HOST, "proc": F_PROC, "pid": F_PID, "file": F_FILE, "hash": F_HASH, "domain": F_DOMAIN,
    "url": F_URL, "email": F_EMAIL, "session": F_SESSION, "key": F_KEY, "action": F_ACTION,
    "proc_self": F_PROC_SELF, "proc_parent": F_PROC_PARENT, "pid_self": F_PID_SELF, "pid_parent": F_PID_PARENT,
    "url_only": F_URL_ONLY, "pod": F_POD, "service": F_SERVICE,
}
_FIELD_INDEX: dict[str, tuple[tuple[str, int], ...]] = {}
for _vname, _names in _VOCABS.items():
    for _pos, _n in enumerate(_names):
        _FIELD_INDEX[_n] = _FIELD_INDEX.get(_n, ()) + ((_vname, _pos),)

# ------------------------------------------------------------------ text regexes (fallback when fields are missing)
HASH_RE = re.compile(r"\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
DOMAIN_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|uk|de|ru|cn|info|biz|xyz|top|"
                       r"onion|edu|gov|mil|dev|app|cloud|ai|me|tv|us|ca|fr|jp|kr|nl|se|no|au|br|in|it|es|pl|ch|at|be|"
                       r"cz|dk|fi|gr|hu|ie|il|mx|nz|pt|ro|sg|tr|ua|za|local|internal|corp|lan))\b", re.I)
URL_RE = re.compile(r"\b(https?://[^\s\"'<>()\]]{4,300})", re.I)
EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
WIN_PATH_RE = re.compile(r"(?<![\w\\])([A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]+)")
NIX_PATH_RE = re.compile(r"(?<![\w/])(/(?:tmp|root|home|etc|var|opt|usr|dev|srv|mnt|data|bin|sbin|lib|proc|sys)/[\w./+-]+)")
PROC_PID_RE = re.compile(r"\b([A-Za-z0-9_.+-]{2,40})\[(\d{1,7})\]")          # sshd[1234] (syslog)
PID_KV_RE = re.compile(r"\b(?:pid|ppid|process_?id)\s*[=:]\s*(\d{1,7})\b", re.I)
REG_RE = re.compile(r"\b(HK(?:LM|CU|CR|U|CC)\\[^\s\"']{3,200})", re.I)
# "Failed password for root from", "Accepted publickey for alice", "user=bob", "USER=root",
# "session opened for user carol", "sudo:  dave :", "Invalid user mallory from"
USER_TEXT_RE = re.compile(
    r"(?:(?:Failed|Accepted) (?:password|publickey|keyboard-interactive|none)(?: for invalid user| for)|Invalid user|"
    r"session (?:opened|closed) for user|\buser[=:]\s*|\bUSER=|\bsudo:\s+|\bfor user\s+|\bby user\s+|\baccount[=:]\s*)"
    r"\s*([A-Za-z0-9._\\$@-]{2,64})\b")

PORT_IN_ENDPOINT_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b")

_STOP = {"", "-", "—", "?", "unknown", "none", "null", "n/a", "na", "root?", "0", "0.0.0.0", "127.0.0.1",
         "255.255.255.255", "::", "::1", "localhost", "system", "anonymous logon", "*", "true", "false"}
_SUCCESS = ("success", "accepted", "allow", "allowed", "permit", "ok", "200", "201", "204", "302", "granted", "logon", "4624")
_FAILURE = ("fail", "failed", "invalid", "denied", "reject", "rejected", "block", "blocked", "drop", "401", "403", "4625",
            "unauthorized", "forbidden", "error", "refused")
_AUTH_WORDS = ("login", "logon", "auth", "signin", "sign-in", "password", "credential", "sshd", "session opened", "consolelogin",
               "assumerole", "getsessiontoken", "kerberos", "ntlm", "pam_unix", "su:", "sudo:")
_WRITE_WORDS = ("write", "wrote", "create", "created", "modif", "put", "upload", "export", "save", "copy", "cp ", "mv ", "rename")
_READ_WORDS = ("read", "open", "get", "download", "cat ", "type ", "less ", "more ", "view", "access")
_DEL_WORDS = ("delet", "remove", "unlink", "rm ", "del ", "truncat", "wipe", "shred", "purge")


# ============================================================================= extraction
@dataclass(slots=True)
class _Rel:
    src: str
    dst: str
    kind: str
    outcome: Optional[str] = None
    why: str = ""


@dataclass(slots=True)
class _Ex:
    """Everything one event contributed: typed nodes and typed relations between them."""
    nodes: dict[str, str] = field(default_factory=dict)  # id -> label
    rels: list[_Rel] = field(default_factory=list)


def nid(t: str, v: str) -> str:
    return f"{t}:{v}"


def plausible_ip(ip: str) -> bool:
    """The IPv4 regex also matches version strings like 0.24.04.1 (ubuntu 0.24.04.1) and dotted build numbers.
    A real address never has a zero first octet outside 0.0.0.0, and never carries a leading-zero octet."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    if any(len(x) > 1 and x[0] == "0" for x in parts):
        return False
    if parts[0] == "0":
        return False
    # 1.0.7.0 / 1.2.5.1 are package versions; 8.8.8.8 / 1.1.1.1 are real resolvers. Versions have a zero octet
    # in the middle or end while public/private hosts almost never do (x.x.0.x is a network address, and .0 in
    # the last octet is not assignable). Keep anything with no zero octet; keep RFC1918 regardless.
    nums = [int(x) for x in parts]
    if nums[0] in (10, 172, 192):
        return True
    if any(n == 0 for n in nums[1:]):
        return False
    return True


_ENC_PREFIX = re.compile(r"^(?:%?2f|%?3d|%?3a|%?2c|%?26|%?3f)+", re.I)  # url-encoded junk glued onto a host
_ENC_STARTS = frozenset(("2f", "3d", "3a", "2c", "26", "3f"))
_SCHEME_RE = re.compile(r"^https?:?/*")
_DOM_LABEL_RE = re.compile(r"[a-z0-9-]+")
# A hostname that is ALREADY clean: lower case, plain labels, no %-encoding, no separators. Matching it
# skips the two unquote() passes, four sub/split calls and the per-label check below — and the great
# majority of the domains a log yields are already in this shape.
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_FAST_DOMAIN_RE = re.compile(_LABEL + r"(?:\." + _LABEL + r")+")


def clean_domain(d: str) -> str:
    """Decode %xx, drop an encoded-separator prefix (%2Faccounts.google.com -> accounts.google.com), lowercase.
    Returns "" if what is left is not a plausible hostname."""
    if d and len(d) <= 253 and not d[0].isdigit() and d[:2] not in _ENC_STARTS \
            and not d.startswith("http") and _FAST_DOMAIN_RE.fullmatch(d):
        return d                       # equivalent to running the whole pipeline; see _FAST_DOMAIN_RE
    from urllib.parse import unquote
    d = unquote(unquote(d)).strip().lower().rstrip(".")
    # after decoding, a leading "/" or "=" is the tail of an encoded separator (%2F, %3D) - strip it, then the
    # 2f/3d hex leftovers a browser history sometimes glues on without the percent sign
    d = d.lstrip("/=:,&?")
    d = _ENC_PREFIX.sub("", d)
    d = _SCHEME_RE.sub("", d)          # a full URL that landed in a domain field
    d = d.split("/")[0].split("?")[0].split("&")[0]
    if "=" in d:
        d = d.split("=")[-1]
    if not d or len(d) > 253 or "." not in d:
        return ""
    if IPV4_RE.fullmatch(d):
        return ""
    labels = d.split(".")
    if any(not lab or len(lab) > 63 or not _DOM_LABEL_RE.fullmatch(lab) or lab[0] == "-" or lab[-1] == "-" for lab in labels):
        return ""
    if labels[0].isdigit() and len(labels[0]) > 8:  # 89966437766-... client ids are not hosts
        return ""
    return d


def url_host(u: str) -> str:
    """The domain a URL points at - URLs become facts on their domain node, never nodes themselves."""
    from urllib.parse import unquote, urlsplit
    try:
        h = urlsplit(unquote(u)).hostname or ""
    except ValueError:
        return ""
    return clean_domain(h)


def _clean(v: Any) -> str:
    return str(v).strip().strip("'\"") if v is not None else ""


Bucket = dict[str, list[tuple[int, str]]]


def _bucket(fields: dict[str, str]) -> Bucket:
    """Vocabulary -> [(position in that vocabulary, cleaned value)], from ONE pass over the event fields."""
    b: Bucket = {}
    idx = _FIELD_INDEX
    for k, v in fields.items():
        hits = idx.get(k)
        if hits is None or not v:
            continue
        c = _clean(v)
        if not c or c.lower() in _STOP:
            continue
        for vname, pos in hits:
            lst = b.get(vname)
            if lst is None:
                b[vname] = [(pos, c)]
            else:
                lst.append((pos, c))
    return b


def _first(b: Bucket, vocab: str) -> str:
    lst = b.get(vocab)
    return min(lst)[1] if lst else ""


def _all(b: Bucket, vocab: str) -> list[str]:
    lst = b.get(vocab)
    if not lst:
        return []
    if len(lst) > 1:
        lst = sorted(lst)
    out: list[str] = []
    for _, c in lst:
        if c not in out:
            out.append(c)
    return out


def _uniq(seq: list) -> Any:
    """Order-preserving dedup that skips the dict build for the empty/single-value case — which is what
    almost every one of extract()'s ~15 per-event dedups actually is."""
    return seq if len(seq) < 2 else dict.fromkeys(seq)


def _words_re(words: Iterable[str]) -> re.Pattern[str]:
    """One compiled alternation instead of N Python-level substring scans. `any(w in text for w in WORDS)`
    was 273 k calls and 1.7 s per 30 k events; a single C-level pass over the same text is equivalent."""
    return re.compile("|".join(re.escape(w) for w in words))


_SUCCESS_RE = _words_re(_SUCCESS)
_FAILURE_RE = _words_re(_FAILURE)
_DENIED_RE = _words_re(("denied", "forbidden", "403", "block"))
_AUTH_RE = _words_re(_AUTH_WORDS)
_WRITE_RE = _words_re(_WRITE_WORDS)
_READ_RE = _words_re(_READ_WORDS)
_DEL_RE = _words_re(_DEL_WORDS)
# Necessary condition of every alternative of USER_TEXT_RE (matched against the lower-cased line).
_USER_TEXT_GATE = _words_re(("user", "sudo:", "account", "failed", "accepted"))


def _outcome(e: Event, b: Bucket) -> Optional[str]:
    blob = " ".join(_all(b, "action")).lower() + " " + e.msg.lower()[:200]
    fail = _FAILURE_RE.search(blob) is not None
    ok = _SUCCESS_RE.search(blob) is not None
    if fail and not ok:
        return "denied" if _DENIED_RE.search(blob) else "failure"
    if ok and not fail:
        return "success"
    if ok and fail:
        return "mixed"
    return None


_USER_STOP = {"session", "user", "users", "account", "login", "logon", "root?", "unknown", "none", "null", "-", "n/a",
              "sudo", "cron", "daemon", "nobody", "true", "false", "name", "id"}


_HOST_STOP = {"install", "configure", "remove", "purge", "upgrade", "trigproc", "status", "startup", "unpack",
              "half-installed", "installed", "unpacked", "unknown", "localhost", "-", "none", "null", "n/a", "true", "false"}


_HOST_OK_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def _plausible_host(h: str) -> bool:
    h = h.strip()
    if not h or len(h) > 253 or h.lower() in _HOST_STOP or " " in h:
        return False
    return bool(_HOST_OK_RE.fullmatch(h))


# separator class = backslash OR forward slash. Built with chr(92) because the literal keeps getting
# eaten by one shell/heredoc layer or another when this file is patched by tooling.
_SEP = "[" + chr(92) + chr(92) + "/]"
_NOISE_FILE_RE = re.compile(
    r"^/dev/(null|zero|random|urandom|tty\d*|pts/\d+)$"       # device pseudo-files
    + "|" + _SEP + r"\.gradle" + _SEP                                # build / dependency caches
    + "|" + _SEP + "node_modules" + _SEP + "|" + _SEP + "__pycache__" + _SEP + "|" + _SEP + r"\.cache" + _SEP
    + "|" + _SEP + "site-packages" + _SEP + "|" + _SEP + "dist-packages" + _SEP
    + r"|^/(proc|sys)/", re.I)


def _noise_file(path: str) -> bool:
    """Paths that are always present and never evidence: /dev/null, build/dependency caches, procfs.
    They dominate any file-count ranking and say nothing about what an attacker touched."""
    return bool(_NOISE_FILE_RE.search(path))


_UID_SUFFIX_RE = re.compile(r"\((?:uid|gid)=\d+\)$")
_ARN_RE = re.compile(r"^arn:aws:(?:iam|sts)::\d*:(?:user|role|assumed-role|group|federated-user)/([^/]+)", re.I)
_TRAIL_PUNCT_RE = re.compile(r"[:;,]+$")


def _clean_user(u: str) -> str:
    """'root(uid=0)' -> 'root'; 'DOMAIN\alice' -> 'DOMAIN\alice'; drops words that are not accounts."""
    u = u.strip().strip("'\"")
    if "(" in u:
        u = _UID_SUFFIX_RE.sub("", u)                   # root(uid=0)
    # an IAM ARN is the same principal as its bare user name - collapse so they are ONE node:
    #   arn:aws:iam::447119089082:user/svc_deploy  ->  svc_deploy
    #   arn:aws:sts::447119089082:assumed-role/Admin/session  ->  Admin
    if u[:4].lower() == "arn:":
        m = _ARN_RE.match(u)
        if m:
            u = m.group(1)
    if u and u[-1] in ":;,":
        u = _TRAIL_PUNCT_RE.sub("", u)
    if not u or " " in u or len(u) > 96 or u.lower() in _USER_STOP:
        return ""
    if u.isdigit() or IPV4_RE.fullmatch(u):
        return ""
    return u


def _proc_label(p: str) -> str:
    """'C:\\Windows\\System32\\cmd.exe /c whoami' → 'cmd.exe'; '/usr/sbin/sshd -D' → 'sshd'."""
    p = p.strip().strip('"')
    head = p.split()[0] if p else p
    head = head.replace("\\", "/").rsplit("/", 1)[-1]
    return head[:80] or p[:80]


def extract(e: Event) -> _Ex:
    """Typed nodes + relations for one event. Pure; no state."""
    ex = _Ex()
    b = _bucket(e.fields)
    text = e.raw if len(e.raw) < 6000 else e.raw[:6000]
    ltext = text.lower()
    # Cheap gates for the expensive text regexes. Each one is a NECESSARY condition of its pattern (an
    # email needs '@', a URL needs '://', a registry path needs 'hk', a bracketed pid needs '['), so the
    # extraction is byte-identical — it just skips scanning lines that cannot possibly match. Substring
    # tests run in C over the whole line; the regex engine does not.
    has_dot = "." in text

    def node(t: str, v: str, label: Optional[str] = None) -> Optional[str]:
        v = _clean(v)
        if not v or v.lower() in _STOP or len(v) > 200:
            return None
        i = nid(t, v)
        ex.nodes.setdefault(i, label or v)
        return i

    def rel(a: Optional[str], b: Optional[str], kind: str, outcome: Optional[str] = None, why: str = "") -> None:
        if a and b and a != b:
            ex.rels.append(_Rel(a, b, kind, outcome, why))

    # -- hosts / users / ips ------------------------------------------------------------
    host = node("host", e.host) if e.host and _plausible_host(e.host) else None
    for h in _all(b, "host"):
        if _plausible_host(h) and not IPV4_RE.fullmatch(h):
            host = host or node("host", h)
            node("host", h)
    users = [u for u in ([e.user] if e.user else []) + _all(b, "user")]
    if _USER_TEXT_GATE.search(ltext):     # every alternative of USER_TEXT_RE contains one of these
        for m in USER_TEXT_RE.finditer(text[:1500]):
            users.append(m.group(1))
    users = [_clean_user(u) for u in _uniq(users)]
    users = [u for u in _uniq(users) if u]
    unodes = [node("user", u) for u in users]
    unodes = [u for u in unodes if u]

    f_src = _all(b, "src_ip")
    src_ips = [ip for v in f_src for ip in IPV4_RE.findall(v) if plausible_ip(ip)] + \
              [ip for v in f_src for ip in IPV6_RE.findall(v) if not ip.startswith("::")]
    dst_ips = [ip for v in _all(b, "dst_ip") for ip in IPV4_RE.findall(v) if plausible_ip(ip)]
    field_ips = set(src_ips) | set(dst_ips)
    text_ips = [ip for ip in IPV4_RE.findall(text) if ip not in field_ips and ip not in _STOP and plausible_ip(ip)] \
        if has_dot else []
    src_n = [node("ip", ip) for ip in _uniq(src_ips)]
    dst_n = [node("ip", ip) for ip in _uniq(dst_ips)]
    other_ip_n = [node("ip", ip) for ip in _uniq(text_ips)]
    src_n = [x for x in src_n if x]; dst_n = [x for x in dst_n if x]; other_ip_n = [x for x in other_ip_n if x]

    # -- ports / endpoints -------------------------------------------------------------
    dport = _first(b, "dst_port")
    if not dport and has_dot:
        m = PORT_IN_ENDPOINT_RE.search(text)
        if m:
            dport = m.group(2)
    port_n = node("port", dport) if dport and dport.isdigit() and int(dport) < 65536 else None

    # -- processes / pids --------------------------------------------------------------
    procs = _all(b, "proc_self")
    parents = _all(b, "proc_parent")
    pids = _all(b, "pid_self")
    ppids = _all(b, "pid_parent")
    if "[" in text[:400]:
        for m in PROC_PID_RE.finditer(text[:400]):  # syslog "sshd[1234]:"
            if m.group(1).lower() not in ("t", "line", "col"):
                procs.append(m.group(1)); pids.append(m.group(2))
    if "pid" in ltext or "process" in ltext:       # every alternative of PID_KV_RE contains one of these
        for m in PID_KV_RE.finditer(text[:1500]):
            pids.append(m.group(1))
    proc_n = [node("process", _proc_label(p), _proc_label(p)) for p in _uniq(procs)]
    proc_n = [x for x in proc_n if x]
    par_n = [node("process", _proc_label(p), _proc_label(p)) for p in _uniq(parents)]
    par_n = [x for x in par_n if x]
    pid_n = [node("pid", p) for p in _uniq(pids) if p.isdigit()]
    pid_n = [x for x in pid_n if x]
    ppid_n = [node("pid", p) for p in _uniq(ppids) if p.isdigit()]
    ppid_n = [x for x in ppid_n if x]

    # -- files / hashes / registry -------------------------------------------------------
    head2k = text[:2000]
    files = _all(b, "file")
    if "\\" in head2k:
        files += WIN_PATH_RE.findall(head2k)
    if "/" in head2k:
        files += NIX_PATH_RE.findall(head2k)
    file_n = [node("file", p) for p in _uniq(files)
              if len(p) > 2 and not IPV4_RE.fullmatch(p) and not p.isdigit() and not _noise_file(p)]
    file_n = [x for x in file_n if x]
    hashes = _all(b, "hash")
    for v in list(hashes):
        hashes += HASH_RE.findall(v)
    hashes += HASH_RE.findall(text[:3000])
    hash_n = [node("hash", h.lower()) for h in _uniq(hashes) if HASH_RE.fullmatch(h)]
    hash_n = [x for x in hash_n if x]
    reg_n = [node("registry", r) for r in _uniq(REG_RE.findall(head2k))] if "hk" in ltext else []
    reg_n = [x for x in reg_n if x]

    # -- domains / urls / emails ---------------------------------------------------------
    raw_domains = _all(b, "domain") + (DOMAIN_RE.findall(head2k) if has_dot else [])
    urls = _all(b, "url_only") + (URL_RE.findall(head2k) if "http" in ltext else [])
    # a URL contributes its HOST as a domain node (and the URL as a fact) - 12k distinct URLs as nodes is a hairball
    raw_domains += [url_host(u) for u in urls]
    dom_n = [node("domain", cd) for cd in dict.fromkeys(clean_domain(d) for d in raw_domains) if cd]
    dom_n = [x for x in dom_n if x]
    emails = _all(b, "email") + (EMAIL_RE.findall(head2k) if "@" in head2k else [])
    email_n = [node("email", m.lower()) for m in _uniq(emails) if EMAIL_RE.fullmatch(m)]
    email_n = [x for x in email_n if x]

    # -- keys / sessions / pods ----------------------------------------------------------
    keys = _all(b, "key")
    if "AKIA" in text or "ASIA" in text:
        keys = keys + AKIA_RE.findall(text)
    if "SHA256:" in text:
        keys = keys + KEYFP_RE.findall(text)
    key_n = [node("key", k) for k in _uniq(keys)]
    key_n = [x for x in key_n if x]
    sess_n = [node("session", s) for s in _uniq(_all(b, "session")) if 3 <= len(s) <= 80]
    sess_n = [x for x in sess_n if x]
    pod = _first(b, "pod")
    pod_n = node("pod", pod) if pod else None
    svc = _first(b, "service")
    svc_n = node("service", svc) if svc and svc != e.host else None

    outcome = _outcome(e, b)
    is_auth = _AUTH_RE.search(ltext) is not None or any(d.id.startswith(("SIGMA-AUTH", "SIGMA-LNX-0012", "SIGMA-LNX-0045", "SIGMA-WIN-0140")) for d in e.detections)
    is_write = _WRITE_RE.search(ltext) is not None
    is_read = _READ_RE.search(ltext) is not None
    is_del = _DEL_RE.search(ltext) is not None
    is_dns = bool(dom_n) and ("dns" in e.source.lower() or "query" in ltext or "resolv" in ltext or "dns" in ltext)

    # ---------------------------------------------------------------- relations
    # authentication: user ← ip
    if is_auth:
        for u in unodes:
            for ip in src_n or other_ip_n:
                rel(u, ip, "auth_from", outcome, "authentication " + (outcome or "attempt"))
    # network: src → dst (:port)
    for s in src_n:
        for d in dst_n:
            rel(s, d, "connected_to", outcome, "network flow")
            if port_n:
                rel(d, port_n, "connected_to", None, "listening port")
    if src_n and not dst_n and host and not is_auth:
        for s in src_n:
            rel(s, host, "connected_to", outcome, "request to host")
    # process execution: user/host → process, process ↔ pid, parent → child
    for p in proc_n:
        for u in unodes:
            rel(u, p, "ran", None, "process run by account")
        if host:
            rel(p, host, "on_host", None, "process on host")
        for pid in pid_n:
            rel(p, pid, "session", None, "process id")
    for parent in par_n:
        for child in proc_n:
            rel(parent, child, "spawned", None, "parent → child process")
    for pp in ppid_n:
        for pid in pid_n:
            rel(pp, pid, "spawned", None, "parent pid → child pid")
    # files: process/user → file
    actor_for_file = proc_n or unodes
    fk = "deleted" if is_del else "wrote" if is_write else "read" if is_read else "co_occurred"
    for fn in file_n:
        for a in actor_for_file:
            rel(a, fn, fk, None, f"file {fk}" if fk != "co_occurred" else "file referenced")
        for h in hash_n:
            rel(fn, h, "session", None, "file hash")
        if host and not actor_for_file:
            rel(fn, host, "on_host", None, "file on host")
    for r in reg_n:
        for a in actor_for_file:
            rel(a, r, "wrote" if is_write else "read", None, "registry key")
    # dns / http
    if is_dns:
        for d in dom_n:
            for s in src_n or ([host] if host else []) or other_ip_n:
                rel(s, d, "resolved", None, "DNS query")
    if urls and not is_dns:  # an HTTP request: requester -> the domain it hit
        for d in dom_n:
            for a in src_n or unodes or other_ip_n or ([host] if host else []):
                rel(a, d, "requested", outcome, "HTTP request")
    # keys / sessions / pods
    for k in key_n:
        for u in unodes:
            rel(u, k, "used_key", None, "credential")
        for ip in src_n or other_ip_n:
            rel(k, ip, "auth_from", outcome, "key used from")
    for s in sess_n:
        for u in unodes:
            rel(u, s, "session", None, "session id")
        for ip in src_n:
            rel(s, ip, "auth_from", None, "session source")
    if pod_n:
        for u in unodes:
            rel(u, pod_n, "ran", None, "k8s action on pod")
        if svc_n:
            rel(pod_n, svc_n, "on_host", None, "pod of service")
    # everything located on the host
    if host:
        for u in unodes:
            rel(u, host, "on_host", None, "account seen on host")
        for ip in other_ip_n:
            rel(ip, host, "co_occurred", None, "IP seen on host")
    for m_ in email_n:
        for u in unodes:
            rel(u, m_, "session", None, "email address")

    # if an event produced typed nodes but no specific relation, keep a co-occurrence so nothing is orphaned -
    # anchored on the host/user/ip, never domain<->domain (that is how a browser history becomes a hairball)
    if ex.nodes and not ex.rels:
        anchors = [x for x in ([host] + unodes + src_n + other_ip_n) if x]
        others = [i for i in ex.nodes if i not in anchors and not i.startswith("domain:")]
        if anchors:
            for a in anchors[:2]:
                for o in others[:6]:
                    rel(a, o, "co_occurred", None, "seen together")
                for d in dom_n[:6]:
                    rel(a, d, "requested", outcome, "seen with")
    return ex


# ============================================================================= vectorised kernels
# The GPU is optional EVERYWHERE in this app: `compute.xp()` hands back cupy only when a CUDA device is
# actually usable, and numpy otherwise. Both of these are written so the numpy path is the definition of
# correct and the cupy path must reproduce it bit for bit — no float maths, no order-dependent reductions,
# and a total sort key so stability of the backend's sort cannot change the answer.
def _xp() -> Any:
    try:
        from . import compute
        return compute.xp()
    except Exception:               # the GPU probe must never be able to break the graph
        return np


def _to_numpy(arr: Any) -> np.ndarray:
    if isinstance(arr, np.ndarray):
        return arr
    try:
        from . import compute
        return compute.asnumpy(arr)
    except Exception:
        return np.asarray(arr)


def _unique_pair_degrees(u: np.ndarray, v: np.ndarray, n: int) -> np.ndarray:
    """Distinct-neighbour count per node id, from parallel arrays of edge endpoints.

    Pairs are normalised to (lo, hi) so a→b and b→a are the same neighbour, deduplicated, then tallied.
    """
    xp = _xp()
    try:
        gu = xp.asarray(u)
        gv = xp.asarray(v)
        lo = xp.minimum(gu, gv)
        hi = xp.maximum(gu, gv)
        pair = xp.unique(lo * n + hi)
        both = xp.concatenate((pair // n, pair % n))
        return _to_numpy(xp.bincount(both, minlength=n))[:n]
    except Exception:
        if xp is np:
            raise
        lo = np.minimum(u, v)
        hi = np.maximum(u, v)
        pair = np.unique(lo * n + hi)
        both = np.concatenate((pair // n, pair % n))
        return np.bincount(both, minlength=n)[:n]


def _lexsort_rank(*keys: np.ndarray) -> np.ndarray:
    """Indices that sort by `keys` in the order given, ties broken by original position (total order)."""
    n = len(keys[0])
    seq = np.arange(n, dtype=np.int64)
    # lexsort takes the LAST row as the PRIMARY key, so the rows run weakest → strongest: the position
    # tiebreaker first, then the given keys in reverse.
    rows = np.vstack((seq,) + tuple(reversed(keys)))
    xp = _xp()
    try:
        return _to_numpy(xp.lexsort(xp.asarray(rows)))
    except Exception:
        if xp is np:
            raise
        return np.lexsort(rows)


# ============================================================================= graph build
# Per-node event bookkeeping is the whole memory story of this structure. Keeping every event index of
# every node was ~8 indices per event: at 1.2 M events that is ~10 M Python ints (≈360 MB of int objects
# and list slots) for something only three call sites read. Instead each node keeps
#   * `count`      — exact, so "Events: 1,204,113" is still exact;
#   * `srcs`/`files` — exact distinct-source / distinct-file tallies, accumulated as the build runs, which
#     is what `_facts` actually wanted from the full list (a node in 219 nginx + 2 firewall lines must not
#     look nginx-only, and a tally cannot lose the 2);
#   * `events`     — the first 200 indices (detections sample, inCase test);
#   * `tail`       — a 200-entry ring of the MOST RECENT indices, which is exactly what node_detail's
#     "last 50 events" needs (the pool is ascending by timestamp, so appends arrive in order).
# Both index buffers are array('i') — 4 bytes an entry, no per-int object.
_HEAD = 200
_TAIL = 200


# Plain __slots__ classes, not dataclasses: these are constructed tens of thousands of times and their
# attributes are touched millions of times inside the build loop, where a generated dataclass __init__ and
# dict-backed attributes are measurable. The Counters became plain dicts for the same reason — Counter()
# construction alone was 107 k calls per 30 k events.
class _NodeAgg:
    __slots__ = ("type", "value", "label", "count", "first", "last", "sev", "detections",
                 "events", "tail", "ti", "srcs", "files")

    def __init__(self, type: str, value: str, label: str, first: str = "", last: str = "") -> None:
        self.type = type
        self.value = value
        self.label = label
        self.count = 0
        self.first = first
        self.last = last
        self.sev = "info"
        self.detections = 0
        self.events = array("i")        # first _HEAD event indices
        self.tail = array("i")          # ring of the most recent _TAIL indices
        self.ti = 0                     # write cursor into `tail` once it is full
        self.srcs: dict[str, int] = {}  # EXACT over every event of the node
        self.files: dict[str, int] = {}

    def add(self, i: int) -> None:
        if len(self.events) < _HEAD:
            self.events.append(i)
        elif len(self.tail) < _TAIL:
            self.tail.append(i)
        else:
            self.tail[self.ti] = i
            self.ti = (self.ti + 1) % _TAIL

    def recent(self) -> list[int]:
        """Event indices in ascending order, most recent last (head + ring, unwrapped)."""
        if len(self.tail) < _TAIL:
            return list(self.events) + list(self.tail)
        return list(self.tail[self.ti:]) + list(self.tail[:self.ti])


class _EdgeAgg:
    # `files` is a SET, not a tally: it exists so a source filter can be exact ("was this relation
    # actually seen in the files I selected?"), and the count per file is not a question anyone asks.
    # A set of a handful of interned names per edge is the cheapest exact answer — without it the
    # filter would have to infer an edge from its endpoints, which shows a relation the selected logs
    # never contained.
    __slots__ = ("source", "target", "relation", "count", "first", "last", "sev", "outcomes", "events",
                 "why", "files")

    def __init__(self, source: str, target: str, relation: str, first: str = "", last: str = "") -> None:
        self.source = source
        self.target = target
        self.relation = relation
        self.count = 0
        self.first = first
        self.last = last
        self.sev = "info"
        self.outcomes: dict[str, int] = {}
        self.events: list[str] = []
        self.why: dict[str, int] = {}
        self.files: set[str] = set()


def aggregate(events: Iterable[Any], nodes: dict[str, _NodeAgg], edges: dict[tuple[str, str, str], _EdgeAgg],
              base: int = 0, progress: Optional[Callable[[int], None]] = None,
              cancelled: Optional[Callable[[], bool]] = None) -> None:
    """Fold one SLICE of the pool into `nodes` / `edges`. The ONE implementation of the aggregation.

    `base` is the slice's offset in the pool, so the per-node event indices are always POOL indices.
    Split out of `GraphBuilder._build` so the multi-process path in `graph_parallel.py` runs exactly
    this code on its chunk — the same reason `parsers/parallel.normalize_batch` exists. Never fork a
    second copy: a divergence here is a graph that changes shape depending on the worker count.

    `events` may be `Event`s or the attribute-compatible row shim a worker rebuilds from its chunk;
    only `.ts/.sev/.source/.file/.id/.detections` and whatever `extract()` reads are ever touched.

    Hot loop: ~6 node occurrences and ~5 relation occurrences PER EVENT, so at 1.2 M events this body
    runs ~14 M times. Everything it touches is a local; `max_sev` and `_NodeAgg.add` are inlined; the
    "<type>:<value>" split only happens when a node is first seen.
    """
    sev_order = SEV_ORDER
    for i, e in enumerate(events):
        if not i % 20_000:
            if progress is not None:
                progress(i)
            if cancelled is not None and cancelled():
                # ~60 checks over a 1.2 M-event pool: free, and it stops a build whose key is already
                # stale from spending another four minutes producing something nothing can read.
                raise BuildCancelled()
        ex = extract(e)
        gi = base + i
        src, fil, ets, esev, edets = e.source, e.file, e.ts, e.sev, len(e.detections)
        erank = sev_order.get(esev, 0)
        for i_id, label in ex.nodes.items():
            n = nodes.get(i_id)
            if n is None:
                t, _, v = i_id.partition(":")
                n = nodes[i_id] = _NodeAgg(t, v, label, ets, ets)
            n.count += 1
            if ets < n.first:
                n.first = ets
            elif ets > n.last:
                n.last = ets
            if erank > sev_order.get(n.sev, 0):
                n.sev = esev
            n.detections += edets
            ev = n.events
            if len(ev) < _HEAD:
                ev.append(gi)
            elif len(n.tail) < _TAIL:
                n.tail.append(gi)
            else:
                n.tail[n.ti] = gi
                n.ti = (n.ti + 1) % _TAIL
            if src:
                s = n.srcs
                s[src] = s.get(src, 0) + 1
            if fil:
                fl = n.files
                fl[fil] = fl.get(fil, 0) + 1
        for r in ex.rels:
            rs, rd = r.src, r.dst
            key = (rs, rd, r.kind)
            ed = edges.get(key)
            if ed is None:
                ed = edges[key] = _EdgeAgg(rs, rd, r.kind, ets, ets)
            ed.count += 1
            if ets < ed.first:
                ed.first = ets
            elif ets > ed.last:
                ed.last = ets
            if erank > sev_order.get(ed.sev, 0):
                ed.sev = esev
            if fil:
                ed.files.add(fil)
            oc = r.outcome
            if oc:
                o = ed.outcomes
                o[oc] = o.get(oc, 0) + 1
            w = r.why
            if w:
                wd = ed.why
                wd[w] = wd.get(w, 0) + 1
            if len(ed.events) < 20:
                ed.events.append(e.id)


class GraphBuilder:
    """Aggregate per-event extractions into a typed graph, then rank/filter it for the API."""

    def __init__(self, events: list[Event], progress: Optional[Callable[[int], None]] = None,
                 parallel: Optional[bool] = None,
                 cancelled: Optional[Callable[[], bool]] = None,
                 preloaded: Optional[tuple[dict, dict]] = None,
                 groups: Optional[list] = None, sigs: Optional[dict] = None,
                 index: Optional[dict] = None, cache: Any = None) -> None:
        """`groups`/`sigs`/`index`/`cache` are the per-source extraction inputs (see graph_parts): the
        store passes them so unchanged sources come from the partial cache. Absent, they are derived
        from `events` — a from-scratch build, still per source, still the same fold."""
        self.events = events
        self._preloaded = preloaded
        self._parallel = parallel
        self._cancelled = cancelled
        self._groups, self._sigs, self._index, self._cache = groups, sigs, index, cache
        self._used_parallel = False
        self.build_note = ""
        self.nodes: dict[str, _NodeAgg] = {}
        self.edges: dict[tuple[str, str, str], _EdgeAgg] = {}
        self._adj: Optional[dict[str, set[str]]] = None
        self._deg: dict[str, int] = {}
        self._progress = progress
        self._ranked: Optional[list[str]] = None
        self._by_node: Optional[dict[str, list[tuple[str, str, str]]]] = None
        self._build()

    def _build(self) -> None:
        prog = self._progress
        if self._preloaded is not None:
            self.nodes, self.edges = self._preloaded
            self._preloaded = None
        elif self.events:
            from . import graph_parts
            # ONE implementation of the build, per source, in-process or across workers. `parallel`
            # is honoured as a ceiling: False pins it in-process (tests compare the two).
            mw = 1 if self._parallel is False else None
            self.build_note = graph_parts.build(self.events, self.nodes, self.edges,
                                                groups=self._groups, sigs=self._sigs, index=self._index,
                                                cache=self._cache, progress=prog,
                                                cancelled=self._cancelled, max_workers=mw)
            self._used_parallel = "in-process" not in self.build_note
        if prog is not None:
            prog(len(self.events))
        self._deg = self._degrees()
        self.ranked_ids()
        self.edges_of("")

    def _edge_endpoint_arrays(self) -> tuple[list[str], Any, Any]:
        """(node ids in insertion order, source index array, target index array) over distinct edges."""
        node_ids = list(self.nodes)
        pos = {i: k for k, i in enumerate(node_ids)}
        m = len(self.edges)
        u = np.empty(m, dtype=np.int64)
        v = np.empty(m, dtype=np.int64)
        w = 0
        for a, b, _k in self.edges:
            ia = pos.get(a)
            ib = pos.get(b)
            if ia is None or ib is None or ia == ib:
                continue
            u[w] = ia
            v[w] = ib
            w += 1
        return node_ids, u[:w], v[:w]

    def _degrees(self) -> dict[str, int]:
        """Undirected DISTINCT-neighbour count per node — the number `rank_key` and the UI call 'links'.

        Identical to the old `len(adj[node])`: two relations between the same pair are one neighbour.
        """
        node_ids, u, v = self._edge_endpoint_arrays()
        n = len(node_ids)
        if not n or not len(u):
            return {}
        counts = _unique_pair_degrees(u, v, n)
        return {node_ids[k]: int(c) for k, c in enumerate(counts) if c}

    # -------------------------------------------------------------- facts per node
    def _facts(self, n: _NodeAgg) -> list[tuple[str, str]]:
        # sources/files are counted over EVERY event the node touches (exact tallies kept during the
        # build) - otherwise a node that lives in 219 nginx lines and 2 firewall lines looks nginx-only
        ev = [self.events[i] for i in n.events[:200]]
        out: list[tuple[str, str]] = [("Type", n.type), ("Events", f"{n.count:,}"),
                                      ("First seen", n.first), ("Last seen", n.last)]
        if n.srcs:
            out.append(("Sources", " · ".join(s for s, _ in Counter(n.srcs).most_common(4))))
        if n.files:
            out.append(("Log files", " · ".join(s for s, _ in Counter(n.files).most_common(3))))
        dets = Counter(d.name for e in ev for d in e.detections)
        if dets:
            out.append(("Detections", "; ".join(f"{k} ({v})" for k, v in dets.most_common(3))))
        if n.type == "ip":
            out.append(("Scope", "internal / private" if is_private_ip(n.value) else "external / public"))
        return out

    # -------------------------------------------------------------- degree / ranking
    @property
    def adj(self) -> dict[str, set[str]]:
        """Neighbour sets, derived from the deduplicated edge keys on first use (focus/hops, path finding)."""
        a = self._adj
        if a is None:
            a = self._adj = defaultdict(set)
            for s, t, _k in self.edges:
                if s != t:
                    a[s].add(t)
                    a[t].add(s)
        return a

    def degree(self, node_id: str) -> int:
        return self._deg.get(node_id, 0)

    def ranked_ids(self) -> list[str]:
        """Every node id in rank order. Computed once per builder — `select` then FILTERS this order
        instead of re-sorting, so a type/focus/limit change is O(nodes) and not O(n log n).

        The order is the one `rank_key` documents, produced by a vectorised lexsort (cupy or numpy). The
        node's own position is the LAST sort key, which makes the order total: the result cannot depend on
        whether the backend's sort happens to be stable, so CPU and GPU return the same list.
        """
        r = self._ranked
        if r is None:
            r = self._ranked = self._rank_order()
        return r

    def _rank_order(self) -> list[str]:
        node_ids = list(self.nodes)
        n = len(node_ids)
        if not n:
            return []
        deg = self._deg
        k_lead = np.empty(n, dtype=np.int64)     # 0 = detection hit AND connected, else 1
        k_infra = np.empty(n, dtype=np.int64)
        k_det = np.empty(n, dtype=np.int64)
        k_deg = np.empty(n, dtype=np.int64)
        k_cnt = np.empty(n, dtype=np.int64)
        infra_types = ("port", "pid", "session")
        for k, i in enumerate(node_ids):
            a = self.nodes[i]
            d = deg.get(i, 0)
            k_lead[k] = 0 if (a.detections and d) else 1
            k_infra[k] = 1 if a.type in infra_types else 0
            k_det[k] = -a.detections
            k_deg[k] = -d
            k_cnt[k] = -a.count
        order = _lexsort_rank(k_lead, k_infra, k_det, k_deg, k_cnt)
        return [node_ids[k] for k in order]

    def edges_of(self, node_id: str) -> list[tuple[str, str, str]]:
        """Edge keys touching a node, from an index built on first use. Scanning `self.edges` per request
        is fine at 5 k edges and is a full second at 1 M."""
        m = self._by_node
        if m is None:
            m = defaultdict(list)
            for key in self.edges:
                m[key[0]].append(key)
                m[key[1]].append(key)
            self._by_node = m
        return m.get(node_id, [])

    def rank_key(self, n: _NodeAgg) -> tuple:
        # Things involved in a rule hit come first - but only if they are actually connected to
        # something: an isolated node cannot be walked, so it is a poor place to start. Then how
        # connected, then how common. Pure infrastructure types (port, pid, session) sink slightly so
        # the actors (ip/user/host/process/file) lead the view.
        deg = self.degree(nid(n.type, n.value))
        infra = 1 if n.type in ("port", "pid", "session") else 0
        return (0 if (n.detections and deg) else 1, infra, -n.detections, -deg, -n.count)

    # -------------------------------------------------------------- output
    def _node_out(self, n: _NodeAgg, in_case: set[str]) -> GraphNode:
        i = nid(n.type, n.value)
        return GraphNode(id=i, type=n.type, value=n.value, label=n.label, count=n.count, first=n.first, last=n.last,  # type: ignore[arg-type]
                         sev=n.sev, detections=n.detections, facts=self._facts(n),  # type: ignore[arg-type]
                         inCase=any(self.events[j].id in in_case for j in n.events[:200]) if in_case else False)

    def _edge_out(self, ed: _EdgeAgg, lean: bool = False) -> GraphEdge:
        oc = None
        if ed.outcomes:
            kinds = set(ed.outcomes)
            oc = "mixed" if len(kinds) > 1 else next(iter(kinds))
        why = max(ed.why, key=ed.why.__getitem__) if ed.why else ed.relation.replace("_", " ")
        eid = f"{ed.source}|{ed.relation}|{ed.target}"
        if lean:
            # what the canvas reads; the event ids and stamps come with the node detail request
            return GraphEdge(id=eid, source=ed.source, target=ed.target, relation=ed.relation, count=ed.count,  # type: ignore[arg-type]
                             sev=ed.sev, outcome=oc, why=why)  # type: ignore[arg-type]
        return GraphEdge(id=eid, source=ed.source, target=ed.target, relation=ed.relation, count=ed.count,  # type: ignore[arg-type]
                         first=ed.first, last=ed.last, sev=ed.sev, outcome=oc, eventIds=list(ed.events), why=why)  # type: ignore[arg-type]

    def select(self, types: Optional[set[str]] = None, relations: Optional[set[str]] = None, min_count: int = 1,
               focus: Optional[str] = None, hops: int = 1, limit: int = DEFAULT_LIMIT,
               in_case: Optional[set[str]] = None,
               files: Optional[set[str]] = None,
               query: str = "",
               max_edges: int = 0, lean: bool = False,
               min_degree: int = 1) -> tuple[list[GraphNode], list[GraphEdge], dict[str, Any]]:
        """`files` restricts the view to entities and relations SEEN IN those log files.

        Both sides are exact: a node keeps a per-file tally of every event it appeared in, and an edge
        keeps the set of files that produced it. Inferring an edge from its endpoints instead would draw
        a relation the selected logs never contained — the graph is evidence, and "these two entities
        each appear in this file" is not the same claim as "this file shows them related".
        """
        in_case = in_case or set()
        # 1. candidate node set, taken in the builder's precomputed rank order and filtered in place
        if focus and focus in self.nodes:
            keep = self.neighbourhood(focus, hops)
            ranked = [i for i in self.ranked_ids() if i in keep]
        else:
            ranked = self.ranked_ids()
        if types:
            ranked = [i for i in ranked if self.nodes[i].type in types]
        if files is not None:
            ranked = [i for i in ranked if not self.nodes[i].files.keys().isdisjoint(files)]
        # 1a. the graph's own search box. It MUST run here, over every ranked node, and not on the
        # payload after the cap: filtering the already-limited top-50 meant a search for anything outside
        # those 50 returned an empty graph, which reads as "no such entity" when the entity is right
        # there. Matches keep their direct neighbours so the result is still a graph, not a dust cloud.
        if query.strip():
            needle = query.strip().lower()
            matched = [i for i in ranked
                       if needle in self.nodes[i].value.lower() or needle in self.nodes[i].label.lower()]
            keep_q = set(matched)
            for i in matched:
                for a, b, _k in self.edges_of(i):
                    keep_q.add(b if a == i else a)
            # rank order is preserved, but a MATCH outranks a neighbour: with limit=50 and 300 hits, the
            # analyst must get matches, not the neighbours of the first few.
            hit = set(matched)
            ranked = [i for i in ranked if i in hit] + [i for i in ranked if i in keep_q and i not in hit]
        # 1b. `min_count` is RELATIONSHIP STRENGTH, not node volume: an edge survives only when at least
        # this many events support that relation, and a node survives only while it still has one.
        # It used to filter `node.count` (how many events mention the entity), which was invisible in
        # practice — the ranking already puts the busiest entities first, so every value up to five
        # figures returned the same 50 nodes and the control looked dead. Filtering edges is also what
        # the control is for: "show me relationships that happened more than once".
        if min_count > 1:
            cand = set(ranked)
            keep: set[str] = set()
            for i in ranked:
                for key in self.edges_of(i):
                    a, b, k = key
                    if relations and k not in relations:
                        continue
                    if self.edges[key].count < min_count:
                        continue
                    if (b if a == i else a) in cand:
                        keep.add(i)
                        break
            ranked = [i for i in ranked if i in keep]
        # 2. cap
        truncated = len(ranked) > limit
        # 3. emit the nodes FIRST, then derive the id set the edges are allowed to reference. An edge whose
        # endpoint was ranked out by `limit` (or filtered out by `types`) must never be returned: the canvas
        # would draw it to a node that is not there, which is what the "floating arrow" artifact looked like.
        # a focus view keeps every node in the neighbourhood even if it has no edge after the relation filter
        nodes = [self._node_out(self.nodes[i], in_case) for i in ranked[:limit]]
        chosen = {n.id for n in nodes}
        seen_keys: set[tuple[str, str, str]] = set()
        picked: list[_EdgeAgg] = []
        # only edges touching a returned node can survive step 3. Walked in NODE RANK ORDER, not set order:
        # a payload whose edge order changes between two identical polls makes every diff and every
        # screenshot comparison meaningless.
        for n_out in nodes:
            for key in self.edges_of(n_out.id):
                a, b, k = key
                if a in chosen and b in chosen and (not relations or k in relations) and key not in seen_keys \
                        and self.edges[key].count >= min_count \
                        and (files is None or not self.edges[key].files.isdisjoint(files)):
                    seen_keys.add(key)
                    picked.append(self.edges[key])
        # Rank and CAP on the aggregates, then build the models. 2,000 well-connected nodes carried
        # 113,457 edges: building a pydantic GraphEdge for each was 1.4 s of a 3.5 s request, and the
        # route then discarded 93,000 of them. The order is the one the payload always had — severity,
        # then count, then id — so the cap keeps the strongest and the payload stays deterministic.
        picked.sort(key=lambda ed: (-SEV_ORDER.get(ed.sev, 0), -ed.count, ed.source, ed.relation, ed.target))
        hidden_edges = 0
        if max_edges and len(picked) > max_edges:
            hidden_edges = len(picked) - max_edges
            picked = picked[:max_edges]
        edges: list[GraphEdge] = [self._edge_out(ed, lean) for ed in picked]
        if min_count > 1:
            # the cap can strand a node whose only strong-enough partner was ranked out — with an edge
            # filter active an edgeless node is not a result, so it goes too (the payload stays closed).
            used = {e.source for e in edges} | {e.target for e in edges}
            nodes = [n for n in nodes if n.id in used]
        # `min_degree` is a different question from `min_count`, and both are worth asking: min_count is
        # "how much evidence supports this RELATION" (drop weak links), min_degree is "how connected is
        # this ENTITY" (drop the leaves). An IP seen once with one host survives min_count=1000 if that
        # one relation is busy; it does not survive min_degree=2. Degree is counted over the edges being
        # RETURNED — that is the graph the analyst is looking at and can count for themselves.
        #
        # It ITERATES to a fixed point (a k-core), and a single pass is wrong for a reason that is not
        # obvious until you count: removing a leaf removes its edge too, so a survivor can drop BELOW the
        # threshold it was just measured against. One pass therefore renders nodes with fewer links than
        # the control says it is showing — the control would be lying about its own result. A chain of
        # leaves peels; a genuine hub never does, because its degree does not depend on any one leaf.
        hidden_by_degree = 0
        if min_degree > 1 and edges:
            keep_d = {n.id for n in nodes}
            while True:
                deg: dict[str, int] = {}
                for e in edges:
                    deg[e.source] = deg.get(e.source, 0) + 1
                    deg[e.target] = deg.get(e.target, 0) + 1
                drop = {i for i in keep_d if deg.get(i, 0) < min_degree}
                if not drop:
                    break
                keep_d -= drop
                edges = [e for e in edges if e.source in keep_d and e.target in keep_d]
            hidden_by_degree = len(nodes) - len(keep_d)
            nodes = [n for n in nodes if n.id in keep_d]
        by_type = Counter(n.type for n in nodes)
        by_rel = Counter(e.relation for e in edges)
        stats = {"nodes": len(nodes), "edges": len(edges), "truncated": truncated,
                 "totalNodes": len(self.nodes), "totalEdges": len(self.edges),
                 "byType": dict(by_type), "byRelation": dict(by_rel),
                 "hiddenByDegree": hidden_by_degree, "hiddenEdges": hidden_edges}
        return nodes, edges, stats

    def neighbourhood(self, start: str, hops: int) -> set[str]:
        seen = {start}
        frontier = {start}
        for _ in range(max(0, hops)):
            nxt: set[str] = set()
            for n in frontier:
                nxt |= self.adj.get(n, set()) - seen
            seen |= nxt
            frontier = nxt
            if not frontier:
                break
        return seen

    @staticmethod
    def node_query(value: str) -> str:
        """The search DSL query that returns EXACTLY this node's events.

        The graph's membership rule is "this value is one of the event's extracted entities", and
        `entity:` is the one field that matches an entity exactly (see query._field_pred). Free text —
        what the Search button used to send — matches the message, the raw line, every field and every
        entity by SUBSTRING, so clicking `10.0.0.1` in the graph landed on a result set that also held
        10.0.0.100 and any line that merely mentioned the string. A colon inside the value (a URL, an
        ip:port) has to be escaped or the parser reads it as another field:value split.
        """
        escaped = value.replace(chr(92), chr(92)*2).replace(chr(34), chr(92)+chr(34)).replace(":", chr(92)+":")
        return f'entity:"{escaped}"'

    def node_detail(self, node_id: str, in_case: Optional[set[str]] = None) -> Optional[dict[str, Any]]:
        n = self.nodes.get(node_id)
        if n is None:
            return None
        neigh = [self._edge_out(self.edges[key]) for key in dict.fromkeys(self.edges_of(node_id))]
        neigh.sort(key=lambda e: (-SEV_ORDER.get(e.sev, 0), -e.count))
        idx = sorted(n.recent(), key=lambda i: self.events[i].ts)[-50:]
        tl = [{"ts": self.events[i].ts, "eventId": self.events[i].id, "msg": self.events[i].msg[:200], "sev": self.events[i].sev} for i in idx]
        return {**self._node_out(n, in_case or set()).model_dump(), "neighbours": neigh[:60], "timeline": tl,
                "query": self.node_query(n.value)}

    def shortest_path(self, a: str, b: str, max_hops: int = 4) -> tuple[list[GraphNode], list[GraphEdge]]:
        if a not in self.nodes or b not in self.nodes:
            return [], []
        prev: dict[str, Optional[str]] = {a: None}
        q = deque([(a, 0)])
        while q:
            cur, d = q.popleft()
            if cur == b:
                break
            if d >= max_hops:
                continue
            for nx in self.adj.get(cur, ()):
                if nx not in prev:
                    prev[nx] = cur
                    q.append((nx, d + 1))
        if b not in prev:
            return [], []
        path: list[str] = []
        cur: Optional[str] = b
        while cur is not None:
            path.append(cur)
            cur = prev[cur]
        path.reverse()
        nodes = [self._node_out(self.nodes[i], set()) for i in path]
        edges: list[GraphEdge] = []
        for x, y in zip(path, path[1:]):
            best = None
            for key in self.edges_of(x):
                if key[0] in (x, y) and key[1] in (x, y):
                    ed = self.edges[key]
                    if best is None or ed.count > best.count:
                        best = ed
            if best:
                edges.append(self._edge_out(best))
        return nodes, edges


# ============================================================================= cache
def _sync_limit() -> int:
    """Pools at or below this many events build the graph on the request thread (sub-second).
    Above it the build moves to a background thread and the request reports `status.state`."""
    try:
        return int(os.environ.get("IRIS_GRAPH_SYNC_MAX", DEFAULT_SYNC_LIMIT))
    except ValueError:
        return DEFAULT_SYNC_LIMIT


# One GraphBuilder per scope, keyed on the store version. `Store.graph_v2*` are the only callers;
# the whole point is that GET /api/graph never builds this on the request thread at pool scale.
GRAPH_CACHE = AsyncCache("graph", sync_limit=_sync_limit())
