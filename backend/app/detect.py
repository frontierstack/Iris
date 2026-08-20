"""Rule engine: Sigma-like built-in rules (simple predicates + windowed aggregates)."""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, replace
from typing import Callable, Iterable, Optional

import numpy as np

from .models import EMPTY_LIST, Detection, Event, max_sev
from .normalize import is_public_ip


@dataclass(frozen=True)
class Param:
    """One editable knob of a built-in's condition.

    Everything that decides whether a rule fires is one of these, so nothing about a built-in is a
    hidden constant: the event id, the status codes it counts, the burst threshold, the window, the byte
    cutoff, the regex. `kind` tells the UI what widget to draw and this module how to parse the string.
    `field` names the event field the value is compared against, when there is one, so the editor can
    say `EventID` rather than just `eventId`.
    """
    key: str
    label: str
    kind: str            # values | regex | text | int | seconds | bytes
    default: str
    field: str = ""
    help: str = ""


@dataclass(frozen=True)
class Rule:
    """A built-in rule.

    `description` and `trigger` are deliberately two different things, because conflating them is what
    made the rule editor confusing: an analyst read the condition in the description field, edited it,
    and nothing changed.

      description — what a hit MEANS and why it matters. Prose. Editable. Purely documentation:
                    changing it never changes what fires.
      trigger     — what the engine actually evaluates, in prose: the fields, values, regex, thresholds
                    and time windows. Generated from the shipped defaults, so read-only.
      mechanism   — how it decides: 'regex' | 'fields' | 'threshold' | 'correlation'. Drives the badge
                    in the editor so the flagging method is obvious at a glance.
      params      — every constant in that condition, as an editable parameter. This is what makes a
                    built-in customisable: the shape of the rule is Python, but each value it compares
                    against, counts to, or matches with is an override the analyst owns.
    """
    id: str
    name: str
    level: str
    description: str
    trigger: str = ""
    mechanism: str = "fields"
    params: tuple[Param, ...] = ()


# ------------------------------------------------------------ rule catalogue
R = {
    "WEB-0042": Rule(
        "SIGMA-WEB-0042", "Credential stuffing — burst of 401s", "high",
        description="Someone is guessing credentials at machine speed. One address collecting 401s in bulk is credential "
                    "stuffing or password spraying, not a user mistyping their password.",
        trigger="Counts nginx access events whose http.status is exactly 401, grouped by src_ip. Fires on the densest "
                "90-second window holding 50 or more, tagging the last event of that window.",
        mechanism="threshold"),
    "AUTH-0111": Rule(
        "SIGMA-AUTH-0111", "Successful auth after failure burst", "critical",
        description="The guessing worked. This is the moment the attacker got in — treat the account as compromised "
                    "from this timestamp onward.",
        trigger="A POST with a 2xx status whose http.path matches the login-path regex, coming from a src_ip that "
                "SIGMA-WEB-0042 already flagged, within 600 seconds of that burst.",
        mechanism="correlation"),
    "AUTH-0203": Rule(
        "SIGMA-AUTH-0203", "Service account interactive login", "high",
        description="Service accounts exist for machines to call APIs. A human-style sign-in on one means its "
                    "credentials leaked, or someone is hiding behind it.",
        trigger="user starts with svc_, svc-, sa_ or sa- on a successful login-path POST (path matched by the "
                "login-path regex) — or on a CloudTrail ConsoleLogin by a svc_/svc- principal.",
        mechanism="regex"),
    "WEB-0050": Rule(
        "SIGMA-WEB-0050", "Web scanner user-agent", "medium",
        description="An automated vulnerability scanner is mapping the site. Reconnaissance that normally precedes an "
                    "exploit attempt.",
        trigger="The user_agent field matches the scanner regex.",
        mechanism="regex"),
    "WEB-0058": Rule(
        "SIGMA-WEB-0058", "Web attack pattern in request path", "medium",
        description="The requested URI itself carries an exploit attempt: directory traversal, injection, or a probe "
                    "for a dropped webshell.",
        trigger="The http.path field matches the web-attack regex.",
        mechanism="regex"),
    "WEB-0063": Rule(
        "SIGMA-WEB-0063", "HTTP 5xx burst", "medium",
        description="The application is failing in bulk — either an outage worth knowing about, or an attack driving "
                    "it into errors.",
        trigger="Counts nginx events whose http.status starts with 5, grouped by the first 40 characters of http.path. "
                "Fires on a 60-second window holding 50 or more.",
        mechanism="threshold"),
    "AWS-0007": Rule(
        "SIGMA-AWS-0007", "Console login without MFA", "critical",
        description="A console sign-in protected by a password alone. If that password is stolen there is nothing left "
                    "standing between the attacker and the account.",
        trigger="CloudTrail eventName = ConsoleLogin with result = Success and MFAUsed = no.",
        mechanism="fields"),
    "AWS-0031": Rule(
        "SIGMA-AWS-0031", "Persistence — access key created", "critical",
        description="A long-lived API key was minted. That is persistence: it keeps working after the password is "
                    "reset and the session is revoked.",
        trigger="CloudTrail eventName = CreateAccessKey with result = Success. Escalated to critical when "
                "sourceIPAddress is a public address or is already flagged as an attacker this run.",
        mechanism="fields"),
    "AWS-0044": Rule(
        "SIGMA-AWS-0044", "Attempt to disable audit logging", "high",
        description="Someone is switching off the recording. Anti-forensics, and usually adjacent in time to whatever "
                    "they did not want recorded.",
        trigger="CloudTrail eventName is one of DeleteTrail, StopLogging, UpdateTrail, DeleteFlowLogs, "
                "PutEventSelectors, DeleteLogGroup.",
        mechanism="fields"),
    "AWS-0052": Rule(
        "SIGMA-AWS-0052", "IAM persistence — user/policy manipulation", "high",
        description="New identities or new privileges are appearing. The attacker is building a way back in that does "
                    "not depend on the account they entered with.",
        trigger="CloudTrail eventName is CreateUser, CreateLoginProfile or PutUserPolicy — or AttachUserPolicy where "
                "the raw event mentions AdministratorAccess.",
        mechanism="fields"),
    "AWS-0060": Rule(
        "SIGMA-AWS-0060", "Root account activity", "high",
        description="The root account should be sealed after setup and never used day to day. Every use of it needs an "
                    "explanation.",
        trigger="CloudTrail field userIdentity.type equals Root.",
        mechanism="fields"),
    "AWS-0071": Rule(
        "SIGMA-AWS-0071", "Security group opened to the world", "medium",
        description="A firewall hole to the entire internet — either a mistake, or deliberate exposure of something "
                    "that was private.",
        trigger="CloudTrail eventName = AuthorizeSecurityGroupIngress and the raw event contains the CIDR 0.0.0.0/0.",
        mechanism="fields"),
    "WIN-0088": Rule(
        "SIGMA-WIN-0088", "NTLM network logon", "medium",
        description="A network logon using legacy NTLM, which can be relayed and replayed. Common in lateral movement "
                    "between Windows hosts.",
        trigger="Security event 4624 where LogonType starts with 3 and AuthenticationPackageName / LmPackageName "
                "contain NTLM.",
        mechanism="fields"),
    "WIN-0091": Rule(
        "SIGMA-WIN-0091", "Sensitive privilege assignment", "high",
        description="An account was handed the privileges that let it read other processes' memory, bypass file "
                    "permissions and load drivers — the toolkit for credential theft.",
        trigger="Security event 4672 where PrivilegeList contains SeDebug, SeBackup, SeTakeOwnership, SeTcb, "
                "SeLoadDriver or SeRestore, and SubjectUserName is neither a system account nor a computer account "
                "(trailing $).",
        mechanism="fields"),
    "WIN-0104": Rule(
        "SIGMA-WIN-0104", "Audit log cleared", "high",
        description="The Windows security log was wiped. Whatever it held is gone — the wipe itself is now the "
                    "evidence.",
        trigger="Security event 1102.",
        mechanism="fields"),
    "WIN-0120": Rule(
        "SIGMA-WIN-0120", "Local user account created", "medium",
        description="A new local account appeared. A quiet way to keep access that survives a password reset on the "
                    "account originally used.",
        trigger="Security event 4720.",
        mechanism="fields"),
    "WIN-0133": Rule(
        "SIGMA-WIN-0133", "Suspicious process creation", "high",
        description="A command line matching known attacker tooling: encoded PowerShell, living-off-the-land binaries, "
                    "host recon, or credential dumping.",
        trigger="Security event 4688 where CommandLine joined with NewProcessName matches the suspicious-process "
                "regex.",
        mechanism="regex"),
    "WIN-0140": Rule(
        "SIGMA-WIN-0140", "Windows logon failure burst", "high",
        description="Repeated failed logons against Windows — brute force against one account, or spraying one "
                    "password across many.",
        trigger="Counts 4625 events grouped by IpAddress, falling back to TargetUserName when there is no IP. Fires on "
                "a 5-minute window holding 10 or more.",
        mechanism="threshold"),
    "WIN-0150": Rule(
        "SIGMA-WIN-0150", "Member added to privileged group", "high",
        description="Someone was added to an admin group. Straightforward privilege escalation, and easy to lose in "
                    "normal directory churn.",
        trigger="Security event 4728, 4732 or 4756 where TargetUserName names Administrators, Domain Admins, "
                "Enterprise Admins or Schema Admins.",
        mechanism="fields"),
    "LNX-0012": Rule(
        "SIGMA-LNX-0012", "Direct root SSH", "high",
        description="A root session opened directly over SSH. It skips the log in as yourself, then elevate path, so "
                    "nothing that follows can be attributed to a person.",
        trigger="syslog program = sshd with result = Accepted and user = root.",
        mechanism="fields"),
    "LNX-0030": Rule(
        "SIGMA-LNX-0030", "Anti-forensics — history cleared", "high",
        description="Shell history was truncated or removed. Someone is covering their tracks, and the commands they "
                    "ran are what is missing.",
        trigger="The raw line matches the history regex AND also shows a removal: auditd op of truncate/unlink/delete/"
                "rename, or wording like trunc, unlink, remov, rm, history -c or unset elsewhere in the line.",
        mechanism="regex"),
    "LNX-0041": Rule(
        "SIGMA-LNX-0041", "Sudo to interactive shell", "medium",
        description="sudo was used to open a shell rather than run one command. That converts a single audited action "
                    "into an unaudited root session.",
        trigger="syslog program = sudo and the raw line matches the interactive-shell regex.",
        mechanism="regex"),
    "LNX-0045": Rule(
        "SIGMA-LNX-0045", "SSH brute force", "medium",
        description="Sustained SSH password guessing against this host.",
        trigger="Counts sshd events with result Failed or Invalid, grouped by src_ip. Fires on a 5-minute window "
                "holding 10 or more.",
        mechanism="threshold"),
    "LNX-0050": Rule(
        "SIGMA-LNX-0050", "New local user added", "medium",
        description="A new local account on a Linux host — persistence that outlives the original entry point.",
        trigger="syslog program is useradd or adduser, or the raw line matches the useradd regex.",
        mechanism="regex"),
    "K8S-0004": Rule(
        "SIGMA-K8S-0004", "Interactive exec into pod", "critical",
        description="Someone opened a shell inside a running container. That bypasses the deployment pipeline "
                    "entirely, so nothing they change exists in source control.",
        trigger="Audit event with resource = pods/exec and verb = create. Escalated to critical when the namespace or "
                "host mentions prod, prd, payments or live.",
        mechanism="fields"),
    "K8S-0011": Rule(
        "SIGMA-K8S-0011", "Secrets enumeration", "medium",
        description="A non-system identity is reading cluster secrets. Credential harvesting, whether or not the "
                    "identity is supposed to have the permission.",
        trigger="resource = secrets with verb list or get, by a user whose name does not start with system:.",
        mechanism="fields"),
    "K8S-0017": Rule(
        "SIGMA-K8S-0017", "Privileged / hostPath pod created", "high",
        description="A pod was created that can escape to the node it runs on — privileged mode or a mount of the "
                    "host filesystem.",
        trigger='resource = pods, verb = create, and the raw request contains "privileged":true or hostPath.',
        mechanism="fields"),
    "K8S-0025": Rule(
        "SIGMA-K8S-0025", "Kubernetes RBAC denial burst", "medium",
        description="One identity is repeatedly hitting permission denials — probing the cluster to find what it can "
                    "reach.",
        trigger="Counts audit events with responseStatus = 403, grouped by user. Fires on a 5-minute window holding 5 "
                "or more.",
        mechanism="threshold"),
    "APP-0055": Rule(
        "SIGMA-APP-0055", "Mass data export", "critical",
        description="A bulk export of records. This is the shape of data theft rather than of normal application use.",
        trigger="An app JSONL event whose event or action field mentions export, dump or download, and whose rows, "
                "row_count or records field is 10,000 or more.",
        mechanism="fields"),
    "APP-0061": Rule(
        "SIGMA-APP-0061", "Application authentication failure burst", "medium",
        description="The application itself is reporting repeated auth failures — guessing against a path the web "
                    "tier may never see.",
        trigger="Counts app events whose msg matches the auth-failure regex, grouped by host. Fires on a 5-minute "
                "window holding 20 or more.",
        mechanism="threshold"),
    "NET-0019": Rule(
        "SIGMA-NET-0019", "Outbound to known-bad IP", "high",
        description="An internal host is talking out to an address that already attacked you. Usually a callback from "
                    "something that got in.",
        trigger="An allowed firewall flow whose dst is an IP already flagged during this run — by a 401 burst, "
                "scanner UA, SSH brute force, 4625 burst or port scan.",
        mechanism="correlation"),
    "NET-0022": Rule(
        "SIGMA-NET-0022", "Large outbound transfer", "critical",
        description="A large one-shot transfer out to the internet. In an intrusion timeline this is the exfiltration "
                    "step.",
        trigger="An allowed flow to a public dst whose bytes reach the larger of 100 MB or 50× that source host's p99 "
                "flow size (the p99 is only computed for hosts with 20 or more flows).",
        mechanism="threshold"),
    "NET-0027": Rule(
        "SIGMA-NET-0027", "Port scan / firewall deny burst", "medium",
        description="One source is being denied at volume — a port scan or sweep against the perimeter.",
        trigger="Counts firewall events with action deny, drop, reject or block, grouped by src. Fires on a 60-second "
                "window holding 50 or more.",
        mechanism="threshold"),
}

RULES: list[Rule] = list(R.values())

_SCANNER_UA = re.compile(r"sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|wpscan|nuclei|acunetix", re.I)
_ATTACK_PATH = re.compile(r"\.\./|/etc/passwd|cmd=|;wget|;curl|\bunion\b.*\bselect\b|<script|\.php\?|/wp-login|/\.env|/\.git/", re.I)
_SUSP_PROC = re.compile(r"powershell.*(-enc|-e |downloadstring|iex|frombase64)|certutil.*(-urlcache|-decode)|mimikatz|procdump|"
                        r"whoami|net\s+user\s+\S+\s+/add|net\s+localgroup\s+administrators|wmic.*process\s+call\s+create|"
                        r"rundll32.*comsvcs|vssadmin.*delete|bitsadmin|mshta|regsvr32.*/i:http|ntdsutil|reg\s+save\s+hklm\\sam", re.I)
_HISTORY = re.compile(r"\.bash_history|\.zsh_history|history\s+-c|unset\s+HISTFILE|HISTFILESIZE=0|HISTSIZE=0", re.I)
_HISTORY_REMOVAL = re.compile(r"trunc|unlink|remov|rm |history -c|unset", re.I)
_SHELL = re.compile(r"COMMAND=(?:/usr)?/bin/(?:ba|z|da)?sh\b|COMMAND=/bin/su\b|COMMAND=(?:/usr)?/bin/su\b", re.I)
_USERADD = re.compile(r"\b(useradd|adduser)\b.*(new user|name=|:\s+\S+)", re.I)
_LOGIN_PATH = re.compile(r"/(login|signin|sign-in|auth|authenticate|session|token|oauth/token)\b", re.I)
_AUTH_FAIL = re.compile(r"(login|auth|authentication|password).*(fail|invalid|denied|rejected)|invalid (credentials|password)|auth(entication)? failure", re.I)

# ------------------------------------------------------------ editable condition parameters
# Every constant that decides whether a built-in fires lives here rather than inline in run_rules, so
# an analyst can retune any of them from the rule editor. run_rules reads them through _pl/_pn/_pt/_prx,
# which fall back to these defaults whenever the analyst has not overridden the parameter.
P = Param
PARAMS: dict[str, tuple[Param, ...]] = {
    "SIGMA-WEB-0042": (
        P("statuses", "Status codes counted", "values", "401", "http.status", "Exact HTTP status codes treated as a failed login."),
        P("window", "Time window", "seconds", "90", "", "Length of the sliding window the events are counted in."),
        P("threshold", "Events to fire", "int", "50", "", "How many must land inside one window before the rule fires."),
    ),
    "SIGMA-AUTH-0111": (
        P("loginPath", "Login path", "regex", _LOGIN_PATH.pattern, "http.path", "Which request paths count as a login attempt."),
        P("methods", "HTTP methods", "values", "POST", "http.method", "Methods that count as a login submission."),
        P("successPrefix", "Success status starts with", "text", "2", "http.status", "Status prefix treated as a successful login."),
        P("within", "Look back", "seconds", "600", "", "How long after the failure burst a success still counts as related."),
    ),
    "SIGMA-AUTH-0203": (
        P("prefixes", "Service account prefixes", "values", "svc_, svc-, sa_, sa-", "user", "Username prefixes treated as service accounts (prefix match)."),
        P("loginPath", "Login path", "regex", _LOGIN_PATH.pattern, "http.path", "Which request paths count as an interactive login."),
    ),
    "SIGMA-WEB-0050": (
        P("pattern", "Scanner user-agent", "regex", _SCANNER_UA.pattern, "user_agent", "Matched against the user-agent of every web request."),
    ),
    "SIGMA-WEB-0058": (
        P("pattern", "Attack pattern", "regex", _ATTACK_PATH.pattern, "http.path", "Matched against the request path of every web request."),
    ),
    "SIGMA-WEB-0063": (
        P("statusPrefix", "Status starts with", "text", "5", "http.status", "Status prefix counted as a server error."),
        P("window", "Time window", "seconds", "60", "", "Length of the sliding window the errors are counted in."),
        P("threshold", "Events to fire", "int", "50", "", "How many errors inside one window before the rule fires."),
    ),
    "SIGMA-AWS-0007": (
        P("eventName", "CloudTrail event", "text", "ConsoleLogin", "eventName", "Exact eventName that must match."),
        P("mfaValue", "MFAUsed equals", "text", "no", "MFAUsed", "Value of MFAUsed that means no second factor was presented."),
        P("result", "Result equals", "text", "success", "result", "Only successful logins are flagged."),
    ),
    "SIGMA-AWS-0031": (
        P("eventName", "CloudTrail event", "text", "CreateAccessKey", "eventName", "Exact eventName that must match."),
    ),
    "SIGMA-AWS-0044": (
        P("eventNames", "CloudTrail events", "values", "DeleteTrail, StopLogging, UpdateTrail, DeleteFlowLogs, PutEventSelectors, DeleteLogGroup",
          "eventName", "Any one of these eventNames fires the rule."),
    ),
    "SIGMA-AWS-0052": (
        P("eventNames", "CloudTrail events", "values", "CreateUser, CreateLoginProfile, PutUserPolicy", "eventName", "Any one of these eventNames fires the rule."),
        P("policyEvent", "Policy-attach event", "text", "AttachUserPolicy", "eventName", "Only flagged when the raw event also mentions the policy marker below."),
        P("policyMarker", "Policy marker", "text", "AdministratorAccess", "raw", "Substring searched for in the raw event body."),
    ),
    "SIGMA-AWS-0060": (
        P("identityType", "Identity type equals", "text", "Root", "userIdentity.type", "Exact value of userIdentity.type that fires the rule."),
    ),
    "SIGMA-AWS-0071": (
        P("eventName", "CloudTrail event", "text", "AuthorizeSecurityGroupIngress", "eventName", "Exact eventName that must match."),
        P("cidrs", "Open CIDRs", "values", "0.0.0.0/0", "raw", "Any of these appearing in the raw event body counts as open to the world."),
    ),
    "SIGMA-WIN-0088": (
        P("eventId", "Event ID", "text", "4624", "EventID", "Windows Security event id."),
        P("logonTypes", "Logon types", "values", "3", "LogonType", "Logon types that count (prefix match, so 3 covers 3.x)."),
        P("packages", "Auth packages", "values", "NTLM", "AuthenticationPackageName", "Authentication packages that count (substring, case-insensitive)."),
    ),
    "SIGMA-WIN-0091": (
        P("eventId", "Event ID", "text", "4672", "EventID", "Windows Security event id."),
        P("privileges", "Sensitive privileges", "values",
          "SeDebugPrivilege, SeBackupPrivilege, SeTakeOwnershipPrivilege, SeTcbPrivilege, SeLoadDriverPrivilege, SeRestorePrivilege",
          "PrivilegeList", "Any one of these in PrivilegeList fires the rule."),
        P("ignoreAccounts", "Ignored accounts", "values", "system, local service, network service, anonymous logon, -", "SubjectUserName",
          "Accounts never flagged. Computer accounts (trailing $) are always ignored."),
    ),
    "SIGMA-WIN-0104": (
        P("eventId", "Event ID", "text", "1102", "EventID", "Windows Security event id for 'audit log cleared'."),
    ),
    "SIGMA-WIN-0120": (
        P("eventId", "Event ID", "text", "4720", "EventID", "Windows Security event id for 'user account created'."),
    ),
    "SIGMA-WIN-0133": (
        P("eventId", "Event ID", "text", "4688", "EventID", "Windows Security event id for 'process created'."),
        P("pattern", "Suspicious command line", "regex", _SUSP_PROC.pattern, "CommandLine", "Matched against CommandLine joined with NewProcessName."),
    ),
    "SIGMA-WIN-0140": (
        P("eventId", "Event ID", "text", "4625", "EventID", "Windows Security event id for 'logon failed'."),
        P("window", "Time window", "seconds", "300", "", "Length of the sliding window the failures are counted in."),
        P("threshold", "Events to fire", "int", "10", "", "How many failures inside one window before the rule fires."),
    ),
    "SIGMA-WIN-0150": (
        P("eventIds", "Event IDs", "values", "4728, 4732, 4756", "EventID", "Group-membership-added events."),
        P("groups", "Privileged groups", "values", "administrators, domain admins, enterprise admins, schema admins", "TargetUserName",
          "Substring match, case-insensitive, against the group being added to."),
    ),
    "SIGMA-LNX-0012": (
        P("program", "Program", "text", "sshd", "program", "syslog program that must match."),
        P("result", "Result equals", "text", "Accepted", "result", "Only successful logins are flagged."),
        P("users", "Users", "values", "root", "user", "Accounts whose direct SSH login is flagged."),
    ),
    "SIGMA-LNX-0030": (
        P("pattern", "History markers", "regex", _HISTORY.pattern, "raw", "Identifies a line as being about shell history."),
        P("removalPattern", "Removal markers", "regex", _HISTORY_REMOVAL.pattern, "raw",
          "A history line only fires if it ALSO shows a removal. Used for non-auditd lines."),
        P("auditOps", "auditd operations", "values", "truncate, unlink, delete, rename", "op", "Which auditd ops count as a removal."),
    ),
    "SIGMA-LNX-0041": (
        P("program", "Program", "text", "sudo", "program", "syslog program that must match."),
        P("pattern", "Interactive shell", "regex", _SHELL.pattern, "raw", "Matched against the raw sudo line."),
    ),
    "SIGMA-LNX-0045": (
        P("program", "Program", "text", "sshd", "program", "syslog program that must match."),
        P("results", "Failure results", "values", "Failed, Invalid", "result", "Results counted as a failed login."),
        P("window", "Time window", "seconds", "300", "", "Length of the sliding window the failures are counted in."),
        P("threshold", "Events to fire", "int", "10", "", "How many failures inside one window before the rule fires."),
    ),
    "SIGMA-LNX-0050": (
        P("programs", "Programs", "values", "useradd, adduser", "program", "syslog programs that always fire the rule."),
        P("pattern", "User-add markers", "regex", _USERADD.pattern, "raw", "Also fires when the raw line matches this, whatever the program."),
    ),
    "SIGMA-K8S-0004": (
        P("resource", "Resource", "text", "pods/exec", "resource", "Audit resource that must match."),
        P("verb", "Verb", "text", "create", "verb", "Audit verb that must match."),
        P("prodKeywords", "Production markers", "values", "prod, payments, prd, live", "namespace",
          "Namespace or host containing any of these escalates the hit to critical."),
    ),
    "SIGMA-K8S-0011": (
        P("resource", "Resource", "text", "secrets", "resource", "Audit resource that must match."),
        P("verbs", "Verbs", "values", "list, get", "verb", "Audit verbs that count as enumeration."),
        P("ignoreUserPrefix", "Ignore users starting with", "text", "system:", "user", "Principals excluded as cluster-internal."),
    ),
    "SIGMA-K8S-0017": (
        P("resource", "Resource", "text", "pods", "resource", "Audit resource that must match."),
        P("verb", "Verb", "text", "create", "verb", "Audit verb that must match."),
        P("markers", "Escape markers", "values", '"privileged":true, "hostPath"', "raw",
          "Any of these in the raw request means the pod can reach the node. Whitespace is stripped before comparing."),
    ),
    "SIGMA-K8S-0025": (
        P("status", "Response status", "text", "403", "responseStatus", "Status counted as an RBAC denial."),
        P("window", "Time window", "seconds", "300", "", "Length of the sliding window the denials are counted in."),
        P("threshold", "Events to fire", "int", "5", "", "How many denials inside one window before the rule fires."),
    ),
    "SIGMA-APP-0055": (
        P("keywords", "Export keywords", "values", "export, dump, download", "event", "Substring match against the event/action field."),
        P("minRows", "Minimum rows", "int", "10000", "rows", "Row count at or above which the export is flagged."),
    ),
    "SIGMA-APP-0061": (
        P("pattern", "Auth failure", "regex", _AUTH_FAIL.pattern, "msg", "Matched against the normalized message to decide what gets counted."),
        P("window", "Time window", "seconds", "300", "", "Length of the sliding window the failures are counted in."),
        P("threshold", "Events to fire", "int", "20", "", "How many failures inside one window before the rule fires."),
    ),
    "SIGMA-NET-0019": (
        P("allowActions", "Allow actions", "values", "allow, accept, permit, allowed, pass", "action", "Firewall actions that mean the flow went through."),
    ),
    "SIGMA-NET-0022": (
        P("allowActions", "Allow actions", "values", "allow, accept, permit, allowed, pass", "action", "Firewall actions that mean the flow went through."),
        P("minBytes", "Minimum transfer", "bytes", "104857600", "bytes", "Absolute floor - a flow this large is flagged whatever the host's baseline."),
        P("p99Multiplier", "Baseline multiplier", "int", "50", "", "Also flagged at this many times the source host's p99 flow size."),
        P("p99MinFlows", "Flows needed for a baseline", "int", "20", "", "Below this, the host has no p99 and only the absolute floor applies."),
    ),
    "SIGMA-NET-0027": (
        P("denyActions", "Deny actions", "values", "deny, drop, reject, block, denied, blocked", "action", "Firewall actions that mean the flow was refused."),
        P("window", "Time window", "seconds", "60", "", "Length of the sliding window the denials are counted in."),
        P("threshold", "Events to fire", "int", "50", "", "How many denials inside one window before the rule fires."),
    ),
}
del P
R = {k: replace(v, params=PARAMS.get(v.id, ())) for k, v in R.items()}
RULES = list(R.values())

_SYSTEM_ACCOUNTS = {"system", "local service", "network service", "anonymous logon", "-", ""}

# Which regex each built-in matches with, and against what — derived from the regex parameters above so
# the two can never drift apart. Surfaced in the rule drawer and editable there.
RULE_PATTERNS: dict[str, list[tuple[str, str]]] = {
    rid: [(p.field or "raw", p.default) for p in ps if p.kind == "regex"]
    for rid, ps in PARAMS.items() if any(p.kind == "regex" for p in ps)
}


def param_spec(rule_id: str, key: str) -> Optional[Param]:
    return next((p for p in PARAMS.get(rule_id, ()) if p.key == key), None)


def parse_param(spec: Param, raw: str) -> str:
    """Validate an analyst-supplied value for `spec` and return it normalized. Raises ValueError.

    Kept here rather than in the router so the rules store, the API and the engine all agree on what a
    legal value is — a parameter that stores but cannot be parsed at match time would silently disable
    the rule it belongs to.
    """
    v = (raw or "").strip()
    if not v:
        raise ValueError("value is required")
    if spec.kind == "regex":
        if len(v) > 2000:
            raise ValueError("regex too long (max 2000 characters)")
        try:
            re.compile(v)
        except re.error as exc:
            raise ValueError(f"invalid regex: {exc}") from exc
        return v
    if spec.kind in ("int", "seconds", "bytes"):
        try:
            n = int(float(v.replace(",", "").replace("_", "")))
        except ValueError:
            raise ValueError("must be a whole number") from None
        if n <= 0:
            raise ValueError("must be greater than zero")
        if spec.kind == "seconds" and n > 86400 * 7:
            raise ValueError("window cannot exceed 7 days")
        return str(n)
    if spec.kind == "values":
        parts = [x.strip() for x in v.split(",") if x.strip()]
        if not parts:
            raise ValueError("give at least one value, comma separated")
        return ", ".join(parts)
    return v


# ------------------------------------------------------------ composable conditions (custom rules)
# A built-in's condition is Python whose constants are Params. A custom rule can now be composed the other
# way round: the analyst picks the field, the operator and the value, and each value is validated with the
# very same typed machinery (Param + parse_param) rather than a parallel one — the operator decides the kind.
CONDITION_OPS: dict[str, tuple[str, str]] = {
    # op: (kind for Param/parse_param — "" means the operator takes no value, phrasing for the trigger)
    "equals": ("text", "equals"),
    "not_equals": ("text", "does not equal"),
    "contains": ("text", "contains"),
    "not_contains": ("text", "does not contain"),
    "starts_with": ("text", "starts with"),
    "ends_with": ("text", "ends with"),
    "regex": ("regex", "matches the regex"),
    "in": ("values", "is one of"),
    "not_in": ("values", "is none of"),
    "gt": ("int", "is greater than"),
    "lt": ("int", "is less than"),
    "exists": ("", "is present"),
}
# Negative operators are true when the field is absent, exactly like `NOT field:value` in the search DSL.
_NEGATIVE_OPS = {"not_equals", "not_contains", "not_in"}
# Fields the condition builder offers by name; anything else is looked up in Event.fields (case-insensitive),
# so a parser-specific key like http.status or EventID works without being enumerated here.
CONDITION_FIELDS: tuple[str, ...] = ("msg", "raw", "host", "user", "source", "file", "id", "ts", "sev",
                                     "detection", "entity")
MAX_CONDITIONS = 20


def condition_param(op: str, field: str = "", label: str = "") -> Param:
    """The Param spec that types one condition's value — the same object the built-in editor uses."""
    kind = CONDITION_OPS.get(op, ("text", ""))[0] or "text"
    return Param(key="value", label=label or f"{field or 'field'} {CONDITION_OPS.get(op, ('', op))[1]}",
                 kind=kind, default="", field=field,
                 help="Value this condition compares the field against.")


def parse_condition(field: str, op: str, value: str) -> tuple[str, str, str]:
    """Validate one (field, operator, value) triple and return it normalized. Raises ValueError.

    Used at save time (→ HTTP 400) and again on load, so a value that cannot be parsed can never reach the
    matcher and silently switch a rule off.
    """
    f = (field or "").strip()
    if not f:
        raise ValueError("field is required")
    if len(f) > 120:
        raise ValueError("field name is too long")
    o = (op or "").strip()
    if o not in CONDITION_OPS:
        raise ValueError(f"unknown operator '{op}'")
    if o == "exists":
        return f, o, ""
    v = (value or "").strip()
    if not v:
        raise ValueError("value is required")
    if o in ("gt", "lt"):
        # numeric comparison: 0 and negatives are legitimate here, so this is a plain number check rather
        # than parse_param's "int" (which is a positive count/threshold).
        try:
            n = float(v.replace(",", "").replace("_", ""))
        except ValueError:
            raise ValueError("must be a number") from None
        return f, o, str(int(n)) if n.is_integer() else str(n)
    return f, o, parse_param(condition_param(o, f), v)


def condition_values(e: Event, field: str) -> list[str]:
    """Every string a condition's field can be compared against, using the search DSL's field vocabulary."""
    from .query import FIELD_ALIASES  # local import: query only depends on models, so no cycle at import time

    f = FIELD_ALIASES.get((field or "").strip().lower(), (field or "").strip())
    fl = f.lower()
    if fl in ("msg", "raw", "host", "user", "source", "file", "id", "ts", "sev"):
        return [str(getattr(e, fl, "") or "")]
    if fl in ("detection", "rule", "sigma"):
        return [x for d in e.detections for x in (d.id, d.name)]
    if fl in ("_entity", "entity", "entities"):
        return list(e.entities)
    if fl == "_ip":
        return list(e.entities) + [e.fields.get(k, "") for k in ("src_ip", "src", "dst", "sourceIPAddress", "IpAddress")]
    val = e.fields.get(f)
    if val is None:
        for k, x in e.fields.items():
            if k.lower() == fl:
                val = x
                break
    return [val] if val is not None else []


def condition_pred(field: str, op: str, value: str) -> Callable[[Event], bool]:
    """Compile one validated condition into a predicate. Comparisons are case-insensitive."""
    v = (value or "").strip()
    lv = v.lower()
    parts = tuple(x.strip().lower() for x in v.split(",") if x.strip())
    rx: Optional["re.Pattern[str]"] = None
    if op == "regex":
        rx = re.compile(v, re.I)  # already validated by parse_condition; a bad one never gets this far
    num: Optional[float] = None
    if op in ("gt", "lt"):
        num = float(v.replace(",", "").replace("_", ""))

    def as_num(s: str) -> Optional[float]:
        try:
            return float(s.strip().replace(",", "").replace("_", ""))
        except ValueError:
            return None

    def pred(e: Event) -> bool:
        vals = [x for x in condition_values(e, field) if x != ""]
        if not vals:
            # an absent field satisfies a negative condition, matching `NOT field:value` in the search DSL
            return op in _NEGATIVE_OPS
        low = [x.lower() for x in vals]
        if op == "exists":
            return True
        if op == "equals":
            return any(x == lv for x in low)
        if op == "not_equals":
            return all(x != lv for x in low)
        if op == "contains":
            return any(lv in x for x in low)
        if op == "not_contains":
            return all(lv not in x for x in low)
        if op == "starts_with":
            return any(x.startswith(lv) for x in low)
        if op == "ends_with":
            return any(x.endswith(lv) for x in low)
        if op == "regex":
            return any(rx.search(x) for x in vals)  # type: ignore[union-attr]
        if op == "in":
            return any(x in parts for x in low)
        if op == "not_in":
            return all(x not in parts for x in low)
        if op in ("gt", "lt"):
            for x in vals:
                n = as_num(x)
                if n is None:
                    continue
                if (op == "gt" and n > num) or (op == "lt" and n < num):  # type: ignore[operator]
                    return True
            return False
        return False

    return pred


def conditions_trigger(conditions: Iterable[tuple[str, str, str]], combinator: str = "and",
                       threshold: Optional[tuple[int, int, str]] = None, source_filter: str = "") -> str:
    """The TRIGGER for a condition-built rule: what the engine evaluates, in words.

    Generated, read-only and served as `Rule.logic` — deliberately not the analyst-editable `description`.
    """
    rows = []
    for f, o, v in conditions:
        phrase = CONDITION_OPS.get(o, ("", o))[1]
        rows.append(f"{f} {phrase}" if o == "exists" else f"{f} {phrase} \"{v}\"")
    if not rows:
        return ""
    joiner = " AND " if (combinator or "and").lower() != "or" else " OR "
    where = joiner.join(rows)
    scope = f" in sources matching \"{source_filter}\"" if source_filter else ""
    if threshold:
        count, window, group_by = threshold
        grouped = f" grouped by {group_by}" if group_by else " across the whole case"
        return (f"Counts events{scope} where {where}{grouped}. Fires on the densest {window}-second window "
                f"holding {count} or more, tagging the last event of that window.")
    return f"Flags every event{scope} where {where}."


def regex_trigger(field: str, pattern: str, source_filter: str = "") -> str:
    """The TRIGGER for a plain regex custom rule — same read-only contract as a built-in's."""
    where = "the message, raw line, host, user and parsed fields" if (field or "any") == "any" else f"the {field} field"
    scope = f", limited to sources matching \"{source_filter}\"" if source_filter else ""
    return f"Flags every event where {where} matches the regex {pattern}{scope}."


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} TB"


_DISABLED: set[str] = set()  # built-in rule ids switched off via /api/rules (set per run_rules call)
_OVERRIDES: dict[str, dict] = {}  # {rule_id: {"name":…, "sev":…}} analyst edits to built-in metadata
_PARAMS: dict[str, dict[str, str]] = {}  # {rule_id: {param key: value}} analyst-tuned condition
_RX_CACHE: dict[tuple[str, str, str], "re.Pattern[str]"] = {}  # compiled regex params, keyed by their text


# ---- parameter accessors. Each falls back to the shipped default, so a missing or unparsable override
#      degrades to stock behaviour instead of silently switching the rule off.
def _praw(rule_id: str, key: str) -> str:
    ov = _PARAMS.get(rule_id, {}).get(key)
    if isinstance(ov, str) and ov.strip():
        return ov.strip()
    spec = param_spec(rule_id, key)
    return spec.default if spec else ""


def _pt(rule_id: str, key: str) -> str:
    """A single literal value."""
    return _praw(rule_id, key)


def _pl(rule_id: str, key: str, lower: bool = True) -> tuple[str, ...]:
    """A comma-separated list, lower-cased by default for case-insensitive comparison."""
    parts = [x.strip() for x in _praw(rule_id, key).split(",") if x.strip()]
    return tuple(x.lower() for x in parts) if lower else tuple(parts)


def _pn(rule_id: str, key: str) -> int:
    try:
        return int(float(_praw(rule_id, key).replace(",", "").replace("_", "")))
    except ValueError:
        spec = param_spec(rule_id, key)
        return int(spec.default) if spec else 0


def _prx(rule_id: str, key: str, fallback: "re.Pattern[str]") -> "re.Pattern[str]":
    """The regex a built-in should match with: the analyst's override if it compiles, else the shipped one."""
    text = _praw(rule_id, key)
    if not text or text == fallback.pattern:
        return fallback
    ck = (rule_id, key, text)
    hit = _RX_CACHE.get(ck)
    if hit is not None:
        return hit
    try:
        rx = re.compile(text, re.I)
    except re.error:
        return fallback
    _RX_CACHE[ck] = rx
    return rx


def _tag(ev: Event, rule: Rule, level: Optional[str] = None) -> None:
    if rule.id in _DISABLED:
        return
    ov = _OVERRIDES.get(rule.id)
    # an analyst-set severity wins over the shipped one, including over a per-call escalation
    lvl = (ov or {}).get("sev") or level or rule.level
    name = (ov or {}).get("name") or rule.name
    if any(d.id == rule.id for d in ev.detections):
        return
    ev.add_detection(Detection(name=name, id=rule.id, level=lvl))  # type: ignore[arg-type]
    ev.sev = max_sev(ev.sev, lvl)  # type: ignore[assignment]


_FAMILIES = ("nginx.access", "windows.evtx", "syslog", "k8s.audit", "app.jsonl")
_NET_FAMILIES = ("firewall", "delimited", "netflow", "fw")


def find_bursts(idx: Iterable[int], ts: np.ndarray, key_of: Callable[[int], str], window_s: float, threshold: int) -> list[tuple[str, int, int, int]]:
    """Group event indices by key and find windows of ≥threshold events within window_s.

    Returns (key, anchor_index, count, first_index) with the anchor being the last event of the densest window.
    """
    groups: dict[str, list[int]] = defaultdict(list)
    for i in idx:
        k = key_of(i)
        if k:
            groups[k].append(i)
    out: list[tuple[str, int, int, int]] = []
    for key, members in groups.items():
        if len(members) < threshold:
            continue
        arr = np.asarray(members)
        t = ts[arr]
        order = np.argsort(t, kind="stable")
        arr, t = arr[order], t[order]
        # The sliding window, without the Python loop. `j[k]` is the first index whose timestamp is
        # within `window_s` of t[k] — exactly what `while t[k] - t[j] > window_s: j += 1` converges to,
        # because t is sorted. argmax then picks the EARLIEST densest window, like `count > best[1]`.
        j = np.searchsorted(t, t - window_s, side="left")
        counts = np.arange(t.shape[0]) - j + 1
        k = int(counts.argmax())
        if int(counts[k]) >= threshold:
            out.append((key, int(arr[k]), int(counts[k]), int(arr[int(j[k])])))
    return out


def run_rules(events: list[Event], ts: np.ndarray, disabled: Optional[set[str]] = None,
              overrides: Optional[dict[str, dict]] = None,
              params: Optional[dict[str, dict[str, str]]] = None) -> dict[str, object]:
    """Evaluate all built-in rules over the events (in-place). Returns summary info (attacker IPs, fired count).

    `disabled` = built-in rule ids that must not fire (toggled off or removed in /api/rules).
    `overrides` = {rule_id: {"name","sev"}} analyst edits applied to the detections this run produces.
    `params`    = {rule_id: {param key: value}} analyst-tuned CONDITIONS. Every threshold, window, event
                  id, value list and regex below is read from here, falling back to the shipped default.
    """
    global _DISABLED, _OVERRIDES, _PARAMS
    _DISABLED = set(disabled or ())
    _OVERRIDES = dict(overrides or {})
    _PARAMS = {k: dict(v) for k, v in (params or {}).items()}
    for ev in events:
        if ev.detections:  # only pay the assignment where there IS a value; empty means the shared list
            ev.detections = EMPTY_LIST
    n = len(events)
    if n == 0:
        return {"fired": 0, "attackers": set(), "rules_evaluated": len(RULES)}
    attackers: dict[str, str] = {}  # ip -> reason
    # ONE pass to bucket events by family. This was six separate `[i for i in range(n) if fam[i] == …]`
    # comprehensions over the whole pool plus the `fam` list itself — seven walks of 1.2 M events before
    # a single rule had been evaluated.
    fam_of: dict[str, list[int]] = {k: [] for k in _FAMILIES}
    ct: list[int] = []
    net: list[int] = []
    for i, e in enumerate(events):
        bucket = fam_of.get(e.source)
        if bucket is not None:
            bucket.append(i)
        elif e.source == "aws.cloudtrail":
            ct.append(i)
        elif e.source.startswith(_NET_FAMILIES):
            net.append(i)
    web = fam_of["nginx.access"]
    # --- WEB-0042: 401 bursts per src ip
    w42_statuses = _pl("SIGMA-WEB-0042", "statuses")
    for ip, anchor, count, first in find_bursts(
        (i for i in web if events[i].fields.get("http.status", "").lower() in w42_statuses), ts,
            lambda i: events[i].fields.get("src_ip", ""), _pn("SIGMA-WEB-0042", "window"), _pn("SIGMA-WEB-0042", "threshold")):
        ev = events[anchor]
        _tag(ev, R["WEB-0042"])
        ev.set_field("burst.count", str(count))
        ev.set_field("burst.window", f"{_pn('SIGMA-WEB-0042', 'window')}s")
        span = max(1, int(round(ts[anchor] - ts[first])))
        m = ev.fields.get("http.method", "-")
        p = ev.fields.get("http.path", "")
        ev.msg = f"{m} {p} 401 — {count} attempts in {span}s from {ip}"
        attackers[ip] = "401 burst"
    # --- WEB-0050 / WEB-0058 / AUTH-0203 / AUTH-0111
    burst_anchor_ts: dict[str, list[float]] = defaultdict(list)
    for i in web:
        e = events[i]
        if e.detections and e.detections[0].id == R["WEB-0042"].id:
            burst_anchor_ts[e.fields.get("src_ip", "")].append(float(ts[i]))
    a111_methods = _pl("SIGMA-AUTH-0111", "methods")
    a111_prefix = _pt("SIGMA-AUTH-0111", "successPrefix")
    a111_within = _pn("SIGMA-AUTH-0111", "within")
    a203_prefixes = tuple(_pl("SIGMA-AUTH-0203", "prefixes"))
    # Resolved ONCE. Called inside the loop these went through _prx -> _praw -> param_spec for every
    # event: 1.8 M dict walks before any matching happened, 14 % of the whole detection pass.
    rx_scanner = _prx("SIGMA-WEB-0050", "pattern", _SCANNER_UA)
    rx_attack_path = _prx("SIGMA-WEB-0058", "pattern", _ATTACK_PATH)
    rx_login_111 = _prx("SIGMA-AUTH-0111", "loginPath", _LOGIN_PATH)
    rx_login_203 = _prx("SIGMA-AUTH-0203", "loginPath", _LOGIN_PATH)
    for i in web:
        e = events[i]
        ua = e.fields.get("user_agent", "")
        if ua and rx_scanner.search(ua):
            _tag(e, R["WEB-0050"])
            attackers.setdefault(e.fields.get("src_ip", ""), "scanner")
        path = e.fields.get("http.path", "")
        if path and rx_attack_path.search(path):
            _tag(e, R["WEB-0058"])
        st = e.fields.get("http.status", "")
        if st.startswith(a111_prefix) and rx_login_111.search(path) \
                and e.fields.get("http.method", "").lower() in a111_methods:
            ip = e.fields.get("src_ip", "")
            prior = burst_anchor_ts.get(ip)
            if prior and any(0 <= ts[i] - t0 <= a111_within for t0 in prior):
                _tag(e, R["AUTH-0111"])
                e.msg = f"{e.fields.get('http.method', 'POST')} {path} {st} — first success from {ip}"
                e.set_field_default("mfa", "not_presented")
            if a203_prefixes and e.user.lower().startswith(a203_prefixes) \
                    and rx_login_203.search(path):
                _tag(e, R["AUTH-0203"])
    w63_prefix = _pt("SIGMA-WEB-0063", "statusPrefix")
    for _, anchor, count, first in find_bursts(
        (i for i in web if events[i].fields.get("http.status", "").startswith(w63_prefix)), ts,
            lambda i: events[i].fields.get("http.path", "/")[:40], _pn("SIGMA-WEB-0063", "window"), _pn("SIGMA-WEB-0063", "threshold")):
        _tag(events[anchor], R["WEB-0063"])
        events[anchor].set_field("burst.count", str(count))

    # --- CloudTrail
    a7_name, a7_mfa, a7_result = _pt("SIGMA-AWS-0007", "eventName"), _pt("SIGMA-AWS-0007", "mfaValue").lower(), _pt("SIGMA-AWS-0007", "result").lower()
    a31_name = _pt("SIGMA-AWS-0031", "eventName")
    a44_names = _pl("SIGMA-AWS-0044", "eventNames")
    a52_names, a52_policy_ev, a52_marker = _pl("SIGMA-AWS-0052", "eventNames"), _pt("SIGMA-AWS-0052", "policyEvent").lower(), _pt("SIGMA-AWS-0052", "policyMarker")
    a60_type = _pt("SIGMA-AWS-0060", "identityType")
    a71_name, a71_cidrs = _pt("SIGMA-AWS-0071", "eventName"), _pl("SIGMA-AWS-0071", "cidrs", lower=False)
    for i in ct:
        e = events[i]
        name = e.fields.get("eventName", "")
        ip = e.fields.get("sourceIPAddress", "")
        if name == a7_name and e.fields.get("MFAUsed", "").lower() == a7_mfa and e.fields.get("result", "").lower() == a7_result:
            _tag(e, R["AWS-0007"])
            if a203_prefixes and e.user.lower().startswith(a203_prefixes):
                _tag(e, R["AUTH-0203"])
        if name == a31_name and e.fields.get("result") == "Success":
            _tag(e, R["AWS-0031"], "critical" if (is_public_ip(ip) or ip in attackers) else "high")
            e.set_field("persistence", "yes")
        if name.lower() in a44_names:
            _tag(e, R["AWS-0044"])
            e.set_field("tactic", "defense evasion")
        if name.lower() in a52_names or (name.lower() == a52_policy_ev and a52_marker in e.raw):
            _tag(e, R["AWS-0052"])
        if e.fields.get("userIdentity.type") == a60_type:
            _tag(e, R["AWS-0060"])
        if name == a71_name and any(c in e.raw for c in a71_cidrs):
            _tag(e, R["AWS-0071"])
        if ip in attackers:
            e.set_field_default("src.reputation", attackers[ip])

    # --- Windows
    win = fam_of["windows.evtx"]
    w88_id, w88_types, w88_pkgs = _pt("SIGMA-WIN-0088", "eventId"), _pl("SIGMA-WIN-0088", "logonTypes", lower=False), _pl("SIGMA-WIN-0088", "packages")
    w91_id, w91_privs = _pt("SIGMA-WIN-0091", "eventId"), _pl("SIGMA-WIN-0091", "privileges", lower=False)
    w91_ignore = set(_pl("SIGMA-WIN-0091", "ignoreAccounts")) | _SYSTEM_ACCOUNTS
    w104_id, w120_id = _pt("SIGMA-WIN-0104", "eventId"), _pt("SIGMA-WIN-0120", "eventId")
    w133_id = _pt("SIGMA-WIN-0133", "eventId")
    w150_ids, w150_groups = _pl("SIGMA-WIN-0150", "eventIds", lower=False), _pl("SIGMA-WIN-0150", "groups")
    rx_susp_proc = _prx("SIGMA-WIN-0133", "pattern", _SUSP_PROC)
    # Independent `if`s, not an elif chain: the event ids are analyst-editable now, so two rules may
    # legitimately be pointed at the same id and both have to get a chance to fire. As a chain, whichever
    # rule happened to be written first silently swallowed the event.
    for i in win:
        e = events[i]
        eid = e.fields.get("EventID", "")
        if eid == w88_id:
            lt = e.fields.get("LogonType", "")
            pkg = (e.fields.get("AuthenticationPackageName", "") + " " + e.fields.get("LmPackageName", "")).lower()
            if any(lt.startswith(t) for t in w88_types) and any(p in pkg for p in w88_pkgs):
                _tag(e, R["WIN-0088"])
                e.set_field("AuthPackage", "NTLM")
        if eid == w91_id:
            user = e.fields.get("SubjectUserName", "")
            privs = e.fields.get("PrivilegeList", "")
            if user.lower() not in w91_ignore and not user.endswith("$") and any(p in privs for p in w91_privs):
                _tag(e, R["WIN-0091"])
        if eid == w104_id:
            _tag(e, R["WIN-0104"])
        if eid == w120_id:
            _tag(e, R["WIN-0120"])
        if eid == w133_id:
            cmd = e.fields.get("CommandLine", "") + " " + e.fields.get("NewProcessName", "")
            if rx_susp_proc.search(cmd):
                _tag(e, R["WIN-0133"])
        if eid in w150_ids:
            grp = e.fields.get("TargetUserName", "").lower()
            if any(g in grp for g in w150_groups):
                _tag(e, R["WIN-0150"])
    w140_id = _pt("SIGMA-WIN-0140", "eventId")
    for key, anchor, count, first in find_bursts(
        (i for i in win if events[i].fields.get("EventID") == w140_id), ts,
            lambda i: events[i].fields.get("IpAddress") or events[i].fields.get("TargetUserName", ""),
            _pn("SIGMA-WIN-0140", "window"), _pn("SIGMA-WIN-0140", "threshold")):
        _tag(events[anchor], R["WIN-0140"])
        events[anchor].set_field("burst.count", str(count))
        if is_public_ip(key):
            attackers.setdefault(key, "4625 burst")

    # --- Linux syslog
    lnx = fam_of["syslog"]
    l12_prog, l12_result, l12_users = _pt("SIGMA-LNX-0012", "program").lower(), _pt("SIGMA-LNX-0012", "result"), _pl("SIGMA-LNX-0012", "users")
    l30_ops = _pl("SIGMA-LNX-0030", "auditOps")
    l41_prog = _pt("SIGMA-LNX-0041", "program").lower()
    l50_progs = _pl("SIGMA-LNX-0050", "programs")
    hist = _prx("SIGMA-LNX-0030", "pattern", _HISTORY)
    rx_hist_removal = _prx("SIGMA-LNX-0030", "removalPattern", _HISTORY_REMOVAL)
    rx_shell = _prx("SIGMA-LNX-0041", "pattern", _SHELL)
    rx_useradd = _prx("SIGMA-LNX-0050", "pattern", _USERADD)
    for i in lnx:
        e = events[i]
        prog = e.fields.get("program", "").lower()
        if prog == l12_prog and e.fields.get("result") == l12_result and e.fields.get("user", "").lower() in l12_users:
            _tag(e, R["LNX-0012"])
        if (prog in ("audit", "auditd") and hist.search(e.raw) and e.fields.get("op", "").lower() in l30_ops) \
                or (prog not in ("audit", "auditd") and hist.search(e.raw)
                    and rx_hist_removal.search(e.raw)):
            _tag(e, R["LNX-0030"])
            e.set_field("tactic", "defense evasion")
            if not e.msg.startswith("shell history"):
                path = e.fields.get("path") or e.fields.get("name") or ""
                e.msg = f"shell history file truncated — {path or e.msg}"
        if prog == l41_prog and rx_shell.search(e.raw):
            _tag(e, R["LNX-0041"])
        if prog in l50_progs or rx_useradd.search(e.raw):
            _tag(e, R["LNX-0050"])
    l45_prog, l45_results = _pt("SIGMA-LNX-0045", "program").lower(), _pl("SIGMA-LNX-0045", "results")
    for ip, anchor, count, first in find_bursts(
        (i for i in lnx if events[i].fields.get("program", "").lower() == l45_prog
            and events[i].fields.get("result", "").lower() in l45_results), ts,
            lambda i: events[i].fields.get("src_ip", ""), _pn("SIGMA-LNX-0045", "window"), _pn("SIGMA-LNX-0045", "threshold")):
        _tag(events[anchor], R["LNX-0045"])
        events[anchor].set_field("burst.count", str(count))
        if is_public_ip(ip):
            attackers.setdefault(ip, "ssh brute force")

    # --- Kubernetes
    k8s = fam_of["k8s.audit"]
    k4_res, k4_verb, k4_prod = _pt("SIGMA-K8S-0004", "resource"), _pt("SIGMA-K8S-0004", "verb"), _pl("SIGMA-K8S-0004", "prodKeywords")
    k11_res, k11_verbs, k11_ignore = _pt("SIGMA-K8S-0011", "resource"), _pl("SIGMA-K8S-0011", "verbs"), _pt("SIGMA-K8S-0011", "ignoreUserPrefix")
    k17_res, k17_verb, k17_markers = _pt("SIGMA-K8S-0017", "resource"), _pt("SIGMA-K8S-0017", "verb"), _pl("SIGMA-K8S-0017", "markers", lower=False)
    for i in k8s:
        e = events[i]
        res = e.fields.get("resource", "")
        verb = e.fields.get("verb", "")
        ns = e.fields.get("namespace", "")
        if res == k4_res and verb == k4_verb:
            prod = any(k in ns for k in k4_prod) or any(k in e.host for k in k4_prod)
            _tag(e, R["K8S-0004"], "critical" if prod else "high")
        if res == k11_res and verb.lower() in k11_verbs and not e.user.startswith(k11_ignore):
            _tag(e, R["K8S-0011"])
        if res == k17_res and verb == k17_verb and any(m.replace(" ", "") in e.raw.replace(" ", "") for m in k17_markers):
            _tag(e, R["K8S-0017"])
    k25_status = _pt("SIGMA-K8S-0025", "status")
    for _, anchor, count, first in find_bursts(
        (i for i in k8s if events[i].fields.get("responseStatus") == k25_status), ts,
            lambda i: events[i].user, _pn("SIGMA-K8S-0025", "window"), _pn("SIGMA-K8S-0025", "threshold")):
        _tag(events[anchor], R["K8S-0025"])
        events[anchor].set_field("burst.count", str(count))

    # --- Application JSON lines
    app = fam_of["app.jsonl"]
    a55_keywords, a55_rows = _pl("SIGMA-APP-0055", "keywords"), _pn("SIGMA-APP-0055", "minRows")
    for i in app:
        e = events[i]
        evname = (e.fields.get("event") or e.fields.get("action") or "").lower()
        rows = e.fields.get("rows") or e.fields.get("row_count") or e.fields.get("records") or ""
        try:
            rows_n = int(float(rows.replace(",", ""))) if rows else 0
        except ValueError:
            rows_n = 0
        if any(k in evname for k in a55_keywords) and rows_n >= a55_rows:
            _tag(e, R["APP-0055"])
            e.set_field("pii", e.fields.get("pii", "yes"))
            dest = e.fields.get("dest") or e.fields.get("path") or ""
            e.msg = f"bulk export completed — {rows_n:,} customer records" + (f" to {dest}" if dest else "")
    rx_auth_fail = _prx("SIGMA-APP-0061", "pattern", _AUTH_FAIL)
    for _, anchor, count, first in find_bursts(
        (i for i in app if rx_auth_fail.search(events[i].msg)), ts,
            lambda i: events[i].host or "app", _pn("SIGMA-APP-0061", "window"), _pn("SIGMA-APP-0061", "threshold")):
        _tag(events[anchor], R["APP-0061"])
        events[anchor].set_field("burst.count", str(count))

    # --- Network / firewall (delimited or firewall.* families)
    n19_allow = _pl("SIGMA-NET-0019", "allowActions")
    n22_allow, n22_min = _pl("SIGMA-NET-0022", "allowActions"), _pn("SIGMA-NET-0022", "minBytes")
    n22_mult, n22_minflows = _pn("SIGMA-NET-0022", "p99Multiplier"), _pn("SIGMA-NET-0022", "p99MinFlows")
    # per-host p99 outbound bytes for anomaly threshold
    by_host: dict[str, list[float]] = defaultdict(list)
    for i in net:
        e = events[i]
        b = e.fields.get("bytes", "")
        if b.isdigit():
            by_host[e.fields.get("src", "")].append(float(b))
    p99: dict[str, float] = {h: float(np.percentile(np.asarray(v), 99)) if len(v) >= n22_minflows else 0.0 for h, v in by_host.items()}
    for i in net:
        e = events[i]
        action = e.fields.get("action", "").lower()
        dst = e.fields.get("dst", "")
        src = e.fields.get("src", "")
        b = e.fields.get("bytes", "")
        bytes_n = int(b) if b.isdigit() else 0
        if action in n19_allow and dst in attackers:
            _tag(e, R["NET-0019"])
            e.set_field("dst.reputation", attackers[dst])
            e.set_field_default("direction", "outbound")
        if action in n22_allow and is_public_ip(dst) and bytes_n > 0:
            thr = max(n22_min, n22_mult * p99.get(src, 0.0))
            if bytes_n >= thr:
                _tag(e, R["NET-0022"])
                e.set_field("bytes_human", _fmt_bytes(bytes_n))
                e.set_field_default("direction", "outbound")
                port = e.fields.get("dst_port", "")
                e.msg = f"{e.fields.get('action', 'ALLOW')} {src} → {dst}{':' + port if port else ''} — {_fmt_bytes(bytes_n)}"
    n27_deny = _pl("SIGMA-NET-0027", "denyActions")
    for ip, anchor, count, first in find_bursts(
        (i for i in net if events[i].fields.get("action", "").lower() in n27_deny), ts,
            lambda i: events[i].fields.get("src", ""), _pn("SIGMA-NET-0027", "window"), _pn("SIGMA-NET-0027", "threshold")):
        _tag(events[anchor], R["NET-0027"])
        events[anchor].set_field("burst.count", str(count))
        if is_public_ip(ip):
            attackers.setdefault(ip, "port scan")

    fired = sum(len(e.detections) for e in events)
    return {"fired": fired, "attackers": set(attackers), "rules_evaluated": len(RULES)}
