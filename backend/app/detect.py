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
    # ---------------------------------------------------------------- web (continued)
    "WEB-0071": Rule(
        "SIGMA-WEB-0071", "Forced browsing - 403 burst", "medium",
        description="One source is being refused at volume. Someone is walking a wordlist through the site looking "
                    "for a page the access rules forgot.",
        trigger="Counts nginx events whose http.status is 403, grouped by src_ip. Fires on a 60-second window holding "
                "30 or more.",
        mechanism="threshold"),
    "WEB-0075": Rule(
        "SIGMA-WEB-0075", "Webshell path requested", "high",
        description="The request names a script that only an attacker asks for - a dropped shell, or a probe for one "
                    "somebody else dropped. A hit on a path that EXISTS is a compromise, not a scan.",
        trigger="The http.path field matches the webshell regex (known shell names, or a script taking a command "
                "parameter such as cmd=, exec= or eval=).",
        mechanism="regex"),
    "WEB-0079": Rule(
        "SIGMA-WEB-0079", "JNDI / Log4Shell injection attempt", "critical",
        description="A ${jndi:...} lookup sent to a server. If anything downstream logs it through a vulnerable Log4j "
                    "that string is remote code execution, not a request.",
        trigger="The request path, the user-agent or the raw line matches the JNDI regex.",
        mechanism="regex"),
    "WEB-0084": Rule(
        "SIGMA-WEB-0084", "Oversized request path", "low",
        description="A request path far longer than anything the application generates. Usually an encoded payload or "
                    "an overflow attempt hiding in the URL.",
        trigger="The length of http.path is at or above the length threshold.",
        mechanism="fields"),
    # ---------------------------------------------------------------- identity
    "AUTH-0230": Rule(
        "SIGMA-AUTH-0230", "Successful sign-in outside business hours", "low",
        description="An interactive sign-in at an hour nobody here works. Weak on its own; next to anything else in a "
                    "timeline it is what says the session was not the account owner's.",
        trigger="A successful Windows 4624 interactive logon (LogonType 2, 10 or 11) or a CloudTrail ConsoleLogin "
                "success whose UTC hour falls outside the business window.",
        mechanism="fields"),
    # ---------------------------------------------------------------- Windows (continued)
    "WIN-0160": Rule(
        "SIGMA-WIN-0160", "Endpoint protection event", "high",
        description="Defender reported malware, or its real-time protection was changed. Both matter: the first names "
                    "what was found, the second is usually what an attacker does so the first never happens.",
        trigger="A Windows event whose EventID is one of the Defender ids (1116 malware detected, 1117 action taken, "
                "5001 real-time protection disabled, 5007 configuration changed).",
        mechanism="fields"),
    "WIN-0170": Rule(
        "SIGMA-WIN-0170", "Password spray - many accounts from one source", "high",
        description="One source failing against MANY DIFFERENT accounts is spraying a single password across the "
                    "directory. A per-account lockout never sees it, which is the whole point of the technique.",
        trigger="Counts DISTINCT TargetUserName values in 4625 events grouped by IpAddress. Fires when one source "
                "reaches the distinct-account threshold inside the window.",
        mechanism="threshold"),
    "WIN-0175": Rule(
        "SIGMA-WIN-0175", "Service installed", "high",
        description="A new Windows service. It starts on boot as SYSTEM, which is why it is a favourite place to keep "
                    "access - and why PsExec-style lateral movement leaves one behind.",
        trigger="A Windows event whose EventID is 7045 (System log) or 4697 (Security log).",
        mechanism="fields"),
    "WIN-0180": Rule(
        "SIGMA-WIN-0180", "Scheduled task created", "medium",
        description="A scheduled task runs code later, on a timer, with nobody logged in. Persistence that survives a "
                    "reboot and a password reset.",
        trigger="A Windows event whose EventID is 4698 or 106 (TaskScheduler log).",
        mechanism="fields"),
    "WIN-0185": Rule(
        "SIGMA-WIN-0185", "Backup and recovery destroyed", "critical",
        description="Shadow copies deleted, the backup catalogue wiped, or recovery switched off. This is the step "
                    "immediately before ransomware encrypts, and it is what makes the encryption stick.",
        trigger="A 4688 process creation whose CommandLine matches the recovery-destruction regex (vssadmin delete "
                "shadows, wbadmin delete, bcdedit recoveryenabled no, wmic shadowcopy delete).",
        mechanism="regex"),
    "WIN-0190": Rule(
        "SIGMA-WIN-0190", "Kerberoasting - RC4 service tickets", "high",
        description="Service tickets requested in bulk with the weak RC4 cipher - which is what an attacker asks for, "
                    "because those tickets crack offline into service account passwords.",
        trigger="Counts 4769 events whose TicketEncryptionType is 0x17, grouped by the requesting account. Fires on a "
                "10-minute window holding 10 or more.",
        mechanism="threshold"),
    # ---------------------------------------------------------------- Linux (continued)
    "LNX-0060": Rule(
        "SIGMA-LNX-0060", "Reverse shell command", "critical",
        description="A command whose only purpose is to hand a shell to a remote listener. There is no legitimate "
                    "reason for this string to appear in a production log.",
        trigger="The raw line matches the reverse-shell regex (/dev/tcp redirection, nc -e, socat EXEC, a python or "
                "perl socket one-liner).",
        mechanism="regex"),
    "LNX-0065": Rule(
        "SIGMA-LNX-0065", "Cron or systemd persistence", "high",
        description="A scheduled job or a service unit was written. Like a scheduled task on Windows, it runs code "
                    "after everyone has gone home and survives the reboot.",
        trigger="The raw line matches the persistence regex (a unit file under /etc/systemd/system, a job under "
                "/etc/cron.d or /var/spool/cron, a crontab edit, or systemctl enable), or the message of a "
                "scheduler program matches it.",
        mechanism="regex"),
    "LNX-0070": Rule(
        "SIGMA-LNX-0070", "SUID bit set on a binary", "high",
        description="A binary was made to run as its owner rather than its caller. Set on a shell or an interpreter, "
                    "that is a root backdoor anyone on the box can use.",
        trigger="The raw line matches the SUID regex (chmod u+s / g+s, or a 4xxx / 2xxx octal mode).",
        mechanism="regex"),
    "LNX-0075": Rule(
        "SIGMA-LNX-0075", "Kernel module loaded", "medium",
        description="Code loaded into the kernel. A rootkit lives here, below everything that would otherwise report "
                    "it - including the tooling looking for it.",
        trigger="syslog program is insmod, modprobe or kextload, or the raw line matches the kernel-module regex.",
        mechanism="regex"),
    # ---------------------------------------------------------------- AWS (continued)
    "AWS-0080": Rule(
        "SIGMA-AWS-0080", "S3 bucket opened to the world", "critical",
        description="Object storage made readable by anyone. Whatever is in that bucket is public from this moment, "
                    "and stays public until somebody notices.",
        trigger="CloudTrail eventName is one of PutBucketAcl, PutBucketPolicy, PutBucketWebsite or "
                "DeletePublicAccessBlock AND the raw event body contains a public-principal marker.",
        mechanism="fields"),
    "AWS-0085": Rule(
        "SIGMA-AWS-0085", "Secret retrieval burst", "high",
        description="One identity pulling secrets in bulk. That is credential harvesting whether or not the identity "
                    "is allowed to do it - normal use fetches a secret, not the vault.",
        trigger="Counts CloudTrail events whose eventName is GetSecretValue, GetParameter, GetParameters or Decrypt, "
                "grouped by user. Fires on a 5-minute window holding 20 or more.",
        mechanism="threshold"),
    "AWS-0090": Rule(
        "SIGMA-AWS-0090", "Snapshot or image shared outside the account", "critical",
        description="A disk image was shared with another account or made public. It is a copy of the data that "
                    "leaves no trace in any data-plane log - exfiltration through the control plane.",
        trigger="CloudTrail eventName is ModifySnapshotAttribute, ModifyImageAttribute or ModifyDBSnapshotAttribute "
                "and the raw body contains a sharing marker.",
        mechanism="fields"),
    "AWS-0095": Rule(
        "SIGMA-AWS-0095", "Security service disabled", "critical",
        description="Detection itself was switched off - GuardDuty, Config, Security Hub or Macie. Anti-forensics "
                    "against the account's own alarms, and usually adjacent to whatever came next.",
        trigger="CloudTrail eventName is one of DeleteDetector, UpdateDetector, StopMonitoringMembers, "
                "DeleteConfigurationRecorder, StopConfigurationRecorder, DisableSecurityHub or DisableMacie.",
        mechanism="fields"),
    # ---------------------------------------------------------------- Kubernetes (continued)
    "K8S-0030": Rule(
        "SIGMA-K8S-0030", "cluster-admin binding created", "critical",
        description="Someone was granted the cluster's highest role. From here every namespace, every secret and "
                    "every node is reachable, and the binding outlives the session that made it.",
        trigger="resource is clusterrolebindings or rolebindings, verb is create or update, and the raw request names "
                "cluster-admin.",
        mechanism="fields"),
    "K8S-0035": Rule(
        "SIGMA-K8S-0035", "Anonymous or unauthenticated API access", "high",
        description="The API server answered a request that carried no identity. Anything it returned went to whoever "
                    "could reach the port.",
        trigger="The audit event's user is system:anonymous, or the raw request names system:unauthenticated.",
        mechanism="fields"),
    # ---------------------------------------------------------------- mail
    "MAIL-0010": Rule(
        "SIGMA-MAIL-0010", "Sender authentication failed", "medium",
        description="The message failed the checks that prove it came from the domain it claims. Not proof of "
                    "phishing on its own, but every phish that spoofs a domain fails one of these.",
        trigger="An e-mail event whose spf, dkim or dmarc field holds a failure verdict (fail, softfail, none, "
                "permerror, temperror).",
        mechanism="fields"),
    "MAIL-0014": Rule(
        "SIGMA-MAIL-0014", "Executable or macro attachment", "high",
        description="An attachment that can run code the moment it is opened. This is the delivery step of most "
                    "intrusions that start with mail.",
        trigger="An e-mail event whose attachment names match the dangerous-attachment regex.",
        mechanism="regex"),
    # ---------------------------------------------------------------- packet captures
    "PCAP-0010": Rule(
        "SIGMA-PCAP-0010", "DNS tunnelling - oversized query name", "high",
        description="A DNS name far longer than any real host name, or one long random-looking label. DNS leaves "
                    "almost every network unfiltered, so it is what data goes out through when nothing else can.",
        trigger="A captured DNS query whose dns_query reaches the length threshold, or which contains a single label "
                "matching the long-label regex.",
        mechanism="regex"),
    "PCAP-0014": Rule(
        "SIGMA-PCAP-0014", "DNS query flood from one host", "medium",
        description="One host resolving names at machine speed - a tunnel carrying data, a domain-generation "
                    "algorithm hunting for its controller, or a resolver being used to amplify an attack.",
        trigger="Counts captured DNS queries grouped by src_ip. Fires on a 60-second window holding 300 or more.",
        mechanism="threshold"),
    "PCAP-0018": Rule(
        "SIGMA-PCAP-0018", "Cleartext protocol in use", "medium",
        description="Traffic on a protocol that carries its credentials in the clear. Anyone on the path - including "
                    "whoever is already inside - reads the password by watching.",
        trigger="A captured TCP packet carrying a payload whose dst_port is one of the cleartext ports (21 FTP, "
                "23 telnet, 110 POP3, 143 IMAP, 512/513/514 r-services).",
        mechanism="fields"),
    "PCAP-0022": Rule(
        "SIGMA-PCAP-0022", "TLS to a suspicious domain", "medium",
        description="The ClientHello names a domain on a service attackers use for throwaway infrastructure. The flow "
                    "is encrypted, so this name is the only thing about it you can read.",
        trigger="A captured TLS ClientHello whose tls_sni matches the suspicious-domain regex (dynamic DNS and "
                "tunnelling services, and the cheap TLDs they are registered under).",
        mechanism="regex"),
    "PCAP-0026": Rule(
        "SIGMA-PCAP-0026", "Port scan - SYN fan-out", "medium",
        description="One host opening connections to many DIFFERENT ports in seconds. That is a scan, not use - "
                    "software talks to the port it needs.",
        trigger="Counts DISTINCT dst_port values in captured TCP packets whose only flag is SYN, grouped by src_ip. "
                "Fires when one source reaches the distinct-port threshold inside the window.",
        mechanism="threshold"),
    "PCAP-0030": Rule(
        "SIGMA-PCAP-0030", "TLS on a non-standard port", "low",
        description="An encrypted session somewhere other than the usual ports. Legitimate services do this; so does "
                    "a command-and-control channel trying to look like anything but HTTPS.",
        trigger="A captured TLS ClientHello (tls_sni present) whose dst_port is not one of the standard TLS ports.",
        mechanism="fields"),
    # ---------------------------------------------------------------- any source
    "APP-0070": Rule(
        "SIGMA-APP-0070", "Secret material in a log line", "high",
        description="A credential was written into a log. Logs are copied, shipped and read far more widely than the "
                    "secret store is - from here the key is wherever this file went.",
        trigger="The raw line of ANY source matches the secret regex (AWS access key id, a PEM private key header, a "
                "JWT, a Slack / GitHub / Stripe token or webhook, or an assigned password / api key / token). An "
                "ASSIGNED value is then checked: it does not fire when the value is a placeholder or mask "
                "(NO_AUTH, null, <redacted>, ********), a template (${VAR}, {{x}}), a working directory after "
                "pwd=, or a PUBLIC web-API key in a URL query string (?apikey=, &apikey=) - the msn.com / maps / "
                "analytics keys every proxy log carries. password= / secret= / token= in a URL still fire.",
        mechanism="regex"),
    "APP-0075": Rule(
        "SIGMA-APP-0075", "Encoded command line", "high",
        description="A command handed its instructions as base64 so that neither a human nor a log search can read "
                    "them. The encoding is the intent - nothing legitimate needs to hide its arguments.",
        trigger="The raw line of ANY source matches the encoded-command regex (powershell -enc with a base64 blob, "
                "certutil -decode, FromBase64String, base64 -d piped into a shell).",
        mechanism="regex"),
    "APP-0080": Rule(
        "SIGMA-APP-0080", "Ransomware indicator", "critical",
        description="A ransom note name or an encrypted-file extension. By the time this reaches a log the encryption "
                    "has already started somewhere.",
        trigger="The raw line of ANY source matches the ransomware regex (ransom note filenames, known encrypted "
                "extensions).",
        mechanism="regex"),
    # ---------------------------------------------------------------- identity (continued)
    "AUTH-0240": Rule(
        "SIGMA-AUTH-0240", "Account used from many addresses", "high",
        description="One account authenticating from many DIFFERENT addresses in a short window. Either the "
                    "person is behind a rotating proxy, or the credential is in more than one pair of hands - "
                    "and the second is what a stolen password looks like the day it is used.",
        trigger="Counts DISTINCT source addresses per account across web logins, syslog auth, Windows 4624/4625 "
                "and cloud sign-ins. Fires when one account reaches the distinct-address threshold inside the "
                "window.",
        mechanism="threshold"),
    # ---------------------------------------------------------------- Windows (continued)
    "WIN-0200": Rule(
        "SIGMA-WIN-0200", "Logon with explicit credentials", "medium",
        description="Someone ran something AS somebody else without logging out - runas, a scheduled task with "
                    "stored credentials, or a tool passing a captured password. It is the event that links the "
                    "account that was used to the account that used it.",
        trigger="Security event 4648, ignoring the machine and system accounts.",
        mechanism="fields"),
    "WIN-0205": Rule(
        "SIGMA-WIN-0205", "Account locked out", "medium",
        description="An account crossed the lockout threshold. On its own it is a bad password; next to a spray "
                    "or a burst of 4625s it is the account somebody was working on.",
        trigger="Security event 4740.",
        mechanism="fields"),
    "WIN-0210": Rule(
        "SIGMA-WIN-0210", "Directory object modified", "medium",
        description="A directory object was changed - group policy, a user attribute, an ACL. Persistence and "
                    "privilege escalation in a domain both end here, and the change outlives the session.",
        trigger="Security event 5136 or 5137 (directory service object modified or created).",
        mechanism="fields"),
    "WIN-0215": Rule(
        "SIGMA-WIN-0215", "Credential caching re-enabled (WDigest)", "high",
        description="A registry change that puts plaintext passwords back in memory. Nothing legitimate turns "
                    "WDigest back on in 2026; it is done so that a dump of LSASS yields passwords rather than "
                    "hashes.",
        trigger="Security event 4657 (registry value modified) whose object name or command line matches the "
                "credential-caching regex (UseLogonCredential, WDigest, RunAsPPL disabled).",
        mechanism="regex"),
    "WIN-0220": Rule(
        "SIGMA-WIN-0220", "Suspicious PowerShell script block", "high",
        description="Script block logging captured the code itself, and the code is doing something a script "
                    "block does not normally do: downloading and executing, hiding its window, reaching into "
                    "memory, or disabling the very logging that recorded it.",
        trigger="PowerShell operational event 4104 whose ScriptBlockText matches the suspicious-script regex.",
        mechanism="regex"),
    "WIN-0225": Rule(
        "SIGMA-WIN-0225", "Remote desktop logon from a public address", "high",
        description="An interactive remote session from off the network. RDP exposed to the internet is how a "
                    "large share of ransomware starts, and a successful one is somebody at the keyboard.",
        trigger="Security event 4624 with LogonType 10 or 7 whose IpAddress is a public address.",
        mechanism="fields"),
    "WIN-0230": Rule(
        "SIGMA-WIN-0230", "Host firewall rule changed", "medium",
        description="A local firewall rule was added, changed or deleted. Attackers open a port to keep a "
                    "listener reachable - and close logging paths on the way out.",
        trigger="A Windows event whose EventID is one of the firewall change ids (2004, 2005, 2006, 2033, 4946, "
                "4947, 4948, 4950).",
        mechanism="fields"),
    "WIN-0235": Rule(
        "SIGMA-WIN-0235", "Event log cleared (non-security)", "high",
        description="A log other than Security was wiped. SIGMA-WIN-0104 covers the Security log; this covers "
                    "System, Application and PowerShell, which is where the tooling actually leaves traces.",
        trigger="A Windows event whose EventID is 104 (log file cleared) on any channel.",
        mechanism="fields"),
    "WIN-0250": Rule(
        "SIGMA-WIN-0250", "Administrative share accessed", "high",
        description="A connection to ADMIN$, C$ or IPC$. That is how a remote-execution tool moves a payload "
                    "onto a machine, and normal use of a file server does not touch these shares.",
        trigger="Security event 5140 or 5145 whose ShareName matches the admin-share regex.",
        mechanism="regex"),
    "WIN-0255": Rule(
        "SIGMA-WIN-0255", "LSASS memory accessed", "critical",
        description="A process opened the memory of the component that holds every credential on the machine. "
                    "This is credential dumping, whatever tool wrote it.",
        trigger="Security event 4656, 4663 or 4690 whose ObjectName matches the target-process regex "
                "(lsass.exe and its full device path).",
        mechanism="regex"),
    # ---------------------------------------------------------------- Azure / Entra ID
    "AZURE-0010": Rule(
        "SIGMA-AZURE-0010", "Risky sign-in", "high",
        description="Entra ID scored this sign-in as risky at the moment it happened - leaked credentials, an "
                    "anonymous IP, an impossible journey. The platform is telling you it does not believe this "
                    "was the account owner.",
        trigger="An Azure sign-in event whose riskLevelDuringSignIn (or riskLevelAggregated / riskState) is one "
                "of the risk levels watched.",
        mechanism="fields"),
    "AZURE-0014": Rule(
        "SIGMA-AZURE-0014", "Legacy authentication used", "high",
        description="A sign-in over a protocol that cannot present a second factor. Legacy auth is the standard "
                    "way around MFA, which is why password spraying still targets it.",
        trigger="An Azure sign-in whose clientAppUsed is one of the legacy protocols (IMAP4, POP3, SMTP AUTH, "
                "MAPI, Exchange ActiveSync, Other clients).",
        mechanism="fields"),
    "AZURE-0018": Rule(
        "SIGMA-AZURE-0018", "MFA challenge failed or denied", "medium",
        description="The password was right and the second factor was not satisfied. A burst of these is an "
                    "attacker holding valid credentials and hammering the prompt - MFA fatigue.",
        trigger="An Azure sign-in whose resultType is one of the MFA failure codes (500121, 50074, 50076, "
                "50079, 50072).",
        mechanism="fields"),
    "AZURE-0022": Rule(
        "SIGMA-AZURE-0022", "Conditional access blocked a sign-in", "medium",
        description="Policy refused the sign-in. Each one is a control working; a run of them from one identity "
                    "is somebody probing for the gap in the policy.",
        trigger="An Azure sign-in whose conditionalAccessStatus is failure, or whose resultType is 53003 "
                "(blocked by conditional access).",
        mechanism="fields"),
    "AZURE-0026": Rule(
        "SIGMA-AZURE-0026", "Azure sign-in failure burst", "high",
        description="Sustained failed sign-ins against one identity or from one address - the cloud equivalent "
                    "of a 4625 burst, and it happens where no endpoint agent can see it.",
        trigger="Counts Azure sign-in events whose resultType is not 0, grouped by the identity. Fires on a "
                "5-minute window holding 10 or more.",
        mechanism="threshold"),
    "AZURE-0030": Rule(
        "SIGMA-AZURE-0030", "Application consent granted", "high",
        description="Someone granted an application permission to act on their behalf. Illicit consent is "
                    "persistence that survives a password reset and an MFA re-enrolment, because it is not the "
                    "password that is being used.",
        trigger="An Azure audit event whose operationName mentions consent to application, add OAuth2 "
                "permission grant, or add app role assignment.",
        mechanism="fields"),
    "AZURE-0034": Rule(
        "SIGMA-AZURE-0034", "Privileged role assigned", "critical",
        description="An account was put into a privileged directory role - Global Administrator and its "
                    "relatives. From there every mailbox, every policy and every other role is reachable.",
        trigger="An Azure audit event whose operationName adds a member to a role and whose body names one of "
                "the privileged roles watched.",
        mechanism="fields"),
    "AZURE-0038": Rule(
        "SIGMA-AZURE-0038", "Service principal or credential added", "high",
        description="A new service principal, or a new secret or certificate on an existing one. That is a "
                    "non-human identity with its own key - the cloud's version of a local account nobody "
                    "notices.",
        trigger="An Azure audit event whose operationName adds a service principal or adds service principal "
                "credentials.",
        mechanism="fields"),
    "AZURE-0042": Rule(
        "SIGMA-AZURE-0042", "Sign-in from many countries", "high",
        description="One identity signing in from several countries in one window. Travel does not work like "
                    "that, and this is the shape a shared or stolen credential makes.",
        trigger="Counts DISTINCT countries in Azure sign-in events grouped by the identity. Fires when one "
                "identity reaches the distinct-country threshold inside the window.",
        mechanism="threshold"),
    "AZURE-0046": Rule(
        "SIGMA-AZURE-0046", "Security defaults or policy weakened", "critical",
        description="A conditional access policy, security defaults or an MFA requirement was changed or "
                    "removed. This is the control being taken down, and it is usually done from a session that "
                    "should not have been able to do it.",
        trigger="An Azure audit event whose operationName deletes or updates a conditional access policy, "
                "disables security defaults, or updates the authentication methods policy.",
        mechanism="fields"),
    # ---------------------------------------------------------------- Microsoft 365 / Defender
    "M365-0010": Rule(
        "SIGMA-M365-0010", "Defender alert", "high",
        description="Microsoft Defender raised an alert of its own. Iris does not re-detect what the platform "
                    "already found - it places it on the same timeline as everything else, which is the thing "
                    "the portal cannot do.",
        trigger="An event carrying a Defender alert shape (AlertId / Title with Severity, or "
                "ProviderName = Microsoft Defender) whose severity is one of the levels watched.",
        mechanism="fields"),
    "M365-0014": Rule(
        "SIGMA-M365-0014", "Inbox rule created or changed", "high",
        description="A mailbox rule was created. In business e-mail compromise this is the step that hides the "
                    "conversation from its owner - replies moved to Deleted Items or RSS Feeds while the "
                    "attacker talks to the finance team.",
        trigger="A Microsoft 365 audit event whose Operation is New-InboxRule, Set-InboxRule or "
                "UpdateInboxRules.",
        mechanism="fields"),
    "M365-0018": Rule(
        "SIGMA-M365-0018", "Mail forwarding configured", "critical",
        description="Mail is being copied out of the tenant. Forwarding survives a password reset and is quiet: "
                    "the owner sees nothing, and the attacker keeps reading.",
        trigger="A Microsoft 365 audit event whose Operation is one of the forwarding operations AND whose raw "
                "body matches the forwarding regex (ForwardingSmtpAddress, ForwardTo, RedirectTo, "
                "DeliverToMailboxAndForward).",
        mechanism="regex"),
    "M365-0022": Rule(
        "SIGMA-M365-0022", "eDiscovery or content search", "high",
        description="Somebody searched or exported tenant-wide content. It is a legitimate compliance tool and "
                    "an excellent exfiltration tool, and the two look identical apart from who ran it.",
        trigger="A Microsoft 365 audit event whose Operation is one of the eDiscovery operations "
                "(SearchStarted, SearchExported, ViewedSearchExported, New-ComplianceSearch).",
        mechanism="fields"),
    "M365-0026": Rule(
        "SIGMA-M365-0026", "Anonymous sharing link created", "high",
        description="A file or site was shared with a link that needs no sign-in. Anyone who gets the URL has "
                    "the data, and the link keeps working after the person who made it leaves.",
        trigger="A Microsoft 365 audit event whose Operation is AnonymousLinkCreated, "
                "AnonymousLinkUsed, AddedToSecureLink or SharingInvitationCreated with an external target.",
        mechanism="fields"),
    "M365-0030": Rule(
        "SIGMA-M365-0030", "Bulk file download or sync", "high",
        description="One identity pulling files in bulk from SharePoint or OneDrive. This is what staged "
                    "exfiltration looks like from the audit log's side.",
        trigger="Counts Microsoft 365 audit events whose Operation is FileDownloaded, FileSyncDownloadedFull "
                "or FileSyncUploadedFull, grouped by the user. Fires on a 10-minute window holding 100 or more.",
        mechanism="threshold"),
    "M365-0034": Rule(
        "SIGMA-M365-0034", "Phishing or malware verdict", "high",
        description="Defender for Office judged a message malicious. Whether it was delivered or not, somebody "
                    "aimed it at this tenant, and the ones that got through are the start of a timeline.",
        trigger="An event one of whose verdict fields (ThreatType, Verdict, DeliveryAction, DetectionMethod) "
                "matches the threat-verdict regex - phish, malware, spam, quarantined or zapped.",
        mechanism="regex"),
    "M365-0038": Rule(
        "SIGMA-M365-0038", "Audit logging disabled", "critical",
        description="Tenant audit logging was switched off or narrowed. Anti-forensics against the only record "
                    "that would show what happened next.",
        trigger="A Microsoft 365 audit event whose Operation is Set-AdminAuditLogConfig, "
                "Set-MailboxAuditBypassAssociation, or a mailbox audit disable.",
        mechanism="fields"),
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

# ---- regexes for the rules added alongside the pcap parser and the wider catalogue. Each one is the
#      SHIPPED DEFAULT of a regex Param below (never a bare constant in run_rules): RULE_PATTERNS and
#      Rule.patterns are derived from those params, so a pattern maintained here and there would drift.
_WEBSHELL = re.compile(r"/(c99|r57|wso|b374k|alfa|shell|cmd|backdoor|webshell|adminer|tinyfilemanager)\.(php|asp|aspx|jsp|jspx|phtml|cfm)\b"
                       r"|\.(php|asp|aspx|jsp|jspx|phtml)\?(?:[^&]*&)*(cmd|exec|eval|system|shell|passthru|run|download)=", re.I)
_JNDI = re.compile(r"\$\{\s*(?:\$\{[^}]*\}|[^}])*?jndi\s*:|\$\{jndi:|%24%7bjndi", re.I)
_RECOVERY_DESTROY = re.compile(r"vssadmin(\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup|backup)"
                               r"|bcdedit(\.exe)?\s+.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)"
                               r"|Get-WmiObject\s+Win32_Shadowcopy.*Delete|Remove-Item.*\\\\Recovery", re.I)
_REVERSE_SHELL = re.compile(r"(?:ba|z|k)?sh\s+-i\s*>&\s*/dev/(tcp|udp)/|/dev/(tcp|udp)/\d{1,3}(?:\.\d{1,3}){3}/\d+"
                            r"|\bnc(?:at)?\b[^\n|;]*\s-[a-z]*e[a-z]*\s+/(?:usr/)?bin/(?:ba|z|da)?sh"
                            r"|socat\b[^\n]*exec\s*:|python[0-9.]*\s+-c\s+['\"]?import\s+socket"
                            r"|perl\s+-e\s+['\"]?use\s+Socket|\bmkfifo\b[^\n]*\|\s*(?:ba|z)?sh", re.I)
_CRON_PERSIST = re.compile(r"/etc/systemd/system/[^\s]+\.(service|timer)|/etc/cron\.(d|daily|hourly|weekly|monthly)/|/var/spool/cron/"
                           r"|\bcrontab\b[^\n]*\s-(?:e|r|l\s+-u)|systemctl\s+(enable|link)\b|BEGIN\s+EDIT|REPLACE\b.*crontab", re.I)
_SUID = re.compile(r"\bchmod\b[^\n]*\b[ug]\+s\b|\bchmod\b\s+[0-7]?[246][0-7]{3}\b|\bchown\b[^\n]*\broot\b[^\n]*\bchmod\b", re.I)
_KERNEL_MODULE = re.compile(r"\b(insmod|modprobe|kextload|rmmod)\b|\bmodule\s+(loaded|verification\s+failed)\b|loading\s+out-of-tree\s+module", re.I)
_ATTACHMENT_BAD = re.compile(r"\.(exe|scr|pif|com|bat|cmd|ps1|vbs|vbe|js|jse|jar|hta|msi|msp|cpl|lnk|iso|img|vhd|reg|wsf|dll)\b"
                             r"|\.(docm|xlsm|pptm|dotm|xlam|xll)\b|\.(zip|rar|7z|gz)\s*[>\)]?\s*$", re.I)
_LONG_LABEL = re.compile(r"(?:^|\.)[A-Za-z0-9+/=_-]{40,}(?:\.|$)")
_SUSPICIOUS_SNI = re.compile(r"\.(tk|top|xyz|gq|ml|cf|ru|su|cc|pw|buzz|click|zip|mov)$"
                             r"|(duckdns|no-ip|noip|hopto|ddns|dynu|serveo|ngrok|trycloudflare|localtunnel|pagekite|portmap|onion)\.", re.I)
# The FORMAT branches are high confidence on their own (an AWS key id, a PEM header, a JWT, a Slack /
# GitHub / Stripe token, a Slack webhook). The ASSIGNED branch — `password=…`, `apikey: …` — is where the
# false positives live, so its key name and value are captured as `name` / `value` and every match goes
# through `_secret_real` before it fires. See that function for what it refuses.
_SECRET = re.compile(r"\bAKIA[0-9A-Z]{16}\b|\bASIA[0-9A-Z]{16}\b|-----BEGIN [A-Z ]*PRIVATE KEY-----"
                     r"|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
                     r"|\b(?P<name>password|passwd|pwd|api[_-]?key|apikey|secret|token|client[_-]?secret)"
                     r"\s*[=:]\s*[\"']?(?P<value>[^\s\"'&;,]{8,})"
                     r"|\bxox[baprs]-[0-9A-Za-z-]{10,}|\bghp_[0-9A-Za-z]{30,}|\bgithub_pat_[0-9A-Za-z_]{20,}"
                     r"|\bgh[oprsu]_[0-9A-Za-z]{30,}|\bsk_live_[0-9A-Za-z]{20,}"
                     r"|hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]{10,}", re.I)
# Values that are not a secret whatever the key name says: masked, templated, or a sentinel.
_SECRET_PLACEHOLDERS = ("no_auth, null, none, undefined, redacted, <redacted>, [redacted], [filtered], "
                        "[masked], changeme, password, example, hidden, omitted")
# Query-string parameters that carry a PUBLIC key when they appear in a URL a browser requested: the
# msn.com / Bing / maps / analytics style `?apikey=…` is a routing token for a public web API, present
# in every proxy log on earth, and reported here as a false positive on a Sophos web-proxy export.
# `password=` / `secret=` / `token=` in a URL are NOT on this list: credentials in a GET are a real leak.
_SECRET_URL_PUBLIC = "apikey, api_key, api-key"
_SECRET_TEMPLATE_STARTS = ("${", "{{", "%", "<", "[", "{", "$(")
_DRIVE_RE = re.compile(r"[A-Za-z]:[\\/]")


def _secret_real(raw: str, rx: "re.Pattern[str]", url_public: set[str], placeholders: set[str]) -> bool:
    """Does `raw` carry secret material, or only something SHAPED like it?

    Reported as a false positive on a web-proxy log: every browser request to api.msn.com carries
    `apikey=qrUeHGGY…`, a public front-end key, and the rule fired 776 times on the analyst's evidence
    for zero credentials. The regex cannot know that; this can, from the CONTEXT of the match:
      • a format match (AKIA…, a PEM header, a JWT, a vendor token) is always real;
      • an assigned value that is a placeholder (`NO_AUTH`, `null`, `<redacted>`), a template
        (`${DB_PASSWORD}`, `{{secret}}`, `%s`), or a mask (`********`, `xxxxxxxx`) is not;
      • `pwd=/home/alice/project` is a working directory, not a password;
      • a URL query parameter on the public list (`?apikey=` / `&apikey=`) is a public key.
    A line with a public `apikey=` AND a real `password=` still fires: every match is checked, and one
    real one is enough. An analyst override regex with no `name`/`value` groups is treated as all-real.
    """
    for m in rx.finditer(raw):
        gd = m.groupdict()
        name, value = gd.get("name"), gd.get("value")
        if not name or not value:
            return True                                # a format match, or an override without the groups
        low = value.strip("\"'").lower()
        if low in placeholders or low.startswith(_SECRET_TEMPLATE_STARTS):
            continue
        if len(set(low)) <= 2:                         # ******** / xxxxxxxx / 00000000
            continue
        n = name.lower().replace("-", "_")
        if n == "pwd" and (low[0] in "/\\" or _DRIVE_RE.match(low)):
            continue
        start = m.start("name")
        if start > 0 and raw[start - 1] in "?&" and n in url_public:
            continue
        return True
    return False
_ENCODED_CMD = re.compile(r"powershell(\.exe)?[^\n]*\s-(?:e|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[A-Za-z0-9+/=]{24,}"
                          r"|FromBase64String\s*\(|certutil(\.exe)?[^\n]*-decode|base64\s+(?:-d|--decode)[^\n]*\|\s*(?:ba|z)?sh"
                          r"|\[Convert\]::FromBase64String|echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64\s+(?:-d|--decode)", re.I)
_RANSOM = re.compile(r"\b(READ_?ME|HOW[_ ]?TO[_ ]?DECRYPT|DECRYPT[_-]?(FILES|INSTRUCTION)|RECOVER[_-]?(FILES|YOUR)|RESTORE[-_]?FILES|"
                     r"YOUR[_-]?FILES[_-]?ARE[_-]?ENCRYPTED)[^\n]{0,40}\.(txt|html|hta)\b"
                     r"|\.(locky|crypt|cryptolocker|encrypted|enc|lockbit|conti|ryuk|revil|sodinokibi|djvu|wannacry|wncry|onion|makop|phobos|cerber)\b", re.I)

# ---- regexes for the Windows / Azure / Microsoft 365 tranche. Same rule as every other pattern here:
#      each is the SHIPPED DEFAULT of a regex Param, never a bare constant read by run_rules.
_WDIGEST = re.compile(r"UseLogonCredential|\\WDigest\\|SecurityProviders\\\\WDigest|RunAsPPL|LsaCfgFlags"
                      r"|DisableRestrictedAdmin|AllowProtectedCreds", re.I)
_PS_SCRIPT = re.compile(r"(?:Invoke-(?:Expression|WebRequest|RestMethod|Mimikatz|Shellcode|DllInjection)|IEX\s*\(|"
                        r"DownloadString|DownloadFile|FromBase64String|Net\.WebClient|Start-BitsTransfer|"
                        r"-w(?:indowstyle)?\s+hidden|-nop\b|-noni\b|Set-MpPreference\s+-Disable|"
                        r"Add-MpPreference\s+-ExclusionPath|Bypass\s+-Scope|EncodedCommand|"
                        r"System\.Reflection\.Assembly|VirtualAlloc|WriteProcessMemory|"
                        r"Get-Credential|ConvertTo-SecureString|LogPipelineExecutionDetails)", re.I)
_ADMIN_SHARE = re.compile(r"\\\\?(ADMIN|IPC|[A-Z])\$$|^(ADMIN|IPC|[A-Z])\$$", re.I)
_LSASS = re.compile(r"lsass\.exe|\\Device\\HarddiskVolume\d+\\Windows\\System32\\lsass", re.I)
_FORWARDING = re.compile(r"ForwardingSmtpAddress|ForwardingAddress|DeliverToMailboxAndForward|"
                         r"\bForwardTo\b|\bRedirectTo\b|BlindCopyTo", re.I)
_THREAT_VERDICT = re.compile(r"\b(phish|malware|spam|malicious|highconfidencephish|ransomware|"
                             r"blocked|quarantined|zap|replaced|delivered\s*to\s*junk)\b", re.I)

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
    "SIGMA-WEB-0071": (
        P("statuses", "Status codes counted", "values", "403", "http.status", "Exact HTTP status codes treated as a refusal."),
        P("window", "Time window", "seconds", "60", "", "Length of the sliding window the refusals are counted in."),
        P("threshold", "Events to fire", "int", "30", "", "How many refusals inside one window before the rule fires."),
    ),
    "SIGMA-WEB-0075": (
        P("pattern", "Webshell path", "regex", _WEBSHELL.pattern, "http.path", "Matched against the request path of every web request."),
    ),
    "SIGMA-WEB-0079": (
        P("pattern", "JNDI lookup", "regex", _JNDI.pattern, "http.path", "Matched against the request path, the user-agent and the raw line."),
    ),
    "SIGMA-WEB-0084": (
        P("minLength", "Path length to fire", "int", "1000", "http.path", "Request paths at least this many characters long are flagged."),
    ),
    "SIGMA-AUTH-0230": (
        P("businessStart", "Business hours start (UTC)", "int", "6", "", "First hour of the working day, 0-23, in UTC."),
        P("businessEnd", "Business hours end (UTC)", "int", "20", "", "Last hour of the working day, 0-23, in UTC. A sign-in outside start..end fires."),
        P("logonTypes", "Interactive logon types", "values", "2, 10, 11", "LogonType", "Windows 4624 logon types treated as a person signing in."),
    ),
    "SIGMA-WIN-0160": (
        P("eventIds", "Defender event IDs", "values", "1116, 1117, 5001, 5007", "EventID", "Windows Defender event ids that fire the rule."),
        P("severeIds", "Ids treated as critical", "values", "1116, 5001", "EventID", "Of those, the ids raised to critical: malware found, or protection switched off."),
    ),
    "SIGMA-WIN-0170": (
        P("eventId", "Event ID", "text", "4625", "EventID", "Windows Security event id counted as a failed logon."),
        P("window", "Time window", "seconds", "900", "", "Length of the sliding window the distinct accounts are counted in."),
        P("distinctAccounts", "Distinct accounts to fire", "int", "10", "TargetUserName", "How many DIFFERENT accounts one source must fail against."),
    ),
    "SIGMA-WIN-0175": (
        P("eventIds", "Event IDs", "values", "7045, 4697", "EventID", "Windows event ids that mean a service was installed."),
    ),
    "SIGMA-WIN-0180": (
        P("eventIds", "Event IDs", "values", "4698, 106", "EventID", "Windows event ids that mean a scheduled task was created."),
    ),
    "SIGMA-WIN-0185": (
        P("eventId", "Event ID", "text", "4688", "EventID", "Windows Security event id for process creation."),
        P("pattern", "Recovery destruction", "regex", _RECOVERY_DESTROY.pattern, "CommandLine", "Matched against the command line of every process creation."),
    ),
    "SIGMA-WIN-0190": (
        P("eventId", "Event ID", "text", "4769", "EventID", "Windows Security event id for a Kerberos service ticket request."),
        P("encryptionTypes", "Ticket encryption types", "values", "0x17, 0x18, 23", "TicketEncryptionType", "Encryption types treated as weak (RC4)."),
        P("window", "Time window", "seconds", "600", "", "Length of the sliding window the requests are counted in."),
        P("threshold", "Events to fire", "int", "10", "", "How many weak-cipher ticket requests inside one window before the rule fires."),
    ),
    "SIGMA-LNX-0060": (
        P("pattern", "Reverse shell", "regex", _REVERSE_SHELL.pattern, "raw", "Matched against the raw line of every syslog event."),
    ),
    "SIGMA-LNX-0065": (
        P("pattern", "Persistence path", "regex", _CRON_PERSIST.pattern, "raw", "Matched against the raw line of every syslog event."),
        P("programs", "Scheduler programs", "values", "cron, crontab, systemd, anacron", "program", "syslog programs whose lines are checked against the pattern."),
    ),
    "SIGMA-LNX-0070": (
        P("pattern", "SUID change", "regex", _SUID.pattern, "raw", "Matched against the raw line of every syslog event."),
    ),
    "SIGMA-LNX-0075": (
        P("pattern", "Kernel module", "regex", _KERNEL_MODULE.pattern, "raw", "Matched against the raw line of every syslog event."),
    ),
    "SIGMA-AWS-0080": (
        P("eventNames", "CloudTrail events", "values", "PutBucketAcl, PutBucketPolicy, PutBucketWebsite, DeletePublicAccessBlock, PutAccountPublicAccessBlock",
          "eventName", "Any one of these eventNames is checked for the public markers below."),
        P("publicMarkers", "Public principal markers", "values", "AllUsers, AuthenticatedUsers, \"Principal\":\"*\", \"Principal\": \"*\"", "raw",
          "Any of these appearing in the raw event body means the bucket was opened up."),
    ),
    "SIGMA-AWS-0085": (
        P("eventNames", "CloudTrail events", "values", "GetSecretValue, GetParameter, GetParameters, GetParametersByPath, Decrypt", "eventName",
          "Events counted as a secret being read."),
        P("window", "Time window", "seconds", "300", "", "Length of the sliding window the reads are counted in."),
        P("threshold", "Events to fire", "int", "20", "", "How many secret reads inside one window before the rule fires."),
    ),
    "SIGMA-AWS-0090": (
        P("eventNames", "CloudTrail events", "values", "ModifySnapshotAttribute, ModifyImageAttribute, ModifyDBSnapshotAttribute, ShareDirectory", "eventName",
          "Events that can hand a disk image to another account."),
        P("shareMarkers", "Sharing markers", "values", "\"all\", add, restore, LaunchPermission", "raw",
          "Any of these in the raw event body means the change was a share rather than a revoke."),
    ),
    "SIGMA-AWS-0095": (
        P("eventNames", "CloudTrail events", "values", "DeleteDetector, UpdateDetector, StopMonitoringMembers, DeleteConfigurationRecorder, StopConfigurationRecorder, DisableSecurityHub, DisableMacie, DeleteMembers",
          "eventName", "Any one of these eventNames fires the rule."),
    ),
    "SIGMA-K8S-0030": (
        P("resources", "Resources", "values", "clusterrolebindings, rolebindings", "resource", "Audit resources that grant a role."),
        P("verbs", "Verbs", "values", "create, update, patch", "verb", "Verbs that mean the binding was written."),
        P("roles", "Roles watched", "values", "cluster-admin, admin", "raw", "A binding naming one of these roles in the raw request fires the rule."),
    ),
    "SIGMA-K8S-0035": (
        P("users", "Anonymous identities", "values", "system:anonymous", "user", "Audit users that mean the request carried no identity."),
        P("groups", "Unauthenticated groups", "values", "system:unauthenticated", "raw", "Groups in the raw request that mean the same thing."),
    ),
    "SIGMA-MAIL-0010": (
        P("verdictFields", "Verdict fields", "values", "spf, dkim, dmarc, auth_results", "spf", "Fields holding the sender-authentication verdicts."),
        P("failValues", "Failure verdicts", "values", "fail, softfail, permerror, temperror", "spf",
          "Verdict values treated as a failure. 'none' is deliberately NOT shipped: dmarc=none is a published "
          "policy rather than a failed check, and it is common enough that including it would make the rule noise."),
    ),
    "SIGMA-MAIL-0014": (
        P("pattern", "Dangerous attachment", "regex", _ATTACHMENT_BAD.pattern, "attachments", "Matched against the attachment names of every message."),
    ),
    "SIGMA-PCAP-0010": (
        P("minLength", "Query length to fire", "int", "60", "dns_query", "DNS names at least this many characters long are flagged."),
        P("pattern", "Long label", "regex", _LONG_LABEL.pattern, "dns_query", "A single label matching this is flagged whatever the total length."),
    ),
    "SIGMA-PCAP-0014": (
        P("window", "Time window", "seconds", "60", "", "Length of the sliding window the queries are counted in."),
        P("threshold", "Events to fire", "int", "300", "", "How many queries from one host inside one window before the rule fires."),
    ),
    "SIGMA-PCAP-0018": (
        P("ports", "Cleartext ports", "values", "21, 23, 110, 143, 512, 513, 514", "dst_port", "Destination ports whose protocols carry credentials in the clear."),
    ),
    "SIGMA-PCAP-0022": (
        P("pattern", "Suspicious domain", "regex", _SUSPICIOUS_SNI.pattern, "tls_sni", "Matched against the server name in every TLS ClientHello."),
    ),
    "SIGMA-PCAP-0026": (
        P("flags", "TCP flags", "text", "SYN", "tcp_flags", "The exact flag set counted as a connection attempt."),
        P("window", "Time window", "seconds", "60", "", "Length of the sliding window the ports are counted in."),
        P("distinctPorts", "Distinct ports to fire", "int", "50", "dst_port", "How many DIFFERENT destination ports one source must try."),
    ),
    "SIGMA-PCAP-0030": (
        P("standardPorts", "Standard TLS ports", "values", "443, 8443, 993, 995, 465, 587, 990, 4443", "dst_port", "Ports where TLS is unremarkable; anything else fires."),
    ),
    "SIGMA-APP-0070": (
        P("pattern", "Secret material", "regex", _SECRET.pattern, "raw",
          "Matched against the raw line of every event, whatever its source. Keep the (?P<name>…)/(?P<value>…) "
          "groups on the assigned-secret branch: they are what the placeholder / URL checks below read."),
        P("urlPublicParams", "Public URL parameters", "values", _SECRET_URL_PUBLIC, "raw",
          "Query-string names that carry a PUBLIC key when found in a URL (?name= / &name=): ignored there. "
          "password / secret / token are deliberately not listed - credentials in a URL are a real leak."),
        P("placeholders", "Placeholder values", "values", _SECRET_PLACEHOLDERS, "raw",
          "Assigned values that are never a secret (sentinels and masks). Templates (${…}, {{…}}, %s) and "
          "repeated-character masks are always ignored."),
    ),
    "SIGMA-APP-0075": (
        P("pattern", "Encoded command", "regex", _ENCODED_CMD.pattern, "raw", "Matched against the raw line of every event, whatever its source."),
    ),
    "SIGMA-APP-0080": (
        P("pattern", "Ransomware indicator", "regex", _RANSOM.pattern, "raw", "Matched against the raw line of every event, whatever its source."),
    ),
    "SIGMA-AUTH-0240": (
        P("window", "Time window", "seconds", "3600", "", "Length of the sliding window the addresses are counted in."),
        P("distinctIps", "Distinct addresses to fire", "int", "5", "src_ip",
          "How many DIFFERENT source addresses one account must be used from."),
        P("ignoreAccounts", "Accounts ignored", "values", "-, anonymous, system, network service, local service", "user",
          "Accounts that are not people and would otherwise dominate the count."),
    ),
    "SIGMA-WIN-0200": (
        P("eventId", "Event ID", "text", "4648", "EventID", "Windows Security event id for a logon with explicit credentials."),
        P("ignoreAccounts", "Accounts ignored", "values", "system, local service, network service, -", "SubjectUserName",
          "Subjects that are the machine itself rather than a person."),
    ),
    "SIGMA-WIN-0205": (
        P("eventId", "Event ID", "text", "4740", "EventID", "Windows Security event id for an account lockout."),
    ),
    "SIGMA-WIN-0210": (
        P("eventIds", "Event IDs", "values", "5136, 5137, 5141", "EventID", "Directory service change event ids."),
    ),
    "SIGMA-WIN-0215": (
        P("eventIds", "Event IDs", "values", "4657, 4688, 13", "EventID", "Registry-modification event ids to inspect."),
        P("pattern", "Credential caching", "regex", _WDIGEST.pattern, "ObjectName",
          "Matched against the registry object name and the command line."),
    ),
    "SIGMA-WIN-0220": (
        P("eventId", "Event ID", "text", "4104", "EventID", "PowerShell operational event id carrying the script block."),
        P("pattern", "Suspicious script", "regex", _PS_SCRIPT.pattern, "ScriptBlockText",
          "Matched against the captured script block text."),
    ),
    "SIGMA-WIN-0225": (
        P("eventId", "Event ID", "text", "4624", "EventID", "Windows Security event id for a successful logon."),
        P("logonTypes", "Logon types", "values", "10, 7", "LogonType", "Logon types that mean a remote interactive session."),
    ),
    "SIGMA-WIN-0230": (
        P("eventIds", "Event IDs", "values", "2004, 2005, 2006, 2033, 4946, 4947, 4948, 4950", "EventID",
          "Windows Firewall rule-change event ids."),
    ),
    "SIGMA-WIN-0235": (
        P("eventId", "Event ID", "text", "104", "EventID", "Event id logged when a channel other than Security is cleared."),
    ),
    "SIGMA-WIN-0250": (
        P("eventIds", "Event IDs", "values", "5140, 5145", "EventID", "Network share access event ids."),
        P("pattern", "Administrative share", "regex", _ADMIN_SHARE.pattern, "ShareName",
          "Matched against the share name of the access."),
    ),
    "SIGMA-WIN-0255": (
        P("eventIds", "Event IDs", "values", "4656, 4663, 4690", "EventID", "Object access event ids."),
        P("pattern", "Target process", "regex", _LSASS.pattern, "ObjectName",
          "Matched against the name of the object that was opened."),
    ),
    "SIGMA-AZURE-0010": (
        P("riskFields", "Risk fields", "values", "riskLevelDuringSignIn, riskLevelAggregated, riskState, properties.riskLevelDuringSignIn",
          "riskLevelDuringSignIn", "Fields Entra ID publishes its risk verdict in."),
        P("riskLevels", "Risk levels", "values", "high, medium, atRisk, confirmedCompromised", "riskLevelDuringSignIn",
          "Verdicts treated as risky."),
    ),
    "SIGMA-AZURE-0014": (
        P("clientApps", "Legacy client apps", "values",
          "IMAP4, POP3, SMTP AUTH, MAPI Over HTTP, Exchange ActiveSync, Exchange Online PowerShell, Other clients, Authenticated SMTP",
          "clientAppUsed", "Client app values that cannot present a second factor."),
    ),
    "SIGMA-AZURE-0018": (
        P("resultTypes", "Result codes", "values", "500121, 50074, 50076, 50079, 50072", "resultType",
          "Entra ID result codes that mean the second factor was not satisfied."),
    ),
    "SIGMA-AZURE-0022": (
        P("statusValues", "Conditional access status", "values", "failure", "conditionalAccessStatus",
          "Values that mean policy refused the sign-in."),
        P("resultTypes", "Result codes", "values", "53003, 53000, 53001, 53004", "resultType",
          "Result codes that mean the same thing when the status field is absent."),
    ),
    "SIGMA-AZURE-0026": (
        P("successResult", "Success result code", "text", "0", "resultType",
          "The result code that means the sign-in worked; anything else is counted as a failure."),
        P("window", "Time window", "seconds", "300", "", "Length of the sliding window the failures are counted in."),
        P("threshold", "Events to fire", "int", "10", "", "How many failures inside one window before the rule fires."),
    ),
    "SIGMA-AZURE-0030": (
        P("operations", "Audit operations", "values",
          "Consent to application, Add OAuth2PermissionGrant, Add app role assignment grant to user, Add delegated permission grant",
          "operationName", "Audit operations that grant an application access to data."),
    ),
    "SIGMA-AZURE-0034": (
        P("operations", "Audit operations", "values", "Add member to role, Add eligible member to role, Add member to role in PIM requested",
          "operationName", "Audit operations that put an account into a directory role."),
        P("roles", "Privileged roles", "values",
          "Global Administrator, Company Administrator, Privileged Role Administrator, Privileged Authentication Administrator, "
          "Security Administrator, Exchange Administrator, SharePoint Administrator, Application Administrator, Cloud Application Administrator, User Administrator",
          "raw", "Roles worth flagging when one of the operations above names them."),
    ),
    "SIGMA-AZURE-0038": (
        P("operations", "Audit operations", "values",
          "Add service principal, Add service principal credentials, Update application - Certificates and secrets management, Add application",
          "operationName", "Audit operations that create a non-human identity or give one a new key."),
    ),
    "SIGMA-AZURE-0042": (
        P("countryFields", "Country fields", "values", "location.countryOrRegion, countryOrRegion, country, location_country",
          "location.countryOrRegion", "Fields the sign-in log publishes the country in."),
        P("window", "Time window", "seconds", "3600", "", "Length of the sliding window the countries are counted in."),
        P("distinctCountries", "Distinct countries to fire", "int", "2", "", "How many DIFFERENT countries one identity must sign in from."),
    ),
    "SIGMA-AZURE-0046": (
        P("operations", "Audit operations", "values",
          "Delete conditional access policy, Update conditional access policy, Disable Strong Authentication, "
          "Update authentication methods policy, Disable security defaults, Update policy",
          "operationName", "Audit operations that weaken or remove an access control."),
    ),
    "SIGMA-M365-0010": (
        P("severityField", "Severity field", "text", "Severity", "Severity", "Field the alert publishes its severity in."),
        P("severities", "Severities", "values", "high, medium, informational", "Severity", "Alert severities worth surfacing."),
        P("markers", "Alert markers", "values", "AlertId, ProviderName, DetectionSource, ThreatFamilyName", "AlertId",
          "Any of these fields present marks the event as a Defender alert."),
    ),
    "SIGMA-M365-0014": (
        P("operations", "Audit operations", "values", "New-InboxRule, Set-InboxRule, UpdateInboxRules, Enable-InboxRule",
          "Operation", "Audit operations that create or change a mailbox rule."),
    ),
    "SIGMA-M365-0018": (
        P("operations", "Audit operations", "values", "Set-Mailbox, Set-InboxRule, New-InboxRule, Set-TransportRule, New-TransportRule",
          "Operation", "Operations that can configure forwarding."),
        P("pattern", "Forwarding parameters", "regex", _FORWARDING.pattern, "raw",
          "Matched against the raw event body to confirm forwarding was actually set."),
    ),
    "SIGMA-M365-0022": (
        P("operations", "Audit operations", "values",
          "SearchStarted, SearchExported, ViewedSearchExported, New-ComplianceSearch, New-ComplianceSearchAction, Start-ComplianceSearch",
          "Operation", "eDiscovery and content-search operations."),
    ),
    "SIGMA-M365-0026": (
        P("operations", "Audit operations", "values",
          "AnonymousLinkCreated, AnonymousLinkUsed, SecureLinkCreated, AddedToSecureLink, SharingInvitationCreated, CompanyLinkCreated",
          "Operation", "Sharing operations that create a link or invite someone outside the tenant."),
    ),
    "SIGMA-M365-0030": (
        P("operations", "Audit operations", "values", "FileDownloaded, FileSyncDownloadedFull, FileSyncUploadedFull, FilePreviewed",
          "Operation", "Operations counted as pulling files."),
        P("window", "Time window", "seconds", "600", "", "Length of the sliding window the downloads are counted in."),
        P("threshold", "Events to fire", "int", "100", "", "How many file operations inside one window before the rule fires."),
    ),
    "SIGMA-M365-0034": (
        P("pattern", "Threat verdict", "regex", _THREAT_VERDICT.pattern, "ThreatType",
          "Matched against the threat/verdict/delivery fields of a mail security event."),
        P("fields", "Verdict fields", "values", "ThreatType, Verdict, DeliveryAction, DetectionMethod, PhishConfidenceLevel",
          "ThreatType", "Fields a mail security product publishes its verdict in."),
    ),
    "SIGMA-M365-0038": (
        P("operations", "Audit operations", "values",
          "Set-AdminAuditLogConfig, Set-MailboxAuditBypassAssociation, Set-Mailbox -AuditEnabled, Remove-UnifiedAuditLogRetentionPolicy",
          "Operation", "Operations that switch audit logging off or narrow it."),
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


# Built-ins that are NOT evaluated by run_rules. `app/graph_rules.py` registers its catalogue here at
# import time so there is ONE list of built-in rules: /api/rules, the toggle, the removal, the metadata
# override and `param_spec` all keep working with no second code path, and the analyst sees one screen.
# `RULES` stays the event catalogue — run_rules must never iterate a rule it cannot evaluate.
EXTRA_RULES: list[Rule] = []


def register_builtins(rules: Iterable[Rule], params: dict[str, tuple[Param, ...]]) -> None:
    """Add rules that live in another module to the shipped catalogue (see EXTRA_RULES).

    Idempotent by id: a module re-imported under a different name (tests do this) must not double the
    catalogue, which would show every graph rule twice on the rules screen.
    """
    PARAMS.update(params)
    have = {r.id for r in EXTRA_RULES}
    for r in rules:
        if r.id in have:
            continue
        EXTRA_RULES.append(replace(r, params=params.get(r.id, r.params)))
        have.add(r.id)


def all_builtin_rules() -> list[Rule]:
    """Every shipped rule the CATALOGUE knows about: event rules plus the registered graph rules.

    The import is HERE, lazily, rather than being left to whoever calls first. A catalogue whose size
    depends on which modules happen to have been imported is a catalogue that is sometimes a dozen rules
    short — and the symptom would be a rules screen missing the graph rules, or a `restore-defaults` that
    quietly drops them, both of which look like data loss rather than an import order. Importing inside
    the function is safe because graph_rules only needs names this module has already defined.
    """
    if not EXTRA_RULES:
        try:
            from . import graph_rules  # noqa: F401  (registers itself on import)
        except Exception:  # noqa: BLE001 - a broken optional catalogue must not take the rules API down
            pass
    return RULES + EXTRA_RULES


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
# The compiled EXCLUSIONS for this pass (app/exclusions.py), or None. Handed in by the caller exactly
# like `disabled` / `overrides` / `params`, so this module still depends on nothing but models+normalize:
# the engine must be testable without a store, a settings file or a suppression list on disk.
_EXCLUDE: Optional[object] = None
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
    # THE ONE CHOKE POINT for a built-in detection, which is why the exclusion check lives here rather
    # than in each of the sixty-odd call sites. It suppresses the CLAIM, never the event: the line stays
    # in the pool, in search and on the timeline, and only the rule's assertion about it is dropped.
    ex = _EXCLUDE
    if ex is not None and not ex.empty and ex.excluded(ev, rule.id):  # type: ignore[attr-defined]
        return
    ov = _OVERRIDES.get(rule.id)
    # an analyst-set severity wins over the shipped one, including over a per-call escalation
    lvl = (ov or {}).get("sev") or level or rule.level
    name = (ov or {}).get("name") or rule.name
    if any(d.id == rule.id for d in ev.detections):
        return
    ev.add_detection(Detection(name=name, id=rule.id, level=lvl))  # type: ignore[arg-type]
    ev.sev = max_sev(ev.sev, lvl)  # type: ignore[assignment]


_FAMILIES = ("nginx.access", "windows.evtx", "syslog", "k8s.audit", "app.jsonl",
             "network.pcap", "mail.message")
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


def find_distinct_bursts(idx: Iterable[int], ts: np.ndarray, key_of: Callable[[int], str],
                         val_of: Callable[[int], str], window_s: float, threshold: int) -> list[tuple[str, int, int, int]]:
    """Like find_bursts, but the threshold counts DISTINCT VALUES, not events.

    "One source failed 200 times" and "one source failed against 40 different accounts" are different
    findings with different responses, and a plain event count cannot tell them apart: a spray that tries
    each account twice never reaches a volume threshold, and a single account locked out by a script
    trivially does. So the two helpers exist side by side and neither is a special case of the other.

    Returns (key, anchor_index, distinct_count, first_index) with the anchor being the last event of the
    densest window — the same contract as find_bursts, so the callers look identical.

    Deliberately NOT vectorised: `searchsorted` gives the window bounds in one shot but the distinct
    count inside a moving window is a running multiset, which is a scan whatever the backend. Groups are
    per-source and small; the cost is the grouping, which both helpers pay.
    """
    groups: dict[str, list[int]] = defaultdict(list)
    for i in idx:
        k = key_of(i)
        if k:
            groups[k].append(i)
    out: list[tuple[str, int, int, int]] = []
    for key, members in groups.items():
        if len(members) < threshold:
            continue                      # fewer events than distinct values needed: impossible
        arr = np.asarray(members)
        t = ts[arr]
        order = np.argsort(t, kind="stable")
        arr, t = arr[order], t[order]
        seen: dict[str, int] = {}
        left = 0
        best = (0, -1, -1)                # (distinct, anchor, first)
        for r in range(arr.shape[0]):
            v = val_of(int(arr[r]))
            if v:
                seen[v] = seen.get(v, 0) + 1
            while t[r] - t[left] > window_s:
                lv = val_of(int(arr[left]))
                if lv:
                    n = seen.get(lv, 0) - 1
                    if n <= 0:
                        seen.pop(lv, None)
                    else:
                        seen[lv] = n
                left += 1
            if len(seen) > best[0]:
                best = (len(seen), int(arr[r]), int(arr[left]))
        if best[0] >= threshold:
            out.append((key, best[1], best[0], best[2]))
    return out


_SCREEN_CACHE: dict[tuple[str, ...], Optional["re.Pattern[str]"]] = {}


def _screen(patterns: list["re.Pattern[str]"]) -> Optional["re.Pattern[str]"]:
    """One alternation over several rule patterns, used as a cheap pre-filter.

    A rule that scans EVERY event (not one family) cannot afford one pass per rule, so the patterns are
    joined and the individual regexes only run on a line the union already matched. Cached on the pattern
    texts, because an analyst override changes them and a stale screen would silently stop matching.
    Returns None if the union will not compile — the caller then skips the pass rather than guessing,
    which is the safe direction: a rule that reports nothing is visibly not firing, whereas a screen
    that quietly drops half the lines is a silent evidence bug.
    """
    key = tuple(p.pattern for p in patterns)
    if key in _SCREEN_CACHE:
        return _SCREEN_CACHE[key]
    try:
        rx: Optional["re.Pattern[str]"] = re.compile("|".join(f"(?:{p})" for p in key), re.I)
    except re.error:
        rx = None
    _SCREEN_CACHE[key] = rx
    return rx


# ---- shared readers for the cloud rules. Azure, Microsoft 365 and Defender publish the same idea under
#      several spellings depending on which export produced the file (Monitor, Graph, advanced hunting,
#      a CSV from the portal), and a rule that only knows one spelling silently covers a fraction of the
#      evidence. One lookup helper, used by every cloud rule, is the difference between that and this.
def _cloud_get(fields: dict, *names: str) -> str:
    for n in names:
        v = fields.get(n)
        if v:
            return str(v)
    return ""


def _cloud_identity(e: Event) -> str:
    """Who a cloud record is about — the identity, not the record id."""
    return (_cloud_get(e.fields, "userPrincipalName", "UserPrincipalName", "userId", "UserId", "UserKey",
                       "identity", "Identity", "initiatedBy.user.userPrincipalName", "actor")
            or e.user or "")


_AUTH_SUCCESS_IDS = ("4624", "4625")


def _auth_user(e: Event, ignore: set) -> str:
    """The account an event authenticated, or '' when it is not an authentication at all.

    Deliberately conservative: a rule that counts DISTINCT ADDRESSES PER ACCOUNT is only meaningful over
    events that really are sign-ins, and treating every line that happens to carry a user name as one
    would count a log entry mentioning an account as the account being used.
    """
    f = e.fields
    src = e.source
    user = ""
    if src == "windows.evtx":
        if f.get("EventID", "") in _AUTH_SUCCESS_IDS:
            user = f.get("TargetUserName", "")
    elif src == "syslog":
        if f.get("program", "").lower() == "sshd" and f.get("result", ""):
            user = f.get("user", "") or e.user
    elif src == "nginx.access":
        if f.get("http.status", "").startswith("2") and _LOGIN_PATH.search(f.get("http.path", "")):
            user = e.user or f.get("user", "")
    elif src == "aws.cloudtrail":
        if f.get("eventName", "") == "ConsoleLogin":
            user = e.user
    else:
        if _cloud_get(f, "resultType", "ResultType", "properties.resultType") or f.get("signInEventTypes"):
            user = _cloud_identity(e)
    user = (user or "").strip()
    if not user or user.lower() in ignore or user.endswith("$"):
        return ""
    return user.lower()


def _auth_ip(e: Event) -> str:
    return _cloud_get(e.fields, "IpAddress", "src_ip", "sourceIPAddress", "ipAddress", "callerIpAddress",
                      "ClientIP", "ClientIPAddress", "client_ip") or ""


def run_rules(events: list[Event], ts: np.ndarray, disabled: Optional[set[str]] = None,
              overrides: Optional[dict[str, dict]] = None,
              params: Optional[dict[str, dict[str, str]]] = None,
              exclude: Optional[object] = None,
              progress: Optional[Callable[[float], None]] = None) -> dict[str, object]:
    """Evaluate all built-in rules over the events (in-place). Returns summary info (attacker IPs, fired count).

    `progress(pct)` is called at the catalogue's section boundaries with a rough 0-100. Rough on
    purpose — the sections are not equal work — but a pass that takes nine minutes on a large pool and
    reports nothing is indistinguishable from a hang, and "detecting 60 %" moving is not.

    `disabled` = built-in rule ids that must not fire (toggled off or removed in /api/rules).
    `overrides` = {rule_id: {"name","sev"}} analyst edits applied to the detections this run produces.
    `params`    = {rule_id: {param key: value}} analyst-tuned CONDITIONS. Every threshold, window, event
                  id, value list and regex below is read from here, falling back to the shipped default.
    """
    global _DISABLED, _OVERRIDES, _PARAMS, _EXCLUDE
    _DISABLED = set(disabled or ())
    _OVERRIDES = dict(overrides or {})
    _PARAMS = {k: dict(v) for k, v in (params or {}).items()}
    _EXCLUDE = exclude
    def _tick(p: float) -> None:
        if progress is not None:
            try:
                progress(p)
            except Exception:  # noqa: BLE001 — a progress listener must never fail a pass
                pass
    _tick(0.0)
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
    _tick(5.0)
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


    _tick(35.0)
    # ================================================================ the wider catalogue
    # Everything below was added alongside the pcap parser. Each block re-uses a bucket already built
    # above — no second walk of the pool per rule — and every constant is read ONCE into a local before
    # its loop, for the reason documented against the original sections.

    # --- web (continued): 403 bursts, webshells, JNDI, oversized paths
    w71_statuses = _pl("SIGMA-WEB-0071", "statuses")
    for ip, anchor, count, first in find_bursts(
        (i for i in web if events[i].fields.get("http.status", "").lower() in w71_statuses), ts,
            lambda i: events[i].fields.get("src_ip", ""), _pn("SIGMA-WEB-0071", "window"), _pn("SIGMA-WEB-0071", "threshold")):
        _tag(events[anchor], R["WEB-0071"])
        events[anchor].set_field("burst.count", str(count))
        attackers.setdefault(ip, "403 burst")
    rx_webshell = _prx("SIGMA-WEB-0075", "pattern", _WEBSHELL)
    rx_jndi = _prx("SIGMA-WEB-0079", "pattern", _JNDI)
    w84_min = _pn("SIGMA-WEB-0084", "minLength")
    for i in web:
        e = events[i]
        path = e.fields.get("http.path", "")
        if path and rx_webshell.search(path):
            _tag(e, R["WEB-0075"])
            attackers.setdefault(e.fields.get("src_ip", ""), "webshell request")
        if (path and rx_jndi.search(path)) or rx_jndi.search(e.fields.get("user_agent", "")) or rx_jndi.search(e.raw):
            _tag(e, R["WEB-0079"])
            e.set_field("tactic", "exploitation")
            attackers.setdefault(e.fields.get("src_ip", ""), "jndi injection")
        if len(path) >= w84_min:
            _tag(e, R["WEB-0084"])
            e.set_field("path.length", str(len(path)))

    # --- sign-in outside business hours. The hour comes from the ts ARRAY, not from re-parsing the
    #     timestamp text: run_rules already has it, and an unstamped event (ts 0.0) must never be read
    #     as "midnight" — a raw-phase event has no time, which is not the same as a time of 00:00.
    a230_start, a230_end = _pn("SIGMA-AUTH-0230", "businessStart"), _pn("SIGMA-AUTH-0230", "businessEnd")
    a230_types = _pl("SIGMA-AUTH-0230", "logonTypes", lower=False)

    def _outside_hours(i: int) -> bool:
        # An event with no parseable timestamp is float('inf') in `ts`: `_iso_to_epoch("")`
        # returns it deliberately, so an unstamped event sorts last and matches no window. But
        # `inf` walks straight past a `t <= 0` guard, and `int((inf // 3600) % 24)` is
        # `int(nan)` -> ValueError, raised out of run_rules, taking the WHOLE catalogue pass with
        # it. One EVTX 4624 or one successful ConsoleLogin whose timestamp did not parse was
        # enough to stop the workspace being scanned at all, silently, because the background
        # refresh has a catch-all. The bound below rejects 0 (unset), inf (unstamped) and nan
        # (no comparison holds), which is every value that is not a real moment in time.
        t = float(ts[i])
        if not 0.0 < t < float("inf"):
            return False
        hour = int((t // 3600) % 24)
        return hour < a230_start or hour > a230_end

    # --- Windows (continued)
    win = fam_of["windows.evtx"]
    w160_ids, w160_severe = _pl("SIGMA-WIN-0160", "eventIds", lower=False), _pl("SIGMA-WIN-0160", "severeIds", lower=False)
    w175_ids = _pl("SIGMA-WIN-0175", "eventIds", lower=False)
    w180_ids = _pl("SIGMA-WIN-0180", "eventIds", lower=False)
    w185_id = _pt("SIGMA-WIN-0185", "eventId")
    rx_recovery = _prx("SIGMA-WIN-0185", "pattern", _RECOVERY_DESTROY)
    a230_win_id = "4624"
    for i in win:
        e = events[i]
        eid = e.fields.get("EventID", "")
        if eid in w160_ids:
            _tag(e, R["WIN-0160"], "critical" if eid in w160_severe else None)
        if eid in w175_ids:
            _tag(e, R["WIN-0175"])
            e.set_field_default("tactic", "persistence")
        if eid in w180_ids:
            _tag(e, R["WIN-0180"])
            e.set_field_default("tactic", "persistence")
        if eid == w185_id and rx_recovery.search(e.fields.get("CommandLine", "") + " " + e.fields.get("NewProcessName", "")):
            _tag(e, R["WIN-0185"])
            e.set_field("tactic", "impact")
        if eid == a230_win_id and any(e.fields.get("LogonType", "").startswith(t) for t in a230_types) and _outside_hours(i):
            _tag(e, R["AUTH-0230"])
            e.set_field("signin.hour", f"{int((float(ts[i]) // 3600) % 24):02d}:00 UTC")
    w170_id = _pt("SIGMA-WIN-0170", "eventId")
    for ip, anchor, count, first in find_distinct_bursts(
        (i for i in win if events[i].fields.get("EventID") == w170_id), ts,
            lambda i: events[i].fields.get("IpAddress", ""),
            lambda i: events[i].fields.get("TargetUserName", "").lower(),
            _pn("SIGMA-WIN-0170", "window"), _pn("SIGMA-WIN-0170", "distinctAccounts")):
        ev = events[anchor]
        _tag(ev, R["WIN-0170"])
        ev.set_field("spray.accounts", str(count))
        ev.msg = f"password spray — {count} different accounts failed from {ip}"
        if is_public_ip(ip):
            attackers.setdefault(ip, "password spray")
    w190_id, w190_enc = _pt("SIGMA-WIN-0190", "eventId"), _pl("SIGMA-WIN-0190", "encryptionTypes")
    for _, anchor, count, first in find_bursts(
        (i for i in win if events[i].fields.get("EventID") == w190_id
            and events[i].fields.get("TicketEncryptionType", "").lower() in w190_enc), ts,
            lambda i: events[i].fields.get("SubjectUserName") or events[i].user or "kerberos",
            _pn("SIGMA-WIN-0190", "window"), _pn("SIGMA-WIN-0190", "threshold")):
        _tag(events[anchor], R["WIN-0190"])
        events[anchor].set_field("burst.count", str(count))

    # --- Linux (continued): one pass, four regexes, each gated on its own rule
    lnx = fam_of["syslog"]
    rx_revshell = _prx("SIGMA-LNX-0060", "pattern", _REVERSE_SHELL)
    rx_persist = _prx("SIGMA-LNX-0065", "pattern", _CRON_PERSIST)
    l65_progs = _pl("SIGMA-LNX-0065", "programs")
    rx_suid = _prx("SIGMA-LNX-0070", "pattern", _SUID)
    rx_kmod = _prx("SIGMA-LNX-0075", "pattern", _KERNEL_MODULE)
    for i in lnx:
        e = events[i]
        raw = e.raw
        if rx_revshell.search(raw):
            _tag(e, R["LNX-0060"])
            e.set_field("tactic", "command and control")
        if rx_persist.search(raw) or e.fields.get("program", "").lower() in l65_progs and rx_persist.search(e.msg):
            _tag(e, R["LNX-0065"])
            e.set_field_default("tactic", "persistence")
        if rx_suid.search(raw):
            _tag(e, R["LNX-0070"])
            e.set_field_default("tactic", "privilege escalation")
        if rx_kmod.search(raw):
            _tag(e, R["LNX-0075"])

    # --- AWS (continued)
    a80_names, a80_markers = _pl("SIGMA-AWS-0080", "eventNames"), _pl("SIGMA-AWS-0080", "publicMarkers", lower=False)
    a90_names, a90_markers = _pl("SIGMA-AWS-0090", "eventNames"), _pl("SIGMA-AWS-0090", "shareMarkers", lower=False)
    a95_names = _pl("SIGMA-AWS-0095", "eventNames")
    a230_ct_name = "ConsoleLogin"
    for i in ct:
        e = events[i]
        name = e.fields.get("eventName", "")
        lname = name.lower()
        if lname in a80_names and any(m in e.raw for m in a80_markers):
            _tag(e, R["AWS-0080"])
            e.set_field("exposure", "public")
        if lname in a90_names and any(m in e.raw for m in a90_markers):
            _tag(e, R["AWS-0090"])
            e.set_field("tactic", "exfiltration")
        if lname in a95_names:
            _tag(e, R["AWS-0095"])
            e.set_field("tactic", "defense evasion")
        if name == a230_ct_name and e.fields.get("result", "").lower() == "success" and _outside_hours(i):
            _tag(e, R["AUTH-0230"])
    a85_names = _pl("SIGMA-AWS-0085", "eventNames")
    for _, anchor, count, first in find_bursts(
        (i for i in ct if events[i].fields.get("eventName", "").lower() in a85_names), ts,
            lambda i: events[i].user or events[i].fields.get("userIdentity.arn", ""),
            _pn("SIGMA-AWS-0085", "window"), _pn("SIGMA-AWS-0085", "threshold")):
        _tag(events[anchor], R["AWS-0085"])
        events[anchor].set_field("burst.count", str(count))

    # --- Kubernetes (continued)
    k30_res, k30_verbs, k30_roles = _pl("SIGMA-K8S-0030", "resources"), _pl("SIGMA-K8S-0030", "verbs"), _pl("SIGMA-K8S-0030", "roles")
    k35_users, k35_groups = _pl("SIGMA-K8S-0035", "users"), _pl("SIGMA-K8S-0035", "groups")
    for i in k8s:
        e = events[i]
        if e.fields.get("resource", "").lower() in k30_res and e.fields.get("verb", "").lower() in k30_verbs \
                and any(r in e.raw.lower() for r in k30_roles):
            _tag(e, R["K8S-0030"])
            e.set_field("tactic", "privilege escalation")
        if e.user.lower() in k35_users or any(g in e.raw.lower() for g in k35_groups):
            _tag(e, R["K8S-0035"])

    # --- mail
    mail = fam_of["mail.message"]
    m10_fields, m10_fails = _pl("SIGMA-MAIL-0010", "verdictFields", lower=False), _pl("SIGMA-MAIL-0010", "failValues")
    rx_attach = _prx("SIGMA-MAIL-0014", "pattern", _ATTACHMENT_BAD)
    for i in mail:
        e = events[i]
        for f in m10_fields:
            v = e.fields.get(f, "").lower()
            if v and any(x in v for x in m10_fails):
                _tag(e, R["MAIL-0010"])
                e.set_field("auth.verdict", f"{f}={v[:40]}")
                break
        names = e.fields.get("attachments") or e.fields.get("attachment_names") or e.fields.get("attachment", "")
        if names and rx_attach.search(names):
            _tag(e, R["MAIL-0014"])
            e.set_field_default("tactic", "initial access")

    # --- packet captures
    pcap = fam_of["network.pcap"]
    p10_min = _pn("SIGMA-PCAP-0010", "minLength")
    rx_long_label = _prx("SIGMA-PCAP-0010", "pattern", _LONG_LABEL)
    p18_ports = set(_pl("SIGMA-PCAP-0018", "ports"))
    rx_sni = _prx("SIGMA-PCAP-0022", "pattern", _SUSPICIOUS_SNI)
    p30_ports = set(_pl("SIGMA-PCAP-0030", "standardPorts"))
    for i in pcap:
        e = events[i]
        f = e.fields
        q = f.get("dns_query", "")
        if q and (len(q) >= p10_min or rx_long_label.search(q)):
            _tag(e, R["PCAP-0010"])
            e.set_field("dns.query_length", str(len(q)))
        dport = f.get("dst_port", "")
        if dport in p18_ports and f.get("protocol") == "TCP" and f.get("payload_len", "0") != "0":
            _tag(e, R["PCAP-0018"])
            e.set_field_default("encrypted", "no")
        sni = f.get("tls_sni", "")
        if sni:
            if rx_sni.search(sni):
                _tag(e, R["PCAP-0022"])
            if dport and dport not in p30_ports:
                _tag(e, R["PCAP-0030"])
    for ip, anchor, count, first in find_bursts(
        (i for i in pcap if events[i].fields.get("dns_qr") == "query"), ts,
            lambda i: events[i].fields.get("src_ip", ""), _pn("SIGMA-PCAP-0014", "window"), _pn("SIGMA-PCAP-0014", "threshold")):
        _tag(events[anchor], R["PCAP-0014"])
        events[anchor].set_field("burst.count", str(count))
    p26_flags = _pt("SIGMA-PCAP-0026", "flags").upper()
    for ip, anchor, count, first in find_distinct_bursts(
        (i for i in pcap if events[i].fields.get("tcp_flags", "").upper() == p26_flags), ts,
            lambda i: events[i].fields.get("src_ip", ""),
            lambda i: events[i].fields.get("dst_port", ""),
            _pn("SIGMA-PCAP-0026", "window"), _pn("SIGMA-PCAP-0026", "distinctPorts")):
        ev = events[anchor]
        _tag(ev, R["PCAP-0026"])
        ev.set_field("scan.ports", str(count))
        ev.msg = f"port scan — {count} different ports probed from {ip}"
        if is_public_ip(ip):
            attackers.setdefault(ip, "port scan")

    _tick(55.0)
    # --- any source: secrets, encoded commands, ransomware markers.
    # This is the ONE pass that is not restricted to a family, so it is also the only one that can cost a
    # full scan of the pool. It pays for itself by SCREENING first: the three patterns are joined into a
    # single alternation and only a line that matches it is tested against them individually, so the
    # common case is one regex over `raw` and nothing else. The whole pass is skipped when all three
    # rules are off — a disabled rule must not cost a scan of the evidence.
    rx_secret = _prx("SIGMA-APP-0070", "pattern", _SECRET)
    s70_public = set(_pl("SIGMA-APP-0070", "urlPublicParams"))
    s70_placeholders = set(_pl("SIGMA-APP-0070", "placeholders"))
    rx_encoded = _prx("SIGMA-APP-0075", "pattern", _ENCODED_CMD)
    rx_ransom = _prx("SIGMA-APP-0080", "pattern", _RANSOM)
    universal = [(rx_secret, R["APP-0070"], "credential exposure"),
                 (rx_encoded, R["APP-0075"], "defense evasion"),
                 (rx_ransom, R["APP-0080"], "impact")]
    universal = [u for u in universal if u[1].id not in _DISABLED]
    if universal:
        screen = _screen([u[0] for u in universal])
        if screen is not None:
            for e in events:
                raw = e.raw
                if not raw or not screen.search(raw):
                    continue
                for rx, rule, tactic in universal:
                    if not rx.search(raw):
                        continue
                    # the secret rule alone has a second opinion: shape is not enough - see _secret_real
                    if rule is R["APP-0070"] and not _secret_real(raw, rx, s70_public, s70_placeholders):
                        continue
                    _tag(e, rule)
                    e.set_field_default("tactic", tactic)


    _tick(80.0)
    # ================================================================ Windows / Azure / Microsoft 365
    # The cloud rules read the fields the JSON exports carry. Azure sign-in and audit logs, Microsoft 365
    # unified audit and Defender alerts all arrive as JSON (Monitor export, Graph, advanced hunting) or
    # as a CSV of the same shape, so they are looked for in the app.jsonl bucket AND the delimited one -
    # and each event is dismissed on ONE dict lookup when it is not that kind of record.

    # --- Windows (continued)
    w200_id, w200_ignore = _pt("SIGMA-WIN-0200", "eventId"), set(_pl("SIGMA-WIN-0200", "ignoreAccounts")) | _SYSTEM_ACCOUNTS
    w205_id = _pt("SIGMA-WIN-0205", "eventId")
    w210_ids = _pl("SIGMA-WIN-0210", "eventIds", lower=False)
    w215_ids = _pl("SIGMA-WIN-0215", "eventIds", lower=False)
    rx_wdigest = _prx("SIGMA-WIN-0215", "pattern", _WDIGEST)
    w220_id = _pt("SIGMA-WIN-0220", "eventId")
    rx_ps = _prx("SIGMA-WIN-0220", "pattern", _PS_SCRIPT)
    w225_id, w225_types = _pt("SIGMA-WIN-0225", "eventId"), _pl("SIGMA-WIN-0225", "logonTypes", lower=False)
    w230_ids = _pl("SIGMA-WIN-0230", "eventIds", lower=False)
    w235_id = _pt("SIGMA-WIN-0235", "eventId")
    w250_ids = _pl("SIGMA-WIN-0250", "eventIds", lower=False)
    rx_share = _prx("SIGMA-WIN-0250", "pattern", _ADMIN_SHARE)
    w255_ids = _pl("SIGMA-WIN-0255", "eventIds", lower=False)
    rx_lsass = _prx("SIGMA-WIN-0255", "pattern", _LSASS)
    for i in win:
        e = events[i]
        f = e.fields
        eid = f.get("EventID", "")
        if eid == w200_id and f.get("SubjectUserName", "").lower() not in w200_ignore \
                and not f.get("SubjectUserName", "").endswith("$"):
            _tag(e, R["WIN-0200"])
        if eid == w205_id:
            _tag(e, R["WIN-0205"])
        if eid in w210_ids:
            _tag(e, R["WIN-0210"])
        if eid in w215_ids and rx_wdigest.search(f.get("ObjectName", "") + " " + f.get("CommandLine", "")
                                                 + " " + f.get("TargetObject", "")):
            _tag(e, R["WIN-0215"])
            e.set_field("tactic", "credential access")
        if eid == w220_id and rx_ps.search(f.get("ScriptBlockText", "") or e.raw):
            _tag(e, R["WIN-0220"])
        if eid == w225_id and any(f.get("LogonType", "").startswith(t) for t in w225_types) \
                and is_public_ip(f.get("IpAddress", "")):
            _tag(e, R["WIN-0225"])
            attackers.setdefault(f.get("IpAddress", ""), "remote desktop logon")
        if eid in w230_ids:
            _tag(e, R["WIN-0230"])
        if eid == w235_id:
            _tag(e, R["WIN-0235"])
            e.set_field_default("tactic", "defense evasion")
        if eid in w250_ids and rx_share.search(f.get("ShareName", "") or f.get("RelativeTargetName", "")):
            _tag(e, R["WIN-0250"])
            e.set_field_default("tactic", "lateral movement")
        if eid in w255_ids and rx_lsass.search(f.get("ObjectName", "") or f.get("TargetImage", "")):
            _tag(e, R["WIN-0255"])
            e.set_field("tactic", "credential access")

    # --- the cloud bucket: Azure sign-in / audit, Microsoft 365 unified audit, Defender alerts
    cloud = app + net
    az10_fields, az10_levels = _pl("SIGMA-AZURE-0010", "riskFields", lower=False), _pl("SIGMA-AZURE-0010", "riskLevels")
    az14_apps = _pl("SIGMA-AZURE-0014", "clientApps")
    az18_results = _pl("SIGMA-AZURE-0018", "resultTypes")
    az22_status, az22_results = _pl("SIGMA-AZURE-0022", "statusValues"), _pl("SIGMA-AZURE-0022", "resultTypes")
    az30_ops = _pl("SIGMA-AZURE-0030", "operations")
    az34_ops, az34_roles = _pl("SIGMA-AZURE-0034", "operations"), _pl("SIGMA-AZURE-0034", "roles")
    az38_ops = _pl("SIGMA-AZURE-0038", "operations")
    az46_ops = _pl("SIGMA-AZURE-0046", "operations")
    m10_sev_field, m10_sevs, m10_markers = (_pt("SIGMA-M365-0010", "severityField"),
                                            _pl("SIGMA-M365-0010", "severities"),
                                            _pl("SIGMA-M365-0010", "markers", lower=False))
    m14_ops = _pl("SIGMA-M365-0014", "operations")
    m18_ops = _pl("SIGMA-M365-0018", "operations")
    rx_forward = _prx("SIGMA-M365-0018", "pattern", _FORWARDING)
    m22_ops = _pl("SIGMA-M365-0022", "operations")
    m26_ops = _pl("SIGMA-M365-0026", "operations")
    m34_fields = _pl("SIGMA-M365-0034", "fields", lower=False)
    rx_verdict = _prx("SIGMA-M365-0034", "pattern", _THREAT_VERDICT)
    m38_ops = _pl("SIGMA-M365-0038", "operations")
    for i in cloud:
        e = events[i]
        f = e.fields
        # ONE lookup decides whether this is a record of the kind these rules read at all. Without it
        # every rule below would touch every delimited row in the pool.
        op = _cloud_get(f, "operationName", "OperationName", "operation", "Operation", "ActivityDisplayName")
        result = _cloud_get(f, "resultType", "ResultType", "properties.resultType")
        client_app = _cloud_get(f, "clientAppUsed", "ClientAppUsed", "properties.clientAppUsed")
        if op:
            lop = op.lower()
            if any(x in lop for x in az30_ops):
                _tag(e, R["AZURE-0030"])
                e.set_field_default("tactic", "persistence")
            if any(x in lop for x in az34_ops) and any(r in e.raw.lower() for r in az34_roles):
                _tag(e, R["AZURE-0034"])
                e.set_field_default("tactic", "privilege escalation")
            if any(x in lop for x in az38_ops):
                _tag(e, R["AZURE-0038"])
            if any(x in lop for x in az46_ops):
                _tag(e, R["AZURE-0046"])
                e.set_field_default("tactic", "defense evasion")
            if any(x in lop for x in m14_ops):
                _tag(e, R["M365-0014"])
            if any(x in lop for x in m18_ops) and rx_forward.search(e.raw):
                _tag(e, R["M365-0018"])
                e.set_field("tactic", "collection")
            if any(x in lop for x in m22_ops):
                _tag(e, R["M365-0022"])
            if any(x in lop for x in m26_ops):
                _tag(e, R["M365-0026"])
                e.set_field_default("exposure", "external")
            if any(x in lop for x in m38_ops):
                _tag(e, R["M365-0038"])
                e.set_field("tactic", "defense evasion")
        for rf in az10_fields:
            v = f.get(rf, "").lower()
            if v and v in az10_levels:
                _tag(e, R["AZURE-0010"])
                e.set_field_default("risk", v)
                break
        if client_app and client_app.lower() in az14_apps:
            _tag(e, R["AZURE-0014"])
        if result and result in az18_results:
            _tag(e, R["AZURE-0018"])
        if _cloud_get(f, "conditionalAccessStatus", "ConditionalAccessStatus").lower() in az22_status \
                or (result and result in az22_results):
            _tag(e, R["AZURE-0022"])
        if any(f.get(m) for m in m10_markers):
            sev = (f.get(m10_sev_field) or f.get(m10_sev_field.lower()) or "").lower()
            if sev in m10_sevs:
                _tag(e, R["M365-0010"], "critical" if sev == "high" else None)
        for vf in m34_fields:
            v = f.get(vf, "")
            if v and rx_verdict.search(v):
                _tag(e, R["M365-0034"])
                e.set_field_default("verdict", v[:60])
                break
    # Azure sign-in failure burst, distinct countries, and bulk file operations.
    az26_ok = _pt("SIGMA-AZURE-0026", "successResult")
    for _, anchor, count, first in find_bursts(
        (i for i in cloud
         if _cloud_get(events[i].fields, "resultType", "ResultType", "properties.resultType") not in ("", az26_ok)), ts,
            lambda i: _cloud_identity(events[i]), _pn("SIGMA-AZURE-0026", "window"), _pn("SIGMA-AZURE-0026", "threshold")):
        _tag(events[anchor], R["AZURE-0026"])
        events[anchor].set_field("burst.count", str(count))
    az42_fields = _pl("SIGMA-AZURE-0042", "countryFields", lower=False)
    for who, anchor, count, first in find_distinct_bursts(
        (i for i in cloud if _cloud_get(events[i].fields, *az42_fields)), ts,
            lambda i: _cloud_identity(events[i]),
            lambda i: _cloud_get(events[i].fields, *az42_fields).lower(),
            _pn("SIGMA-AZURE-0042", "window"), _pn("SIGMA-AZURE-0042", "distinctCountries")):
        ev = events[anchor]
        _tag(ev, R["AZURE-0042"])
        ev.set_field("signin.countries", str(count))
        ev.msg = f"{who} signed in from {count} different countries"
    m30_ops = _pl("SIGMA-M365-0030", "operations")
    for _, anchor, count, first in find_bursts(
        (i for i in cloud
         if _cloud_get(events[i].fields, "Operation", "operationName", "OperationName").lower() in m30_ops), ts,
            lambda i: _cloud_identity(events[i]), _pn("SIGMA-M365-0030", "window"), _pn("SIGMA-M365-0030", "threshold")):
        _tag(events[anchor], R["M365-0030"])
        events[anchor].set_field("burst.count", str(count))
        events[anchor].set_field_default("tactic", "exfiltration")

    # --- one account, many addresses. Deliberately across EVERY family that carries an authentication:
    # a credential in two pairs of hands rarely shows up in one log, and the whole point of a workspace
    # that holds the web tier, the endpoint and the cloud together is that this question can be asked
    # once instead of three times.
    a240_ignore = set(_pl("SIGMA-AUTH-0240", "ignoreAccounts")) | _SYSTEM_ACCOUNTS
    auth_idx = [i for i in (web + win + lnx + ct + cloud) if _auth_user(events[i], a240_ignore)]
    for who, anchor, count, first in find_distinct_bursts(
        auth_idx, ts, lambda i: _auth_user(events[i], a240_ignore), lambda i: _auth_ip(events[i]),
            _pn("SIGMA-AUTH-0240", "window"), _pn("SIGMA-AUTH-0240", "distinctIps")):
        ev = events[anchor]
        _tag(ev, R["AUTH-0240"])
        ev.set_field("account.addresses", str(count))
        ev.msg = f"{who} authenticated from {count} different addresses"
    _tick(100.0)
    fired = sum(len(e.detections) for e in events)
    suppressed = _EXCLUDE.counts() if (_EXCLUDE is not None and not _EXCLUDE.empty) else {}  # type: ignore[attr-defined]
    return {"fired": fired, "attackers": set(attackers), "rules_evaluated": len(RULES),
            "suppressed": suppressed}
