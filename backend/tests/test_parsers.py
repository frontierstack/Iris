"""Parser sniff + parse tests."""
from __future__ import annotations

import pytest

from app.parsers.cloudtrail import CloudTrailParser
from app.parsers.delimited import DelimitedParser
from app.parsers.evtx import EvtxParser
from app.parsers.jsonl import JsonlParser
from app.parsers.k8s_audit import K8sAuditParser
from app.parsers.nginx import NginxParser
from app.parsers.registry import fingerprint
from app.parsers.syslog import SyslogParser

NGINX = '45.83.140.22 - svc_deploy [11/Aug/2026:03:14:47 +0000] "POST /api/v2/login HTTP/2.0" 200 1284 "-" "python-requests/2.31.0" rt=0.211'
SYSLOG3164 = "Aug 11 03:22:41 bastion-1 sshd[20418]: Accepted publickey for root from 10.22.4.19 port 44120 ssh2: RSA SHA256:8mQ2kL1p"
SYSLOG5424 = '<34>1 2026-08-11T03:22:41Z bastion-1 sshd 20418 - - Accepted publickey for root'
CT = '{"eventVersion":"1.09","eventTime":"2026-08-11T03:16:02Z","eventName":"CreateAccessKey","awsRegion":"us-east-1","sourceIPAddress":"45.83.140.22","userIdentity":{"userName":"svc_deploy","type":"IAMUser"},"responseElements":{"accessKey":{"accessKeyId":"AKIA4YV2XN31LR8Q7QMX","status":"Active"}}}'
K8S = '{"kind":"Event","apiVersion":"audit.k8s.io/v1","verb":"create","stage":"ResponseComplete","objectRef":{"resource":"pods","subresource":"exec","namespace":"payments","name":"payments-api-7c9d"},"user":{"username":"svc_deploy"},"requestURI":"/api/v1/namespaces/payments/pods/payments-api-7c9d/exec?command=/bin/sh","responseStatus":{"code":101}}'
JSONL = '{"ts":"2026-08-11T03:27:15Z","level":"info","svc":"payments-api","event":"export.complete","rows":41208,"dest":"/tmp/x.tar.gz","actor":"svc_deploy"}'
PIPE = "2026-08-11T03:29:50Z|fw-edge-2|ALLOW|10.22.4.19:51993|45.83.140.22:8443|tcp|len=2297851904"
EVTX_XML = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4624</EventID><Computer>WIN-FS01</Computer><TimeCreated SystemTime="2026-08-11T03:21:04.117Z"/></System><EventData><Data Name="TargetUserName">svc_deploy</Data><Data Name="LogonType">3</Data><Data Name="IpAddress">10.22.4.19</Data><Data Name="AuthenticationPackageName">NTLM</Data></EventData></Event>'


def test_nginx_sniff_and_parse():
    p = NginxParser()
    assert p.sniff([NGINX] * 10, "edge-lb-01_access.log") > 0.9
    ev = list(p.parse([NGINX]))[0]
    assert ev.fields["src_ip"] == "45.83.140.22"
    assert ev.fields["http.status"] == "200"
    assert ev.user == "svc_deploy"


def test_syslog_both_formats():
    p = SyslogParser()
    assert p.sniff([SYSLOG3164] * 5) > 0.7
    ev = list(p.parse([SYSLOG3164]))[0]
    assert ev.host == "bastion-1"
    assert ev.fields["result"] == "Accepted"
    assert ev.fields["user"] == "root"
    ev2 = list(p.parse([SYSLOG5424]))[0]
    assert ev2.host == "bastion-1"


def test_cloudtrail():
    p = CloudTrailParser()
    assert p.sniff([CT] * 3) > 0.7
    ev = list(p.parse([CT]))[0]
    assert ev.fields["eventName"] == "CreateAccessKey"
    assert ev.fields["accessKeyId"] == "AKIA4YV2XN31LR8Q7QMX"
    assert ev.user == "svc_deploy"


def test_cloudtrail_records_wrapper():
    wrapped = '{"Records":[' + CT + "]}"
    ev = list(CloudTrailParser().parse([wrapped]))
    assert len(ev) == 1 and ev[0].fields["eventName"] == "CreateAccessKey"


def test_k8s_audit():
    p = K8sAuditParser()
    assert p.sniff([K8S] * 3) > 0.7
    ev = list(p.parse([K8S]))[0]
    assert ev.fields["resource"] == "pods/exec"
    assert ev.user == "svc_deploy"
    assert "exec" in ev.msg


def test_jsonl_infers_keys():
    p = JsonlParser()
    assert p.sniff([JSONL] * 3) > 0.6
    ev = list(p.parse([JSONL]))[0]
    assert ev.host == "payments-api"
    assert ev.user == "svc_deploy"
    assert "41,208" in ev.msg or "41208" in ev.msg


def test_delimited_role_guessing():
    p = DelimitedParser()
    rows = [PIPE] * 30
    assert p.sniff(rows, "fw-edge-2.pipe.log") > 0.5
    ev = list(p.parse([PIPE]))[0]
    assert ev.fields.get("dst") == "45.83.140.22"
    assert ev.fields.get("action", "").upper() == "ALLOW"


def test_delimited_mapping_override():
    p = DelimitedParser(fields=["timestamp", "host", "action", "src", "dst", "proto", "bytes"], delimiter="|")
    ev = list(p.parse([PIPE]))[0]
    assert ev.fields["dst"] == "45.83.140.22"
    assert ev.fields["bytes"] == "2297851904"


def test_evtx_xml_export():
    p = EvtxParser()
    assert p.sniff([EVTX_XML]) >= 0.9
    ev = list(p.parse([EVTX_XML]))[0]
    assert ev.fields["EventID"] == "4624"
    assert ev.host == "WIN-FS01"
    assert "network" in ev.msg


def test_fingerprint_picks_best():
    fp = fingerprint("edge-lb-01_access.log", ("\n".join([NGINX] * 50)).encode())
    assert fp.parser.family == "nginx.access"
    assert fp.state == "READY"


# ------------------------------------------------- exported-search timestamps (Kibana / OpenSearch)
@pytest.mark.parametrize("text,expect", [
    ("Aug 17, 2026 @ 09:32:52.000", "2026-08-17T09:32:52Z"),
    ('"Aug 17, 2026 @ 09:32:52.000"', "2026-08-17T09:32:52Z"),   # the cell kept its quotes
    ("August 17, 2026 @ 9:32:52", "2026-08-17T09:32:52Z"),
    ("Aug 17, 2026 @ 09:32:52.000 +0200", "2026-08-17T07:32:52Z"),
])
def test_a_kibana_export_timestamp_is_parsed(text, expect):
    """How Kibana / OpenSearch / Elastic Discover write a time when a search is exported to CSV.

    dateutil is the last resort in `parse_ts` and `fuzzy=False` refuses the " @ ", so these files
    landed with NO timestamp at all — 11.1 M of 11.4 M events on the analyst's workspace, i.e. 98 % of
    the pool invisible to every time filter, the timeline and every windowed detection, while looking
    perfectly parsed everywhere else. That is the silent-omission class, not a formatting nicety.
    """
    from app.normalize import parse_ts, to_iso

    got = parse_ts(text)
    assert got is not None, text
    assert to_iso(got) == expect


@pytest.mark.parametrize("text", ["1.6", "2096", "not a date", "@ 09:32:52", "Aug 17 @ 09:32:52"])
def test_the_export_shape_does_not_widen_what_counts_as_a_timestamp(text):
    """`parse_ts` deliberately refuses things that merely look numeric — a version string must never
    become a date. The new pattern requires a month name, a day, a four-digit year AND a time."""
    from app.normalize import parse_ts

    assert parse_ts(text) is None


def test_a_csv_exported_from_a_search_gets_a_time_range():
    """End to end: the column is read, the timestamp is parsed, and the source reports a range —
    which is what puts those events on the timeline instead of sorting them last with no time."""
    from app.parsers.csv import CsvParser

    data = (b'time,src_ip,query\n'
            b'"Aug 17, 2026 @ 09:32:52.000","150.171.28.10","example.com"\n'
            b'"Aug 17, 2026 @ 09:33:10.000","10.0.0.5","internal.local"\n')
    rows = list(CsvParser().parse_bytes(data))
    assert len(rows) == 2
    stamped = [r for r in rows if getattr(r, "ts", None) or (isinstance(r, dict) and r.get("ts"))]
    assert stamped, "the exported time column produced no timestamp"
