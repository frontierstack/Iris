"""Generate realistic raw demo log files that reproduce the mockup scenario.

Writes 7 source files into app/demo/. Total stays well under ~1 MB. The files parse
through the real parsers and, once loaded, produce the credential-stuffing -> egress
narrative (clusters, entities, detections) from docs/mockup-reference.html.

Run:  python -m app.demo.gen_demo
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

UTC = timezone.utc
OUT = Path(__file__).resolve().parent
ATTACKER = "45.83.140.22"
PIVOT = "10.22.4.19"
UA_BOT = "python-requests/2.31.0"
UA_HUMAN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
DAY = "2026-08-11"
rnd = random.Random(1337)

BENIGN_PATHS = ["/", "/status", "/api/v2/products", "/api/v2/cart", "/assets/app.js", "/assets/app.css",
                "/api/v2/search?q=shoes", "/favicon.ico", "/api/v2/orders", "/health"]
BENIGN_IPS = ["203.0.113.%d" % i for i in range(2, 40)] + ["198.51.100.%d" % i for i in range(2, 30)]
BENIGN_USERS = ["-", "-", "-", "alice", "bob", "carol", "-", "-"]


def nginx_ts(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def gen_nginx() -> None:
    """~2000 lines: normal traffic, a 214x401 burst at 03:09:41, then the 200 success at 03:14:47."""
    lines: list[str] = []
    base = datetime(2026, 8, 11, 2, 0, 0, tzinfo=UTC)
    # background traffic 02:00 - 04:00
    for _ in range(1600):
        dt = base + timedelta(seconds=rnd.randint(0, 7200))
        ip = rnd.choice(BENIGN_IPS)
        path = rnd.choice(BENIGN_PATHS)
        method = "GET" if not path.startswith("/api/v2/login") else "POST"
        status = rnd.choice([200, 200, 200, 200, 304, 200, 404, 200])
        user = rnd.choice(BENIGN_USERS)
        size = rnd.randint(120, 5000)
        rt = round(rnd.uniform(0.002, 0.09), 3)
        lines.append((dt, f'{ip} - {user} [{nginx_ts(dt)}] "{method} {path} HTTP/2.0" {status} {size} "-" "{UA_HUMAN}" rt={rt}'))
    # a couple of legit failed logins scattered (baseline ~3/hour)
    for _ in range(6):
        dt = base + timedelta(seconds=rnd.randint(0, 7200))
        ip = rnd.choice(BENIGN_IPS)
        lines.append((dt, f'{ip} - - [{nginx_ts(dt)}] "POST /api/v2/login HTTP/2.0" 401 173 "-" "{UA_HUMAN}" rt=0.03'))
    # the burst: 214 x 401 in 90s from the attacker, starting 03:09:41
    burst_start = datetime(2026, 8, 11, 3, 9, 41, tzinfo=UTC)
    for i in range(214):
        dt = burst_start + timedelta(seconds=(i * 90) // 214, milliseconds=rnd.randint(0, 400))
        rt = round(rnd.uniform(0.008, 0.02), 3)
        lines.append((dt, f'{ATTACKER} - - [{nginx_ts(dt)}] "POST /api/v2/login HTTP/2.0" 401 173 "-" "{UA_BOT}" rt={rt}'))
    # first success at 03:14:47
    succ = datetime(2026, 8, 11, 3, 14, 47, tzinfo=UTC)
    lines.append((succ, f'{ATTACKER} - svc_deploy [{nginx_ts(succ)}] "POST /api/v2/login HTTP/2.0" 200 1284 "-" "{UA_BOT}" rt=0.211'))
    # a few authenticated calls afterwards
    for i in range(4):
        dt = succ + timedelta(seconds=8 + i * 3)
        lines.append((dt, f'{ATTACKER} - svc_deploy [{nginx_ts(dt)}] "GET /api/v2/account HTTP/2.0" 200 {rnd.randint(400, 900)} "-" "{UA_BOT}" rt=0.05'))
    lines.sort(key=lambda x: x[0])
    (OUT / "edge-lb-01_access.log").write_text("\n".join(t for _, t in lines) + "\n", encoding="utf-8")


def gen_cloudtrail() -> None:
    records = []

    def rec(t: str, name: str, extra: dict, ip: str = ATTACKER, user: str = "svc_deploy", err: str | None = None) -> dict:
        r = {"eventVersion": "1.09", "eventTime": t, "eventSource": name.lower() + ".amazonaws.com" if False else "signin.amazonaws.com",
             "eventName": name, "awsRegion": "us-east-1", "sourceIPAddress": ip,
             "userIdentity": {"type": "IAMUser", "userName": user, "accountId": "447119089082",
                              "arn": f"arn:aws:iam::447119089082:user/{user}"},
             "recipientAccountId": "447119089082", "requestParameters": {}, "responseElements": {}}
        r.update(extra)
        if err:
            r["errorCode"] = err
        return r
    # baseline benign events across the window
    base = datetime(2026, 8, 11, 0, 0, 0, tzinfo=UTC)
    for _ in range(60):
        dt = base + timedelta(seconds=rnd.randint(0, 4 * 3600))
        records.append(rec(dt.strftime("%Y-%m-%dT%H:%M:%SZ"), rnd.choice(["DescribeInstances", "ListBuckets", "GetCallerIdentity", "AssumeRole"]),
                           {"eventSource": "ec2.amazonaws.com"}, ip="10.0.3.44", user="ci-runner"))
    records.append(rec("2026-08-11T03:15:10Z", "ConsoleLogin",
                       {"eventSource": "signin.amazonaws.com", "additionalEventData": {"MFAUsed": "No"},
                        "responseElements": {"ConsoleLogin": "Success"}}))
    records.append(rec("2026-08-11T03:16:02Z", "CreateAccessKey",
                       {"eventSource": "iam.amazonaws.com",
                        "responseElements": {"accessKey": {"accessKeyId": "AKIA4YV2XN31LR8Q7QMX", "status": "Active", "userName": "svc_deploy"}},
                        "requestParameters": {"userName": "svc_deploy"}}))
    records.append(rec("2026-08-11T03:35:22Z", "DeleteTrail",
                       {"eventSource": "cloudtrail.amazonaws.com", "requestParameters": {"name": "org-audit-trail"}}, err="AccessDenied"))
    records.sort(key=lambda r: r["eventTime"])
    (OUT / "cloudtrail_20260811.json").write_text(json.dumps({"Records": records}, indent=1), encoding="utf-8")


def gen_k8s() -> None:
    lines = []

    def ev(t: str, verb: str, resource: str, name: str, ns: str, user: str, sub: str = "", code: int = 200,
           uri: str = "", req_obj: dict | None = None) -> str:
        o = {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "RequestResponse", "stage": "ResponseComplete",
             "requestReceivedTimestamp": t, "stageTimestamp": t, "verb": verb,
             "user": {"username": user, "groups": ["system:authenticated"]},
             "objectRef": {"resource": resource, "namespace": ns, "name": name},
             "sourceIPs": [PIVOT if user == "svc_deploy" else "10.0.3.44"],
             "responseStatus": {"metadata": {}, "code": code},
             "requestURI": uri or f"/api/v1/namespaces/{ns}/{resource}/{name}"}
        if sub:
            o["objectRef"]["subresource"] = sub
        if req_obj:
            o["requestObject"] = req_obj
        return json.dumps(o)
    base = datetime(2026, 8, 11, 0, 0, 0, tzinfo=UTC)
    for _ in range(120):
        dt = base + timedelta(seconds=rnd.randint(0, 4 * 3600))
        lines.append((dt, ev(dt.strftime("%Y-%m-%dT%H:%M:%SZ"), rnd.choice(["get", "list", "watch"]),
                             rnd.choice(["pods", "configmaps", "services", "endpoints"]), "svc-x", "default", "system:serviceaccount:kube-system:controller")))
    t13 = datetime(2026, 8, 11, 2, 41, 12, tzinfo=UTC)
    lines.append((t13, ev("2026-08-11T02:41:12Z", "patch", "deployments", "payments-api", "payments", "ci-runner",
                          req_obj={"spec": {"replicas": 6}})))
    t09 = datetime(2026, 8, 11, 3, 24, 0, tzinfo=UTC)
    lines.append((t09, ev("2026-08-11T03:24:00Z", "create", "pods", "payments-api-7c9d", "payments", "svc_deploy", sub="exec", code=101,
                          uri="/api/v1/namespaces/payments/pods/payments-api-7c9d/exec?command=/bin/sh&stdin=true&tty=true")))
    lines.sort(key=lambda x: x[0])
    (OUT / "k8s_audit_20260811.jsonl").write_text("\n".join(t for _, t in lines) + "\n", encoding="utf-8")


def gen_syslog() -> None:
    lines = []

    def sl(dt: datetime, host: str, prog: str, pid: int | None, msg: str) -> tuple:
        stamp = dt.strftime("%b %e %H:%M:%S").replace("  ", " ")
        p = f"[{pid}]" if pid else ""
        return (dt, f"{stamp} {host} {prog}{p}: {msg}")
    base = datetime(2026, 8, 11, 0, 0, 0, tzinfo=UTC)
    for _ in range(120):
        dt = base + timedelta(seconds=rnd.randint(0, 4 * 3600))
        lines.append(sl(dt, "bastion-1", "systemd", None, rnd.choice(
            ["Started Session c%d of user backup." % rnd.randint(1, 99), "Reached target Timers.", "Starting Daily apt upgrade..."])))
    lines.append(sl(datetime(2026, 8, 11, 3, 2, 55, tzinfo=UTC), "bastion-1", "CRON", 19882,
                    "pam_unix(cron:session): session opened for user backup by (uid=0)"))
    lines.append(sl(datetime(2026, 8, 11, 3, 22, 41, tzinfo=UTC), "bastion-1", "sshd", 20418,
                    f"Accepted publickey for root from {PIVOT} port 44120 ssh2: RSA SHA256:8mQ2kLxV0pWq3nZ7bYcRtA1sD9fG4hJ6kL1p"))
    lines.append(sl(datetime(2026, 8, 11, 3, 31, 8, tzinfo=UTC), "bastion-1", "audit", 0,
                    'PATH name="/root/.bash_history" inode=2621451 mode=0600 op=truncate'))
    lines.sort(key=lambda x: x[0])
    (OUT / "bastion-1_syslog").write_text("\n".join(t for _, t in lines) + "\n", encoding="utf-8")


def gen_app_jsonl() -> None:
    lines = []
    base = datetime(2026, 8, 11, 2, 30, 0, tzinfo=UTC)
    for _ in range(150):
        dt = base + timedelta(seconds=rnd.randint(0, 90 * 60))
        o = {"ts": dt.strftime("%Y-%m-%dT%H:%M:%SZ"), "level": rnd.choice(["info", "info", "info", "warn", "debug"]),
             "svc": "payments-api", "event": rnd.choice(["request.complete", "cache.hit", "db.query", "export.complete"]),
             "actor": rnd.choice(["ci-runner", "svc_deploy", "system"]), "duration_ms": rnd.randint(2, 400)}
        if o["event"] == "export.complete":
            o["rows"] = rnd.randint(20, 1140)
            o["dest"] = "/exports/report-%d.csv" % rnd.randint(1, 999)
        lines.append((dt, json.dumps(o)))
    big = datetime(2026, 8, 11, 3, 27, 15, tzinfo=UTC)
    lines.append((big, json.dumps({"ts": "2026-08-11T03:27:15Z", "level": "info", "svc": "payments-api",
                                   "event": "export.complete", "rows": 41208, "dest": "/tmp/x.tar.gz",
                                   "actor": "svc_deploy", "duration_ms": 48210, "pii": "yes"})))
    lines.sort(key=lambda x: x[0])
    (OUT / "payments-api_app.jsonl").write_text("\n".join(t for _, t in lines) + "\n", encoding="utf-8")


def gen_firewall() -> None:
    """Pipe-delimited unknown format: ts|host|action|src:port|dst:port|proto|len=bytes."""
    lines = []
    base = datetime(2026, 8, 11, 0, 0, 0, tzinfo=UTC)
    internal = ["10.22.4.%d" % i for i in range(2, 60)]
    for _ in range(200):
        dt = base + timedelta(seconds=rnd.randint(0, 4 * 3600))
        src = rnd.choice(internal)
        dst = rnd.choice(["93.184.216.34", "140.82.112.3", "151.101.1.69", "10.22.5.10"])
        action = rnd.choice(["ALLOW", "ALLOW", "ALLOW", "DENY"])
        sp, dp = rnd.randint(1024, 65535), rnd.choice([443, 80, 53, 22])
        blen = rnd.randint(200, 80000)
        lines.append((dt, f"{dt.strftime('%Y-%m-%dT%H:%M:%SZ')}|fw-edge-2|{action}|{src}:{sp}|{dst}:{dp}|tcp|len={blen}"))
    lines.append((datetime(2026, 8, 11, 3, 18, 33, tzinfo=UTC),
                  f"2026-08-11T03:18:33Z|fw-edge-2|ALLOW|{PIVOT}:51882|{ATTACKER}:8443|tcp|len=1420"))
    lines.append((datetime(2026, 8, 11, 3, 29, 50, tzinfo=UTC),
                  f"2026-08-11T03:29:50Z|fw-edge-2|ALLOW|{PIVOT}:51993|{ATTACKER}:8443|tcp|len=2297851904"))
    lines.sort(key=lambda x: x[0])
    (OUT / "fw-edge-2.pipe.log").write_text("\n".join(t for _, t in lines) + "\n", encoding="utf-8")


def gen_evtx_xml() -> None:
    """Exported EVTX XML (the evtx parser also accepts .xml exports)."""
    ns = "http://schemas.microsoft.com/win/2004/08/events/event"

    def event(eid: int, ts: str, data: dict) -> str:
        d = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
        return (f'<Event xmlns="{ns}"><System>'
                f'<Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>{eid}</EventID>'
                f'<Level>0</Level><Channel>Security</Channel><Computer>WIN-FS01</Computer>'
                f'<TimeCreated SystemTime="{ts}"/></System><EventData>{d}</EventData></Event>')
    events = []
    base = datetime(2026, 8, 11, 0, 0, 0, tzinfo=UTC)
    for _ in range(60):
        dt = base + timedelta(seconds=rnd.randint(0, 4 * 3600))
        events.append((dt, event(4624, dt.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                                 {"TargetUserName": rnd.choice(["alice", "SYSTEM", "backup-svc"]), "LogonType": "5",
                                  "IpAddress": "-", "AuthenticationPackageName": "Kerberos"})))
    events.append((datetime(2026, 8, 11, 3, 21, 4, tzinfo=UTC),
                   event(4624, "2026-08-11T03:21:04.117Z",
                         {"SubjectUserName": "-", "TargetUserName": "svc_deploy", "LogonType": "3", "IpAddress": PIVOT,
                          "AuthenticationPackageName": "NTLM", "LmPackageName": "NTLM V2", "LogonProcessName": "NtLmSsp"})))
    events.append((datetime(2026, 8, 11, 3, 21, 9, tzinfo=UTC),
                   event(4672, "2026-08-11T03:21:09.201Z",
                         {"SubjectUserName": "svc_deploy", "SubjectLogonId": "0x4f2a91",
                          "PrivilegeList": "SeDebugPrivilege SeBackupPrivilege SeTakeOwnershipPrivilege"})))
    events.sort(key=lambda x: x[0])
    body = "".join(e for _, e in events)
    xml = '<?xml version="1.0" encoding="utf-8"?>\n<Events>' + body + "</Events>\n"
    (OUT / "WIN-FS01_Security.evtx.xml").write_text(xml, encoding="utf-8")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    gen_nginx()
    gen_cloudtrail()
    gen_k8s()
    gen_syslog()
    gen_app_jsonl()
    gen_firewall()
    gen_evtx_xml()
    total = sum(f.stat().st_size for f in OUT.glob("*") if f.is_file() and f.suffix != ".py")
    print(f"demo files written to {OUT} ({total / 1024:.0f} KB total)")


if __name__ == "__main__":
    main()
