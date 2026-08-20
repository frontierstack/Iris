"""E-mail parsing: .eml, multi-message .mbox, MIME/quoted-printable/base64, and the security fields."""
from __future__ import annotations

import base64
import quopri

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.parsers.eml import EmailParser
from app.parsers.registry import fingerprint

EML = b"""Return-Path: <payroll@evil-corp.example>
Received: from mx1.corp.example (mx1.corp.example [10.0.0.9])
\tby mail.corp.example with ESMTP id ABC123; Tue, 11 Aug 2026 03:15:00 +0000
Received: from unknown (relay.evil-corp.example [45.83.140.22])
\tby mx1.corp.example with ESMTP id XYZ789; Tue, 11 Aug 2026 03:14:47 +0000
Authentication-Results: mx1.corp.example; spf=fail smtp.mailfrom=evil-corp.example;
\tdkim=fail header.d=evil-corp.example; dmarc=fail
From: "Payroll Team" <payroll@evil-corp.example>
To: alice@corp.example, bob@corp.example
Cc: security@corp.example
Reply-To: collect@other-domain.example
Subject: Urgent: update your bank details
Message-ID: <9f2c@evil-corp.example>
Date: Tue, 11 Aug 2026 03:14:47 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUND"

--BOUND
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: quoted-printable

Please confirm at http://payroll.evil-corp.example/login before 5pm.=0A=
Regards,=20Payroll
--BOUND
Content-Type: application/octet-stream; name="invoice.exe"
Content-Disposition: attachment; filename="invoice.exe"
Content-Transfer-Encoding: base64

QUJDREVG

--BOUND--
"""


def _mbox(n: int = 3) -> bytes:
    out = []
    for i in range(n):
        out.append(
            f"From sender{i}@example.com Tue Aug 11 03:14:4{i} 2026\r\n"
            f"From: sender{i}@example.com\r\n"
            f"To: alice@corp.example\r\n"
            f"Subject: message number {i}\r\n"
            f"Message-ID: <m{i}@example.com>\r\n"
            f"Date: Tue, 11 Aug 2026 03:14:4{i} +0000\r\n"
            f"\r\n"
            f"Body of message {i}.\r\n"
            f">From a quoted line\r\n"
        )
    return "".join(out).encode()


@pytest.fixture()
def c():
    with TestClient(app) as client:
        yield client


def test_eml_is_selected_by_extension_and_by_content():
    fp = fingerprint("phish.eml", EML)
    assert isinstance(fp.parser, EmailParser)
    assert fp.state == "READY"
    # no extension at all: the header block still identifies it
    fp2 = fingerprint("message", EML)
    assert isinstance(fp2.parser, EmailParser), fp2.scores


def test_eml_headers_become_an_event():
    ev = list(EmailParser().parse_bytes(EML))[0]
    assert ev.msg == "Urgent: update your bank details"
    assert ev.user == "payroll@evil-corp.example"
    assert ev.ts is not None and ev.ts.strftime("%Y-%m-%dT%H:%M:%S") == "2026-08-11T03:14:47"
    assert ev.fields["to"] == "alice@corp.example, bob@corp.example"
    assert ev.fields["cc"] == "security@corp.example"
    assert ev.fields["message_id"] == "<9f2c@evil-corp.example>"
    assert ev.fields["from_domain"] == "evil-corp.example"
    assert ev.fields["reply_to_mismatch"] == "yes"


def test_security_extraction():
    ev = list(EmailParser().parse_bytes(EML))[0]
    # originating IP = the FIRST hop, i.e. the last Received header
    assert ev.fields["src_ip"] == "45.83.140.22"
    assert "45.83.140.22" in ev.fields["received_ips"]
    assert "10.0.0.9" not in ev.fields["received_ips"]  # private hop is not an indicator
    assert ev.fields["spf"] == "fail" and ev.fields["dkim"] == "fail" and ev.fields["dmarc"] == "fail"
    assert "http://payroll.evil-corp.example/login" in ev.fields["url"]
    assert "invoice.exe" in ev.fields["attachment_names"]
    assert "risky_attachment" in ev.fields
    # base64 attachment "QUJDREVG" -> b"ABCDEF"; hash proves it was decoded, not hashed as text
    import hashlib
    assert hashlib.sha256(b"ABCDEF").hexdigest() in ev.fields["attachment_hashes"]
    assert ev.sev == "high"  # executable attachment


def test_quoted_printable_body_is_decoded():
    ev = list(EmailParser().parse_bytes(EML))[0]
    assert "Please confirm at http://payroll.evil-corp.example/login" in ev.fields["body"]
    assert "=0A" not in ev.fields["body"] and "=20" not in ev.fields["body"]


def test_auth_failure_alone_is_medium():
    body = EML.replace(b'filename="invoice.exe"', b'filename="invoice.pdf"').replace(
        b'name="invoice.exe"', b'name="invoice.pdf"')
    ev = list(EmailParser().parse_bytes(body))[0]
    assert ev.sev == "medium"
    assert ev.fields["auth_failed"] == "spf, dkim, dmarc"


def test_mbox_yields_one_event_per_message():
    evs = list(EmailParser().parse_bytes(_mbox(3)))
    assert len(evs) == 3
    assert [e.msg for e in evs] == ["message number 0", "message number 1", "message number 2"]
    assert evs[0].user == "sender0@example.com"
    assert evs[2].fields["mbox_index"] == "3"
    assert all(e.ts is not None for e in evs)
    assert "From a quoted line" in evs[0].fields["body"]  # >From unescaped


def test_body_line_starting_with_from_does_not_split_an_eml():
    single = (b"From: a@example.com\r\nTo: b@example.com\r\nSubject: hi\r\n"
              b"Date: Tue, 11 Aug 2026 03:14:47 +0000\r\n\r\n"
              b"From here on the story continues\r\n")
    evs = list(EmailParser().parse_bytes(single))
    assert len(evs) == 1 and evs[0].msg == "hi"


def test_malformed_headers_do_not_crash():
    broken = (b"Subject: =?utf-8?B?bm90LXZhbGlkLWJhc2U2NA??=\r\n"
              b"From: <<<not-an-address>>>\r\n"
              b"Date: not a date at all\r\n"
              b"Content-Type: multipart/mixed; boundary=\r\n\r\n"
              b"body\r\n")
    evs = list(EmailParser().parse_bytes(broken))
    assert len(evs) == 1
    assert evs[0].ts is None  # unparseable Date is simply absent, not fatal


def test_base64_body_is_decoded():
    payload = base64.b64encode(b"clicked http://drop.example/x.bin from 45.83.140.22")
    msg = (b"From: a@example.com\r\nTo: b@example.com\r\nSubject: b64\r\n"
           b"Date: Tue, 11 Aug 2026 03:14:47 +0000\r\n"
           b"Content-Type: text/plain; charset=utf-8\r\n"
           b"Content-Transfer-Encoding: base64\r\n\r\n" + payload + b"\r\n")
    ev = list(EmailParser().parse_bytes(msg))[0]
    assert "http://drop.example/x.bin" in ev.fields["url"]


def test_msg_without_the_optional_package():
    from app.parsers import eml as eml_mod

    ole2 = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64
    if eml_mod.msg_available():
        pytest.skip("extract_msg installed; the unsupported-format path is not exercised")
    with pytest.raises(RuntimeError) as exc:
        list(EmailParser().parse_bytes(ole2))
    assert "extract_msg" in str(exc.value)


def test_eml_ingested_end_to_end(c):
    r = c.post("/api/sources", files=[("files", ("phish.eml", EML, "message/rfc822"))])
    assert r.status_code == 200, r.text
    src = r.json()[0]
    assert src["parser"] == "E-mail message" and src["events"] == 1
    rows = c.get("/api/events", params={"q": "Urgent", "sources": src["id"], "limit": 50}).json()["rows"]
    assert len(rows) == 1 and rows[0]["sev"] == "high"
    assert "45.83.140.22" in rows[0]["entities"]
    assert "payroll@evil-corp.example" in rows[0]["entities"]


def test_mbox_ingested_end_to_end(c):
    r = c.post("/api/sources", files=[("files", ("inbox.mbox", _mbox(4), "application/mbox"))])
    assert r.status_code == 200, r.text
    assert r.json()[0]["events"] == 4


def test_quopri_roundtrip_helper_sanity():
    """Guards the fixture itself: the QP body really is encoded."""
    assert quopri.decodestring(b"a=0Ab") == b"a\nb"
