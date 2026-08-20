"""7-Zip and Outlook .msg support, exercised against the REAL libraries.

Both py7zr and extract-msg are shipped in requirements.txt, but every import of them in the app is guarded,
so these tests importorskip: a stripped-down install must still be able to run the suite (and gets the
"unsupported format" message path, which test_archives.py / test_email_parser.py already cover).
"""
from __future__ import annotations

import io
import zipfile

import pytest

from app.parsers import archives
from app.parsers.eml import EmailParser, _merge_urls, _msg_extras

AUTH = (b"Jan  1 00:00:01 host sshd[1]: Failed password for root from 10.0.0.9 port 22 ssh2\n"
        b"Jan  1 00:00:05 host sshd[1]: Accepted password for root from 10.0.0.9 port 22 ssh2\n")


# --------------------------------------------------------------------------- 7-Zip
def _sevenz(password: str = "", header_encryption: bool = False, members=(("var/log/auth.log", AUTH),)) -> bytes:
    py7zr = pytest.importorskip("py7zr")
    buf = io.BytesIO()
    kwargs = {"password": password} if password else {}
    with py7zr.SevenZipFile(buf, "w", header_encryption=header_encryption, **kwargs) as z:
        for name, blob in members:
            z.writef(io.BytesIO(blob), name)
    return buf.getvalue()


def test_real_7z_archive_expands_to_its_members():
    pytest.importorskip("py7zr")
    result = archives.expand("evidence.7z", _sevenz())
    assert result.errors == []
    assert ("evidence.7z!var/log/auth.log", AUTH) in result.members


def test_real_7z_with_several_members_keeps_provenance():
    pytest.importorskip("py7zr")
    data = _sevenz(members=(("a/auth.log", AUTH), ("b/web.log", b"127.0.0.1 - - GET / 200\n")))
    result = archives.expand("case.7z", data)
    assert result.errors == []
    assert sorted(n for n, _ in result.members) == ["case.7z!a/auth.log", "case.7z!b/web.log"]


def test_real_7z_nested_inside_a_zip_is_expanded():
    pytest.importorskip("py7zr")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("inner.7z", _sevenz())
    result = archives.expand("outer.zip", buf.getvalue())
    assert ("outer.zip!inner.7z!var/log/auth.log", AUTH) in result.members


@pytest.mark.parametrize("header_encryption", [False, True])
def test_password_protected_7z_is_reported_and_never_ingested(header_encryption):
    pytest.importorskip("py7zr")
    data = _sevenz(password="s3cret", header_encryption=header_encryption)
    result = archives.expand("secret.7z", data)
    assert result.errors, "an encrypted archive must never fail silently"
    joined = " ".join(result.errors)
    assert "password protected" in joined and "NOT" in joined
    assert all(blob != AUTH for _, blob in result.members)


def test_corrupt_7z_is_reported_and_bytes_kept():
    pytest.importorskip("py7zr")
    result = archives.expand("broken.7z", archives.SEVENZ_MAGIC + b"\x00" * 64)
    assert any("7-Zip" in e for e in result.errors)
    assert any(name == "broken.7z" for name, _ in result.members)


def test_rar_message_names_the_licence_limitation():
    """rarfile is deliberately not shipped; the message has to say why, not just 'pip install'."""
    result = archives.expand("evidence.rar", archives.RAR_MAGIC + b"\x00" * 64)
    joined = " ".join(result.errors)
    try:
        import rarfile  # noqa: F401
    except Exception:
        assert "rarfile" in joined and "unrar" in joined
        assert "non-free" in joined, "the analyst must be told WHY .rar is not supported out of the box"
        assert ".zip" in joined  # and what to do instead


# --------------------------------------------------------------------------- Outlook .msg
class _FakeAttachment:
    def __init__(self, name: str, data):
        self.longFilename = name
        self.shortFilename = name[:8]
        self.data = data


class _FakeMsg:
    """The shape extract_msg hands back: body + attachments live outside the transport headers."""

    def __init__(self, header=None, body="", attachments=(), subject="", sender="", to=""):
        self.header = header
        self.body = body
        self.attachments = list(attachments)
        self.subject = subject
        self.sender = sender
        self.to = to
        self.date = None
        self.closed = False

    def close(self):
        self.closed = True


HEADERS = ("Date: Mon, 18 Nov 2013 10:26:24 +0200\r\n"
           "From: Attacker <bad@evil.example>\r\n"
           "To: victim@corp.example\r\n"
           "Subject: Invoice overdue\r\n"
           "Received: from mail.evil.example (mail.evil.example [45.66.77.88]) by mx.corp.example\r\n"
           "Authentication-Results: mx.corp.example; spf=fail; dkim=fail\r\n"
           "Message-ID: <abc@evil.example>\r\n\r\n")


def _parse_fake(monkeypatch, fake) -> list:
    """Run EmailParser._parse_msg against a stand-in for extract_msg, exercising OUR merge logic."""
    import sys
    import types

    module = types.ModuleType("extract_msg")
    module.openMsg = lambda _stream: fake
    monkeypatch.setitem(sys.modules, "extract_msg", module)
    from app.parsers.eml import OLE2_MAGIC
    return list(EmailParser().parse_bytes(OLE2_MAGIC + b"\x00" * 32))


def test_msg_body_and_attachments_are_merged_into_the_header_event(monkeypatch):
    import email
    import email.policy

    header = email.message_from_string(HEADERS, policy=email.policy.compat32)
    fake = _FakeMsg(header=header, body="Please open http://evil.example/pay now",
                    attachments=[_FakeAttachment("invoice.exe", b"MZ payload"),
                                 _FakeAttachment("notes.txt", b"hello")])
    events = _parse_fake(monkeypatch, fake)
    assert len(events) == 1
    ev = events[0]
    # the RFC 822 side still works...
    assert ev.fields["from"] == "bad@evil.example"
    assert ev.fields["src_ip"] == "45.66.77.88"
    assert ev.fields["spf"] == "fail"
    # ...and the parts that only exist in the .msg streams came along
    assert ev.fields["body"].startswith("Please open")
    assert "invoice.exe" in ev.fields["attachment_names"]
    assert "sha256:" in ev.fields["attachment_hashes"]
    assert ev.fields["attachment_count"] == "2"
    assert ev.fields["risky_attachment"] == "invoice.exe"
    assert ev.sev == "high", "an .exe attachment must not lose its severity on the .msg path"
    assert "http://evil.example/pay" in ev.fields["url"]
    assert fake.closed, "the .msg must be closed even on the happy path"


def test_msg_without_transport_headers_still_yields_the_facts(monkeypatch):
    fake = _FakeMsg(header=None, subject="Payroll update", sender="hr@evil.example",
                    to="victim@corp.example", body="see attached",
                    attachments=[_FakeAttachment("payroll.scr", b"MZ")])
    events = _parse_fake(monkeypatch, fake)
    assert len(events) == 1
    ev = events[0]
    assert ev.msg == "Payroll update"
    assert ev.fields["from"] == "hr@evil.example"
    assert ev.fields["risky_attachment"] == "payroll.scr"
    assert ev.sev == "high"


def test_msg_extras_survives_an_unreadable_attachment_stream():
    class Broken:
        longFilename = "embedded.msg"

        @property
        def data(self):
            raise RuntimeError("embedded message, not bytes")

    fields = _msg_extras(_FakeMsg(body="hi", attachments=[Broken()]))
    assert fields["attachment_names"] == "embedded.msg"
    assert "attachment_hashes" not in fields  # no bytes, no hash - but the name is still evidence


def test_merge_urls_unions_both_sides():
    fields = {"url": "http://a.example"}
    _merge_urls(fields, {"url": "http://b.example, http://a.example"})
    assert fields["url"] == "http://a.example, http://b.example"
    assert fields["url_count"] == "2"


def test_real_extract_msg_rejects_a_file_that_is_not_a_msg():
    """Exercises the real library: OLE2 magic routes to the .msg branch, which must fail cleanly."""
    pytest.importorskip("extract_msg")
    from app.parsers.eml import OLE2_MAGIC

    with pytest.raises(RuntimeError) as exc:
        list(EmailParser().parse_bytes(OLE2_MAGIC + b"\x00" * 512))
    assert "could not be read" in str(exc.value)
