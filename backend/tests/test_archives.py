"""Archive ingestion: many container formats, provenance in the member name, and the refusals
(password protected, zip-slip, zip bomb, unsupported format) reaching the API as an ERROR source."""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.parsers import archives
from app.store import STORE

AUTH = (b"Jan 01 00:00:01 web-1 sshd[1]: Accepted password for alice from 10.0.0.5 port 22 ssh2\n"
        b"Jan 01 00:00:02 web-1 sshd[2]: Failed password for bob from 45.83.140.22 port 22 ssh2\n")
NGINX = b'45.83.140.22 - - [11/Aug/2026:03:14:47 +0000] "GET /admin HTTP/1.1" 401 12 "-" "curl/8.0"\n'


@pytest.fixture()
def c():
    with TestClient(app) as client:
        yield client


def _zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, blob in entries.items():
            zf.writestr(name, blob)
    return buf.getvalue()


def _tar(entries: dict[str, bytes], mode: str = "w") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for name, blob in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(blob)
            tf.addfile(info, io.BytesIO(blob))
    return buf.getvalue()


# --------------------------------------------------------------------------- formats
def test_zip_members_keep_provenance():
    data = _zip({"var/log/auth.log": AUTH, "nginx/access.log": NGINX})
    result = archives.expand("incident.zip", data)
    assert result.errors == []
    names = sorted(n for n, _ in result.members)
    assert names == ["incident.zip!nginx/access.log", "incident.zip!var/log/auth.log"]
    assert dict(result.members)["incident.zip!var/log/auth.log"] == AUTH


@pytest.mark.parametrize("suffix,mode", [(".tar", "w"), (".tar.gz", "w:gz"), (".tgz", "w:gz"),
                                         (".tar.bz2", "w:bz2"), (".tar.xz", "w:xz")])
def test_tar_flavours(suffix, mode):
    data = _tar({"logs/auth.log": AUTH}, mode)
    result = archives.expand(f"evidence{suffix}", data)
    assert result.errors == []
    assert result.members == [(f"evidence{suffix}!logs/auth.log", AUTH)]


@pytest.mark.parametrize("suffix,compress", [(".gz", gzip.compress), (".bz2", bz2.compress),
                                             (".xz", lzma.compress)])
def test_single_file_compressors(suffix, compress):
    result = archives.expand(f"auth.log{suffix}", compress(AUTH))
    assert result.errors == []
    assert result.members == [("auth.log", AUTH)]


def test_plain_file_passes_through():
    result = archives.expand("auth.log", AUTH)
    assert result.members == [("auth.log", AUTH)] and result.errors == []


def test_office_documents_are_not_treated_as_archives():
    openpyxl = pytest.importorskip("openpyxl")
    wb = openpyxl.Workbook()
    wb.active.append(["timestamp", "host"])
    buf = io.BytesIO()
    wb.save(buf)
    data = buf.getvalue()
    assert archives.expand("audit.xlsx", data).members == [("audit.xlsx", data)]
    assert STORE.expand_upload("audit.xlsx", data) == [("audit.xlsx", data)]  # back-compat helper


def test_nested_archives_to_bounded_depth():
    inner = _tar({"logs/auth.log": AUTH}, "w:gz")
    outer = _zip({"day1/inner.tar.gz": inner})
    result = archives.expand("case.zip", outer)
    assert result.errors == []
    assert result.members == [("case.zip!day1/inner.tar.gz!logs/auth.log", AUTH)]


def test_nesting_within_the_limit(monkeypatch):
    monkeypatch.setattr(archives, "MAX_DEPTH", 1)
    outer = _zip({"inner.zip": _zip({"auth.log": AUTH})})
    result = archives.expand("case.zip", outer)
    assert result.errors == []
    assert result.members == [("case.zip!inner.zip!auth.log", AUTH)]


def test_nesting_deeper_than_the_limit_is_reported(monkeypatch):
    monkeypatch.setattr(archives, "MAX_DEPTH", 0)  # no nesting allowed at all
    inner = _zip({"auth.log": AUTH})
    outer = _zip({"inner.zip": inner})
    result = archives.expand("case.zip", outer)
    assert any("nested archives deeper than" in e for e in result.errors)
    assert result.members == [("case.zip!inner.zip", inner)]  # container kept, not expanded


# --------------------------------------------------------------------------- refusals
def test_zip_slip_is_refused():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../../../etc/passwd", b"root:x:0:0\n")
        zf.writestr("ok/auth.log", AUTH)
    result = archives.expand("evil.zip", buf.getvalue())
    assert result.members == [("evil.zip!ok/auth.log", AUTH)]
    assert any("zip-slip" in e and "escapes the archive root" in e for e in result.errors)


def test_absolute_and_drive_paths_are_refused():
    assert archives.safe_member_name("/etc/shadow") is None
    assert archives.safe_member_name("C:\\Windows\\System32\\x.dll") is None
    assert archives.safe_member_name("a/../../b") is None
    assert archives.safe_member_name("logs/./auth.log") == "logs/auth.log"
    assert archives.safe_member_name("dir\\sub\\auth.log") == "dir/sub/auth.log"


def test_tar_slip_is_refused():
    data = _tar({"../escape.log": AUTH, "in/auth.log": AUTH})
    result = archives.expand("evil.tar", data)
    assert result.members == [("evil.tar!in/auth.log", AUTH)]
    assert any("escapes the archive root" in e for e in result.errors)


def test_entry_count_cap(monkeypatch):
    monkeypatch.setattr(archives, "MAX_ENTRIES", 3)
    data = _zip({f"log{i}.log": AUTH for i in range(10)})
    result = archives.expand("many.zip", data)
    assert len(result.members) == 3
    assert any("possible zip bomb" in e and "more entries" in e for e in result.errors)


def test_total_bytes_cap(monkeypatch):
    monkeypatch.setattr(archives, "MAX_TOTAL_BYTES", 1024)
    big = b"A" * 4096
    data = _zip({"huge.log": big, "small.log": AUTH})
    result = archives.expand("bomb.zip", data)
    assert all(len(b) <= 1024 for _, b in result.members)
    assert any("uncompressed limit" in e for e in result.errors)


def test_member_size_cap(monkeypatch):
    monkeypatch.setattr(archives, "MAX_MEMBER_BYTES", 1024)
    data = _zip({"huge.log": b"A" * 4096, "small.log": AUTH})
    result = archives.expand("bomb.zip", data)
    assert result.members == [("bomb.zip!small.log", AUTH)]
    assert any("per-file limit" in e for e in result.errors)


def _encrypted_zip(tmp_path: Path) -> bytes:
    """A real AES/ZipCrypto archive. Built with the `zip` CLI when present, else hand-assembled by
    setting the encryption flag bit — which is exactly what the reader checks."""
    exe = tmp_path / "secret.zip"
    inner = tmp_path / "auth.log"
    inner.write_bytes(AUTH)
    try:
        subprocess.run(["zip", "-j", "-P", "hunter2", str(exe), str(inner)],
                       check=True, capture_output=True, timeout=30)
        return exe.read_bytes()
    except (OSError, subprocess.SubprocessError):
        pass
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("auth.log", AUTH)
    raw = bytearray(buf.getvalue())
    for i in range(len(raw) - 4):
        if raw[i:i + 4] in (b"PK\x03\x04", b"PK\x01\x02"):
            flag = 6 if raw[i:i + 4] == b"PK\x03\x04" else 8
            raw[i + flag] |= 0x01  # general purpose bit 0 = encrypted
    return bytes(raw)


def test_password_protected_zip_is_reported(tmp_path):
    result = archives.expand("secret.zip", _encrypted_zip(tmp_path))
    assert result.members == [] or all(b != AUTH for _, b in result.members)
    assert result.errors, "an encrypted archive must never fail silently"
    joined = " ".join(result.errors)
    assert "password protected" in joined and "NOT ingested" in joined


def test_unsupported_7z_and_rar_report_clearly():
    sevenz = archives.expand("evidence.7z", archives.SEVENZ_MAGIC + b"\x00" * 64)
    rar = archives.expand("evidence.rar", archives.RAR_MAGIC + b"\x00" * 64)
    try:
        import py7zr  # noqa: F401
    except Exception:
        assert any("py7zr" in e for e in sevenz.errors)
    try:
        import rarfile  # noqa: F401
    except Exception:
        assert any("rarfile" in e for e in rar.errors)


def test_corrupt_zip_is_reported_and_bytes_kept():
    result = archives.expand("broken.zip", b"PK\x03\x04" + b"\x00" * 50)
    assert any("not a readable zip archive" in e for e in result.errors)


# --------------------------------------------------------------------------- through the API
def test_upload_expands_and_ingests_members(c):
    data = _zip({"var/log/auth.log": AUTH, "nginx/access.log": NGINX})
    r = c.post("/api/sources", files=[("files", ("incident.zip", data, "application/zip"))])
    assert r.status_code == 200, r.text
    sources = r.json()
    files = sorted(s["file"] for s in sources)
    assert files == ["incident.zip!nginx/access.log", "incident.zip!var/log/auth.log"]
    assert all(s["state"] != "ERROR" for s in sources)
    assert sum(s["events"] for s in sources) == 3
    ids = ",".join(s["id"] for s in sources)
    rows = c.get("/api/events", params={"q": "alice", "sources": ids, "limit": 100}).json()["rows"]
    assert rows and any(e["file"] == "incident.zip!var/log/auth.log" for e in rows)


def test_encrypted_upload_surfaces_an_error_source(c, tmp_path):
    data = _encrypted_zip(tmp_path)
    r = c.post("/api/sources", files=[("files", ("secret.zip", data, "application/zip"))])
    assert r.status_code == 200, r.text
    sources = r.json()
    errored = [s for s in sources if s["state"] == "ERROR"]
    assert errored, f"expected an ERROR source, got {sources}"
    assert "password protected" in errored[0]["error"]
    assert errored[0]["file"] == "secret.zip"
    # and it is visible on the case, not just in the upload response
    case = c.get("/api/case").json()
    assert any(s["state"] == "ERROR" and "password protected" in (s["error"] or "")
               for s in case["sources"])


def test_zip_slip_upload_reports_and_still_ingests_the_good_member(c):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../evil.log", b"nope\n")
        zf.writestr("good/auth.log", AUTH)
    r = c.post("/api/sources", files=[("files", ("evil.zip", buf.getvalue(), "application/zip"))])
    assert r.status_code == 200, r.text
    sources = r.json()
    assert any(s["file"] == "evil.zip!good/auth.log" and s["state"] != "ERROR" for s in sources)
    errored = [s for s in sources if s["state"] == "ERROR"]
    assert errored and "escapes the archive root" in errored[0]["error"]
    # nothing was ever written outside the case's upload directory
    upload_dir = STORE.upload_dir.resolve()
    for path in STORE.source_paths.values():
        assert path.resolve().parent == upload_dir


def test_tar_gz_upload(c):
    data = _tar({"logs/auth.log": AUTH}, "w:gz")
    r = c.post("/api/sources", files=[("files", ("evidence.tar.gz", data, "application/gzip"))])
    assert r.status_code == 200, r.text
    assert [s["file"] for s in r.json()] == ["evidence.tar.gz!logs/auth.log"]


def test_expansion_is_uncapped_by_default() -> None:
    """No entry count or size limit unless an operator asks for one.

    The caps were a zip-bomb defence, and the trade was wrong for this app: a bomb is hypothetical
    while an archive of evidence Iris refuses to open is the everyday case, and the refusal handed
    the analyst the very chore Iris exists to do. The mechanism still works (the tests above set the
    caps and watch them trip) — it is simply off. DEPTH stays, because with the size caps gone it is
    all that stands between the expander and a self-referential archive, and that is a hang, not a
    trade-off.
    """
    assert archives.MAX_ENTRIES == 0, "an entry cap was reintroduced as the default"
    assert archives.MAX_TOTAL_BYTES == 0, "a total-size cap was reintroduced as the default"
    assert archives.MAX_MEMBER_BYTES == 0, "a per-member cap was reintroduced as the default"
    assert archives.MAX_DEPTH >= 3, "nesting depth is the one guard that must stay"

    # an archive with more members than the old 5,000-entry cap expands in full
    import io as _io
    import zipfile
    buf = _io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i in range(6000):
            z.writestr(f"logs/app-{i}.log", b"2026-05-01T10:00:00Z host app: line\n")
    result = archives.expand("many.zip", buf.getvalue())
    assert len(result.members) == 6000, f"expanded only {len(result.members)} of 6000"
    assert not result.errors, result.errors
