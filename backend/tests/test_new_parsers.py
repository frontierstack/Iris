"""Tests for the document / tabular / binary parsers and the /api/parsers endpoint."""
from __future__ import annotations

import io

import pytest

from app.parsers.csv import CsvParser
from app.parsers.image import ImageParser
from app.parsers.memdump import MemdumpParser, is_binary
from app.parsers.registry import fingerprint
from app.parsers.xlsx import XlsxParser

CSV = "\n".join([
    "timestamp,hostname,username,message",
    '2026-08-11T03:14:47Z,web-1,alice,"login ok, retry"',
    "2026-08-11T03:15:00Z,web-2,bob,failed from 45.83.140.22",
])


def test_csv_header_detection():
    p = CsvParser()
    lines = CSV.splitlines()
    assert p.sniff(lines, "audit.csv") > 0.7
    evs = list(p.parse(lines))
    assert len(evs) == 2
    assert evs[0].host == "web-1" and evs[0].user == "alice"
    assert evs[0].ts is not None
    assert "login ok, retry" in evs[0].msg  # quoted comma preserved
    assert evs[1].fields["hostname"] == "web-2"


def test_csv_fingerprint_name():
    fp = fingerprint("audit.csv", CSV.encode())
    assert fp.parser.name == "CSV (header)"
    assert fp.parser.family == "delimited.csv"


def test_tsv_detected():
    tsv = "time\thost\tmsg\n2026-08-11T03:14:47Z\tweb-1\thello\n2026-08-11T03:15:00Z\tweb-2\tworld"
    p = CsvParser()
    assert p.sniff(tsv.splitlines(), "x.tsv") > 0.5
    evs = list(p.parse(tsv.splitlines()))
    assert evs[0].host == "web-1"


def _make_xlsx() -> bytes:
    openpyxl = pytest.importorskip("openpyxl")
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Events"
    ws.append(["timestamp", "host", "user", "message"])
    ws.append(["2026-08-11T03:14:47Z", "web-1", "alice", "login ok"])
    ws.append(["2026-08-11T03:15:00Z", "web-2", "bob", "failed from 45.83.140.22"])
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def test_xlsx_rows_to_events():
    data = _make_xlsx()
    fp = fingerprint("audit.xlsx", data)
    assert isinstance(fp.parser, XlsxParser)
    assert fp.state == "READY"
    evs = list(fp.parser.parse_bytes(data))
    assert len(evs) == 2
    assert evs[0].host == "web-1" and evs[0].user == "alice"
    assert evs[0].fields["sheet"] == "Events"
    assert evs[0].fields["row"] == "2"
    assert evs[0].ts is not None
    assert "45.83.140.22" in evs[1].raw


def test_xlsx_not_expanded_as_zip():
    from app.store import STORE
    data = _make_xlsx()
    members = STORE.expand_upload("audit.xlsx", data)
    assert members == [("audit.xlsx", data)]  # OOXML zip must stay intact


def _make_dump() -> bytes:
    blob = b"\x00\x01\x02\x03junk\x00"
    blob += b"powershell -enc SQBFAFgA\x00"
    blob += b"connect to http://malware.example.com/payload\x00"
    blob += b"beacon from 45.83.140.22 to 10.0.0.5\x00"
    blob += b"C:\\Windows\\System32\\cmd.exe /c whoami\x00"
    blob += "operator@evil.example".encode("utf-16-le") + b"\x00\x00"
    blob += b"\xff\xee" * 3000  # padding / non-printable tail
    return blob


def test_memdump_strings_and_iocs():
    data = _make_dump()
    assert is_binary(data[:8192])
    fp = fingerprint("crash.dmp", data)
    assert isinstance(fp.parser, MemdumpParser)
    evs = list(fp.parser.parse_bytes(data))
    joined = {e.msg: e for e in evs}
    ps = next(e for e in evs if "powershell" in e.msg)
    assert ps.sev == "medium" and "powershell -enc" in ps.fields["suspicious"]
    url_ev = next(e for e in evs if e.fields.get("url"))
    assert "malware.example.com" in url_ev.fields["url"]
    ip_ev = next(e for e in evs if e.fields.get("ip"))
    assert "45.83.140.22" in ip_ev.fields["ip"]
    assert all("offset" in e.fields and e.fields["offset"].startswith("0x") for e in evs)
    assert any(e.fields.get("encoding") == "utf-16le" for e in evs)


def test_memdump_detects_untyped_binary():
    # a file with no known extension but a non-UTF-8 body still routes to strings extraction
    data = b"\x00\x89\xffhello world this is a readable string\x00" + b"\x00" * 100
    fp = fingerprint("mystery.blob", data)
    assert fp.parser.family == "binary.strings"


def test_pdf_selection_and_parse():
    pytest.importorskip("pypdf")
    data = _minimal_pdf()
    fp = fingerprint("report.pdf", data)
    assert fp.parser.family == "document.pdf"
    # must not raise, whatever text (if any) pypdf recovers
    evs = list(fp.parser.parse_bytes(data))
    assert isinstance(evs, list)


def _minimal_pdf() -> bytes:
    """A hand-built one-page PDF with a text content stream ('Hello 2026-08-11T03:14:47Z')."""
    objs = []
    objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objs.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objs.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
                b"/Resources << /Font << /F1 5 0 R >> >> >>")
    stream = b"BT /F1 12 Tf 72 720 Td (Hello 2026-08-11T03:14:47Z login ok) Tj ET"
    objs.append(b"<< /Length %d >>\nstream\n%s\nendstream" % (len(stream), stream))
    objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref_pos = len(out)
    out += b"xref\n0 %d\n" % (len(objs) + 1)
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF" % (len(objs) + 1, xref_pos)
    return bytes(out)


def test_image_ocr_graceful_when_unavailable():
    p = ImageParser()
    from app.parsers.image import ocr_status
    ok, _ = ocr_status()
    png = bytes.fromhex("89504e470d0a1a0a")  # PNG magic
    assert p.sniff([], "shot.png", png) == 1.0
    if ok:
        pytest.skip("tesseract present; graceful-error path not exercised")
    with pytest.raises(RuntimeError) as exc:
        list(p.parse_bytes(png + b"\x00" * 20))
    assert "OCR unavailable: install tesseract-ocr" in str(exc.value)
