"""GET /api/parsers: the supported input types and whether their optional dependencies are present."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter

from ..parsers import (archives as _archives, docx as _docx, eml as _eml, image as _image, pdf as _pdf,
                       sqlitedb as _sqlite, xlsx as _xlsx)
from ..parsers.memdump import EXTENSIONS as BIN_EXT

router = APIRouter(prefix="/parsers", tags=["parsers"])


def _evtx_available() -> bool:
    try:
        import Evtx  # noqa: F401
        return True
    except Exception:
        return False


def _entry(name: str, family: str, extensions: list[str], description: str, available: bool = True,
           note: Optional[str] = None) -> dict:
    d: dict = {"name": name, "family": family, "extensions": extensions, "description": description, "available": available}
    if note:
        d["note"] = note
    return d


def _importable(module: str) -> bool:
    try:
        __import__(module)
        return True
    except Exception:
        return False


def list_parsers() -> list[dict]:
    ocr_ok, ocr_note = _image.ocr_status()
    _sevenz_ok = _importable("py7zr")
    _rar_ok = _importable("rarfile")
    evtx_ok = _evtx_available()
    xls_ok = True
    try:
        import xlrd  # noqa: F401
    except Exception:
        xls_ok = False
    return [
        _entry("Windows EVTX", "windows.evtx", [".evtx", ".xml"],
               "Windows event logs: binary .evtx (python-evtx) or exported XML; EventID, logon type, accounts and IPs.",
               available=True, note=None if evtx_ok else "binary .evtx needs python-evtx; XML exports still parse"),
        _entry("AWS CloudTrail", "aws.cloudtrail", [".json", ".jsonl", ".gz"],
               "CloudTrail {\"Records\":[...]} documents or JSON lines; IAM identity, region, source IP, error codes."),
        _entry("Kubernetes audit", "k8s.audit", [".jsonl", ".json", ".log"],
               "kube-apiserver audit events (audit.k8s.io/v1): verb, resource, user, response code."),
        _entry("nginx / apache access", "nginx.access", [".log", ".txt"],
               "Combined / common log format access lines: client IP, method, path, status, bytes, UA."),
        _entry("syslog", "syslog", [".log", ".txt"],
               "RFC 3164 and RFC 5424 syslog; sshd/sudo/systemd auth events enriched (result, user, source IP)."),
        _entry("JSON lines (inferred)", "app.jsonl", [".jsonl", ".json", ".ndjson", ".log"],
               "Generic JSON: one object per line, a JSON array, or an object holding a top-level list "
               "(Records/events/items/logs/data); ts/level/message/host/user keys inferred."),
        _entry("CSV (header)", "delimited.csv", [".csv", ".tsv", ".txt"],
               "CSV/TSV with a header row (auto-detected); columns become fields; timestamp/host/user/message columns inferred by name."),
        _entry("delimited (unknown)", "delimited", [".log", ".txt", ".csv", ".psv"],
               "Pipe/comma/tab/semicolon rows without a usable header: roles guessed per column; review or map fields manually."),
        _entry("plain text", "text", ["*"],
               "Fallback for any other text: timestamp regex + level keyword per line."),
        _entry("PDF (text)", "document.pdf", [".pdf"],
               "Text extracted per page (pypdf); each non-empty line is an event with page/line_no.",
               available=_pdf.available(), note=None if _pdf.available() else "install pypdf"),
        _entry("Excel workbook", "document.xlsx", [".xlsx", ".xlsm", ".xls"],
               "Each row of each sheet is an event; first row as header; sheet/row in fields. Legacy .xls via xlrd.",
               available=_xlsx.available(),
               note=None if (_xlsx.available() and xls_ok) else ("install openpyxl" if not _xlsx.available() else "legacy .xls needs xlrd")),
        _entry("Word document (DOCX)", "document.docx", [".docx", ".docm"],
               "Paragraphs and table rows become lines/events (python-docx).",
               available=_docx.available(), note=None if _docx.available() else "install python-docx"),
        _entry("Image (OCR)", "document.image", list(_image.EXTENSIONS),
               "OCR via tesseract (grayscale + 2x upscale for small images); each recognised line is an event with confidence.",
               available=ocr_ok, note=None if ocr_ok else ocr_note),
        _entry("Binary strings", "binary.strings", list(BIN_EXT),
               "Memory dumps, disk images and any non-UTF-8 file: printable ASCII + UTF-16LE strings (min 6 chars) like "
               "`strings -a -el`; timestamps, IPs, URLs, e-mails, paths, registry keys and suspicious commands extracted; capped at 200k strings."),
        _entry("SQLite database", "db.sqlite", list(_sqlite.EXTENSIONS),
               "Opened READ-ONLY (mode=ro&immutable=1 — the evidence file is never written to). Every user table is "
               "enumerated; timestamp columns are decoded from unix s/ms/us/ns, Julian day, WebKit/Chrome and .NET "
               "ticks; one event per row with table/row in fields and BLOBs rendered as size + SHA-256."),
        _entry("E-mail message", "mail.message", [".eml", ".mbox", ".msg"],
               "RFC 822 .eml and multi-message .mbox (one event per message): Date, From/To/Cc, Subject, Message-ID, "
               "originating IPs from Received, SPF/DKIM/DMARC from Authentication-Results, body URLs and attachment "
               "names + SHA-256.",
               available=True,
               note=None if _eml.msg_available() else "Outlook .msg needs the optional 'extract_msg' package"),
        _entry("Archives", "archive", [".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".gz", ".bz2", ".xz",
                                       ".7z", ".rar"],
               "Expanded on upload; each member is fingerprinted separately and keeps its provenance as "
               "'archive.zip!path/inside.log' (Office documents are not treated as archives). Nested archives are "
               f"expanded {_archives.MAX_DEPTH} levels deep; path traversal (zip-slip) is refused and zip bombs are "
               f"capped at {_archives.MAX_ENTRIES:,} entries / "
               f"{_archives.MAX_TOTAL_BYTES // (1024 * 1024)} MB. Password-protected archives are reported, never "
               "silently skipped. 7z/RAR need the optional py7zr / rarfile packages.",
               available=True,
               note=None if (_sevenz_ok and _rar_ok) else
               ("7z needs py7zr; RAR needs rarfile" if not (_sevenz_ok or _rar_ok)
                else ("RAR needs rarfile" if _sevenz_ok else "7z needs py7zr"))),
    ]


@router.get("")
def get_parsers() -> dict:
    return {"parsers": list_parsers()}
