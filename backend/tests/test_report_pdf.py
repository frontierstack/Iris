"""PDF export of the report draft.

The PDF is an IR deliverable, so the checks are about it being a real, multi-page, non-trivial
document — and about it still rendering when the case has nothing in it.
"""
from __future__ import annotations

import io

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.report import PDF_AVAILABLE
from tests.conftest import load_sample_case

pytestmark = pytest.mark.skipif(not PDF_AVAILABLE, reason="reportlab is not installed")


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        load_sample_case(c)
        yield c


def _pages(data: bytes) -> int:
    from pypdf import PdfReader

    return len(PdfReader(io.BytesIO(data)).pages)


def test_pdf_export_is_a_real_pdf(client):
    r = client.get("/api/report/export", params={"format": "pdf"})
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/pdf")
    assert "attachment; filename=" in r.headers["content-disposition"]
    assert r.headers["content-disposition"].endswith('.pdf"')
    body = r.content
    assert body[:5] == b"%PDF-"
    assert len(body) > 20_000, f"suspiciously small PDF: {len(body)} bytes"
    assert _pages(body) >= 5


def test_pdf_carries_the_case_sections(client):
    from pypdf import PdfReader

    body = client.get("/api/report/export", params={"format": "pdf"}).content
    text = "\n".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(body)).pages)
    for section in ("Case overview", "Ingested sources", "Timeline of key events", "Detections and findings",
                    "Indicators of compromise", "Entity graph highlights", "Analyst notes", "Case set"):
        assert section in text, f"missing section: {section}"
    assert "Page 2 of" in text          # footer with page numbers
    assert "IRIS" in text               # title page


def test_pdf_scope_case(client):
    body = client.get("/api/report/export", params={"format": "pdf", "scope": "case"}).content
    assert body[:5] == b"%PDF-"
    assert _pages(body) >= 4


def test_pdf_of_an_empty_case_still_renders(client):
    """No sources, no findings, no notes, no IOCs — every section must degrade to a sentence."""
    from pypdf import PdfReader

    client.post("/api/case/reset")
    try:
        body = client.get("/api/report/export", params={"format": "pdf"}).content
        assert body[:5] == b"%PDF-"
        text = "\n".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(body)).pages)
        assert "No sources have been ingested" in text
        assert "No investigation notes" in text
    finally:
        load_sample_case(client)


def test_unknown_format_still_400s(client):
    r = client.get("/api/report/export", params={"format": "docx"})
    assert r.status_code == 400
    assert "pdf" in r.json()["detail"]
