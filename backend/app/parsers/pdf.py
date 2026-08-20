"""PDF parser: text extraction per page via pypdf -> one event per non-empty line."""
from __future__ import annotations

import io
from typing import Iterable, Iterator

from .base import BaseParser, ParsedEvent
from .tabular import line_event

PDF_MAGIC = b"%PDF"


def available() -> bool:
    try:
        import pypdf  # noqa: F401
        return True
    except Exception:
        return False


class PdfParser(BaseParser):
    name = "PDF (text)"
    family = "document.pdf"
    binary = True
    extensions = (".pdf",)

    def sniff(self, sample: list[str], filename: str = "", head: bytes = b"") -> float:
        if head.startswith(PDF_MAGIC):
            return 1.0
        if filename.lower().endswith(".pdf"):
            return 0.8
        return 0.0

    def parse(self, lines: Iterable[str]) -> Iterator[ParsedEvent]:  # text fallback (should not happen)
        for i, line in enumerate(lines):
            if line.strip():
                yield line_event(line.strip(), {"page": "1", "line_no": str(i + 1)})

    def parse_bytes(self, data: bytes) -> Iterator[ParsedEvent]:
        try:
            from pypdf import PdfReader
        except Exception as exc:
            raise RuntimeError(f"pypdf not installed: {exc}")
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            try:
                reader.decrypt("")
            except Exception:
                raise RuntimeError("PDF is encrypted")
        for pno, page in enumerate(reader.pages, start=1):
            try:
                text = page.extract_text() or ""
            except Exception as exc:  # broken page: keep going
                yield ParsedEvent(raw="", msg=f"page {pno}: text extraction failed ({type(exc).__name__})",
                                  fields={"page": str(pno), "parse_error": "pdf-page"})
                continue
            for lno, line in enumerate(text.splitlines(), start=1):
                s = line.strip()
                if not s:
                    continue
                yield line_event(s, {"page": str(pno), "line_no": str(lno)})
