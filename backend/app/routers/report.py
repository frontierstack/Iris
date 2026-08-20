"""Report endpoints."""
from __future__ import annotations

import orjson
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

from ..models import Report
from ..report import PDF_AVAILABLE, PDF_IMPORT_ERROR, build_report, export_markdown, export_pdf, export_stix, safe_filename
from ..store import STORE
from .iocs import _all_iocs

router = APIRouter(prefix="/report", tags=["report"])


@router.get("", response_model=Report)
def report(scope: str = Query("all", pattern="^(all|case)$")) -> Report:
    return build_report(STORE, scope)


@router.get("/export")
def export(format: str = "md", scope: str = Query("all", pattern="^(all|case)$")) -> Response:
    rep = build_report(STORE, scope)
    base = safe_filename(f"{rep.caseId}_{rep.caseName}")
    disposition = 'attachment; filename="%s.%s"'
    if format == "md":
        return Response(export_markdown(rep), media_type="text/markdown; charset=utf-8",
                        headers={"Content-Disposition": disposition % (base, "md")})
    if format == "json":
        return Response(orjson.dumps(rep.model_dump(), option=orjson.OPT_INDENT_2), media_type="application/json",
                        headers={"Content-Disposition": disposition % (base, "json")})
    if format == "stix":
        return Response(orjson.dumps(export_stix(rep), option=orjson.OPT_INDENT_2), media_type="application/stix+json",
                        headers={"Content-Disposition": disposition % (base, "stix.json")})
    if format == "pdf":
        if not PDF_AVAILABLE:
            raise HTTPException(503, f"PDF export needs reportlab, which is not installed on the server ({PDF_IMPORT_ERROR})")
        # manual indicators live in the store, not in the derived Report, so merge both lists for the deliverable
        pdf = export_pdf(rep, STORE, scope, iocs=_all_iocs(scope))
        return Response(pdf, media_type="application/pdf",
                        headers={"Content-Disposition": disposition % (base, "pdf")})
    raise HTTPException(400, "format must be md, json, stix or pdf")
