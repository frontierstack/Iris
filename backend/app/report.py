"""Report builder + exports (md / json / stix / pdf)."""
from __future__ import annotations

import io
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from .correlate import clock, fmt_span
from .models import Cluster, Event, Finding, IOC, IOCHit, Report, SEV_ORDER, max_sev
from .normalize import AKIA_RE, KEYFP_RE, PATH_RE, is_public_ip
from .store import Store

UTC = timezone.utc


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _summary(store: Store, clusters: list[Cluster], events: list[Event]) -> str:
    seeds = [e for e in events if e.detections]
    if not seeds:
        n = len(events)
        return (f"{n:,} events from {len(store.case_source_ids())} source(s) were normalized. No detection rules fired; "
                "no correlated activity was identified in this dataset.")
    seeds.sort(key=lambda e: e.ts)
    first, last = seeds[0], seeds[-1]
    day = first.ts[:10]
    parts = [f"Between {clock(first.ts)} and {clock(last.ts)} UTC on {day}, "
             f"{len(clusters)} correlated incident cluster(s) were identified across {len({e.source for e in seeds})} log source(s) "
             f"({len(seeds)} detection-bearing events out of {len(events):,} normalized)."]
    for c in clusters:
        parts.append(f"{c.title} ({c.span}, {c.sev}): {c.why}")
    top_entities = [e.name for e in store.analysis()["entities"][:5]]
    if top_entities:
        parts.append("Key entities: " + ", ".join(top_entities) + ".")
    parts.append("Containment and credential rotation actions should be tracked against the curated case set.")
    return " ".join(parts)


def _findings(clusters: list[Cluster], store: Store) -> list[Finding]:
    out: list[Finding] = []
    for c in clusters:
        evs = [store.event(i) for i in c.eventIds]
        evs = [e for e in evs if e is not None]
        rules = []
        for e in evs:
            for d in e.detections:
                if d.id not in rules:
                    rules.append(d.id)
        evidence = "; ".join(f"{clock(e.ts)} {e.msg}" for e in evs[:5]) + ("; …" if len(evs) > 5 else "")
        body = f"{c.why} Rules: {', '.join(rules[:6])}. Sources: {' · '.join(c.sources)}."
        out.append(Finding(level=c.sev, title=c.title, body=body, evidence=evidence))
    out.sort(key=lambda f: -SEV_ORDER.get(f.level, 0))
    return out


MAX_IOC_HITS = 5


def sample_hit(ioc: IOC, e: Event) -> None:
    """Keep a small set of click-through hits that COVERS every file the indicator claims.

    The sample was simply the first `MAX_IOC_HITS` matches in time order, so one busy log crowded the
    others out: an indicator listing `Sophos Web Proxy.csv` and `DNS Logs.csv` showed five Sophos hits
    and nothing to click for DNS. The list of files said one thing and the list of places said
    another, which reads as "the DNS reference was wrong" — a claim about the evidence, made by a
    display cap.

    So: the first hit for each NEW file always goes in, and the remaining slots go to whatever comes
    next. A file only listed once therefore always has a way in, and the caller's "showing X of N"
    line still tells the analyst the sample is a sample.
    """
    covered = {h.file for h in ioc.hits}
    if e.file and e.file not in covered:
        ioc.hits.append(IOCHit(eventId=e.id, ts=e.ts, sourceId=e.sourceId, file=e.file))
        return
    if len(ioc.hits) < MAX_IOC_HITS:
        ioc.hits.append(IOCHit(eventId=e.id, ts=e.ts, sourceId=e.sourceId, file=e.file))


def _iocs(events: list[Event]) -> list[IOC]:
    """Indicators plus every place they were seen, so the UI can link back to the log file."""
    idx: dict[tuple[str, str], IOC] = {}

    def add(kind: str, value: str, e: Event) -> None:
        if not value:
            return
        ioc = idx.get((kind, value))
        if ioc is None:
            ioc = IOC(kind=kind, value=value, firstSeen=e.ts, lastSeen=e.ts)
            idx[(kind, value)] = ioc
        ioc.count += 1
        if e.file and e.file not in ioc.files:
            ioc.files.append(e.file)
        if not ioc.firstSeen or e.ts < ioc.firstSeen:
            ioc.firstSeen = e.ts
        if not ioc.lastSeen or e.ts > ioc.lastSeen:
            ioc.lastSeen = e.ts
        sample_hit(ioc, e)

    seeds = [e for e in events if e.detections]
    for e in seeds:
        for x in e.entities:
            if is_public_ip(x):
                add("ipv4", x, e)
        for k in AKIA_RE.findall(e.raw):
            add("aws-access-key", k, e)
        for fp in KEYFP_RE.findall(e.raw):
            add("ssh-key-fingerprint", fp, e)
        for p in PATH_RE.findall(e.raw):
            add("file-path", p, e)
        ua = e.fields.get("user_agent", "")
        if ua and any(d.id in ("SIGMA-WEB-0042", "SIGMA-WEB-0050") for d in e.detections):
            add("user-agent", ua, e)
        dst = e.fields.get("dst", "")
        if dst and is_public_ip(dst) and e.fields.get("dst_port"):
            add("dst-endpoint", f"{dst}:{e.fields['dst_port']}", e)
    # most-seen first, then alphabetical so the list is stable between refreshes
    return sorted(idx.values(), key=lambda i: (-i.count, i.kind, i.value))


def build_report(store: Store, scope: str = "all") -> Report:
    analysis = store.analysis(scope)
    clusters: list[Cluster] = analysis["clusters"]
    # scope=all means every event OF THIS CASE — a report is case documentation, so the case-less
    # library pool is deliberately out of scope (see store.case_events)
    events = store.case_set_events() if scope == "case" else store.case_events()
    severity = "info"
    for e in events:
        for d in e.detections:
            severity = max_sev(severity, d.level)
    curated = [store.event(eid) for eid in store.case_set]
    return Report(caseId=store.case_id, caseName=store.name, analyst=store.analyst, generatedAt=_now(),
                  severity=severity, summary=_summary(store, clusters, events), findings=_findings(clusters, store),  # type: ignore[arg-type]
                  caseSet=[p for p in curated if p is not None], iocs=_iocs(events), notes=store.notes)


# ------------------------------------------------------------------ exports
def export_markdown(rep: Report) -> str:
    lines = [f"# {rep.caseName}", "", f"- Case: {rep.caseId}", f"- Analyst: {rep.analyst}", f"- Generated: {rep.generatedAt}",
             f"- Severity: **{rep.severity.upper()}**", "", "## Summary", "", rep.summary, "", "## Findings", ""]
    for i, f in enumerate(rep.findings, 1):
        lines += [f"### {i}. [{f.level.upper()}] {f.title}", "", f.body, "", f"Evidence: {f.evidence}", ""]
    lines += ["## Case set — curated evidence", ""]
    if rep.caseSet:
        # The FILE, not the parser. A report is read away from Iris — by someone who has to go back to
        # the original log — and `source` is what the line was parsed AS (nginx, delimited, jsonl), which
        # several files share. Naming it as the reference points at nothing.
        lines += ["| ts | file | host | user | sev | labels | message |", "|---|---|---|---|---|---|---|"]
        for e in rep.caseSet:
            labels = ", ".join(e.labels) if e.labels else ""
            lines.append(f"| {e.ts} | {e.file or e.source} | {e.host} | {e.user} | {e.sev} | {labels} | "
                         f"{e.msg.replace('|', '/')} |")
    else:
        lines.append("_none_")
    lines += ["", "## Investigation notes", ""]
    if rep.notes:
        for n in rep.notes:
            stamp = n.createdAt + (f" (edited {n.updatedAt})" if n.updatedAt else "")
            who = f" — {n.author}" if n.author else ""
            lines += [f"**{stamp}**{who}", "", n.text, ""]
            if n.refs:
                lines += ["Linked: " + ", ".join(f"{r.kind}:{r.label or r.value}" for r in n.refs), ""]
    else:
        lines.append("_none_")
    lines += ["", "## Indicators of compromise", ""]
    if rep.iocs:
        lines += ["| kind | value | seen | log files | first | last |", "|---|---|---|---|---|---|"]
        for i in rep.iocs:
            lines.append(f"| {i.kind} | `{i.value}` | {i.count} | {' · '.join(i.files) or '—'} | {i.firstSeen or '—'} | {i.lastSeen or '—'} |")
    else:
        lines.append("_none_")
    return "\n".join(lines) + "\n"


_STIX_PATTERN = {
    "ipv4": lambda v: f"[ipv4-addr:value = '{v}']",
    "aws-access-key": lambda v: f"[user-account:user_id = '{v}' AND user-account:account_type = 'aws-access-key']",
    "ssh-key-fingerprint": lambda v: f"[x-ssh-key:fingerprint = '{v}']",
    "file-path": lambda v: f"[file:name = '{v.split('/')[-1]}' AND directory:path = '{v.rsplit('/', 1)[0] or '/'}']",
    "user-agent": lambda v: f"[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '{v}']",
    "dst-endpoint": lambda v: f"[ipv4-addr:value = '{v.split(':')[0]}' AND network-traffic:dst_port = {v.split(':')[1]}]",
}


def export_stix(rep: Report) -> dict[str, Any]:
    now = rep.generatedAt
    ns = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
    identity_id = f"identity--{uuid.uuid5(ns, 'iris-' + rep.analyst)}"
    objects: list[dict[str, Any]] = [{
        "type": "identity", "spec_version": "2.1", "id": identity_id, "created": now, "modified": now,
        "name": rep.analyst or "Iris analyst", "identity_class": "individual",
    }]
    report_refs: list[str] = []
    for ioc in rep.iocs:
        pat = _STIX_PATTERN.get(ioc.kind)
        if not pat:
            continue
        iid = f"indicator--{uuid.uuid5(ns, ioc.kind + ':' + ioc.value)}"
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": iid, "created": now, "modified": now, "created_by_ref": identity_id,
            "name": f"{ioc.kind}: {ioc.value}", "indicator_types": ["malicious-activity"],
            "pattern": pat(ioc.value.replace("'", "\\'")), "pattern_type": "stix", "valid_from": now,
            "labels": [ioc.kind, rep.severity],
        })
        report_refs.append(iid)
    for f in rep.findings:
        sid = f"attack-pattern--{uuid.uuid5(ns, f.title)}"
        objects.append({"type": "attack-pattern", "spec_version": "2.1", "id": sid, "created": now, "modified": now,
                        "created_by_ref": identity_id, "name": f.title, "description": f.body,
                        "labels": [f.level]})
        report_refs.append(sid)
    objects.append({
        "type": "report", "spec_version": "2.1", "id": f"report--{uuid.uuid5(ns, rep.caseId + now)}", "created": now, "modified": now,
        "created_by_ref": identity_id, "name": rep.caseName, "description": rep.summary, "report_types": ["threat-report"],
        "published": now, "object_refs": report_refs or [identity_id], "labels": [rep.severity],
    })
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def safe_filename(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_") or "report"


# ------------------------------------------------------------------ pdf export
# reportlab is pure Python (no system binaries), so the slim Docker image keeps working. The import is
# guarded all the same: a missing wheel must surface as a 503 on /api/report/export?format=pdf, never as
# an import-time crash that takes the whole app down.
try:  # pragma: no cover - exercised by whichever environment lacks the wheel
    from reportlab.lib import colors as _rl_colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.pdfgen import canvas as _rl_canvas
    from reportlab.platypus import (BaseDocTemplate, Frame, HRFlowable, KeepTogether, LongTable, PageBreak,
                                    PageTemplate, Paragraph, Spacer, Table, TableStyle)

    PDF_AVAILABLE = True
    PDF_IMPORT_ERROR = ""
except Exception as exc:  # pragma: no cover
    PDF_AVAILABLE = False
    PDF_IMPORT_ERROR = str(exc)


class PdfUnavailable(RuntimeError):
    """reportlab is not installed in this environment."""


_SEV_HEX = {"critical": "#8c1d18", "high": "#a63a10", "medium": "#8a6100", "low": "#1f4f8f", "info": "#5a6570"}
_INK = "#16202e"          # headings
_BODY = "#26313f"
_MUTED = "#6b7480"
_RULE = "#c9d0d8"
_HEAD_BG = "#eef1f5"
_ZEBRA = "#f8f9fb"
PDF_PAGE = letter if PDF_AVAILABLE else None
_MARGIN = 0.75 * 72
_CONTENT_W = 8.5 * 72 - 2 * _MARGIN     # 468pt


def _esc(v: Any, limit: int = 400) -> str:
    """Escape for reportlab's mini-XML and clamp so nothing runs off the page."""
    s = "" if v is None else str(v)
    s = s.replace("\r", " ").replace("\t", " ")
    if len(s) > limit:
        s = s[: limit - 1] + "…"
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _human_size(n: int) -> str:
    x = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if x < 1024 or unit == "GB":
            return f"{x:.0f} {unit}" if unit == "B" else f"{x:.1f} {unit}"
        x /= 1024
    return f"{x:.1f} GB"


def _pdf_styles() -> dict[str, Any]:
    base = ParagraphStyle("body", fontName="Helvetica", fontSize=9, leading=12.6, textColor=_rl_colors.HexColor(_BODY),
                          alignment=TA_LEFT)
    return {
        "title": ParagraphStyle("title", parent=base, fontName="Helvetica-Bold", fontSize=22, leading=27,
                                textColor=_rl_colors.HexColor(_INK), spaceAfter=6),
        "subtitle": ParagraphStyle("subtitle", parent=base, fontSize=11, leading=15, textColor=_rl_colors.HexColor(_MUTED)),
        "eyebrow": ParagraphStyle("eyebrow", parent=base, fontName="Helvetica-Bold", fontSize=8, leading=11,
                                  textColor=_rl_colors.HexColor(_MUTED)),
        "h1": ParagraphStyle("h1", parent=base, fontName="Helvetica-Bold", fontSize=14, leading=18,
                             textColor=_rl_colors.HexColor(_INK), spaceBefore=0, spaceAfter=2),
        "h2": ParagraphStyle("h2", parent=base, fontName="Helvetica-Bold", fontSize=10.5, leading=14,
                             textColor=_rl_colors.HexColor(_INK), spaceBefore=8, spaceAfter=3),
        "body": base,
        "small": ParagraphStyle("small", parent=base, fontSize=8, leading=11, textColor=_rl_colors.HexColor(_MUTED)),
        "cell": ParagraphStyle("cell", parent=base, fontSize=7.6, leading=10),
        "cellmono": ParagraphStyle("cellmono", parent=base, fontName="Courier", fontSize=7.2, leading=9.6),
        "cellhead": ParagraphStyle("cellhead", parent=base, fontName="Helvetica-Bold", fontSize=7.6, leading=10,
                                   textColor=_rl_colors.HexColor(_INK)),
        "empty": ParagraphStyle("empty", parent=base, fontSize=9, leading=13, textColor=_rl_colors.HexColor(_MUTED)),
    }


def _table(rows: list[list[Any]], widths: list[float], st: dict[str, Any], align: Optional[dict[int, str]] = None) -> Any:
    """A paginating table with a repeated header row. rows[0] is the header."""
    data = [[Paragraph(_esc(c, 120), st["cellhead"]) for c in rows[0]]]
    for r in rows[1:]:
        data.append([c if hasattr(c, "wrap") else Paragraph(_esc(c), st["cell"]) for c in r])
    t = LongTable(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), _rl_colors.HexColor(_HEAD_BG)),
        ("LINEBELOW", (0, 0), (-1, 0), 0.6, _rl_colors.HexColor(_RULE)),
        ("GRID", (0, 0), (-1, -1), 0.25, _rl_colors.HexColor(_RULE)),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_rl_colors.white, _rl_colors.HexColor(_ZEBRA)]),
    ]
    for col, how in (align or {}).items():
        style.append(("ALIGN", (col, 0), (col, -1), how))
    t.setStyle(TableStyle(style))
    return t


def _sev_para(sev: str, st: dict[str, Any]) -> Any:
    hexc = _SEV_HEX.get(sev, _MUTED)
    return Paragraph(f'<font color="{hexc}"><b>{_esc(sev.upper())}</b></font>', st["cell"])


def _section(title: str, st: dict[str, Any], first: bool = False) -> list[Any]:
    out: list[Any] = [] if first else [PageBreak()]
    out += [Paragraph(_esc(title), st["h1"]),
            HRFlowable(width="100%", thickness=0.8, color=_rl_colors.HexColor(_RULE), spaceBefore=3, spaceAfter=9)]
    return out


def _empty(text: str, st: dict[str, Any]) -> Any:
    return Paragraph(_esc(text), st["empty"])


def _pdf_facts(store: Optional[Store], rep: Report, scope: str) -> dict[str, Any]:
    """Everything the PDF shows beyond the Report model — sources, clusters, detections, graph."""
    facts: dict[str, Any] = {"sources": [], "clusters": [], "events": [], "detections": [], "nodes": [], "edges": [],
                             "eventCount": 0, "range": None}
    if store is None:
        return facts
    try:
        # the report documents the CASE, so it lists the case's own sources — files staged in the library
        # belong to no case and have no place in its evidence trail
        facts["sources"] = [store.sources[s] for s in store.case_source_ids()]
    except Exception:
        facts["sources"] = list(getattr(store, "sources", {}).values())
    try:
        events = store.case_set_events() if scope == "case" else store.case_events()
    except Exception:
        events = []
    facts["eventCount"] = len(events)
    stamps = sorted(e.ts for e in events if e.ts)
    facts["range"] = (stamps[0], stamps[-1]) if stamps else None
    try:
        facts["clusters"] = store.analysis(scope)["clusters"]
    except Exception:
        facts["clusters"] = []
    seeds = sorted((e for e in events if e.detections), key=lambda e: e.ts)
    facts["events"] = seeds
    tally: dict[str, dict[str, Any]] = {}
    for e in seeds:
        for d in e.detections:
            row = tally.setdefault(d.id, {"id": d.id, "name": d.name, "level": d.level, "count": 0})
            row["count"] += 1
            row["level"] = max_sev(row["level"], d.level)
    facts["detections"] = sorted(tally.values(), key=lambda r: (-SEV_ORDER.get(r["level"], 0), -r["count"], r["id"]))
    try:
        gb = store.graph_v2(scope)
        nodes, edges, _stats = gb.select(limit=40)
        facts["nodes"], facts["edges"] = nodes, edges
    except Exception:
        facts["nodes"], facts["edges"] = [], []
    return facts


if PDF_AVAILABLE:
    class _NumberedCanvas(_rl_canvas.Canvas):  # type: ignore[misc]
        """Two-pass canvas so the footer can say 'Page 2 of 9'."""

        def __init__(self, *a: Any, **kw: Any) -> None:
            self._footer = kw.pop("iris_footer", "")
            super().__init__(*a, **kw)
            self._pages: list[dict[str, Any]] = []

        def showPage(self) -> None:  # noqa: N802 - reportlab API
            self._pages.append(dict(self.__dict__))
            self._startPage()

        def save(self) -> None:
            total = len(self._pages)
            for state in self._pages:
                self.__dict__.update(state)
                self._draw_footer(total)
                super().showPage()
            super().save()

        def _draw_footer(self, total: int) -> None:
            page = self._pageNumber
            if page == 1 and total > 1:      # the title page carries no rule/footer
                return
            w, _h = PDF_PAGE
            y = _MARGIN - 22
            self.setStrokeColor(_rl_colors.HexColor(_RULE))
            self.setLineWidth(0.5)
            self.line(_MARGIN, y + 13, w - _MARGIN, y + 13)
            self.setFont("Helvetica", 7.5)
            self.setFillColor(_rl_colors.HexColor(_MUTED))
            self.drawString(_MARGIN, y, self._footer[:120])
            self.drawRightString(w - _MARGIN, y, f"Page {page} of {total}")


def export_pdf(rep: Report, store: Optional[Store] = None, scope: str = "all",
               iocs: Optional[list[IOC]] = None) -> bytes:
    """Render the full case as a paginated, print-ready PDF (title page + one section per topic)."""
    if not PDF_AVAILABLE:
        raise PdfUnavailable(PDF_IMPORT_ERROR or "reportlab is not installed")
    st = _pdf_styles()
    facts = _pdf_facts(store, rep, scope)
    ioc_list = iocs if iocs is not None else rep.iocs
    buf = io.BytesIO()
    footer = f"{rep.caseName or 'Untitled case'} · case {rep.caseId} · generated {rep.generatedAt}"

    doc = BaseDocTemplate(buf, pagesize=PDF_PAGE, leftMargin=_MARGIN, rightMargin=_MARGIN,
                          topMargin=_MARGIN, bottomMargin=_MARGIN, title=f"{rep.caseName} — Iris incident report",
                          author=rep.analyst or "Iris", subject=f"Case {rep.caseId}", creator="Iris")
    frame = Frame(_MARGIN, _MARGIN, _CONTENT_W, PDF_PAGE[1] - 2 * _MARGIN, id="body",
                  leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    doc.addPageTemplates([PageTemplate(id="main", frames=[frame])])

    flow: list[Any] = []
    flow += _pdf_title_page(rep, facts, st, scope)
    flow += _pdf_overview(rep, facts, st, scope)
    flow += _pdf_sources(facts, st)
    flow += _pdf_timeline(facts, st)
    flow += _pdf_findings(rep, facts, st)
    flow += _pdf_iocs(ioc_list, st)
    flow += _pdf_graph(facts, st)
    flow += _pdf_notes(rep, st)
    flow += _pdf_case_set(rep, st)

    doc.build(flow, canvasmaker=lambda *a, **kw: _NumberedCanvas(*a, iris_footer=footer, **kw))
    return buf.getvalue()


# ---------------------------------------------------------------- pdf sections
_SECTIONS = ["Case overview", "Ingested sources", "Timeline of key events", "Detections and findings",
             "Indicators of compromise", "Entity graph highlights", "Analyst notes", "Case set — curated evidence"]


def _pdf_title_page(rep: Report, facts: dict[str, Any], st: dict[str, Any], scope: str) -> list[Any]:
    sev = rep.severity or "info"
    meta = [
        ["Case name", rep.caseName or "Untitled case"],
        ["Case id", rep.caseId or "—"],
        ["Analyst", rep.analyst or "—"],
        ["Generated (UTC)", rep.generatedAt or _now()],
        ["Report scope", "curated case set only" if scope == "case" else "every ingested event"],
        ["Highest severity", Paragraph(f'<font color="{_SEV_HEX.get(sev, _MUTED)}"><b>{_esc(sev.upper())}</b></font>', st["cell"])],
    ]
    rng = facts.get("range")
    if rng:
        meta.append(["Evidence window", f"{rng[0]} → {rng[1]}"])
    meta.append(["Events analyzed", f"{facts.get('eventCount', 0):,}"])
    meta.append(["Sources ingested", str(len(facts.get("sources", [])))])

    rows = [["Field", "Value"]] + meta
    flow: list[Any] = [
        Spacer(1, 1.1 * inch),
        Paragraph("IRIS · INCIDENT REPORT", st["eyebrow"]),
        Spacer(1, 6),
        Paragraph(_esc(rep.caseName or "Untitled case", 160), st["title"]),
        Paragraph("Log parsing, detection and correlation workbench output", st["subtitle"]),
        HRFlowable(width="100%", thickness=1, color=_rl_colors.HexColor(_RULE), spaceBefore=14, spaceAfter=18),
        _table(rows, [1.6 * inch, _CONTENT_W - 1.6 * inch], st),
        Spacer(1, 26),
        Paragraph("Contents", st["h2"]),
    ]
    flow += [Paragraph("· " + _esc(s), st["body"]) for s in _SECTIONS]
    flow += [Spacer(1, 24),
             Paragraph("This document is generated from the case as it stands at the timestamp above. "
                       "All timestamps are ISO-8601 UTC.", st["small"])]
    return flow


def _pdf_overview(rep: Report, facts: dict[str, Any], st: dict[str, Any], scope: str) -> list[Any]:
    flow = _section("Case overview", st)
    flow.append(Paragraph("Summary", st["h2"]))
    flow.append(Paragraph(_esc(rep.summary, 6000) if rep.summary else "No summary is available for this case yet.",
                          st["body"] if rep.summary else st["empty"]))
    flow.append(Spacer(1, 12))
    flow.append(Paragraph("At a glance", st["h2"]))
    counts = [
        ["Metric", "Value"],
        ["Events analyzed", f"{facts.get('eventCount', 0):,}"],
        ["Sources ingested", str(len(facts.get("sources", [])))],
        ["Detection-bearing events", f"{len(facts.get('events', [])):,}"],
        ["Distinct rules fired", str(len(facts.get("detections", [])))],
        ["Correlated clusters", str(len(facts.get("clusters", [])))],
        ["Findings", str(len(rep.findings))],
        ["Indicators", str(len(rep.iocs))],
        ["Case-set events", str(len(rep.caseSet))],
        ["Analyst notes", str(len(rep.notes))],
        ["Scope", "curated case set only" if scope == "case" else "every ingested event"],
    ]
    flow.append(_table(counts, [2.2 * inch, _CONTENT_W - 2.2 * inch], st))
    return flow


def _pdf_sources(facts: dict[str, Any], st: dict[str, Any]) -> list[Any]:
    flow = _section("Ingested sources", st)
    sources = facts.get("sources", [])
    if not sources:
        flow.append(_empty("No sources have been ingested into this case.", st))
        return flow
    rows: list[list[Any]] = [["File", "Parser", "Events", "Size", "State", "First seen", "Last seen"]]
    for s in sources:
        rng = getattr(s, "range", None)
        rows.append([Paragraph(_esc(s.file, 90), st["cell"]), s.parser or "—", f"{s.events:,}", _human_size(s.size),
                     s.state, (rng[0] if rng else "—"), (rng[1] if rng else "—")])
    widths = [1.55 * inch, 0.75 * inch, 0.5 * inch, 0.55 * inch, 0.6 * inch, 0.9 * inch, 0.9 * inch]
    widths[0] = _CONTENT_W - sum(widths[1:])
    flow.append(_table(rows, widths, st, align={2: "RIGHT", 3: "RIGHT"}))
    total = sum(s.events for s in sources)
    flow.append(Spacer(1, 8))
    flow.append(Paragraph(f"{len(sources)} source(s), {total:,} parsed events.", st["small"]))
    return flow


def _pdf_timeline(facts: dict[str, Any], st: dict[str, Any], limit: int = 120) -> list[Any]:
    flow = _section("Timeline of key events", st)
    clusters = facts.get("clusters", [])
    flow.append(Paragraph("Correlated clusters", st["h2"]))
    if clusters:
        rows: list[list[Any]] = [["Window", "Cluster", "Sev", "Events", "Why"]]
        for c in clusters:
            # the escape happens per-half so the <br/> stays real markup rather than literal text
            rows.append([Paragraph(f"{_esc(c.start)}<br/>{_esc(c.end)}", st["cell"]),
                         Paragraph(_esc(c.title, 120), st["cell"]), _sev_para(c.sev, st), str(c.count),
                         Paragraph(_esc(c.why, 300), st["cell"])])
        widths = [1.15 * inch, 1.5 * inch, 0.5 * inch, 0.45 * inch]
        widths.append(_CONTENT_W - sum(widths))
        flow.append(_table(rows, widths, st, align={3: "RIGHT"}))
    else:
        flow.append(_empty("No correlated clusters were identified.", st))

    flow.append(Spacer(1, 14))
    events = facts.get("events", [])
    flow.append(Paragraph(f"Detection-bearing events · {len(events):,}", st["h2"]))
    if not events:
        flow.append(_empty("No detection rules fired on this dataset.", st))
        return flow
    rows = [["Timestamp (UTC)", "File", "Host / user", "Sev", "Rules", "Message"]]
    for e in events[:limit]:
        who = " / ".join(x for x in (e.host, e.user) if x) or "—"
        rules = ", ".join(dict.fromkeys(d.id for d in e.detections))
        rows.append([Paragraph(_esc(e.ts), st["cell"]), Paragraph(_esc(e.file or e.source, 40), st["cell"]),
                     Paragraph(_esc(who, 60), st["cell"]), _sev_para(e.sev, st),
                     Paragraph(_esc(rules, 60), st["cell"]), Paragraph(_esc(e.msg, 300), st["cell"])])
    widths = [1.0 * inch, 0.75 * inch, 0.9 * inch, 0.45 * inch, 0.95 * inch]
    widths.append(_CONTENT_W - sum(widths))
    flow.append(_table(rows, widths, st))
    if len(events) > limit:
        flow.append(Spacer(1, 8))
        flow.append(Paragraph(f"Showing the first {limit:,} of {len(events):,} detection-bearing events; "
                              "the full set is available in the JSON export.", st["small"]))
    return flow


def _pdf_findings(rep: Report, facts: dict[str, Any], st: dict[str, Any]) -> list[Any]:
    flow = _section("Detections and findings", st)
    dets = facts.get("detections", [])
    flow.append(Paragraph("Rules fired", st["h2"]))
    if dets:
        rows: list[list[Any]] = [["Rule id", "Rule", "Severity", "Hits"]]
        for d in dets:
            rows.append([Paragraph(_esc(d["id"], 40), st["cellmono"]), Paragraph(_esc(d["name"], 120), st["cell"]),
                         _sev_para(d["level"], st), f"{d['count']:,}"])
        widths = [1.25 * inch, 0.9 * inch, 0.75 * inch]
        widths[1] = _CONTENT_W - (widths[0] + widths[2] + 0.6 * inch)
        flow.append(_table(rows, [widths[0], widths[1], widths[2], 0.6 * inch], st, align={3: "RIGHT"}))
    else:
        flow.append(_empty("No detection rules fired.", st))

    flow.append(Spacer(1, 14))
    flow.append(Paragraph(f"Findings · {len(rep.findings)}", st["h2"]))
    if not rep.findings:
        flow.append(_empty("No findings have been recorded for this case.", st))
        return flow
    for sev in ("critical", "high", "medium", "low", "info"):
        group = [f for f in rep.findings if f.level == sev]
        if not group:
            continue
        flow.append(Spacer(1, 8))
        flow.append(Paragraph(f'<font color="{_SEV_HEX[sev]}">{sev.upper()}</font> · {len(group)} finding(s)', st["h2"]))
        for i, f in enumerate(group, 1):
            block = [Paragraph(f"{i}. {_esc(f.title, 200)}", st["h2"]),
                     Paragraph(_esc(f.body, 3000) if f.body else "—", st["body"])]
            if f.evidence:
                block += [Spacer(1, 3), Paragraph("Evidence: " + _esc(f.evidence, 1500), st["small"])]
            block.append(Spacer(1, 6))
            flow.append(KeepTogether(block))
    return flow


def _pdf_iocs(iocs: list[IOC], st: dict[str, Any]) -> list[Any]:
    flow = _section("Indicators of compromise", st)
    if not iocs:
        flow.append(_empty("No indicators were extracted, and none were added by hand.", st))
        return flow
    manual = sum(1 for i in iocs if getattr(i, "manual", False))
    flow.append(Paragraph(f"{len(iocs)} indicator(s) — {len(iocs) - manual} extracted, {manual} added by the analyst.",
                          st["small"]))
    flow.append(Spacer(1, 8))
    rows: list[list[Any]] = [["Kind", "Value", "Src", "Seen", "First", "Last", "Log files"]]
    for i in iocs:
        rows.append([Paragraph(_esc(i.kind, 40), st["cell"]), Paragraph(_esc(i.value, 160), st["cellmono"]),
                     "manual" if getattr(i, "manual", False) else "auto", f"{i.count:,}",
                     Paragraph(_esc(i.firstSeen or "—"), st["cell"]), Paragraph(_esc(i.lastSeen or "—"), st["cell"]),
                     Paragraph(_esc(" · ".join(i.files) or "—", 200), st["cell"])])
    widths = [0.85 * inch, 1.5 * inch, 0.45 * inch, 0.4 * inch, 0.95 * inch, 0.95 * inch]
    widths.append(_CONTENT_W - sum(widths))
    flow.append(_table(rows, widths, st, align={3: "RIGHT"}))
    return flow


def _pdf_graph(facts: dict[str, Any], st: dict[str, Any]) -> list[Any]:
    flow = _section("Entity graph highlights", st)
    nodes, edges = facts.get("nodes", []), facts.get("edges", [])
    flow.append(Paragraph("Top-ranked entities", st["h2"]))
    if nodes:
        rows: list[list[Any]] = [["Type", "Entity", "Events", "Detections", "Sev", "First seen", "Last seen"]]
        for n in nodes[:25]:
            rows.append([n.type, Paragraph(_esc(n.label or n.value, 90), st["cell"]), f"{n.count:,}",
                         str(n.detections), _sev_para(n.sev, st), Paragraph(_esc(n.first or "—"), st["cell"]),
                         Paragraph(_esc(n.last or "—"), st["cell"])])
        widths = [0.6 * inch, 1.6 * inch, 0.5 * inch, 0.65 * inch, 0.5 * inch, 0.95 * inch]
        widths.append(_CONTENT_W - sum(widths))
        flow.append(_table(rows, widths, st, align={2: "RIGHT", 3: "RIGHT"}))
    else:
        flow.append(_empty("The entity graph is empty for this scope.", st))

    flow.append(Spacer(1, 14))
    flow.append(Paragraph("Strongest relations", st["h2"]))
    if edges:
        rows = [["From", "Relation", "To", "Count", "Outcome", "Observed"]]
        for e in edges[:25]:
            rows.append([Paragraph(_esc(e.source, 80), st["cell"]), e.relation.replace("_", " "),
                         Paragraph(_esc(e.target, 80), st["cell"]), f"{e.count:,}", e.outcome or "—",
                         Paragraph(_esc(e.why, 120), st["cell"])])
        widths = [1.25 * inch, 0.8 * inch, 1.25 * inch, 0.5 * inch, 0.65 * inch]
        widths.append(_CONTENT_W - sum(widths))
        flow.append(_table(rows, widths, st, align={3: "RIGHT"}))
    else:
        flow.append(_empty("No relations were derived for this scope.", st))
    return flow


def _pdf_notes(rep: Report, st: dict[str, Any]) -> list[Any]:
    flow = _section("Analyst notes", st)
    if not rep.notes:
        flow.append(_empty("No investigation notes have been written for this case.", st))
        return flow
    for n in rep.notes:
        stamp = n.createdAt + (f" · edited {n.updatedAt}" if n.updatedAt else "")
        who = f" · {n.author}" if n.author else ""
        block = [Paragraph(_esc(stamp + who, 140), st["eyebrow"]), Spacer(1, 2),
                 Paragraph(_esc(n.text, 6000).replace("\n", "<br/>") or "—", st["body"])]
        if n.refs:
            block += [Spacer(1, 2),
                      Paragraph("Linked: " + _esc(", ".join(f"{r.kind}:{r.label or r.value}" for r in n.refs), 400), st["small"])]
        block += [Spacer(1, 4), HRFlowable(width="100%", thickness=0.4, color=_rl_colors.HexColor(_RULE),
                                           spaceBefore=2, spaceAfter=8)]
        flow.append(KeepTogether(block))
    return flow


def _pdf_case_set(rep: Report, st: dict[str, Any], limit: int = 250) -> list[Any]:
    flow = _section("Case set — curated evidence", st)
    if not rep.caseSet:
        flow.append(_empty("No events have been curated into the case set.", st))
        return flow
    rows: list[list[Any]] = [["Timestamp (UTC)", "File", "Host / user", "Sev", "Labels", "Message"]]
    for e in rep.caseSet[:limit]:
        who = " / ".join(x for x in (e.host, e.user) if x) or "—"
        rows.append([Paragraph(_esc(e.ts), st["cell"]), Paragraph(_esc(e.file or e.source, 40), st["cell"]),
                     Paragraph(_esc(who, 60), st["cell"]), _sev_para(e.sev, st),
                     Paragraph(_esc(", ".join(e.labels) or "—", 80), st["cell"]),
                     Paragraph(_esc(e.msg, 300), st["cell"])])
    widths = [1.0 * inch, 0.75 * inch, 0.9 * inch, 0.45 * inch, 0.8 * inch]
    widths.append(_CONTENT_W - sum(widths))
    flow.append(_table(rows, widths, st))
    if len(rep.caseSet) > limit:
        flow.append(Spacer(1, 8))
        flow.append(Paragraph(f"Showing the first {limit:,} of {len(rep.caseSet):,} curated events.", st["small"]))
    return flow
