"""Parallel analysis agents (triage / timeline / entities / iocs) + synthesizer, streamed as SSE events.

If no AI provider is configured, deterministic offline agents built on the correlation engine are used so the
endpoint always produces a useful result.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any, AsyncIterator, Optional

import orjson

from ..config import get_settings
from ..correlate import clock
from ..models import Event, SEV_ORDER
from ..report import build_report
from ..store import Store
from .client import AIError, LLMClient
from .prompts import AGENTS, agent_prompt, synth_prompt

AGENT_ORDER = ["triage", "timeline", "entities", "iocs"]


# ------------------------------------------------------------------ context
def _event_line(e: Event) -> str:
    det = ", ".join(f"{d.id}" for d in e.detections)
    return f"- {e.ts} [{e.sev}] {e.source} host={e.host or '-'} user={e.user or '-'} :: {e.msg}" + (f" (detections: {det})" if det else "")


def build_context(store: Store, scope: str, id: Optional[str], event_ids: Optional[list[str]], max_events: int = 40) -> tuple[str, str]:
    """Return (header, full_context)."""
    case = store.case()
    analysis = store.analysis()
    clusters = analysis["clusters"]
    entities = analysis["entities"]
    header = (f"Case {case.id} '{case.name}' — {case.eventCount:,} events from {len(case.sources)} sources: "
              + ", ".join(f"{s.file} ({s.parser}, {s.events:,} events)" for s in case.sources)
              + ". Posture: " + "; ".join(f"{p.label}={p.value}" for p in case.posture) + ".")
    lines: list[str] = [header, ""]
    focus: list[Event] = []
    if scope == "event" and id:
        e = store.event(id)
        if e:
            focus = [e]
            lines.append("FOCUS EVENT:\n" + _event_line(e) + f"\n  raw: {e.raw[:600]}\n  fields: " + orjson.dumps(dict(list(e.fields.items())[:24])).decode())
            az = analysis.get("analyzer")
            if az is not None:
                i = store.event_index[e.id]
                corr = az.correlations_for(i, limit=8)
                lines.append("Correlated events:\n" + "\n".join(f"- {c.ts} [{c.sev}] {c.msg} ({c.reason})" for c in corr))
                lines.append("Baseline: " + az.baseline_for(i))
    elif scope == "cluster" and id:
        c = next((c for c in clusters if c.id == id), None)
        if c:
            focus = [x for x in (store.event(i) for i in c.eventIds) if x]
            lines.append(f"FOCUS CLUSTER {c.id}: {c.title} [{c.tag}, {c.sev}] {c.start}→{c.end} ({c.span}); why: {c.why}")
    elif scope == "selection" and event_ids:
        focus = [x for x in (store.event(i) for i in event_ids) if x]
        lines.append(f"FOCUS SELECTION: {len(focus)} events")
    if focus:
        lines.append("\n".join(_event_line(e) for e in focus[:max_events]))
    lines.append("")
    lines.append(f"CLUSTERS ({len(clusters)}):")
    for c in clusters[:12]:
        lines.append(f"- {c.id} {c.title} [{c.tag}, {c.sev}] {clock(c.start)}–{clock(c.end)} span={c.span} count={c.count} sources={' · '.join(c.sources)}\n  why: {c.why}")
    lines.append("")
    seeds = sorted((e for e in store.events if e.detections), key=lambda e: (-SEV_ORDER.get(e.sev, 0), e.ts))[:max_events]
    seeds.sort(key=lambda e: e.ts)
    lines.append(f"TOP DETECTION EVENTS ({len(seeds)}):")
    lines.extend(_event_line(e) for e in seeds)
    lines.append("")
    lines.append(f"ENTITIES ({len(entities)}):")
    for en in entities[:16]:
        facts = "; ".join(f"{k}={v}" for k, v in en.facts[:6])
        links = ", ".join(f"{l.name} ({l.shared} shared, {l.via})" for l in en.links[:4])
        lines.append(f"- {en.name} [{en.kind}] first={clock(en.first)} count={en.count} | {facts} | links: {links}")
    if store.case_set:
        lines.append("")
        lines.append("CASE SET (analyst-curated evidence): " + ", ".join(
            f"{eid}{(' [' + ', '.join(entry.labels) + ']') if entry.labels else ''}"
            for eid, entry in store.case_set.items()))
    if store.notes:
        lines.append("")
        lines.append("ANALYST NOTES:")
        for n in store.notes[-12:]:  # most recent entries, oldest first
            stamp = (n.createdAt or "")[:16].replace("T", " ")
            lines.append(f"- [{stamp}] {n.text.strip()[:400]}")
    return header, "\n".join(lines)


# ----------------------------------------------------------- offline agents
def _offline(agent: str, store: Store, context: str) -> str:
    rep = build_report(store)
    analysis = store.analysis()
    if agent == "triage":
        acts = ["Rotate credentials for compromised principals and revoke any created access keys.",
                "Block attacker IPs at the edge and review egress rules.",
                "Preserve volatile evidence on pivot hosts before remediation."]
        return (f"**Verdict:** {rep.severity.upper()} — {len(rep.findings)} correlated finding(s).\n\n"
                + "\n".join(f"- {f.title}: {f.evidence[:160]}" for f in rep.findings[:6])
                + "\n\n**Immediate actions**\n" + "\n".join(f"- {a}" for a in acts))
    if agent == "timeline":
        seeds = sorted((e for e in store.events if e.detections), key=lambda e: e.ts)[:30]
        return "\n".join(f"{i + 1}. {clock(e.ts)} — {e.source} — {e.msg} — {e.detections[0].name}" for i, e in enumerate(seeds)) or "No detections."
    if agent == "entities":
        return "\n".join(f"- **{en.name}** ({en.kind}): {en.count} events; " + "; ".join(f"{k} {v}" for k, v in en.facts[4:7])
                         + (" — linked to " + ", ".join(f"{l.name} via {l.via}" for l in en.links[:3]) if en.links else "")
                         for en in analysis["entities"][:12]) or "No entities."
    if agent == "iocs":
        return "\n".join(f"- {i.kind}: `{i.value}`" for i in rep.iocs) or "No indicators."
    return ""


# ------------------------------------------------------------------ runner
def _sse(obj: dict[str, Any]) -> str:
    return "data: " + orjson.dumps(obj).decode() + "\n\n"


def _parse_synth(text: str, fallback_summary: str) -> tuple[str, list[dict[str, Any]]]:
    raw = text.strip()
    raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw)
    try:
        data = orjson.loads(raw)
    except orjson.JSONDecodeError:
        m = re.search(r"\{.*\}", raw, re.S)
        if not m:
            return raw or fallback_summary, []
        try:
            data = orjson.loads(m.group(0))
        except orjson.JSONDecodeError:
            return raw or fallback_summary, []
    summary = str(data.get("summary") or fallback_summary)
    findings = []
    for f in data.get("findings", []) or []:
        if isinstance(f, dict):
            lvl = str(f.get("level", "medium")).lower()
            findings.append({"level": lvl if lvl in SEV_ORDER else "medium", "title": str(f.get("title", "")),
                             "body": str(f.get("body", "")), "evidence": str(f.get("evidence", ""))})
    steps = data.get("next_steps")
    if isinstance(steps, list) and steps:
        summary += "\n\nNext steps:\n" + "\n".join(f"- {s}" for s in steps)
    return summary, findings


async def analyze_stream(store: Store, scope: str, id: Optional[str], event_ids: Optional[list[str]], question: str = "") -> AsyncIterator[str]:
    settings = get_settings()
    n_agents = max(1, min(4, settings.ai.agents))
    agents = AGENT_ORDER[:n_agents]
    header, context = build_context(store, scope, id, event_ids)
    client = LLMClient.from_settings(settings.ai)
    offline = not client.configured
    queue: asyncio.Queue = asyncio.Queue()
    outputs: dict[str, str] = {}
    errors: list[str] = []

    yield _sse({"type": "status", "text": f"running {len(agents)} agent(s) via {'offline analysis engine' if offline else client.provider + ' / ' + client.model}"})

    async def run_agent(name: str) -> None:
        buf: list[str] = []
        try:
            if offline:
                text = _offline(name, store, context)
                for chunk in re.split(r"(?<=\n)", text):
                    buf.append(chunk)
                    await queue.put({"type": "agent", "agent": name, "text": chunk})
                    await asyncio.sleep(0)
            else:
                system, user = agent_prompt(name, context, question)
                async for chunk in client.stream(system, user):
                    buf.append(chunk)
                    await queue.put({"type": "agent", "agent": name, "text": chunk})
        except (AIError, Exception) as exc:  # noqa: BLE001
            errors.append(f"{name}: {exc}")
            await queue.put({"type": "agent", "agent": name, "text": f"\n[agent error: {exc}]"})
        finally:
            outputs[name] = "".join(buf)
            await queue.put({"type": "agent_done", "agent": name})

    tasks = [asyncio.create_task(run_agent(a)) for a in agents]
    pending = len(tasks)
    while pending:
        item = await queue.get()
        if item.get("type") == "agent_done":
            pending -= 1
        yield _sse(item)
    await asyncio.gather(*tasks, return_exceptions=True)

    if errors and len(errors) == len(agents):
        yield _sse({"type": "error", "message": "; ".join(errors)})
        return

    # synthesizer
    rep = build_report(store)
    fallback_findings = [f.model_dump() for f in rep.findings]
    if offline:
        summary = rep.summary
        if question:
            summary = f"Question: {question}\n\n" + summary
        yield _sse({"type": "agent", "agent": "synthesizer", "text": summary})
        yield _sse({"type": "done", "summary": summary, "findings": fallback_findings})
        return
    try:
        system, user = synth_prompt(outputs, header, question)
        buf: list[str] = []
        async for chunk in client.stream(system, user):
            buf.append(chunk)
            yield _sse({"type": "agent", "agent": "synthesizer", "text": chunk})
        summary, findings = _parse_synth("".join(buf), rep.summary)
        yield _sse({"type": "done", "summary": summary, "findings": findings or fallback_findings})
    except Exception as exc:  # noqa: BLE001
        yield _sse({"type": "done", "summary": "\n\n".join(f"## {k}\n{v}" for k, v in outputs.items()),
                    "findings": fallback_findings, "note": f"synthesizer failed: {exc}"})
