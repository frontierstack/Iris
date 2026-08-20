"""AI graph reviewer: reads the deterministic entity graph (graph.py) plus a sample of the events behind its
hottest nodes and PROPOSES additional links, aliases and an attack-path narrative.

It never mutates the graph. Everything the model returns is validated against the real GraphBuilder before it
is yielded (node ids must exist, relation must be in the vocabulary, no self-links, no re-proposing an edge the
extractor already drew, confidence clamped to [0, 1]); the analyst then accepts links one at a time through
POST /api/graph/links. `review_graph()` is an async generator of SSE-ready dicts — see docs/API_CONTRACT.md,
"AI graph review" — and never raises: any failure becomes one {"type": "error"} event.
"""
from __future__ import annotations

from typing import Any, AsyncIterator, Optional

import orjson

from ..config import get_settings
from ..graph import RELATIONS
from ..models import Event, GraphEdge, SEV_ORDER
from .client import AIError, LLMClient

NODE_LIMIT = 150          # nodes handed to the model (gb.select limit)
EDGE_LIMIT = 400          # edge lines in the prompt (select already sorts by severity, then count)
EVENT_SAMPLE = 40         # events around the highest-severity nodes
HOT_NODES = 15            # how many top nodes seed the event sample
MAX_LINKS = 40
MAX_ALIASES = 20
DISABLED_MESSAGE = "AI assistant is disabled — enable a provider in Settings"

# relations the prompt steers the model toward: the ones that explain how an attacker moved
_PIVOT_RELATIONS = ("auth_from", "connected_to", "ran", "wrote", "resolved", "used_key")

SYSTEM_PROMPT = (
    "You are a senior incident-response analyst reviewing an ENTITY GRAPH inside Iris, a log correlation workbench. "
    "The graph was extracted deterministically from log events: every node has an id of the form '<type>:<value>' and every "
    "edge a relation kind. Your job is to add what the extractor could not see and to narrate the attack path.\n\n"
    "RULES\n"
    "1. Only reference node ids that appear VERBATIM in the NODES list below. Never invent, rename or abbreviate an id.\n"
    "2. Do not re-propose an edge that is already in the EDGES list (same source, relation and target). Propose links the "
    "extractor MISSED: a pivot implied by timing (an IP that authenticated as a user, then the same user ran a process on "
    "another host), the same real-world thing seen under two names, a domain a host resolved just before it connected out.\n"
    "3. relation MUST be one of: " + ", ".join(RELATIONS) + ". Prefer relations that EXPLAIN a pivot: "
    + ", ".join(_PIVOT_RELATIONS) + ". Use co_occurred only when nothing more specific fits.\n"
    "4. An ALIAS means two nodes are the SAME real-world thing — a hostname and its IP address, a user and their email "
    "address, a short and a fully-qualified name. Do not alias two things that merely interact.\n"
    "5. Every link needs a short plain-English 'why' that cites the evidence (timestamps, event ids, log lines) and a "
    "confidence between 0 and 1. Be conservative — a wrong link misleads an analyst.\n"
    "6. The narrative is a concise attack-path story in Markdown (initial access → pivots → objective), citing node ids "
    "and times, and stating what is uncertain. If nothing looks malicious, say so.\n\n"
    "Return STRICT JSON only (no code fences) with exactly this shape:\n"
    '{"links":[{"source":"<nodeId>","target":"<nodeId>","relation":"<relation>","why":"…","confidence":0.0}],'
    ' "aliases":[{"a":"<nodeId>","b":"<nodeId>","reason":"…"}],'
    ' "narrative":"…"}'
)


# ------------------------------------------------------------------ context building
def _short_ts(ts: str) -> str:
    return (ts or "")[:19].replace("T", " ")


def _node_line(n: Any) -> str:
    return (f"- {n.id} | sev={n.sev} | events={n.count} | detections={n.detections} | "
            f"{_short_ts(n.first)} → {_short_ts(n.last)}")


def _edge_line(e: Any) -> str:
    oc = f", outcome={e.outcome}" if getattr(e, "outcome", None) else ""
    return f"- {e.source} -{e.relation}-> {e.target} (n={e.count}{oc}; {e.why})"


def _event_line(e: Event) -> str:
    det = ", ".join(d.id for d in e.detections)
    fields = {k: str(v)[:60] for k, v in list(e.fields.items())[:8] if v not in (None, "", "-")}
    tail = ""
    if fields:
        tail += " fields=" + orjson.dumps(fields).decode()
    if det:
        tail += f" detections=[{det}]"
    return (f"- {e.id} {e.ts} [{e.sev}] {e.source} host={e.host or '-'} user={e.user or '-'} :: "
            f"{e.msg[:220]}{tail}")


def _sample_events(gb: Any, nodes: list[Any], limit: int = EVENT_SAMPLE) -> list[Event]:
    """~40 events around the highest-severity nodes: gather the events of the hottest nodes, keep the most severe
    / detection-bearing ones, then present them chronologically."""
    hot = sorted(nodes, key=lambda n: (-SEV_ORDER.get(n.sev, 0), -n.detections, -n.count))[:HOT_NODES]
    idx: set[int] = set()
    for n in hot:
        agg = gb.nodes.get(n.id)
        if agg is not None:
            idx.update(agg.events[:60])
    events = [gb.events[i] for i in idx if 0 <= i < len(gb.events)]
    events.sort(key=lambda e: (-SEV_ORDER.get(e.sev, 0), -len(e.detections), e.ts))
    picked = events[:limit]
    picked.sort(key=lambda e: e.ts)
    return picked


def build_prompt(gb: Any, nodes: list[Any], edges: list[Any], events: list[Event], known_links: list[dict[str, Any]],
                 focus: Optional[str], question: str) -> str:
    lines: list[str] = []
    if focus:
        lines.append(f"FOCUS: the analyst is looking at node {focus} (2-hop neighbourhood shown).")
    if question:
        lines.append(f"ANALYST QUESTION: {question.strip()[:800]}")
    lines.append(f"NODES ({len(nodes)} shown of {len(gb.nodes)} in the graph) — id | max severity | events | detections | first → last:")
    lines.extend(_node_line(n) for n in nodes)
    lines.append("")
    lines.append(f"EDGES ({min(len(edges), EDGE_LIMIT)} shown of {len(edges)} among these nodes) — already known, do NOT re-propose:")
    lines.extend(_edge_line(e) for e in edges[:EDGE_LIMIT])
    if known_links:
        lines.append("")
        lines.append("ANALYST-ACCEPTED LINKS (also already known):")
        lines.extend(f"- {l.get('source')} -{l.get('relation')}-> {l.get('target')} ({l.get('why') or ''})" for l in known_links[:60])
    lines.append("")
    lines.append(f"SAMPLE EVENTS ({len(events)}, chronological, around the highest-severity nodes):")
    lines.extend(_event_line(e) for e in events)
    lines.append("")
    lines.append("Propose the missing links, aliases and the attack-path narrative as JSON.")
    return "\n".join(lines)


# ------------------------------------------------------------------ validation
def _clamp_conf(v: Any) -> Optional[float]:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    if f != f:  # NaN
        return None
    return max(0.0, min(1.0, f))


def validate_links(raw: Any, gb: Any, known_links: Optional[list[dict[str, Any]]] = None) -> list[GraphEdge]:
    """Keep only links whose ends are real nodes, whose relation is in the vocabulary, that are not self-links and
    that the extractor (or the analyst) has not already drawn — in either direction. Capped at MAX_LINKS."""
    out: list[GraphEdge] = []
    seen: set[tuple[str, str, str]] = set()
    persisted = {(str(l.get("source")), str(l.get("target")), str(l.get("relation"))) for l in (known_links or [])}
    if not isinstance(raw, list):
        return out
    for item in raw:
        if len(out) >= MAX_LINKS:
            break
        if not isinstance(item, dict):
            continue
        s, t, rel = str(item.get("source") or "").strip(), str(item.get("target") or "").strip(), str(item.get("relation") or "").strip()
        if not s or not t or s == t:
            continue
        if s not in gb.nodes or t not in gb.nodes:
            continue
        if rel not in RELATIONS:
            continue
        key = (s, t, rel)
        if key in gb.edges or (t, s, rel) in gb.edges:
            continue
        if key in persisted or (t, s, rel) in persisted:
            continue
        if key in seen or (t, s, rel) in seen:
            continue
        seen.add(key)
        out.append(GraphEdge(id=f"{s}|{rel}|{t}", source=s, target=t, relation=rel, count=0, first="", last="",  # type: ignore[arg-type]
                             sev="info", eventIds=[], why=str(item.get("why") or "").strip()[:600], ai=True,
                             confidence=_clamp_conf(item.get("confidence"))))
    return out


def validate_aliases(raw: Any, gb: Any) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[frozenset[str]] = set()
    if not isinstance(raw, list):
        return out
    for item in raw:
        if len(out) >= MAX_ALIASES:
            break
        if not isinstance(item, dict):
            continue
        a, b = str(item.get("a") or "").strip(), str(item.get("b") or "").strip()
        if not a or not b or a == b or a not in gb.nodes or b not in gb.nodes:
            continue
        key = frozenset((a, b))
        if key in seen:
            continue
        seen.add(key)
        out.append({"a": a, "b": b, "reason": str(item.get("reason") or "").strip()[:600]})
    return out


# ------------------------------------------------------------------ the generator
async def review_graph(store: Any, scope: str = "all", focus: Optional[str] = None,
                       question: str = "") -> AsyncIterator[dict[str, Any]]:
    """Async generator of SSE-ready dicts: thinking* → link* → alias* → narrative → done, or a single error."""
    try:
        settings = get_settings()
        client = LLMClient.from_settings(settings.ai)
        if not client.configured:
            yield {"type": "error", "message": DISABLED_MESSAGE}
            return

        gb = store.graph_v2(scope if scope in ("all", "case") else "all")
        focus = (focus or "").strip() or None
        if focus and focus not in gb.nodes:
            yield {"type": "thinking", "text": f"focus node {focus} is not in the graph — reviewing the top of the whole graph instead"}
            focus = None
        nodes, edges, _stats = gb.select(limit=NODE_LIMIT, focus=focus, hops=2 if focus else 1)
        if not nodes:
            yield {"type": "error", "message": "the graph is empty — ingest sources (or add events to the case set) first"}
            return
        yield {"type": "thinking", "text": f"reading {len(nodes)} nodes / {len(edges)} edges"
                                            + (f" around {focus}" if focus else "")
                                            + f" ({len(gb.nodes):,} nodes / {len(gb.edges):,} edges in the {scope} graph)"}
        events = _sample_events(gb, nodes)
        yield {"type": "thinking", "text": f"sampling {len(events)} events around the highest-severity nodes"}
        known_links = [l for l in (getattr(store, "graph_links", None) or []) if isinstance(l, dict)]
        user = build_prompt(gb, nodes, edges, events, known_links, focus, question or "")
        yield {"type": "thinking", "text": f"asking {client.model} for missing links, aliases and an attack-path narrative"}

        data = await client.complete_json(SYSTEM_PROMPT, user, max_tokens=2500, temperature=0.0)

        links = validate_links(data.get("links"), gb, known_links)
        aliases = validate_aliases(data.get("aliases"), gb)
        for edge in links:
            yield {"type": "link", "edge": edge.model_dump(), "confidence": edge.confidence}
        for al in aliases:
            yield {"type": "alias", **al}
        narrative = data.get("narrative")
        if not isinstance(narrative, str):
            narrative = orjson.dumps(narrative).decode() if narrative else ""
        yield {"type": "narrative", "text": narrative.strip()}
        yield {"type": "done", "links": len(links), "aliases": len(aliases)}
    except AIError as exc:
        yield {"type": "error", "message": str(exc)}
    except Exception as exc:  # noqa: BLE001 — never raise out of the stream
        yield {"type": "error", "message": f"graph review failed: {exc}"}
