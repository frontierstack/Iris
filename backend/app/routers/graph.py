"""Entity graph endpoints.

v2 (typed nodes + typed relations, graph.py) is the default shape of GET /api/graph. The old v1 payload
(bare-name entities with co-occurrence weights) stays reachable at GET /api/graph/{name} for callers that
still ask for one Entity by name.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional

import orjson
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from ..ai.graph_review import review_graph
from ..graph import DEFAULT_LIMIT, NODE_TYPES
from ..models import Entity, GraphEdge, GraphLink, GraphNode, GraphV2
from ..store import STORE

router = APIRouter(prefix="/graph", tags=["graph"])
UTC = timezone.utc


def _case_nodes(known: set[str]) -> list[GraphNode]:
    """Nodes the analyst or the agent AUTHORED, as opposed to the ones extraction found.

    The investigation graph has to be drawable on a workspace where extraction found nothing — which is
    every raw-first workspace, and was the reason `add_graph_link` could refuse every endpoint it was
    given ("not a node in the graph"). These are overlays with the same lifecycle as `graph_links`:
    persisted in case.json, merged per request, never part of the built structure and never counted as
    evidence — `count` is 0 and `why` says who concluded it.
    """
    out: list[GraphNode] = []
    for n in STORE.graph_nodes:
        nid = str(n.get("id") or "")
        if not nid or nid in known:
            continue      # extraction found it too; the real node wins, with its real counts
        kind = str(n.get("type") or "") or nid.partition(":")[0]
        if kind not in NODE_TYPES:
            continue
        value = str(n.get("value") or nid.partition(":")[2])
        out.append(GraphNode(id=nid, type=kind, value=value,  # type: ignore[arg-type]
                             label=str(n.get("label") or value), count=0,
                             first=str(n.get("createdAt") or ""), last=str(n.get("createdAt") or ""),
                             sev=str(n.get("sev") or "info"),  # type: ignore[arg-type]
                             inCase=False, ai=bool(n.get("ai")), manual=True,
                             why=str(n.get("why") or "")))
    return out


def _links_as_edges(gb, extra: Optional[set[str]] = None) -> list[GraphEdge]:
    """Persisted (accepted-AI / hand-drawn) links, rendered as edges — when both ends exist."""
    out: list[GraphEdge] = []
    known = extra or set()
    for l in STORE.graph_links:
        s, t = str(l.get("source") or ""), str(l.get("target") or "")
        if (s not in gb.nodes and s not in known) or (t not in gb.nodes and t not in known):
            continue
        rel = str(l.get("relation") or "co_occurred")
        out.append(GraphEdge(id=str(l.get("id") or f"{s}|{rel}|{t}"), source=s, target=t, relation=rel,  # type: ignore[arg-type]
                             count=0, first=str(l.get("createdAt") or ""), last=str(l.get("createdAt") or ""),
                             sev="info", why=str(l.get("why") or "analyst-added link"),
                             ai=bool(l.get("ai")), manual=not bool(l.get("ai")),
                             confidence=l.get("confidence")))
    return out


def _files_for(sources: str) -> Optional[set[str]]:
    """Source IDS from the UI -> the FILE NAMES the graph aggregates by, or None for "everything".

    The graph keys its per-node and per-edge provenance on `Event.file`, which is what the Sources page
    lists; the UI has ids. An id that no longer exists resolves to nothing, which correctly yields an
    empty view rather than silently widening it back to the whole pool.
    """
    ids = [s.strip() for s in (sources or "").split(",") if s.strip()]
    if not ids:
        return None
    with STORE.lock:
        return {STORE.sources[s].file for s in ids if s in STORE.sources}


@router.get("", response_model=GraphV2)
def graph(scope: str = Query("all", pattern="^(all|case)$"),
          types: str = "", relations: str = "", minCount: int = Query(1, ge=1),
          minDegree: int = Query(1, ge=1, le=100),
          focus: Optional[str] = None, hops: int = Query(1, ge=0, le=4),
          limit: int = Query(DEFAULT_LIMIT, ge=10, le=2000), q: str = "", sources: str = "") -> GraphV2:
    """The typed graph.

    `q` is a free-text filter over node values/labels (case-insensitive substring) — the graph's own
    query bar. Combine with `types`, `relations`, `minCount`, and `focus`+`hops` for a neighbourhood.

    `minCount` is RELATIONSHIP STRENGTH: drop every edge supported by fewer than that many events, and
    then every node left with no edge. It does NOT filter how many events mention an entity. Analyst-added
    and accepted-AI links (`graph_links`) carry no event count and are exempt — they are overlays.

    `minDegree` is the other question: how CONNECTED an entity is. It drops every node with fewer than
    that many links in the returned graph (and the edges that lose an endpoint). The two compose: an IP
    seen once, linked to one busy host, survives any `minCount` and no `minDegree` above 1.
    `stats.hiddenByDegree` says how many nodes it removed, so the screen can say so rather than just
    showing less.

    `sources` (comma-separated source ids) restricts the view to entities and relations actually seen in
    those log files — exact on both sides, never inferred from the endpoints. Omitted means the whole
    pool; the UI starts with nothing selected and asks, because a graph of every source at once is a
    hairball nobody reads.
    """
    # The graph is built ONCE per store version, in the background (store.graph_v2_ready). Every filter
    # here — limit, focus/hops, types, relations, q — slices that cached builder; nothing re-extracts
    # entities from events. A request that arrives before the build finishes returns immediately with an
    # empty graph and `stats.status.state == 'building'` instead of blocking for a minute and a half.
    gb = STORE.graph_v2_ready(scope)
    status = STORE.graph_status(scope)
    if gb is None:
        return GraphV2(nodes=[], edges=[], stats={"nodes": 0, "edges": 0, "truncated": False,
                                                  "totalNodes": 0, "totalEdges": 0, "byType": {},
                                                  "byRelation": {}, "status": status})
    tset = {t.strip() for t in types.split(",") if t.strip()} or None
    rset = {r.strip() for r in relations.split(",") if r.strip()} or None
    in_case = set(STORE.case_set.keys())
    # `q` goes INTO select, never applied to its result: the payload is already capped at `limit`, so
    # post-filtering it searched the top-N ranked nodes only and answered "nothing" for every entity
    # outside them (measured: q=claude -> 0 nodes on a graph holding 21,676).
    nodes, edges, stats = gb.select(types=tset, relations=rset, min_count=minCount, focus=focus, hops=hops,
                                    limit=limit, in_case=in_case, files=_files_for(sources), query=q,
                                    min_degree=minDegree)
    if q.strip():
        stats = {**stats, "query": q.strip()}
    # Authored nodes and links are OVERLAYS: exempt from minCount/minDegree (they carry no event count
    # to be strong or weak by) and added after the ranking, so an investigation the agent drew cannot be
    # ranked out of its own case's graph.
    authored = _case_nodes({n.id for n in nodes})
    if authored:
        nodes = nodes + authored
    edges = edges + _links_as_edges(gb, {n.id for n in authored})
    # Closing invariant, asserted by tests/test_graph_edges.py: the payload is a CLOSED graph — every edge
    # endpoint is one of the nodes returned above. A persisted graph_link whose ends survived `add_link`
    # but were later ranked out by `limit`/`types` is dropped here rather than drawn to a phantom node.
    node_ids = {n.id for n in nodes}
    seen: set[str] = set()
    edges = [e for e in edges
             if e.source in node_ids and e.target in node_ids and not (e.id in seen or seen.add(e.id))]
    stats = {**stats, "edges": len(edges), "status": status}
    return GraphV2(nodes=nodes, edges=edges, stats=stats)


@router.get("/node/{node_id:path}")
def node(node_id: str, scope: str = Query("all", pattern="^(all|case)$")) -> dict:
    gb = STORE.graph_v2(scope)
    d = gb.node_detail(node_id, set(STORE.case_set.keys()))
    if d is None:
        raise HTTPException(404, "node not found")
    return d


@router.get("/path")
def path(from_: str = Query(..., alias="from"), to: str = Query(...), maxHops: int = Query(4, ge=1, le=8),
         scope: str = Query("all", pattern="^(all|case)$")) -> dict:
    """Shortest chain between two entities — 'how does this IP reach that file?'"""
    gb = STORE.graph_v2(scope)
    nodes, edges = gb.shortest_path(from_, to, maxHops)
    return {"found": bool(nodes), "path": [n.model_dump() for n in nodes], "edges": [e.model_dump() for e in edges]}


class LinkBody(BaseModel):
    source: str
    target: str
    relation: str = "co_occurred"
    why: str = ""
    confidence: Optional[float] = None
    ai: bool = False


@router.post("/links", response_model=GraphEdge)
def add_link(body: LinkBody) -> GraphEdge:
    """Persist a link the analyst accepted from the AI reviewer, or drew by hand.

    An end that extraction never found is CREATED as an authored node on the case, exactly as
    `build_case_graph` does for the agent. This used to 404 with "both ends of a link must be nodes in
    the current graph", which on a raw-first workspace can be every node the analyst wants to draw —
    and it left the two paths inconsistent, the agent able to draw a picture the analyst could not.
    An authored node is a CONCLUSION, marked as one and drawn with the dashed ring; it is never counted
    as evidence.
    """
    if body.source == body.target:
        raise HTTPException(400, "a link needs two different nodes")
    gb = STORE.graph_v2("all")
    created: list[str] = []
    for nid in (body.source, body.target):
        kind = str(nid).partition(":")[0].strip().lower()
        value = str(nid).partition(":")[2].strip()
        if nid in gb.nodes:
            continue
        if not value or kind not in NODE_TYPES:
            raise HTTPException(400, f"{nid!r} is not a node in the graph and is not a valid node id "
                                     f"either — use <type>:<value>, one of: {', '.join(sorted(NODE_TYPES))}")
        created.append(nid)
    lid = f"{body.source}|{body.relation}|{body.target}"
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    with STORE.lock:
        if any(l.get("id") == lid for l in STORE.graph_links):
            raise HTTPException(409, "that link already exists")
        for nid in created:
            if any(str(n.get("id")) == nid for n in STORE.graph_nodes):
                continue
            kind, _, value = str(nid).partition(":")
            STORE.graph_nodes.append({"id": nid, "type": kind.lower(), "value": value, "label": value,
                                      "why": body.why.strip(), "ai": bool(body.ai), "createdAt": now})
        STORE.graph_links.append({"id": lid, "source": body.source, "target": body.target, "relation": body.relation,
                                  "why": body.why.strip(), "confidence": body.confidence, "ai": body.ai,
                                  "createdAt": now})
    STORE.save_meta()
    return next(e for e in _links_as_edges(gb, set(created)) if e.id == lid)


@router.delete("/links/{link_id:path}")
def delete_link(link_id: str) -> dict:
    with STORE.lock:
        before = len(STORE.graph_links)
        STORE.graph_links = [l for l in STORE.graph_links if l.get("id") != link_id]
        removed = before - len(STORE.graph_links)
    if not removed:
        raise HTTPException(404, "link not found")
    STORE.save_meta()
    return {"ok": True}


# ------------------------------------------------------------------ AI graph review (SSE)
class AiReviewBody(BaseModel):
    scope: Literal["all", "case"] = "all"
    focus: Optional[str] = None
    question: Optional[str] = None


@router.post("/ai-review")
async def ai_review(body: AiReviewBody) -> StreamingResponse:
    """Stream the AI reviewer's PROPOSED links / aliases / narrative over SSE. Nothing is persisted here —
    the analyst accepts individual links via POST /api/graph/links."""
    async def gen():
        async for item in review_graph(STORE, body.scope, body.focus, body.question or ""):
            yield "data: " + orjson.dumps(item).decode() + "\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"})


# ------------------------------------------------------------------ v1 compatibility
@router.get("/{name:path}", response_model=Entity)
def entity(name: str, scope: str = Query("all", pattern="^(all|case)$")) -> Entity:
    a = STORE.analysis(scope)
    ent = a["entity_map"].get(name)
    if ent is None:
        az = a.get("analyzer")
        if az is not None and name in az.entity_index:
            idx = az.entity_index[name]
            kind = az._kind(name, idx)
            first = min(idx, key=lambda i: az.ts[i])
            facts = [("Kind", kind), ("Events", f"{len(idx):,}")] + az._kind_facts(name, kind, idx)
            return Entity(name=name, kind=kind, first=az.events[first].ts, count=len(idx), facts=facts, links=[])
        raise HTTPException(404, "entity not found")
    return ent
