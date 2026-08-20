import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { memo, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type PointerEvent as ReactPointerEvent } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { ENTITY_TYPES, RELATIONS, type EntityType, type GraphEdge, type GraphNode, type GraphReviewEvent, type Relation } from '../api/types';
import { useAiPanel } from '../components/AiPanel';
import { ScopeToggle } from '../components/CaseSet';
import { DerivedPauseActions } from '../components/Enrichment';
import { Icon } from '../components/icons';
import { BuildingState, EmptyState, ErrorState, Loading } from '../components/ui';
import { qk, useCase, useGraph } from '../hooks/queries';
import { useDebounce } from '../hooks/useDebounce';
import { useScope } from '../hooks/useScope';
import { useToast } from '../hooks/useToast';
import { GraphSim } from '../utils/forceLayout';
import { GraphPainter, readPalette, type PaintEdge, type PaintNode, type PaintState } from '../utils/graphPaint';
import { cx, fmtInt, fmtRelative, fmtTs, sevVar } from '../utils/format';

const MIN_K = 0.15;
const MAX_K = 6;
/** How many nodes carry a permanent label. A label is what makes a node identifiable without hovering,
 *  so on a small graph (which is what a source filter produces) every node gets one; the cap only exists
 *  to stop 2,000 chips from turning the canvas into text soup. */
const GRAPH_SOURCES_KEY = 'iris.graph.sources';
const LABEL_TOP_N = 22;
const LABEL_ALL_BELOW = 70;
/** Default node cap. MUST match `graph.DEFAULT_LIMIT` in the backend (backend/app/graph.py). */
const DEFAULT_LIMIT = 50;

/* ── Visual vocabulary for typed nodes ─────────────────────────────────────────
   One short glyph and one hue per entity type, so a glance tells an IP from a user
   from a file. Colours are theme tokens where they exist; the rest are muted so
   severity (ring) still reads on top. */
const TYPE_META: Record<EntityType, { glyph: string; label: string; hue: string }> = {
  ip:       { glyph: 'IP', label: 'IP address',  hue: 'var(--accent)' },
  user:     { glyph: 'U',  label: 'account',     hue: '#c9a3ff' },
  host:     { glyph: 'H',  label: 'host',        hue: '#7fb2ff' },
  process:  { glyph: 'P',  label: 'process',     hue: '#ffb86b' },
  pid:      { glyph: '#',  label: 'process id',  hue: '#f0a56b' },
  file:     { glyph: 'F',  label: 'file',        hue: '#8fe3c8' },
  hash:     { glyph: '⌗',  label: 'hash',        hue: '#8fe3c8' },
  domain:   { glyph: 'D',  label: 'domain',      hue: '#f7d774' },
  url:      { glyph: 'L',  label: 'url',         hue: '#f7d774' },
  port:     { glyph: ':',  label: 'port',        hue: '#9aa8b5' },
  email:    { glyph: '@',  label: 'email',       hue: '#c9a3ff' },
  key:      { glyph: 'K',  label: 'credential',  hue: '#ff8fa3' },
  session:  { glyph: 'S',  label: 'session',     hue: '#9aa8b5' },
  pod:      { glyph: 'Po', label: 'pod',         hue: '#7fb2ff' },
  service:  { glyph: 'Sv', label: 'service',     hue: '#7fb2ff' },
  registry: { glyph: 'R',  label: 'registry',    hue: '#8fe3c8' },
  other:    { glyph: '•',  label: 'other',       hue: '#9aa8b5' },
};
const REL_LABEL: Record<Relation, string> = {
  auth_from: 'authenticated from', connected_to: 'connected to', ran: 'ran', spawned: 'spawned', wrote: 'wrote',
  read: 'read', deleted: 'deleted', resolved: 'resolved', requested: 'requested', used_key: 'used key',
  on_host: 'on host', session: 'has', co_occurred: 'seen with',
};

interface View { x: number; y: number; k: number }

/** Human-friendly node names: strip the type prefix, shorten hashes/paths, keep the tail of long values. */
function displayName(n: GraphNode): string {
  const v = n.label || n.value;
  if (n.type === 'hash') return `${v.slice(0, 8)}…${v.slice(-6)}`;
  if (n.type === 'file' && v.length > 34) {
    const parts = v.replace(/\\/g, '/').split('/');
    return parts.length > 2 ? `…/${parts.slice(-2).join('/')}` : v.slice(0, 32) + '…';
  }
  if (n.type === 'url' && v.length > 34) return v.replace(/^https?:\/\//, '').slice(0, 32) + '…';
  return v.length > 34 ? v.slice(0, 32) + '…' : v;
}


/* Off-screen, focusable list of the nodes the canvas draws — a <canvas> is opaque to Tab and to assistive
   tech. memo()'d and fed a value that only changes when the QUERY RESULT changes: a hover or a drag
   re-renders GraphScreen, and reconciling two thousand list items on every mouse move is exactly the kind
   of cost the canvas was supposed to remove. */
interface A11yItem { id: string; text: string }
const GraphA11yList = memo(function GraphA11yList({ nodes, onPick, onPeek, onLeave }: {
  nodes: A11yItem[]; onPick: (id: string) => void; onPeek: (id: string) => void; onLeave: () => void;
}) {
  return (
    <ul className="graph__a11y" aria-label="Entities in the graph">
      {nodes.map((n) => (
        <li key={n.id}>
          <button onClick={() => onPick(n.id)} onFocus={() => onPeek(n.id)} onBlur={onLeave}>{n.text}</button>
        </li>
      ))}
    </ul>
  );
});

/* ─────────────────────────────────────────────────────────────────────────── */

export function GraphScreen() {
  const [scope, setScope] = useScope();
  const [sp, setSp] = useSearchParams();
  const nav = useNavigate();
  const ai = useAiPanel();
  const toast = useToast();
  const qc = useQueryClient();
  const activeCase = useCase().data;
  const poolSources = useMemo(() => {
    const all = [...(activeCase?.sources ?? []), ...(activeCase?.librarySources ?? [])];
    return all.filter((x) => x.events > 0).sort((a, b) => b.events - a.events);
  }, [activeCase]);
  const nInCase = activeCase?.caseSet.length ?? 0;
  const noCase = !!activeCase?.pending;

  /* ── query state (URL-backed so a filtered graph is linkable) ── */
  const [q, setQ] = useState(sp.get('q') ?? '');
  const qDeb = useDebounce(q, 350);
  const [types, setTypes] = useState<EntityType[]>(() => (sp.get('types') ?? '').split(',').filter((t): t is EntityType => (ENTITY_TYPES as string[]).includes(t)));
  const [rels, setRels] = useState<Relation[]>(() => (sp.get('rel') ?? '').split(',').filter((r): r is Relation => (RELATIONS as string[]).includes(r)));
  const [minCount, setMinCount] = useState(() => Math.max(1, Number(sp.get('min') ?? 1) || 1));
  const [minDegree, setMinDegree] = useState(() => Math.max(1, Number(sp.get('deg') ?? 1) || 1));
  const [limit, setLimit] = useState(() => Math.max(10, Number(sp.get('limit') ?? DEFAULT_LIMIT) || DEFAULT_LIMIT));
  const focus = sp.get('focus');
  const [hops, setHops] = useState(() => Math.min(4, Math.max(1, Number(sp.get('hops') ?? 1) || 1)));
  // Which log files the graph is drawn from. NOTHING is selected by default: a graph of every source at
  // once is a hairball, and the first question about any entity is "in which log did this happen".
  // Empty = draw nothing and ask, which is also why the expensive request is skipped until you choose.
  // The URL wins when it names sources (a shared link must show what it says); otherwise the last
  // selection made on this browser is restored. Without that, every visit — and every refresh — came
  // back to "Choose the logs to graph", which read as the graph never populating.
  const [srcSel, setSrcSelState] = useState<string[]>(() => {
    const fromUrl = (sp.get('sources') ?? '').split(',').filter(Boolean);
    if (fromUrl.length) return fromUrl;
    try { return JSON.parse(localStorage.getItem(GRAPH_SOURCES_KEY) ?? '[]') as string[]; } catch { return []; }
  });
  const setSrcSel = useCallback((next: string[] | ((cur: string[]) => string[])) => {
    setSrcSelState((cur) => {
      const v = typeof next === 'function' ? next(cur) : next;
      try { localStorage.setItem(GRAPH_SOURCES_KEY, JSON.stringify(v)); } catch { /* private mode */ }
      return v;
    });
  }, []);
  const [srcOpen, setSrcOpen] = useState(false);
  // `co_occurred` ("seen with") is not a relationship — it is "these two turned up in the same event",
  // which is true of almost every pair in a busy log and produces most of the edges on the canvas. It is
  // hidden by default and one chip away, because a hairball is not a finding.
  const [showCoOccur, setShowCoOccur] = useState(sp.get('co') === '1');
  const selected = sp.get('entity');
  const setSelected = useCallback((id: string | null) => {
    const p = new URLSearchParams(sp);
    if (id) p.set('entity', id); else p.delete('entity');
    setSp(p, { replace: true });
  }, [sp, setSp]);
  const setFocus = useCallback((id: string | null) => {
    const p = new URLSearchParams(sp);
    if (id) p.set('focus', id); else p.delete('focus');
    setSp(p, { replace: true });
  }, [sp, setSp]);
  useEffect(() => {
    const p = new URLSearchParams(sp);
    if (qDeb) p.set('q', qDeb); else p.delete('q');
    if (types.length) p.set('types', types.join(',')); else p.delete('types');
    if (rels.length) p.set('rel', rels.join(',')); else p.delete('rel');
    if (minCount > 1) p.set('min', String(minCount)); else p.delete('min');
    if (minDegree > 1) p.set('deg', String(minDegree)); else p.delete('deg');
    if (limit !== DEFAULT_LIMIT) p.set('limit', String(limit)); else p.delete('limit');
    if (hops !== 1) p.set('hops', String(hops)); else p.delete('hops');
    if (srcSel.length) p.set('sources', srcSel.join(',')); else p.delete('sources');
    if (showCoOccur) p.set('co', '1'); else p.delete('co');
    if (p.toString() !== sp.toString()) setSp(p, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qDeb, types, rels, minCount, minDegree, limit, hops, srcSel, showCoOccur]);

  // With no explicit relation filter, ask for everything EXCEPT co-occurrence (unless it is toggled on).
  // The API takes an include-list, so "hide one" is expressed as "include the others".
  const relParam = useMemo<Relation[] | undefined>(() => {
    if (rels.length) return rels;
    return showCoOccur ? undefined : RELATIONS.filter((r) => r !== 'co_occurred');
  }, [rels, showCoOccur]);
  const g = useGraph({ scope, q: qDeb || undefined, types: types.length ? types : undefined, relations: relParam,
                       minCount, minDegree, limit, focus: focus ?? undefined, hops: focus ? hops : undefined,
                       sources: srcSel }, srcSel.length > 0);

  const nodesData = useMemo(() => g.data?.nodes ?? [], [g.data]);
  const edgesData = useMemo(() => g.data?.edges ?? [], [g.data]);
  const byId = useMemo(() => new Map(nodesData.map((n) => [n.id, n])), [nodesData]);
  /** display names, computed once per fetch instead of once per edge per render */
  const nameById = useMemo(() => new Map(nodesData.map((n) => [n.id, displayName(n)])), [nodesData]);
  const maxCount = useMemo(() => {
    let m = 1;
    for (const e of edgesData) if (e.count > m) m = e.count;
    return m;
  }, [edgesData]);

  /* ── canvas size ── */
  const canvasRef = useRef<HTMLDivElement>(null);
  const [W, setW] = useState(900);
  const [H, setH] = useState(640);
  useEffect(() => {
    const el = canvasRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect.width;
      const h = entries[0]?.contentRect.height;
      if (w) setW((cur) => (Math.abs(w - cur) > 4 ? Math.round(w) : cur));
      if (h) setH((cur) => (Math.abs(h - cur) > 4 ? Math.round(h) : cur));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  /* ── simulation ── */
  const simRef = useRef<GraphSim | null>(null);
  if (!simRef.current) simRef.current = new GraphSim();
  const sim = simRef.current;
  useEffect(() => () => sim.destroy(), [sim]);

  /* ── canvas painter ──
     One <canvas> replaces ~16 SVG elements per node plus one <path> per edge. Nothing about the graph is
     in the DOM any more, so a hover, a drag or an AI-review chunk cannot cause thousands of style
     recalculations. See utils/graphPaint.ts for the measured reason. */
  const glRef = useRef<HTMLCanvasElement>(null);
  const painterRef = useRef<GraphPainter | null>(null);
  if (!painterRef.current) painterRef.current = new GraphPainter(readPalette(document.documentElement));
  const painter = painterRef.current;
  const tooltipRef = useRef<HTMLDivElement>(null);
  const viewRef = useRef<View>({ x: 0, y: 0, k: 1 });
  const hoverRef = useRef<string | null>(null);
  const [hover, setHover] = useState<string | null>(null);
  const [pinAfterDrag, setPinAfterDrag] = useState(false);
  const pinRef = useRef(false);
  pinRef.current = pinAfterDrag;
  const [pinVersion, setPinVersion] = useState(0);   // drag/pin changes that only affect the pin dot
  const [running, setRunning] = useState(false);

  /* One draw per animation frame, no matter how many ticks / pointer moves / view changes ask for it. */
  const frameRef = useRef(0);
  const scheduleDraw = useCallback(() => {
    if (frameRef.current) return;
    frameRef.current = requestAnimationFrame(() => {
      frameRef.current = 0;
      painter.draw(sim.nodes, sim.links, viewRef.current);
      placeTooltipRef.current();
    });
  }, [painter, sim]);
  // The ref MUST be cleared, not just cancelled: `scheduleDraw` uses a non-zero `frameRef` to mean "a
  // frame is already pending", so a cancelled-but-remembered id wedges the renderer shut for good. React
  // 18 StrictMode runs this cleanup on the simulated remount, which is exactly how the canvas came up
  // blank while every other part of the screen worked.
  useEffect(() => () => { cancelAnimationFrame(frameRef.current); frameRef.current = 0; }, []);

  const applyView = useCallback(() => {
    const v = viewRef.current;
    const grid = gridRef.current;
    if (grid) {
      const size = 26 * v.k;
      grid.style.backgroundSize = `${size}px ${size}px`;
      grid.style.backgroundPosition = `${v.x}px ${v.y}px`;
    }
    scheduleDraw();
  }, [scheduleDraw]);

  const gridRef = useRef<HTMLDivElement>(null);
  const placeTooltipRef = useRef<() => void>(() => {});
  const placeTooltip = useCallback(() => {
    const tip = tooltipRef.current;
    if (!tip) return;
    const name = hoverRef.current;
    if (!name) { if (tip.style.opacity !== '0') tip.style.opacity = '0'; return; }  // nothing hovered: no work per tick
    const nd = sim.node(name);
    if (!nd || nd.x === undefined || nd.y === undefined) { tip.style.opacity = '0'; return; }
    const v = viewRef.current;
    const sx = nd.x * v.k + v.x;
    const sy = nd.y * v.k + v.y - nd.r * v.k - 10;
    tip.style.opacity = '1';
    tip.style.transform = `translate(${Math.round(sx)}px, ${Math.round(sy)}px) translate(-50%, -100%)`;
  }, [sim]);

  placeTooltipRef.current = placeTooltip;

  useEffect(() => sim.onTick(scheduleDraw), [sim, scheduleDraw]);
  useEffect(() => {
    const off = () => setRunning(false);
    sim.sim.on('end.ui', off);
    const id = window.setInterval(() => setRunning(sim.sim.alpha() > sim.sim.alphaMin()), 500);
    setRunning(true);
    return () => { sim.sim.on('end.ui', null); window.clearInterval(id); };
  }, [sim]);
  useEffect(() => { sim.setSize(W, H); }, [sim, W, H]);
  /* The simulation is fed DURING render, not from an effect.
     It used to be a useEffect, which meant that for at least one painted frame the JSX below mapped the
     PREVIOUS `sim.links` while `byId` already held the new nodes: nodes missing from the new data returned
     null and vanished, but their edges were still drawn — arrows hanging off nothing. Passive effects are
     scheduled, not synchronous, so on a big graph that desync lasted several frames and looked random.
     Deriving the layout in a memo keyed on the query data makes the two always agree in the same render. */
  const dataVersion = useRef(0);
  const layoutVersion = useMemo(() => {
    if (!g.data) return dataVersion.current;
    // edge weight for the layout: log-scaled event count so a 1,000-event edge doesn't crush the layout
    sim.setData(nodesData.map((n) => ({ id: n.id, count: n.count })),
                edgesData.map((e) => ({ id: e.id, source: e.source, target: e.target, weight: 1 + Math.log10(e.count + 1) })));
    return ++dataVersion.current;
  }, [sim, g.data, nodesData, edgesData]);

  /* ── what the painter draws ──
     Static per fetch (colours, glyphs, widths), so a hover or a drag never rebuilds any of it. */
  const paintNodes = useMemo<PaintNode[]>(() => nodesData.map((n) => {
    const meta = TYPE_META[n.type] ?? TYPE_META.other;
    return {
      id: n.id, hue: meta.hue, glyph: meta.glyph, name: nameById.get(n.id) ?? n.value,
      kind: `${meta.label}${n.detections > 0 ? ` · ${n.detections} detection${n.detections === 1 ? '' : 's'}` : ''}`,
      sev: n.sev, detections: n.detections, inCase: !!n.inCase,
    };
  }), [nodesData, nameById]);
  const paintEdges = useMemo<PaintEdge[]>(() => edgesData.map((e) => {
    const t = Math.log10(e.count + 1) / Math.log10(maxCount + 1);
    return {
      id: e.id, width: 0.9 + t * 2.6, opacity: 0.4 + t * 0.55,
      arrow: e.relation !== 'co_occurred' && e.relation !== 'session',
      bad: e.outcome === 'failure' || e.outcome === 'denied',
      ai: !!e.ai || !!e.manual,
    };
  }), [edgesData, maxCount]);

  const a11yNodes = useMemo<A11yItem[]>(() => nodesData.map((n) => ({
    id: n.id, text: `${TYPE_META[n.type].label} ${n.value}, ${fmtInt(n.count)} events`,
  })), [nodesData]);
  const pickNode = useCallback((id: string) => { setSelected(id); centerOnRef.current(id); }, [setSelected]);
  const peekNode = useCallback((id: string) => { hoverRef.current = id; setHover(id); }, []);

  useLayoutEffect(() => { painter.attach(glRef.current); }, [painter]);
  useLayoutEffect(() => { painter.setSize(W, H, window.devicePixelRatio || 1); applyView(); }, [painter, W, H, applyView]);
  useLayoutEffect(() => {
    painter.setData(paintNodes, paintEdges);
    applyView();
  }, [painter, paintNodes, paintEdges, layoutVersion, applyView]);
  /* Themes are CSS variable sets on :root[data-theme=…]; the canvas has to resolve them itself. */
  useEffect(() => {
    const reread = () => { painter.setPalette(readPalette(document.documentElement)); scheduleDraw(); };
    reread();
    const obs = new MutationObserver(reread);
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    return () => obs.disconnect();
  }, [painter, scheduleDraw]);

  /* ── labels / neighbours ── */
  const degree = useMemo(() => {
    const d = new Map<string, number>();
    for (const e of edgesData) { d.set(e.source, (d.get(e.source) ?? 0) + 1); d.set(e.target, (d.get(e.target) ?? 0) + 1); }
    return d;
  }, [edgesData]);
  const labelled = useMemo(() => {
    const ranked = [...nodesData].sort((a, b) => (b.detections - a.detections) || ((degree.get(b.id) ?? 0) - (degree.get(a.id) ?? 0)) || (b.count - a.count));
    const n = nodesData.length <= LABEL_ALL_BELOW ? nodesData.length : LABEL_TOP_N;
    return new Set(ranked.slice(0, n).map((x) => x.id));
  }, [nodesData, degree]);
  const neighbors = useMemo(() => {
    const s = new Set<string>();
    if (!selected) return s;
    for (const e of edgesData) { if (e.source === selected) s.add(e.target); if (e.target === selected) s.add(e.source); }
    return s;
  }, [edgesData, selected]);

  /* ── view: pan / zoom / fly (unchanged from v1) ── */
  const flyRaf = useRef(0);
  const flyTo = useCallback((target: View, ms = 420) => {
    cancelAnimationFrame(flyRaf.current);
    const from = { ...viewRef.current };
    const t0 = performance.now();
    const step = (t: number) => {
      const p = Math.min(1, (t - t0) / ms);
      const e = 1 - Math.pow(1 - p, 3);
      viewRef.current = { x: from.x + (target.x - from.x) * e, y: from.y + (target.y - from.y) * e, k: from.k + (target.k - from.k) * e };
      applyView(); placeTooltip();
      if (p < 1) flyRaf.current = requestAnimationFrame(step);
    };
    flyRaf.current = requestAnimationFrame(step);
  }, [applyView, placeTooltip]);
  useEffect(() => () => cancelAnimationFrame(flyRaf.current), []);
  const zoomAt = useCallback((factor: number, sx: number, sy: number, animate = false) => {
    const v = viewRef.current;
    const k = Math.max(MIN_K, Math.min(MAX_K, v.k * factor));
    const x = sx - ((sx - v.x) * k) / v.k;
    const y = sy - ((sy - v.y) * k) / v.k;
    if (animate) flyTo({ x, y, k }, 180); else { viewRef.current = { x, y, k }; applyView(); placeTooltip(); }
  }, [applyView, flyTo, placeTooltip]);
  const centerOnRef = useRef<(id: string) => void>(() => {});
  const centerOn = useCallback((id: string) => {
    const nd = sim.node(id);
    if (!nd || nd.x === undefined || nd.y === undefined) return;
    const k = Math.max(viewRef.current.k, 1.15);
    flyTo({ k, x: W / 2 - nd.x * k, y: H / 2 - nd.y * k });
  }, [sim, flyTo, W, H]);
  centerOnRef.current = centerOn;
  const fitView = useCallback(() => {
    const b = sim.bounds();
    if (!b) { flyTo({ x: 0, y: 0, k: 1 }); return; }
    const pad = 48;
    const bw = Math.max(1, b.maxX - b.minX);
    const bh = Math.max(1, b.maxY - b.minY);
    const k = Math.max(MIN_K, Math.min(MAX_K, Math.min((W - pad * 2) / bw, (H - pad * 2) / bh)));
    flyTo({ k, x: (W - bw * k) / 2 - b.minX * k, y: (H - bh * k) / 2 - b.minY * k });
  }, [sim, flyTo, W, H]);
  /* The first nodes to arrive are FITTED into view — on a first load, and when a build that was
     running while the analyst watched finally lands. Nothing did this before: the canvas kept whatever
     pan/zoom happened to be there, so a graph that arrived after a long build could be laid out
     outside the visible area and the screen stayed blank until someone pressed 0, hit Fit, or reloaded
     the page. Only on the 0 -> N transition, never on a filter tweak: re-fitting under someone who has
     panned to a corner of their own graph is its own bug. */
  const hadNodes = useRef(false);
  useEffect(() => {
    if (!nodesData.length) { hadNodes.current = false; return; }
    if (hadNodes.current) return;
    hadNodes.current = true;
    // a beat, so the simulation has moved the nodes off their spawn points before the bounds are read
    const id = window.setTimeout(() => fitView(), 400);
    return () => window.clearTimeout(id);
  }, [nodesData, fitView]);

  const panBy = useCallback((dx: number, dy: number) => { const v = viewRef.current; flyTo({ x: v.x + dx, y: v.y + dy, k: v.k }, 120); }, [flyTo]);
  const onCanvasKeyDown = (e: ReactKeyboardEvent) => {
    if ((e.target as Element).closest('.node, input, button')) return;
    const step = e.shiftKey ? 160 : 60;
    switch (e.key) {
      case 'ArrowLeft': panBy(step, 0); break;
      case 'ArrowRight': panBy(-step, 0); break;
      case 'ArrowUp': panBy(0, step); break;
      case 'ArrowDown': panBy(0, -step); break;
      case '+': case '=': zoomAt(1.2, W / 2, H / 2, true); break;
      case '-': case '_': zoomAt(1 / 1.2, W / 2, H / 2, true); break;
      case '0': fitView(); break;
      case 'Escape': setSelected(null); break;
      default: return;
    }
    e.preventDefault();
  };
  useEffect(() => {
    const el = canvasRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const rect = el.getBoundingClientRect();
      zoomAt(e.deltaY < 0 ? 1.12 : 1 / 1.12, e.clientX - rect.left, e.clientY - rect.top);
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  }, [zoomAt]);

  /* ── pointer: pan canvas / drag nodes (unchanged from v1) ── */
  const [dragging, setDragging] = useState(false);
  const panRef = useRef<{ id: number; sx: number; sy: number; ox: number; oy: number; moved: boolean } | null>(null);
  const nodeDragRef = useRef<{ id: number; name: string; sx: number; sy: number; moved: boolean } | null>(null);
  const toWorld = (clientX: number, clientY: number) => {
    const rect = canvasRef.current!.getBoundingClientRect();
    const v = viewRef.current;
    return { x: (clientX - rect.left - v.x) / v.k, y: (clientY - rect.top - v.y) / v.k };
  };
  /** Canvas hit test — the replacement for "the pointer event landed on this node's <g>". */
  const hitAt = (clientX: number, clientY: number): string | null => {
    const w = toWorld(clientX, clientY);
    return painter.hitTest(sim.nodes, w.x, w.y);
  };
  const onCanvasPointerDown = (e: ReactPointerEvent) => {
    if (e.button !== 0) return;
    if ((e.target as Element).closest('.graph__tools, .graph__side-tools, .graph__querybar')) return;
    const hit = hitAt(e.clientX, e.clientY);
    if (hit) { onNodePointerDown(e, hit); return; }
    const v = viewRef.current;
    panRef.current = { id: e.pointerId, sx: e.clientX, sy: e.clientY, ox: v.x, oy: v.y, moved: false };
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
    setDragging(true);
  };
  const onCanvasPointerMove = (e: ReactPointerEvent) => {
    const p = panRef.current;
    if (p && p.id === e.pointerId) {
      const dx = e.clientX - p.sx; const dy = e.clientY - p.sy;
      if (Math.abs(dx) + Math.abs(dy) > 3) p.moved = true;
      viewRef.current = { ...viewRef.current, x: p.ox + dx, y: p.oy + dy };
      applyView(); placeTooltip();
      return;
    }
    const d = nodeDragRef.current;
    if (d && d.id === e.pointerId) {
      if (Math.abs(e.clientX - d.sx) + Math.abs(e.clientY - d.sy) > 3) d.moved = true;
      const w = toWorld(e.clientX, e.clientY);
      sim.drag(d.name, w.x, w.y);
      return;
    }
    // hover: one O(nodes) hit test per pointer move, and React state only when the node under the
    // cursor actually changes — the canvas has no pointerenter/leave per node to lean on.
    const id = hitAt(e.clientX, e.clientY);
    if (id !== hoverRef.current) {
      hoverRef.current = id;
      setHover(id);
      scheduleDraw();
    }
    placeTooltip();
  };
  const onCanvasPointerUp = (e: ReactPointerEvent) => {
    const p = panRef.current;
    if (p && p.id === e.pointerId) { panRef.current = null; setDragging(false); if (!p.moved) setSelected(null); return; }
    const d = nodeDragRef.current;
    if (d && d.id === e.pointerId) {
      nodeDragRef.current = null;
      sim.dragEnd(d.name, pinRef.current);
      setDragging(false);
      if (!d.moved) setSelected(d.name); else setPinVersion((v) => v + 1);
    }
  };
  const onNodePointerDown = useCallback((e: ReactPointerEvent, name: string) => {
    if (e.button !== 0) return;
    nodeDragRef.current = { id: e.pointerId, name, sx: e.clientX, sy: e.clientY, moved: false };
    canvasRef.current?.setPointerCapture(e.pointerId);
    sim.dragStart(name);
    setDragging(true);
  }, [sim]);
  const enterHover = useCallback((name: string) => { hoverRef.current = name; setHover(name); placeTooltip(); }, [placeTooltip]);
  const leaveHover = useCallback(() => { hoverRef.current = null; setHover(null); placeTooltip(); }, [placeTooltip]);

  /* ── selected node detail (server-side: full neighbours + timeline) ── */
  const detail = useQuery({ queryKey: ['graph-node', selected, scope], queryFn: () => api.graphNode(selected!, scope), enabled: !!selected });
  const sel = selected ? byId.get(selected) ?? null : null;
  const hov = hover ? byId.get(hover) ?? null : null;

  /* ── path finder ── */
  const [pathFrom, setPathFrom] = useState<string | null>(null);
  const pathQ = useQuery({
    queryKey: ['graph-path', pathFrom, selected],
    queryFn: () => api.graphPath(pathFrom!, selected!),
    enabled: !!pathFrom && !!selected && pathFrom !== selected,
  });
  const pathIds = useMemo(() => new Set(pathQ.data?.found ? pathQ.data.path.map((n) => n.id) : []), [pathQ.data]);
  const pathEdgeIds = useMemo(() => new Set(pathQ.data?.found ? pathQ.data.edges.map((e) => e.id) : []), [pathQ.data]);

  /* ── AI review ── */
  const [reviewing, setReviewing] = useState(false);
  const [thinking, setThinking] = useState<string[]>([]);
  const [proposed, setProposed] = useState<GraphEdge[]>([]);
  const [aliases, setAliases] = useState<{ a: string; b: string; reason: string }[]>([]);
  const [narrative, setNarrative] = useState('');
  const [reviewErr, setReviewErr] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const runReview = () => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setReviewing(true); setThinking([]); setProposed([]); setAliases([]); setNarrative(''); setReviewErr(null);
    void api.graphAiReview({ scope, focus: focus ?? selected ?? undefined }, (ev: GraphReviewEvent) => {
      if (ev.type === 'thinking') setThinking((t) => [...t.slice(-6), ev.text]);
      else if (ev.type === 'link') setProposed((p) => (p.some((x) => x.id === ev.edge.id) ? p : [...p, ev.edge]));
      else if (ev.type === 'alias') setAliases((a) => [...a, { a: ev.a, b: ev.b, reason: ev.reason }]);
      else if (ev.type === 'narrative') setNarrative((n) => n + ev.text);
      else if (ev.type === 'error') setReviewErr(ev.message);
      else if (ev.type === 'done') setReviewing(false);
    }, ac.signal).catch((e) => setReviewErr(e instanceof Error ? e.message : String(e))).finally(() => setReviewing(false));
  };
  useEffect(() => () => abortRef.current?.abort(), []);
  const accept = useMutation({
    mutationFn: (e: GraphEdge) => api.addGraphLink({ source: e.source, target: e.target, relation: e.relation, why: e.why, confidence: e.confidence ?? undefined, ai: true }),
    onSuccess: (_r, e) => {
      setProposed((p) => p.filter((x) => x.id !== e.id));
      toast.success('Link accepted', `${displayName(byId.get(e.source) ?? ({ value: e.source, type: 'other' } as GraphNode))} → ${displayName(byId.get(e.target) ?? ({ value: e.target, type: 'other' } as GraphNode))}`);
      void qc.invalidateQueries({ queryKey: qk.graph });
    },
    onError: (err) => toast.error('Could not save the link', err),
  });
  const removeLink = useMutation({
    mutationFn: (id: string) => api.deleteGraphLink(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: qk.graph }),
    onError: (err) => toast.error('Could not remove the link', err),
  });
  /** Node ids drawn with the dashed ring: the ends of a PROPOSED link, and any node the analyst or the
   *  agent AUTHORED (`manual`) rather than extraction finding it. Both are conclusions rather than
   *  readings, which is exactly what that ring means; precomputed so the painter takes a set, not a scan. */
  const proposedNodeIds = useMemo(() => {
    const s = new Set<string>();
    for (const e of proposed) { s.add(e.source); s.add(e.target); }
    for (const n of nodesData) if (n.manual) s.add(n.id);
    return s;
  }, [proposed, nodesData]);
  const proposedForNode = useMemo(() => proposed.filter((e) => selected && (e.source === selected || e.target === selected)), [proposed, selected]);

  /* Interaction state for the painter. Rebuilt only when one of these sets changes — a simulation tick
     never touches it, and the painter reads it straight off the object on the next frame. */
  useLayoutEffect(() => {
    painter.isPinned = (id: string) => sim.isPinned(id);
    const st: PaintState = {
      selected, hover, neighbours: neighbors, pathNodes: pathIds, pathEdges: pathEdgeIds,
      proposed: proposedNodeIds, labelled,
    };
    painter.setState(st);
    scheduleDraw();
  }, [painter, sim, selected, hover, neighbors, pathIds, pathEdgeIds, proposedNodeIds, labelled, pinVersion, scheduleDraw]);

  /* ── filter helpers ── */
  const toggleType = (t: EntityType) => setTypes((cur) => (cur.includes(t) ? cur.filter((x) => x !== t) : [...cur, t]));
  const toggleRel = (r: Relation) => setRels((cur) => (cur.includes(r) ? cur.filter((x) => x !== r) : [...cur, r]));
  const clearFilters = () => { setQ(''); setTypes([]); setRels([]); setMinCount(1); setMinDegree(1); setFocus(null); };
  const activeFilters = (q ? 1 : 0) + types.length + rels.length + (minCount > 1 ? 1 : 0) + (minDegree > 1 ? 1 : 0) + (focus ? 1 : 0);
  // drop remembered ids that no longer exist in the pool (a deleted source), or the filter silently
  // narrows to nothing forever
  useEffect(() => {
    if (!poolSources.length || !srcSel.length) return;
    const live = new Set(poolSources.map((x) => x.id));
    if (srcSel.some((id) => !live.has(id))) setSrcSel(srcSel.filter((id) => live.has(id)));
  }, [poolSources, srcSel, setSrcSel]);
  const selectedNames = useMemo(() => {
    if (!srcSel.length) return 'the workspace';
    const names = poolSources.filter((x) => srcSel.includes(x.id)).map((x) => x.file);
    if (!names.length) return 'the selected sources';
    return names.length <= 2 ? names.join(' and ') : `${names[0]} and ${names.length - 1} more`;
  }, [srcSel, poolSources]);
  const stats = g.data?.stats;
  const buildingGraph = stats?.status?.state === 'building';

  /* ── render ──
     Nothing about the graph itself is in this tree any more: the <canvas> is painted imperatively by
     GraphPainter, so a re-render here costs the chrome around it and nothing else. */

  return (
    <div className="page graph">
      {/* ── query / filter bar ── */}
      <div className="graph__querybar">
        <div className="graph__q">
          <Icon.Search />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter the graph — an IP, a user, a file, a hash… (matches node values; neighbours stay visible)"
            aria-label="Filter graph nodes" spellCheck={false} />
          {q && <button className="graph__q-clear" onClick={() => setQ('')} aria-label="Clear">×</button>}
        </div>
        {/* Which logs the graph is drawn from. Nothing is selected until the analyst says so. */}
        <div className="graph__srcpick">
          <button className={cx('btn btn--sm', srcSel.length ? 'btn--accent' : '', srcOpen && 'on')}
            onClick={() => setSrcOpen((v) => !v)} aria-expanded={srcOpen}
            title="Choose which log files this graph is built from">
            <Icon.Sources />
            {srcSel.length ? `${srcSel.length} source${srcSel.length === 1 ? '' : 's'}` : 'Choose sources'}
            <Icon.Chevron className="srccase__caret" />
          </button>
          {srcOpen && (
            <>
              <div className="srccase__scrim" onClick={() => setSrcOpen(false)} aria-hidden />
              <div className="graph__srcmenu" role="menu">
                {/* The case set is the other thing worth graphing: the events the analyst chose. It is a
                    SCOPE server-side, not a file, so picking it clears the file selection rather than
                    mixing two different notions of "what is in this graph". */}
                <div className="graph__srccase">
                  <button className={cx('graph__srcrow', scope === 'case' && 'on')}
                    disabled={noCase || nInCase === 0}
                    title={noCase ? 'No active case yet'
                      : nInCase === 0 ? 'Nothing is on the case timeline yet — add events from Search'
                      : 'Graph only the events curated into the active case'}
                    onClick={() => { setScope('case'); setSrcSel(poolSources.map((x) => x.id)); setSrcOpen(false); }}>
                    <Icon.Cases />
                    <span className="ellipsis">Case set — {activeCase?.name ?? 'active case'}</span>
                    <span className="cell-mono cell-dim">{fmtInt(nInCase)}</span>
                  </button>
                  {scope === 'case' && (
                    <button className="btn btn--sm btn--ghost" onClick={() => setScope('all')}>back to the whole pool</button>
                  )}
                </div>
                <div className="graph__srcmenu-head">
                  <span className="eyebrow">Sources in the graph</span>
                  <span className="graph__srcmenu-acts">
                    <button className="btn btn--sm btn--ghost" onClick={() => setSrcSel(poolSources.map((x) => x.id))}>all</button>
                    <button className="btn btn--sm btn--ghost" onClick={() => setSrcSel([])}>none</button>
                  </span>
                </div>
                <div className="graph__srclist">
                  {poolSources.length === 0 && <div className="muted" style={{ padding: '6px 8px' }}>Nothing ingested yet.</div>}
                  {poolSources.map((src) => {
                    const on = srcSel.includes(src.id);
                    return (
                      <label key={src.id} className={cx('graph__srcrow', on && 'on')}>
                        <input type="checkbox" checked={on}
                          onChange={() => setSrcSel((cur) => (on ? cur.filter((x) => x !== src.id) : [...cur, src.id]))} />
                        <span className="ellipsis" title={src.file}>{src.file}</span>
                        <span className="cell-mono cell-dim">{fmtInt(src.events)}</span>
                      </label>
                    );
                  })}
                </div>
              </div>
            </>
          )}
        </div>
        <ScopeToggle scope={scope} onChange={setScope} count={nInCase} noCase={noCase} />
        <span className="graph__count">
          {g.isFetching && !g.data ? <span className="spinner" style={{ width: 10, height: 10, display: 'inline-block' }} /> : null}
          {stats ? <>{fmtInt(stats.nodes)} of {fmtInt(stats.totalNodes ?? stats.nodes)} nodes · {fmtInt(stats.edges)} links{stats.truncated ? ' · capped' : ''}</> : ''}
        </span>
        {activeFilters > 0 && <button className="btn btn--sm btn--ghost" onClick={clearFilters}>clear {activeFilters} filter{activeFilters === 1 ? '' : 's'}</button>}
        <button className={cx('btn btn--sm', reviewing && 'btn--accent')} onClick={runReview} disabled={reviewing || !g.data?.nodes.length}
          title="Ask the AI to review the logs and propose links the extractor could not see, plus an attack-path narrative">
          {reviewing ? <span className="btn__spinner" /> : <Icon.Sparkle />}{reviewing ? 'Reviewing…' : 'AI review'}
        </button>
      </div>
      <div className="graph__filters">
        <span className="chip-row__label">Types</span>
        {ENTITY_TYPES.filter((t) => (stats?.byType?.[t] ?? 0) > 0 || types.includes(t)).map((t) => (
          <button key={t} className={cx('chip chip--type', types.includes(t) && 'on')} onClick={() => toggleType(t)} aria-pressed={types.includes(t)}
            style={{ ['--type-hue' as string]: TYPE_META[t].hue }}>
            <i className="chip__swatch" />{TYPE_META[t].label}<span className="chip__count">{stats?.byType?.[t] ?? 0}</span>
          </button>
        ))}
        <span className="graph__filters-sep" />
        <span className="chip-row__label">Relations</span>
        {RELATIONS.filter((r) => (stats?.byRelation?.[r] ?? 0) > 0 || rels.includes(r)).map((r) => (
          <button key={r} className={cx('chip', rels.includes(r) && 'on')} onClick={() => toggleRel(r)} aria-pressed={rels.includes(r)}>
            {REL_LABEL[r]}<span className="chip__count">{stats?.byRelation?.[r] ?? 0}</span>
          </button>
        ))}
        <button className={cx('chip', showCoOccur && 'on')} onClick={() => setShowCoOccur((v) => !v)}
          aria-pressed={showCoOccur}
          title="'Seen with' means two entities appeared in the same event. It is true of nearly every pair in a busy log, so it is hidden by default.">
          seen with{stats?.byRelation?.co_occurred ? <span className="chip__count">{fmtInt(stats.byRelation.co_occurred)}</span> : null}
        </button>
        <span className="graph__filters-sep" />
        <label className="graph__num" title="Relationship strength. Hides every link supported by fewer than this many events, and any node left with no links. It does not filter how many events mention an entity.">
          min link events <input type="number" min={1} value={minCount} onChange={(e) => setMinCount(Math.max(1, Number(e.target.value) || 1))} aria-describedby="graph-mincount-help" />
        </label>
        <span id="graph-mincount-help" className="graph__hint">links seen ≥ N times</span>
        <label className="graph__num" title="How CONNECTED an entity is. Hides every node with fewer than this many links in the graph being shown — the lone leaves hanging off a busy host. A different question from min link events: an IP seen once, linked to one busy host, survives any link-event threshold but not this one.">
          min connections <input type="number" min={1} max={100} value={minDegree} onChange={(e) => setMinDegree(Math.max(1, Math.min(100, Number(e.target.value) || 1)))} aria-describedby="graph-mindeg-help" />
        </label>
        <span id="graph-mindeg-help" className="graph__hint">
          nodes with ≥ N links{minDegree > 1 && stats?.hiddenByDegree ? ` · ${fmtInt(stats.hiddenByDegree)} hidden` : ''}
        </span>
        <label className="graph__num" title="Caps how many nodes are drawn, ranked by detections, then links, then events.">max nodes <input type="number" min={10} max={2000} step={50} value={limit} onChange={(e) => setLimit(Math.min(2000, Math.max(10, Number(e.target.value) || DEFAULT_LIMIT)))} /></label>
        {focus && (
          <span className="graph__focus">
            focused on <b>{displayName(byId.get(focus) ?? ({ value: focus, type: 'other' } as GraphNode))}</b> ·
            <label className="graph__num" style={{ marginLeft: 6 }}>hops <input type="number" min={1} max={4} value={hops} onChange={(e) => setHops(Math.min(4, Math.max(1, Number(e.target.value) || 1)))} /></label>
            <button className="btn btn--sm btn--ghost" onClick={() => setFocus(null)}>whole graph</button>
          </span>
        )}
      </div>

      {/* The graph is built from what enrichment extracted. A source that has not been interpreted
          contributes nothing to it, and an entity that is missing for that reason is indistinguishable
          from an entity that is not in the evidence — so say which it is, above the canvas. */}

      {srcSel.length === 0 ? (
        <div className="graph__pick">
          <Icon.Graph />
          <div>
            <div className="graph__pick-title">Choose the logs to graph</div>
            <div className="graph__pick-body">
              An entity graph over every source at once is a hairball. Pick the files this investigation is
              about — the graph is then exactly the entities and relations those logs contain, and you can
              add or drop a source at any time.
            </div>
            <div className="graph__pick-acts">
              <button className="btn btn--accent btn--sm" onClick={() => setSrcOpen(true)}><Icon.Sources />Choose sources</button>
              {poolSources.length > 0 && poolSources.length <= 12 && (
                <button className="btn btn--sm" onClick={() => setSrcSel(poolSources.map((x) => x.id))}>
                  Use all {poolSources.length}
                </button>
              )}
            </div>
          </div>
        </div>
      ) : (
      <div className="graph__body">
      <div
        ref={canvasRef}
        className={cx('graph__canvas', dragging && 'dragging')}
        onPointerDown={onCanvasPointerDown} onPointerMove={onCanvasPointerMove} onPointerUp={onCanvasPointerUp} onPointerCancel={onCanvasPointerUp}
        onKeyDown={onCanvasKeyDown}
        onDoubleClick={(e) => { const id = hitAt(e.clientX, e.clientY); if (id) setFocus(id); else fitView(); }}
        role="application"
        aria-label="Entity graph. Drag nodes to move them, drag empty space to pan, scroll to zoom, arrows pan, +/- zoom, 0 fits, click a node to select, Escape clears."
        tabIndex={0}
        style={{ outline: 'none', touchAction: 'none' }}
      >
        <div ref={gridRef} className="graph__grid" />
        {g.isLoading && <div className="graph__overlay"><Loading inline label="Building the typed graph…" /></div>}
        {g.isError && <div className="graph__overlay"><ErrorState title="Graph unavailable" error={g.error} onRetry={() => void g.refetch()} /></div>}
        {/* The graph is built once per pool version in a BACKGROUND thread; until it lands the payload is
            empty on purpose. Showing the normal "no entities extracted" empty state here would tell the
            analyst the pool has no entities in it, which is the opposite of what is happening. */}
        {buildingGraph && <div className="graph__overlay"><BuildingState what="entity graph" status={stats?.status} action={<DerivedPauseActions />} /></div>}
        {/* A source filter that returns nothing, or entities with no relations between them, is a real
            and common answer — a package log or a proxy CSV has plenty of entities and no typed
            relations at all. Saying "no entities extracted" there is wrong, and an empty canvas is
            worse: it reads as a broken graph. Name the selection and say which half is missing. */}
        {!buildingGraph && g.data && nodesData.length === 0 && (
          <div className="graph__overlay">
            <EmptyState icon={<Icon.Graph />}
              title={srcSel.length ? 'Nothing in the selected logs' : activeFilters ? 'Nothing matches these filters' : 'No entities extracted yet'}
              body={srcSel.length
                ? `${selectedNames} produced no entities that pass the current filters. Add another source, or clear the type/relation filters.`
                : activeFilters ? 'Loosen the query, type or relation filters.'
                : 'IPs, accounts, hosts, processes, files, hashes and domains appear once sources are parsed and linked by what happened between them.'}
              actions={<>
                {srcSel.length > 0 && <button className="btn btn--accent" onClick={() => setSrcOpen(true)}><Icon.Sources />Change sources</button>}
                {activeFilters > 0 && <button className="btn" onClick={clearFilters}>Clear filters</button>}
                {!srcSel.length && !activeFilters && <button className="btn btn--accent" onClick={() => nav('/ingest')}>Go to Sources</button>}
              </>} />
          </div>
        )}
        {!buildingGraph && g.data && nodesData.length > 0 && edgesData.length === 0 && (
          <div className="graph__note">
            <Icon.Warn />
            <span>
              <b>{fmtInt(nodesData.length)}</b> entit{nodesData.length === 1 ? 'y' : 'ies'} in {selectedNames}, and no
              relations between them — that log records things, not interactions between them. Select a log that does
              (auth, network, process or audit records) to see connections.
            </span>
          </div>
        )}
        <canvas ref={glRef} className="graph__gl" aria-hidden />
        <GraphA11yList nodes={a11yNodes} onPick={pickNode} onPeek={peekNode} onLeave={leaveHover} />

        <div ref={tooltipRef} className="graph__tip" style={{ opacity: 0 }} aria-hidden>
          {hov && (
            <>
              <div className="graph__tip-name"><span className="graph__tip-type" style={{ color: TYPE_META[hov.type].hue }}>{TYPE_META[hov.type].label}</span>{hov.value}</div>
              <div className="graph__tip-row"><span>events</span><b>{fmtInt(hov.count)}</b></div>
              <div className="graph__tip-row"><span>links</span><b>{degree.get(hov.id) ?? 0}</b></div>
              {hov.detections > 0 && <div className="graph__tip-row"><span>detections</span><b style={{ color: sevVar(hov.sev) }}>{hov.detections} · {hov.sev}</b></div>}
              <div className="graph__tip-row"><span>first</span><b>{fmtTs(hov.first)}</b></div>
              <div className="graph__tip-row"><span>last</span><b>{fmtTs(hov.last)}</b></div>
              <div className="graph__tip-hint">click · select &nbsp; double-click · focus</div>
            </>
          )}
        </div>

        <div className="graph__legend">
          <span className="graph__legend-chip"><i className="graph__legend-dot" style={{ background: 'var(--node-ring)' }} /> size = events</span>
          <span className="graph__legend-chip"><i className="graph__legend-line" /> arrow = relation</span>
          <span className="graph__legend-chip"><i className="graph__legend-line graph__legend-line--bad" /> failed / denied</span>
          <span className="graph__legend-chip"><i className="graph__legend-line graph__legend-line--ai" /> AI / analyst link</span>
          <span className="graph__legend-chip"><i className="graph__legend-dot graph__legend-dot--sev" /> ring = detection severity</span>
          <span className={cx('graph__legend-chip', running && 'graph__legend-chip--live')}><i className="graph__legend-dot" style={{ background: running ? 'var(--accent)' : 'var(--muted-3)' }} /> {running ? 'settling' : 'settled'}</span>
        </div>

        <div className="graph__tools">
          <button className="btn btn--sm btn--icon" onClick={() => zoomAt(1.25, W / 2, H / 2, true)} aria-label="Zoom in" title="Zoom in"><Icon.Plus /></button>
          <button className="btn btn--sm btn--icon" onClick={() => zoomAt(1 / 1.25, W / 2, H / 2, true)} aria-label="Zoom out" title="Zoom out"><Icon.Minus /></button>
          <button className="btn btn--sm btn--icon" onClick={fitView} aria-label="Fit to view" title="Fit all nodes (double-click canvas · key 0)"><Icon.Fit /></button>
          <span className="graph__tools-sep" />
          <button className="btn btn--sm" onClick={() => { sim.relayout(); }} title="Scatter and re-run the layout"><Icon.Refresh />Re-layout</button>
          <button className={cx('btn btn--sm', pinAfterDrag && 'btn--accent')} onClick={() => setPinAfterDrag((p) => !p)} aria-pressed={pinAfterDrag} title="Keep nodes where you drop them"><Icon.Pin />Pin after drag</button>
          {sim.nodes.some((n) => sim.isPinned(n.name)) && (
            <button className="btn btn--sm btn--ghost" onClick={() => { sim.unpinAll(); setPinVersion((v) => v + 1); }} title="Release all pinned nodes">Unpin all</button>
          )}
        </div>
      </div>

      {/* ── side panel ── */}
      <div className="graph__side">
        {/* AI review results, when running or present */}
        {(reviewing || proposed.length > 0 || narrative || aliases.length > 0 || reviewErr) && (
          <div className="panel panel--tight graph__ai">
            <div className="sec" style={{ marginBottom: 6 }}>
              <div className="eyebrow">AI review</div>
              {reviewing && <span className="sec__hint">working…</span>}
              {!reviewing && (proposed.length > 0 || narrative) && <button className="btn btn--sm btn--ghost" onClick={() => { setProposed([]); setNarrative(''); setAliases([]); setThinking([]); }}>dismiss</button>}
            </div>
            {reviewErr && <div className="graph__ai-err">{reviewErr}</div>}
            {reviewing && thinking.length > 0 && <div className="graph__ai-think">{thinking[thinking.length - 1]}</div>}
            {narrative && <div className="graph__ai-narr">{narrative}</div>}
            {proposed.length > 0 && (
              <>
                <div className="eyebrow" style={{ marginTop: 10 }}>Proposed links · {proposed.length}</div>
                <div className="graph__ai-hint">Dashed on the canvas until you accept them. Accepted links persist with the case.</div>
                <div className="link-list">
                  {proposed.slice(0, 40).map((e) => {
                    const a = byId.get(e.source); const b = byId.get(e.target);
                    return (
                      <div key={e.id} className="link-item link-item--proposed">
                        <div className="link-item__row">
                          <button className="link-item__name" onClick={() => { setSelected(e.source); centerOn(e.source); }}>{a ? displayName(a) : e.source}</button>
                          <span className="link-item__rel">{REL_LABEL[e.relation]}</span>
                          <button className="link-item__name" onClick={() => { setSelected(e.target); centerOn(e.target); }}>{b ? displayName(b) : e.target}</button>
                        </div>
                        <div className="link-item__via">{e.why}{e.confidence != null ? ` · ${Math.round(e.confidence * 100)}% confident` : ''}</div>
                        <div className="link-item__actions">
                          <button className="btn btn--sm btn--accent" onClick={() => accept.mutate(e)} disabled={accept.isPending}>Accept</button>
                          <button className="btn btn--sm btn--ghost" onClick={() => setProposed((p) => p.filter((x) => x.id !== e.id))}>Dismiss</button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </>
            )}
            {aliases.length > 0 && (
              <>
                <div className="eyebrow" style={{ marginTop: 10 }}>Probable aliases · {aliases.length}</div>
                <div className="link-list">
                  {aliases.map((al, i) => (
                    <div key={i} className="link-item">
                      <div className="link-item__row"><span className="link-item__name">{displayName(byId.get(al.a) ?? ({ value: al.a, type: 'other' } as GraphNode))}</span><span className="link-item__rel">≡</span><span className="link-item__name">{displayName(byId.get(al.b) ?? ({ value: al.b, type: 'other' } as GraphNode))}</span></div>
                      <div className="link-item__via">{al.reason}</div>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        )}

        <div className="panel panel--tight">
          <div className="eyebrow">Selected entity</div>
          {!sel && <div className="muted" style={{ marginTop: 8, fontSize: 'var(--fs-base)' }}>{selected ? 'That node is not in the current view.' : 'Click a node to inspect it. Double-click to focus on its neighbourhood. Drag to rearrange.'}</div>}
          {sel && (
            <>
              <div className="graph__ent-head">
                <span className="graph__ent-glyph" style={{ color: TYPE_META[sel.type].hue, borderColor: TYPE_META[sel.type].hue }}>{TYPE_META[sel.type].glyph}</span>
                <div style={{ minWidth: 0 }}>
                  <div className="graph__ent-name" title={sel.value}>{sel.value}</div>
                  <div className="graph__ent-kind">{TYPE_META[sel.type].label} · {fmtInt(sel.count)} events · first {fmtRelative(sel.first)}</div>
                </div>
              </div>
              {sel.detections > 0 && <div className="graph__ent-det" style={{ borderColor: sevVar(sel.sev), color: sevVar(sel.sev) }}>{sel.detections} detection{sel.detections === 1 ? '' : 's'} · max {sel.sev}</div>}
              <div className="kv-list" style={{ marginTop: 12 }}>
                {sel.facts.filter(([k]) => !['type', 'events', 'first seen', 'last seen'].includes(k.toLowerCase())).map(([k, v], i) => (
                  <div key={`${k}-${i}`} className="kv"><span className="kv__k">{k}</span><span className="kv__v">{v}</span></div>
                ))}
              </div>
              <div className="graph__ent-actions">
                <button className="btn btn--sm" onClick={() => setFocus(sel.id)} title="Show only this node's neighbourhood"><Icon.Fit />Focus</button>
                {/* The graph owns the rule for "these are my events" (entity extraction), so it hands the
                    UI the query — free text matched msg/raw/fields by SUBSTRING, so searching node
                    10.0.0.1 also returned 10.0.0.100 and every line that merely mentioned it. */}
                <button className="btn btn--sm" title={`Search the ${fmtInt(sel.count)} events this entity appears in`}
                  onClick={() => nav(`/search?q=${encodeURIComponent(detail.data?.query ?? `entity:"${sel.value.replace(/:/g, '\\:')}"`)}${srcSel.length ? `&sources=${encodeURIComponent(srcSel.join(','))}` : ''}`)}>
                  <Icon.Search />Search its {fmtInt(sel.count)} events
                </button>
                <button className={cx('btn btn--sm', pathFrom === sel.id && 'btn--accent')} onClick={() => setPathFrom(pathFrom === sel.id ? null : sel.id)} title="Then select another node to find the shortest chain between them">
                  {pathFrom === sel.id ? 'Path from here ✓' : 'Path from here'}
                </button>
                <button className="btn btn--sm btn--ghost" onClick={() => ai.open({ scope: 'selection', id: sel.value, label: sel.value })}><Icon.Sparkle />Ask AI</button>
              </div>
              {pathFrom && pathFrom !== sel.id && (
                <div className="graph__path">
                  {pathQ.isLoading && <span className="muted">finding a path…</span>}
                  {pathQ.data && !pathQ.data.found && <span className="muted">no chain within 4 hops between those two.</span>}
                  {pathQ.data?.found && (
                    <>
                      <div className="eyebrow">Path · {pathQ.data.path.length - 1} hop{pathQ.data.path.length === 2 ? '' : 's'}</div>
                      <div className="graph__path-chain">
                        {pathQ.data.path.map((n, i) => (
                          <span key={n.id}>
                            <button className="graph__path-node" onClick={() => { setSelected(n.id); centerOn(n.id); }}>{displayName(n)}</button>
                            {i < pathQ.data!.edges.length && <span className="graph__path-rel"> —{REL_LABEL[pathQ.data!.edges[i]!.relation]}→ </span>}
                          </span>
                        ))}
                      </div>
                    </>
                  )}
                  <button className="btn btn--sm btn--ghost" onClick={() => setPathFrom(null)} style={{ marginTop: 6 }}>clear path</button>
                </div>
              )}
            </>
          )}
        </div>

        <div className="panel panel--tight">
          <div className="sec" style={{ marginBottom: 0 }}>
            <div className="eyebrow">Relations</div>
            {detail.data && <span className="sec__hint">{detail.data.neighbours.length}</span>}
          </div>
          <div className="link-list">
            {!sel && <div className="muted" style={{ fontSize: 'var(--fs-base)' }}>—</div>}
            {sel && detail.isLoading && <Loading inline />}
            {sel && detail.data && detail.data.neighbours.length === 0 && proposedForNode.length === 0 && <div className="muted" style={{ fontSize: 'var(--fs-base)' }}>No relations extracted for this node.</div>}
            {sel && [...proposedForNode.map((e) => ({ e, proposed: true })), ...(detail.data?.neighbours ?? []).map((e) => ({ e, proposed: false }))].slice(0, 60).map(({ e, proposed: isProp }) => {
              const other = e.source === sel.id ? e.target : e.source;
              const outgoing = e.source === sel.id;
              const on = byId.get(other);
              return (
                <button key={e.id} className={cx('link-item', isProp && 'link-item--proposed', (e.ai || e.manual) && 'link-item--ai')} onClick={() => { setSelected(other); centerOn(other); }} onMouseEnter={() => enterHover(other)} onMouseLeave={leaveHover}>
                  <div className="link-item__row">
                    <span className="link-item__rel">{outgoing ? '→' : '←'} {REL_LABEL[e.relation]}</span>
                    <span className="link-item__name">{on ? displayName(on) : other.split(':').slice(1).join(':')}</span>
                    <span className="link-item__n">{isProp ? 'proposed' : `${fmtInt(e.count)}×`}{e.outcome ? ` · ${e.outcome}` : ''}</span>
                  </div>
                  <div className="link-item__via">{e.why}{e.ai ? ' · AI, accepted' : e.manual ? ' · analyst' : ''}
                    {(e.ai || e.manual) && !isProp && <span role="button" className="link-item__remove" onClick={(ev) => { ev.stopPropagation(); removeLink.mutate(e.id); }} title="Remove this link">remove</span>}
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {sel && detail.data && detail.data.timeline.length > 0 && (
          <div className="panel panel--tight">
            <div className="sec" style={{ marginBottom: 4 }}><div className="eyebrow">Recent events</div><span className="sec__hint">{detail.data.timeline.length}</span></div>
            <div className="graph__tl">
              {detail.data.timeline.slice(-12).reverse().map((t) => (
                <button key={t.eventId} className="graph__tl-row" onClick={() => nav(`/events/${encodeURIComponent(t.eventId)}`)}>
                  <span className="cell-mono cell-dim">{fmtTs(t.ts).slice(11, 19)}</span>
                  <span className="graph__tl-msg" style={{ borderColor: sevVar(t.sev) }}>{t.msg}</span>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
      </div>
      )}
    </div>
  );
}
