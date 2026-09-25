/**
 * The case timeline, REPLAYED as an incident: the curated events happen again, in order, at the pace
 * they really happened, and the screen tells the story as it unfolds — modelled on the incident
 * replay the analyst pointed at ("Anatomy of a frontier-lab agent intrusion"): a console with the
 * incident clock, three running figures, a map of what the intrusion has reached that BUILDS node
 * by node as the replay reaches each one, the phases opening as they are entered, a live stream that
 * types each moment in as it happens, and the tempo of the whole thing. The per-event detail is the
 * timeline's other view (Full events); it was repeated here and was taken out on request. What that page does with glow and pulsing, this does with colour and fades:
 * this app's rule is that nothing glows or pulses, and a replay is no exception.
 *
 * TIME ACCURACY is the rule everything here serves (measured on the analyst's case: every gap that is
 * not skipped plays within ±14 ms of the real one — under one frame):
 *  - every event is placed at its instant in MILLISECONDS. The normalised `ts` keeps whole seconds,
 *    and the server recovers the fraction from the log line itself (GET /api/case-set/replay);
 *  - the playhead is a clock anchored to `performance.now()`, never accumulated per frame, so a
 *    throttled tab or a slow frame cannot make it drift from the timestamps;
 *  - the default speed is 1x, REAL TIME, and the analyst's choice is remembered. Fitting the span
 *    into a minute made a 54-minute case play at 60x, and a burst of events 100 ms apart flashed past
 *    in two milliseconds — reported as "the timeline plays too fast";
 *  - "Skip quiet stretches" (on by default) jumps a lull longer than a few seconds of screen time and
 *    marks every moment reached that way "skipped", so a skipped gap never looks like a short one.
 *    Within a burst nothing is skipped: the pace of the activity itself is always the real one.
 *
 * An entry with no parsed timestamp cannot be placed on a clock. It is counted and named rather than
 * slotted in somewhere, the same rule the list follows when it sorts those entries last.
 */
import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { KeyboardEvent as ReactKeyboardEvent, PointerEvent as ReactPointerEvent } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import type { CaseSetEntry, Event, ReplayBeat, Severity } from '../api/types';
import { useTypewriter } from '../hooks/useArrivals';
import { useCase } from '../hooks/queries';
import { cx } from '../utils/format';
import { inlineMd } from '../utils/markdown';
import { Icon } from './icons';
import { EmptyState, Loading } from './ui';
import { noteLine } from './timelineText';

/** Replay rates: how many seconds of the incident pass per second on screen. */
const SPEEDS = [0.25, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600, 7200, 21600, 43200, 86400];
/** The ones offered as one-click segments; the rest are in the "more" menu. */
const SPEED_SEGS = [0.5, 1, 2, 10, 60];
/** The speed that plays the whole span in about this much screen time is offered in the menu. */
const TARGET_MS = 60_000;
/** With skipping on, a gap longer than this much SCREEN time is jumped... */
const QUIET_MS = 8_000;
/** ...after the previous event has been on screen this long... */
const QUIET_HOLD_MS = 1_200;
/** ...landing this long (screen time) before the next event, so it is still seen to arrive. */
const QUIET_LEAD_MS = 800;
/** The time axis is padded either side of the first and last event. */
const PAD_SHARE = 0.03;
const PAD_MIN_MS = 1_000;
/** Playback starts this much SCREEN time before the first event, whatever the span. */
const LEAD_IN_MS = 1_500;
/** Pointer within this many pixels of an event snaps the playhead onto it. */
const SNAP_PX = 8;
/** A milestone callout stays over the map this long (screen time). */
const FLARE_MS = 3_800;
/** Newest events shown in the live stream. */
const UNLABELLED = 'unlabelled';
const SPEED_KEY = 'iris.replay.speed';
const SKIP_KEY = 'iris.replay.skipQuiet';

/* Phase colours: the entity graph's own type hues (GraphScreen TYPE_META), cycled — so the replay
   reads in the same colours as the graph, and never borrows a SEVERITY colour for something that is
   not a severity. */
const PHASE_HUES = ['var(--accent)', '#6f9fd8', '#d8974f', '#a58fd8', '#cbb96e', '#5fb8a8', '#d8707a', '#c98a5f'];
/** What an entity on the map is, and its colour — again the graph's hues, by type. */
const ROLE_META: Record<string, { tag: string; hue: string; kind: string }> = {
  to: { tag: 'destination', hue: 'var(--accent)', kind: 'address' },
  from: { tag: 'source', hue: 'var(--accent)', kind: 'address' },
  ip: { tag: 'address', hue: 'var(--accent)', kind: 'address' },
  domain: { tag: 'domain', hue: '#cbb96e', kind: 'domain' },
  account: { tag: 'account', hue: '#a58fd8', kind: 'account' },
  host: { tag: 'host', hue: '#6f9fd8', kind: 'host' },
  process: { tag: 'process', hue: '#d8974f', kind: 'process' },
  file: { tag: 'file', hue: '#5fb8a8', kind: 'file' },
  hash: { tag: 'hash', hue: '#5fb8a8', kind: 'hash' },
};

interface Item {
  idx: number;
  en: CaseSetEntry;
  e: Event;
  t: number;              // epoch ms
  precise: boolean;       // true when the millisecond came from the log line
  said: string;           // the analyst's sentence, or '' when there is no note
  sev: Severity;
  lane: number;
  beats: ReplayBeat[];
  action: { kind: string; verb: string; object: string; actor?: string };
  ents: string[];         // the SPECIFIC entities it carries (file, process, hash, domain, address)
  allEnts: string[];      // ...plus its host and account, for the footprint
}
/** One node per EVENT: every event on the timeline is drawn on the map. */
interface MapNode { key: string; role: string; value: string; verb: string; t: number; first: number; lane: number }
/** `actor`: b was done BY a's process (spawned, wrote, loaded, connected); `shared`: they touched the same thing. */
interface MapEdge { a: string; b: string; at: number; kind: 'actor' | 'shared' }

/* ───────── formatting ───────── */
const pad2 = (n: number) => String(n).padStart(2, '0');
const pad3 = (n: number) => String(n).padStart(3, '0');
function utcParts(t: number): { day: string; clock: string; ms: string } {
  const d = new Date(t);
  return {
    day: `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())}`,
    clock: `${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}`,
    ms: `.${pad3(d.getUTCMilliseconds())}`,
  };
}
/** T+hh:mm:ss from the first event; before it, a countdown that rounds up (never T−00:00:00). */
function tOffset(ms: number): string {
  const sign = ms < 0 ? '−' : '+';
  let s = ms < 0 ? Math.ceil(-ms / 1000) : Math.floor(ms / 1000);
  if (s === 0) return 'T+00:00:00';
  const d = Math.floor(s / 86400); s -= d * 86400;
  const h = Math.floor(s / 3600); s -= h * 3600;
  const m = Math.floor(s / 60); s -= m * 60;
  return `T${sign}${d ? `${d}d ` : ''}${pad2(h)}:${pad2(m)}:${pad2(s)}`;
}
/** A duration in words: 0.9s, 7.3s, 9m 58s, 2h 14m, 3d 4h. */
function dur(ms: number): string {
  if (ms < 10_000) return `${(Math.max(0, ms) / 1000).toFixed(1)}s`;
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${pad2(s % 60)}s`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ${pad2(m % 60)}m`;
  const d = Math.floor(h / 24);
  return `${d}d ${h % 24}h`;
}
function rateLabel(v: number): string {
  if (v === 1) return '1× · real time';
  if (v < 1) return `${v}× · slow motion`;
  const per = v >= 86400 ? `${v / 86400} d` : v >= 3600 ? `${v / 3600} h` : v >= 60 ? `${v / 60} min` : `${v} s`;
  return `${v.toLocaleString()}× · 1 s = ${per}`;
}
function reachedBy(items: Item[], t: number): number {
  let lo = 0; let hi = items.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (items[mid]!.t <= t) lo = mid + 1; else hi = mid;
  }
  return lo;
}
/** A log's own "no value" placeholder is not a host or a user. */
const real = (v: string | undefined) => !!v && v !== '-' && v !== '--';
function stored<T>(key: string, parse: (v: string) => T | undefined, fallback: T): T {
  try {
    const v = localStorage.getItem(key);
    const p = v == null ? undefined : parse(v);
    return p === undefined ? fallback : p;
  } catch { return fallback; }
}
function remember(key: string, value: string): void {
  try { localStorage.setItem(key, value); } catch { /* private mode: the choice lasts this visit */ }
}
const trunc = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
/** Markdown marks off, for a one-line description that is shown as plain text. */
const plain = (s: string) => s.replace(/\*\*|__|`/g, '').replace(/\s+/g, ' ').trim();

/* ───────── beats: what the server observed about one moment ───────── */
const BEAT_TAG: Record<string, string> = {
  first: 'first seen', earlier: 'seen before', detection: 'detection', download: 'download',
  process: 'process', command: 'command', file: 'file', signature: 'signature', library: 'dll',
  network: 'network', registry: 'registry', persistence: 'persistence', access: 'account',
  'auth-fail': 'failed auth', privilege: 'privilege', account: 'account', 'anti-forensics': 'log cleared',
  execution: 'execution', web: 'web', dns: 'dns',
};
function beatTone(b: ReplayBeat): string {
  if (b.kind === 'persistence' || b.kind === 'anti-forensics' || b.kind === 'auth-fail') return 'bad';
  if (b.kind === 'detection') return b.sev === 'critical' || b.sev === 'high' ? 'bad' : 'warn';
  if (b.kind === 'access' || b.kind === 'privilege' || b.kind === 'account' || b.kind === 'execution') return 'warn';
  if (b.kind === 'first') return 'accent';
  if (b.kind === 'earlier') return 'muted';
  return 'plain';
}
/** The one observation worth a callout over the map, if the moment has one. Milestones only: a
 *  callout on every event is a callout on none. */
const FLARE_ORDER = ['persistence', 'anti-forensics', 'detection', 'access', 'privilege', 'auth-fail', 'first', 'download'];
function milestone(it: Item): ReplayBeat | undefined {
  for (const k of FLARE_ORDER) {
    const b = it.beats.find((x) => x.kind === k && (k !== 'detection' || x.sev === 'high' || x.sev === 'critical'));
    if (b) return b;
  }
  return undefined;
}
/* ───────── the map: what the intrusion has reached, BUILT as the replay reaches it ───────── */
const NODE_W = 190;
const NODE_H = 44;
/** A phase stacks at most this many entities per column, then wraps into another column inside its
 *  own zone — so a phase that touches forty things makes the map wider, not four screens tall. */
const ROWS_MAX = 6;
const SUB_GAP = 16;
const COL_GAP = 52;
const ZONE_PAD = 16;          // the left margin carries same-phase brackets
const ZONE_HEAD = 28;
const ROW_GAP = 14;
/** Vertical space between two ROWS of phase zones, once they wrap. */
const ZONE_ROW_GAP = 30;
const MAP_EMPTY_H = 120;
/** The same one-letter badges the entity graph draws, so an entity reads the same on both screens. */
/** How an event is drawn, by what it DID. Hues are the entity graph's, plus the level colours for the
 *  actions an analyst must not miss (a deletion, persistence, a cleared log, a failed sign-in). */
const ACTION_META: Record<string, { tag: string; glyph: string; hue: string }> = {
  process: { tag: 'process', glyph: 'P', hue: '#d8974f' },
  execution: { tag: 'execution', glyph: 'EX', hue: '#d8974f' },
  library: { tag: 'dll', glyph: 'L', hue: '#c98a5f' },
  file: { tag: 'file', glyph: 'F', hue: '#5fb8a8' },
  delete: { tag: 'deletion', glyph: 'X', hue: 'var(--bad)' },
  download: { tag: 'download', glyph: '↓', hue: '#6f9fd8' },
  web: { tag: 'web', glyph: 'W', hue: '#cbb96e' },
  dns: { tag: 'dns', glyph: 'D', hue: '#cbb96e' },
  network: { tag: 'network', glyph: 'N', hue: 'var(--accent)' },
  registry: { tag: 'registry', glyph: 'R', hue: '#5fb8a8' },
  access: { tag: 'access', glyph: 'U', hue: '#a58fd8' },
  account: { tag: 'account', glyph: 'U', hue: '#a58fd8' },
  'auth-fail': { tag: 'failed auth', glyph: 'U', hue: 'var(--sev-high)' },
  privilege: { tag: 'privilege', glyph: 'PR', hue: '#d8707a' },
  persistence: { tag: 'persistence', glyph: 'PS', hue: 'var(--sev-high)' },
  'anti-forensics': { tag: 'log cleared', glyph: 'LC', hue: 'var(--bad)' },
  cloud: { tag: 'cloud', glyph: 'C', hue: '#6f9fd8' },
  event: { tag: 'event', glyph: '•', hue: 'var(--muted)' },
};

/** Positions for the nodes REACHED so far. Each phase zone is exactly as big as what it holds now and
 *  grows as its events arrive. The first version reserved every zone's final size up front so that
 *  nothing would ever move, and the result was large empty boxes waiting for events ("too large
 *  looking"). Phases keep the order they first happened in and nodes the order they arrived, so a
 *  node only ever moves when a zone to its LEFT gains a column: every six events, not every event. */
function layoutMap(nodes: MapNode[], lanes: string[], avail: number) {
  // The map is ALWAYS drawn at its natural size — shrinking it to fit is what made it cramped. It grows
  // DOWNWARD instead: phase zones flow left to right and wrap onto a new row when the width runs out,
  // and a phase with more events than fit across gets taller rather than wider.
  const cols = [...new Set(nodes.map((n) => n.lane))].sort((a, b) => a - b);
  const count = new Map<number, number>();
  for (const n of nodes) count.set(n.lane, (count.get(n.lane) ?? 0) + 1);
  const maxSubs = Math.max(1, Math.floor((avail - 4 * ZONE_PAD + SUB_GAP) / (NODE_W + SUB_GAP)));
  const zones: { lane: number; name: string; x: number; y: number; w: number; h: number; rows: number }[] = [];
  let x = ZONE_PAD;
  let y = ZONE_PAD;
  let rowH = 0;
  for (const lane of cols) {
    const n = count.get(lane)!;
    const subs = Math.min(Math.ceil(n / ROWS_MAX), maxSubs);
    const rows = Math.ceil(n / subs);
    const w = subs * NODE_W + (subs - 1) * SUB_GAP + 2 * ZONE_PAD;
    const h = ZONE_HEAD + rows * (NODE_H + ROW_GAP) - ROW_GAP + ZONE_PAD;
    if (x > ZONE_PAD && x + w > avail - ZONE_PAD) {          // no room left on this row: wrap
      x = ZONE_PAD;
      y += rowH + ZONE_ROW_GAP;
      rowH = 0;
    }
    zones.push({ lane, name: lanes[lane] ?? UNLABELLED, x, y, w, h, rows });
    x += w + COL_GAP;
    rowH = Math.max(rowH, h);
  }
  const zoneOf = new Map(zones.map((z) => [z.lane, z]));
  const seen = new Map<number, number>();
  const pos = new Map<string, { x: number; y: number }>();
  for (const n of nodes) {
    const z = zoneOf.get(n.lane)!;
    const r = seen.get(n.lane) ?? 0;
    seen.set(n.lane, r + 1);
    pos.set(n.key, {
      x: z.x + ZONE_PAD + Math.floor(r / z.rows) * (NODE_W + SUB_GAP),
      y: z.y + ZONE_HEAD + (r % z.rows) * (NODE_H + ROW_GAP),
    });
  }
  return { pos, zones };
}

/** Eases the frame from one size to the next, so the map zooms out as it grows instead of jumping. */
function useTween(w: number, h: number, ms = 450): { w: number; h: number } {
  const [v, setV] = useState({ w, h });
  const cur = useRef({ w, h });
  useEffect(() => {
    const from = { ...cur.current };
    let reduce = false;
    try { reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch { /* default */ }
    if (reduce || (from.w === w && from.h === h)) { cur.current = { w, h }; setV({ w, h }); return; }
    const t0 = performance.now();
    let raf = 0;
    const step = () => {
      const k = Math.min(1, (performance.now() - t0) / ms);
      const e = 1 - (1 - k) ** 3;
      cur.current = { w: from.w + (w - from.w) * e, h: from.h + (h - from.h) * e };
      setV(cur.current);
      if (k < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [w, h, ms]);
  return v;
}

const AttackMap = memo(function AttackMap({ nodes, edges, lanes, reached, current, hidden }: {
  nodes: MapNode[]; edges: MapEdge[]; lanes: string[]; reached: number; current: Set<string>; hidden: number;
}) {
  const shown = useMemo(() => nodes.filter((n) => n.first < reached), [nodes, reached]);
  // The frame is the card's width, at natural size; only its HEIGHT follows what has been reached,
  // eased, so the map grows as it builds and is never squeezed to fit.
  const box = useRef<HTMLDivElement>(null);
  const [avail, setAvail] = useState(900);
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setAvail(Math.max(320, el.clientWidth)));
    ro.observe(el);
    setAvail(Math.max(320, el.clientWidth));
    return () => ro.disconnect();
  }, []);
  const { pos, zones: open } = useMemo(() => layoutMap(shown, lanes, avail), [shown, lanes, avail]);
  const contentW = open.length ? Math.max(...open.map((z) => z.x + z.w)) + ZONE_PAD : 0;
  const contentH = open.length ? Math.max(...open.map((z) => z.y + z.h)) + ZONE_PAD : 0;
  const vbW = Math.max(contentW, avail);        // wider only when one zone alone cannot fit
  const frame = useTween(vbW, contentH);
  const pxW = Math.round(frame.w);
  const pxH = Math.round(frame.h);
  const overflow = pxW > avail + 1;

  /* ── connections ──
     Ports: a node with several links spreads them down its side instead of sending every one from
     the same point (that single point is what made the host a tangle). Lines leave and arrive
     HORIZONTALLY, so the curve reads as a flow from one phase into the next. A link inside one phase
     runs as a bracket down the zone's left margin rather than looping over the node text. The head is
     drawn separately from the line, so it can arrive AFTER the line has drawn itself. */
  const visibleEdges = edges.filter((ed) => ed.at < reached && pos.has(ed.a) && pos.has(ed.b));
  const ports = useMemo(() => {
    const out = new Map<string, number>();
    const spread = (list: MapEdge[], side: 'a' | 'b') => {
      const groups = new Map<string, MapEdge[]>();
      for (const ed of list) {
        const k = `${ed[side]}|${side}`;
        const g = groups.get(k);
        if (g) g.push(ed); else groups.set(k, [ed]);
      }
      for (const [k, g] of groups) {
        const other = side === 'a' ? 'b' : 'a';
        g.sort((x, y) => (pos.get(x[other])!.y - pos.get(y[other])!.y) || (pos.get(x[other])!.x - pos.get(y[other])!.x));
        const step = g.length > 1 ? Math.min(7, (NODE_H - 14) / (g.length - 1)) : 0;
        g.forEach((ed, i) => out.set(`${k}|${ed.a}|${ed.b}`, (i - (g.length - 1) / 2) * step));
      }
    };
    spread(visibleEdges, 'a');
    spread(visibleEdges, 'b');
    return out;
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visibleEdges.length, pos]);
  const route = (ed: MapEdge): { d: string; head: string } => {
    const a = pos.get(ed.a)!; const b = pos.get(ed.b)!;
    const oa = ports.get(`${ed.a}|a|${ed.a}|${ed.b}`) ?? 0;
    const ob = ports.get(`${ed.b}|b|${ed.a}|${ed.b}`) ?? 0;
    const ya = a.y + NODE_H / 2 + oa;
    const yb = b.y + NODE_H / 2 + ob;
    const H = 5.5;   // arrowhead half-height
    if (Math.abs(a.x - b.x) < 1) {                 // same phase column: a bracket in the left margin
      const x = a.x - 2; const bx = x - 11 - Math.abs(ob) * 0.4;
      const xe = b.x - 1;
      return { d: `M${x},${ya} C${bx},${ya} ${bx},${yb} ${xe - 7},${yb}`,
        head: `M${xe - 8},${yb - H} L${xe},${yb} L${xe - 8},${yb + H} Z` };
    }
    if (a.x < b.x) {                               // into a later phase, left to right
      const x1 = a.x + NODE_W; const x2 = b.x - 1;
      const dx = Math.max(26, (x2 - x1) * 0.5);
      return { d: `M${x1},${ya} C${x1 + dx},${ya} ${x2 - dx},${yb} ${x2 - 7},${yb}`,
        head: `M${x2 - 8},${yb - H} L${x2},${yb} L${x2 - 8},${yb + H} Z` };
    }
    const x1 = a.x; const x2 = b.x + NODE_W + 1;   // back into an earlier phase, right to left
    const dx = Math.max(26, (x1 - x2) * 0.5);
    return { d: `M${x1},${ya} C${x1 - dx},${ya} ${x2 + dx},${yb} ${x2 + 7},${yb}`,
      head: `M${x2 + 8},${yb - H} L${x2},${yb} L${x2 + 8},${yb + H} Z` };
  };
  const laneOfNode = useMemo(() => new Map(nodes.map((n) => [n.key, n.lane])), [nodes]);
  if (!nodes.length) {
    return <div className="rp-map__empty">No hosts, addresses, accounts or files were identified on these events.</div>;
  }
  return (
    <div className={cx('rp-mapview', overflow && 'rp-mapview--scroll')} ref={box}>
      {shown.length === 0 ? (
        <div className="rp-map__wait" style={{ height: MAP_EMPTY_H }}>
          The map builds as the replay reaches each host, address, account and file.
        </div>
      ) : (
        <svg className="rp-map" width={pxW} height={pxH} viewBox={`0 0 ${frame.w} ${frame.h}`}
          role="img" aria-label={`Map of the ${shown.length} entities the replay has reached so far, grouped by phase`}>
          {open.map((z) => (
            <g key={z.lane} className="rp-zone" style={{ ['--c' as string]: PHASE_HUES[z.lane % PHASE_HUES.length] }}>
              <rect x={z.x} y={z.y} width={z.w} height={z.h} rx={10} />
              <circle cx={z.x + 14} cy={z.y + 14} r={3.5} className="rp-zone__dot" />
              <text x={z.x + 24} y={z.y + 18}>{trunc(z.name, Math.floor(z.w / 7.5))}</text>
            </g>
          ))}
          {visibleEdges.map((ed) => {
            const { d, head } = route(ed);
            const hot = current.has(ed.b);
            return (
              <g key={`${ed.a}|${ed.b}`} className={cx('rp-link', `rp-link--${ed.kind}`, hot && 'rp-link--hot')}
                style={{ ['--c' as string]: PHASE_HUES[(laneOfNode.get(ed.b) ?? 0) % PHASE_HUES.length] }}>
                <path className="rp-edge" d={d} pathLength={1} />
                <path className="rp-arrowhead" d={head} />
              </g>
            );
          })}
          {shown.map((n) => {
            const p = pos.get(n.key)!;
            const meta = ACTION_META[n.role] ?? ACTION_META.event!;
            const c = utcParts(n.t);
            return (
              <g key={n.key} transform={`translate(${p.x},${p.y})`} style={{ ['--c' as string]: meta.hue }}>
                <g className={cx('rp-node', current.has(n.key) && 'rp-node--now')}>
                  <title>{`${c.clock}${c.ms} UTC — ${n.verb}: ${n.value}`}</title>
                  <rect className="rp-node__box" width={NODE_W} height={NODE_H} rx={9} />
                  <circle className="rp-node__badge" cx={21} cy={NODE_H / 2} r={11.5} />
                  <text className="rp-node__glyph" x={21} y={NODE_H / 2 + 3.5} textAnchor="middle">{meta.glyph}</text>
                  <text className="rp-node__title" x={40} y={19}>{trunc(n.value, 20)}</text>
                  <text className="rp-node__sub" x={40} y={33}>{trunc(n.verb, 17)} · {c.clock}</text>
                </g>
              </g>
            );
          })}
        </svg>
      )}
      {hidden > 0 && reached > nodes[nodes.length - 1]!.first && (
        <div className="rp-map__more">+{hidden} more entities not drawn — the map keeps the first {nodes.length}.</div>
      )}
    </div>
  );
});

/* ───────── phase activity: a phase opens when the replay enters it ───────── */
interface PhaseStat {
  name: string; li: number; total: number; done: number; first: number; last: number; desc: string;
  ticks: { t: number; on: boolean }[];
}
const PhaseActivity = memo(function PhaseActivity({ phases, active, pct, headPct }: {
  phases: PhaseStat[]; active: number; pct: (t: number) => number; headPct: number;
}) {
  const open = phases.filter((ph) => ph.done > 0);
  const ahead = phases.length - open.length;
  if (!open.length) {
    return <div className="rp-phases rp-phases--idle">Phases open here as the timeline enters them — {phases.length} to come.</div>;
  }
  return (
    <div className="rp-phases">
      {open.map((ph) => {
        const now = ph.li === active;
        const complete = ph.done === ph.total;
        return (
          <div key={ph.li} className={cx('rp-phase', now && 'rp-phase--active', complete && !now && 'rp-phase--done')}
            style={{ ['--c' as string]: PHASE_HUES[ph.li % PHASE_HUES.length] }}>
            <div className="rp-phase__row">
              <span className="rp-phase__dot" />
              <span className="rp-phase__nm">{ph.name}</span>
              <span className="rp-phase__when mono">{utcParts(ph.first).clock}{ph.last > ph.first ? ` → ${utcParts(ph.last).clock}` : ''}</span>
              <span className="rp-phase__ct mono">{ph.done}<i>/{ph.total}</i></span>
            </div>
            {ph.desc && <div className="rp-phase__ds" title={ph.desc}>{ph.desc}</div>}
            <div className="rp-phase__bar"><span style={{ width: `${(ph.done / ph.total) * 100}%` }} /></div>
            <div className="rp-phase__trk" aria-hidden>
              {ph.ticks.map((tk, i) => (
                <span key={i} className={cx('rp-phase__tick', tk.on && 'rp-phase__tick--on')} style={{ left: `${pct(tk.t)}%` }} />
              ))}
              <span className="rp-phase__head" style={{ left: `${headPct}%` }} />
            </div>
          </div>
        );
      })}
      {ahead > 0 && <div className="rp-phases__ahead">{ahead} more phase{ahead === 1 ? '' : 's'} ahead</div>}
    </div>
  );
});

/* ───────── the live stream: newest on top, typed in as it happens ───────── */
function StreamLine({ it, fresh, age, skipped, onOpen }: {
  it: Item; fresh: boolean; age: number; skipped: boolean; onOpen: (id: string) => void;
}) {
  const text = it.said || trunc(it.e.raw || it.e.msg, 220);
  const shown = useTypewriter(text, fresh);
  const typing = shown.length < text.length;
  const p = utcParts(it.t);
  const flare = milestone(it);
  return (
    <div className={cx('rp-ln', age === 0 && 'rp-ln--new', flare && beatTone(flare) === 'bad' && 'rp-ln--flare')}
      style={{ ['--c' as string]: PHASE_HUES[it.lane % PHASE_HUES.length], opacity: Math.max(0.45, 1 - age * 0.09) }}>
      <span className="rp-ln__ts mono">{p.clock}{it.precise ? <i>{p.ms}</i> : null}
        {skipped && <em>after a skipped lull</em>}</span>
      <span className="rp-ln__body">
        <span className="rp-ln__head">
          <span className="rp-ln__tag">{it.en.labels[0] || UNLABELLED}</span>
          <button type="button" className="rp-ln__open" onClick={() => onOpen(it.en.eventId)}
            title="Open this entry in Full events">open</button>
        </span>
        <span className={cx('rp-ln__cmd', !it.said && 'mono')}>
          {typing ? shown : (it.said ? inlineMd(it.said, `rps-${it.en.eventId}`) : text)}
        </span>
        {!typing && it.beats.slice(0, 3).map((b, i) => (
          <span key={i} className={`rp-ln__out rp-ln__out--${beatTone(b)}`}>
            <b>{BEAT_TAG[b.kind] ?? b.kind}</b>{inlineMd(b.text, `rpo-${it.en.eventId}-${i}`)}
          </span>
        ))}
      </span>
    </div>
  );
}
const Stream = memo(function Stream({ items, reached, skipped, onOpen }: {
  items: Item[]; reached: number; skipped: Set<number>; onOpen: (id: string) => void;
}) {
  // Remember which rows were already on screen: only a row that ARRIVES is typed in. A seek or a
  // step back re-mounts rows, and retyping a screenful of history would be noise.
  const seen = useRef<Set<string>>(new Set());
  const shown = items.slice(0, reached).reverse();     // every event, newest first
  useEffect(() => { for (const it of shown) seen.current.add(it.en.eventId); });
  if (!shown.length) return <div className="rp-log rp-log--idle">Waiting for the first event…</div>;
  return (
    <div className="rp-log" aria-live="polite" aria-relevant="additions">
      {shown.map((it, i) => (
        <StreamLine key={it.en.eventId} it={it} age={i} skipped={skipped.has(it.idx)} onOpen={onOpen}
          fresh={i === 0 && !seen.current.has(it.en.eventId)} />
      ))}
    </div>
  );
});

/* ───────── the replay ───────── */
export function TimelineReplay({ entries, byId, onOpen }: {
  /** The timeline's entries, oldest first. */
  entries: CaseSetEntry[];
  byId: Map<string, Event>;
  onOpen: (eventId: string) => void;
}) {
  const kase = useCase();
  // The exact instants and the observations. Keyed under the case set, so anything that changes the
  // case set (an entry added, a note edited) refetches this too.
  const ctx = useQuery({ queryKey: ['case-set', 'replay'], queryFn: api.caseSetReplay, staleTime: 30_000 });
  const ctxById = useMemo(() => new Map((ctx.data?.events ?? []).map((x) => [x.eventId, x])), [ctx.data]);

  /* ── the sequence, its phases and the entities it reaches ── */
  const { items, lanes, nodes, edges, hiddenNodes } = useMemo(() => {
    const raw: Omit<Item, 'lane' | 'idx' | 'ents' | 'allEnts' | 'action'>[] = [];
    for (const en of entries) {
      const e = byId.get(en.eventId);
      const rc = ctxById.get(en.eventId);
      const t = rc?.tMs ?? (e?.ts ? Date.parse(e.ts) : NaN);
      if (!e || !Number.isFinite(t)) continue;
      raw.push({ en, e, t, precise: rc?.precision === 'ms', said: en.note ? noteLine(en.note) : '',
        sev: e.sev, beats: rc?.beats ?? [] });
    }
    raw.sort((a, b) => a.t - b.t);     // stable: two events in one millisecond keep the list's order
    const laneOf = new Map<string, number>();
    const names: string[] = [];
    const out: Item[] = raw.map((r, idx) => {
      const name = r.en.labels[0] || UNLABELLED;
      let lane = laneOf.get(name);
      if (lane === undefined) { lane = names.length; laneOf.set(name, lane); names.push(name); }
      const rc = ctxById.get(r.en.eventId);
      const key = (role: string, value: string) => `${ROLE_META[role]?.kind ?? role}:${value.toLowerCase()}`;
      const vals = rc?.entities?.length ? rc.entities
        : r.beats.filter((b) => b.value && b.role).map((b) => ({ role: b.role!, value: b.value! }));
      const ents = [...new Set(vals.filter((v) => v.role !== 'host' && v.role !== 'account').map((v) => key(v.role, v.value)))];
      const allEnts = [...new Set([...vals.map((v) => key(v.role, v.value)),
        ...(real(r.e.host) ? [key('host', r.e.host)] : []), ...(real(r.e.user) ? [key('account', r.e.user)] : [])])];
      const tick = /`([^`]{1,120})`/.exec(r.en.note || '');
      const action = rc?.action ?? { kind: 'event', verb: 'event', object: tick ? tick[1]! : trunc(r.e.msg || r.e.raw, 60) };
      return { ...r, idx, lane, action, ents, allEnts };
    });
    // Links, strongest first. ACTOR: the event was done by a process the timeline has already shown —
    // a child process to the process that spawned it, a file write or a DLL load to the process that
    // did it. Two such events share no file, hash or address, only the relationship, which is why a
    // child process used to float unlinked. SHARED: the most recent earlier events that touched the
    // same specific thing. Host and account are left out: nearly every event shares them, and a link
    // to everything is a link to nothing.
    const lastWith = new Map<string, number>();
    const lastProc = new Map<string, number>();
    const edgeList: MapEdge[] = [];
    for (const it of out) {
      const linked = new Set<number>();
      const actor = (it.action.actor || '').toLowerCase();
      const byActor = actor ? lastProc.get(actor) : undefined;
      if (byActor !== undefined) {
        linked.add(byActor);
        edgeList.push({ a: out[byActor]!.en.eventId, b: it.en.eventId, at: it.idx, kind: 'actor' });
      }
      for (const k of it.ents) {
        const prev = lastWith.get(k);
        if (prev !== undefined && !linked.has(prev) && linked.size < 3) {
          linked.add(prev);
          edgeList.push({ a: out[prev]!.en.eventId, b: it.en.eventId, at: it.idx, kind: 'shared' });
        }
      }
      for (const k of it.ents) lastWith.set(k, it.idx);
      if (it.action.kind === 'process' && it.action.object) lastProc.set(it.action.object.toLowerCase(), it.idx);
    }
    return {
      items: out, lanes: names,
      nodes: out.map((it) => ({ key: it.en.eventId, role: it.action.kind, value: it.action.object || it.action.verb,
        verb: it.action.verb, t: it.t, first: it.idx, lane: it.lane })),
      edges: edgeList,
      hiddenNodes: 0,
    };
  }, [entries, byId, ctxById]);
  const unplaced = entries.length - items.length;
  const anyPrecise = items.some((it) => it.precise);
  const wholeSeconds = items.filter((it) => !it.precise).length;

  const start = items[0]?.t ?? 0;
  const end = items[items.length - 1]?.t ?? 0;
  const padMs = Math.max((end - start) * PAD_SHARE, PAD_MIN_MS);
  const d0 = start - padMs;
  const d1 = end + padMs;
  const autoSpeed = useMemo(() => {
    const need = (d1 - d0) / TARGET_MS;
    return SPEEDS.find((v) => v >= need) ?? SPEEDS[SPEEDS.length - 1]!;
  }, [d0, d1]);

  /* ── the clock ── */
  const [speed, setSpeed] = useState<number>(() =>
    stored(SPEED_KEY, (v) => (SPEEDS.includes(Number(v)) ? Number(v) : undefined), 1));
  const [skipQuiet, setSkipQuietState] = useState<boolean>(() =>
    stored(SKIP_KEY, (v) => (v === '1' ? true : v === '0' ? false : undefined), true));
  const setSkipQuiet = (on: boolean) => { remember(SKIP_KEY, on ? '1' : '0'); setSkipQuietState(on); };
  // Autoplay, but only once the exact instants have arrived: starting on whole seconds and then
  // shifting every event by its milliseconds mid-replay would be the inaccuracy this view exists to avoid.
  const [playing, setPlaying] = useState(false);
  const autostarted = useRef(false);
  const [t, setT] = useState(d0);
  // The replay time at a wall-clock instant. Every frame derives the time from this, so nothing
  // accumulates and nothing drifts.
  const anchor = useRef({ wall: performance.now(), t: d0 });
  const tRef = useRef(t);
  tRef.current = t;
  const seek = useCallback((x: number) => {
    const c = Math.min(d1, Math.max(d0, x));
    anchor.current = { wall: performance.now(), t: c };
    setT(c);
  }, [d0, d1]);
  const startAt = Math.max(d0, start - LEAD_IN_MS * speed);
  const startRef = useRef(startAt);
  startRef.current = startAt;
  // A different sequence (a case switch, an entry added or removed) starts again from the top.
  useEffect(() => { seek(startRef.current); }, [d0, d1, seek]);
  useEffect(() => {
    if (autostarted.current || ctx.isLoading || !items.length) return;
    autostarted.current = true;
    seek(startRef.current);
    setPlaying(true);
  }, [ctx.isLoading, items.length, seek, d0]);
  const changeSpeed = (v: number) => {       // a new speed must not move the playhead
    anchor.current = { wall: performance.now(), t: tRef.current };
    remember(SPEED_KEY, String(v));
    setSpeed(v);
  };
  const play = () => {
    const from = tRef.current >= d1 ? startRef.current : tRef.current;   // from the end = watch again
    anchor.current = { wall: performance.now(), t: from };
    setT(from);
    setPlaying(true);
  };
  const toggle = () => (playing ? setPlaying(false) : play());
  const reached = reachedBy(items, t);
  const [skipped, setSkipped] = useState<Set<number>>(() => new Set());
  useEffect(() => { setSkipped(new Set()); }, [items, skipQuiet]);

  useEffect(() => {
    if (!playing || !items.length) return;
    let raf = 0;
    const tick = () => {
      const now = performance.now();
      let nt = anchor.current.t + (now - anchor.current.wall) * speed;
      if (skipQuiet) {
        const k = reachedBy(items, nt);
        const next = items[k];
        const prevT = k > 0 ? items[k - 1]!.t : d0;
        if (next && (next.t - prevT) / speed > QUIET_MS && (nt - prevT) / speed >= QUIET_HOLD_MS) {
          const land = next.t - QUIET_LEAD_MS * speed;
          if (land > nt) {
            nt = land;
            anchor.current = { wall: now, t: nt };
            setSkipped((s) => (s.has(k) ? s : new Set(s).add(k)));
          }
        }
      }
      if (nt >= d1) { setT(d1); setPlaying(false); return; }
      setT(nt);
      raf = requestAnimationFrame(tick);
    };
    anchor.current = { wall: performance.now(), t: tRef.current };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [playing, speed, skipQuiet, items, d0, d1]);

  const stepNext = () => {
    const k = reachedBy(items, tRef.current);
    if (k < items.length) seek(items[k]!.t);
  };
  const stepPrev = () => {
    const k = reachedBy(items, tRef.current);
    seek(k >= 2 ? items[k - 2]!.t : startRef.current);   // back to the event BEFORE the one on screen
  };

  /* ── the milestone callout: shown for a few seconds of SCREEN time when a moment carries one ── */
  const [flare, setFlare] = useState<{ id: string; text: string; tone: string; clock: string } | null>(null);
  const lastFlare = useRef(-1);
  const flareTimer = useRef(0);
  useEffect(() => () => window.clearTimeout(flareTimer.current), []);
  useEffect(() => {
    if (reached === 0 || reached - 1 === lastFlare.current) return;
    lastFlare.current = reached - 1;
    const it = items[reached - 1]!;
    const b = milestone(it);
    if (!b) return;
    // The timer outlives this effect on purpose: the NEXT event (with no milestone of its own) must
    // not cancel it, or the callout would stay up for good.
    window.clearTimeout(flareTimer.current);
    setFlare({ id: it.en.eventId, text: b.text, tone: beatTone(b), clock: utcParts(it.t).clock });
    flareTimer.current = window.setTimeout(() => setFlare(null), FLARE_MS);
  }, [reached, items]);

  /* ── the scrub track ── */
  const trackRef = useRef<HTMLDivElement>(null);
  const pct = (x: number) => (d1 > d0 ? ((x - d0) / (d1 - d0)) * 100 : 0);
  const fromPointer = (clientX: number): number => {
    const el = trackRef.current;
    if (!el) return tRef.current;
    const r = el.getBoundingClientRect();
    const px = Math.min(r.width, Math.max(0, clientX - r.left));
    let best = d0 + (px / r.width) * (d1 - d0);
    let bestPx = SNAP_PX;
    for (const it of items) {
      const dpx = Math.abs(((it.t - d0) / (d1 - d0)) * r.width - px);
      if (dpx <= bestPx) { best = it.t; bestPx = dpx; }
    }
    return best;
  };
  const dragging = useRef<{ wasPlaying: boolean } | null>(null);
  const onPointerDown = (ev: ReactPointerEvent<HTMLDivElement>) => {
    ev.currentTarget.setPointerCapture(ev.pointerId);
    dragging.current = { wasPlaying: playing };
    setPlaying(false);
    seek(fromPointer(ev.clientX));
  };
  const onPointerMove = (ev: ReactPointerEvent<HTMLDivElement>) => { if (dragging.current) seek(fromPointer(ev.clientX)); };
  const onPointerUp = () => {
    const d = dragging.current;
    dragging.current = null;
    if (d?.wasPlaying && tRef.current < d1) {
      anchor.current = { wall: performance.now(), t: tRef.current };
      setPlaying(true);
    }
  };
  const onKey = (ev: ReactKeyboardEvent) => {
    const k = ev.key;
    if (k === 'ArrowRight') stepNext();
    else if (k === 'ArrowLeft') stepPrev();
    else if (k === 'Home') seek(startRef.current);
    else if (k === 'End') seek(d1);
    else if (k === ' ' || k === 'k') toggle();
    else return;
    ev.preventDefault();
  };

  /* ── full screen: the replay is something to watch, and the page around it is not ── */
  const rootRef = useRef<HTMLElement>(null);
  const [full, setFull] = useState(false);
  useEffect(() => {
    const on = () => setFull(document.fullscreenElement === rootRef.current);
    document.addEventListener('fullscreenchange', on);
    return () => document.removeEventListener('fullscreenchange', on);
  }, []);
  const toggleFull = () => {
    try {
      if (document.fullscreenElement) void document.exitFullscreen();
      else void rootRef.current?.requestFullscreen();
    } catch { /* not allowed here: the page stays as it is */ }
  };

  /* ── figures derived from where the playhead is ── */
  const cur = reached > 0 ? items[reached - 1]! : undefined;
  const current = useMemo(() => new Set(cur ? [cur.en.eventId] : []), [cur]);
  const phaseStats = useMemo(() => lanes.map((name, li) => {
    const mine = items.filter((it) => it.lane === li);
    const done = mine.filter((it) => it.idx < reached).length;
    const lead = mine[0];
    return { name, li, total: mine.length, done, first: lead?.t ?? 0, last: mine[mine.length - 1]?.t ?? 0,
      desc: lead ? plain(lead.said || lead.e.msg) : '', ticks: mine.map((it) => ({ t: it.t, on: it.idx < reached })) };
  }), [lanes, items, reached]);
  const footprint = useMemo(() => {
    const seen = new Set<string>();
    for (const it of items) if (it.idx < reached) for (const k of it.allEnts) seen.add(k);
    const by = new Map<string, number>();
    for (const k of seen) { const kind = k.slice(0, k.indexOf(':')); by.set(kind, (by.get(kind) ?? 0) + 1); }
    return { n: seen.size, parts: [...by.entries()].map(([k, v]) => `${v} ${k}${v === 1 ? '' : k.endsWith('s') ? 'es' : 's'}`) };
  }, [items, reached]);
  const tempo = useMemo(() => {
    const B = Math.min(12, Math.max(4, items.length));
    const w = Math.max(1, end - start) / B;
    const bins = Array.from({ length: B }, (_, i) => ({ from: start + i * w, n: 0, done: 0 }));
    for (const it of items) {
      const b = bins[Math.min(B - 1, Math.floor((it.t - start) / w))]!;
      b.n += 1;
      if (it.idx < reached) b.done += 1;
    }
    return { bins, max: Math.max(1, ...bins.map((b) => b.n)), w };
  }, [items, start, end, reached]);
  const curBin = cur ? Math.min(tempo.bins.length - 1, Math.floor((cur.t - start) / tempo.w)) : -1;

  if (!items.length) {
    return (
      <EmptyState title="Nothing to replay"
        body={entries.length
          ? 'None of the events on this timeline has a parsed timestamp, so none of them can be placed on a clock. Enriching their sources gives them one.'
          : 'Add events to the timeline first.'} />
    );
  }

  const now = utcParts(t);
  const next = items[reached];
  const ended = t >= d1;
  const c = kase.data;
  const phaseNow = cur ? phaseStats[cur.lane] : undefined;
  const lede = (c?.summary || '').split(/(?<=[.!?])\s+/).slice(0, 2).join(' ');

  return (
    <section className={cx('rp', full && 'rp--full')} ref={rootRef} aria-label="Timeline replay">
      {/* ── header ── */}
      <header className="rp-hero">
        <div className="rp-kicker">Incident replay · {c?.id ?? 'case'} · reconstructed from {items.length} curated event{items.length === 1 ? '' : 's'}</div>
        <h2 className="rp-title">{c?.name || 'Case timeline'}</h2>
        <p className="rp-lede">{lede || 'Press play to watch it unfold, at the pace it actually happened.'}</p>
        <div className="rp-chips">
          <span className="rp-chip"><b>{utcParts(start).day}</b>{utcParts(start).day !== utcParts(end).day ? <> → <b>{utcParts(end).day}</b></> : null} UTC</span>
          <span className="rp-chip"><b>{dur(end - start)}</b> span</span>
          <span className="rp-chip"><b>{items.length}</b> events</span>
          <span className="rp-chip"><b>{lanes.length}</b> phase{lanes.length === 1 ? '' : 's'}</span>
          <span className="rp-chip"><b>{nodes.length + hiddenNodes}</b> entities</span>
          <span style={{ flex: 1 }} />
          <button className="btn btn--sm" onClick={toggleFull} title={full ? 'Leave full screen (Esc)' : 'Watch in full screen'}>
            {full ? 'Exit full screen' : 'Full screen'}
          </button>
        </div>
      </header>

      {/* ── console: transport, speed, clock, scrub ── */}
      <div className="rp-console">
        <div className="rp-console__top">
          <div className="rp-transport">
            <button className="rp-playbtn" onClick={toggle}
              aria-label={playing ? 'Pause' : ended ? 'Replay again' : 'Play'}
              title={playing ? 'Pause (space)' : ended ? 'Replay from the start' : 'Play (space)'}>
              {playing ? <Icon.Pause width={16} height={16} /> : ended ? <Icon.Restart width={16} height={16} /> : <Icon.Play width={16} height={16} />}
            </button>
            <button className="btn btn--icon" onClick={stepPrev} title="Previous event (←)" aria-label="Previous event"><Icon.StepBack /></button>
            <button className="btn btn--icon" onClick={stepNext} disabled={!next} title="Next event (→)" aria-label="Next event"><Icon.StepFwd /></button>
            <button className="btn" onClick={() => { seek(startRef.current); setPlaying(true); }} title="Restart from the beginning">
              <Icon.Restart /> Restart
            </button>
          </div>
          <div className="rp-speeds" role="group" aria-label="Replay speed">
            {SPEED_SEGS.map((v) => (
              <button key={v} className={cx(speed === v && 'on')} aria-pressed={speed === v} onClick={() => changeSpeed(v)}
                title={rateLabel(v)}>{v}×</button>
            ))}
            <select value={SPEED_SEGS.includes(speed) ? '' : String(speed)} aria-label="Other speeds"
              onChange={(e) => e.target.value && changeSpeed(Number(e.target.value))}>
              <option value="">more…</option>
              {SPEEDS.filter((v) => !SPEED_SEGS.includes(v)).map((v) => (
                <option key={v} value={v}>{rateLabel(v)}{v === autoSpeed ? ' · whole span in ~1 min' : ''}</option>
              ))}
            </select>
          </div>
          <label className="rp-skip"
            title="Jump over any gap that would take more than 8 seconds on screen. Moments reached by a jump are marked, so a skipped gap never looks like a short one.">
            <input type="checkbox" checked={skipQuiet} onChange={(e) => setSkipQuiet(e.target.checked)} />
            Skip quiet stretches
          </label>
          <div className="rp-clock" aria-live="off">
            <div className="rp-clock__t mono">{now.day} {now.clock}<span className="rp-clock__ms">{now.ms}</span></div>
            <div className="rp-clock__d mono">
              {tOffset(t - start)} · phase {cur ? cur.lane + 1 : 0} / {lanes.length} · UTC
            </div>
          </div>
        </div>
        <div className="rp-scrub">
          <div className="rp-track" ref={trackRef} role="slider" tabIndex={0}
            aria-label="Replay position" aria-valuemin={0} aria-valuemax={items.length} aria-valuenow={reached}
            aria-valuetext={`${now.clock} UTC, ${reached} of ${items.length} events`}
            onPointerDown={onPointerDown} onPointerMove={onPointerMove} onPointerUp={onPointerUp}
            onPointerCancel={onPointerUp} onKeyDown={onKey}>
            <div className="rp-track__bar" />
            <div className="rp-track__fill" style={{ width: `${pct(t)}%` }} />
            {items.map((it) => (
              <span key={it.en.eventId} className={cx('rp-tick', it.idx < reached && 'rp-tick--on')}
                style={{ left: `${pct(it.t)}%`, background: PHASE_HUES[it.lane % PHASE_HUES.length] }}
                title={`${utcParts(it.t).clock} UTC — ${it.said || it.e.msg}`} />
            ))}
            <span className="rp-thumb" style={{ left: `${pct(t)}%` }} />
          </div>
          <div className="rp-axis mono">
            <span>{utcParts(start).clock}</span>
            <span className="rp-axis__mid">
              {next ? <>next in <b>{dur(next.t - t)}</b>{speed !== 1 ? ` · ${dur((next.t - t) / speed)} on screen` : ''}</>
                : ended ? 'end of the timeline' : 'every event has happened'}
            </span>
            <span>{utcParts(end).clock}</span>
          </div>
        </div>
      </div>

      {ctx.isLoading && <Loading inline label="Reading each event's exact instant and first sightings…" />}

      {/* ── three running figures ── */}
      <div className="rp-stats">
        <div className="rp-stat rp-stat--count">
          <div className="rp-stat__lab">Events replayed</div>
          <div className="rp-stat__big mono">{reached}</div>
          <div className="rp-stat__sub">of {items.length} on the timeline{skipped.size ? ` · ${skipped.size} lull${skipped.size === 1 ? '' : 's'} skipped` : ''}</div>
        </div>
        <div className="rp-stat" style={{ ['--c' as string]: cur ? PHASE_HUES[cur.lane % PHASE_HUES.length] : 'var(--muted-2)' }}>
          <div className="rp-stat__lab">Active phase</div>
          <div className="rp-stat__big rp-stat__big--word">{phaseNow ? phaseNow.name : '—'}</div>
          <div className="rp-stat__sub">{phaseNow ? `${phaseNow.done} of ${phaseNow.total} events · since ${utcParts(phaseNow.first).clock}` : 'awaiting the first event'}</div>
        </div>
        <div className="rp-stat">
          <div className="rp-stat__lab">Footprint</div>
          <div className="rp-stat__big mono">{footprint.n}</div>
          <div className="rp-stat__sub">{footprint.n ? `entities reached · ${footprint.parts.join(' · ')}` : 'nothing reached yet'}</div>
        </div>
      </div>

      {/* ── the map: the full width, because it holds every event ── */}
      <div className="rp-card rp-card--map">
          <div className="rp-card__hd"><span className="rp-mk" /><h3>What it reached</h3>
            <span className="rp-tagline">every event, drawn as it happens · linked by what they share</span></div>
          {/* The milestone line has a place of its own: floated over the map it covered the very
              nodes it was talking about. Fixed height, so a callout arriving never moves the map. */}
          <div className={cx('rp-callout', flare && `rp-callout--${flare.tone}`)} role="status">
            {flare ? (
              <span key={flare.id} className="rp-callout__in">
                <span className="rp-callout__t mono">{flare.clock}</span>
                <span className="rp-callout__x">{inlineMd(flare.text, `rpf-${flare.id}`)}</span>
              </span>
            ) : <span className="rp-callout__idle">Milestones are called out here as they happen: first sightings, accounts, persistence, detections.</span>}
          </div>
          <div className="rp-mapwrap">
            <AttackMap nodes={nodes} edges={edges} lanes={lanes} reached={reached} current={current} hidden={hiddenNodes} />
          </div>
      </div>

      {/* ── the live stream, and beside it the phases and the activity over time ── */}
      <div className="rp-stage rp-stage--2">
        <div className="rp-card">
          <div className="rp-card__hd"><span className="rp-mk" style={{ background: '#d8974f' }} /><h3>Live event stream</h3>
            <span className="rp-tagline">every event, newest first · scroll for the rest</span></div>
          <div className="rp-logwrap"><Stream items={items} reached={reached} skipped={skipped} onOpen={onOpen} /></div>
        </div>
        <div className="rp-side">
        <div className="rp-card">
          <div className="rp-card__hd"><span className="rp-mk" style={{ background: '#6f9fd8' }} /><h3>Phase activity</h3>
            <span className="rp-tagline">first seen → last seen, to scale</span></div>
          <PhaseActivity phases={phaseStats} active={cur ? cur.lane : -1} pct={pct} headPct={pct(t)} />
        </div>
        <div className="rp-card">
          <div className="rp-card__hd"><span className="rp-mk" style={{ background: '#cbb96e' }} /><h3>Activity over time</h3>
            <span className="rp-tagline">events per {dur(tempo.w)}</span></div>
          <div className="rp-tempo">
            <div className="rp-bars">
              {tempo.bins.map((b, i) => (
                <div key={i} className={cx('rp-bin', i === curBin && 'rp-bin--cur', b.done === b.n && b.n > 0 && i !== curBin && 'rp-bin--done')}
                  title={`${utcParts(b.from).clock} — ${b.n} event${b.n === 1 ? '' : 's'}`}>
                  <span className="rp-bin__v mono">{b.n || ''}</span>
                  <span className="rp-bin__bg"><span className="rp-bin__bar" style={{ height: `${(b.done / tempo.max) * 100}%` }} />
                    <span className="rp-bin__ghost" style={{ height: `${(b.n / tempo.max) * 100}%` }} /></span>
                </div>
              ))}
            </div>
            <div className="rp-axis mono"><span>{utcParts(start).clock}</span><span>{utcParts(end).clock}</span></div>
            <div className="rp-chapter">
              {phaseNow
                ? <><b>{phaseNow.name}</b> — {inlineMd(trunc(phaseNow.desc, 180), 'rp-chapter')}</>
                : 'The first phase opens with the first event.'}
            </div>
          </div>
        </div>
        </div>
      </div>

      <div className="rp-foot">
        {ctx.isError && <div>The exact instants could not be read, so events play at the start of their second and without observations.</div>}
        {!ctx.isError && wholeSeconds > 0 && anyPrecise && (
          <div>{wholeSeconds} event{wholeSeconds === 1 ? '' : 's'} carr{wholeSeconds === 1 ? 'ies' : 'y'} only a whole second in the log, and play{wholeSeconds === 1 ? 's' : ''} at the start of it.</div>
        )}
        {unplaced > 0 && (
          <div>
            {unplaced} timeline entr{unplaced === 1 ? 'y has' : 'ies have'} no parsed timestamp and
            {unplaced === 1 ? ' is' : ' are'} not in the replay: without a time they cannot be placed on the clock.
            {unplaced === 1 ? ' It is' : ' They are'} still in the list view.
          </div>
        )}
        {ctx.data?.valuesCapped && <div>First sightings were checked for the first {ctx.data.valuesChecked} values only.</div>}
        <div>Times are UTC and to the millisecond where the log recorded one. Timing is real: at 1× the gaps are the real gaps.</div>
      </div>
    </section>
  );
}
