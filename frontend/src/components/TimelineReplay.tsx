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
 * SMOOTHNESS ("the seek bar moves very jaggedly — everything with replay needs to move smoothly"):
 * the playhead is NOT React state. The old loop called setState every frame, so every frame re-rendered
 * the whole replay — map, stream, phases — and on a busy frame the thumb jumped. Now one animation
 * frame loop owns the clock and writes the continuous things straight to the DOM (a `--rp-pu` custom
 * property the fill, thumb and phase heads read; the clock and the countdown text), and React renders
 * only when something DISCRETE changes: an event is reached, the replay ends. A seek glides instead of
 * jumping, a drag is coalesced to one paint per frame, and the pointer snaps to an event only on a
 * click — snapping WHILE dragging is what made the thumb lurch from tick to tick.
 *
 * An entry with no parsed timestamp cannot be placed on a clock. It is counted and named rather than
 * slotted in somewhere, the same rule the list follows when it sorts those entries last.
 */
import { memo, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { CSSProperties, KeyboardEvent as ReactKeyboardEvent, PointerEvent as ReactPointerEvent } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import type { CaseSetEntry, Event, ReplayBeat, ReplayContext, Severity } from '../api/types';
import { useTypewriter } from '../hooks/useArrivals';
import { useCase } from '../hooks/queries';
import { cx } from '../utils/format';
import { inlineMd } from '../utils/markdown';
import { buildScale, fromU, gapLabel, ticks as rulerTicks, toU } from '../utils/replayScale';
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
/** The seek bar starts this long (INCIDENT time) before the first event and ends this long after the
 *  last. It used to be padded by 3 % of the whole span: on a 21-hour case that is 38 minutes of empty
 *  bar before the first event — "a massive space ... it can take a long time to get to the first event". */
const LEAD_MS = 2_500;
const TAIL_MS = 2_500;
/** Pointer within this many pixels of an event snaps the playhead onto it (on a click, not a drag). */
const SNAP_PX = 8;
/** A drag this many pixels long is a drag, not a click. */
const CLICK_PX = 4;
/** How long a seek glides (screen time). */
const GLIDE_MS = 260;
/** Seek-bar zoom: the deepest zoom is this many times the whole bar (the layer that carries the ticks is
 *  that many track-widths wide, and a browser lays out ~33 M px at most), and never under 20 ms. */
const ZOOM_MAX = 10_000;
const ZOOM_MIN_UNITS = 20;
/** A manual pan/zoom holds the view this long before the playhead is followed again. */
const FOLLOW_HOLD_MS = 2_500;
/** A milestone callout stays over the map this long (screen time). */
const FLARE_MS = 3_800;
const UNLABELLED = 'unlabelled';
const SPEED_KEY = 'iris.replay.speed';
const SKIP_KEY = 'iris.replay.skipQuiet';

/* Phase colours: the entity graph's own type hues (GraphScreen TYPE_META), cycled — so the replay
   reads in the same colours as the graph, and never borrows a SEVERITY colour for something that is
   not a severity. */
const PHASE_HUES = ['var(--accent)', '#6f9fd8', '#d8974f', '#a58fd8', '#cbb96e', '#5fb8a8', '#d8707a', '#c98a5f'];
/** What an entity on the map is — again the graph's vocabulary, by type. */
const ROLE_KIND: Record<string, string> = {
  to: 'address', from: 'address', ip: 'address', domain: 'domain', account: 'account', host: 'host',
  process: 'process', file: 'file', hash: 'hash',
};
/** Most specific first: a shared HASH says far more about two events than a shared address does. */
const SPECIFIC = ['hash', 'file', 'process', 'domain', 'address'];

interface Item {
  idx: number;
  order: number;          // position in the timeline (curation order) — the tie-break
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
  raw: boolean;           // its source is not interpreted yet
}
/** One node per EVENT: every event on the timeline is drawn on the map. */
interface MapNode { key: string; role: string; value: string; verb: string; t: number; first: number; lane: number }
/** `actor`: b was done BY a's process (spawned, wrote, loaded, connected); `shared`: they touched the
 *  same thing. `label` is the reason in two or three words, drawn on the line; `detail` the sentence. */
interface MapEdge { a: string; b: string; at: number; kind: 'actor' | 'shared'; label: string; detail: string }

/** THE order, used by every list in the replay: the exact instant, then the timeline's own order. The
 *  stream, the phases, the ticks and the map all come from `items`, which is sorted by this once. */
function byInstant(a: { t: number; order: number }, b: { t: number; order: number }): number {
  return a.t - b.t || a.order - b.order;
}

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
function reducedMotion(): boolean {
  try { return window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch { return false; }
}
const trunc = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
/** Markdown marks off, for a one-line description that is shown as plain text. */
const plain = (s: string) => s.replace(/\*\*|__|`/g, '').replace(/\s+/g, ' ').trim();
const easeOut = (k: number) => 1 - (1 - k) ** 3;

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

/* ───────── connections: FEWER, and each one says WHY ─────────
   "When there are multiple connections and lines, it gets kind of hard to see what is going on. Make
   connections meaningful." A node used to take an actor link plus up to three "shares something"
   links, all unlabelled, so a busy map was a tangle nobody could read. Now each event gets at most TWO
   incoming links, and each carries its reason:
     - ACTOR (solid): the process that did it — "spawned", "wrote", "loaded", "connected to". This is
       causation, the strongest thing the map can say, and it is always kept.
     - SHARED (dashed): ONE link, for the MOST SPECIFIC value it shares with an earlier event (a hash
       before a file before a process before a domain before an address), to the most recent event
       carrying it — so a value that recurs reads as a chain, not as a fan of lines to every earlier
       sighting. Host and account are never linked on: nearly everything shares them. An event that already
       has an actor link gets a shared one only for a hash or a file.
   The labels are drawn only on the links of the event in focus (the one being played, or the one
   under the pointer), and everything else steps back — a label on every line is a label on none. */
function actorLabel(kind: string, verb: string): string {
  switch (kind) {
    case 'process': return 'spawned';
    case 'execution': return 'ran';
    case 'library': return 'loaded';
    case 'delete': return 'deleted';
    case 'network': return 'connected to';
    case 'dns': return 'looked up';
    case 'web': case 'download': return 'fetched';
    case 'registry': return 'wrote registry';
    case 'file': {
      const v = verb.replace(/^file\s+/i, '').split(/\s*&\s*/)[0] ?? '';
      return v && v !== 'file' ? v : 'touched';
    }
    default: return 'then';
  }
}
function buildEdges(out: Item[], display: Map<string, string>): MapEdge[] {
  const lastWith = new Map<string, number>();
  const lastProc = new Map<string, number>();
  const edges: MapEdge[] = [];
  for (const it of out) {
    const actorName = it.action.actor || '';
    const byActor = actorName ? lastProc.get(actorName.toLowerCase()) : undefined;
    if (byActor !== undefined) {
      const label = actorLabel(it.action.kind, it.action.verb);
      edges.push({ a: out[byActor]!.en.eventId, b: it.en.eventId, at: it.idx, kind: 'actor', label,
        detail: `${actorName} ${label} ${it.action.object || it.action.verb}` });
    }
    let best: { prev: number; k: string; rank: number } | null = null;
    for (const k of it.ents) {
      const prev = lastWith.get(k);
      if (prev === undefined || prev === byActor) continue;
      const kind = k.slice(0, k.indexOf(':'));
      const r = SPECIFIC.indexOf(kind);
      const rank = r < 0 ? SPECIFIC.length : r;
      if (!best || rank < best.rank || (rank === best.rank && prev > best.prev)) best = { prev, k, rank };
    }
    // With a causal link already drawn, a shared ADDRESS or DOMAIN adds a line and little meaning (the
    // same process talks to the same server again); only a shared hash or file still earns one.
    if (best && byActor !== undefined && best.rank > 1) best = null;
    if (best) {
      const kind = best.k.slice(0, best.k.indexOf(':'));
      const value = display.get(best.k) ?? best.k.slice(kind.length + 1);
      edges.push({ a: out[best.prev]!.en.eventId, b: it.en.eventId, at: it.idx, kind: 'shared',
        label: `same ${kind}`, detail: `both involve ${kind} ${value}` });
    }
    for (const k of it.ents) lastWith.set(k, it.idx);
    if (it.action.kind === 'process' && it.action.object) lastProc.set(it.action.object.toLowerCase(), it.idx);
  }
  return edges;
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
 *  node only ever moves when a zone to its LEFT gains a column — and when it does, it GLIDES there. */
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

/** A path as a CSS `d` value, so a line whose end moved GLIDES to its new route (CSS transitions `d`)
 *  instead of snapping. The attribute is set too, for an engine without CSS `d`. */
const pathStyle = (d: string): CSSProperties => ({ d: `path("${d}")` } as unknown as CSSProperties);

const AttackMap = memo(function AttackMap({ nodes, edges, lanes, reached, current }: {
  nodes: MapNode[]; edges: MapEdge[]; lanes: string[]; reached: number; current: string | null;
}) {
  const shown = useMemo(() => nodes.filter((n) => n.first < reached), [nodes, reached]);
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
  // Focus: the event under the pointer, else one the analyst clicked, else the one being played.
  const [hover, setHover] = useState<string | null>(null);
  const [pinned, setPinned] = useState<string | null>(null);
  const focus = hover ?? pinned ?? current;
  const chosen = hover != null || pinned != null;
  const { pos, zones: open } = useMemo(() => layoutMap(shown, lanes, avail), [shown, lanes, avail]);
  const contentW = open.length ? Math.max(...open.map((z) => z.x + z.w)) + ZONE_PAD : 0;
  const contentH = open.length ? Math.max(...open.map((z) => z.y + z.h)) + ZONE_PAD : 0;
  const vbW = Math.max(contentW, avail);        // wider only when one zone alone cannot fit
  const overflow = vbW > avail + 1;

  /* ── connections ──
     Ports: a node with several links spreads them down its side instead of sending every one from
     the same point. Lines leave and arrive HORIZONTALLY, so the curve reads as a flow from one phase
     into the next. A link inside one phase runs as a bracket down the zone's left margin rather than
     looping over the node text. The head is drawn separately from the line, so it can arrive AFTER
     the line has drawn itself. */
  const visibleEdges = useMemo(
    () => edges.filter((ed) => ed.at < reached && pos.has(ed.a) && pos.has(ed.b)),
    [edges, reached, pos]);
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
        // Ordered by where the OTHER end is, so two lines leaving one node never cross each other.
        g.sort((x, y) => (pos.get(x[other])!.y - pos.get(y[other])!.y) || (pos.get(x[other])!.x - pos.get(y[other])!.x));
        const step = g.length > 1 ? Math.min(8, (NODE_H - 12) / (g.length - 1)) : 0;
        g.forEach((ed, i) => out.set(`${k}|${ed.a}|${ed.b}`, (i - (g.length - 1) / 2) * step));
      }
    };
    spread(visibleEdges, 'a');
    spread(visibleEdges, 'b');
    return out;
  }, [visibleEdges, pos]);
  const route = (ed: MapEdge): { d: string; head: string; mid: { x: number; y: number } } => {
    const a = pos.get(ed.a)!; const b = pos.get(ed.b)!;
    const oa = ports.get(`${ed.a}|a|${ed.a}|${ed.b}`) ?? 0;
    const ob = ports.get(`${ed.b}|b|${ed.a}|${ed.b}`) ?? 0;
    const ya = a.y + NODE_H / 2 + oa;
    const yb = b.y + NODE_H / 2 + ob;
    const H = 5.5;   // arrowhead half-height
    // The label sits at the curve's own midpoint: B(½) = (P0 + 3·P1 + 3·P2 + P3) / 8.
    const bez = (x0: number, x1: number, x2: number, x3: number, y0: number, y3: number) =>
      ({ x: (x0 + 3 * x1 + 3 * x2 + x3) / 8, y: (y0 + 3 * y0 + 3 * y3 + y3) / 8 });
    if (Math.abs(a.x - b.x) < 1) {                 // same phase column: a bracket in the left margin
      const x = a.x - 2; const bx = x - 12 - Math.abs(ob) * 0.4;
      const xe = b.x - 1;
      return { d: `M${x},${ya} C${bx},${ya} ${bx},${yb} ${xe - 7},${yb}`,
        head: `M${xe - 8},${yb - H} L${xe},${yb} L${xe - 8},${yb + H} Z`, mid: bez(x, bx, bx, xe - 7, ya, yb) };
    }
    if (a.x < b.x) {                               // into a later phase, left to right
      const x1 = a.x + NODE_W; const x2 = b.x - 1;
      const dx = Math.max(26, (x2 - x1) * 0.5);
      return { d: `M${x1},${ya} C${x1 + dx},${ya} ${x2 - dx},${yb} ${x2 - 7},${yb}`,
        head: `M${x2 - 8},${yb - H} L${x2},${yb} L${x2 - 8},${yb + H} Z`, mid: bez(x1, x1 + dx, x2 - dx, x2 - 7, ya, yb) };
    }
    const x1 = a.x; const x2 = b.x + NODE_W + 1;   // back into an earlier phase, right to left
    const dx = Math.max(26, (x1 - x2) * 0.5);
    return { d: `M${x1},${ya} C${x1 - dx},${ya} ${x2 + dx},${yb} ${x2 + 7},${yb}`,
      head: `M${x2 + 8},${yb - H} L${x2},${yb} L${x2 + 8},${yb + H} Z`, mid: bez(x1, x1 - dx, x2 + dx, x2 + 7, ya, yb) };
  };
  const laneOfNode = useMemo(() => new Map(nodes.map((n) => [n.key, n.lane])), [nodes]);
  // The events joined to the focus, so the rest of the map can step back.
  const near = useMemo(() => {
    const s = new Set<string>();
    if (focus) {
      s.add(focus);
      for (const ed of visibleEdges) if (ed.a === focus || ed.b === focus) { s.add(ed.a); s.add(ed.b); }
    }
    return s;
  }, [focus, visibleEdges]);
  if (!nodes.length) {
    return <div className="rp-map__empty">No hosts, addresses, accounts or files were identified on these events.</div>;
  }
  const hot = (ed: MapEdge) => focus != null && (ed.a === focus || ed.b === focus);
  // Links keep ONE order in the DOM. Raising the focused ones to the top re-inserts their elements,
  // and a re-inserted element replays its entrance - every line would redraw itself on every event.
  // The stepped-back lines are faint enough that a focused one reads through them.
  const ordered = visibleEdges;
  return (
    <div className={cx('rp-mapview', overflow && 'rp-mapview--scroll', chosen && 'rp-mapview--chosen')} ref={box}
      onPointerLeave={() => setHover(null)}>
      {shown.length === 0 ? (
        <div className="rp-map__wait" style={{ height: MAP_EMPTY_H }}>
          The map builds as the replay reaches each host, address, account and file.
        </div>
      ) : (
        // The FRAME eases to its new height (CSS), so the map grows instead of jumping; the drawing
        // inside is always at its natural size and never re-scaled mid-play.
        <div className="rp-mapframe" style={{ height: contentH, width: vbW }}>
          <svg className="rp-map" width={vbW} height={contentH} viewBox={`0 0 ${vbW} ${contentH}`}
            role="img" aria-label={`Map of the ${shown.length} events the replay has reached so far, grouped by phase`}>
            {open.map((z) => (
              <g key={z.lane} className="rp-zone" style={{ ['--c' as string]: PHASE_HUES[z.lane % PHASE_HUES.length] }}>
                <rect x={z.x} y={z.y} width={z.w} height={z.h} rx={10} className="rp-zone__box" />
                <circle cx={z.x + 14} cy={z.y + 14} r={3.5} className="rp-zone__dot" />
                <text x={z.x + 24} y={z.y + 18}>{trunc(z.name, Math.floor(z.w / 7.5))}</text>
              </g>
            ))}
            {ordered.map((ed) => {
              const { d, head } = route(ed);
              const on = hot(ed);
              return (
                <g key={`${ed.a}|${ed.b}`}
                  className={cx('rp-link', `rp-link--${ed.kind}`, on && 'rp-link--hot', !on && focus && 'rp-link--back')}
                  style={{ ['--c' as string]: PHASE_HUES[(laneOfNode.get(ed.b) ?? 0) % PHASE_HUES.length] }}>
                  <title>{ed.detail}</title>
                  {/* an actor link draws itself (a normalised dash); a shared one is DASHED, so it fades in */}
                  <path className="rp-edge" d={d} style={pathStyle(d)} pathLength={ed.kind === 'actor' ? 1 : undefined} />
                  <path className="rp-arrowhead" d={head} style={pathStyle(head)} />
                </g>
              );
            })}
            {shown.map((n) => {
              const p = pos.get(n.key)!;
              const meta = ACTION_META[n.role] ?? ACTION_META.event!;
              const c = utcParts(n.t);
              const dim = chosen && !near.has(n.key);
              return (
                <g key={n.key} className={cx('rp-nodepos', dim && 'rp-nodepos--dim')} style={{ transform: `translate(${p.x}px, ${p.y}px)`, ['--c' as string]: meta.hue }}
                  onPointerEnter={() => setHover(n.key)}
                  onClick={() => setPinned((cur) => (cur === n.key ? null : n.key))}>
                  <g className={cx('rp-node', n.key === current && 'rp-node--now', n.key === focus && chosen && 'rp-node--focus')}>
                    <title>{`${c.clock}${c.ms} UTC — ${n.verb}: ${n.value}${pinned === n.key ? ' (click again to release)' : ' (click to hold its links)'}`}</title>
                    <rect className="rp-node__box" width={NODE_W} height={NODE_H} rx={9} />
                    <circle className="rp-node__badge" cx={21} cy={NODE_H / 2} r={11.5} />
                    <text className="rp-node__glyph" x={21} y={NODE_H / 2 + 3.5} textAnchor="middle">{meta.glyph}</text>
                    <text className="rp-node__title" x={40} y={19}>{trunc(n.value, 20)}</text>
                    <text className="rp-node__sub" x={40} y={33}>{trunc(n.verb, 17)} · {c.clock}</text>
                  </g>
                </g>
              );
            })}
            {/* The reasons, on the focus's links only, above everything so a node never hides one. */}
            {ordered.filter(hot).map((ed) => {
              const { mid } = route(ed);
              const w = Math.round(ed.label.length * 6.1 + 14);
              return (
                <g key={`l|${ed.a}|${ed.b}`} className={cx('rp-elabel', `rp-elabel--${ed.kind}`)}
                  style={{ transform: `translate(${mid.x}px, ${mid.y}px)`, ['--c' as string]: PHASE_HUES[(laneOfNode.get(ed.b) ?? 0) % PHASE_HUES.length] }}>
                  <title>{ed.detail}</title>
                  <rect x={-w / 2} y={-9} width={w} height={18} rx={4} />
                  <text x={0} y={3.5} textAnchor="middle">{ed.label}</text>
                </g>
              );
            })}
          </svg>
        </div>
      )}
    </div>
  );
});

/* ───────── phase activity: a phase opens when the replay enters it ───────── */
interface PhaseStat {
  name: string; li: number; total: number; done: number; first: number; last: number; desc: string;
  ticks: { t: number; on: boolean }[];
}
const PhaseActivity = memo(function PhaseActivity({ phases, active, pct, newestFirst }: {
  phases: PhaseStat[]; active: number; pct: (t: number) => number; newestFirst: boolean;
}) {
  // The same order as the stream and the list: by when the phase OPENED, flipped with "newest first".
  const open = phases.filter((ph) => ph.done > 0).sort((a, b) => a.first - b.first || a.li - b.li);
  if (newestFirst) open.reverse();
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
            <div className="rp-phase__bar"><span style={{ transform: `scaleX(${ph.done / ph.total})` }} /></div>
            <div className="rp-phase__trk" aria-hidden>
              {ph.ticks.map((tk, i) => (
                <span key={i} className={cx('rp-phase__tick', tk.on && 'rp-phase__tick--on')} style={{ left: `${pct(tk.t)}%` }} />
              ))}
              {/* driven by --rp-pu on the replay root: moves every frame without a render */}
              <span className="rp-phase__head" />
            </div>
          </div>
        );
      })}
      {ahead > 0 && <div className="rp-phases__ahead">{ahead} more phase{ahead === 1 ? '' : 's'} ahead</div>}
    </div>
  );
});

/* ───────── the live stream: typed in as it happens, in the timeline's order ───────── */
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
const Stream = memo(function Stream({ items, reached, skipped, onOpen, newestFirst }: {
  items: Item[]; reached: number; skipped: Set<number>; onOpen: (id: string) => void; newestFirst: boolean;
}) {
  // Remember which rows were already on screen: only a row that ARRIVES is typed in. A seek or a
  // step back re-mounts rows, and retyping a screenful of history would be noise.
  const seen = useRef<Set<string>>(new Set());
  const wrap = useRef<HTMLDivElement>(null);
  const atEdge = useRef(true);         // following the newest row (top or bottom, by the order)
  const done = items.slice(0, reached);
  const shown = newestFirst ? [...done].reverse() : done;
  useEffect(() => { for (const it of shown) seen.current.add(it.en.eventId); });
  // Oldest first puts the newest row at the BOTTOM: follow it there, smoothly, unless the analyst has
  // scrolled up to read something (then stay put — yanking the view away mid-read is worse).
  useLayoutEffect(() => {
    const el = wrap.current;
    if (!el || !atEdge.current) return;
    const top = newestFirst ? 0 : el.scrollHeight;
    el.scrollTo({ top, behavior: reducedMotion() ? 'auto' : 'smooth' });
  }, [reached, newestFirst]);
  const onScroll = () => {
    const el = wrap.current;
    if (!el) return;
    atEdge.current = newestFirst ? el.scrollTop < 40 : el.scrollHeight - el.clientHeight - el.scrollTop < 60;
  };
  return (
    <div className="rp-logwrap" ref={wrap} onScroll={onScroll}>
      {!shown.length ? <div className="rp-log rp-log--idle">Waiting for the first event…</div> : (
        <div className="rp-log" aria-live="polite" aria-relevant="additions">
          {shown.map((it, i) => {
            const age = newestFirst ? i : shown.length - 1 - i;
            return (
              <StreamLine key={it.en.eventId} it={it} age={age} skipped={skipped.has(it.idx)} onOpen={onOpen}
                fresh={age === 0 && !seen.current.has(it.en.eventId)} />
            );
          })}
        </div>
      )}
    </div>
  );
});

/** Poll while the answer is still moving: after a restart the pool loads and sources are interpreted
 *  in the background, and the replay used to keep the first, link-less answer for good. */
function replayPoll(d: ReplayContext | undefined): number | false {
  if (!d) return false;
  if (d.poolLoading || d.missing || d.awaiting) return 2_500;
  if (d.rawEvents) return 10_000;
  return false;
}

/* ───────── the replay ───────── */
export function TimelineReplay({ entries, byId, onOpen, newestFirst = false }: {
  /** The timeline's entries, oldest first. */
  entries: CaseSetEntry[];
  byId: Map<string, Event>;
  onOpen: (eventId: string) => void;
  /** The timeline's own order setting: the live stream and the phase list follow it. */
  newestFirst?: boolean;
}) {
  const kase = useCase();
  const qc = useQueryClient();
  // The exact instants and the observations. Keyed under the case set, so anything that changes the
  // case set (an entry added, a note edited) refetches this too.
  const ctx = useQuery({ queryKey: ['case-set', 'replay'], queryFn: api.caseSetReplay, staleTime: 30_000,
    refetchInterval: (q) => replayPoll(q.state.data) });
  const ctxById = useMemo(() => new Map((ctx.data?.events ?? []).map((x) => [x.eventId, x])), [ctx.data]);
  // The events themselves (`byId`) come from the case-set list. When the POOL under the replay moved
  // (a source was interpreted, the library finished loading), that list is stale too: re-read it, or the
  // replay would pair new links with the old, raw events.
  const seenVersion = useRef<number | undefined>(undefined);
  useEffect(() => {
    const v = ctx.data?.version;
    if (v === undefined) return;
    if (seenVersion.current !== undefined && seenVersion.current !== v) {
      void qc.invalidateQueries({ queryKey: ['case-set'], exact: true });
    }
    seenVersion.current = v;
  }, [ctx.data?.version, qc]);

  /* ── the sequence, its phases and the entities it reaches ── */
  const { items, lanes, nodes, edges } = useMemo(() => {
    const raw: Omit<Item, 'lane' | 'idx' | 'ents' | 'allEnts' | 'action'>[] = [];
    entries.forEach((en, order) => {
      const e = byId.get(en.eventId);
      const rc = ctxById.get(en.eventId);
      const t = rc?.tMs ?? (e?.ts ? Date.parse(e.ts) : NaN);
      if (!e || !Number.isFinite(t)) return;
      raw.push({ en, e, t, order, precise: rc?.precision === 'ms', said: en.note ? noteLine(en.note) : '',
        sev: e.sev, beats: rc?.beats ?? [], raw: rc ? rc.interpreted === false : false });
    });
    raw.sort(byInstant);
    const laneOf = new Map<string, number>();
    const names: string[] = [];
    const display = new Map<string, string>();
    const out: Item[] = raw.map((r, idx) => {
      const name = r.en.labels[0] || UNLABELLED;
      let lane = laneOf.get(name);
      if (lane === undefined) { lane = names.length; laneOf.set(name, lane); names.push(name); }
      const rc = ctxById.get(r.en.eventId);
      const key = (role: string, value: string) => {
        const k = `${ROLE_KIND[role] ?? role}:${value.toLowerCase()}`;
        if (!display.has(k)) display.set(k, value);
        return k;
      };
      const vals = rc?.entities?.length ? rc.entities
        : r.beats.filter((b) => b.value && b.role).map((b) => ({ role: b.role!, value: b.value! }));
      const ents = [...new Set(vals.filter((v) => v.role !== 'host' && v.role !== 'account').map((v) => key(v.role, v.value)))];
      const allEnts = [...new Set([...vals.map((v) => key(v.role, v.value)),
        ...(real(r.e.host) ? [key('host', r.e.host)] : []), ...(real(r.e.user) ? [key('account', r.e.user)] : [])])];
      const tick = /`([^`]{1,120})`/.exec(r.en.note || '');
      const action = rc?.action ?? { kind: 'event', verb: 'event', object: tick ? tick[1]! : trunc(r.e.msg || r.e.raw, 60) };
      return { ...r, idx, lane, action, ents, allEnts };
    });
    return {
      items: out, lanes: names,
      nodes: out.map((it) => ({ key: it.en.eventId, role: it.action.kind, value: it.action.object || it.action.verb,
        verb: it.action.verb, t: it.t, first: it.idx, lane: it.lane })),
      edges: buildEdges(out, display),
    };
  }, [entries, byId, ctxById]);
  const unplaced = entries.length - items.length;
  const anyPrecise = items.some((it) => it.precise);
  const wholeSeconds = items.filter((it) => !it.precise).length;
  const rawCount = items.filter((it) => it.raw).length;

  const start = items[0]?.t ?? 0;
  const end = items[items.length - 1]?.t ?? 0;
  const d0 = start - LEAD_MS;
  const d1 = end + TAIL_MS;
  // The bar's geometry: bursts at their real proportions, long quiet gaps compressed to a labelled
  // break (utils/replayScale.ts). Time itself is never compressed - only where it is DRAWN.
  const scale = useMemo(() => buildScale(items.map((it) => it.t), d0, d1), [items, d0, d1]);
  const autoSpeed = useMemo(() => {
    const need = (d1 - d0) / TARGET_MS;
    return SPEEDS.find((v) => v >= need) ?? SPEEDS[SPEEDS.length - 1]!;
  }, [d0, d1]);

  /* ── the clock ──
     The playhead lives in refs and one animation-frame loop; React hears about it only when an event
     is reached or the replay ends. See SMOOTHNESS at the top of this file. */
  const [speed, setSpeed] = useState<number>(() =>
    stored(SPEED_KEY, (v) => (SPEEDS.includes(Number(v)) ? Number(v) : undefined), 1));
  const [skipQuiet, setSkipQuietState] = useState<boolean>(() =>
    stored(SKIP_KEY, (v) => (v === '1' ? true : v === '0' ? false : undefined), true));
  const setSkipQuiet = (on: boolean) => { remember(SKIP_KEY, on ? '1' : '0'); setSkipQuietState(on); };
  // Autoplay, but only once the exact instants have arrived: starting on whole seconds and then
  // shifting every event by its milliseconds mid-replay would be the inaccuracy this view exists to avoid.
  const [playing, setPlayingState] = useState(false);
  const playingRef = useRef(false);
  const setPlaying = useCallback((on: boolean) => { playingRef.current = on; setPlayingState(on); }, []);
  const autostarted = useRef(false);
  const [reached, setReached] = useState(0);
  const [ended, setEnded] = useState(false);
  const [skipped, setSkipped] = useState<Set<number>>(() => new Set());

  // The replay time at a wall-clock instant. Every frame derives the time from this, so nothing
  // accumulates and nothing drifts.
  const anchor = useRef({ wall: performance.now(), t: d0 });
  const tRef = useRef(d0);
  const reachedRef = useRef(0);
  const endedRef = useRef(false);
  const glide = useRef<{ from: number; to: number; t0: number } | null>(null);
  const dragTo = useRef<number | null>(null);
  // Live copies for the frame loop, which must not be torn down and rebuilt on every render.
  const live = useRef({ items, d0, d1, start, speed, skipQuiet, scale });
  live.current = { items, d0, d1, start, speed, skipQuiet, scale };
  // The seek bar's ZOOM: the window [v0, v1] of bar units on screen. Like the playhead it is written to
  // CSS custom properties by the frame loop, so zooming and panning never cost a render; `view` is
  // the SETTLED window, for the things that do render (the ruler's density, the minimap).
  const viewRef = useRef({ v0: 0, v1: scale.U });
  const wholeRef = useRef(true);          // the whole bar is on screen (kept whole across a rescale)
  const viewAnim = useRef<{ f0: number; f1: number; to0: number; to1: number; t0: number } | null>(null);
  const manualAt = useRef(0);
  const settleTimer = useRef(0);
  const [view, setView] = useState<[number, number]>([0, scale.U]);
  const [trackW, setTrackW] = useState(1000);

  const rootRef = useRef<HTMLElement>(null);
  const clockRef = useRef<HTMLSpanElement>(null);
  const msRef = useRef<HTMLSpanElement>(null);
  const offRef = useRef<HTMLSpanElement>(null);
  const nextRef = useRef<HTMLElement>(null);
  const nextScreenRef = useRef<HTMLSpanElement>(null);
  const trackRef = useRef<HTMLDivElement>(null);
  const scrubRef = useRef<HTMLDivElement>(null);     // carries the zoom's custom properties
  const miniRef = useRef<HTMLDivElement>(null);

  /** Write the playhead to the screen: continuous things straight to the DOM, discrete ones to React. */
  const paint = useCallback((t: number) => {
    const { items: its, d1: b, start: s, speed: sp, scale: sc } = live.current;
    tRef.current = t;
    const u = sc.U > 0 ? toU(sc, t) : 0;
    rootRef.current?.style.setProperty('--rp-pu', (sc.U > 0 ? u / sc.U : 0).toFixed(7));
    // Zoomed in and the playhead is running off the window: follow it - unless the analyst has just
    // moved the window themselves, in which case their view wins for a moment.
    const { v0, v1 } = viewRef.current;
    const w = v1 - v0;
    if (w < sc.U * 0.999 && (playingRef.current || glide.current) && !viewAnim.current
      && performance.now() - manualAt.current > FOLLOW_HOLD_MS && (u < v0 || u > v1 - w * 0.08)) {
      viewAnim.current = { f0: v0, f1: v1, to0: u - w * 0.25, to1: u + w * 0.75, t0: performance.now() };
    }
    const c = utcParts(t);
    if (clockRef.current) clockRef.current.textContent = `${c.day} ${c.clock}`;
    if (msRef.current) msRef.current.textContent = c.ms;
    if (offRef.current) offRef.current.textContent = tOffset(t - s);
    const k = reachedBy(its, t);
    const nx = its[k];
    if (nx && nextRef.current) nextRef.current.textContent = dur(nx.t - t);
    if (nx && nextScreenRef.current) nextScreenRef.current.textContent = sp !== 1 ? ` · ${dur((nx.t - t) / sp)} on screen` : '';
    trackRef.current?.setAttribute('aria-valuetext', `${c.clock} UTC, ${k} of ${its.length} events`);
    if (k !== reachedRef.current) { reachedRef.current = k; setReached(k); }
    const e = t >= b;
    if (e !== endedRef.current) { endedRef.current = e; setEnded(e); }
  }, []);

  /** Put a window of the bar on screen. Clamped to the bar, never narrower than the zoom allows. */
  const applyView = useCallback((a: number, b: number, settle = true) => {
    const U = live.current.scale.U;
    const minW = Math.max(ZOOM_MIN_UNITS, U / ZOOM_MAX);
    let w = Math.min(U, Math.max(minW, b - a));
    if (!(w > 0)) w = U || 1;
    let v0 = Math.min(Math.max(0, a), Math.max(0, U - w));
    if (!Number.isFinite(v0)) v0 = 0;
    const v1 = v0 + w;
    viewRef.current = { v0, v1 };
    wholeRef.current = w >= U * 0.999;
    const el = scrubRef.current;
    if (el && U > 0) {
      el.style.setProperty('--rp-zl', (-v0 / w).toFixed(7));
      el.style.setProperty('--rp-zw', (U / w).toFixed(7));
      el.style.setProperty('--rp-v0f', (v0 / U).toFixed(7));
      el.style.setProperty('--rp-vwf', (w / U).toFixed(7));
    }
    if (settle) {
      window.clearTimeout(settleTimer.current);
      settleTimer.current = window.setTimeout(() => setView([viewRef.current.v0, viewRef.current.v1]), 90);
    }
  }, []);
  const animateView = useCallback((a: number, b: number) => {
    if (reducedMotion()) { applyView(a, b); return; }
    const { v0, v1 } = viewRef.current;
    viewAnim.current = { f0: v0, f1: v1, to0: a, to1: b, t0: performance.now() };
  }, [applyView]);
  /** Zoom by `k` (< 1 zooms in) keeping the unit `about` where it is on screen. */
  const zoomBy = useCallback((k: number, about: number, smooth: boolean) => {
    const { v0, v1 } = viewRef.current;
    const w = v1 - v0;
    const nw = w * k;
    const f = w > 0 ? (about - v0) / w : 0.5;
    manualAt.current = performance.now();
    if (smooth) animateView(about - f * nw, about - f * nw + nw); else applyView(about - f * nw, about - f * nw + nw);
  }, [animateView, applyView]);
  const fit = useCallback(() => { manualAt.current = 0; animateView(0, live.current.scale.U); }, [animateView]);
  // A new scale (the same timeline refined by a poll, or another one): a whole-bar view stays the whole
  // bar; a zoomed one keeps its window, clamped. A different timeline resets it below, with the playhead.
  useLayoutEffect(() => {
    viewAnim.current = null;
    if (wholeRef.current) applyView(0, scale.U, false);
    else applyView(viewRef.current.v0, viewRef.current.v1, false);
    setView([viewRef.current.v0, viewRef.current.v1]);
  }, [scale, applyView]);
  useEffect(() => () => window.clearTimeout(settleTimer.current), []);

  /** Move the playhead. `smooth` glides there (a click, a step, a key); a drag and the clock do not. */
  const seek = useCallback((x: number, smooth = false) => {
    const { d0: a, d1: b } = live.current;
    const c = Math.min(b, Math.max(a, x));
    const now = performance.now();
    if (smooth && !reducedMotion() && Math.abs(c - tRef.current) > 0) {
      glide.current = { from: tRef.current, to: c, t0: now };
    } else {
      glide.current = null;
      anchor.current = { wall: now, t: c };
      paint(c);
    }
  }, [paint]);

  // ONE loop for the life of the replay. Each frame: a drag target, else a glide, else the running
  // clock. An idle frame writes nothing.
  useEffect(() => {
    let raf = 0;
    const frame = () => {
      raf = requestAnimationFrame(frame);
      const now = performance.now();
      const { items: its, d0: a, d1: b, speed: sp, skipQuiet: skip, scale: sc } = live.current;
      const va = viewAnim.current;
      if (va) {
        // ease IN and out: a follow-pan that starts at full speed reads as a jump
        const k = Math.min(1, (now - va.t0) / 420);
        const e = k < 0.5 ? 4 * k * k * k : 1 - (-2 * k + 2) ** 3 / 2;
        applyView(va.f0 + (va.to0 - va.f0) * e, va.f1 + (va.to1 - va.f1) * e, k >= 1);
        if (k >= 1) viewAnim.current = null;
      }
      let nt: number | null = null;
      if (dragTo.current != null) {
        nt = dragTo.current;
        dragTo.current = null;
        anchor.current = { wall: now, t: nt };
      } else if (glide.current) {
        const g = glide.current;
        const k = Math.min(1, (now - g.t0) / GLIDE_MS);
        nt = g.from + (g.to - g.from) * easeOut(k);
        if (k >= 1) { glide.current = null; nt = g.to; anchor.current = { wall: now, t: g.to }; }
      } else if (playingRef.current && its.length) {
        nt = anchor.current.t + (now - anchor.current.wall) * sp;
        if (skip) {
          const k = reachedBy(its, nt);
          const next = its[k];
          const prevT = k > 0 ? its[k - 1]!.t : a;
          // Quiet = a gap the BAR compresses (so the bar and the playback agree), or one that would
          // hold the screen still for more than a few seconds at this speed.
          const quiet = next && (sc.gapBefore[k] || (next.t - prevT) / sp > QUIET_MS);
          if (next && quiet && (nt - prevT) / sp >= QUIET_HOLD_MS) {
            const land = next.t - QUIET_LEAD_MS * sp;
            if (land > nt) {
              // The jump GLIDES across the gap (a quarter second) rather than teleporting the thumb;
              // the glide's end re-anchors the clock at the landing point, so timing is unaffected.
              setSkipped((s) => (s.has(k) ? s : new Set(s).add(k)));
              if (!reducedMotion()) {
                glide.current = { from: nt, to: land, t0: now };
              } else {
                nt = land;
                anchor.current = { wall: now, t: nt };
              }
            }
          }
        }
        if (nt >= b) { nt = b; setPlaying(false); }
      }
      if (nt != null && nt !== tRef.current) paint(nt);
    };
    raf = requestAnimationFrame(frame);
    return () => cancelAnimationFrame(raf);
  }, [paint, setPlaying, applyView]);

  // A DIFFERENT timeline (a case switch) starts again from the top. The SAME timeline refined - the
  // exact instants arriving, a source finishing loading, an entry added - keeps the playhead where it
  // is: the replay now re-asks the server while the pool is loading, and restarting on every answer
  // would make it unwatchable.
  const seqIds = useMemo(() => items.map((it) => it.en.eventId), [items]);
  const prevSeq = useRef<Set<string> | null>(null);
  useLayoutEffect(() => {
    const prev = prevSeq.current;
    prevSeq.current = new Set(seqIds);
    if (!prev || !seqIds.some((id) => prev.has(id))) {
      viewAnim.current = null;
      applyView(0, live.current.scale.U);
      seek(d0);
      return;
    }
    const t = Math.min(d1, Math.max(d0, glide.current?.to ?? tRef.current));
    glide.current = null;
    anchor.current = { wall: performance.now(), t };
    paint(t);
  }, [seqIds, d0, d1, seek, paint, applyView]);
  // Text the loop writes also has to be right the moment React re-renders the spans that hold it.
  useLayoutEffect(() => { paint(tRef.current); }, [paint, reached, ended, speed, items]);
  useEffect(() => {
    if (autostarted.current || ctx.isLoading || !items.length) return;
    autostarted.current = true;
    seek(live.current.d0);
    setPlaying(true);
  }, [ctx.isLoading, items.length, seek, setPlaying]);
  useEffect(() => { setSkipped(new Set()); }, [items, skipQuiet]);

  const changeSpeed = (v: number) => {       // a new speed must not move the playhead
    anchor.current = { wall: performance.now(), t: tRef.current };
    remember(SPEED_KEY, String(v));
    setSpeed(v);
  };
  const play = () => {
    if (tRef.current >= d1) seek(d0);          // from the end = watch again
    anchor.current = { wall: performance.now(), t: tRef.current };
    setPlaying(true);
  };
  const toggle = () => (playing ? setPlaying(false) : play());
  const stepNext = () => {
    const k = reachedBy(items, glide.current?.to ?? tRef.current);
    if (k < items.length) seek(items[k]!.t, true);
  };
  const stepPrev = () => {
    const k = reachedBy(items, glide.current?.to ?? tRef.current);
    seek(k >= 2 ? items[k - 2]!.t : d0, true);   // back to the event BEFORE the one on screen
  };

  /* ── the milestone callout: shown for a few seconds of SCREEN time when a moment carries one ── */
  const [flare, setFlare] = useState<{ id: string; text: string; tone: string; clock: string } | null>(null);
  const lastFlare = useRef(-1);
  const flareTimer = useRef(0);
  useEffect(() => () => window.clearTimeout(flareTimer.current), []);
  useEffect(() => {
    if (reached === 0 || reached - 1 === lastFlare.current) return;
    lastFlare.current = reached - 1;
    const it = items[reached - 1];
    if (!it) return;
    const b = milestone(it);
    if (!b) return;
    // The timer outlives this effect on purpose: the NEXT event (with no milestone of its own) must
    // not cancel it, or the callout would stay up for good.
    window.clearTimeout(flareTimer.current);
    setFlare({ id: it.en.eventId, text: b.text, tone: beatTone(b), clock: utcParts(it.t).clock });
    flareTimer.current = window.setTimeout(() => setFlare(null), FLARE_MS);
  }, [reached, items]);

  /* ── the scrub track ── */
  /** Where an instant sits on the WHOLE bar, in % - the ticks, the phase tracks and the minimap. */
  const pct = useCallback((x: number) => (scale.U > 0 ? (toU(scale, x) / scale.U) * 100 : 0), [scale]);
  const unitAt = (clientX: number): number => {
    const el = trackRef.current;
    const { v0, v1 } = viewRef.current;
    if (!el) return v0;
    const r = el.getBoundingClientRect();
    const px = Math.min(r.width, Math.max(0, clientX - r.left));
    return v0 + (px / Math.max(1, r.width)) * (v1 - v0);
  };
  const fromPointer = (clientX: number, snap: boolean): number => {
    const el = trackRef.current;
    if (!el) return tRef.current;
    const u = unitAt(clientX);
    let best = fromU(scale, u);
    if (!snap) return best;
    // An event within a few PIXELS of the click is what was meant - at every zoom level.
    const { v0, v1 } = viewRef.current;
    const width = el.getBoundingClientRect().width;
    const px = ((u - v0) / (v1 - v0)) * width;
    let bestPx = SNAP_PX;
    for (const it of items) {
      const dpx = Math.abs(((toU(scale, it.t) - v0) / (v1 - v0)) * width - px);
      if (dpx <= bestPx) { best = it.t; bestPx = dpx; }
    }
    return best;
  };
  // Wheel over the bar zooms around the pointer (a trackpad pinch arrives as ctrl+wheel); a sideways
  // wheel or shift+wheel pans. A NATIVE listener, because React's wheel handler is passive and the
  // page would scroll underneath.
  useEffect(() => {
    const el = trackRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setTrackW(el.clientWidth || 1000));
    ro.observe(el);
    setTrackW(el.clientWidth || 1000);
    const onWheel = (ev: WheelEvent) => {
      ev.preventDefault();
      const unit = ev.deltaMode === 1 ? 16 : ev.deltaMode === 2 ? 400 : 1;
      const dx = ev.deltaX * unit; const dy = ev.deltaY * unit;
      viewAnim.current = null;
      const { v0, v1 } = viewRef.current;
      manualAt.current = performance.now();
      if (ev.shiftKey || Math.abs(dx) > Math.abs(dy)) {
        const pan = ((ev.shiftKey ? dy : dx) / Math.max(1, el.clientWidth)) * (v1 - v0);
        applyView(v0 + pan, v1 + pan);
      } else {
        zoomBy(Math.exp(dy * (ev.ctrlKey ? 0.01 : 0.0018)), unitAt(ev.clientX), false);
      }
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => { el.removeEventListener('wheel', onWheel); ro.disconnect(); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [applyView, zoomBy, items.length > 0]);
  const dragging = useRef<{ wasPlaying: boolean; x0: number; moved: boolean; pan: false | { v0: number; v1: number } } | null>(null);
  const onPointerDown = (ev: ReactPointerEvent<HTMLDivElement>) => {
    ev.currentTarget.setPointerCapture(ev.pointerId);
    const zoomed = viewRef.current.v1 - viewRef.current.v0 < scale.U * 0.999;
    if (zoomed && (ev.button === 1 || ev.shiftKey)) {      // pan the zoomed bar, do not scrub
      ev.preventDefault();
      viewAnim.current = null;
      dragging.current = { wasPlaying: false, x0: ev.clientX, moved: true, pan: { ...viewRef.current } };
      return;
    }
    dragging.current = { wasPlaying: playingRef.current, x0: ev.clientX, moved: false, pan: false };
    setPlaying(false);
    seek(fromPointer(ev.clientX, true), true);
  };
  const onPointerMove = (ev: ReactPointerEvent<HTMLDivElement>) => {
    const d = dragging.current;
    if (!d) return;
    if (d.pan) {
      const w = d.pan.v1 - d.pan.v0;
      const du = -((ev.clientX - d.x0) / Math.max(1, trackRef.current?.clientWidth ?? 1)) * w;
      manualAt.current = performance.now();
      applyView(d.pan.v0 + du, d.pan.v1 + du);
      return;
    }
    if (!d.moved && Math.abs(ev.clientX - d.x0) < CLICK_PX) return;
    d.moved = true;
    const target = fromPointer(ev.clientX, false);
    // A glide from the press still in flight is RE-AIMED at the pointer rather than cut off: cutting
    // it off jumped the thumb the rest of the way in one frame.
    if (glide.current) glide.current.to = target;
    else dragTo.current = target;                       // coalesced: the loop paints it once per frame
  };
  const onPointerUp = () => {
    const d = dragging.current;
    dragging.current = null;
    if (d?.pan) return;
    if (d?.wasPlaying && (glide.current?.to ?? dragTo.current ?? tRef.current) < d1) {
      if (!glide.current) anchor.current = { wall: performance.now(), t: dragTo.current ?? tRef.current };
      setPlaying(true);
    }
  };
  const onKey = (ev: ReactKeyboardEvent) => {
    const k = ev.key;
    if (k === 'ArrowRight') stepNext();
    else if (k === 'ArrowLeft') stepPrev();
    else if (k === 'Home') seek(d0, true);
    else if (k === 'End') seek(d1, true);
    else if (k === ' ' || k === 'k') toggle();
    else if (k === '+' || k === '=') zoomBy(0.5, toU(scale, tRef.current), true);
    else if (k === '-' || k === '_') zoomBy(2, toU(scale, tRef.current), true);
    else if (k === '0') fit();
    else return;
    ev.preventDefault();
  };

  /* ── full screen: the replay is something to watch, and the page around it is not ── */
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

  /* ── figures derived from which events have been reached ── */
  const cur = reached > 0 ? items[reached - 1] : undefined;
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
  // The ruler for the settled window, with half a window either side so a pan never shows bare bar
  // before it settles. It lives in bar units inside the zoom layer, so it moves WITH the zoom.
  const ruler = useMemo(() => {
    const w = Math.max(1e-9, view[1] - view[0]);
    const a = Math.max(0, view[0] - w / 2);
    const b = Math.min(scale.U, view[1] + w / 2);
    return rulerTicks(scale, a, b, trackW * ((b - a) / w)).ticks;
  }, [scale, view, trackW]);
  const breaks = useMemo(() => scale.segs.filter((g) => g.gap), [scale]);
  const zoomed = !wholeRef.current && view[1] - view[0] < scale.U * 0.999;
  const zoomX = scale.U > 0 ? scale.U / Math.max(1e-9, view[1] - view[0]) : 1;
  const miniDrag = useRef<{ off: number } | null>(null);
  const miniUnit = (clientX: number): number => {
    const r = miniRef.current?.getBoundingClientRect();
    return r ? ((clientX - r.left) / Math.max(1, r.width)) * scale.U : 0;
  };
  const onMiniDown = (ev: ReactPointerEvent<HTMLDivElement>) => {
    ev.currentTarget.setPointerCapture(ev.pointerId);
    const u = miniUnit(ev.clientX);
    const { v0, v1 } = viewRef.current;
    const off = u >= v0 && u <= v1 ? u - v0 : (v1 - v0) / 2;
    miniDrag.current = { off };
    viewAnim.current = null;
    manualAt.current = performance.now();
    applyView(u - off, u - off + (v1 - v0));
  };
  const onMiniMove = (ev: ReactPointerEvent<HTMLDivElement>) => {
    const m = miniDrag.current;
    if (!m) return;
    const u = miniUnit(ev.clientX);
    const { v0, v1 } = viewRef.current;
    manualAt.current = performance.now();
    applyView(u - m.off, u - m.off + (v1 - v0));
  };
  const onMiniUp = () => { miniDrag.current = null; };
  const edgeCounts = useMemo(() => ({
    actor: edges.filter((e) => e.kind === 'actor').length, shared: edges.filter((e) => e.kind === 'shared').length,
  }), [edges]);

  if (!items.length) {
    return (
      <EmptyState title="Nothing to replay"
        body={entries.length
          ? 'None of the events on this timeline has a parsed timestamp, so none of them can be placed on a clock. Enriching their sources gives them one.'
          : 'Add events to the timeline first.'} />
    );
  }

  const next = items[reached];
  const c = kase.data;
  const phaseNow = cur ? phaseStats[cur.lane] : undefined;
  const lede = (c?.summary || '').split(/(?<=[.!?])\s+/).slice(0, 2).join(' ');
  const d = ctx.data;

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
          <span className="rp-chip"><b>{edges.length}</b> link{edges.length === 1 ? '' : 's'}</span>
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
            <button className="btn" onClick={() => { seek(d0, true); setPlaying(true); }} title="Restart from the beginning">
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
            <div className="rp-clock__t mono"><span ref={clockRef} /><span className="rp-clock__ms" ref={msRef} /></div>
            <div className="rp-clock__d mono">
              <span ref={offRef} /> · phase {cur ? cur.lane + 1 : 0} / {lanes.length} · UTC
            </div>
          </div>
        </div>
        <div className="rp-scrub" ref={scrubRef}>
          <div className={cx('rp-track', playing && 'rp-track--playing', zoomed && 'rp-track--zoomed')} ref={trackRef}
            role="slider" tabIndex={0}
            title={zoomed ? 'Drag to scrub · wheel to zoom · shift+drag or shift+wheel to pan · 0 to fit'
              : 'Drag to scrub · wheel over the bar to zoom in'}
            aria-label="Replay position" aria-valuemin={0} aria-valuemax={items.length} aria-valuenow={reached}
            onPointerDown={onPointerDown} onPointerMove={onPointerMove} onPointerUp={onPointerUp}
            onPointerCancel={onPointerUp} onKeyDown={onKey}>
            <div className="rp-track__view">
              {/* The zoom layer: the WHOLE bar, scaled and shifted by --rp-zw / --rp-zl, so everything in it
                  is placed once in bar units and zooming moves it without a render. */}
              <div className="rp-track__layer">
                <div className="rp-track__bar" />
                {breaks.map((g) => (
                  <div key={g.u0} className="rp-break"
                    style={{ left: `${(g.u0 / scale.U) * 100}%`, width: `${((g.u1 - g.u0) / scale.U) * 100}%` }}
                    title={`Quiet for ${gapLabel(g.r1 - g.r0)}: ${utcParts(g.r0).clock} → ${utcParts(g.r1).clock} UTC. Compressed on the bar only; the clock keeps real time.`}>
                    {/* the full length where there is room for it, its largest unit where there is not */}
                    <span>⋯ {((g.u1 - g.u0) / Math.max(1e-9, view[1] - view[0])) * trackW >= 64
                      ? gapLabel(g.r1 - g.r0) : gapLabel(g.r1 - g.r0).split(' ')[0]}</span>
                  </div>
                ))}
                <div className="rp-track__fill" />
                {ruler.map((tk) => (
                  <span key={tk.t} className="rp-rule" style={{ left: `${(tk.u / scale.U) * 100}%` }}><i>{tk.label}</i></span>
                ))}
                {items.map((it) => (
                  <span key={it.en.eventId} className={cx('rp-tick', it.idx < reached && 'rp-tick--on')}
                    style={{ left: `${pct(it.t)}%`, background: PHASE_HUES[it.lane % PHASE_HUES.length] }}
                    title={`${utcParts(it.t).clock} UTC — ${it.said || it.e.msg}`} />
                ))}
                <span className="rp-thumb" />
              </div>
            </div>
          </div>
          {zoomed && (
            <div className="rp-mini" ref={miniRef} onPointerDown={onMiniDown} onPointerMove={onMiniMove}
              onPointerUp={onMiniUp} onPointerCancel={onMiniUp} title="The whole timeline. Drag the window to pan.">
              {breaks.map((g) => (
                <span key={g.u0} className="rp-mini__gap"
                  style={{ left: `${(g.u0 / scale.U) * 100}%`, width: `${((g.u1 - g.u0) / scale.U) * 100}%` }} />
              ))}
              {items.map((it) => (
                <span key={it.en.eventId} className="rp-mini__tick"
                  style={{ left: `${pct(it.t)}%`, background: PHASE_HUES[it.lane % PHASE_HUES.length] }} />
              ))}
              <span className="rp-mini__win" />
              <span className="rp-mini__head" />
            </div>
          )}
          <div className="rp-axis mono">
            <span className="rp-axis__mid">
              {next ? <>next in <b ref={nextRef} /><span ref={nextScreenRef} /></>
                : ended ? 'end of the timeline' : 'every event has happened'}
              {breaks.length > 0 && <span className="rp-axis__gaps"> · {breaks.length} quiet gap{breaks.length === 1 ? '' : 's'} compressed on the bar</span>}
            </span>
            <span className="rp-zoom" role="group" aria-label="Seek bar zoom">
              <button type="button" className="rp-zoom__b" onClick={() => zoomBy(2, toU(scale, tRef.current), true)}
                disabled={!zoomed} aria-label="Zoom out" title="Zoom out (−)">−</button>
              <span className="rp-zoom__x">{zoomed ? `${zoomX < 10 ? zoomX.toFixed(1) : Math.round(zoomX).toLocaleString()}×` : 'whole span'}</span>
              <button type="button" className="rp-zoom__b" onClick={() => zoomBy(0.5, toU(scale, tRef.current), true)}
                disabled={zoomX >= ZOOM_MAX * 0.99} aria-label="Zoom in" title="Zoom in around the playhead (+), or wheel over the bar">+</button>
              <button type="button" className="rp-zoom__fit" onClick={fit} disabled={!zoomed} title="Show the whole timeline (0)">Fit</button>
            </span>
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
            <span className="rp-tagline">every event, drawn as it happens · linked by what did it and what they share</span></div>
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
          {/* Why the map may have fewer links than it will: said, never left to look like "no links". */}
          {(d?.poolLoading || (d?.missing ?? 0) > 0 || rawCount > 0) && (
            <div className="rp-mapnote" role="status">
              {d?.poolLoading && <span>Iris is still loading logs — the map fills in as they load.</span>}
              {!d?.poolLoading && (d?.missing ?? 0) > 0 && (
                <span>{d!.missing} timeline entr{d!.missing === 1 ? 'y is' : 'ies are'} not in the loaded logs yet.</span>
              )}
              {rawCount > 0 && (
                <span>
                  {rawCount} of {items.length} event{items.length === 1 ? '' : 's'} come from logs that are not interpreted yet,
                  so only the addresses and hashes written in their lines can link them — which process did what
                  appears once their sources are enriched{d?.awaiting ? ' (in progress)' : ' (Sources → Enrich)'}.
                </span>
              )}
            </div>
          )}
          <div className="rp-mapwrap">
            <AttackMap nodes={nodes} edges={edges} lanes={lanes} reached={reached} current={cur?.en.eventId ?? null} />
          </div>
          <div className="rp-legend" aria-hidden>
            <span className="rp-legend__k"><svg width="26" height="8"><path d="M1,4 L25,4" className="rp-legend__actor" /></svg>done by — the process that did it{edgeCounts.actor ? ` (${edgeCounts.actor})` : ''}</span>
            <span className="rp-legend__k"><svg width="26" height="8"><path d="M1,4 L25,4" className="rp-legend__shared" /></svg>same file, hash, domain or address as an earlier event{edgeCounts.shared ? ` (${edgeCounts.shared})` : ''}</span>
            <span className="rp-legend__hint">Point at an event to read its links; click to hold them.</span>
          </div>
      </div>

      {/* ── the live stream, and beside it the phases and the activity over time ── */}
      <div className="rp-stage rp-stage--2">
        <div className="rp-card">
          <div className="rp-card__hd"><span className="rp-mk" style={{ background: '#d8974f' }} /><h3>Live event stream</h3>
            <span className="rp-tagline">every event, {newestFirst ? 'newest' : 'oldest'} first — the timeline's order</span></div>
          <Stream items={items} reached={reached} skipped={skipped} onOpen={onOpen} newestFirst={newestFirst} />
        </div>
        <div className="rp-side">
        <div className="rp-card">
          <div className="rp-card__hd"><span className="rp-mk" style={{ background: '#6f9fd8' }} /><h3>Phase activity</h3>
            <span className="rp-tagline">first seen → last seen, to scale · {newestFirst ? 'newest' : 'oldest'} first</span></div>
          <PhaseActivity phases={phaseStats} active={cur ? cur.lane : -1} pct={pct} newestFirst={newestFirst} />
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
        {d?.valuesCapped && <div>First sightings were checked for the first {d.valuesChecked} values only.</div>}
        <div>Times are UTC and to the millisecond where the log recorded one. Timing is real: at 1× the gaps are the real gaps.</div>
      </div>
    </section>
  );
}
