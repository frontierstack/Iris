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
 *  - "Skip quiet stretches" (on by default) FAST-FORWARDS a lull - a gap the seek bar draws as a
 *    break, decided by incident time and never by the speed: the clock holds the chosen speed for a
 *    second after the event, speeds up as far as it takes to cross the lull in about a second and a
 *    half, and is back at the chosen speed 5 s (incident time; 3-8 s of screen) before the next
 *    event - see ffPlan. Every moment reached that way is marked "skipped", so a
 *    skipped gap never looks like a short one. Within a burst nothing is skipped: the pace of the
 *    activity itself is always the real one.
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
import type { CSSProperties, KeyboardEvent as ReactKeyboardEvent, MouseEvent as ReactMouseEvent, PointerEvent as ReactPointerEvent } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { createPortal } from 'react-dom';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import type { CaseSetEntry, Event, ReplayBeat, ReplayContext, ReplayLink, Severity } from '../api/types';
import { useTypewriter } from '../hooks/useArrivals';
import { useCase } from '../hooks/queries';
import { cx } from '../utils/format';
import { inlineMd } from '../utils/markdown';
import { buildScale, fromU, gapLabel, ticks as rulerTicks, toU } from '../utils/replayScale';
import { edgeKey, layoutReplay } from '../utils/replayLayout';
import { Icon } from './icons';
import { ReplaySummary } from './ReplaySummary';
import { EmptyState, Loading } from './ui';
import { noteLine } from './timelineText';

/** Replay rates: how many seconds of the incident pass per second on screen. */
/*  "I need slow speeds, also remove anything higher than 10x ... better organization for slower
 *  replays". Nothing above 10x: "Skip quiet stretches" already crosses the dead air, so a high rate
 *  only made the events themselves flash past. The slow end is where a burst is actually read, so it
 *  gets the most steps, and the control is grouped Slow / Real time / Fast rather than one row. */
const SPEED_GROUPS: { label: string; speeds: number[] }[] = [
  { label: 'Slow', speeds: [0.1, 0.25, 0.5, 0.75] },
  { label: 'Real time', speeds: [1] },
  { label: 'Fast', speeds: [1.5, 2, 5, 10] },
];
const SPEEDS = SPEED_GROUPS.flatMap((g) => g.speeds);
/** The seek bar starts this long (INCIDENT time) before the first event and ends this long after the
 *  last. It used to be padded by 3 % of the whole span: on a 21-hour case that is 38 minutes of empty
 *  bar before the first event — "a massive space ... it can take a long time to get to the first event". */
const LEAD_MS = 2_500;
const TAIL_MS = 2_500;
/** FAST-FORWARD TO THE NEXT EVENT. Asked for twice: "very quickly speed up until it gets close to the
 *  next event so there isn't a large waiting period ... then revert back to the user set time scale",
 *  then "maybe more than 60x, increase to whatever speed is needed to get quickly within 5 or 10s to the
 *  next event". So the fast rate is not a constant: each gap is CROSSED in FF_CROSS_MS of screen time,
 *  at whatever rate that takes (a 40 s lull at ~35x, a three-hour one at ~9,400x), and the clock is
 *  back at the chosen speed FF_NEAR_SCREEN_MS of SCREEN time before the next event - so the last
 *  seconds before every arrival, and every burst (whose events are all inside that window), play at
 *  the chosen speed, anchored to performance.now(). Only the dead air is shortened; the clock always
 *  shows the real incident time, and the arrival reached this way is marked in the stream.
 *  The rate follows a constant-acceleration curve (FF_RAMP_MS up, FF_RAMP_MS down), never a step: a
 *  clock that lurches from 1x to 1000x in one frame is the jagged motion this screen was fixed for.
 *  This IS "Skip quiet stretches": it used to glide over a lull in a quarter second and land 0.8 s
 *  before the next event, which was both abrupt and too little warning; it now crosses it this way. */
/*  WHICH GAPS ARE SKIPPED. Twice now: "the empty space should be skipped ahead and then it slows down
 *  when it gets to the next event ... the skip quiet stretches check box doesn't seem to be doing
 *  anything". A gap is dead air when WATCHING it at the chosen speed would take longer than
 *  FF_QUIET_SCREEN_MS of screen - judged in SCREEN time, because that is what the analyst sits through.
 *  An incident-time threshold (the seek bar's G, >= 10 s) was tried and was a regression: on a case
 *  whose events are 3-8 s apart it skipped nothing, so at 0.5x the thumb crawled through every empty
 *  stretch at one constant rate and the checkbox visibly did nothing.
 *  Inside a skipped gap: FF_HOLD_MS at the chosen speed after the event (it is seen to land), a fast
 *  crossing, then FF_NEAR_SCREEN_MS of SCREEN time at the chosen speed before the next event - so every
 *  arrival, and every burst, plays at exactly the speed chosen, and a slower speed is a slower approach. */
/** After an event, this long (screen time) at the chosen speed before speeding up. */
const FF_HOLD_MS = 500;
/** The chosen speed resumes this much SCREEN time before the next event: the slow-down onto it. */
const FF_NEAR_SCREEN_MS = 1_600;
/** A gap is skipped when watching it at the chosen speed would take longer than this (screen time). */
const FF_QUIET_SCREEN_MS = 4_500;
/** How long (screen time) the fast part of a gap takes to cross, ramps included. */
const FF_CROSS_MS = 1_200;
/** A lull is only fast-forwarded when that is at least this many times the chosen speed: below it the
 *  hold and the approach take nearly the whole gap anyway, and a 2x "skip" would mark as skipped a gap
 *  the analyst mostly watched in real time. */
const FF_MIN_GAIN = 4;
/** Screen time to go from the chosen speed to the gap's rate, and back (each ramp). */
const FF_RAMP_MS = 450;
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
/** How much slower (> 1) or quicker (< 1) every REVEAL plays than at 1x: a node settling in, a link
 *  drawing itself, a stream row typing in, a phase bar filling, the milestone callout's stay. It is the
 *  inverse of the speed, so 0.25x shows each arrival four times as slowly and 5x five times as briskly,
 *  bounded so 0.1x is slow rather than frozen and 10x still leaves a node long enough to be seen.
 *  Navigation is NOT scaled — a seek's glide (GLIDE_MS), the follow-pan and the clock are the analyst
 *  moving through the replay, not the replay playing. Written to the root as `--rp-anim`; every
 *  duration in replay.css that belongs to a reveal is `calc(<base> * var(--rp-anim))`. */
const ANIM_MIN = 0.2;
const ANIM_MAX = 4;
export const animFactor = (speed: number) => Math.min(ANIM_MAX, Math.max(ANIM_MIN, 1 / Math.max(1e-3, speed)));
const UNLABELLED = 'unlabelled';
const SPEED_KEY = 'iris.replay.speed';
const SKIP_KEY = 'iris.replay.skipQuiet';

/** How much INCIDENT time before the next event the chosen speed resumes, at speed `sp`: 5 s, unless
 *  that would be under 3 s of screen (a fast speed) or over 8 s of it (a slow one). */
function ffNear(sp: number): number {
  return FF_NEAR_SCREEN_MS * sp;
}
/** The fast-forward across the gap from the event at `tp` to the next one at `tn`: the stretch
 *  [lo, hi] it covers, its top rate and the ramp constant `tau`, or null when the gap is too short to
 *  need one.
 *  The ramps are EXPONENTIAL in the rate - v = sp + distance / tau - so the rate grows by the same RATIO
 *  every frame, which is what reads as smooth: a constant-acceleration (square-root) ramp put a 29x jump
 *  into the first frame of a three-hour gap. `tau` is chosen so each ramp lasts FF_RAMP_MS whatever the
 *  ratio, and each covers tau x (top - sp) of incident time; `top` is then solved (bisection - the left
 *  side grows with it) so ramp + cruise + ramp takes FF_CROSS_MS.
 *  `G` is unused (kept for the call sites): what is quiet is decided in SCREEN time, see FF_QUIET_SCREEN_MS. */
const ffMemo = { key: '', plan: null as { lo: number; hi: number; top: number; tau: number } | null };
function ffPlan(tp: number, tn: number, sp: number, G: number): { lo: number; hi: number; top: number; tau: number } | null {
  const key = `${tp}|${tn}|${sp}|${G}`;
  if (ffMemo.key === key) return ffMemo.plan;
  void G;
  if ((tn - tp) / sp <= FF_QUIET_SCREEN_MS) { ffMemo.key = key; ffMemo.plan = null; return null; }
  const lo = tp + FF_HOLD_MS * sp;
  const hi = tn - ffNear(sp);
  const d = hi - lo;
  const cruise = FF_CROSS_MS - 2 * FF_RAMP_MS;
  const tauOf = (top: number) => FF_RAMP_MS / Math.log(top / sp);
  const covered = (top: number) => 2 * tauOf(top) * (top - sp) + top * cruise;
  let plan: { lo: number; hi: number; top: number; tau: number } | null = null;
  if (d > 0 && covered(sp * FF_MIN_GAIN) < d) {
    let a = sp * FF_MIN_GAIN, b = Math.max(a * 2, d / cruise);
    for (let i = 0; i < 60 && b / a > 1.0005; i++) { const m = Math.sqrt(a * b); if (covered(m) < d) a = m; else b = m; }
    const top = a;
    plan = { lo, hi, top, tau: tauOf(top) };
  }
  ffMemo.key = key; ffMemo.plan = plan;
  return plan;
}
/** The clock's rate (incident ms per screen ms) at instant `t` of that gap: the chosen speed through
 *  the hold and the approach, the plan's top rate between them, joined by the exponential ramps. */
function ffRate(t: number, tp: number, tn: number, sp: number, G: number): number {
  const f = ffPlan(tp, tn, sp, G);
  if (!f || t <= f.lo || t >= f.hi) return sp;
  return Math.min(f.top, sp + (t - f.lo) / f.tau, sp + (f.hi - t) / f.tau);
}
/** Advance the clock `dt` screen ms from `t` through a fast-forward, EXACTLY: each ramp is solved in
 *  closed form (v = sp + distance / tau, so the distance grows or decays as e^(s / tau)) and the frame
 *  is split across the phases it crosses - ramp up, cruise, ramp down, then the chosen speed from `hi`.
 *  Stepping it per frame (t += rate x dt) was measured overshooting when the browser dropped a frame
 *  at the tail of the slow-down: 306x -> 38x in one 18 ms frame, where the curve itself changes ~2x. */
function ffAdvance(t: number, dt: number, f: { lo: number; hi: number; top: number; tau: number }, sp: number): number {
  const k = sp * f.tau;
  const ramp = f.tau * (f.top - sp);                 // incident distance each ramp covers
  const upEnd = f.lo + ramp;
  const downAt = Math.max(upEnd, f.hi - ramp);
  let rem = dt;
  for (let i = 0; i < 5 && rem > 0; i++) {
    if (t >= f.hi) return t + rem * sp;
    if (t >= downAt) {                                // ramp down: x = hi - t decays
      const x0 = f.hi - t;
      const s = f.tau * Math.log((x0 + k) / k);       // screen time to reach hi
      if (rem < s) return f.hi - ((x0 + k) * Math.exp(-rem / f.tau) - k);
      t = f.hi; rem -= s;
    } else if (t < upEnd) {                           // ramp up: y = t - lo grows
      const y0 = Math.max(0, t - f.lo), y1 = Math.min(upEnd, downAt) - f.lo;
      const s = f.tau * Math.log((y1 + k) / (y0 + k));
      if (rem < s) return f.lo + (y0 + k) * Math.exp(rem / f.tau) - k;
      t = f.lo + y1; rem -= s;
    } else {                                          // cruise at the top rate
      const s = (downAt - t) / f.top;
      if (rem < s) return t + rem * f.top;
      t = downAt; rem -= s;
    }
  }
  return t;
}
/** A rate as the indicator says it: 35x, 1,200x. */
const rateX = (v: number) => `${v < 10 ? v.toFixed(1) : Math.round(v).toLocaleString()}×`;

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
interface MapNode { key: string; role: string; value: string; verb: string; t: number; first: number; lane: number; host: string }
/** `actor`: b was done BY a's process (spawned, wrote, loaded, connected); `shared`: they touched the
 *  same thing. `label` is the reason in two or three words, drawn on the line; `detail` the sentence. */
interface MapEdge {
  a: string; b: string; at: number; kind: 'actor' | 'shared'; label: string; detail: string;
  /** b is a NEW thing a produced (a spawned process, a file it ran): the layout puts it one column right */
  step: boolean;
  /** lower = more specific; the layout builds its tree from the most specific link into each event */
  rank: number;
}
/** Who asked for the hold: the map (a node was clicked) or the stream (a card was). Each side scrolls
 *  itself to the held event only when the OTHER side asked — the side that was clicked is already on it. */
type HoldFrom = 'map' | 'stream';

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
  if (v < 1) return `${v}× · slow motion: 1 s of the incident takes ${+(1 / v).toFixed(2)} s on screen`;
  return `${v}× · 1 s on screen = ${v} s of the incident`;
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
        detail: `${actorName} ${label} ${it.action.object || it.action.verb}`, step: label !== 'then', rank: 0 });
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
        label: `same ${kind}`, detail: `both involve ${kind} ${value}`, step: false, rank: 4 + best.rank });
    }
    for (const k of it.ents) lastWith.set(k, it.idx);
    if (it.action.kind === 'process' && it.action.object) lastProc.set(it.action.object.toLowerCase(), it.idx);
  }
  return edges;
}

/** The server's links (app/replay.relations): EVERY tie between two events that a value both carry
 *  supports — the parent by PID, the process's own later activity, what it injected into, the domain
 *  a proxy row, a DNS row and a process's own HTTP call share. `buildEdges` above only guessed from two
 *  names, and left a process's API calls, a proxy row and a DNS row alone on the map with the tie
 *  sitting right there in their fields. Each pair appears once, with its most specific reason; a link
 *  to an event that is not on the timeline (unstamped) is dropped, never pointed somewhere else. */
function serverEdges(links: ReplayLink[], out: Item[]): MapEdge[] {
  const idx = new Map(out.map((it) => [it.en.eventId, it.idx]));
  const seen = new Set<string>();
  const edges: MapEdge[] = [];
  for (const l of links) {
    const ia = idx.get(l.a); const ib = idx.get(l.b);
    if (ia === undefined || ib === undefined || ia >= ib) continue;
    const k = edgeKey(l.a, l.b);
    if (seen.has(k)) continue;
    seen.add(k);
    edges.push({ a: l.a, b: l.b, at: ib, kind: l.kind, label: l.label, detail: l.detail,
      step: l.rel === 'spawned' || l.rel === 'executed', rank: l.rank });
  }
  // Most specific first: the layout takes the FIRST link into each event as the one it builds from.
  return edges.sort((p, q) => p.rank - q.rank || p.at - q.at);
}

/* ───────── the map: what the intrusion has reached, BUILT as the replay reaches it ───────── */
const NODE_W = 190;
const NODE_H = 44;
/** Outer padding of the drawing inside its frame. */
const MAP_PAD = 16;
const MAP_EMPTY_H = 120;
/** The geometry the layered layout works in (utils/replayLayout.ts). The column gap holds the trunks
 *  that carry a process's links to its children, and a reason plate on the one in focus. */
const LAYOUT = { nodeW: NODE_W, nodeH: NODE_H, colGap: 84, rowGap: 18, pad: 12, head: 26, blockGap: 26 };
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
  injection: { tag: 'injection', glyph: 'IN', hue: 'var(--sev-high)' },
  api: { tag: 'api call', glyph: 'A', hue: '#c98a5f' },
  alert: { tag: 'alert', glyph: '!', hue: 'var(--sev-high)' },
  event: { tag: 'event', glyph: '•', hue: 'var(--muted)' },
};

/** A path as a CSS `d` value, so a line whose end moved GLIDES to its new route (CSS transitions `d`)
 *  instead of snapping. The attribute is set too, for an engine without CSS `d`. */
const pathStyle = (d: string): CSSProperties => ({ d: `path("${d}")` } as unknown as CSSProperties);

/** The map is a LAYERED FLOW, laid out once over every event (utils/replayLayout.ts): columns are
 *  causal depth — a process, then what it spawned, then what those did — and a process's own later
 *  activity stacks under it. Each connected thread of events is one block, blocks sit in the order
 *  they began. Because the layout covers every event from the start, nothing moves when the replay
 *  reaches the next one: the map draws what has been reached, in place, and its frame grows to hold it. */
/** Map zoom bounds, and the step one button press / key / wheel notch takes. */
const MZ_MIN = 0.25;
const MZ_MAX = 4;
const MZ_STEP = 1.25;
/** A pointer that travels further than this before it is released was a PAN, not a click. */
const MZ_DRAG_PX = 4;
interface MapView { k: number; x: number; y: number }

const AttackMap = memo(function AttackMap({ nodes, edges, lanes, reached, current, held, holdFrom, onHold, onOpenEvent, zoomSlot }: {
  nodes: MapNode[]; edges: MapEdge[]; lanes: string[]; reached: number; current: string | null;
  /** Where the zoom controls go: a slot in the map card's header, owned by the replay. */
  zoomSlot?: HTMLElement | null;
  /** The HELD event (clicked here or on its stream card), or null. The replay owns it: one state, so
   *  the map and the stream can never disagree about which event is held. */
  held: string | null; holdFrom: HoldFrom;
  onHold: (id: string | null) => void;
  /** Open the event's own page. */
  onOpenEvent: (id: string) => void;
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
  // Focus: the event under the pointer, else the held one, else the one being played. A held event
  // the replay has not reached yet (a seek back) is not on the map, so it holds nothing.
  const [hover, setHover] = useState<string | null>(null);
  const pinned = held != null && shown.some((n) => n.key === held) ? held : null;
  const focus = hover ?? pinned ?? current;
  const chosen = hover != null || pinned != null;
  const toggle = (key: string) => onHold(pinned === key ? null : key);
  // Over EVERY event, not the reached ones: that is what keeps a node where it first appeared.
  const L = useMemo(() => layoutReplay(
    nodes.map((n) => ({ key: n.key, first: n.first, host: n.host })),
    // An actor link to the process's OWN activity ('then') keeps it under the process; one to a thing
    // it produced (spawned, wrote, loaded, connected to) moves that thing to the next column.
    edges.map((ed) => ({ a: ed.a, b: ed.b, kind: ed.kind, step: ed.step })),
    { ...LAYOUT, avail: avail - 2 * MAP_PAD }), [nodes, edges, avail]);
  const pos = useMemo(() => {
    const m = new Map<string, { x: number; y: number }>();
    for (const [k, p] of L.pos) m.set(k, { x: p.x + MAP_PAD, y: p.y + MAP_PAD });
    return m;
  }, [L]);
  const vbW = Math.max(L.width + 2 * MAP_PAD, avail);   // wider only when one thread alone cannot fit
  const overflow = vbW > avail + 1;
  // The frame is CROPPED to what has been reached — the drawing is laid out for every event, the frame
  // only ever shows as far down as the replay has got, and eases to its new height.
  const contentH = shown.length ? Math.max(...shown.map((n) => pos.get(n.key)!.y + NODE_H)) + MAP_PAD + 2 : 0;
  const svgH = Math.max(contentH, L.height + 2 * MAP_PAD);

  /* ── zoom and pan ──
     The view (scale k, offset x/y in screen px) lives in a REF and reaches the drawing as CSS custom
     properties on one wrapper, so a wheel notch or a drag frame never re-renders the map (the seek bar's
     zoom works the same way). React only hears about the switch between the two MODES:
       natural (zoomH null) - exactly the map as it always was: natural size, the frame grows with what
         has been reached, the page scrolls past it;
       zoomed (zoomH = a fixed viewport height) - the analyst's own view, kept while new events appear,
         until they press Fit. The height is frozen at entry (at most 70 % of the window) so the page
         under the map does not jump while they zoom. */
  const frameRef = useRef<HTMLDivElement>(null);
  const zoomRef = useRef<HTMLDivElement>(null);
  const readRef = useRef<HTMLSpanElement>(null);
  const minusRef = useRef<HTMLButtonElement>(null);
  const plusRef = useRef<HTMLButtonElement>(null);
  const oneRef = useRef<HTMLButtonElement>(null);
  const view = useRef<MapView>({ k: 1, x: 0, y: 0 });
  const [zoomH, setZoomH] = useState<number | null>(null);
  const zoomHRef = useRef<number | null>(null);
  const dims = useRef({ w: 0, h: 0 });
  dims.current = { w: vbW, h: contentH };
  const glideTimer = useRef(0);
  const viewport = () => ({ vw: box.current?.clientWidth ?? 0, vh: zoomHRef.current ?? dims.current.h });
  // Content can never be lost: bigger than the viewport, it covers it; smaller, it stays wholly inside.
  const clampView = (v: MapView): MapView => {
    const { vw, vh } = viewport();
    const cl = (p: number, room: number) => Math.min(Math.max(0, room), Math.max(Math.min(0, room), p));
    return { k: v.k, x: cl(v.x, vw - dims.current.w * v.k), y: cl(v.y, vh - dims.current.h * v.k) };
  };
  const apply = (v: MapView, glide = false) => {
    view.current = v;
    const z = zoomRef.current;
    if (z) {
      z.style.setProperty('--rp-mx', `${v.x.toFixed(2)}px`);
      z.style.setProperty('--rp-my', `${v.y.toFixed(2)}px`);
      z.style.setProperty('--rp-mk', v.k.toFixed(4));
      if (glide && !reducedMotion()) {
        z.classList.add('rp-mapzoom--glide');
        window.clearTimeout(glideTimer.current);
        glideTimer.current = window.setTimeout(() => z.classList.remove('rp-mapzoom--glide'), 280);
      }
    }
    const zoomed = zoomHRef.current != null;
    if (readRef.current) readRef.current.textContent = `${Math.round((zoomed ? v.k : 1) * 100)}%`;
    if (minusRef.current) minusRef.current.disabled = zoomed && v.k <= MZ_MIN + 1e-3;
    if (plusRef.current) plusRef.current.disabled = zoomed && v.k >= MZ_MAX - 1e-3;
    if (oneRef.current) oneRef.current.disabled = !zoomed || Math.abs(v.k - 1) < 1e-3;
  };
  // Leave the natural view for a zoomed one, starting from exactly what is on screen now.
  const ensureZoomed = () => {
    if (zoomHRef.current != null) return;
    const b = box.current; const f = frameRef.current;
    const cur = f ? f.getBoundingClientRect().height : dims.current.h;
    const h = Math.round(Math.min(Math.max(cur, 310), Math.max(240, window.innerHeight * 0.7)));
    const sx = b?.scrollLeft ?? 0;
    zoomHRef.current = h;
    view.current = { k: 1, x: -sx, y: 0 };
    if (b) b.scrollLeft = 0;
    if (f) { f.classList.add('rp-mapframe--zoomed'); f.style.height = `${h}px`; f.style.width = '100%'; }
    setZoomH(h);
  };
  /** Zoom by `factor` about a point given in the FRAME's own pixels: that point stays put. */
  const zoomAt = (factor: number, px: number, py: number, glide = false) => {
    ensureZoomed();
    const v = view.current;
    const k = Math.min(MZ_MAX, Math.max(MZ_MIN, v.k * factor));
    const r = k / v.k;
    apply(clampView({ k, x: px - (px - v.x) * r, y: py - (py - v.y) * r }), glide);
  };
  const zoomCentre = (factor: number) => {
    ensureZoomed();
    const { vw, vh } = viewport();
    zoomAt(factor, vw / 2, vh / 2, true);
  };
  const panBy = (dx: number, dy: number) => {
    if (zoomHRef.current == null) {                 // natural view: only a map wider than its card moves
      if (box.current) box.current.scrollLeft -= dx;
      return;
    }
    const v = view.current;
    apply(clampView({ k: v.k, x: v.x + dx, y: v.y + dy }));
  };
  const fit = () => {
    zoomHRef.current = null;
    const f = frameRef.current;
    if (f) f.classList.remove('rp-mapframe--zoomed');
    apply({ k: 1, x: 0, y: 0 }, true);
    setZoomH(null);
  };
  const actualSize = () => {
    if (zoomHRef.current == null) return;
    const { vw, vh } = viewport();
    zoomAt(1 / view.current.k, vw / 2, vh / 2, true);
  };
  // Every render re-asserts the view (a remounted frame, a new node) and the controls' states.
  useLayoutEffect(() => { apply(view.current); });

  // WHEEL. Ctrl/Cmd+wheel (and a trackpad pinch, which the browser reports as one) zooms about the
  // pointer. Shift+wheel or a sideways two-finger scroll pans a zoomed map. A plain vertical wheel is
  // NEVER taken: it scrolls the page, zoomed or not. Non-passive, so it has to be a real listener.
  const wheelRef = useRef<(e: WheelEvent) => void>(() => undefined);
  wheelRef.current = (e: WheelEvent) => {
    if (e.ctrlKey || e.metaKey) {
      const r = frameRef.current?.getBoundingClientRect();
      if (!r) return;
      e.preventDefault();
      const dy = e.deltaMode === 1 ? e.deltaY * 16 : e.deltaY;
      // a mouse notch is ~100, a pinch sends small deltas many times a second
      zoomAt(Math.exp(-dy * (Math.abs(dy) < 40 ? 0.012 : 0.0025)), e.clientX - r.left, e.clientY - r.top);
      return;
    }
    if (zoomHRef.current == null) return;           // natural view: the browser's own scrolling
    const unit = e.deltaMode === 1 ? 16 : 1;
    const side = e.shiftKey ? (e.deltaY || e.deltaX) : (Math.abs(e.deltaX) > Math.abs(e.deltaY) ? e.deltaX : 0);
    if (!side) return;
    e.preventDefault();
    panBy(-side * unit, 0);
  };
  const hasFrame = shown.length > 0;
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const on = (e: WheelEvent) => wheelRef.current(e);
    el.addEventListener('wheel', on, { passive: false });
    return () => el.removeEventListener('wheel', on);
  }, [hasFrame, nodes.length > 0]);

  // DRAG to pan (mouse, pen, or one finger on a zoomed map), PINCH to zoom (two fingers). Nothing is
  // captured until the pointer has travelled MZ_DRAG_PX: capturing on press would retarget the click,
  // and a node must still be clickable. A drag that did travel swallows the click it ends in.
  const drag = useRef<{ id: number; sx: number; sy: number; lx: number; ly: number; moved: boolean } | null>(null);
  const touches = useRef(new Map<number, { x: number; y: number }>());
  const pinch = useRef<{ d: number; k: number; mx: number; my: number } | null>(null);
  const swallowClick = useRef(false);
  const pannable = () => zoomHRef.current != null || (box.current ? box.current.scrollWidth > box.current.clientWidth + 1 : false);
  const twoFinger = () => {
    const [a, b] = [...touches.current.values()];
    return { d: Math.hypot(a!.x - b!.x, a!.y - b!.y) || 1, mx: (a!.x + b!.x) / 2, my: (a!.y + b!.y) / 2 };
  };
  const onFrameDown = (e: ReactPointerEvent<HTMLDivElement>) => {
    if ((e.target as Element).closest('.rp-openev, .rp-mapfitpill')) return;
    if (e.pointerType === 'touch') {
      touches.current.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (touches.current.size === 2) {
        const t = twoFinger();
        pinch.current = { d: t.d, k: zoomHRef.current == null ? 1 : view.current.k, mx: t.mx, my: t.my };
        drag.current = null;
        return;
      }
      // natural view: a finger scrolls the PAGE (touch-action lets it); only a zoomed map is dragged
      if (zoomHRef.current == null) return;
    } else {
      if (e.button === 1 && pannable()) e.preventDefault();    // no autoscroll on a middle-drag
      else if (e.button !== 0) return;
      if (!pannable()) return;
    }
    drag.current = { id: e.pointerId, sx: e.clientX, sy: e.clientY, lx: e.clientX, ly: e.clientY, moved: false };
  };
  const onFrameMove = (e: ReactPointerEvent<HTMLDivElement>) => {
    if (e.pointerType === 'touch' && touches.current.has(e.pointerId)) {
      touches.current.set(e.pointerId, { x: e.clientX, y: e.clientY });
      const p = pinch.current;
      if (p && touches.current.size >= 2) {
        const r = frameRef.current?.getBoundingClientRect();
        if (!r) return;
        const t = twoFinger();
        const target = Math.min(MZ_MAX, Math.max(MZ_MIN, p.k * (t.d / p.d)));
        const cur = zoomHRef.current == null ? 1 : view.current.k;
        zoomAt(target / cur, t.mx - r.left, t.my - r.top);
        panBy(t.mx - p.mx, t.my - p.my);
        p.mx = t.mx; p.my = t.my;
        swallowClick.current = true;
        return;
      }
    }
    const d = drag.current;
    if (!d || d.id !== e.pointerId) return;
    if (!d.moved) {
      if (Math.hypot(e.clientX - d.sx, e.clientY - d.sy) <= MZ_DRAG_PX) return;
      d.moved = true;
      try { frameRef.current?.setPointerCapture(e.pointerId); } catch { /* pointer already gone */ }
      frameRef.current?.classList.add('rp-mapframe--panning');
    }
    panBy(e.clientX - d.lx, e.clientY - d.ly);
    d.lx = e.clientX; d.ly = e.clientY;
  };
  const onFrameUp = (e: ReactPointerEvent<HTMLDivElement>) => {
    touches.current.delete(e.pointerId);
    if (touches.current.size < 2) pinch.current = null;
    const d = drag.current;
    if (!d || d.id !== e.pointerId) return;
    drag.current = null;
    if (d.moved) {
      swallowClick.current = true;
      window.setTimeout(() => { swallowClick.current = false; }, 0);
      frameRef.current?.classList.remove('rp-mapframe--panning');
      try { frameRef.current?.releasePointerCapture(e.pointerId); } catch { /* released already */ }
    }
  };
  const onFrameClickCapture = (e: ReactMouseEvent) => {
    if (!swallowClick.current) return;
    swallowClick.current = false;
    e.stopPropagation(); e.preventDefault();
  };
  // + / - / 0 while the map (or anything in it) has focus. The seek bar's own + / - / 0 are handled on
  // the seek bar, so the two never both fire. Arrows pan a zoomed map when the map itself is focused.
  const onMapKey = (ev: ReactKeyboardEvent<HTMLDivElement>) => {
    if (ev.ctrlKey || ev.metaKey || ev.altKey) return;
    const k = ev.key;
    if (k === '+' || k === '=') zoomCentre(MZ_STEP);
    else if (k === '-' || k === '_') zoomCentre(1 / MZ_STEP);
    else if (k === '0') fit();
    else if (zoomHRef.current != null && ev.target === ev.currentTarget && k.startsWith('Arrow')) {
      const s = 60;
      panBy(k === 'ArrowLeft' ? s : k === 'ArrowRight' ? -s : 0, k === 'ArrowUp' ? s : k === 'ArrowDown' ? -s : 0);
    }
    else return;
    ev.preventDefault();
  };

  // A card clicked in the STREAM holds its node here: bring the node into view, but only when it is
  // off screen, and never when the hold came from the map (that node is under the pointer already).
  // Zoomed, that is the MAP's view moving to it - the page stays where the analyst put it.
  const nodeEls = useRef(new Map<string, SVGGElement>());
  useEffect(() => {
    if (!pinned || holdFrom !== 'stream') return;
    if (zoomHRef.current != null) {
      const p = pos.get(pinned);
      if (!p) return;
      const { vw, vh } = viewport();
      const v = view.current;
      const sx = v.x + p.x * v.k; const sy = v.y + p.y * v.k;
      const m = 12;
      if (sx < m || sy < m || sx + NODE_W * v.k > vw - m || sy + NODE_H * v.k > vh - m) {
        apply(clampView({ k: v.k, x: vw / 2 - (p.x + NODE_W / 2) * v.k, y: vh / 2 - (p.y + NODE_H / 2) * v.k }), true);
      }
      return;
    }
    const el = nodeEls.current.get(pinned);
    if (!el) return;
    const r = el.getBoundingClientRect();
    const frame = box.current?.getBoundingClientRect();
    const offX = frame ? r.left < frame.left || r.right > frame.right : false;
    const offY = r.top < 0 || r.bottom > window.innerHeight;
    if (offX || offY) el.scrollIntoView({ block: 'nearest', inline: 'nearest', behavior: reducedMotion() ? 'auto' : 'smooth' });
  }, [pinned, holdFrom]);

  // A thread's box is the bounds of what it has REACHED, so it grows with it instead of standing empty.
  const threads = useMemo(() => {
    const out: { id: number; x: number; y: number; w: number; h: number; label: string; n: number; total: number }[] = [];
    const reachedKeys = new Set(shown.map((n) => n.key));
    for (const b of L.blocks) {
      if (b.keys.length < 2) continue;
      const on = b.keys.filter((k) => reachedKeys.has(k));
      if (!on.length) continue;
      const bx = b.x + MAP_PAD; const by = b.y + MAP_PAD;
      const right = Math.max(...on.map((k) => pos.get(k)!.x + NODE_W)) + LAYOUT.pad;
      const bottom = Math.max(...on.map((k) => pos.get(k)!.y + NODE_H)) + LAYOUT.pad;
      const hosts = b.hosts.length ? b.hosts.slice(0, 2).join(', ') + (b.hosts.length > 2 ? ` +${b.hosts.length - 2}` : '') : 'no host recorded';
      out.push({ id: b.id, x: bx, y: by, w: right - bx, h: bottom - by, label: hosts, n: on.length, total: b.keys.length });
    }
    return out;
  }, [L, shown, pos]);

  /* ── connections ──
     Every route comes from the layout and never changes: out of a node's right edge, down the trunk it
     shares with its siblings in the gap between two columns, into the child's left edge. A process's
     later activity hangs under it on a short spine. The head is a stroked chevron, drawn separately
     from the line so it can land AFTER the line has drawn itself. */
  const visibleEdges = useMemo(
    () => edges.filter((ed) => ed.at < reached && pos.has(ed.a) && pos.has(ed.b) && L.routes.has(edgeKey(ed.a, ed.b))),
    [edges, reached, pos, L]);
  const route = (ed: MapEdge) => L.routes.get(edgeKey(ed.a, ed.b))!;
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
  const hue = (lane: number) => PHASE_HUES[lane % PHASE_HUES.length];
  const zoomed = zoomH != null;
  const controls = zoomSlot && createPortal(
    <span className="rp-zoom rp-mapzoomctl" role="group" aria-label="Map zoom">
      <button type="button" className="rp-zoom__b" ref={minusRef} onClick={() => zoomCentre(1 / MZ_STEP)}
        aria-label="Zoom the map out" title="Zoom out (-, or Ctrl + wheel)">−</button>
      <span className="rp-zoom__x rp-mapzoomctl__x mono" ref={readRef} aria-label="Map zoom level" />
      <button type="button" className="rp-zoom__b" ref={plusRef} onClick={() => zoomCentre(MZ_STEP)}
        aria-label="Zoom the map in" title="Zoom in (+, or Ctrl + wheel)">+</button>
      <button type="button" className="rp-zoom__fit" ref={oneRef} onClick={actualSize}
        aria-label="Actual size, keeping the centre of the view" title="Actual size, keeping the centre of the view">100%</button>
      <button type="button" className="rp-zoom__fit" onClick={fit} disabled={!zoomed}
        aria-label="Fit: back to the whole map at natural size" title="Back to the whole map at natural size, growing as it plays (0)">Fit</button>
    </span>, zoomSlot);
  return (
    <div className={cx('rp-mapview', overflow && !zoomed && 'rp-mapview--scroll', zoomed && 'rp-mapview--zoomed', chosen && 'rp-mapview--chosen')} ref={box}
      tabIndex={0} role="group" onKeyDown={onMapKey}
      aria-label="Event map. Ctrl + wheel or pinch zooms, + and - zoom, 0 fits; drag pans a zoomed map, arrow keys too."
      onPointerLeave={() => setHover(null)}>
      {controls}
      {shown.length === 0 ? (
        <div className="rp-map__wait" style={{ height: MAP_EMPTY_H }}>
          The map builds as the replay reaches each host, address, account and file.
        </div>
      ) : (
        // The FRAME eases to its new height (CSS), so the map grows instead of jumping; the drawing
        // inside is at its natural size unless the analyst has zoomed (see "zoom and pan" above).
        <div className={cx('rp-mapframe', zoomed && 'rp-mapframe--zoomed')} ref={frameRef}
          style={zoomed ? { height: zoomH, width: '100%' } : { height: contentH, width: vbW }}
          onPointerDown={onFrameDown} onPointerMove={onFrameMove} onPointerUp={onFrameUp} onPointerCancel={onFrameUp}
          onClickCapture={onFrameClickCapture}>
          <div className="rp-mapzoom" ref={zoomRef} style={{ width: vbW, height: svgH }}>
          <svg className="rp-map" width={vbW} height={svgH}
            viewBox={`0 0 ${vbW} ${svgH}`}
            role="img" aria-label={`Map of the ${shown.length} events the replay has reached so far, laid out by what caused what`}>
            {threads.map((z) => (
              <g key={z.id} className="rp-thread">
                <rect className="rp-thread__box" x={z.x} y={z.y} width={z.w} height={z.h} rx={6}
                  style={{ width: z.w, height: z.h } as CSSProperties} />
                <text className="rp-thread__hd" x={z.x + 12} y={z.y + 17}>
                  {trunc(z.label, Math.max(8, Math.floor((z.w - 90) / 6.6)))}
                  <tspan className="rp-thread__n" dx={8}>{z.n === z.total ? `${z.n} events` : `${z.n} of ${z.total}`}</tspan>
                </text>
              </g>
            ))}
            {ordered.map((ed) => {
              const { d, head } = route(ed);
              const on = hot(ed);
              return (
                <g key={`${ed.a}|${ed.b}`}
                  // A SECONDARY link (not the one the layout was built from) is drawn too - dashed and
                  // lighter, stronger on focus - so a node is alone on the map only when nothing ties it.
                  className={cx('rp-link', `rp-link--${ed.kind}`, !L.primary.has(edgeKey(ed.a, ed.b)) && 'rp-link--extra',
                    on && 'rp-link--hot', !on && chosen && 'rp-link--back')}
                  style={{ transform: `translate(${MAP_PAD}px, ${MAP_PAD}px)`, ['--c' as string]: hue(laneOfNode.get(ed.b) ?? 0) }}>
                  <title>{ed.detail}</title>
                  {/* an actor link draws itself (a normalised dash); a shared one is DASHED, so it fades in */}
                  <path className="rp-edge" d={d} style={pathStyle(d)}
                    pathLength={ed.kind === 'actor' && L.primary.has(edgeKey(ed.a, ed.b)) ? 1 : undefined} />
                  <path className="rp-arrowhead" d={head} style={pathStyle(head)} />
                </g>
              );
            })}
            {shown.map((n) => {
              const p = pos.get(n.key)!;
              const meta = ACTION_META[n.role] ?? ACTION_META.event!;
              const c = utcParts(n.t);
              const dim = chosen && !near.has(n.key);
              const phase = lanes[n.lane] ?? UNLABELLED;
              return (
                <g key={n.key} className={cx('rp-nodepos', dim && 'rp-nodepos--dim')} style={{ transform: `translate(${p.x}px, ${p.y}px)`, ['--c' as string]: meta.hue, ['--ph' as string]: hue(n.lane) }}
                  ref={(el) => { if (el) nodeEls.current.set(n.key, el); else nodeEls.current.delete(n.key); }}
                  tabIndex={0} role="button" aria-pressed={pinned === n.key}
                  aria-label={`${n.verb}: ${n.value}, ${c.clock} UTC. Space holds its links, Enter opens the event.`}
                  onPointerEnter={() => setHover(n.key)}
                  // The second click of a double-click (detail 2) is ignored: the first one held the
                  // node and the double-click opens it, so it never ends up released under the pointer.
                  onClick={(ev) => { if (ev.detail < 2) toggle(n.key); }}
                  onDoubleClick={() => { onHold(n.key); onOpenEvent(n.key); }}
                  onKeyDown={(ev) => {
                    if (ev.key === 'Enter') { ev.preventDefault(); onOpenEvent(n.key); }
                    else if (ev.key === ' ') { ev.preventDefault(); toggle(n.key); }
                  }}>
                  <g className={cx('rp-node', n.key === current && 'rp-node--now', n.key === focus && chosen && 'rp-node--focus', pinned === n.key && 'rp-node--held')}>
                    <title>{`${c.clock}${c.ms} UTC — ${n.verb}: ${n.value}\nphase: ${phase}${n.host ? `\nhost: ${n.host}` : ''}${pinned === n.key ? '\n(click again to release; double-click to open the event)' : '\n(click to hold its links; double-click to open the event)'}`}</title>
                    <rect className="rp-node__box" width={NODE_W} height={NODE_H} rx={5} />
                    {/* the phase it belongs to: a rule down the left edge, in the phase's colour */}
                    <rect className="rp-node__phase" x={0.6} y={6} width={2.6} height={NODE_H - 12} />
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
              const { mid, side, pts } = route(ed);
              const w = Math.round(ed.label.length * 6.1 + 14);
              // A plate never sits on an event: with every link now drawn, a secondary one's midpoint can
              // fall on a node's title. Try the layout's spot, then the middle of each stretch of the
              // route (and beside it), and take the first that covers no node.
              const covers = (cx0: number, cy0: number) => shown.some((n) => {
                const p = pos.get(n.key)!;
                return cx0 < p.x + NODE_W && cx0 + w > p.x && cy0 - 9 < p.y + NODE_H && cy0 + 9 > p.y;
              });
              let at = { x: mid.x + MAP_PAD + (side === 'r' ? 0 : -w / 2), y: mid.y + MAP_PAD };
              if (covers(at.x, at.y)) {
                for (let i = 1; i < pts.length; i++) {
                  const mx = (pts[i - 1]!.x + pts[i]!.x) / 2 + MAP_PAD; const my = (pts[i - 1]!.y + pts[i]!.y) / 2 + MAP_PAD;
                  const c0 = [mx - w / 2, mx + 6, mx - w - 6].map((x) => ({ x, y: my })).find((c) => !covers(c.x, c.y));
                  if (c0) { at = c0; break; }
                }
              }
              const x0 = 0;
              return (
                <g key={`l|${ed.a}|${ed.b}`} className={cx('rp-elabel', `rp-elabel--${ed.kind}`)}
                  style={{ transform: `translate(${at.x}px, ${at.y}px)`, ['--c' as string]: hue(laneOfNode.get(ed.b) ?? 0) }}>
                  <title>{ed.detail}</title>
                  <rect x={x0} y={-9} width={w} height={18} rx={3} />
                  <text x={x0 + w / 2} y={3.5} textAnchor="middle">{ed.label}</text>
                </g>
              );
            })}
          </svg>
          {/* The held event can be OPENED: a real button beside its node (keyboard reachable, never
              hover-only), placed in the same coordinates as the drawing. */}
          {pinned && pos.has(pinned) && (
            <button type="button" className="rp-openev" onClick={() => onOpenEvent(pinned)}
              // right-aligned under the node, in the row gap: the frame clips its sides, never the gap
              style={{ left: pos.get(pinned)!.x + NODE_W, top: pos.get(pinned)!.y + NODE_H + 1 }}
              title="Open this event's detail page">Open event</button>
          )}
          </div>
          {/* Zoomed, the way back sits on the map itself too, not only in a header scrolled away. */}
          {zoomed && (
            <button type="button" className="rp-mapfitpill" onClick={fit}
              aria-label="Fit: back to the whole map at natural size" title="Back to the whole map at natural size (0)">Fit map</button>
          )}
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
const PhaseActivity = memo(function PhaseActivity({ phases, active, pct, newestFirst, picked, onPick }: {
  phases: PhaseStat[]; active: number; pct: (t: number) => number; newestFirst: boolean;
  /** Phases the stream is filtered to (empty = no filter). The filter touches the STREAM only. */
  picked: ReadonlySet<number>; onPick: (li: number) => void;
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
          // A real button: pressing it narrows the live stream to this phase (several may be chosen).
          // The inner parts are spans, because a button may only hold phrasing content.
          <button type="button" key={ph.li} aria-pressed={picked.has(ph.li)}
            className={cx('rp-phase', now && 'rp-phase--active', complete && !now && 'rp-phase--done',
              picked.has(ph.li) && 'rp-phase--picked', picked.size > 0 && !picked.has(ph.li) && 'rp-phase--other')}
            style={{ ['--c' as string]: PHASE_HUES[ph.li % PHASE_HUES.length] }}
            title={picked.has(ph.li) ? 'Showing this phase in the stream - click to stop filtering by it'
              : 'Show only this phase in the live event stream (click more to add them)'}
            onClick={() => onPick(ph.li)}>
            <span className="rp-phase__row">
              <span className="rp-phase__dot" />
              <span className="rp-phase__nm">{ph.name}</span>
              <span className="rp-phase__when mono">{utcParts(ph.first).clock}{ph.last > ph.first ? ` → ${utcParts(ph.last).clock}` : ''}</span>
              <span className="rp-phase__ct mono">{ph.done}<i>/{ph.total}</i></span>
            </span>
            {ph.desc && <span className="rp-phase__ds" title={ph.desc}>{ph.desc}</span>}
            <span className="rp-phase__bar"><span style={{ transform: `scaleX(${ph.done / ph.total})` }} /></span>
            <span className="rp-phase__trk" aria-hidden>
              {ph.ticks.map((tk, i) => (
                <span key={i} className={cx('rp-phase__tick', tk.on && 'rp-phase__tick--on')} style={{ left: `${pct(tk.t)}%` }} />
              ))}
              {/* driven by --rp-pu on the replay root: moves every frame without a render */}
              <span className="rp-phase__head" />
            </span>
          </button>
        );
      })}
      {ahead > 0 && <div className="rp-phases__ahead">{ahead} more phase{ahead === 1 ? '' : 's'} ahead</div>}
    </div>
  );
});

/* ───────── the live stream: typed in as it happens, in the timeline's order ───────── */
function StreamLine({ it, fresh, age, skipped, onOpen, anim, hl, follow, onHold }: {
  it: Item; fresh: boolean; age: number; skipped: boolean; onOpen: (id: string) => void; anim: number;
  /** Held (on the map or here): drawn highlighted. */
  hl: boolean;
  /** Scroll the stream to it: only when the MAP asked. A card clicked here is already on screen, and
   *  moving the stream under the pointer that just clicked it is the jump this must never make. */
  follow: boolean;
  /** Click the card: hold its node on the map (again: release). */
  onHold: (id: string) => void;
}) {
  const row = useRef<HTMLDivElement>(null);
  useEffect(() => {
    // Scroll the STREAM to it, never the page: scrollIntoView would also move the window.
    const el = row.current;
    const wrap = el?.closest('.rp-logwrap') as HTMLElement | null;
    if (!hl || !follow || !el || !wrap) return;
    const top = el.offsetTop - wrap.clientHeight / 2 + el.offsetHeight / 2;
    wrap.scrollTo({ top: Math.max(0, top), behavior: reducedMotion() ? 'auto' : 'smooth' });
  }, [hl]);
  const text = it.said || trunc(it.e.raw || it.e.msg, 220);
  const shown = useTypewriter(text, fresh, anim);
  const typing = shown.length < text.length;
  const p = utcParts(it.t);
  const flare = milestone(it);
  return (
    // The card is a toggle for its node on the map. It is a div with button semantics rather than a
    // <button>, because it holds the "open" button and a button may not contain another; that button,
    // and any link in the text, stop their click from reaching the card.
    <div ref={row} className={cx('rp-ln', age === 0 && 'rp-ln--new', flare && beatTone(flare) === 'bad' && 'rp-ln--flare', hl && 'rp-ln--hl')}
      role="button" tabIndex={0} aria-pressed={hl}
      title={hl ? 'Held on the map - click to release' : 'Click to find this event on the map and hold its links'}
      onClick={(ev) => {
        if ((ev.target as HTMLElement).closest('button, a')) return;
        if (window.getSelection()?.toString()) return;     // selecting text to copy is not a click
        onHold(it.en.eventId);
      }}
      onKeyDown={(ev) => {
        if (ev.target !== ev.currentTarget) return;
        if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); onHold(it.en.eventId); }
      }}
      style={{ ['--c' as string]: PHASE_HUES[it.lane % PHASE_HUES.length], opacity: hl ? 1 : Math.max(0.45, 1 - age * 0.09) }}>
      <span className="rp-ln__ts mono">{p.clock}{it.precise ? <i>{p.ms}</i> : null}
        {skipped && <em>after a skipped lull</em>}</span>
      <span className="rp-ln__body">
        <span className="rp-ln__head">
          {/* the phase it belongs to, in the phase's own colour and marker - the same ones the
              phase activity list and the map's phase rule use, so a row matches its phase at a glance */}
          <span className="rp-ln__tag" title={`Phase: ${it.en.labels[0] || UNLABELLED}`}>
            <span className="rp-ln__tagdot" aria-hidden />{it.en.labels[0] || UNLABELLED}
          </span>
          <button type="button" className="rp-ln__open" onClick={(ev) => { ev.stopPropagation(); onOpen(it.en.eventId); }}
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
const Stream = memo(function Stream({ items, reached, skipped, onOpen, newestFirst, picked, onClear, anim, held, holdFrom, onHold }: {
  items: Item[]; reached: number; skipped: Set<number>; onOpen: (id: string) => void; newestFirst: boolean;
  /** The held event: its card is highlighted, and shown even when a phase filter hides its phase. */
  held: string | null; holdFrom: HoldFrom;
  onHold: (id: string) => void;
  /** Phases chosen in Phase activity: only their rows are shown. Empty = every row. */
  picked: ReadonlySet<number>; onClear: () => void; anim: number;
}) {
  // Remember which rows were already on screen: only a row that ARRIVES is typed in. A seek or a
  // step back re-mounts rows, and retyping a screenful of history would be noise.
  const seen = useRef<Set<string>>(new Set());
  const wrap = useRef<HTMLDivElement>(null);
  const atEdge = useRef(true);         // following the newest row (top or bottom, by the order)
  const done = items.slice(0, reached);
  const kept = picked.size ? done.filter((it) => picked.has(it.lane) || it.en.eventId === held) : done;
  const shown = newestFirst ? [...kept].reverse() : kept;
  useEffect(() => { for (const it of shown) seen.current.add(it.en.eventId); });
  // Oldest first puts the newest row at the BOTTOM: follow it there, smoothly, unless the analyst has
  // scrolled up to read something (then stay put — yanking the view away mid-read is worse).
  useLayoutEffect(() => {
    const el = wrap.current;
    if (!el || !atEdge.current || held) return;     // a held card owns the scroll position
    const top = newestFirst ? 0 : el.scrollHeight;
    el.scrollTo({ top, behavior: reducedMotion() ? 'auto' : 'smooth' });
  }, [reached, newestFirst, picked]);
  const onScroll = () => {
    const el = wrap.current;
    if (!el) return;
    atEdge.current = newestFirst ? el.scrollTop < 40 : el.scrollHeight - el.clientHeight - el.scrollTop < 60;
  };
  return (
    <>
    {/* A filtered stream always says so: it must never be mistaken for the whole replay. */}
    {picked.size > 0 && (
      <div className="rp-logfilter" role="status">
        <span>Showing <b className="mono">{kept.length}</b> of <b className="mono">{done.length}</b> event{done.length === 1 ? '' : 's'} so far
          · {picked.size} phase{picked.size === 1 ? '' : 's'}</span>
        <button type="button" className="rp-logfilter__clear" onClick={onClear}>Clear</button>
      </div>
    )}
    <div className="rp-logwrap" ref={wrap} onScroll={onScroll}>
      {!shown.length ? (
        <div className="rp-log rp-log--idle">{done.length && picked.size ? 'No event in the chosen phases yet.' : 'Waiting for the first event…'}</div>
      ) : (
        <div className="rp-log" aria-live="polite" aria-relevant="additions">
          {shown.map((it, i) => {
            const age = newestFirst ? i : shown.length - 1 - i;
            return (
              <StreamLine key={it.en.eventId} it={it} age={age} skipped={skipped.has(it.idx)} onOpen={onOpen} anim={anim}
                hl={it.en.eventId === held} follow={holdFrom === 'map'} onHold={onHold}
                fresh={age === 0 && !seen.current.has(it.en.eventId)} />
            );
          })}
        </div>
      )}
    </div>
    </>
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
  const links = ctx.data?.links;
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
        verb: it.action.verb, t: it.t, first: it.idx, lane: it.lane, host: real(it.e.host) ? it.e.host : '' })),
      edges: links ? serverEdges(links, out) : buildEdges(out, display),
    };
  }, [entries, byId, ctxById, links]);
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
  const ffFor = useRef(-1);          // the event whose approach was fast-forwarded (marked once)
  const ffRef = useRef<HTMLSpanElement>(null);

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
  // SCROLL ANCHORING, done here. "When replay is playing and things are generating the scrollbar for
  // the page keeps resetting": the map grows as events are reached and pushed everything under it
  // (the stream, the phases) down under the reader. The browser's own anchoring compensated only
  // sometimes - measured, the stream drifted 100 -> 266 px down the screen in 14 s with scrollY
  // unchanged, and a manual fix stacked on top of it overshot. So the replay opts out of it
  // (`overflow-anchor: none` on .rp) and anchors on the STREAM: while the stream is on screen and the
  // map's bottom is above the viewport, any change in the stream's position is scrolled back out.
  // While the map itself is in view nothing is adjusted - it grows downward, as it should.
  useEffect(() => {
    const root = rootRef.current;
    if (!root || typeof ResizeObserver === 'undefined') return;
    const anchorEl = () => root.querySelector<HTMLElement>('.rp-logwrap');
    let last = anchorEl()?.getBoundingClientRect().top ?? null;
    let sy = window.scrollY;
    const sync = () => { last = anchorEl()?.getBoundingClientRect().top ?? null; sy = window.scrollY; };
    // A scroll moves the anchor by exactly the scroll delta. Re-reading the layout here instead would
    // also swallow growth that landed since the last observation, and lose part of each correction.
    const onScroll = () => { if (last != null) last -= window.scrollY - sy; sy = window.scrollY; };
    const ro = new ResizeObserver(() => {
      const a = anchorEl();
      if (!a) { last = null; return; }
      const top = a.getBoundingClientRect().top;
      const map = root.querySelector<HTMLElement>('.rp-mapframe, .rp-map__wait');
      const mapAbove = !map || map.getBoundingClientRect().bottom < 64;
      if (last != null && top !== last && mapAbove && top < window.innerHeight && !document.fullscreenElement) {
        window.scrollBy(0, top - last);
        last = top - (window.scrollY - sy);     // where the anchor is after the correction
        sy = window.scrollY;
        return;
      }
      sync();
    });
    ro.observe(root);                             // anything above the stream changes the root's height
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => { ro.disconnect(); window.removeEventListener('scroll', onScroll); };
    // Once the replay is on screen, for its life: re-running per render would re-read the layout
    // mid-growth. (The section is not rendered until there is something to replay.)
  }, [items.length > 0]);
  /** The map card's header slot its zoom controls are portalled into (the map owns the view). */
  const [mapZoomSlot, setMapZoomSlot] = useState<HTMLSpanElement | null>(null);
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
    // "on screen" is a promise about the wait; a gap that will be fast-forwarded cannot keep it at sp.
    const ffGap = live.current.skipQuiet && nx && ffPlan(k > 0 ? its[k - 1]!.t : live.current.d0, nx.t, sp, sc.G) != null;
    if (nx && nextScreenRef.current) nextScreenRef.current.textContent = sp !== 1 && !ffGap ? ` · ${dur((nx.t - t) / sp)} on screen` : '';
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
    let last = performance.now();
    const showFf = (top: number | null) => { // the indicator: a DOM write, and only when it changes
      // compared with the span's OWN text: it is re-mounted whenever the "next in" line is
      const want = top != null ? ` · fast-forwarding at up to ${rateX(top)}` : '';
      if (ffRef.current && ffRef.current.textContent !== want) ffRef.current.textContent = want;
    };
    const frame = () => {
      raf = requestAnimationFrame(frame);
      const now = performance.now();
      // A frame's step is capped: a throttled tab must not fast-forward past the approach it lands on.
      const dt = Math.min(100, Math.max(0, now - last));
      last = now;
      const { items: its, d0: a, d1: b, speed: sp, skipQuiet: ff, scale: sc } = live.current;
      let fast: number | null = null;
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
        const k0 = reachedBy(its, tRef.current);
        const nx0 = its[k0];
        const tp0 = k0 > 0 ? its[k0 - 1]!.t : a;
        const rate = ff && nx0 ? ffRate(tRef.current, tp0, nx0.t, sp, sc.G) : sp;
        if (rate > sp && nx0) {
          // Integrated, not anchored: this stretch is by definition not real time. It stops at the
          // approach, and from there the anchored clock below takes over at the chosen speed - the
          // anchor written here is exactly where it picks up, so there is no seam.
          const plan = ffPlan(tp0, nx0.t, sp, sc.G)!;
          fast = plan.top;
          // Exact, phase by phase - and the frame that reaches the approach spends the REST of its time
          // at the chosen speed: cutting it short there froze the clock for one frame at every handover
          // (measured: ~1.1x -> 0.01x -> 1x).
          nt = ffAdvance(tRef.current, dt, plan, sp);
          anchor.current = { wall: now, t: nt };
          if (ffFor.current !== k0) {
            ffFor.current = k0;
            setSkipped((s) => (s.has(k0) ? s : new Set(s).add(k0)));
          }
        } else {
          nt = anchor.current.t + (now - anchor.current.wall) * sp;
        }
        if (nt >= b) { nt = b; setPlaying(false); }
      }
      showFf(fast);
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
  useEffect(() => { setSkipped(new Set()); ffFor.current = -1; }, [items, skipQuiet]);

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
  const anim = animFactor(speed);
  const animRef = useRef(anim);
  animRef.current = anim;
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
    flareTimer.current = window.setTimeout(() => setFlare(null), FLARE_MS * animRef.current);
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
    else if (k === '[' || k === ']') {         // step the speed: the slow end is where bursts are read
      const i = SPEEDS.indexOf(speed);
      const j = Math.min(SPEEDS.length - 1, Math.max(0, (i < 0 ? SPEEDS.indexOf(1) : i) + (k === ']' ? 1 : -1)));
      changeSpeed(SPEEDS[j]!);
    }
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

  /* ── the stream's phase filter: per view, never persisted, and it touches ONLY the stream ── */
  const [picked, setPicked] = useState<ReadonlySet<number>>(() => new Set());
  // The HELD event: a node clicked on the map, or a card clicked in the stream. ONE state for both, so
  // the node and the card can never disagree; `from` says which side asked, so only the other scrolls.
  const [hold, setHold] = useState<{ id: string | null; from: HoldFrom }>({ id: null, from: 'map' });
  const held = hold.id;
  const holdFromMap = useCallback((id: string | null) => setHold({ id, from: 'map' }), []);
  const holdFromStream = useCallback((id: string) => setHold((c) => ({ id: c.id === id ? null : id, from: 'stream' })), []);
  const nav = useNavigate();
  const openEvent = useCallback((id: string) => nav(`/events/${encodeURIComponent(id)}`), [nav]);
  const togglePicked = useCallback((li: number) => setPicked((cur) => {
    const next = new Set(cur);
    if (next.has(li)) next.delete(li); else next.add(li);
    return next;
  }), []);
  const clearPicked = useCallback(() => setPicked(new Set()), []);
  const laneKey = lanes.join('|');
  useEffect(() => { setPicked(new Set()); }, [laneKey]);   // a different set of phases: drop the old choice

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
  // What the legend counts is what the map has DRAWN so far: the links into the events reached.
  const edgeCounts = useMemo(() => {
    const drawn = edges.filter((e) => e.at < reached);
    return { actor: drawn.filter((e) => e.kind === 'actor').length, shared: drawn.filter((e) => e.kind === 'shared').length };
  }, [edges, reached]);

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
  const d = ctx.data;

  return (
    <section className={cx('rp', full && 'rp--full')} ref={rootRef} aria-label="Timeline replay"
      style={{ ['--rp-anim' as string]: anim.toFixed(3) }}>
      {/* ── header ── */}
      <header className="rp-hero">
        <div className="rp-kicker">Incident replay · {c?.id ?? 'case'} · reconstructed from {items.length} curated event{items.length === 1 ? '' : 's'}</div>
        <h2 className="rp-title">{c?.name || 'Case timeline'}</h2>
        <ReplaySummary text={c?.summary || ''} fallback="Press play to watch it unfold, at the pace it actually happened." />
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
          <div className="rp-speeds" role="group" aria-label="Replay speed" title="[ slower · ] faster">
            {SPEED_GROUPS.map((g) => (
              <div key={g.label} className="rp-speeds__grp" role="group" aria-label={g.label}>
                <span className="rp-speeds__lbl">{g.label}</span>
                <div className="rp-speeds__btns">
                  {g.speeds.map((v) => (
                    <button key={v} className={cx(speed === v && 'on')} aria-pressed={speed === v} onClick={() => changeSpeed(v)}
                      title={rateLabel(v)}>{v}×</button>
                  ))}
                </div>
              </div>
            ))}
          </div>
          <label className="rp-skip"
            title="Skip the empty space between events: a gap that would take more than a few seconds to watch at the chosen speed is crossed quickly, and the replay slows back to the chosen speed about 1.6 seconds (on screen) before the next event, so every arrival and every burst plays at the speed you picked. The clock always shows real time, and moments reached this way are marked, so a skipped gap never looks like a short one.">
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
              {next ? <>next in <b ref={nextRef} /><span ref={nextScreenRef} /><span ref={ffRef} /></>
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
            <span className="rp-tagline">every event, drawn as it happens · linked by what did it and what they share</span>
            <span className="rp-mapzoomslot" ref={setMapZoomSlot} /></div>
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
            <AttackMap nodes={nodes} edges={edges} lanes={lanes} reached={reached} current={cur?.en.eventId ?? null}
              held={held} holdFrom={hold.from} onHold={holdFromMap} onOpenEvent={openEvent} zoomSlot={mapZoomSlot} />
          </div>
          <div className="rp-legend" aria-hidden>
            <span className="rp-legend__k"><svg width="26" height="8"><path d="M1,4 L25,4" className="rp-legend__actor" /></svg>done by — spawned it, ran it, or the same process again{edgeCounts.actor ? ` (${edgeCounts.actor})` : ''}</span>
            <span className="rp-legend__k"><svg width="26" height="8"><path d="M1,4 L25,4" className="rp-legend__shared" /></svg>same file, hash, domain, address or session as an earlier event{edgeCounts.shared ? ` (${edgeCounts.shared})` : ''}</span>
            <span className="rp-legend__k"><svg width="26" height="8"><path d="M1,4 L25,4" className="rp-legend__extra" /></svg>lighter: a further tie beyond the one it is placed by</span>
            {lanes.length > 1 && (
              <span className="rp-legend__phases" title="The rule down an event's left edge is the phase it belongs to">
                {lanes.map((name, li) => (
                  <span key={name} className="rp-legend__ph" style={{ ['--c' as string]: PHASE_HUES[li % PHASE_HUES.length] }}>{name}</span>
                ))}
              </span>
            )}
            <span className="rp-legend__hint">Left to right is cause to effect. Point at an event to read its links; click to hold them; double-click to open the event. Ctrl + wheel or pinch zooms the map; drag pans it once zoomed.</span>
          </div>
      </div>

      {/* ── the live stream, and beside it the phases and the activity over time ── */}
      <div className="rp-stage rp-stage--2">
        <div className="rp-card">
          <div className="rp-card__hd"><span className="rp-mk" style={{ background: '#d8974f' }} /><h3>Live event stream</h3>
            <span className="rp-tagline">every event, {newestFirst ? 'newest' : 'oldest'} first — the timeline's order</span></div>
          <Stream items={items} reached={reached} skipped={skipped} onOpen={onOpen} newestFirst={newestFirst}
            picked={picked} onClear={clearPicked} anim={anim} held={held} holdFrom={hold.from} onHold={holdFromStream} />
        </div>
        <div className="rp-side">
        <div className="rp-card">
          <div className="rp-card__hd"><span className="rp-mk" style={{ background: '#6f9fd8' }} /><h3>Phase activity</h3>
            <span className="rp-tagline">first seen → last seen, to scale · {newestFirst ? 'newest' : 'oldest'} first</span></div>
          <PhaseActivity phases={phaseStats} active={cur ? cur.lane : -1} pct={pct} newestFirst={newestFirst}
            picked={picked} onPick={togglePicked} />
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
