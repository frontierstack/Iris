/**
 * The case timeline, REPLAYED: the curated events happen again, in order, at the pace they really
 * happened. If the installer ran at 08:50 and persistence landed at 09:00, then at 1x the second
 * event appears ten minutes after the first, and at 60x ten seconds after it. The spacing is always
 * the real spacing, and only the speed changes.
 *
 * TIME ACCURACY is the rule everything here serves, because the point of watching a sequence rather
 * than reading a list is to FEEL its pace:
 *  - every event is placed at its instant in MILLISECONDS. The normalised `ts` keeps whole seconds,
 *    and the server recovers the fraction from the log line itself (GET /api/case-set/replay), so
 *    two events 900 ms apart do not play as simultaneous;
 *  - the playhead is a clock anchored to `performance.now()`, never accumulated per frame, so a
 *    throttled tab or a slow frame cannot make it drift from the timestamps;
 *  - the default speed is the smallest one on the ladder that plays the whole span in about a
 *    minute, so a short sequence replays at true 1x;
 *  - "Skip quiet stretches" is OFF by default, and every event reached by a jump is marked
 *    "skipped", so a skipped gap is never shown as a short one.
 *
 * WHAT IS ON SCREEN, top to bottom:
 *  - the transport and the incident clock;
 *  - the PROGRESSION CHART: one lane per phase (an entry's first label), time proportional left to
 *    right, and a line drawn from event to event as the playhead reaches them. That line crossing
 *    lanes (download, then installation, then first run) is the picture of an incident unfolding;
 *  - the STORY: each moment fades in on a spine as it happens, with the gap since the one before
 *    and the observations the server made about it. Examples: "first traffic to 52.85.12.49 in any
 *    log", "account accessed", "service installed", or an address that "was already active" before
 *    the timeline begins.
 *
 * An entry with no parsed timestamp cannot be placed on a clock. It is counted and named rather than
 * slotted in somewhere, the same rule the list follows when it sorts those entries last.
 */
import { memo, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { KeyboardEvent as ReactKeyboardEvent, PointerEvent as ReactPointerEvent } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import type { CaseSetEntry, Event, ReplayBeat, Severity } from '../api/types';
import { cx, sevVar } from '../utils/format';
import { inlineMd } from '../utils/markdown';
import { Icon } from './icons';
import { EmptyState, Loading, SevTag } from './ui';
import { noteLine } from './timelineText';

/** Replay rates: how many seconds of the incident pass per second on screen. */
const SPEEDS = [1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600, 7200, 21600, 43200, 86400];
/** The default aims to play the whole span within this much screen time. */
const TARGET_MS = 60_000;
/** With skipping on, a gap longer than this much SCREEN time is jumped... */
const QUIET_MS = 3_000;
/** ...after the previous event has been on screen this long... */
const QUIET_HOLD_MS = 1_200;
/** ...landing this long (screen time) before the next event, so it is still seen to arrive. */
const QUIET_LEAD_MS = 800;
/** The chart is padded either side so the first event is seen to HAPPEN rather than start there. */
const PAD_SHARE = 0.03;
const PAD_MIN_MS = 1_000;
/** Pointer within this many pixels of an event snaps the playhead onto it. */
const SNAP_PX = 8;
const LANE_H = 34;
const AXIS_H = 26;
const UNLABELLED = 'unlabelled';
/** Round steps for the chart's time axis, in ms, so a tick is always a readable unit of time. */
const TICK_STEPS = [100, 250, 500, 1e3, 2e3, 5e3, 1e4, 15e3, 3e4, 6e4, 12e4, 3e5, 6e5, 9e5, 18e5,
  36e5, 72e5, 108e5, 216e5, 432e5, 864e5, 1728e5, 6048e5];

interface Item {
  en: CaseSetEntry;
  e: Event;
  t: number;              // epoch ms
  precise: boolean;       // true when the millisecond came from the log line
  said: string;           // the analyst's sentence, or '' when there is no note
  sev: Severity;
  lane: number;
  beats: ReplayBeat[];
}

const pad2 = (n: number) => String(n).padStart(2, '0');
const pad3 = (n: number) => String(n).padStart(3, '0');
/** '2026-09-17', '18:49:15' and '.945' for an epoch in UTC. */
function utcParts(t: number): { day: string; clock: string; ms: string } {
  const d = new Date(t);
  return {
    day: `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())}`,
    clock: `${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}`,
    ms: `.${pad3(d.getUTCMilliseconds())}`,
  };
}
/** A signed offset from the first event, as T+hh:mm:ss (with days when it needs them). Before the
 *  first event it is a COUNTDOWN and rounds up, so it never reads T−00:00:00 while nothing has
 *  happened yet. */
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
/** What one screen second is worth at a speed, for the speed menu. */
function rateLabel(v: number): string {
  if (v === 1) return '1× · real time';
  const per = v >= 86400 ? `${v / 86400} d` : v >= 3600 ? `${v / 3600} h` : v >= 60 ? `${v / 60} min` : `${v} s`;
  return `${v.toLocaleString()}× · 1 s = ${per}`;
}
/** How many items have happened by `t` (index of the first item strictly after it). */
function reachedBy(items: Item[], t: number): number {
  let lo = 0; let hi = items.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (items[mid]!.t <= t) lo = mid + 1; else hi = mid;
  }
  return lo;
}
const reducedMotion = () => {
  try { return window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch { return false; }
};
/** A log's own "no value" placeholder is not a host or a user. */
const real = (v: string | undefined) => !!v && v !== '-' && v !== '--';

/* ───────── beats: what the server observed about one moment ───────── */
const BEAT_TAG: Record<string, string> = {
  first: 'first seen', earlier: 'seen before', detection: 'detection', download: 'download',
  process: 'process', command: 'command', file: 'file', signature: 'signature', library: 'dll',
  network: 'network', registry: 'registry', persistence: 'persistence', access: 'account',
  'auth-fail': 'failed auth', privilege: 'privilege', account: 'account', 'anti-forensics': 'log cleared',
  execution: 'execution', web: 'web', dns: 'dns',
};
/** The tone a beat is drawn in. Only what an analyst must not miss is loud. */
function beatTone(b: ReplayBeat): string {
  if (b.kind === 'persistence' || b.kind === 'anti-forensics' || b.kind === 'auth-fail') return 'bad';
  if (b.kind === 'detection') return b.sev === 'critical' || b.sev === 'high' ? 'bad' : 'warn';
  if (b.kind === 'access' || b.kind === 'privilege' || b.kind === 'account' || b.kind === 'execution') return 'warn';
  if (b.kind === 'first') return 'accent';
  if (b.kind === 'earlier') return 'muted';
  return 'plain';
}
const Beats = memo(function Beats({ beats, id }: { beats: ReplayBeat[]; id: string }) {
  if (!beats.length) return null;
  return (
    <ul className="rp-beats">
      {beats.map((b, i) => (
        <li key={i} className={`rp-beat rp-beat--${beatTone(b)}`}>
          <span className="rp-beat__tag">{BEAT_TAG[b.kind] ?? b.kind}</span>
          <span className="rp-beat__text" title={b.text}>{inlineMd(b.text, `rpb-${id}-${i}`)}</span>
        </li>
      ))}
    </ul>
  );
});

/* ───────── the progression chart: static layers (redrawn only when an event is reached) ───────── */
function niceTicks(d0: number, d1: number, width: number): number[] {
  const want = Math.max(2, Math.floor(width / 110));
  const step = TICK_STEPS.find((s) => (d1 - d0) / s <= want) ?? TICK_STEPS[TICK_STEPS.length - 1]!;
  const out: number[] = [];
  for (let x = Math.ceil(d0 / step) * step; x <= d1; x += step) out.push(x);
  return out;
}
function tickLabel(t: number, span: number): string {
  const p = utcParts(t);
  if (span < 10_000) return `${p.clock.slice(3)}${p.ms}`;
  if (span < 86_400_000) return span < 600_000 ? p.clock : p.clock.slice(0, 5);
  const d = new Date(t);
  return `${d.getUTCDate()} ${d.toLocaleString('en-GB', { month: 'short', timeZone: 'UTC' })} ${p.clock.slice(0, 5)}`;
}
/** Vertical offsets that fan out events in the same lane within a few pixels of each other, so a
 *  burst reads as a burst instead of one dot. */
function fanOut(items: Item[], x: (t: number) => number): number[] {
  const out = new Array<number>(items.length).fill(0);
  const order = items.map((_, i) => i).sort((a, b) => items[a]!.lane - items[b]!.lane || items[a]!.t - items[b]!.t);
  let lastX = -1e9; let lastLane = -1; let k = 0;
  for (const i of order) {
    const it = items[i]!;
    const px = x(it.t);
    k = it.lane === lastLane && px - lastX < 4 ? k + 1 : 0;
    out[i] = k === 0 ? 0 : (k % 2 ? -1 : 1) * Math.ceil(k / 2) * 5;
    lastX = px; lastLane = it.lane;
  }
  return out;
}

const ChartStatic = memo(function ChartStatic({ items, lanes, reached, d0, d1, width }: {
  items: Item[]; lanes: string[]; reached: number; d0: number; d1: number; width: number;
}) {
  const x = useCallback((t: number) => ((t - d0) / (d1 - d0 || 1)) * width, [d0, d1, width]);
  const y = (lane: number) => AXIS_H + lane * LANE_H + LANE_H / 2;
  const ticks = useMemo(() => niceTicks(d0, d1, width), [d0, d1, width]);
  const offsets = useMemo(() => fanOut(items, x), [items, x]);
  const h = AXIS_H + lanes.length * LANE_H;
  // The progression: event to event, in time order, as far as the replay has reached.
  const path = items.slice(0, reached)
    .map((it, i) => `${i ? 'L' : 'M'}${x(it.t).toFixed(1)},${(y(it.lane) + offsets[i]!).toFixed(1)}`).join(' ');
  const cur = reached > 0 ? items[reached - 1]! : undefined;

  return (
    <g>
      {lanes.map((_, i) => (
        <rect key={`lane-${i}`} className={cx('rp-lane', i % 2 === 1 && 'rp-lane--alt')}
          x={0} y={AXIS_H + i * LANE_H} width={width} height={LANE_H} />
      ))}
      {ticks.map((tk) => (
        <g key={tk}>
          <line className="rp-grid" x1={x(tk)} x2={x(tk)} y1={AXIS_H - 4} y2={h} />
          <text className="rp-ticklbl" x={x(tk)} y={AXIS_H - 9} textAnchor="middle">{tickLabel(tk, d1 - d0)}</text>
        </g>
      ))}
      {path && <path className="rp-prog" d={path} />}
      {items.map((it, i) => {
        const past = i < reached;
        const p = utcParts(it.t);
        return (
          <circle key={it.en.eventId} className={cx('rp-node', past ? 'rp-node--past' : 'rp-node--future')}
            cx={x(it.t)} cy={y(it.lane) + offsets[i]!} r={past ? 5 : 3.5}
            style={{ ['--rp-sev' as string]: sevVar(it.sev) }}>
            <title>{`${p.clock}${it.precise ? p.ms : ''} UTC — ${it.said || it.e.msg}`}</title>
          </circle>
        );
      })}
      {cur && <circle key={cur.en.eventId} className="rp-node-ring" cx={x(cur.t)} cy={y(cur.lane) + offsets[reached - 1]!} r={9} />}
    </g>
  );
});

/* ───────── the story: each moment fades in on a spine as it happens ───────── */
const Story = memo(function Story({ items, reached, skipped, precise, onSeek, onOpen }: {
  items: Item[]; reached: number; skipped: Set<number>; precise: boolean;
  onSeek: (t: number) => void; onOpen: (eventId: string) => void;
}) {
  const box = useRef<HTMLOListElement>(null);
  // Follow the newest moment inside the story's own scroller. Never scrollIntoView, which would
  // also scroll the PAGE out from under the controls on every event.
  useLayoutEffect(() => {
    const el = box.current;
    if (!el || reached === 0) return;
    const last = el.querySelector<HTMLElement>('.rp-mo--now');
    const top = last ? last.offsetTop - 8 : el.scrollHeight;
    el.scrollTo({ top, behavior: reducedMotion() ? 'auto' : 'smooth' });
  }, [reached]);

  if (reached === 0) {
    const first = items[0]!;
    return (
      <div className="rp-story rp-story--idle">
        Nothing has happened yet. The first event is at{' '}
        <span className="mono">{utcParts(first.t).clock} UTC</span> on <span className="mono">{utcParts(first.t).day}</span>.
      </div>
    );
  }
  const shown = items.slice(0, reached);
  return (
    <ol className="rp-story" ref={box} aria-live="polite" aria-relevant="additions">
      {shown.map((it, i) => {
        const now = i === reached - 1;
        const prev = i > 0 ? items[i - 1]! : undefined;
        const gap = prev ? it.t - prev.t : 0;
        const p = utcParts(it.t);
        const { e, en } = it;
        return (
          <li key={en.eventId} className={cx('rp-mo', now && 'rp-mo--now')}
            style={{ ['--rp-sev' as string]: sevVar(it.sev) }}>
            {prev && (
              <div className={cx('rp-mo__gap', gap >= 60_000 && 'rp-mo__gap--long')}>
                <span>{gap < 1 ? 'same instant' : `${dur(gap)} later`}</span>
                {skipped.has(i) && <span className="rp-mo__skip">skipped on screen</span>}
              </div>
            )}
            <div className="rp-mo__row">
              <button type="button" className="rp-mo__when" onClick={() => onSeek(it.t)} title="Jump the replay to this moment">
                <span className="mono rp-mo__clock">{p.clock}{precise && it.precise ? <span className="rp-mo__ms">{p.ms}</span> : null}</span>
                <span className="mono rp-mo__off">{tOffset(it.t - items[0]!.t)}</span>
              </button>
              <span className="rp-mo__dot" aria-hidden />
              <div className="rp-mo__body">
                <div className="rp-mo__head">
                  <SevTag sev={it.sev} />
                  {en.labels.map((l) => <span key={l} className="tag tag--label">{l}</span>)}
                  <span style={{ flex: 1 }} />
                  {now && (
                    <button className="btn btn--sm btn--ghost" onClick={() => onOpen(en.eventId)}
                      title="Open this entry in the timeline list: its note, raw line, entities and detections">
                      Open entry
                    </button>
                  )}
                </div>
                <div className={cx('rp-mo__said', !it.said && 'rp-mo__said--log')}>
                  {it.said ? inlineMd(it.said, `rp-${en.eventId}`) : (e.msg || e.raw)}
                </div>
                <Beats beats={it.beats} id={en.eventId} />
                <div className="rp-mo__facts">
                  <span title={e.file}>{e.file || e.source}</span>
                  {real(e.host) && <span>host {e.host}</span>}
                  {real(e.user) && <span>user {e.user}</span>}
                  <span className="mono">{en.eventId}</span>
                </div>
                {now && e.raw && <pre className="rp-mo__raw"><code>{e.raw}</code></pre>}
              </div>
            </div>
          </li>
        );
      })}
      {reached < items.length && (
        <li className="rp-mo__more">{items.length - reached} more event{items.length - reached === 1 ? '' : 's'} to come</li>
      )}
    </ol>
  );
});

/* ───────── the replay ───────── */
export function TimelineReplay({ entries, byId, onOpen }: {
  /** The timeline's entries, oldest first. */
  entries: CaseSetEntry[];
  byId: Map<string, Event>;
  onOpen: (eventId: string) => void;
}) {
  // The exact instants and the observations. Keyed under the case set, so anything that changes the
  // case set (an entry added, a note edited) refetches this too.
  const ctx = useQuery({ queryKey: ['case-set', 'replay'], queryFn: api.caseSetReplay, staleTime: 30_000 });
  const ctxById = useMemo(() => new Map((ctx.data?.events ?? []).map((x) => [x.eventId, x])), [ctx.data]);

  const { items, lanes } = useMemo(() => {
    const raw: Omit<Item, 'lane'>[] = [];
    for (const en of entries) {
      const e = byId.get(en.eventId);
      const rc = ctxById.get(en.eventId);
      const t = rc?.tMs ?? (e?.ts ? Date.parse(e.ts) : NaN);
      if (!e || !Number.isFinite(t)) continue;
      raw.push({ en, e, t, precise: rc?.precision === 'ms', said: en.note ? noteLine(en.note) : '',
        sev: e.sev, beats: rc?.beats ?? [] });
    }
    // Stable, by time: two events in the same millisecond keep the list's order.
    raw.sort((a, b) => a.t - b.t);
    // Lanes are PHASES: an entry's first label, in the order the phases first happen.
    const laneOf = new Map<string, number>();
    const names: string[] = [];
    const out: Item[] = raw.map((r) => {
      const name = r.en.labels[0] || UNLABELLED;
      let lane = laneOf.get(name);
      if (lane === undefined) { lane = names.length; laneOf.set(name, lane); names.push(name); }
      return { ...r, lane };
    });
    return { items: out, lanes: names };
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

  const [speed, setSpeed] = useState(autoSpeed);
  const [skipQuiet, setSkipQuiet] = useState(false);
  // Autoplay, but only once the exact instants have arrived: starting on whole seconds and then
  // shifting every event by its milliseconds mid-replay would be the inaccuracy this view exists
  // to avoid.
  const [playing, setPlaying] = useState(false);
  const autostarted = useRef(false);
  const [t, setT] = useState(d0);
  // The clock: the replay time at a wall-clock instant. Every frame derives the time from this, so
  // nothing accumulates and nothing drifts.
  const anchor = useRef({ wall: performance.now(), t: d0 });
  const tRef = useRef(t);
  tRef.current = t;

  const seek = useCallback((x: number) => {
    const c = Math.min(d1, Math.max(d0, x));
    anchor.current = { wall: performance.now(), t: c };
    setT(c);
  }, [d0, d1]);

  // A different sequence (a case switch, an entry added or removed) starts again from the top.
  useEffect(() => { seek(d0); }, [d0, d1, seek]);
  useEffect(() => { setSpeed(autoSpeed); }, [autoSpeed]);
  useEffect(() => {
    if (autostarted.current || ctx.isLoading || !items.length) return;
    autostarted.current = true;
    seek(d0);
    setPlaying(true);
  }, [ctx.isLoading, items.length, seek, d0]);

  // A new speed must not move the playhead: re-anchor at the current time.
  const changeSpeed = (v: number) => {
    anchor.current = { wall: performance.now(), t: tRef.current };
    setSpeed(v);
  };
  const play = () => {
    const from = tRef.current >= d1 ? d0 : tRef.current;   // playing from the end means watching again
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
    seek(k >= 2 ? items[k - 2]!.t : d0);   // back to the event BEFORE the one on screen
  };

  /* ── the chart's geometry and scrubbing ── */
  const plotRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(800);
  const hasItems = items.length > 0;
  useLayoutEffect(() => {
    const el = plotRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setWidth(Math.max(200, el.clientWidth)));
    ro.observe(el);
    setWidth(Math.max(200, el.clientWidth));
    return () => ro.disconnect();
  }, [hasItems]);
  const xOf = (x: number) => ((x - d0) / (d1 - d0 || 1)) * width;
  const fromPointer = (clientX: number): number => {
    const el = plotRef.current;
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
  const onPointerMove = (ev: ReactPointerEvent<HTMLDivElement>) => {
    if (dragging.current) seek(fromPointer(ev.clientX));
  };
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
    else if (k === 'Home') seek(d0);
    else if (k === 'End') seek(d1);
    else if (k === ' ' || k === 'k') toggle();
    else return;
    ev.preventDefault();
  };

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
  const laneCounts = lanes.map((_, li) => {
    let total = 0; let done = 0;
    items.forEach((it, i) => { if (it.lane === li) { total++; if (i < reached) done++; } });
    return { total, done };
  });
  const plotH = AXIS_H + lanes.length * LANE_H;
  const headX = xOf(t);
  const cur = reached > 0 ? items[reached - 1]! : undefined;

  return (
    <section className="rp" aria-label="Timeline replay">
      <div className="rp-bar">
        <div className="rp-transport">
          <button className="btn btn--sm btn--icon" onClick={stepPrev} title="Previous event (←)" aria-label="Previous event">
            <Icon.StepBack />
          </button>
          <button className="btn btn--sm btn--primary rp-play" onClick={toggle}
            aria-label={playing ? 'Pause' : ended ? 'Replay again' : 'Play'}
            title={playing ? 'Pause (space)' : ended ? 'Replay from the start' : 'Play (space)'}>
            {playing ? <Icon.Pause /> : ended ? <Icon.Restart /> : <Icon.Play />}
            {playing ? 'Pause' : ended ? 'Again' : 'Play'}
          </button>
          <button className="btn btn--sm btn--icon" onClick={stepNext} disabled={!next} title="Next event (→)" aria-label="Next event">
            <Icon.StepFwd />
          </button>
          <button className="btn btn--sm btn--icon btn--ghost" onClick={() => { seek(d0); setPlaying(true); }}
            title="Restart from the beginning" aria-label="Restart">
            <Icon.Restart />
          </button>
        </div>

        {/* The clock is the replay's subject: what time it is in the incident, to the millisecond. */}
        <div className="rp-clock" aria-live="off">
          <span className="rp-clock__time mono">{now.clock}<span className="rp-clock__ms">{now.ms}</span></span>
          <span className="rp-clock__sub mono">{now.day} UTC · {tOffset(t - start)}</span>
        </div>

        <div className="rp-progress" aria-hidden>
          <span className="rp-progress__n mono">{reached}</span><span className="rp-progress__of">of {items.length} events</span>
        </div>

        <span style={{ flex: 1 }} />

        <label className="rp-opt">
          <span className="rp-opt__lbl">Speed</span>
          <select value={speed} onChange={(e) => changeSpeed(Number(e.target.value))} aria-label="Replay speed">
            {SPEEDS.map((v) => <option key={v} value={v}>{rateLabel(v)}{v === autoSpeed ? ' (fits)' : ''}</option>)}
          </select>
        </label>
        <label className="rp-opt rp-opt--check"
          title="Jump over any gap that would take more than a few seconds on screen. Moments reached by a jump are marked 'skipped on screen', so a skipped gap never looks like a short one.">
          <input type="checkbox" checked={skipQuiet} onChange={(e) => setSkipQuiet(e.target.checked)} />
          Skip quiet stretches
        </label>
      </div>

      {/* ── the progression chart ── */}
      <div className="rp-chart">
        <div className="rp-lanes" style={{ paddingTop: AXIS_H }}>
          {lanes.map((name, i) => (
            <div key={name} className={cx('rp-lanelbl', laneCounts[i]!.done > 0 && 'rp-lanelbl--on',
              cur?.lane === i && 'rp-lanelbl--now')} style={{ height: LANE_H }} title={name}>
              <span className="rp-lanelbl__name">{name}</span>
              <span className="rp-lanelbl__n mono">{laneCounts[i]!.done}/{laneCounts[i]!.total}</span>
            </div>
          ))}
        </div>
        <div className="rp-plot" ref={plotRef} role="slider" tabIndex={0}
          aria-label="Replay position" aria-valuemin={0} aria-valuemax={items.length} aria-valuenow={reached}
          aria-valuetext={`${now.clock} UTC, ${reached} of ${items.length} events`}
          onPointerDown={onPointerDown} onPointerMove={onPointerMove} onPointerUp={onPointerUp}
          onPointerCancel={onPointerUp} onKeyDown={onKey} style={{ height: plotH }}>
          <svg width={width} height={plotH} className="rp-svg">
            <rect className="rp-pastfill" x={0} y={AXIS_H} width={Math.max(0, headX)} height={plotH - AXIS_H} />
            <ChartStatic items={items} lanes={lanes} reached={reached} d0={d0} d1={d1} width={width} />
            {/* The wire from the last event to the playhead: the sequence reaching for what comes next. */}
            {cur && headX > xOf(cur.t) && (
              <line className="rp-wire" x1={xOf(cur.t)} x2={headX}
                y1={AXIS_H + cur.lane * LANE_H + LANE_H / 2} y2={AXIS_H + cur.lane * LANE_H + LANE_H / 2} />
            )}
            <line className="rp-head" x1={headX} x2={headX} y1={AXIS_H - 2} y2={plotH} />
            <rect className="rp-head__grip" x={headX - 4} y={AXIS_H - 6} width={8} height={6} rx={2} />
          </svg>
        </div>
      </div>

      <div className="rp-status">
        {next ? (
          <>
            <span className="rp-status__k">Next</span>
            <span className="mono">in {dur(next.t - t)}</span>
            {speed !== 1 && <span className="rp-status__dim">({dur((next.t - t) / speed)} on screen)</span>}
            <span className="rp-status__what">{next.said ? inlineMd(next.said, `rpn-${next.en.eventId}`) : next.e.msg}</span>
          </>
        ) : (
          <span className="rp-status__dim">{ended ? 'End of the timeline.' : 'Every event has happened.'}</span>
        )}
        <span className="rp-status__span mono">
          {dur(end - start)} span{speed === 1 ? ' · real time' : ` · plays in ${dur((d1 - d0) / speed)}`}
        </span>
      </div>

      {ctx.isLoading && <Loading inline label="Reading each event's exact instant and first sightings…" />}
      <Story items={items} reached={reached} skipped={skipped} precise={anyPrecise} onSeek={seek} onOpen={onOpen} />

      <div className="rp-foot field__hint">
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
      </div>
    </section>
  );
}
