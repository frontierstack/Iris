/**
 * The replay's TIME SCALE: how real time maps onto the seek bar, and back.
 *
 * "Need to handle large spaces of time — reduce the 'factor' of the timeline while maintaining the
 * accurate time." A case whose events cluster into a few bursts across a day drew a bar that was almost
 * all empty: the analyst's own 40-event case spans 21 h 24 m, and 16 of those hours are two quiet gaps.
 * So the bar is PIECEWISE: an active stretch keeps its true proportions (one unit = one real
 * millisecond), and a quiet gap longer than the threshold G is COMPRESSED to one small fixed width W
 * (4 % of the active time) and drawn as a hatched break labelled with its real length ("⋯ 10h 23m").
 * W may be NARROWER than a gap just under G that is drawn to scale: that is why a break is always
 * visibly a break, never a stretch of bar that could be read as proportional. Nothing about TIME changes — the clock, every timestamp and
 * the playback inside a burst stay real — only the bar's geometry and the dead time are compressed.
 * Inside a compressed gap the map is still linear, so a pointer placed there reads back the real
 * instant inside the gap.
 *
 * The playback uses the same model: with "Skip quiet stretches" on, every gap the bar compresses is
 * jumped, so the bar and the playback agree about what counts as quiet.
 *
 * Pure and dependency-free on purpose: backend/tests/test_replay_scale.py runs it under Node against
 * randomised gaps (real → bar → real must round-trip, and order must be kept).
 */

export interface Seg {
  /** real time, epoch ms */
  r0: number; r1: number;
  /** bar units (an active unit is one real millisecond) */
  u0: number; u1: number;
  /** a compressed quiet gap */
  gap: boolean;
}
export interface Scale {
  segs: Seg[];
  /** total bar units */
  U: number;
  d0: number; d1: number;
  /** the gap threshold, real ms: a gap longer than this is compressed */
  G: number;
  /** the width every compressed gap is drawn at, in units */
  W: number;
  /** gapBefore[k]: the gap BEFORE event k (after event k-1) is compressed */
  gapBefore: boolean[];
}

export const GAP_MIN_MS = 10_000;
export const GAP_MAX_MS = 600_000;
export const GAP_SHARE = 0.02;
/** A compressed gap is drawn this share of the ACTIVE time wide, within [BREAK_MIN_MS, G]. */
export const BREAK_SHARE = 0.04;
export const BREAK_MIN_MS = 500;

/** 2 % of the span, but never under 10 s (a burst's own rhythm is never compressed) and never over
 *  10 min (a day-long case still shows its hour-long silences as breaks). */
export function gapThreshold(span: number): number {
  return Math.min(GAP_MAX_MS, Math.max(GAP_MIN_MS, span * GAP_SHARE));
}

/** `times` must be sorted ascending and lie inside [d0, d1]. */
export function buildScale(times: readonly number[], d0: number, d1: number, G = gapThreshold(d1 - d0)): Scale {
  const segs: Seg[] = [];
  const gapBefore = times.map(() => false);
  let quiet = 0;
  for (let k = 1; k < times.length; k++) {
    const g = times[k]! - times[k - 1]!;
    if (g > G) quiet += g;
  }
  const W = Math.min(G, Math.max(BREAK_MIN_MS, (d1 - d0 - quiet) * BREAK_SHARE));
  let u = 0;
  const push = (r0: number, r1: number, gap: boolean) => {
    if (r1 <= r0) return;
    const w = gap ? W : r1 - r0;
    segs.push({ r0, r1, u0: u, u1: u + w, gap });
    u += w;
  };
  let run = d0;                       // start of the current ACTIVE stretch
  for (let k = 1; k < times.length; k++) {
    const a = times[k - 1]!;
    const b = times[k]!;
    if (b - a > G) {
      push(run, a, false);
      push(a, b, true);
      gapBefore[k] = true;
      run = b;
    }
  }
  push(run, d1, false);
  if (!segs.length) segs.push({ r0: d0, r1: d1, u0: 0, u1: 0, gap: false });
  return { segs, U: u, d0, d1, G, W, gapBefore };
}

function segAtReal(s: Scale, t: number): Seg {
  const g = s.segs;
  let lo = 0; let hi = g.length - 1;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (g[mid]!.r1 < t) lo = mid + 1; else hi = mid;
  }
  return g[lo]!;
}
function segAtUnit(s: Scale, u: number): Seg {
  const g = s.segs;
  let lo = 0; let hi = g.length - 1;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (g[mid]!.u1 < u) lo = mid + 1; else hi = mid;
  }
  return g[lo]!;
}

/** Real time → bar units. */
export function toU(s: Scale, t: number): number {
  const c = Math.min(s.d1, Math.max(s.d0, t));
  const g = segAtReal(s, c);
  if (g.r1 <= g.r0) return g.u0;
  return g.u0 + ((c - g.r0) / (g.r1 - g.r0)) * (g.u1 - g.u0);
}
/** Bar units → real time. */
export function fromU(s: Scale, u: number): number {
  const c = Math.min(s.U, Math.max(0, u));
  const g = segAtUnit(s, c);
  if (g.u1 <= g.u0) return g.r0;
  return g.r0 + ((c - g.u0) / (g.u1 - g.u0)) * (g.r1 - g.r0);
}

/* ───────── the ruler: round times at a density that suits the zoom ───────── */

/** 1-2-5 ladder, extended with the steps a clock actually uses (15 s, 30 s, 15 min, 3 h, 6 h …). */
export const STEPS = [
  1, 2, 5, 10, 20, 50, 100, 200, 500,
  1_000, 2_000, 5_000, 10_000, 15_000, 30_000,
  60_000, 120_000, 300_000, 600_000, 900_000, 1_800_000,
  3_600_000, 7_200_000, 10_800_000, 21_600_000, 43_200_000, 86_400_000,
];

const p2 = (n: number) => String(n).padStart(2, '0');
function tickLabel(t: number, step: number): string {
  const d = new Date(t);
  const hm = `${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}`;
  if (step >= 86_400_000) return `${d.getUTCFullYear()}-${p2(d.getUTCMonth() + 1)}-${p2(d.getUTCDate())}`;
  if (step >= 60_000) return hm;
  const hms = `${hm}:${p2(d.getUTCSeconds())}`;
  if (step >= 1_000) return hms;
  return `${hms}.${String(d.getUTCMilliseconds()).padStart(3, '0')}`;
}
/** A duration in words for a break label: 42s, 9m 58s, 2h 14m, 3d 4h. */
export function gapLabel(ms: number): string {
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${p2(s % 60)}s`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ${p2(m % 60)}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

export interface Tick { u: number; t: number; label: string }
/** Round-time ticks for the view [v0, v1] (units) on a track `widthPx` wide, at least `minPx` apart.
 *  Ticks are only placed in ACTIVE stretches, where one unit is one real millisecond, so one step fits
 *  all of them; a compressed gap is a break with its own label instead. */
export function ticks(s: Scale, v0: number, v1: number, widthPx: number, minPx = 90): { step: number; ticks: Tick[] } {
  const w = Math.max(1e-9, v1 - v0);
  const pxPerMs = widthPx / w;
  const step = STEPS.find((x) => x * pxPerMs >= minPx) ?? STEPS[STEPS.length - 1]!;
  const out: Tick[] = [];
  for (const g of s.segs) {
    if (g.gap || g.u1 < v0 || g.u0 > v1) continue;
    const r0 = fromU(s, Math.max(g.u0, v0));
    const r1 = fromU(s, Math.min(g.u1, v1));
    for (let t = Math.ceil(r0 / step) * step; t <= r1 && out.length < 400; t += step) {
      out.push({ u: toU(s, t), t, label: tickLabel(t, step) });
    }
  }
  return { step, ticks: out };
}
