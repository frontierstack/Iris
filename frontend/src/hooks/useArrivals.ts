/**
 * Arrivals: which items of a list appeared WHILE THE ANALYST WAS WATCHING, and a typewriter for them.
 *
 * *"For the notes and timelines, have a subtle fade in, with typing animation, showing it building the
 * notes and timelines."* The live bus (useLiveWorkspace) makes a note or a timeline entry appear the
 * moment the assistant writes it; this is the one piece of motion that makes that arrival legible —
 * a row that fades in and a sentence that is revealed as if being written — rather than a list that
 * silently grows by one between two frames.
 *
 * THE ARRIVAL IS DECIDED DURING RENDER, NOT IN AN EFFECT. The first build computed it in a
 * `useEffect`, which runs after the new row has already painted: the row mounted as "not arriving",
 * the typewriter locked itself to the full text on that first render, and the fade class landed a
 * frame late — reported as "I'm still not seeing the notes fade in with a typing animation". So the
 * set of new ids is derived synchronously from a ref of ids seen so far, and each arrival keeps its
 * status for ARRIVAL_MS from the moment it was first rendered. Idempotent under StrictMode's double
 * render: the second pass finds the id already seen AND already stamped as an arrival, so it is
 * still one.
 *
 * The rules that keep it from being decoration:
 * - Only an ARRIVAL animates. The ids present on the first render are the initial load and paint at
 *   once; a refetch that changes nothing animates nothing; an edit to an existing entry does not
 *   re-type it.
 * - The reveal is CAPPED: `useTypewriter` paces itself so the longest note still finishes in about
 *   REVEAL_MS — a 3,000-character write-up is not typed for forty seconds, it is revealed in a second.
 * - `prefers-reduced-motion` turns both off: the text is complete on its first frame and the fade is
 *   the 0.01 ms transition base.css already imposes.
 * - No caret. The project's rule against a blinking typing caret stands; the growing text is the
 *   animation, and a cursor on top of it would be exactly the decoration that rule forbids.
 */
import { useEffect, useReducer, useRef } from 'react';

/** How long an arrival keeps its `arriving` state (the fade, the reveal and the tint settling). */
export const ARRIVAL_MS = 5200;
/** The reveal is paced by LENGTH — about 520 characters a second reads as writing rather than as a
 *  flicker (the first cut revealed 412 characters in 1.1 s and was reported as "they just appear") —
 *  bounded so a one-liner still takes a readable moment and a long write-up never drags. */
export const REVEAL_CHARS_PER_SEC = 520;
export const REVEAL_MIN_MS = 1200;
export const REVEAL_MAX_MS = 3500;

function reducedMotion(): boolean {
  try { return window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch { return false; }
}

/** The ids in `ids` that arrived while this list was mounted, for ARRIVAL_MS after they did.
 *
 *  `loaded` is whether the list's query has answered. The first render of a feed happens with the
 *  query still in flight — no ids at all — and seeding "seen" from THAT made every note of the
 *  initial load an arrival when the data landed a moment later. So nothing is seeded until the
 *  first loaded render; before it there are no arrivals. */
export function useArrivals(ids: readonly string[], loaded = true): ReadonlySet<string> {
  const seen = useRef<Set<string> | null>(null);
  const stamped = useRef<Map<string, number>>(new Map());
  const [, rerender] = useReducer((n: number) => n + 1, 0);
  const now = Date.now();

  if (seen.current === null) {
    if (loaded) seen.current = new Set(ids);          // first LOADED render: the initial load, no arrivals
  } else {
    for (const id of ids) {
      if (!seen.current.has(id)) {
        seen.current.add(id);
        stamped.current.set(id, now);
      }
    }
  }
  // expire what has settled; keep what is still within its window
  const fresh = new Set<string>();
  let soonest = Infinity;
  for (const [id, at] of stamped.current) {
    const left = at + ARRIVAL_MS - now;
    if (left <= 0) stamped.current.delete(id);
    else { fresh.add(id); if (left < soonest) soonest = left; }
  }
  // one re-render when the soonest arrival settles, so `arriving` is taken off the row
  useEffect(() => {
    if (!Number.isFinite(soonest)) return;
    const t = window.setTimeout(rerender, soonest + 16);
    return () => window.clearTimeout(t);
  }, [soonest, fresh.size]);
  return fresh;
}

/** `text`, revealed progressively when `active` on its FIRST render — the whole of it otherwise. */
export function useTypewriter(text: string, active: boolean): string {
  const animate = useRef(active && !reducedMotion());   // decided once, at mount: an arrival, or not
  const [n, setN] = useReducer((_: number, v: number) => v, animate.current ? 0 : text.length);
  useEffect(() => {
    if (!animate.current) return;
    const ms = Math.min(REVEAL_MAX_MS, Math.max(REVEAL_MIN_MS, (text.length / REVEAL_CHARS_PER_SEC) * 1000));
    const frames = Math.max(1, Math.round(ms / 16));
    const step = Math.max(1, Math.ceil(text.length / frames));
    let shown = 0;
    let raf = 0;
    const tick = () => {
      shown = Math.min(text.length, shown + step);
      setN(shown);
      if (shown < text.length) raf = requestAnimationFrame(tick);
      else animate.current = false;                   // done: any later edit shows in full at once
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [text]);
  return animate.current && n < text.length ? text.slice(0, n) : text;
}
