/**
 * The live workspace: the case screens update themselves while the assistant works.
 *
 * *"When the AI assistant is working and building a case, I want to see the case being updated live
 * ... see events appear live without having to refresh the page."*
 *
 * One `EventSource` on `GET /api/ai/live` for the whole app, opened by the provider that is mounted for
 * the app's lifetime (not by the AI panel, which unmounts when closed — and a run outlives the panel).
 * Every event the server pushes — a run starting, a WRITE landing, a run ending, an undo — becomes a
 * TanStack Query invalidation of the case data: the screens that render it refetch and re-render, and a
 * note, an indicator, a timeline entry or a graph link appears the moment the agent wrote it. That is the
 * React-native answer: the components already subscribe to their queries; this only tells the cache
 * when the truth moved. No screen polls.
 *
 * Two details that matter:
 * - Writes arrive in BURSTS (a run records twelve artefacts in a few seconds), so invalidations are
 *   coalesced on a short timer rather than refetching every query per write.
 * - A `create_case` write is followed: the run makes a NEW case while the analyst is looking at the old
 *   one (or the list), and a case screen that never navigates would show the run building nothing.
 *   Only from a case route — never yank someone off Search — and only for a case the run created or
 *   activated, which the action's undo payload names.
 * - `EventSource` reconnects by itself after a drop; on every (re)connect the case data is refetched
 *   once, because whatever happened during the gap is not replayed (the bus has no history).
 */
import { useEffect, useRef } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useQueryClient } from '@tanstack/react-query';
import type { AiAction } from '../api/types';

/** Everything a write to a case can change on screen. `['case']` is the header/sidebar snapshot. */
const CASE_KEYS: readonly (readonly string[])[] = [
  ['case'], ['cases'], ['case-detail'], ['case-set'], ['notes'], ['iocs'], ['timeline'], ['timeline-iocs'],
  ['graph'], ['graph-anomalies'], ['events'], ['event'], ['entity'],
];
/** A rule or exclusion write re-runs the catalogue, so the detections change too. */
const RULE_KEYS: readonly (readonly string[])[] = [['rules'], ['anomalies'], ['events'], ['event']];
const RULE_TOOLS = /rule|exclusion/;

const COALESCE_MS = 120;

type LiveEvent =
  | { type: 'hello'; subscribers: number }
  | { type: 'run'; runId: string; caseId: string }
  | { type: 'write'; runId: string; action: AiAction }
  | { type: 'done'; runId: string; state: string; writes: number }
  | { type: 'undo'; runId: string; undone: number };

export function useLiveWorkspace(): void {
  const qc = useQueryClient();
  const nav = useNavigate();
  const loc = useLocation();
  const pathRef = useRef(loc.pathname);
  pathRef.current = loc.pathname;

  useEffect(() => {
    if (typeof EventSource === 'undefined') return;
    let timer = 0;
    let pending = new Set<string>();
    const flush = () => {
      timer = 0;
      const keys = pending;
      pending = new Set();
      for (const k of keys) void qc.invalidateQueries({ queryKey: [k] });
    };
    const invalidate = (keys: readonly (readonly string[])[]) => {
      for (const k of keys) pending.add(k[0]!);
      if (!timer) timer = window.setTimeout(flush, COALESCE_MS);
    };
    const follow = (action: AiAction) => {
      // Only a case the run just CREATED or ACTIVATED, and only from a case route.
      if (action.tool !== 'create_case' && action.tool !== 'activate_case') return;
      const id = String(action.undo?.caseId ?? '');
      const path = pathRef.current;
      if (!id || !path.startsWith('/cases')) return;
      if (path === `/cases/${id}`) return;
      nav(`/cases/${id}`);
    };

    const es = new EventSource('/api/ai/live');
    es.onopen = () => invalidate(CASE_KEYS);   // cover whatever happened while disconnected
    es.onmessage = (m) => {
      let ev: LiveEvent;
      try { ev = JSON.parse(m.data) as LiveEvent; } catch { return; }
      switch (ev.type) {
        case 'write':
          invalidate(RULE_TOOLS.test(ev.action?.tool ?? '') ? RULE_KEYS : CASE_KEYS);
          if (ev.action) follow(ev.action);
          break;
        case 'run':
        case 'done':
        case 'undo':
          invalidate(CASE_KEYS);
          if (ev.type !== 'run') invalidate(RULE_KEYS);
          break;
        default:
          break;
      }
    };
    // onerror: EventSource retries on its own; nothing to do but let it.
    return () => { es.close(); if (timer) window.clearTimeout(timer); };
  }, [qc, nav]);
}
