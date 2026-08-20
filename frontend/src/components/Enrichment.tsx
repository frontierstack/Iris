import { useMutation } from '@tanstack/react-query';
import { useEffect, useMemo, useRef, type ReactNode } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import type { EnrichState, Source } from '../api/types';
import { Icon } from './icons';
import { useCase, useInvalidateCaseData } from '../hooks/queries';
import { useToast } from '../hooks/useToast';
import { cx, fmtInt, fmtTs } from '../utils/format';

/**
 * Two-phase ingest, said out loud.
 *
 * Phase 1 lands every line of a log in the pool immediately — searchable, but with no timestamp, no
 * severity, no parsed fields and no entities. Phase 2 (a single background worker, one source at a
 * time) runs the real parser and normalization and replaces that source's events.
 *
 * The consequence this module exists for: while N sources are still `raw`, the case timeline, the
 * entity graph and the anomaly list are answering over PART of the corpus. An empty graph that is
 * really "not enriched yet" is a lie about the evidence, so every screen that reads derived data says
 * so, in the same words, with the way to fix it attached.
 *
 * `skipped` is a deliberate analyst decision and is NOT outstanding: it must never keep a warning
 * alive. That is why the banner counts `enrichment.outstanding` (raw + queued + enriching).
 */

export const ENRICH_ORDER: EnrichState[] = ['raw', 'queued', 'enriching', 'enriched', 'skipped', 'error'];

/** The states in which a source's events are still the raw lines: no timestamp, no severity, no parsed
 *  fields. `skipped` is deliberately NOT here — leaving a file raw is an analyst decision, and the
 *  banner, the per-screen note and the Search field note all read this one set. */
const OUTSTANDING_STATES = new Set<EnrichState>(['raw', 'queued', 'enriching']);

export const ENRICH_META: Record<EnrichState, { label: string; pill: string; help: string }> = {
  raw: {
    label: 'raw',
    pill: 'pill--warn',
    help: 'Landed as raw lines: searchable as text, but not interpreted — no timestamp, no severity, no parsed fields, no entities. The timeline, the entity graph and the detection rules cannot see it yet.',
  },
  queued: {
    label: 'queued',
    pill: 'pill--accent',
    help: 'Waiting for the enrichment worker, which takes one source at a time, oldest first.',
  },
  enriching: {
    label: 'enriching',
    pill: 'pill--accent',
    help: 'Being parsed and normalized now. Its events are replaced in place when it finishes; their ids do not move.',
  },
  enriched: {
    label: 'enriched',
    pill: 'pill--muted',
    help: 'Fully parsed and normalized — timestamps, severities, parsed fields, entities and detections. Everything reads it.',
  },
  skipped: {
    label: 'skipped',
    pill: 'pill--muted',
    help: 'Left raw on purpose. It stays searchable as text and stays out of the timeline, the graph and the detections until you enrich it.',
  },
  error: {
    label: 'error',
    pill: 'pill--bad',
    help: 'Enrichment failed on this file. Its raw lines are still in the pool and still searchable — nothing was lost.',
  },
};

/** A source with no `enrich` field at all (an older server, or a container that has no raw form) is
 *  treated as enriched: it is the state in which nothing is being withheld. */
export function enrichOf(s: Source): EnrichState {
  return (s.enrich ?? 'enriched') as EnrichState;
}

/** The workspace's enrichment picture, read from the one `/api/case` poll the whole app shares.
 *  No screen adds a request of its own for this. */
export function useEnrichment() {
  const c = useCase();
  const sources = useMemo(
    () => [...(c.data?.sources ?? []), ...(c.data?.librarySources ?? [])],
    [c.data],
  );
  const e = c.data?.enrichment;
  const raw = useMemo(() => sources.filter((s) => enrichOf(s) === 'raw'), [sources]);
  const counts = e?.counts;
  // `outstanding` is the server's number; fall back to counting the pool so a stale/absent field can
  // never make an incomplete workspace look complete.
  const outstanding = e ? e.outstanding : sources.filter((s) => OUTSTANDING_STATES.has(enrichOf(s))).length;
  return {
    counts,
    outstanding,
    pending: e?.pending ?? 0,
    running: e?.running ?? '',
    // What the running source is doing right now, so a screen can show MOVEMENT. On a large pool one
    // source takes tens of seconds, so a count alone changes once a minute and reads as frozen.
    detail: {
      file: e?.runningFile ?? '',
      pct: e?.runningPct ?? null,
      phase: e?.runningPhase ?? '',
      etaSec: e?.runningEtaSec ?? null,
    },
    needsAction: e?.needsAction ?? 0,
    total: sources.length,
    raw,
    sources,
    loading: c.isLoading,
  };
}

/** Queue every still-raw source. The server's queue is serial, so submitting them all is one decision,
 *  not a stampede. */
export function useEnrichAll() {
  const invalidate = useInvalidateCaseData();
  const toast = useToast();
  return useMutation({
    mutationFn: async (ids: string[]) => {
      const out: string[] = [];
      for (const id of ids) {
        await api.enrichSource(id);
        out.push(id);
      }
      return out;
    },
    onSuccess: (ids) => {
      toast.info(`${fmtInt(ids.length)} source${ids.length === 1 ? '' : 's'} queued for enrichment`,
        'They are parsed one at a time in the background; the screens fill in as each finishes.');
      invalidate();
    },
    onError: (e) => toast.error('Could not queue enrichment', e),
  });
}

export function useSkipAll() {
  const invalidate = useInvalidateCaseData();
  const toast = useToast();
  return useMutation({
    mutationFn: async (ids: string[]) => {
      // 409 is expected and is not a failure: a source that started enriching between the click and
      // the call cannot be un-started, and one already enriched needs no skipping. Skip what can be
      // skipped and report the number honestly rather than failing the whole batch on one race.
      const done: string[] = [];
      for (const id of ids) {
        try { await api.skipEnrichSource(id); done.push(id); } catch { /* already running or done */ }
      }
      return done;
    },
    onSuccess: (ids) => {
      toast.info(`${fmtInt(ids.length)} source${ids.length === 1 ? '' : 's'} left uninterpreted`,
        'Their raw lines stay searchable. Interpret any of them later from the Sources table.');
      invalidate();
    },
    onError: (e) => toast.error('Could not skip enrichment', e),
  });
}

/**
 * What a screen that is BLOCKED by the derived-build pause offers the analyst.
 *
 * The graph, the timeline and the anomaly roll-up do not build while sources are still being
 * interpreted: one bump per finished source would restart a six-worker extraction and throw it away,
 * which is the storm that used to end in SIGSEGV. Correct, but on a big workspace the queue is hours
 * long and the screen just says "waiting" — and the two ways out (skip a source, turn off automatic
 * interpretation) live on a different screen from the one that is blocked, so nobody finds them.
 *
 * Nothing is offered while the LIBRARY is loading: that ends by itself and there is no decision to make.
 */
export function DerivedPauseActions() {
  const c = useCase().data;
  const nav = useNavigate();
  const skipAll = useSkipAll();
  const queued = useMemo(
    () => [...(c?.sources ?? []), ...(c?.librarySources ?? [])].filter((s) => enrichOf(s) === 'queued'),
    [c],
  );
  if (!c || c.poolLoading || queued.length === 0) return null;
  return (
    <div className="pause-actions">
      <div className="pause-actions__count">
        <b>{fmtInt(queued.length)}</b> source{queued.length === 1 ? '' : 's'} still to interpret
        {c.enrichment?.running ? ' · 1 running now' : ''}
      </div>
      <div className="pause-actions__row">
        <button className="btn btn--sm" disabled={skipAll.isPending}
          onClick={() => skipAll.mutate(queued.map((s) => s.id))}>
          {skipAll.isPending && <span className="spinner" />}Skip the rest and build now
        </button>
        <button className="btn btn--sm" onClick={() => nav('/ingest')}><Icon.Sources />Sources</button>
      </div>
      <div className="pause-actions__hint">
        Skipping leaves those logs searchable as raw lines, with no parsed fields, timestamps or
        entities — so this view will answer over the rest of the corpus and say so. Interpret any of
        them again later from the Sources table.
      </div>
    </div>
  );
}

/* ───────────── per-source chip and actions (Sources table) ───────────── */

export function EnrichChip({ source }: { source: Source }) {
  const st = enrichOf(source);
  const meta = ENRICH_META[st];
  const at = source.enrichedAt;
  const tip = at ? `${meta.help} · enriched ${fmtTs(at)} UTC` : meta.help;
  return (
    <span className={cx('pill', meta.pill, 'tip')} data-tip={tip}>
      {st === 'enriching' && <span className="spinner" />}
      {st === 'error' && <Icon.Warn width={10} height={10} />}
      {meta.label}
    </span>
  );
}

/** Enrich now / Skip, per row. Dimmed, never hover-hidden — a control that only exists on hover is
 *  unreachable by touch. */
export function EnrichActions({ source }: { source: Source }) {
  const st = enrichOf(source);
  const invalidate = useInvalidateCaseData();
  const toast = useToast();
  const enrich = useMutation({
    mutationFn: () => api.enrichSource(source.id),
    onSuccess: () => { toast.info('Queued for enrichment', source.file); invalidate(); },
    onError: (e) => toast.error('Could not queue enrichment', e),
  });
  const skip = useMutation({
    mutationFn: () => api.skipEnrichSource(source.id),
    onSuccess: () => { toast.info('Left raw', `${source.file} stays searchable as text and out of the timeline, graph and detections.`); invalidate(); },
    onError: (e) => toast.error('Could not skip enrichment', e),
  });
  const busy = enrich.isPending || skip.isPending;
  const canEnrich = st === 'raw' || st === 'skipped' || st === 'error';
  const canSkip = st === 'raw' || st === 'queued';
  if (!canEnrich && !canSkip) return null;
  return (
    // the row itself is a button (it opens the mapping drawer); neither a click nor an Enter on these
    // two controls may reach it
    <span className="enrich-acts" onClick={(e) => e.stopPropagation()} onKeyDown={(e) => e.stopPropagation()}>
      {canEnrich && (
        <button className="enrich-act" disabled={busy} onClick={() => enrich.mutate()}
          title={st === 'error' ? 'Try the full parse again on this file' : 'Parse and normalize this file now — timestamps, severities, fields, entities and detections'}>
          {enrich.isPending && <span className="spinner" />}Enrich now
        </button>
      )}
      {canSkip && (
        <button className="enrich-act" disabled={busy} onClick={() => skip.mutate()}
          title="Leave this file raw. It stays searchable as text; it stays out of the timeline, the graph and the detections.">
          {skip.isPending && <span className="spinner" />}Skip
        </button>
      )}
    </span>
  );
}

/* ───────────── the workspace banner ───────────── */

/** Shown on every screen while enrichment is outstanding, and gone the moment it is not. It is
 *  deliberately one strip: the detail (which file, which error) lives on the Sources table, which is
 *  why this does not render there. */
/**
 * Readiness, on the Sources screen, in the analyst's terms.
 *
 * The old line was `40 of 679 not interpreted · 1 running · 39 queued`, and the complaint about it was
 * exactly right: it counts what is WRONG, it never says what is available, and on a big pool the
 * numbers move once a minute so it reads as stuck. What an analyst needs from this strip is three
 * things — how much of the workspace is fully usable, what is happening right now (with movement), and
 * what, if anything, they have to do to reach a fully ready state.
 *
 * So: ready count first, live file and percentage for the source in phase 2 (straight off the parse
 * tracker, which ticks constantly), the queue behind it, and a separate line for anything that needs a
 * PERSON — a failed parse, or raw files sitting still because automatic interpretation is off. Skipped
 * is stated as a decision, not as a warning: it is the one state that must never nag.
 */
export function EnrichBanner() {
  const { pathname } = useLocation();
  const { outstanding, total, pending, running, raw, counts, detail } = useEnrichment();
  const enrichAll = useEnrichAll();
  const invalidate = useInvalidateCaseData();
  // Enrichment finishes with no request from the UI, so every derived query (search, timeline, graph,
  // anomalies) is stale the moment it does. Refresh them once, on the transition — the same rule the
  // background pool load follows in AppShell.
  const was = useRef(outstanding);
  useEffect(() => {
    if (was.current > 0 && outstanding === 0) invalidate();
    was.current = outstanding;
  }, [outstanding, invalidate]);

  // ONE place, on request: the Sources screen. It rode above every screen in the app, which put a
  // four-line warning over the search results, the graph and the case notes at once. The analyst asked
  // for it on Sources only, and then asked again after the per-screen notes on Graph, Anomalies and the
  // case timeline turned out to be the same sentence in a different font — those are gone too.
  // Consequence, recorded because it is a real trade the analyst chose: while sources are still being
  // interpreted, the graph, the anomaly list and the case timeline answer over PART of the corpus and
  // no longer say so on the screen. This strip, on Sources, is the only place that says it.
  if (!pathname.startsWith('/ingest')) return null;
  if (!outstanding && !(counts?.error ?? 0)) return null;

  const queued = Math.max(0, pending - (running ? 1 : 0));
  const failed = counts?.error ?? 0;
  const idle = pending === 0;
  const pct = detail.pct;
  const eta = detail.etaSec;

  return (
    <div className="enrich-banner enrich-banner--slim" role="status" aria-live="polite">
      <div className="enrich-banner__body">
        <div className="enrich-banner__line">
          <b>{fmtInt(total - raw.length)} of {fmtInt(total)} source{total === 1 ? '' : 's'} interpreted</b>
          <span className="muted"> — every source is searchable with its timestamps either way;
            interpreting one adds parsed fields, entities and detections.</span>
        </div>

        {running ? (
          <div className="enrich-banner__line">
            <span className="spinner" />
            Interpreting <span className="mono">{detail.file || running}</span>
            {typeof pct === 'number' ? ` — ${pct.toFixed(0)}%` : ''}
            {typeof eta === 'number' && eta > 0 ? ` · ~${eta < 60 ? `${eta}s` : `${Math.round(eta / 60)}m`} left` : ''}
            {queued > 0 ? ` · ${fmtInt(queued)} waiting behind it` : ''}
          </div>
        ) : queued > 0 ? (
          <div className="enrich-banner__line"><span className="spinner" />{fmtInt(queued)} queued to interpret</div>
        ) : null}

        {(raw.length > 0 && idle) || failed > 0 ? (
          <div className={cx('enrich-banner__line', failed > 0 && 'enrich-banner__line--act')}>
            {failed > 0 && <Icon.Warn />}
            {/* Raw is a CHOICE now (Settings -> ingest), not an omission: it is 3.4 bytes of RAM per
                byte of log against 16.5, and a 20-column export ingests in a second instead of ten.
                So this states what those sources can and cannot answer — it does not scold. */}
            {raw.length > 0 && idle && (
              <span>
                <b>{fmtInt(raw.length)} kept raw</b> — searchable, with timestamps, and readable in
                full. Interpret one when you need <span className="mono">field:value</span> queries,
                its entities in the graph, or detection rules that read parsed fields.
              </span>
            )}
            {failed > 0 && (
              <span>{raw.length > 0 && idle ? ' ' : ''}<b>{fmtInt(failed)} failed to parse</b> — open the row to see the error and retry.</span>
            )}
            {raw.length > 0 && idle && (
              <button className="btn btn--sm btn--accent" disabled={enrichAll.isPending}
                onClick={() => enrichAll.mutate(raw.map((s) => s.id))}>
                {enrichAll.isPending && <span className="btn__spinner" />}Interpret {fmtInt(raw.length)} now
              </button>
            )}
          </div>
        ) : null}

        {(counts?.skipped ?? 0) > 0 && (
          <div className="enrich-banner__line muted">
            {fmtInt(counts?.skipped ?? 0)} left raw on purpose — they stay searchable as text. Interpret
            any of them from its row.
          </div>
        )}
      </div>
    </div>
  );
}

/* ───────────── the per-screen incompleteness note ───────────── */

/**
 * What Timeline / Graph / Anomalies say when the corpus they are answering over is partial. Same
 * visual language as the derived-build panel next to it: state what is missing, in numbers, and offer
 * the fix. `consequence` is the one sentence that differs per screen — what THIS view loses.
 */
/** NOT MOUNTED ANYWHERE — see the note in EnrichBanner. Kept because the wording is the honest
 *  statement of what an un-interpreted source costs a derived screen, and re-deriving it later from
 *  scratch would be worse than reading it here. Do not re-add it to a screen without asking. */
export function IncompleteNote({ consequence }: { consequence: ReactNode }) {
  const { outstanding, total, pending, raw } = useEnrichment();
  const nav = useNavigate();
  const enrichAll = useEnrichAll();
  if (!outstanding) return null;
  return (
    <div className="enrich-note" role="status" aria-live="polite">
      <Icon.Warn />
      <div className="enrich-note__body">
        <b>{fmtInt(outstanding)} of {fmtInt(total)} source{total === 1 ? '' : 's'} {outstanding === 1 ? 'is' : 'are'} not interpreted yet</b>
        {pending > 0 ? ` (${fmtInt(pending)} in the enrichment queue)` : ''}. {consequence}
      </div>
      <div className="enrich-note__acts">
        {pending === 0 && raw.length > 0 && (
          <button className="btn btn--sm" disabled={enrichAll.isPending}
            onClick={() => enrichAll.mutate(raw.map((s) => s.id))}>
            {enrichAll.isPending && <span className="btn__spinner" />}Enrich {fmtInt(raw.length)} now
          </button>
        )}
        <button className="btn btn--sm btn--ghost" onClick={() => nav('/ingest')}>Sources</button>
      </div>
    </div>
  );
}

/* ───────────── the Search field-level note ───────────── */

/** `status:` / `EventID:` / `user:` … — at most three named, then a count. Monospaced because they are
 *  query syntax, not prose. */
function FieldNames({ fields }: { fields: string[] }) {
  const shown = fields.slice(0, 3);
  const more = fields.length - shown.length;
  return (
    <>
      {shown.map((f, i) => (
        <span key={f}>
          {i > 0 && (i === shown.length - 1 && more === 0 ? ' and ' : ', ')}
          <span className="mono">{f}:</span>
        </span>
      ))}
      {more > 0 && ` and ${fmtInt(more)} other field${more === 1 ? '' : 's'}`}
    </>
  );
}

/**
 * What Search says when the query is scoped to a FIELD and part of the pool has no fields to scope on.
 *
 * This is the one incompleteness in the app that only exists for SOME queries. A raw source is fully
 * searchable as TEXT, so free text reaches every line of it and a warning there would be pure noise —
 * which is why the workspace banner, which cannot know the query, does not say this. But a
 * field-scoped term (`status:200`, `EventID:4625`) cannot match a single event of a source that is
 * still raw: the phase-1 event carries the line, its file and its id and nothing else. The analyst
 * then reads a hit count with no indication that whole files were never eligible to be counted —
 * exactly the "a file absent from search is indistinguishable from a search that found nothing"
 * failure this project keeps fighting.
 *
 * `fields` is what the query actually scoped on, decided from the DSL by the caller (SearchScreen owns
 * the DSL mirror). `sourceIds` is the page's source filter, so a query already narrowed to interpreted
 * files says nothing at all. `skipped` never raises it — leaving a file raw is a decision, and the
 * analyst who made it does not need telling again on every query.
 *
 * The workspace banner lives on Sources only now, so on Search this note is the ONLY signal — and it
 * fires only for a query that names a structured field. That is the case that can silently return
 * nothing (`status:200` cannot match an event with no parsed fields); a free-text query still reaches
 * every raw line, which is why it needs no warning of its own. If a future change makes free text
 * miss raw sources too, this screen needs a second note — not a global banner.
 */
export function FieldQueryNote({ fields, sourceIds }: { fields: string[]; sourceIds: string[] }) {
  const { sources } = useEnrichment();
  const nav = useNavigate();
  const enrichAll = useEnrichAll();
  // The counts come from the source list, not from `enrichment.outstanding`: the source filter narrows
  // them and the server's number is workspace-wide.
  const scope = useMemo(
    () => (sourceIds.length ? sources.filter((s) => sourceIds.includes(s.id)) : sources),
    [sources, sourceIds],
  );
  const affected = useMemo(() => scope.filter((s) => OUTSTANDING_STATES.has(enrichOf(s))), [scope]);
  const raw = useMemo(() => affected.filter((s) => enrichOf(s) === 'raw'), [affected]);
  if (fields.length === 0 || affected.length === 0) return null;
  const queued = affected.length - raw.length;
  return (
    <div className="enrich-note enrich-note--inline" role="status" aria-live="polite">
      <Icon.Warn width={12} height={12} />
      <div className="enrich-note__body">
        <b>{fmtInt(affected.length)} of {fmtInt(scope.length)} source{scope.length === 1 ? '' : 's'} could not
        be queried by field</b> — <FieldNames fields={fields} /> {fields.length === 1 ? 'is' : 'are'} empty on
        every event of a source that is not interpreted yet, so this result is over the rest of the pool.
        Those lines are still searchable as free text.
      </div>
      <div className="enrich-note__acts">
        {queued === 0 && raw.length > 0 && (
          <button className="btn btn--sm" disabled={enrichAll.isPending}
            onClick={() => enrichAll.mutate(raw.map((s) => s.id))}>
            {enrichAll.isPending && <span className="btn__spinner" />}Enrich {fmtInt(raw.length)} now
          </button>
        )}
        <button className="btn btn--sm btn--ghost" onClick={() => nav('/ingest')}>Sources</button>
      </div>
    </div>
  );
}
