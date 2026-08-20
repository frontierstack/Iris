/**
 * The case timeline: the events curated into this case, in the order they happened, each with a label
 * and a note the analyst writes.
 *
 * It replaces two things that used to be separate — the global Timeline screen (correlated clusters over
 * the whole pool) and the label-grouped "events curated into this case" list. Neither was the thing an
 * analyst actually builds: a case timeline is a chosen, ordered, annotated sequence — *this* happened,
 * then *this* — and it has to be editable in place, item by item.
 *
 * Adding is deliberately two doors, because evidence arrives two ways: pick individual lines out of a
 * source file (AddFromSource, below) or send them over from Search. Removing an entry never deletes the
 * event — it leaves the case's selection, and stays in the pool.
 */
import { Fragment, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import type { CaseSetEntry, Event, Source } from '../api/types';
import { useAddToCase, useCaseSet, useRemoveFromCase } from '../hooks/queries';
import { useToast } from '../hooks/useToast';
import { cx, fmtClock, fmtDay, fmtInt, fmtTs } from '../utils/format';
import { renderMarkdown } from '../utils/markdown';
import { LabelEditor } from './CaseSet';
import { Icon } from './icons';
import { Drawer, EmptyState, Loading, SevTag } from './ui';

/* ───────── add individual log lines from one source ───────── */
function AddFromSource({ sources, inSet }: { sources: Source[]; inSet: Set<string> }) {
  const [open, setOpen] = useState(false);
  const [sid, setSid] = useState<string>('');
  const [q, setQ] = useState('');
  const add = useAddToCase();
  const toast = useToast();
  const picked = sid || sources[0]?.id || '';

  // Only fetch once the drawer is open: a source can hold a million events and this is a picker, not a
  // search screen — the server-side query does the filtering.
  const rows = useQuery({
    queryKey: ['case-timeline-picker', picked, q],
    queryFn: () => api.events({ q, sources: [picked], limit: 100, sort: 'ts_asc' }),
    enabled: open && !!picked,
  });

  const addOne = (e: Event) =>
    add.mutate({ id: e.id }, {
      onSuccess: () => toast.success('Added to the timeline', e.msg.slice(0, 80)),
      onError: (err) => toast.error('Could not add that event', err),
    });

  return (
    <>
      <button className="btn btn--sm" onClick={() => setOpen(true)} disabled={!sources.length}
        title={sources.length ? 'Pick individual log lines out of a file in this case'
          : 'Put a source in scope for this case first'}>
        <Icon.Plus /> Add from source
      </button>
      <Drawer open={open} onClose={() => setOpen(false)} wide
        title="Add log lines to the timeline"
        sub="pick a file in this case, then add the individual lines that belong in the sequence"
        footer={<button className="btn btn--ghost" onClick={() => setOpen(false)}>Done</button>}>
        <div className="form-row" style={{ marginBottom: 12 }}>
          <select value={picked} onChange={(e) => setSid(e.target.value)} aria-label="Source file">
            {sources.map((s) => <option key={s.id} value={s.id}>{s.file} · {fmtInt(s.events)} events</option>)}
          </select>
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="filter these lines (same query syntax as Search)"
            spellCheck={false} aria-label="Filter lines" />
        </div>
        {rows.isLoading && <Loading inline label="Reading the file…" />}
        {rows.data && rows.data.rows.length === 0 && (
          <EmptyState inline title="No matching lines" body="Clear the filter, or pick a different file." />
        )}
        <div className="tl-picker">
          {(rows.data?.rows ?? []).map((e) => {
            const on = inSet.has(e.id);
            return (
              <div key={e.id} className={cx('tl-picker__row', on && 'on')}>
                <button className="btn btn--sm btn--icon btn--ghost" disabled={on || add.isPending}
                  title={on ? 'Already on the timeline' : 'Add this line to the timeline'}
                  aria-label={on ? 'Already on the timeline' : 'Add to timeline'}
                  onClick={() => addOne(e)}>
                  {on ? <Icon.Check /> : <Icon.Plus />}
                </button>
                <SevTag sev={e.sev} />
                <span className="cell-mono cell-dim">{e.ts ? `${fmtTs(e.ts)} UTC` : 'no timestamp'}</span>
                <span className="cell-mono cell-bright ellipsis" title={e.msg}>{e.msg}</span>
              </div>
            );
          })}
        </div>
        {rows.data && rows.data.total > rows.data.rows.length && (
          <div className="field__hint" style={{ marginTop: 8 }}>
            Showing {rows.data.rows.length} of {fmtInt(rows.data.total)} matching lines — narrow the filter to see the rest.
          </div>
        )}
      </Drawer>
    </>
  );
}

/* ───────── the timeline itself ───────── */
export function CaseTimeline({ sources }: { sources: Source[] }) {
  const nav = useNavigate();
  const caseSet = useCaseSet();
  const remove = useRemoveFromCase();
  const toast = useToast();
  const [editing, setEditing] = useState<string | null>(null);

  const byId = useMemo(
    () => new Map((caseSet.data?.events ?? []).map((e) => [e.id, e])),
    [caseSet.data],
  );
  // Chronological, because that is what a timeline is. An entry whose event has no parsed timestamp
  // sorts last rather than silently claiming a position in the sequence it cannot support.
  const ordered = useMemo(() => {
    const entries = caseSet.data?.entries ?? [];
    return [...entries].sort((a, b) => {
      const ta = byId.get(a.eventId)?.ts ?? '';
      const tb = byId.get(b.eventId)?.ts ?? '';
      if (!ta && !tb) return a.eventId.localeCompare(b.eventId);
      if (!ta) return 1;
      if (!tb) return -1;
      return ta.localeCompare(tb);
    });
  }, [caseSet.data, byId]);
  const inSet = useMemo(() => new Set(ordered.map((e) => e.eventId)), [ordered]);

  const drop = (en: CaseSetEntry, e?: Event) =>
    remove.mutate(en.eventId, { onSuccess: () => toast.info('Removed from the timeline', e?.msg ?? en.eventId) });

  const actions = (
    <>
      <AddFromSource sources={sources} inSet={inSet} />
      <button className="btn btn--sm" onClick={() => nav('/search')} title="Find events anywhere in the pool and add them">
        <Icon.Search /> Add from search
      </button>
    </>
  );

  if (caseSet.isLoading) return <><div className="tl-head">{actions}</div><Loading inline /></>;

  /* The un-interpreted-sources note that used to sit here was removed on request (it is stated once,
     on Sources). An unenriched event still has ts="" and still sorts last — that has not changed, it
     is simply no longer explained on this screen. */
  const incomplete = null;

  if (!ordered.length) {
    return (
      <>
        <div className="tl-head">{actions}</div>
        {incomplete}
        <EmptyState
          title="No timeline yet"
          body="Add the log lines that matter — from a file in this case, or from Search. Each one can carry a label (initial access, lateral movement, exfiltration…) and a sentence of context."
        />
      </>
    );
  }

  return (
    <>
      <div className="tl-head">
        <span className="field__hint">{ordered.length} event{ordered.length === 1 ? '' : 's'} · oldest first</span>
        <span style={{ flex: 1 }} />
        {actions}
      </div>
      {incomplete}
      <ol className="tl">
        {ordered.map((en, i) => {
          const e = byId.get(en.eventId);
          const open = editing === en.eventId;
          // A chronology is read by DAY first. Grouping under a sticky date heading is what turns a
          // flat list of fifty timestamps into something an analyst can scan — and it is why the row
          // itself can show the clock alone: the date is on screen, one heading above, so the
          // absolute time an analyst correlates against raw logs is never lost (the full stamp is
          // still on the row's own title).
          const day = e?.ts ? e.ts.slice(0, 10) : '';
          const prevDay = i > 0 ? (byId.get(ordered[i - 1]!.eventId)?.ts ?? '').slice(0, 10) : null;
          const newDay = day !== prevDay;
          return (
            <Fragment key={en.eventId}>
            {newDay && (
              <li className="tl__day" aria-hidden={false}>
                <span className="tl__day-label">{day ? fmtDay(day) : 'No timestamp'}</span>
                <span className="tl__day-rule" />
              </li>
            )}
            <li className="tl__item">
              <div className="tl__rail" aria-hidden><span className={cx('tl__dot', e && `tl__dot--${e.sev}`)} /></div>
              <div className="tl__body">
                <div className="tl__row">
                  {/* The FULL event timestamp, date included and marked UTC. A timeline read weeks later
                      is correlated against raw logs by absolute time — a clock with no date cannot be. */}
                  <span className="cell-mono tl__ts"
                    title={[e?.ts ? `${fmtTs(e.ts)} UTC` : 'this event has no parsed timestamp',
                            en.addedAt ? `added to the case ${fmtTs(en.addedAt)} UTC` : ''].filter(Boolean).join(' · ')}>
                    {e?.ts ? fmtClock(e.ts) : '--:--:--'}
                  </span>
                  {e && <SevTag sev={e.sev} />}
                  {en.labels.map((l) => <span key={l} className="tag tag--label">{l}</span>)}
                  {/* NOT `ellipsis`: a raw log line cut at the right edge of the row tells the analyst
                      almost nothing about the event they curated. It wraps to two lines and clamps
                      there, so a long line is readable and a row is still a fixed, scannable height. */}
                  <span className="cell-mono cell-bright tl__msg"
                    role="link" tabIndex={0} title={e?.msg}
                    onClick={() => nav(`/events/${encodeURIComponent(en.eventId)}`)}
                    onKeyDown={(k) => { if (k.key === 'Enter') nav(`/events/${encodeURIComponent(en.eventId)}`); }}>
                    {e?.msg ?? `${en.eventId} — event not in the pool`}
                  </span>
                  {/* The FILE, not the parser. `source` is what the line was parsed AS (nginx, delimited,
                      jsonl) and several files share one; a timeline entry has to name the log it came
                      from, because that is what the analyst opens and what a report cites. The parser
                      is still one hover away. */}
                  <span className="cell-mono cell-dim tl__src ellipsis"
                    title={e ? `${e.file}${e.source ? `  ·  parsed as ${e.source}` : ''}` : undefined}>
                    {e?.file || e?.source}
                  </span>
                  <button className="btn btn--sm btn--ghost" onClick={() => setEditing(open ? null : en.eventId)}>
                    {en.labels.length || en.note ? 'Edit' : 'Label'}
                  </button>
                  <button className="btn btn--sm btn--icon btn--ghost" title="Remove from the timeline (the event stays in the pool)"
                    aria-label="Remove from timeline" onClick={() => drop(en, e)}>
                    <Icon.Trash />
                  </button>
                </div>
                {en.note && !open && <div className="tl__note md">{renderMarkdown(en.note)}</div>}
                {open && (
                  <div className="tl__editor">
                    <LabelEditor eventId={en.eventId} labels={en.labels} note={en.note} onDone={() => setEditing(null)} />
                  </div>
                )}
              </div>
            </li>
            </Fragment>
          );
        })}
      </ol>
    </>
  );
}
