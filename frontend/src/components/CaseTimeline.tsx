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
 *
 * THE ROW IS THE CLAIM; THE OPENED ENTRY IS THE EVIDENCE. Every row used to carry the log line itself,
 * which is the wrong altitude for a chronology — what an analyst reads down the page is WHEN something
 * happened and WHAT THEY CONCLUDED about it. So the row leads with their own sentence (the first line
 * of the note), and the log line moved into `EntryDetail`, which the whole row opens: identity chips
 * with the event id to cite, the note and labels with their editor, then the raw line exactly as the
 * log recorded it, the entities it mentions and the rules it fired. An
 * entry with no note yet still has to be identifiable, so it falls back to the normalized message —
 * set in mono and dimmed, because those are the log's words and not the analyst's.
 *
 * Several entries can be open at once. Comparing two moments of a chronology side by side is the whole
 * reason to open them, and an accordion that shuts one to open the next forbids exactly that.
 */
import { Fragment, useCallback, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import type { CaseSetEntry, Event, Source } from '../api/types';
import { useAddToCase, useCaseSet, useRemoveFromCase } from '../hooks/queries';
import { useToast } from '../hooks/useToast';
import { useArrivals, useTypewriter } from '../hooks/useArrivals';
import { cx, fmtClock, fmtDay, fmtInt, fmtTs, humanizeStamps, sevVar } from '../utils/format';
import { inlineMd, renderMarkdown, unescapeBreaks } from '../utils/markdown';
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

/* ───────── one entry, opened ───────── */

/** localStorage: '1' = newest first. Oldest first is the default — a timeline reads forward. */
const SORT_KEY = 'iris.timeline.newestFirst';

/** The pace of the sequence: how long after the entry that happened just before it in time this
 *  one happened (`older` is the neighbouring row — above when oldest-first, below when newest-first).
 *  A chronology whose entries are four seconds apart and one whose entries are four days apart look
 *  identical in a list of timestamps, and the difference is usually the finding. */
function gapLabel(older: string | undefined, cur: string | undefined): string {
  if (!older || !cur) return '';
  const ms = Date.parse(cur) - Date.parse(older);
  if (!Number.isFinite(ms) || ms <= 0) return '';
  const s = Math.round(ms / 1000);
  if (s < 60) return `+${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `+${m}m${s % 60 ? ` ${s % 60}s` : ''}`;
  const h = Math.floor(m / 60);
  if (h < 24) return `+${h}h${m % 60 ? ` ${m % 60}m` : ''}`;
  const d = Math.floor(h / 24);
  return `+${d}d${h % 24 ? ` ${h % 24}h` : ''}`;
}

/** The row's one-line summary of a note. It goes through the same `unescapeBreaks` repair the renderer
 *  uses — a model that double-escapes its tool arguments writes the two characters backslash-n where it
 *  means a line break, and every AI-written note on disk is stored that way — and then its first real
 *  line is taken, with heading and bullet markers stripped, because `## Finding` is not a sentence. */
function noteLine(note: string): string {
  const first = unescapeBreaks(note).split('\n').map((l) => l.trim()).find(Boolean) ?? '';
  const bare = first.replace(/^#{1,6}\s+/, '').replace(/^[-*+]\s+/, '').replace(/^>\s*/, '');
  // The same stamp repair the renderer applies, and with the same exception: text between backticks
  // is a quoted value and keeps the form the log gave it.
  return bare.split('`').map((seg, i) => (i % 2 === 0 ? humanizeStamps(seg) : seg)).join('`');
}

/** The row's sentence. Its own component because an ARRIVING row (the assistant just annotated
 *  it while the timeline was on screen) is revealed as if being written — hooks/useArrivals.ts —
 *  and a hook has to live in a component, not in a `.map`. */
function RowSaid({ said, summary, arriving, id }: { said: string; summary: string; arriving: boolean; id: string }) {
  const shown = useTypewriter(said, arriving);
  return (
    <span className={cx('tl__title', !said && 'tl__title--log')} title={said || undefined}>
      {said && <Icon.Note className="tl__noteglyph" aria-hidden />}
      {/* The analyst's sentence is MARKUP: inline code, emphasis and the data marks
          (`proseRun`) render on the row itself, so an address or a file name reads as
          one at a glance instead of vanishing into the line. The log fallback stays
          a plain string — those are the log's words, shown as the log wrote them. */}
      {said ? inlineMd(shown, `tl-${id}`) : summary}
    </span>
  );
}

/** Everything behind one entry, revealed by clicking the row.
 *
 *  The row used to carry the log line itself, and that is the wrong altitude for a chronology: what an
 *  analyst reads down the page is WHEN it happened and WHAT THEY CONCLUDED, and the line that proves it
 *  is what they open when they want it. So the row is the claim and this is the evidence — identity
 *  first, then the analyst's own words, then the raw line exactly as the log recorded it — set as a
 *  code block, because it IS code as far as the reader is concerned — the entities it mentions and the
 *  rules it fired. The normalized message and the parsed fields were removed on request: the row
 *  already falls back to the message when there is no note, and the fields are one click away on the
 *  event page.
 *
 *  Deliberately NOT a second copy of the event detail page: no correlations (an O(pool) derived
 *  structure — see CLAUDE.md on why event detail itself must stay a dictionary lookup) and no file
 *  context. The page is one button away for those. */
function EntryDetail({ en, e, editing, onEdit, onDone }: {
  en: CaseSetEntry; e: Event | undefined; editing: boolean; onEdit: () => void; onDone: () => void;
}) {
  const nav = useNavigate();

  return (
    <div className="tlx">
      {/* Identity as labelled chips rather than one dot-separated sentence — the event id most of all,
          because that is what every note, indicator and report citation has to quote. */}
      <div className="tlx__facts">
        <span className="tlx__fact"><i>event</i><b className="mono">{en.eventId}</b></span>
        <span className="tlx__fact"><i>when</i>{e?.ts ? `${fmtTs(e.ts)} UTC` : 'no parsed timestamp'}</span>
        {e && <span className="tlx__fact tlx__fact--file"><i>file</i><span title={e.file}>{e.file}</span></span>}
        {e?.source && <span className="tlx__fact"><i>parsed as</i>{e.source}</span>}
        {e?.host && <span className="tlx__fact"><i>host</i>{e.host}</span>}
        {e?.user && <span className="tlx__fact"><i>user</i>{e.user}</span>}
        {en.addedAt && <span className="tlx__fact"><i>added</i>{fmtTs(en.addedAt)} UTC</span>}
      </div>

      <section className="tlx__sec">
        <div className="tlx__eyebrow">Why it is on the timeline</div>
        {editing ? (
          <LabelEditor eventId={en.eventId} labels={en.labels} note={en.note} onDone={onDone} />
        ) : (
          <>
            {en.labels.length > 0 && (
              <div className="tlx__labels">{en.labels.map((l) => <span key={l} className="tag tag--label">{l}</span>)}</div>
            )}
            {en.note
              ? <div className="tl__note md">{renderMarkdown(en.note)}</div>
              : <div className="tlx__empty">No label or note yet. Say what this moment was and the row reads as your sentence instead of the log&rsquo;s.</div>}
            <div className="tlx__acts">
              <button className="btn btn--sm" onClick={onEdit}>
                {en.labels.length || en.note ? 'Edit label & note' : 'Add label & note'}
              </button>
            </div>
          </>
        )}
      </section>

      {/* An entry whose event is not in the pool is KEPT, and says so plainly: it is anchored to the log
          LINE, not to the id, so it comes back when its file is loaded again. Dropping the analyst's
          curation because a source is unloaded is the worst bug this app has had. */}
      {!e && (
        <div className="tlx__gone">
          This line is not in the workspace right now, so its evidence cannot be shown. The entry is kept —
          it is anchored to the log line itself and re-attaches when that file is loaded again.
        </div>
      )}

      {e && (
        <>
          <section className="tlx__sec">
            <div className="tlx__eyebrow">Raw line<span className="tlx__hint">as the log recorded it</span></div>
            <pre className="tlx__code"><code>{e.raw || e.msg || '—'}</code></pre>
          </section>

          {e.entities.length > 0 && (
            <section className="tlx__sec">
              <div className="tlx__eyebrow">Entities<span className="sec__count">{e.entities.length}</span></div>
              <div className="entity-chips">
                {e.entities.map((t) => (
                  <button key={t} className="chip chip--mono"
                    onClick={() => nav(`/search?q=${encodeURIComponent(`entity:"${t}"`)}`)}
                    title={`Search every event mentioning ${t}`}>{t}</button>
                ))}
              </div>
            </section>
          )}

          {e.detections.length > 0 && (
            <section className="tlx__sec">
              <div className="tlx__eyebrow">Detections fired<span className="sec__count">{e.detections.length}</span></div>
              <div className="tlx__dets">
                {e.detections.map((d) => (
                  <div key={d.id} className="detection" style={{ borderColor: sevVar(d.level) }}>
                    <div className="detection__name">{d.name}</div>
                    {/* the level in lowercase, like every other statement of severity in the app —
                        uppercase mono is the treatment this UI dropped for pills, tags and heads */}
                    <div className="detection__meta">{d.id} · {d.level}</div>
                  </div>
                ))}
              </div>
            </section>
          )}

          <div className="tlx__acts">
            <button className="btn btn--sm" onClick={() => nav(`/events/${encodeURIComponent(en.eventId)}`)}>
              Open the full event
            </button>
          </div>
        </>
      )}
    </div>
  );
}

/* ───────── the timeline itself ───────── */
export function CaseTimeline({ sources }: { sources: Source[] }) {
  const nav = useNavigate();
  const caseSet = useCaseSet();
  const remove = useRemoveFromCase();
  const toast = useToast();
  const [editing, setEditing] = useState<string | null>(null);
  // Which entries are open. A SET, not one id: comparing two moments of a chronology side by side
  // is the whole reason to open them, and an accordion that shuts one to open the next forbids it.
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  const toggle = useCallback((id: string) => {
    setExpanded((cur) => {
      const next = new Set(cur);
      if (!next.delete(id)) next.add(id);
      return next;
    });
  }, []);

  const byId = useMemo(
    () => new Map((caseSet.data?.events ?? []).map((e) => [e.id, e])),
    [caseSet.data],
  );
  // Chronological — oldest first — because that is what a timeline is; a "Newest first" toggle
  // flips it, remembered per browser. An entry whose event has no parsed timestamp sorts LAST in
  // BOTH directions rather than silently claiming a position in the sequence it cannot support.
  const [newestFirst, setNewestFirst] = useState<boolean>(() => {
    try { return localStorage.getItem(SORT_KEY) === '1'; } catch { return false; }
  });
  const toggleSort = () => {
    setNewestFirst((v) => {
      try { localStorage.setItem(SORT_KEY, v ? '0' : '1'); } catch { /* private mode */ }
      return !v;
    });
  };
  const chronological = useMemo(() => {
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
  const ordered = useMemo(() => {
    if (!newestFirst) return chronological;
    const stamped = chronological.filter((en) => byId.get(en.eventId)?.ts);
    const blank = chronological.filter((en) => !byId.get(en.eventId)?.ts);
    return [...stamped.reverse(), ...blank];
  }, [chronological, newestFirst, byId]);
  const inSet = useMemo(() => new Set(ordered.map((e) => e.eventId)), [ordered]);
  // Entries that landed while the timeline was on screen — the assistant building it — arrive with
  // a fade and their sentence revealed; the initial load paints at once. An ANNOTATION of an entry
  // already present is keyed separately (id + note) so a fresh sentence on an old row is revealed too.
  const arrivals = useArrivals(useMemo(
    () => ordered.map((en) => `${en.eventId}\u0001${en.note ? 'n' : ''}`), [ordered]), caseSet.data !== undefined);
  /* What the sequence covers, stated once above it. Not a row of stat tiles — the case screen
     deliberately has none — just the two facts a chronology is asked for first: how long it spans, and
     how much of it the analyst has actually written up. */
  const span = useMemo(() => {
    const stamped = chronological.map((en) => byId.get(en.eventId)?.ts).filter(Boolean) as string[];
    if (!stamped.length) return '';
    const a = stamped[0]!;
    const b = stamped[stamped.length - 1]!;
    if (a === b) return `${fmtTs(a)} UTC`;
    return a.slice(0, 10) === b.slice(0, 10)
      ? `${fmtTs(a)} → ${fmtClock(b)} UTC`
      : `${fmtTs(a)} → ${fmtTs(b)} UTC`;
  }, [chronological, byId]);
  const annotated = useMemo(() => ordered.filter((en) => en.note || en.labels.length).length, [ordered]);

  const drop = (en: CaseSetEntry, e?: Event) =>
    remove.mutate(en.eventId, { onSuccess: () => toast.info('Removed from the timeline', e?.msg ?? en.eventId) });

  const actions = (
    <>
      <button className="btn btn--sm" onClick={toggleSort} aria-pressed={newestFirst}
        title={newestFirst ? 'Showing the latest entry first — click for oldest first' : 'Showing the earliest entry first — click for newest first'}>
        {newestFirst ? 'Newest first' : 'Oldest first'}
      </button>
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
        <span className="field__hint">
          {ordered.length} event{ordered.length === 1 ? '' : 's'} · oldest first
          {span && <> · <span className="mono" title="first and last curated moment (UTC)">{span}</span></>}
          {annotated > 0 && <> · {annotated} annotated</>}
        </span>
        <span style={{ flex: 1 }} />
        {actions}
      </div>
      {incomplete}
      <ol className="tl">
        {ordered.map((en, i) => {
          const e = byId.get(en.eventId);
          const open = expanded.has(en.eventId);
          // A chronology is read by DAY first. Grouping under a sticky date heading is what turns a
          // flat list of fifty timestamps into something an analyst can scan — and it is why the row
          // itself can show the clock alone: the date is on screen, one heading above, so the
          // absolute time an analyst correlates against raw logs is never lost (the full stamp is on
          // the row's own title, and spelled out in the opened entry).
          const day = e?.ts ? e.ts.slice(0, 10) : '';
          const prevTs = i > 0 ? byId.get(ordered[i - 1]!.eventId)?.ts : undefined;
          const prevDay = i > 0 ? (prevTs ?? '').slice(0, 10) : null;
          const newDay = day !== prevDay;
          // The gap is measured against the entry that happened just BEFORE this one in time — the
          // row above when oldest-first, the row below when newest-first — and only within a day:
          // "+19h" across a date heading restates what the heading already says.
          const olderIdx = newestFirst ? i + 1 : i - 1;
          const olderTs = olderIdx >= 0 && olderIdx < ordered.length ? byId.get(ordered[olderIdx]!.eventId)?.ts : undefined;
          const olderDay = (olderTs ?? '').slice(0, 10);
          const gap = olderTs && olderDay === day ? gapLabel(olderTs, e?.ts) : '';
          // THE ROW IS THE CLAIM, NOT THE EVIDENCE. The analyst's own sentence leads when there is one;
          // a log line is what they wrote it about, and it lives in the opened entry. An entry with no
          // note yet still needs to be identifiable, so it falls back to the normalized message —
          // quieter, and marked as the log's words rather than the analyst's.
          // `said` may come back empty from a note that is only a heading marker, so the fallback is
          // driven by what there actually is to show, not by whether a note exists.
          const said = en.note ? noteLine(en.note) : '';
          const summary = said || e?.msg || 'this line is not in the workspace right now';
          return (
            <Fragment key={en.eventId}>
            {newDay && (
              <li className="tl__day" aria-hidden={false}>
                <span className="tl__day-label">{day ? fmtDay(day) : 'No timestamp'}</span>
                <span className="tl__day-rule" />
              </li>
            )}
            <li className={cx('tl__item', open && 'tl__item--open', arrivals.has(`${en.eventId}\u0001${en.note ? 'n' : ''}`) && 'tl__item--arriving')}>
              <div className="tl__rail" aria-hidden><span className={cx('tl__dot', e && `tl__dot--${e.sev}`)} /></div>
              <div className="tl__body">
                <div className="tl__row">
                  {/* One real <button> spanning the row, with the remove control OUTSIDE it: a button
                      inside a button is invalid, and making the row a role="button" div would put the
                      keyboard handling back on us for no gain. */}
                  <button type="button" className="tl__summary" aria-expanded={open}
                    onClick={() => toggle(en.eventId)}
                    title={open ? 'Collapse this entry' : 'Open this entry — the raw line, its entities and detections'}>
                    <Icon.Chevron className={cx('tl__chev', open && 'tl__chev--open')} aria-hidden />
                    <span className="cell-mono tl__ts"
                      title={[e?.ts ? `${fmtTs(e.ts)} UTC` : 'this event has no parsed timestamp',
                              en.addedAt ? `added to the case ${fmtTs(en.addedAt)} UTC` : ''].filter(Boolean).join(' · ')}>
                      {e?.ts ? fmtClock(e.ts) : '--:--:--'}
                    </span>
                    {gap && <span className="tl__gap" title="how long after the entry just before it in time">{gap}</span>}
                    {e && <SevTag sev={e.sev} />}
                    {en.labels.map((l) => <span key={l} className="tag tag--label">{l}</span>)}
                    <RowSaid said={said} summary={summary} arriving={arrivals.has(`${en.eventId}\u0001${en.note ? 'n' : ''}`)} id={en.eventId} />
                    {/* The FILE, not the parser. `source` is what the line was parsed AS (nginx,
                        delimited, jsonl) and several files share one; a timeline entry has to name the
                        log it came from, because that is what the analyst opens and what a report
                        cites. The parser is one line down in the opened entry. */}
                    <span className="cell-mono cell-dim tl__src ellipsis" title={e?.file}>{e?.file || e?.source}</span>
                  </button>
                  <button className="btn btn--sm btn--icon btn--ghost tl__x"
                    title="Remove from the timeline (the event stays in the pool)"
                    aria-label="Remove from timeline" onClick={() => drop(en, e)}>
                    <Icon.Trash />
                  </button>
                </div>
                {open && (
                  <EntryDetail en={en} e={e} editing={editing === en.eventId}
                    onEdit={() => setEditing(en.eventId)} onDone={() => setEditing(null)} />
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
