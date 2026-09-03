import { Icon } from '../components/icons';
import { useQuery } from '@tanstack/react-query';
import { useNavigate, useParams } from 'react-router-dom';
import { api } from '../api/client';
import { useAiPanel } from '../components/AiPanelContext';
import { NoteAboutButton } from '../components/CaseNotes';
import { AddToCaseButton } from '../components/CaseSet';
import { ErrorState, Loading, SevTag } from '../components/ui';
import { qk, useCase } from '../hooks/queries';
import { cx, fmtClock, fmtTs, sevVar } from '../utils/format';

/** Where this event sits in its original log file, with a few lines of context.
 *
 *  Two panels, because they answer two questions: the line as the log recorded it, and its
 *  neighbourhood in the file. Each carries its own head — the file name and the line number sit
 *  there, in mono, where the template puts what a result cost. */
function FileLocation({ eventId, raw, file }: { eventId: string; raw: string; file: string }) {
  const loc = useQuery({ queryKey: ['event-location', eventId], queryFn: () => api.eventLocation(eventId), staleTime: 300_000 });
  const d = loc.data;
  return (
    <>
      <section className="dpanel">
        <div className="dpanel__head">
          <span className="lbl">Raw line</span>
          <span className="dpanel__meta">
            <span className="dpanel__meta--file" title={file}>{file}</span>
            {d?.line != null && (
              <span className="num">
                line {d.line.toLocaleString()}
                {d.totalLines ? ` of ${d.totalLines.toLocaleString()}` : ''}
              </span>
            )}
            {d?.line != null && !d.exact && <span className="badge badge--warn" title={d.reason ?? ''}>approx</span>}
            {loc.isLoading && <span>locating…</span>}
            {d && d.line == null && <span title={d.reason ?? ''}>not line-addressable</span>}
          </span>
        </div>
        <div className="raw">{raw || '—'}</div>
      </section>
      {d?.context?.length ? (
        <section className="dpanel filectx">
          <div className="dpanel__head">
            <span className="lbl">In context</span>
            <span className="dpanel__meta"><span className="num">{d.context.length} lines</span></span>
          </div>
          {/* one scroller around every line — scrolling per line gave each its own scrollbar */}
          <div className="filectx__body">
            {d.context.map((l) => (
              <div key={l.n} className={cx('filectx__line', l.current && 'current')}>
                <span className="filectx__n">{l.n}</span>
                <span className="filectx__t">{l.text}</span>
              </div>
            ))}
          </div>
        </section>
      ) : null}
    </>
  );
}

export function EventDetailScreen() {
  const { id = '' } = useParams();
  const nav = useNavigate();
  const ai = useAiPanel();
  const c = useCase();
  const q = useQuery({ queryKey: qk.event(id), queryFn: () => api.event(id), enabled: !!id });
  const e = q.data;

  if (q.isLoading) return <div className="page"><Loading label="Loading event…" /></div>;
  if (q.isError || !e)
    return (
      <div className="page">
        <ErrorState title="Event not found" error={q.error} onRetry={() => void q.refetch()} />
        <div className="detail__backrow" style={{ marginTop: 12 }}><button className="btn" onClick={() => nav('/search')}>Back to search</button></div>
      </div>
    );

  const fields = Object.entries(e.fields ?? {});
  const color = sevVar(e.sev);
  const canGoBack = (window.history.state?.idx ?? 0) > 0;
  return (
    <div className="page detail">
      <div className="detail__main">
        <div className="detail__backrow">
          <button className="btn btn--sm" onClick={() => (canGoBack ? nav(-1) : nav('/search'))}><Icon.ArrowLeft />{canGoBack ? 'Back' : 'Back to search'}</button>
          <button className="btn btn--sm btn--ghost" onClick={() => nav('/search')}>Search</button>
        </div>
        <section className="dpanel">
          <div className="detail__head">
            <div className="detail__sevbar" style={{ background: color }} />
            <div className="detail__ident">
              <div className="detail__title">{e.msg}</div>
              {/* Facts as labelled chips instead of one dot-separated string: an analyst reading a
                  detail page is looking for ONE of these (which host? which file?), and a run-on line
                  makes every lookup a scan. The event id leads, because it is what every note,
                  indicator and report citation has to quote; the timestamp is full and marked UTC,
                  like everywhere else. */}
              <div className="detail__facts">
                <span className="detail__fact detail__fact--id" title="event id — cite this in notes and indicators"><i>id</i>{e.id}</span>
                <span className="detail__fact"><SevTag sev={e.sev} /></span>
                <span className="detail__fact detail__fact--ts" title="event timestamp (UTC)">{fmtTs(e.ts)} UTC</span>
                <span className="detail__fact"><i>source</i>{e.source}</span>
                <span className="detail__fact detail__fact--file" title={e.file}><i>file</i><span>{e.file}</span></span>
                {e.host && <span className="detail__fact"><i>host</i>{e.host}</span>}
                {e.user && <span className="detail__fact"><i>user</i>{e.user}</span>}
              </div>
            </div>
            <div className="detail__actions">
              <button className="btn btn--sm" onClick={() => ai.open({ scope: 'event', id: e.id, label: e.msg })}>Ask AI about this event</button>
              <AddToCaseButton event={e} />
              {c.data && <NoteAboutButton caseId={c.data.id} refToAttach={{ kind: 'event', value: e.id, label: e.msg.slice(0, 60) }} />}
            </div>
          </div>
          <div className="dpanel__head">
            <span className="lbl">Parsed fields</span>
            <span className="dpanel__meta"><span className="num">{fields.length}</span></span>
          </div>
          {fields.length === 0
            ? <div className="dpanel__empty">No structured fields were extracted from this line.</div>
            : (
              <div className="fields-grid">
                {fields.map(([k, v]) => (
                  <div key={k} className="field-kv">
                    <span className="field-kv__k">{k}</span>
                    <span className="field-kv__v" title={v}>{v === '' ? '—' : v}</span>
                  </div>
                ))}
              </div>
            )}
        </section>

        <FileLocation eventId={e.id} raw={e.raw} file={e.file} />

        <section className="dpanel">
          <div className="dpanel__head">
            <span className="lbl">Correlated events</span>
            <span className="dpanel__note">why Iris tied each one to this event</span>
            <span className="dpanel__meta"><span className="num">{e.correlations.length}</span></span>
          </div>
          <div className="table">
            {/* "None" and "not computed yet" are different facts about the evidence, and the second one
                must never be printed as the first. The server sends `analysis` only when it could not
                answer — opening an event no longer waits minutes for that build to finish. */}
            {e.correlations.length === 0 && (e.analysis
              ? <div className="table__empty">
                  Correlations are not available yet — {e.analysis.note
                    ? e.analysis.note
                    : `the correlation analysis is ${e.analysis.state === 'building'
                        ? `still building (${Math.round(e.analysis.pct ?? 0)}%)`
                        : 'not built for the current pool'}`}. This does not mean nothing correlates
                  with this event.
                </div>
              : <div className="table__empty">No correlated events — nothing shares an entity, session or tight time window with this one.</div>)}
            {e.correlations.map((r) => (
              <div key={r.id} className="table__row corr-grid clickable" role="link" tabIndex={0} onClick={() => nav(`/events/${encodeURIComponent(r.id)}`)} onKeyDown={(k) => { if (k.key === 'Enter') nav(`/events/${encodeURIComponent(r.id)}`); }}>
                <div className="cell-mono corr__ts" style={{ color: sevVar(r.sev) }}>{fmtClock(r.ts)}</div>
                <div className="cell-mono ellipsis corr__msg" title={r.msg}>{r.msg}</div>
                <div className="corr__reason"><span className="tag" title={r.reason}>{r.reason}</span></div>
              </div>
            ))}
          </div>
        </section>
      </div>

      <div className="detail__side">
        <section className="dpanel">
          <div className="dpanel__head">
            <span className="lbl">Detections fired</span>
            <span className="dpanel__meta"><span className="num">{e.detections.length}</span></span>
          </div>
          {e.detections.length === 0
            ? <div className="dpanel__empty">No detection rules matched this event.</div>
            : (
              <div className="detections">
                {e.detections.map((d) => (
                  <div key={d.id} className="detection" style={{ borderLeftColor: sevVar(d.level) }}>
                    <div className="detection__name">{d.name}</div>
                    <div className="detection__meta">{d.id} · {d.level}</div>
                  </div>
                ))}
              </div>
            )}
        </section>
        <section className="dpanel">
          <div className="dpanel__head">
            <span className="lbl">Entities</span>
            <span className="dpanel__meta"><span className="num">{e.entities.length}</span></span>
          </div>
          {/* Two doors, because they answer different questions and the graph could only answer one
              of them badly. `?entity=` alone names a NODE ID (`ip:10.0.0.5`), which a bare entity
              value never matches, and the Graph screen starts with no sources selected — so it
              skipped the request entirely and the analyst landed on an empty canvas. The graph link
              now carries the graph's own filter (`q`) AND this event's source, so something is
              actually drawn; the second chip goes to the events themselves via the one field that
              matches EXACTLY (`entity:"…"`). */}
          {e.entities.length === 0
            ? <div className="dpanel__empty">None extracted.</div>
            : (
              <div className="entity-chips">
                {e.entities.map((t) => (
                  <span key={t} className="entity-chip">
                    <button className="chip chip--mono"
                      onClick={() => nav(`/graph?q=${encodeURIComponent(t)}&sources=${encodeURIComponent(e.sourceId)}&entity=${encodeURIComponent(t)}`)}
                      title={`Show ${t} and its neighbours in the entity graph`}>{t}</button>
                    <button className="chip chip--icon"
                      onClick={() => nav(`/search?q=${encodeURIComponent(`entity:"${t}"`)}`)}
                      title={`Search every event mentioning ${t}`} aria-label={`Search events for ${t}`}>
                      <Icon.Search width={11} height={11} />
                    </button>
                  </span>
                ))}
              </div>
            )}
        </section>
        <section className="dpanel">
          <div className="dpanel__head">
            <span className="lbl">Frequency baseline</span>
          </div>
          {e.baseline
            ? <div className="baseline">{e.baseline}</div>
            : <div className="dpanel__empty">No baseline available for this host / principal yet.</div>}
        </section>
      </div>
    </div>
  );
}
