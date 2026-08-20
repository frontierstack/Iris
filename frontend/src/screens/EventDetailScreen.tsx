import { Icon } from '../components/icons';
import { useQuery } from '@tanstack/react-query';
import { useNavigate, useParams } from 'react-router-dom';
import { api } from '../api/client';
import { useAiPanel } from '../components/AiPanel';
import { NoteAboutButton } from '../components/CaseNotes';
import { AddToCaseButton } from '../components/CaseSet';
import { ErrorState, Loading, SevTag } from '../components/ui';
import { qk, useCase } from '../hooks/queries';
import { cx, fmtClock, fmtTs, sevVar } from '../utils/format';

/** Where this event sits in its original log file, with a few lines of context. */
function FileLocation({ eventId, raw, file }: { eventId: string; raw: string; file: string }) {
  const loc = useQuery({ queryKey: ['event-location', eventId], queryFn: () => api.eventLocation(eventId), staleTime: 300_000 });
  const d = loc.data;
  return (
    <div>
      <div className="section-head" style={{ marginBottom: 9 }}>
        <div className="eyebrow">Raw line</div>
        <div className="section-hint" style={{ color: 'var(--muted-3)' }}>
          <span className="mono">{file}</span>
          {d?.line != null && (
            <>
              {' · '}
              <b className="mono">line {d.line.toLocaleString()}</b>
              {d.totalLines ? <span className="muted"> of {d.totalLines.toLocaleString()}</span> : null}
              {!d.exact && <span className="badge badge--warn" style={{ marginLeft: 6 }} title={d.reason ?? ''}>approx</span>}
            </>
          )}
          {loc.isLoading && <span className="muted"> · locating…</span>}
          {d && d.line == null && <span className="muted" title={d.reason ?? ''}> · not line-addressable</span>}
        </div>
      </div>
      <div className="raw">{raw || '—'}</div>
      {d?.context?.length ? (
        <div className="filectx">
          <div className="eyebrow filectx__head">In context</div>
          {/* one scroller around every line — scrolling per line gave each its own scrollbar */}
          <div className="filectx__body">
            {d.context.map((l) => (
              <div key={l.n} className={cx('filectx__line', l.current && 'current')}>
                <span className="filectx__n">{l.n}</span>
                <span className="filectx__t">{l.text}</span>
              </div>
            ))}
          </div>
        </div>
      ) : null}
    </div>
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
        <div style={{ marginTop: 12 }}><button className="btn" onClick={() => nav('/search')}>Back to search</button></div>
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
        <div className="panel panel--flush">
          <div className="detail__head">
            <div className="detail__sevbar" style={{ background: color }} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div className="detail__title">{e.msg}</div>
              {/* Facts as labelled chips instead of one dot-separated string: an analyst reading a
                  detail page is looking for ONE of these (which host? which file?), and a run-on line
                  makes every lookup a scan. The timestamp is full and marked UTC, like everywhere else. */}
              <div className="detail__facts">
                <span className="detail__fact"><SevTag sev={e.sev} /></span>
                <span className="detail__fact detail__fact--ts" title="event timestamp (UTC)">{fmtTs(e.ts)} UTC</span>
                <span className="detail__fact"><i>source</i>{e.source}</span>
                <span className="detail__fact detail__fact--file" title={e.file}><i>file</i>{e.file}</span>
                {e.host && <span className="detail__fact"><i>host</i>{e.host}</span>}
                {e.user && <span className="detail__fact"><i>user</i>{e.user}</span>}
                <span className="detail__fact detail__fact--id" title="event id — cite this in notes and indicators"><i>id</i>{e.id}</span>
              </div>
            </div>
            <div className="detail__actions">
              <button className="btn btn--sm" onClick={() => ai.open({ scope: 'event', id: e.id, label: e.msg })}>Ask AI about this event</button>
              <AddToCaseButton event={e} />
              {c.data && <NoteAboutButton caseId={c.data.id} refToAttach={{ kind: 'event', value: e.id, label: e.msg.slice(0, 60) }} />}
            </div>
          </div>
          <div className="fields-grid">
            {fields.length === 0 && <div className="muted" style={{ gridColumn: '1 / -1', fontSize: 'var(--fs-base)' }}>No structured fields were extracted from this line.</div>}
            {fields.map(([k, v]) => (
              <div key={k} className="field-kv">
                <span className="field-kv__k">{k}</span>
                <span className="field-kv__v" title={v}>{v === '' ? '—' : v}</span>
              </div>
            ))}
          </div>
        </div>

        <FileLocation eventId={e.id} raw={e.raw} file={e.file} />

        <div>
          <div className="section-head" style={{ marginBottom: 9 }}>
            <div className="eyebrow">Correlated events <span className="sec__count">{e.correlations.length}</span></div>
            <div className="section-hint" style={{ color: 'var(--muted-3)' }}>why Iris tied each one to this event</div>
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
                <div className="cell-mono" style={{ fontSize: 'var(--fs-sm)', color: sevVar(r.sev) }}>{fmtClock(r.ts)}</div>
                <div className="cell-mono ellipsis" style={{ color: 'var(--text-2)' }} title={r.msg}>{r.msg}</div>
                <div className="corr__reason"><span className="tag" title={r.reason}>{r.reason}</span></div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="detail__side">
        <div className="panel panel--tight">
          <div className="eyebrow">Detections fired <span className="sec__count">{e.detections.length}</span></div>
          <div className="detections">
            {e.detections.length === 0 && <div className="muted" style={{ fontSize: 'var(--fs-base)' }}>No detection rules matched this event.</div>}
            {e.detections.map((d) => (
              <div key={d.id} className="detection" style={{ borderColor: sevVar(d.level) }}>
                <div className="detection__name">{d.name}</div>
                <div className="detection__meta">{d.id} · {d.level.toUpperCase()}</div>
              </div>
            ))}
          </div>
        </div>
        <div className="panel panel--tight">
          <div className="eyebrow">Entities in this event <span className="sec__count">{e.entities.length}</span></div>
          <div className="entity-chips">
            {e.entities.length === 0 && <div className="muted" style={{ fontSize: 'var(--fs-base)' }}>None extracted.</div>}
            {/* Two doors, because they answer different questions and the graph could only answer one
                of them badly. `?entity=` alone names a NODE ID (`ip:10.0.0.5`), which a bare entity
                value never matches, and the Graph screen starts with no sources selected — so it
                skipped the request entirely and the analyst landed on an empty canvas. The graph link
                now carries the graph's own filter (`q`) AND this event's source, so something is
                actually drawn; the second chip goes to the events themselves via the one field that
                matches EXACTLY (`entity:"…"`). */}
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
        </div>
        <div className="panel panel--tight">
          <div className="eyebrow">Frequency baseline</div>
          <div className="baseline">{e.baseline || <span className="muted">No baseline available for this host / principal yet.</span>}</div>
        </div>
      </div>
    </div>
  );
}
