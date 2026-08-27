/** Indicators found in the case, each linking back to the events and log files it was seen in. */
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import type { Ioc, Scope } from '../api/types';
import { useIocs } from '../hooks/queries';
import { useToast } from '../hooks/useToast';
import { cx, fmtInt, fmtTs } from '../utils/format';
import { Icon } from './icons';
import { EmptyState, ErrorState, Loading, SkeletonRows } from './ui';

function RemoveIoc({ ioc }: { ioc: Ioc }) {
  const qc = useQueryClient();
  const toast = useToast();
  const del = useMutation({
    mutationFn: () => api.deleteIoc(ioc.id),
    onSuccess: () => { toast.info('Indicator removed', ioc.value); void qc.invalidateQueries({ queryKey: ['iocs'] }); },
    onError: (e) => toast.error('Could not remove the indicator', e),
  });
  return (
    <button className="btn btn--sm btn--icon btn--ghost" onClick={() => del.mutate()} disabled={del.isPending}
      title="Remove this indicator" aria-label={`Remove ${ioc.value}`}>
      <Icon.Trash />
    </button>
  );
}

function IocRow({ ioc }: { ioc: Ioc }) {
  const nav = useNavigate();
  const [open, setOpen] = useState(false);
  return (
    <>
      <div
        className={cx('table__row ioc-grid clickable', open && 'selected')}
        role="button"
        tabIndex={0}
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setOpen((v) => !v); } }}
      >
        <div>
          <span className="tag">{ioc.kind}</span>
          {ioc.addedBy === 'ai' && (
            <span className="badge" style={{ marginLeft: 4 }} title="Recorded by the AI assistant during an investigation">AI</span>
          )}
          {ioc.addedBy === 'analyst' && <span className="badge badge--ok" style={{ marginLeft: 4 }} title="Added by hand">manual</span>}
        </div>
        <div className="ioc__id" title={ioc.note || ioc.value}>
          <div className="cell-mono cell-bright ellipsis">{ioc.value}</div>
          {/* WHY it is an indicator, on the row itself. It was only in the expanded detail, so the list
              read as bare values with nothing saying what each had been seen doing — "not much
              reference as to why those iocs were added". One ellipsised line; the detail has the rest. */}
          {ioc.note && <div className="ioc__why ellipsis">{ioc.note}</div>}
        </div>
        <div className="cell-mono num">{fmtInt(ioc.count)}</div>
        <div className="ioc__files ellipsis" title={ioc.files.join(', ')}>
          {ioc.files.slice(0, 2).map((f) => <span key={f} className="tag">{f}</span>)}
          {ioc.files.length > 2 && <span className="tag">+{ioc.files.length - 2}</span>}
        </div>
        <div className="cell-mono cell-dim" style={{ fontSize: 'var(--fs-xs)' }}>{ioc.firstSeen ? fmtTs(ioc.firstSeen) : '—'}</div>
        <div className="ioc__caret"><Icon.Chevron style={{ transform: open ? 'rotate(180deg)' : undefined }} /></div>
      </div>
      {open && (
        <div className="ioc__detail">
          <div className="ioc__detail-head">
            <span className="eyebrow">Seen in</span>
            <span style={{ display: 'flex', gap: 6 }}>
              <button className="btn btn--sm" onClick={() => nav(`/search?q=${encodeURIComponent(ioc.value)}`)}>
                <Icon.Search /> Search every occurrence
              </button>
              {ioc.manual && <RemoveIoc ioc={ioc} />}
            </span>
          </div>
          {ioc.note && <div className="ioc__note">{ioc.note}</div>}
          {ioc.addedBy !== 'extracted' && (
            <div className="field__hint">
              Recorded by {ioc.addedBy === 'ai' ? 'the AI assistant' : 'the analyst'}
              {ioc.addedAt ? ` on ${fmtTs(ioc.addedAt)}` : ''}
              {ioc.citedEventIds.length
                ? ` — cited from ${ioc.citedEventIds.length} event${ioc.citedEventIds.length === 1 ? '' : 's'}, which is what places it on the timeline.`
                : '.'}
            </div>
          )}
          {ioc.hits.length === 0 && (
            <div className="field__hint">Not seen in this case yet — it stays tracked and will match if a matching log is ingested.</div>
          )}
          {ioc.hits.map((h) => (
            <button key={h.eventId} className="ioc__hit" onClick={() => nav(`/events/${encodeURIComponent(h.eventId)}`)}>
              <span className="cell-mono cell-dim">{fmtTs(h.ts)}</span>
              <span className="cell-mono ioc__hit-file ellipsis" title={h.file}>{h.file || '—'}</span>
              <span className="cell-mono cell-dim">{h.eventId}</span>
              <span className="ioc__hit-go">open →</span>
            </button>
          ))}
          {ioc.count > ioc.hits.length && (
            <div className="field__hint" style={{ marginTop: 6 }}>
              Showing {ioc.hits.length} of {fmtInt(ioc.count)} occurrences — use the search above for the rest.
            </div>
          )}
        </div>
      )}
    </>
  );
}

const KINDS = ['ipv4', 'domain', 'url', 'file-path', 'file-hash', 'email', 'user-agent', 'aws-access-key', 'dst-endpoint', 'other'];

/** Add an indicator by hand — it is then looked up across the case so you see where it appears. */
function AddIoc({ onDone }: { onDone: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [kind, setKind] = useState('ipv4');
  const [value, setValue] = useState('');
  const [note, setNote] = useState('');

  const add = useMutation({
    mutationFn: () => api.addIoc({ kind, value: value.trim(), note: note.trim() }),
    onSuccess: (i) => {
      toast.success('Indicator added', i.count ? `found in ${i.count} event${i.count === 1 ? '' : 's'}` : 'no occurrences in this case yet');
      setValue('');
      setNote('');
      void qc.invalidateQueries({ queryKey: ['iocs'] });
      onDone();
    },
    onError: (e) => toast.error('Could not add the indicator', e),
  });

  return (
    <form className="ioc-add" onSubmit={(e) => { e.preventDefault(); if (value.trim()) add.mutate(); }}>
      <div className="field">
        <label className="field__label" htmlFor="ioc-kind">Kind</label>
        <select id="ioc-kind" value={kind} onChange={(e) => setKind(e.target.value)}>
          {KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
        </select>
      </div>
      <div className="field" style={{ flex: 2 }}>
        <label className="field__label" htmlFor="ioc-value">Indicator</label>
        <input id="ioc-value" className="mono" value={value} onChange={(e) => setValue(e.target.value)}
          placeholder="45.83.140.22" autoFocus spellCheck={false} />
      </div>
      <div className="field" style={{ flex: 2 }}>
        <label className="field__label" htmlFor="ioc-note">Note</label>
        <input id="ioc-note" value={note} onChange={(e) => setNote(e.target.value)} placeholder="where it came from (optional)" />
      </div>
      <div className="ioc-add__actions">
        <button type="button" className="btn btn--sm btn--ghost" onClick={onDone}>Cancel</button>
        <button type="submit" className="btn btn--sm btn--accent" disabled={!value.trim() || add.isPending}>
          {add.isPending && <span className="btn__spinner" />}Add
        </button>
      </div>
    </form>
  );
}

/**
 * The "Add indicator" control lives in the section header of the screen that hosts the panel
 * (see CaseDetailScreen), so `adding` is controlled from outside: with an internal header row the
 * panel opened with an otherwise-empty band under the section heading.
 */
export function IocPanel({ scope = 'all', adding = false, onAddingDone }: { scope?: Scope; adding?: boolean; onAddingDone?: () => void }) {
  const q = useIocs(scope);
  const [kind, setKind] = useState<string>('');
  const kinds = useMemo(() => [...new Set((q.data?.iocs ?? []).map((i) => i.kind))].sort(), [q.data]);
  const list = useMemo(() => (q.data?.iocs ?? []).filter((i) => !kind || i.kind === kind), [q.data, kind]);
  const recorded = useMemo(() => list.filter((i) => i.addedBy !== 'extracted'), [list]);
  const extracted = useMemo(() => list.filter((i) => i.addedBy === 'extracted'), [list]);
  const [showExtracted, setShowExtracted] = useState(false);

  if (q.isError) return <ErrorState title="Could not load indicators" error={q.error} onRetry={() => void q.refetch()} />;

  return (
    <div>
      {kinds.length > 1 && (
        <div className="ioc-head">
          <div className="chip-row">
            <span className="chip-row__label">Kind</span>
            <button className={cx('chip', !kind && 'on')} onClick={() => setKind('')} aria-pressed={!kind}>all</button>
            {kinds.map((k) => (
              <button key={k} className={cx('chip', kind === k && 'on')} onClick={() => setKind(k)} aria-pressed={kind === k}>{k}</button>
            ))}
          </div>
        </div>
      )}

      {adding && <AddIoc onDone={() => onAddingDone?.()} />}

      {q.isLoading && <Loading inline label="Extracting indicators…" />}
      {!q.isLoading && !q.data?.iocs.length && (
        <EmptyState inline title="No indicators yet"
          body="Indicators are extracted automatically from events that fired a detection rule — IPs, access keys, paths, user agents and destinations. You can also add your own above; Iris then searches the case for it and links every occurrence." />
      )}

      {/* RECORDED first — what the analyst or the assistant put on the case, each with its reason —
          and the automatically EXTRACTED ones (every IP / path / key the extractor pulls out of the
          case's events) under their own heading, closed by default. Mixed into one table the extracted
          rows outnumbered the curated ones and read as indicators nobody had chosen. */}
      {!!recorded.length && (
        <div className="table">
          <div className="table__head ioc-grid">
            <div>Kind</div><div>Indicator</div><div className="num">Seen</div><div>Log files</div><div>First seen</div><div />
          </div>
          {q.isFetching && !q.data && <SkeletonRows n={4} />}
          {recorded.map((i) => <IocRow key={i.id || `${i.kind}:${i.value}`} ioc={i} />)}
        </div>
      )}
      {!!extracted.length && (
        <div className="ioc-extracted">
          <button className="ioc-extracted__head" onClick={() => setShowExtracted((v) => !v)} aria-expanded={showExtracted}>
            <span className="eyebrow">Extracted automatically</span>
            <span className="ioc-extracted__hint">
              {fmtInt(extracted.length)} value{extracted.length === 1 ? '' : 's'} the extractor pulled out of
              {scope === 'case' ? ' the events on this case' : ' the workspace'} — not curated, no reason attached
            </span>
            <span className="btn btn--sm btn--ghost">{showExtracted ? 'Hide' : 'Show'}</span>
          </button>
          {showExtracted && (
            <div className="table">
              <div className="table__head ioc-grid">
                <div>Kind</div><div>Indicator</div><div className="num">Seen</div><div>Log files</div><div>First seen</div><div />
              </div>
              {extracted.map((i) => <IocRow key={i.id || `${i.kind}:${i.value}`} ioc={i} />)}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
