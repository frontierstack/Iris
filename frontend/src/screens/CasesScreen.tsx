import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import type { CaseSummary, TrashEntry } from '../api/types';
import { Icon } from '../components/icons';
import { ConfirmDialog, EmptyState, ErrorState, SectionHead, SkeletonRows } from '../components/ui';
import { qk, useCases } from '../hooks/queries';
import { useToast } from '../hooks/useToast';
import { cx, fmtBytes, fmtCompact, fmtRelative, fmtTs } from '../utils/format';

interface EditState { id: string; name: string; analyst: string }

/** How the list is ordered. "Active first" is the default because the active case is the one every
 *  other screen is operating on — burying it under an alphabetical sort makes the page lie about
 *  where you are. */
type SortKey = 'recent' | 'name' | 'events' | 'size';
const SORTS: { id: SortKey; label: string }[] = [
  { id: 'recent', label: 'Recently updated' },
  { id: 'name', label: 'Name' },
  { id: 'events', label: 'Events' },
  { id: 'size', label: 'Size on disk' },
];

/**
 * What deleting this case actually takes away.
 *
 * It used to print four fixed rows — source files, parsed events, case-set events, bytes on disk — and
 * in a case-optional workspace those are all legitimately 0 for a case whose evidence stayed in the
 * library. The analyst was shown "0 … 0 … 0 … 0 B" for a case holding four notes and a set of
 * indicators: a confirmation dialog saying, wrongly, that there is nothing to lose. So it counts
 * everything a case holds, prints only what is actually there, and when a case really is empty it says
 * that in words rather than as a column of zeros.
 */
function trashContents(t: TrashEntry): string {
  const parts: string[] = [];
  if (t.events) parts.push(`${fmtCompact(t.events)} events`);
  if (t.sources) parts.push(`${t.sources} file${t.sources === 1 ? '' : 's'}`);
  if (t.caseSet) parts.push(`${t.caseSet} on timeline`);
  if (t.noteCount) parts.push(`${t.noteCount} note${t.noteCount === 1 ? '' : 's'}`);
  if (t.iocCount) parts.push(`${t.iocCount} indicator${t.iocCount === 1 ? '' : 's'}`);
  if (t.sizeBytes) parts.push(fmtBytes(t.sizeBytes));
  return parts.join(' · ') || 'empty case';
}

function CaseContents({ cs }: { cs: CaseSummary | null }) {
  if (!cs) return null;
  const rows: Array<{ n: string; label: string }> = [];
  const add = (n: number, one: string, many: string) => {
    if (n > 0) rows.push({ n: fmtCompact(n), label: n === 1 ? one : many });
  };
  add(cs.sources, 'uploaded source file', 'uploaded source files');
  add(cs.events, 'parsed event', 'parsed events');
  add(cs.caseSet, 'event on the case timeline', 'events on the case timeline');
  add(cs.noteCount, 'case note', 'case notes');
  add(cs.iocCount, 'indicator', 'indicators');
  add(cs.graphLinkCount, 'graph link', 'graph links');
  if (cs.sizeBytes > 0) rows.push({ n: fmtBytes(cs.sizeBytes), label: 'of uploads on disk' });

  if (!rows.length) {
    return (
      <div className="case-del__list case-del__list--empty">
        This case is empty — no files, no timeline entries, no notes and no indicators.
      </div>
    );
  }
  return (
    <ul className="case-del__list">
      {rows.map((r) => (
        <li key={r.label} className="case-del__row">
          <span className="case-del__n">{r.n}</span>
          <span className="case-del__l">{r.label}</span>
        </li>
      ))}
    </ul>
  );
}

export function CasesScreen() {
  const cases = useCases();
  const qc = useQueryClient();
  const nav = useNavigate();
  const toast = useToast();
  const [showNew, setShowNew] = useState(false);
  const [newName, setNewName] = useState('');
  const [newAnalyst, setNewAnalyst] = useState('');
  const [editing, setEditing] = useState<EditState | null>(null);
  const [toDelete, setToDelete] = useState<CaseSummary | null>(null);
  const [showTrash, setShowTrash] = useState(false);
  const [filter, setFilter] = useState('');
  const [sort, setSort] = useState<SortKey>('recent');

  // Deleting moves a case aside rather than destroying it, so recently deleted cases are recoverable.
  const trash = useQuery({ queryKey: ['case-trash'], queryFn: api.caseTrash });
  const restore = useMutation({
    mutationFn: (entry: string) => api.restoreTrashedCase(entry),
    onSuccess: (cs) => {
      toast.success('Case restored', `${cs.name} is back with its ${cs.sources} source${cs.sources === 1 ? '' : 's'}`);
      invalidateAll();
    },
    onError: (e) => toast.error('Could not restore case', e),
  });

  const invalidateAll = () => void qc.invalidateQueries();

  const create = useMutation({
    mutationFn: () => api.createCase({ name: newName.trim(), analyst: newAnalyst.trim() || undefined }),
    onSuccess: (cs) => {
      toast.success('Case created', `${cs.name} is now the active case`);
      setShowNew(false);
      setNewName('');
      setNewAnalyst('');
      invalidateAll();
      nav('/ingest');
    },
    onError: (e) => toast.error('Could not create case', e),
  });
  const activate = useMutation({
    mutationFn: (id: string) => api.activateCase(id),
    onSuccess: (c) => { toast.success('Case activated', c.name); invalidateAll(); },
    onError: (e) => toast.error('Could not activate case', e),
  });
  const rename = useMutation({
    mutationFn: (v: EditState) => api.patchCaseById(v.id, { name: v.name.trim(), analyst: v.analyst.trim() }),
    onSuccess: () => {
      setEditing(null);
      void qc.invalidateQueries({ queryKey: qk.cases });
      void qc.invalidateQueries({ queryKey: qk.case });
      void qc.invalidateQueries({ queryKey: qk.report });
    },
    onError: (e) => toast.error('Could not update case', e),
  });
  const del = useMutation({
    mutationFn: (id: string) => api.deleteCase(id),
    onSuccess: () => {
      toast.success('Case deleted', 'recoverable from "Recently deleted"');
      closeDelete();
      setShowTrash(true);  // the way back is visible immediately, not something to go hunting for
      invalidateAll();
    },
    onError: (e) => toast.error('Could not delete case', e),
  });

  const all = cases.data ?? [];
  const rows = useMemo(() => {
    const q = filter.trim().toLowerCase();
    const hit = (c: CaseSummary) =>
      !q || c.name.toLowerCase().includes(q) || c.id.toLowerCase().includes(q) || c.analyst.toLowerCase().includes(q);
    const by: Record<SortKey, (a: CaseSummary, b: CaseSummary) => number> = {
      recent: (a, b) => b.updatedAt.localeCompare(a.updatedAt),
      name: (a, b) => a.name.localeCompare(b.name),
      events: (a, b) => b.events - a.events,
      size: (a, b) => b.sizeBytes - a.sizeBytes,
    };
    // the active case leads whatever the sort — it is the one the rest of the app is working on
    return all.filter(hit).sort((a, b) => Number(b.active) - Number(a.active) || by[sort](a, b));
  }, [all, filter, sort]);

  const editKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && editing && editing.name.trim()) rename.mutate(editing);
    if (e.key === 'Escape') setEditing(null);
  };

  const openDelete = (cs: CaseSummary) => setToDelete(cs);
  const closeDelete = () => setToDelete(null);

  const open = (id: string) => nav(`/cases/${encodeURIComponent(id)}`);

  return (
    <div className="page cases">
      <SectionHead
        eyebrow="Cases"
        title="Investigations on disk"
        hint="one case is active at a time — every screen operates on it"
        actions={
          <>
            {(trash.data?.length ?? 0) > 0 && (
              <button className="btn btn--sm btn--ghost" onClick={() => setShowTrash((v) => !v)} aria-expanded={showTrash}
                title="Cases you deleted recently — still restorable">
                <Icon.Trash /> Recently deleted <span className="chip__count">{trash.data!.length}</span>
              </button>
            )}
            <button className="btn btn--accent btn--sm" onClick={() => setShowNew((v) => !v)} aria-expanded={showNew}>
              <Icon.Plus /> New case
            </button>
          </>
        }
      />

      {/* Finding a case among two dozen was a scroll. Search matches name, id or analyst; the sort is
          for the questions the list is actually asked ("which is biggest", "what did I touch last"). */}
      {all.length > 3 && (
        <div className="cases__toolbar">
          <div className="cases__search">
            <Icon.Search className="cases__search-icon" aria-hidden />
            <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter by name, id or analyst"
              aria-label="Filter cases" spellCheck={false} />
            {filter && (
              <button className="cases__search-x" onClick={() => setFilter('')} aria-label="Clear filter">×</button>
            )}
          </div>
          <div className="cases__sort">
            <label className="field__label" htmlFor="cases-sort">Sort</label>
            <select id="cases-sort" value={sort} onChange={(e) => setSort(e.target.value as SortKey)}>
              {SORTS.map((o) => <option key={o.id} value={o.id}>{o.label}</option>)}
            </select>
          </div>
          <span className="cases__count">{rows.length} of {all.length}</span>
        </div>
      )}

      {showTrash && (trash.data?.length ?? 0) > 0 && (
        <div className="cases__trash">
          <div className="cases__trash-head">
            <span className="eyebrow">Recently deleted</span>
            <span className="muted" style={{ fontSize: 'var(--fs-xs)' }}>
              the {trash.data!.length} most recent deletes are kept with their uploads — restoring re-parses them
            </span>
          </div>
          {trash.data!.map((t) => (
            <div key={t.entry} className="cases__trash-row">
              <span className="cell-bright ellipsis" title={t.name}>{t.name}</span>
              <span className="cell-mono cell-dim">{t.caseId}</span>
              {/* what would come BACK on a restore. A curation-only case has no uploads and no events
                  of its own, and three zeros said nothing about the investigation inside it. */}
              <span className="cell-mono cell-dim">{trashContents(t)}</span>
              <button className="btn btn--sm" onClick={() => restore.mutate(t.entry)} disabled={restore.isPending}>
                {restore.isPending && restore.variables === t.entry && <span className="btn__spinner" />}Restore
              </button>
            </div>
          ))}
        </div>
      )}

      {showNew && (
        <form className="cases__new" onSubmit={(e) => { e.preventDefault(); if (newName.trim()) create.mutate(); }}>
          <div className="field" style={{ flex: 2 }}>
            <label className="field__label" htmlFor="case-name">Case name</label>
            <input id="case-name" value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="e.g. Suspected credential abuse" autoFocus required />
          </div>
          <div className="field" style={{ flex: 1 }}>
            <label className="field__label" htmlFor="case-analyst">Analyst</label>
            <input id="case-analyst" value={newAnalyst} onChange={(e) => setNewAnalyst(e.target.value)} placeholder="optional" />
          </div>
          <div className="cases__new-actions">
            <button type="button" className="btn btn--sm btn--ghost" onClick={() => setShowNew(false)}>Cancel</button>
            <button type="submit" className="btn btn--sm btn--accent" disabled={!newName.trim() || create.isPending}>
              {create.isPending && <span className="btn__spinner" />}Create &amp; activate
            </button>
          </div>
        </form>
      )}

      {cases.isError ? (
        <ErrorState title="Could not load cases" error={cases.error} onRetry={() => void cases.refetch()} />
      ) : cases.isLoading ? (
        <div style={{ marginTop: 14 }}><SkeletonRows n={4} /></div>
      ) : rows.length === 0 ? (
        <div style={{ marginTop: 14 }}>
          {all.length ? (
            <EmptyState
              title="No case matches that"
              body={<>Nothing in {all.length} case{all.length === 1 ? '' : 's'} matches “{filter}”.</>}
              actions={<button className="btn btn--sm" onClick={() => setFilter('')}>Clear filter</button>}
            />
          ) : (
            <EmptyState
              title="No cases yet"
              body="A case is optional: everything you ingest is already searchable, graphed and correlated. Create one when an investigation needs a timeline, notes and indicators kept together."
              actions={<button className="btn btn--sm btn--accent" onClick={() => setShowNew(true)}><Icon.Plus /> New case</button>}
            />
          )}
        </div>
      ) : (
        <div className={cx('cases__list', rows.length === 1 && 'cases__list--single')}>
          {rows.map((cs) => {
            const isEdit = editing !== null && editing.id === cs.id;
            return (
              <div key={cs.id}
                className={cx('case-card', cs.active && 'case-card--active', isEdit && 'case-card--editing')}
                role={isEdit ? undefined : 'link'}
                tabIndex={isEdit ? undefined : 0}
                onClick={() => { if (!isEdit) open(cs.id); }}
                onKeyDown={(k) => { if (!isEdit && (k.key === 'Enter' || k.key === ' ')) { k.preventDefault(); open(cs.id); } }}
                title={isEdit ? undefined : `Open ${cs.name}`}>

                <div className="case-card__head">
                  {isEdit ? (
                    <div className="case-card__edit" onClick={(e) => e.stopPropagation()}>
                      <input value={editing.name} onChange={(e) => setEditing({ ...editing, name: e.target.value })} aria-label="Case name" placeholder="Case name" autoFocus onKeyDown={editKey} />
                      <input value={editing.analyst} onChange={(e) => setEditing({ ...editing, analyst: e.target.value })} aria-label="Analyst" placeholder="Analyst" onKeyDown={editKey} />
                    </div>
                  ) : (
                    <div className="case-card__ident">
                      <div className="case-card__title">
                        <span className="case-card__name" title={cs.name}>{cs.name}</span>
                        {cs.active && <span className="badge badge--ok">Active</span>}
                      </div>
                      <div className="case-card__uid mono">
                        {cs.id}
                        <span className="case-card__sep">·</span>
                        {cs.analyst || 'unassigned'}
                      </div>
                    </div>
                  )}
                </div>

                {/* Three numbers as chips rather than three big stat blocks: on a card the size of a
                    business card, the case NAME is the headline and the counts are supporting detail. */}
                <div className="case-card__chips">
                  <span className="case-chip" title={`${cs.events.toLocaleString('en-US')} parsed events`}>
                    <b>{fmtCompact(cs.events)}</b> events
                  </span>
                  <span className="case-chip" title={`${cs.sources} file${cs.sources === 1 ? '' : 's'} in scope`}>
                    <b>{cs.sources}</b> source{cs.sources === 1 ? '' : 's'}
                  </span>
                  <span className="case-chip" title="events curated onto the case timeline">
                    <b>{cs.caseSet}</b> on timeline
                  </span>
                  <span className="case-chip case-chip--quiet">{fmtBytes(cs.sizeBytes)}</span>
                </div>

                <div className="case-card__meta">
                  <span title={`created ${fmtTs(cs.createdAt)} UTC`}>Created <b>{fmtTs(cs.createdAt)} UTC</b></span>
                  <span className="case-card__sep">·</span>
                  <span title={`updated ${fmtTs(cs.updatedAt)} UTC`}>Updated <b>{fmtRelative(cs.updatedAt)}</b></span>
                </div>

                <div className="case-card__actions" onClick={(e) => e.stopPropagation()}>
                  {isEdit ? (
                    <>
                      <button className="btn btn--sm btn--accent" onClick={() => rename.mutate(editing)} disabled={rename.isPending || !editing.name.trim()}>
                        {rename.isPending && <span className="btn__spinner" />}Save
                      </button>
                      <button className="btn btn--sm btn--ghost" onClick={() => setEditing(null)}>Cancel</button>
                    </>
                  ) : (
                    <>
                      <button className="btn btn--sm" onClick={() => open(cs.id)}>Open</button>
                      {!cs.active && (
                        <button className="btn btn--sm btn--ghost" onClick={() => activate.mutate(cs.id)} disabled={activate.isPending} title="Load this case into the workbench">
                          {activate.isPending && activate.variables === cs.id && <span className="btn__spinner" />}Activate
                        </button>
                      )}
                      <button className="btn btn--sm btn--ghost" onClick={() => setEditing({ id: cs.id, name: cs.name, analyst: cs.analyst })} title="Rename">Rename</button>
                      <span className="case-card__spacer" />
                      <button className="btn btn--sm btn--icon btn--ghost" onClick={() => openDelete(cs)} title="Delete case" aria-label={`Delete ${cs.name}`}><Icon.Trash /></button>
                    </>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      <ConfirmDialog
        open={toDelete !== null}
        title="Delete case"
        danger
        confirmLabel="Delete case"
        busy={del.isPending}
        text={
          <>
            Deleting <b>{toDelete?.name}</b> removes it and everything below from the case list.
            {toDelete?.active ? ' It is the active case — the most recent remaining case will be activated.' : ''}
            {' '}It is moved to <b>Recently deleted</b>, where the last few deletes are kept with their uploads and can
            be restored. Older ones are discarded for good as new deletes come in.
          </>
        }
        onConfirm={() => { if (toDelete) del.mutate(toDelete.id); }}
        onCancel={closeDelete}
      >
        <CaseContents cs={toDelete} />
      </ConfirmDialog>
    </div>
  );
}
