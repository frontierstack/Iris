/**
 * Pull files that are already on disk into the active case, instead of re-uploading them.
 *
 * Two kinds show up here: files uploaded into some OTHER case, and UNATTACHED files staged in the
 * library (caseId ''), which belong to no case at all and survive every case delete. Attaching copies
 * the bytes into the active case either way, so the source stays available to attach again later.
 */
import { useMutation } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import { api } from '../api/client';
import type { LibraryFile } from '../api/types';
import { useCase, useCases, useInvalidateCaseData, useLibrary } from '../hooks/queries';
import { useToast } from '../hooks/useToast';
import { cx, fmtBytes, fmtInt } from '../utils/format';
import { Icon } from './icons';
import { Drawer, EmptyState, Loading } from './ui';

export function AddSources({ caseId }: { caseId?: string } = {}) {
  const [open, setOpen] = useState(false);
  const lib = useLibrary();
  const cases = useCases();
  const activeCase = useCase();
  const activeId = activeCase.data && !activeCase.data.pending ? activeCase.data.id : '';
  const [target, setTarget] = useState(caseId ?? '');
  const invalidate = useInvalidateCaseData();
  const toast = useToast();
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [onlyUnused, setOnlyUnused] = useState(true);
  const [onlyUnattached, setOnlyUnattached] = useState(false);
  // A pending case is an id held in reserve with nothing on disk. Attaching into it would materialise a
  // case the analyst never created — the same phantom "Untitled case" that uploading used to produce.
  // Not a blocker for analysis: a library file is already parsed and searchable. Filing it into a case
  // is what needs a case, and this button says so instead of implying nothing works.
  const noCase = !!activeCase.data?.pending;

  const key = (f: LibraryFile) => `${f.caseId}:${f.fileName}`;
  const rows = useMemo(() => {
    const all = lib.data ?? [];
    let list = onlyUnused ? all.filter((f) => !f.inActiveCase) : all;
    if (onlyUnattached) list = list.filter((f) => !f.caseId);
    // unattached files first: they are the ones deliberately staged for linking
    return [...list].sort((a, b) =>
      Number(!!a.caseId) - Number(!!b.caseId) || a.displayName.localeCompare(b.displayName));
  }, [lib.data, onlyUnused, onlyUnattached]);
  const nUnattached = (lib.data ?? []).filter((f) => !f.caseId).length;
  // staged files whose events are NOT in the workspace pool — invisible to search until they are loaded
  const skippedFiles = (lib.data ?? []).filter((f) => f.skipped);
  const nSkipped = skippedFiles.length;
  const skippedBytes = skippedFiles.reduce((n, f) => n + f.size, 0);

  const attach = useMutation({
    mutationFn: () => {
      const items = (lib.data ?? []).filter((f) => picked.has(key(f))).map((f) => ({ caseId: f.caseId, fileName: f.fileName }));
      // `target` is which case receives them — blank means the active one. Opened from a case screen it
      // is that case; from anywhere else the analyst picks, because "add to a case" with no way to say
      // which case is only usable when you are already standing in the right one.
      return api.attachFromLibrary(items, target);
    },
    onSuccess: (added) => {
      toast.success(`Added ${added.length} source${added.length === 1 ? '' : 's'}`, added.map((s) => s.file).slice(0, 3).join(', '));
      setPicked(new Set());
      setOpen(false);
      invalidate();
    },
    onError: (e) => toast.error('Could not add sources', e),
  });

  const toggle = (f: LibraryFile) =>
    setPicked((s) => {
      const n = new Set(s);
      const k = key(f);
      if (n.has(k)) n.delete(k); else n.add(k);
      return n;
    });

  return (
    <>
      <button className="btn btn--sm" onClick={() => setOpen(true)} disabled={noCase}
        title={noCase
          ? 'Library files are already parsed and searchable — create a case to file them into one'
          : 'File logs already on this server — including everything staged in the library — into this case'}>
        <Icon.Sources /> Add existing sources
      </button>
      <Drawer
        open={open}
        onClose={() => setOpen(false)}
        wide
        title="Add sources to this case"
        sub={<>files already on this server — including {nUnattached} staged without a case · pick what belongs in <b>{cases.data?.find((c) => c.id === (target || activeId))?.name ?? activeCase.data?.name ?? 'the case'}</b></>}
        footer={
          <>
            <button className="btn btn--ghost" onClick={() => setOpen(false)}>Cancel</button>
            <span style={{ flex: 1 }} />
            <button className="btn btn--accent" onClick={() => attach.mutate()} disabled={!picked.size || attach.isPending}>
              {attach.isPending && <span className="btn__spinner" />}
              Add {picked.size || ''} source{picked.size === 1 ? '' : 's'}
            </button>
          </>
        }
      >
        {nSkipped > 0 && (
          <div className="notloaded notloaded--inline">
            <Icon.Warn />
            <span>
              <b>{nSkipped}</b> staged file{nSkipped === 1 ? ' is' : 's are'} not loaded into the workspace
              ({fmtBytes(skippedBytes)}), so search cannot see their events. Each row says why — Sources → “not loaded”
              has the remedy.
            </span>
          </div>
        )}
        {!caseId && (cases.data?.length ?? 0) > 1 && (
          <div className="field" style={{ marginBottom: 12 }}>
            <label className="field__label" htmlFor="add-src-case">Add them to</label>
            <select id="add-src-case" value={target || activeId} onChange={(e) => setTarget(e.target.value)}>
              {(cases.data ?? []).map((c) => (
                <option key={c.id} value={c.id}>{c.name} · {c.id}{c.id === activeId ? ' (active)' : ''}</option>
              ))}
            </select>
            <div className="field__hint">Choosing another case makes it active — Iris keeps one case in memory at a time.</div>
          </div>
        )}
        <div className="chip-row" style={{ marginBottom: 12 }}>
          <button className={cx('chip', onlyUnused && 'on')} onClick={() => setOnlyUnused((v) => !v)} aria-pressed={onlyUnused}>
            hide files already in this case
          </button>
          {nUnattached > 0 && (
            <button className={cx('chip', onlyUnattached && 'on')} onClick={() => setOnlyUnattached((v) => !v)} aria-pressed={onlyUnattached}
              title="Files uploaded to the library without a case">
              unattached only <span className="chip__count">{nUnattached}</span>
            </button>
          )}
          {rows.length > 0 && (
            <button className="btn btn--sm btn--ghost" onClick={() => setPicked(picked.size === rows.length ? new Set() : new Set(rows.map(key)))}>
              {picked.size === rows.length ? 'clear' : 'select all'}
            </button>
          )}
        </div>

        {lib.isLoading && <Loading inline label="Reading the upload library…" />}
        {!lib.isLoading && rows.length === 0 && (
          <EmptyState inline title="Nothing to add"
            body={onlyUnattached ? 'Nothing is staged in the library. Upload with "To library (no case)" on the Sources page.'
              : onlyUnused ? 'Every uploaded file is already in this case. Untick the filter to see them all.'
              : 'No files have been uploaded on this server yet.'} />
        )}

        <div className="library">
          {rows.map((f) => {
            const k = key(f);
            const on = picked.has(k);
            return (
              <label key={k} className={cx('library__row', on && 'on', f.inActiveCase && 'library__row--used')}>
                <input type="checkbox" checked={on} onChange={() => toggle(f)} disabled={f.inActiveCase} />
                <span className="library__name ellipsis" title={f.sample || f.displayName}>
                  {f.displayName}
                  {/* Detected at stage time (a bounded sniff, no parsing) so a staged file is not an
                      opaque blob before it is linked — see docs/API_CONTRACT.md → Upload library. */}
                  {f.parser && (
                    <span className="muted"> · {f.parser}{f.lines ? ` · ${f.linesEstimated ? '~' : ''}${fmtInt(f.lines)} lines` : ''}</span>
                  )}
                </span>
                <span className="cell-mono cell-dim num">{fmtBytes(f.size)}</span>
                <span className="library__origin">
                  {/* Not in the pool = not searchable. Which problem it is decides the fix, so the badge
                      says which one rather than a single vague "skipped". */}
                  {f.skipped && (
                    <span className={cx('badge', f.skipReason === 'parse-error' ? 'badge--bad' : 'badge--warn')}
                      title={f.skipDetail || 'This file is not in the workspace pool, so search cannot see its events'}>
                      {f.skipReason === 'budget' ? 'not loaded · over budget'
                        : f.skipReason === 'parse-error' ? 'not loaded · parse error'
                        : f.skipReason === 'unreadable' ? 'not loaded · unreadable'
                        : 'not loaded'}
                    </span>
                  )}
                  {f.state === 'MAP' && <span className="badge badge--warn" title="Unrecognised layout — you will be asked for a field mapping after attaching">needs mapping</span>}
                  {f.caseId ? (
                    <>
                      <span className="tag">{f.caseId}</span>
                      {/* a file on disk that its own case.json no longer lists — still recoverable from here */}
                      {!f.attached && <span className="badge badge--warn" title="Uploaded but not registered as a source of that case">orphaned</span>}
                    </>
                  ) : (
                    <span className="badge" title={f.uploadedAt ? `Uploaded ${f.uploadedAt}` : 'In the library, not tied to any case'}>
                      {f.uploadedAt ? f.uploadedAt.replace('T', ' ').replace('Z', '') : 'library'}
                    </span>
                  )}
                  {f.inActiveCase && <span className="badge badge--ok">in this case</span>}
                </span>
              </label>
            );
          })}
        </div>
      </Drawer>
    </>
  );
}
