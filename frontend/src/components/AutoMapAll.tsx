/** Run the AI field mapper over every source still waiting on a mapping, in one go. */
import { useMutation } from '@tanstack/react-query';
import { useState } from 'react';
import { api } from '../api/client';
import type { AutoMapResponse, AutoMapResult } from '../api/types';
import { useInvalidateCaseData, usePendingMappings, useSettings } from '../hooks/queries';
import { useToast } from '../hooks/useToast';
import { cx, fmtInt } from '../utils/format';
import { Icon } from './icons';
import { Drawer } from './ui';

const STATUS_BADGE: Record<AutoMapResult['status'], string> = {
  applied: 'badge--ok',
  suggested: '',
  skipped: 'badge--warn',
  failed: 'badge--bad',
};

export function AutoMapAll() {
  const pending = usePendingMappings();
  const settings = useSettings();
  const invalidate = useInvalidateCaseData();
  const toast = useToast();
  const [result, setResult] = useState<AutoMapResponse | null>(null);

  const n = pending.data?.total ?? 0;
  const aiOff = settings.data ? settings.data.ai.provider === 'none' : false;

  const run = useMutation({
    mutationFn: () => api.autoMapAll({ apply: true }),
    onSuccess: (r) => {
      setResult(r);
      invalidate();
      if (r.applied) toast.success(`Mapped ${r.applied} source${r.applied === 1 ? '' : 's'}`, r.skipped || r.failed ? `${r.skipped} skipped · ${r.failed} failed` : undefined);
      else toast.info('Nothing applied', 'No source met the confidence threshold — open one to map it by hand.');
    },
    onError: (e) => toast.error('Auto-mapping failed', e),
  });

  if (n === 0) return null;

  return (
    <>
      <button
        className="btn btn--accent btn--sm"
        onClick={() => run.mutate()}
        disabled={run.isPending}
        // The count is deliberately NOT in the label. It read as a contradiction next to "343 need
        // review": those two numbers answer different questions, and the button's own number is the
        // narrower one — only a delimited file has anonymous COLUMNS to name. Remapping the 340 JSONL
        // sources as delimited would rewrite files that parsed correctly and name their own fields.
        title={aiOff
          ? `AI is disabled — a heuristic column-role guess will be used for the ${n} file${n === 1 ? '' : 's'} that need one`
          : `Name the columns of every file waiting for a field mapping (${n} right now). Files that name their own fields — JSON, syslog, EVTX — are not touched.`}
      >
        {run.isPending ? <span className="btn__spinner" /> : <Icon.Sparkle />}
        {run.isPending ? 'Mapping…' : 'Map all with AI'}
      </button>

      <Drawer
        open={!!result}
        onClose={() => setResult(null)}
        wide
        title="Auto-mapping results"
        sub={result ? `${result.applied} applied · ${result.skipped} skipped · ${result.failed} failed` : ''}
        footer={<><span style={{ flex: 1 }} /><button className="btn btn--accent" onClick={() => setResult(null)}>Done</button></>}
      >
        <div className="automap">
          {result?.results.map((r) => (
            <div key={r.id} className="automap__row">
              <div className="automap__head">
                <span className="cell-mono cell-bright ellipsis" title={r.file}>{r.file}</span>
                <span className={cx('badge', STATUS_BADGE[r.status])}>{r.status}</span>
                {r.source && <span className="badge">{r.source}</span>}
                {r.confidence !== undefined && <span className="badge">{Math.round(r.confidence * 100)}%</span>}
                {r.status === 'applied' && r.events !== undefined && (
                  <span className="muted mono" style={{ fontSize: 'var(--fs-xs)' }}>{fmtInt(r.events)} events · {r.newState}</span>
                )}
              </div>
              {r.fields?.length ? (
                <div className="automap__fields">
                  {r.fields.map((f, i) => <span key={`${f}:${i}`} className="tag">{f}</span>)}
                </div>
              ) : null}
              {r.rationale && <div className="automap__why">{r.rationale}</div>}
              {(r.reason || r.error) && <div className="automap__why" style={{ color: 'var(--bad)' }}>{r.reason || r.error}</div>}
            </div>
          ))}
        </div>
      </Drawer>
    </>
  );
}
