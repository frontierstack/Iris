/** Add or remove an entire log file's events from the case set — the + on a Sources row. */
import { useMemo, useState } from 'react';
import type { Source } from '../api/types';
import { useAddSourceToCase, useCaseSet, useRemoveSourceFromCase } from '../hooks/queries';
import { useToast } from '../hooks/useToast';
import { cx, fmtInt } from '../utils/format';
import { Icon } from './icons';
import { ConfirmDialog } from './ui';

/** Adding a whole file can be thousands of events, so anything sizeable asks first. */
const CONFIRM_ABOVE = 500;

export function SourceCaseToggle({ source }: { source: Source }) {
  const caseSet = useCaseSet();
  const add = useAddSourceToCase();
  const remove = useRemoveSourceFromCase();
  const toast = useToast();
  const [confirm, setConfirm] = useState(false);

  // how many of this file's events are already curated (labels carry the file name)
  const inCase = useMemo(
    () => (caseSet.data?.events ?? []).filter((e) => e.sourceId === source.id).length,
    [caseSet.data, source.id],
  );
  const all = inCase > 0 && inCase >= source.events;
  const busy = add.isPending || remove.isPending;

  const doAdd = () =>
    add.mutate({ id: source.id }, {
      onSuccess: (r) => toast.success(`Added ${fmtInt(r.added)} event${r.added === 1 ? '' : 's'} to the case`,
        r.truncated ? `${source.file} — capped at ${fmtInt(r.added)} of ${fmtInt(r.total)}` : source.file),
      onError: (e) => toast.error('Could not add the log to the case', e),
    });

  const onClick = () => {
    if (all) {
      remove.mutate(source.id, {
        onSuccess: (r) => toast.info(`Removed ${fmtInt(r.removed)} event${r.removed === 1 ? '' : 's'} from the case`, source.file),
        onError: (e) => toast.error('Could not remove the log from the case', e),
      });
    } else if (source.events > CONFIRM_ABOVE) {
      setConfirm(true);
    } else {
      doAdd();
    }
  };

  const label = all ? 'Remove this log from the case set' : `Add all ${fmtInt(source.events)} events of this log to the case set`;
  return (
    <>
      <button
        className={cx('incase-btn', (all || inCase > 0) && 'on')}
        onClick={onClick}
        disabled={busy || source.state === 'PARSING' || source.events === 0}
        aria-pressed={all}
        title={inCase > 0 && !all ? `${fmtInt(inCase)} of ${fmtInt(source.events)} already in the case` : label}
        aria-label={label}
      >
        {busy ? <span className="btn__spinner" /> : all ? <Icon.Check /> : <Icon.Plus />}
      </button>
      <ConfirmDialog
        open={confirm}
        title="Add this whole log to the case?"
        confirmLabel={`Add ${fmtInt(source.events)} events`}
        busy={add.isPending}
        text={
          <>
            <b>{source.file}</b> has {fmtInt(source.events)} events. Adding all of them makes the case set large,
            which is usually the opposite of curating it — Timeline, the entity graph and the report can all be scoped
            to the case set, and that only helps when the set is selective.
            <br /><br />
            You can still narrow it afterwards, or add individual events from Search instead.
          </>
        }
        onConfirm={() => { setConfirm(false); doAdd(); }}
        onCancel={() => setConfirm(false)}
      />
    </>
  );
}
