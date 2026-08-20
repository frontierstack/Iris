/** Shared controls for the case set — the curated events that ARE the case (replaces pins). */
import { useEffect, useRef, useState } from 'react';
import type { Event, Scope } from '../api/types';
import { useAddToCase, useCaseSet, useRemoveFromCase, useUpdateCaseEntry } from '../hooks/queries';
import { useToast } from '../hooks/useToast';
import { cx } from '../utils/format';
import { Icon } from './icons';

/**
 * Everything | Case set switch.
 *
 * "Everything" is every ingested source, whether or not it belongs to a case — analysis never requires
 * one. "Case set" is the curated subset, so it is unavailable until a case exists and has something in
 * it; the title says which of the two reasons applies rather than just greying out.
 */
export function ScopeToggle({ scope, onChange, count, noCase }: { scope: Scope; onChange: (s: Scope) => void; count: number; noCase?: boolean }) {
  const empty = count === 0;
  return (
    <div className="scope" role="group" aria-label="Analysis scope">
      <button className={cx('scope__btn', scope === 'all' && 'on')} onClick={() => onChange('all')} aria-pressed={scope === 'all'}
        title="Every ingested source — no case required">
        Everything
      </button>
      <button
        className={cx('scope__btn', scope === 'case' && 'on')}
        onClick={() => onChange('case')}
        aria-pressed={scope === 'case'}
        disabled={empty}
        title={noCase
          ? 'No case yet — a case is where you curate a subset of these events. Create one on the Cases page.'
          : empty ? 'Add events to the case first — nothing is curated yet'
          : 'Re-run the analysis over only the curated case set'}
      >
        Case set{count > 0 && <span className="scope__count">{count}</span>}
      </button>
    </div>
  );
}

/**
 * Add / remove a single event, with an inline label editor.
 * `compact` renders the icon-only variant used inside dense table rows.
 */
export function AddToCaseButton({ event, compact }: { event: Pick<Event, 'id' | 'msg' | 'inCase' | 'labels'>; compact?: boolean }) {
  const add = useAddToCase();
  const remove = useRemoveFromCase();
  const toast = useToast();
  const [editing, setEditing] = useState(false);
  const inCase = !!event.inCase;
  const busy = add.isPending || remove.isPending;

  const onClick = () => {
    if (inCase) {
      remove.mutate(event.id, {
        onSuccess: () => toast.info('Removed from case', event.msg),
        onError: (e) => toast.error('Could not remove from case', e),
      });
    } else {
      add.mutate({ id: event.id }, {
        onSuccess: () => { toast.success('Added to case', event.msg); if (!compact) setEditing(true); },
        onError: (e) => toast.error('Could not add to case', e),
      });
    }
  };

  if (compact) {
    return (
      <button
        className={cx('incase-btn', inCase && 'on')}
        onClick={(e) => { e.stopPropagation(); onClick(); }}
        disabled={busy}
        aria-pressed={inCase}
        title={inCase ? 'Remove from the case set' : 'Add this event to the case set'}
        aria-label={inCase ? 'Remove from case' : 'Add to case'}
      >
        {inCase ? <Icon.Check /> : <Icon.Plus />}
      </button>
    );
  }

  return (
    <div className="incase">
      <button className={cx('btn btn--sm', inCase && 'btn--accent')} onClick={onClick} disabled={busy} aria-pressed={inCase}>
        {busy ? <span className="btn__spinner" /> : inCase ? <Icon.Check /> : <Icon.Plus />}
        {inCase ? 'In this case' : 'Add to case'}
      </button>
      {inCase && (
        <button className="btn btn--sm btn--ghost" onClick={() => setEditing((v) => !v)} aria-expanded={editing}>
          {event.labels?.length ? `${event.labels.length} label${event.labels.length === 1 ? '' : 's'}` : 'Add labels'}
        </button>
      )}
      {inCase && editing && <LabelEditor eventId={event.id} labels={event.labels ?? []} onDone={() => setEditing(false)} />}
    </div>
  );
}

/** Comma/Enter separated label chips for one case-set entry, with suggestions from labels already in use. */
export function LabelEditor({ eventId, labels, note, onDone }: { eventId: string; labels: string[]; note?: string; onDone?: () => void }) {
  const update = useUpdateCaseEntry();
  const caseSet = useCaseSet();
  const toast = useToast();
  const [draft, setDraft] = useState<string[]>(labels);
  const [text, setText] = useState('');
  const [noteText, setNoteText] = useState(note ?? '');
  const inputRef = useRef<HTMLInputElement>(null);
  useEffect(() => { inputRef.current?.focus(); }, []);

  const known = (caseSet.data?.labels ?? []).filter((l) => !draft.includes(l));
  const commit = (raw: string) => {
    const lab = raw.trim().replace(/,$/, '').trim();
    if (!lab || draft.some((d) => d.toLowerCase() === lab.toLowerCase())) { setText(''); return; }
    setDraft((d) => [...d, lab]);
    setText('');
  };
  const save = () => {
    update.mutate({ id: eventId, labels: draft, note: noteText }, {
      onSuccess: () => { toast.success('Case entry updated'); onDone?.(); },
      onError: (e) => toast.error('Could not update entry', e),
    });
  };

  return (
    <div className="label-editor">
      <div className="label-editor__chips">
        {draft.map((l) => (
          <span key={l} className="tag tag--label">
            {l}
            <button onClick={() => setDraft((d) => d.filter((x) => x !== l))} aria-label={`Remove label ${l}`}>×</button>
          </span>
        ))}
        <input
          ref={inputRef}
          value={text}
          onChange={(e) => { const v = e.target.value; if (v.endsWith(',')) commit(v); else setText(v); }}
          onKeyDown={(e) => {
            if (e.key === 'Enter') { e.preventDefault(); commit(text); }
            if (e.key === 'Backspace' && !text && draft.length) setDraft((d) => d.slice(0, -1));
          }}
          onBlur={() => commit(text)}
          placeholder={draft.length ? 'add another…' : 'e.g. exfil, initial-access'}
          aria-label="Add a label"
        />
      </div>
      {known.length > 0 && (
        <div className="label-editor__known">
          <span className="muted">in use:</span>
          {known.slice(0, 8).map((l) => (
            <button key={l} className="tag tag--ghost" onClick={() => setDraft((d) => [...d, l])}>+ {l}</button>
          ))}
        </div>
      )}
      <textarea
        className="label-editor__note"
        rows={2}
        value={noteText}
        onChange={(e) => setNoteText(e.target.value)}
        placeholder="why this event matters (optional)"
      />
      <div className="label-editor__actions">
        <button className="btn btn--sm btn--ghost" onClick={onDone}>Cancel</button>
        <button className="btn btn--sm btn--accent" onClick={save} disabled={update.isPending}>
          {update.isPending && <span className="btn__spinner" />}Save
        </button>
      </div>
    </div>
  );
}
