/**
 * Edit or create a saved prompt without leaving the AI panel — opened from the prompt picker's menu
 * (an edit control on every saved row, "New prompt" in its footer). Settings → System prompts stays
 * the full manager (default, the built-in prompt, view effective); this is the quick path: the
 * analyst is mid-investigation, notices the instructions are wrong, fixes them, and runs.
 *
 * Same API calls as the Settings screen (`aiCreateSystemPrompt` / `aiUpdateSystemPrompt` /
 * `aiDeleteSystemPrompt`) and the same query key, so the two never disagree about what is saved.
 */
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { api } from '../api/client';
import type { SystemPrompt } from '../api/types';
import { qk } from '../hooks/queries';
import { useToast } from '../hooks/useToast';
import { cx } from '../utils/format';

export interface PromptEditorDialogProps {
  /** a saved prompt to edit, or 'new' */
  target: SystemPrompt | 'new';
  onClose: () => void;
  /** called with the saved row (so the picker can select what was just created or edited) */
  onSaved?: (row: SystemPrompt) => void;
  /** called after a delete, with the id that went */
  onDeleted?: (id: string) => void;
}

export function PromptEditorDialog({ target, onClose, onSaved, onDeleted }: PromptEditorDialogProps) {
  const qc = useQueryClient();
  const toast = useToast();
  const isNew = target === 'new';
  const [name, setName] = useState(isNew ? '' : target.name);
  const [text, setText] = useState(isNew ? '' : target.text);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const invalidate = () => { void qc.invalidateQueries({ queryKey: qk.aiSystemPrompts }); };

  const save = useMutation({
    mutationFn: () => isNew
      ? api.aiCreateSystemPrompt({ name: name.trim(), text })
      : api.aiUpdateSystemPrompt(target.id, { name: name.trim(), text }),
    onSuccess: (row) => { toast.success(isNew ? 'Prompt saved' : 'Prompt updated', row.name); invalidate(); onSaved?.(row); onClose(); },
    onError: (e) => toast.error('Could not save the prompt', e),
  });
  const del = useMutation({
    mutationFn: () => api.aiDeleteSystemPrompt((target as SystemPrompt).id),
    onSuccess: (r) => {
      toast.success('Prompt deleted', r.defaultReset ? 'It was the default — the assistant is back on the built-in prompt alone' : (target as SystemPrompt).name);
      invalidate();
      if (r.defaultReset) void qc.invalidateQueries({ queryKey: qk.settings });
      onDeleted?.(r.id);
      onClose();
    },
    onError: (e) => toast.error('Could not delete the prompt', e),
  });

  const busy = save.isPending || del.isPending;
  const dirty = isNew ? (!!name.trim() || !!text.trim()) : (name !== target.name || text !== target.text);
  const canSave = !!name.trim() && !!text.trim() && dirty && !busy;

  // Escape closes (the picker's own Escape handler is gone by now — the menu closed to open this),
  // Ctrl/Cmd+Enter saves: a prompt editor is a text box first, so Enter alone must insert a newline.
  useEffect(() => {
    const on = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { e.stopPropagation(); if (confirmDelete) setConfirmDelete(false); else onClose(); }
      if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && canSave) { e.preventDefault(); save.mutate(); }
    };
    window.addEventListener('keydown', on, true);
    return () => window.removeEventListener('keydown', on, true);
  }, [onClose, canSave, save, confirmDelete]);

  return (
    <div className="modal" role="dialog" aria-modal="true" aria-label={isNew ? 'New prompt' : `Edit prompt ${target.name}`}>
      <div className="overlay" onClick={busy ? undefined : onClose} />
      <div className="modal__box modal__box--wide pedit">
        <div className="modal__body">
          <div className="modal__title">{isNew ? 'New prompt' : 'Edit prompt'}</div>
          <div className="modal__text">Additional instructions for a kind of investigation. Always added after the built-in prompt — it cannot switch off the evidence rules, and cited event ids still have to be real.</div>
          <div className="pedit__form">
            <div className="field">
              <label className="field__label" htmlFor="pedit-name">Name</label>
              <input id="pedit-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Phishing triage" maxLength={120} spellCheck={false} autoFocus={isNew} />
            </div>
            <div className="field">
              <label className="field__label" htmlFor="pedit-text">Instructions</label>
              <textarea id="pedit-text" className="pedit__text" value={text} onChange={(e) => setText(e.target.value)} rows={10} spellCheck={false} autoFocus={!isNew}
                placeholder='e.g. "For a phishing case always establish the sender, the first click, and whether credentials were used afterwards. Every note ends with a confidence rating."' />
              <div className="field__hint">{text.length.toLocaleString()} / 40,000 characters · Ctrl+Enter saves</div>
            </div>
          </div>
          {confirmDelete && !isNew && (
            <div className="pedit__confirm" role="alert">
              <span>Delete <b>{target.name}</b>? Conversations already run on it are unaffected.</span>
              <button className="btn btn--danger btn--sm" onClick={() => del.mutate()} disabled={busy}>{del.isPending && <span className="btn__spinner" />}Delete</button>
              <button className="btn btn--sm btn--ghost" onClick={() => setConfirmDelete(false)} disabled={busy}>Keep</button>
            </div>
          )}
        </div>
        <div className={cx('modal__foot', 'pedit__foot')}>
          {!isNew && !confirmDelete && (
            <button className="btn btn--ghost pedit__delete" onClick={() => setConfirmDelete(true)} disabled={busy}>Delete…</button>
          )}
          <span className="pedit__spacer" />
          <button className="btn" onClick={onClose} disabled={busy}>Cancel</button>
          <button className="btn btn--primary" onClick={() => save.mutate()} disabled={!canSave}>
            {save.isPending && <span className="btn__spinner" />}{isNew ? 'Save prompt' : 'Save changes'}
          </button>
        </div>
      </div>
    </div>
  );
}
