/**
 * The prompt picker in the AI composer — a chip that opens a menu, the way a model picker does in a
 * modern chat UI, instead of a native <select> that takes the OS's styling and cannot show a
 * description per row.
 *
 * The model is deliberately simple for the analyst: the rows are "Built-in prompt only" plus every
 * saved prompt, ONE of them is checked, and that is what the next run uses. Underneath, `value` is
 * `null` (follow the default chosen in Settings), `''` (built-in only) or a prompt id — choosing the
 * row that IS the current default stores `null`, so a later change of the default in Settings is
 * followed rather than silently pinned.
 */
import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import type { SystemPrompt } from '../api/types';
import { cx } from '../utils/format';
import { Icon } from './icons';

export interface PromptPickerProps {
  prompts: SystemPrompt[];
  /** `settings.ai.systemPromptId` — '' means the built-in prompt alone is the default */
  defaultId: string;
  /** null = follow the default; '' = built-in only; otherwise a prompt id */
  value: string | null;
  onChange: (v: string | null) => void;
  disabled?: boolean;
  builtinEdited?: boolean;
  /** called when the analyst navigates to Settings from the menu (the panel closes itself) */
  onNavigate?: () => void;
}

const BUILTIN = '';

function firstLine(text: string, max = 88): string {
  const line = text.replace(/\s+/g, ' ').trim();
  return line.length > max ? line.slice(0, max - 1).trimEnd() + '…' : line;
}

export function PromptPicker({ prompts, defaultId, value, onChange, disabled, builtinEdited, onNavigate }: PromptPickerProps) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const btnRef = useRef<HTMLButtonElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const menuId = useId();

  // the id actually in force for the next run, with the default resolved
  const defaultExists = defaultId === BUILTIN || prompts.some((p) => p.id === defaultId);
  const effectiveDefault = defaultExists ? defaultId : BUILTIN;
  const effective = value === null ? effectiveDefault : value;
  const current = effective === BUILTIN ? null : prompts.find((p) => p.id === effective) ?? null;
  const label = current ? current.name : 'Built-in prompt';

  const close = useCallback((refocus = true) => {
    setOpen(false);
    if (refocus) btnRef.current?.focus();
  }, []);

  // click outside / Escape close it; the menu is not modal, the page underneath stays live
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => { if (!rootRef.current?.contains(e.target as Node)) setOpen(false); };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') { e.stopPropagation(); close(); } };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey, true);
    return () => { document.removeEventListener('mousedown', onDown); document.removeEventListener('keydown', onKey, true); };
  }, [open, close]);

  // focus the checked row on open; arrows move between rows
  useEffect(() => {
    if (!open) return;
    const items = listRef.current?.querySelectorAll<HTMLButtonElement>('[role="menuitemradio"]');
    if (!items?.length) return;
    const checked = Array.from(items).find((el) => el.getAttribute('aria-checked') === 'true') ?? items[0];
    if (checked) window.setTimeout(() => checked.focus(), 0);
  }, [open]);

  const onListKey = (e: React.KeyboardEvent) => {
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp' && e.key !== 'Home' && e.key !== 'End') return;
    const items = Array.from(listRef.current?.querySelectorAll<HTMLButtonElement>('[role="menuitemradio"]') ?? []);
    if (!items.length) return;
    e.preventDefault();
    const i = items.indexOf(document.activeElement as HTMLButtonElement);
    const next = e.key === 'Home' ? 0 : e.key === 'End' ? items.length - 1
      : e.key === 'ArrowDown' ? (i + 1) % items.length : (i - 1 + items.length) % items.length;
    items[next]?.focus();
  };

  const pick = (id: string) => {
    onChange(id === effectiveDefault ? null : id);
    close();
  };

  const row = (id: string, name: string, desc: string, extra?: React.ReactNode) => {
    const checked = effective === id;
    return (
      <button
        key={id || '__builtin'}
        type="button"
        role="menuitemradio"
        aria-checked={checked}
        className={cx('ppick__item', checked && 'checked')}
        onClick={() => pick(id)}
      >
        <span className="ppick__check" aria-hidden>{checked && <Icon.Check />}</span>
        <span className="ppick__text">
          <span className="ppick__name">{name}{id === effectiveDefault && <span className="ppick__tag">default</span>}{extra}</span>
          {desc && <span className="ppick__desc">{desc}</span>}
        </span>
      </button>
    );
  };

  return (
    <div className={cx('ppick', open && 'open')} ref={rootRef}>
      <button
        ref={btnRef}
        type="button"
        className="ppick__btn"
        onClick={() => setOpen((v) => !v)}
        disabled={disabled}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={menuId}
        title="The prompt the next run uses — the built-in prompt, plus the saved instructions you pick here"
      >
        <span className="ppick__btn-label">Prompt</span>
        <span className="ppick__btn-name">{label}</span>
        {current && <span className="ppick__btn-plus" aria-hidden>+ built-in</span>}
        <Icon.Chevron className="ppick__caret" />
      </button>

      {open && (
        <div className="ppick__menu" id={menuId} role="menu" aria-label="Prompt for the next run" ref={listRef} onKeyDown={onListKey}>
          <div className="ppick__section">
            {row(BUILTIN, 'Built-in prompt', builtinEdited ? 'Your edited base prompt, nothing added' : 'How Iris searches, cites and stops — nothing added',
              builtinEdited ? <span className="ppick__tag ppick__tag--warn">edited</span> : undefined)}
          </div>
          {prompts.length > 0 ? (
            <div className="ppick__section">
              <div className="ppick__head">Saved prompts <span>added after the built-in prompt</span></div>
              {prompts.map((p) => row(p.id, p.name, firstLine(p.text)))}
            </div>
          ) : (
            <div className="ppick__empty">
              No saved prompts yet. A saved prompt adds standing instructions for a kind of investigation — a report format, what counts as critical, sources to distrust.
            </div>
          )}
          <div className="ppick__foot">
            <Link to="/settings#prompts" className="ppick__manage" role="menuitem" onClick={() => { setOpen(false); onNavigate?.(); }}>
              {prompts.length ? 'Manage prompts' : 'Add a prompt'}
              <Icon.ArrowLeft className="ppick__manage-arrow" />
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}
