import { useEffect, type ReactNode } from 'react';
import type { DerivedState, Severity } from '../api/types';
import { cx, sevVar } from '../utils/format';
import { useToast } from '../hooks/useToast';

/* ───── Severity ───── */
export function SevTag({ sev, bar = true }: { sev: Severity; bar?: boolean }) {
  return (
    <span className={cx('sev', `sev-${sev}`)}>
      {bar && <span className="sev__bar" style={{ background: sevVar(sev) }} />}
      {sev}
    </span>
  );
}
export function SevChip({ sev }: { sev: Severity }) {
  return <span className={cx('sev-chip', `sev-chip--${sev}`)}>{sev}</span>;
}

/* ───── States ───── */
export function Loading({ label = 'Loading…', inline }: { label?: string; inline?: boolean }) {
  return (
    <div className={cx('state', inline && 'state--inline')} role="status" aria-live="polite">
      <div className="spinner" />
      <div className="state__body">{label}</div>
    </div>
  );
}
export function ErrorState({ title = 'Something went wrong', error, onRetry, inline }: { title?: string; error?: unknown; onRetry?: () => void; inline?: boolean }) {
  const msg = error instanceof Error ? error.message : typeof error === 'string' ? error : undefined;
  return (
    <div className={cx('state state--error', inline && 'state--inline')} role="alert">
      <div className="state__title">{title}</div>
      {msg && <div className="state__body mono">{msg}</div>}
      {onRetry && (
        <div className="state__actions">
          <button className="btn btn--sm" onClick={onRetry}>Retry</button>
        </div>
      )}
    </div>
  );
}
export function EmptyState({ title, body, actions, inline, icon }: { title: string; body?: ReactNode; actions?: ReactNode; inline?: boolean; icon?: ReactNode }) {
  return (
    <div className={cx('state', inline && 'state--inline')}>
      {icon && <div className="state__icon">{icon}</div>}
      <div className="state__title">{title}</div>
      {body && <div className="state__body">{body}</div>}
      {actions && <div className="state__actions">{actions}</div>}
    </div>
  );
}
/** A derived structure (entity graph, correlation clusters) is being built on the server.
 *
 *  This is deliberately NOT a plain spinner: at 1.2 M events the build takes tens of seconds, and an
 *  unexplained wait that long is indistinguishable from a hang — which is exactly how the old
 *  build-on-the-request-thread behaviour read. Say what is being built, how far along it is, and that
 *  the screen will fill itself in. */
export function BuildingState({ what, status, action }: { what: string; status?: DerivedState; action?: ReactNode }) {
  const pct = Math.max(0, Math.min(100, status?.pct ?? 0));
  const secs = status?.elapsedSec ?? 0;
  if (status?.note) {
    // Paused, not building. Two different causes reach this branch and they end differently: a library
    // load finishes on its own in minutes, while an enrichment queue on a big workspace runs for hours
    // and the analyst may reasonably want to stop waiting. The title said "once the library finishes
    // loading" for BOTH, which is a wrong sentence for the common case and left the enrichment wait
    // looking like a hang. The server's own note names the cause; `action` carries whatever the
    // analyst can do about it (nothing, when there is nothing to decide).
    const enriching = /enrich/i.test(status.note);
    return (
      <div className="state" role="status" aria-live="polite">
        <div className="spinner" />
        <div className="state__title">
          The {what} builds once {enriching ? 'the sources have been interpreted' : 'the library has finished loading'}
        </div>
        <div className="state__body">
          {status.note} — every {enriching ? 'source that finishes' : 'file that lands'} would restart it,
          so it waits for the last one.
        </div>
        {action}
      </div>
    );
  }
  return (
    <div className="state" role="status" aria-live="polite">
      <div className="spinner" />
      <div className="state__title">Building the {what}…</div>
      <div className="state__body">
        {status?.target
          ? `${status.events.toLocaleString()} of ${status.target.toLocaleString()} events · ${pct.toFixed(0)}%`
          : 'reading the event pool'}
        {secs > 0 && ` · ${secs}s elapsed`}
      </div>
      <div className="state__bar" aria-hidden><i style={{ width: `${pct}%` }} /></div>
      <div className="state__body">
        This runs once per change to the event pool, in the background — the view fills in by itself.
      </div>
    </div>
  );
}
export function SkeletonRows({ n = 6 }: { n?: number }) {
  return (
    <div className="skeleton-rows" aria-hidden>
      {Array.from({ length: n }).map((_, i) => (
        <div key={i}><div className="skeleton" style={{ width: `${55 + ((i * 17) % 40)}%` }} /></div>
      ))}
    </div>
  );
}

/* ───── Toasts ───── */
export function Toasts() {
  const { toasts, dismiss } = useToast();
  if (!toasts.length) return null;
  return (
    <div className="toasts" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} className={cx('toast', `toast--${t.kind}`)}>
          <div>
            <div className="toast__title">{t.title}</div>
            {t.msg && <div className="toast__msg">{t.msg}</div>}
          </div>
          <button className="toast__x" onClick={() => dismiss(t.id)} aria-label="Dismiss">×</button>
        </div>
      ))}
    </div>
  );
}

/* ───── Modal / confirm ───── */
export function ConfirmDialog({ open, title, text, confirmLabel = 'Confirm', danger, busy, confirmDisabled, onConfirm, onCancel, children }: {
  open: boolean; title: string; text: ReactNode; confirmLabel?: string; danger?: boolean; busy?: boolean;
  /** when true the confirm button stays disabled (e.g. a type-the-name gate); defaults to false */
  confirmDisabled?: boolean;
  onConfirm: () => void; onCancel: () => void; children?: ReactNode;
}) {
  useEffect(() => {
    if (!open) return;
    const on = (e: KeyboardEvent) => { if (e.key === 'Escape') onCancel(); };
    window.addEventListener('keydown', on);
    return () => window.removeEventListener('keydown', on);
  }, [open, onCancel]);
  if (!open) return null;
  return (
    <div className="modal" role="dialog" aria-modal="true" aria-label={title}>
      <div className="overlay" onClick={onCancel} />
      <div className="modal__box">
        <div className="modal__body">
          <div className="modal__title">{title}</div>
          <div className="modal__text">{text}</div>
          {children && <div className="modal__extra">{children}</div>}
        </div>
        <div className="modal__foot">
          <button className="btn" onClick={onCancel} disabled={busy}>Cancel</button>
          <button className={cx('btn', danger ? 'btn--danger' : 'btn--primary')} onClick={onConfirm} disabled={busy || confirmDisabled} autoFocus>
            {busy && <span className="btn__spinner" />}{confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ───── Drawer ───── */
export function Drawer({ open, title, sub, wide, onClose, children, footer, actions }: {
  open: boolean; title: ReactNode; sub?: ReactNode; wide?: boolean; onClose: () => void; children: ReactNode;
  footer?: ReactNode;
  /** Controls in the head, left of the close button (e.g. "Detach" on the raw log viewer). */
  actions?: ReactNode;
}) {
  useEffect(() => {
    if (!open) return;
    const on = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', on);
    return () => window.removeEventListener('keydown', on);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <>
      <div className="overlay" onClick={onClose} />
      <aside className={cx('drawer', wide && 'drawer--wide')} role="dialog" aria-modal="true">
        <div className="drawer__head">
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="drawer__title">{title}</div>
            {sub && <div className="drawer__sub">{sub}</div>}
          </div>
          {actions}
          <button className="close-x" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="drawer__body">{children}</div>
        {footer && <div className="drawer__foot">{footer}</div>}
      </aside>
    </>
  );
}

/* ───── Bar ───── */
export function Bar({ pct, color, width }: { pct: number; color: string; width?: number | string }) {
  return (
    <div className="bar" style={width !== undefined ? { width } : undefined}>
      <div className="bar__fill" style={{ width: `${Math.max(0, Math.min(100, pct))}%`, background: color }} />
    </div>
  );
}

/* ───── Toggle ───── */
export function Toggle({ on, onChange, label, disabled }: { on: boolean; onChange: (v: boolean) => void; label?: ReactNode; disabled?: boolean }) {
  return (
    <label className={cx('toggle', on && 'on')} aria-disabled={disabled}>
      <input type="checkbox" checked={on} onChange={(e) => onChange(e.target.checked)} disabled={disabled} />
      <span className="toggle__track"><span className="toggle__thumb" /></span>
      {label && <span className="toggle__label">{label}</span>}
    </label>
  );
}

/* ───── Section header with eyebrow ───── */
export function SectionHead({ eyebrow, title, hint, actions, id, open, onToggle }: {
  eyebrow?: string; title: ReactNode; hint?: ReactNode; actions?: ReactNode; id?: string;
  /** When `onToggle` is given the head is a DISCLOSURE: the title toggles the section body. The hint
   *  stays visible either way (it carries the counts, which is what a collapsed section should still
   *  say); the actions only exist while the body they act on is on screen. */
  open?: boolean; onToggle?: () => void;
}) {
  const collapsible = typeof onToggle === 'function';
  const head = (
    <>
      {eyebrow && <div className="sec__eyebrow">{eyebrow}</div>}
      <div className="sec__title">
        {collapsible && <span className={cx('sec__chev', open && 'open')} aria-hidden="true" />}
        {title}
      </div>
    </>
  );
  return (
    <div className={cx('sec', collapsible && 'sec--collapsible', collapsible && !open && 'sec--closed')} id={id}>
      {collapsible
        ? <button type="button" className="sec__toggle" aria-expanded={!!open} onClick={onToggle}>{head}</button>
        : <div>{head}</div>}
      {hint && <div className="sec__hint">{hint}</div>}
      {actions && (!collapsible || open) && <div className="sec__actions">{actions}</div>}
    </div>
  );
}
