/**
 * A detached, movable, resizable panel.
 *
 * The raw log viewer lived in the right-hand drawer, which is modal and fixed-width: reading a log line
 * while looking at the source row that produced it meant closing the drawer, and a 200-column line was
 * squeezed into 640px whatever the screen. Detaching it makes the log a window you place where you want
 * and size to the content — the rest of the page stays live behind it.
 *
 * The AI panel is the second tenant, for the same reason turned up one notch: an investigation is
 * WATCHED while the analyst reads the evidence it is quoting, and a modal slide-over made that two
 * alternating screens. `flush` and `closeOnEscape` exist for it — see the props.
 *
 * Deliberate choices:
 * - **No overlay.** The point of detaching is to keep working underneath; an overlay would take the
 *   clicks the analyst detached the window to be able to make.
 * - **Position and size persist** per storage key, so the window you set up stays put across reopens
 *   and reloads — otherwise every open is a re-arrange.
 * - **Clamped back into view on mount and on resize.** A window saved at x=1800 on a wide monitor is
 *   unreachable on a laptop, and a title bar you cannot grab is a window you cannot close.
 * - Pointer events (not mouse) with capture, so a drag that leaves the window keeps tracking, and touch
 *   works the same as a mouse.
 */
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { cx } from '../utils/format';

export interface WinBox { x: number; y: number; w: number; h: number }

const MIN_W = 380;
const MIN_H = 240;
const HEADER_GRAB = 28;   // keep at least this much of the title bar on screen

/** Per-window floors: a window whose own furniture is taller than the default minimum can raise it. */
interface Mins { w: number; h: number }

function clampBox(b: WinBox, min: Mins): WinBox {
  const vw = window.innerWidth;
  const vh = window.innerHeight;
  const w = Math.min(Math.max(b.w, min.w), Math.max(min.w, vw - 16));
  const h = Math.min(Math.max(b.h, min.h), Math.max(min.h, vh - 16));
  return {
    w,
    h,
    x: Math.min(Math.max(b.x, -(w - 120)), Math.max(0, vw - 120)),
    y: Math.min(Math.max(b.y, 0), Math.max(0, vh - HEADER_GRAB)),
  };
}

function readBox(key: string, fallback: WinBox, min: Mins): WinBox {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return clampBox(fallback, min);
    const p = JSON.parse(raw) as Partial<WinBox>;
    if (typeof p.x !== 'number' || typeof p.y !== 'number' || typeof p.w !== 'number' || typeof p.h !== 'number') {
      return clampBox(fallback, min);
    }
    return clampBox(p as WinBox, min);
  } catch {
    return clampBox(fallback, min);
  }
}

type Mode = null | { kind: 'move'; dx: number; dy: number } | { kind: 'resize'; edge: string; start: WinBox; px: number; py: number };

export function FloatingWindow({
  title, sub, actions, head, className, onClose, children, storageKey, defaultBox,
  flush = false, ariaLabel, closeOnEscape = true, minW = MIN_W, minH = MIN_H,
}: {
  title: ReactNode;
  sub?: ReactNode;
  /** Controls for the title bar — the dock button lives here. */
  actions?: ReactNode;
  /**
   * The WHOLE title bar, supplied by the child, replacing the ident/actions/close arrangement.
   *
   * For a window whose docked form already has a header of its own — the AI panel is the assistant
   * template's 58px header, brand lozenge and all — the default bar would sit ABOVE that one and the
   * analyst would read two headers. Passing it here keeps one header and keeps the bar as the drag
   * handle, and the child then owns its own close control (`startMove` ignores a press on a button,
   * so nothing inside it drags the window).
   */
  head?: ReactNode;
  /** Extra class on the window frame, so a tenant can dress it without forking the primitive. */
  className?: string;
  onClose: () => void;
  children: ReactNode;
  /** localStorage key for the remembered geometry. */
  storageKey: string;
  defaultBox?: Partial<WinBox>;
  /**
   * The body scrolls its own content and manages its own padding — for a child that is itself a
   * flex column with a scrolling middle and a pinned footer (the AI panel). Without it the window
   * scrolls the child AND the child scrolls itself, so the composer drifts off the bottom.
   */
  flush?: boolean;
  /** Needed when `title` is a node rather than a string; the node is what the analyst reads. */
  ariaLabel?: string;
  /**
   * Escape closes. TRUE for a viewer, FALSE for a window holding an unsent text input: a detached
   * window is not modal, so Escape is being pressed at whatever the analyst is doing on the page
   * underneath, and closing on it would throw away a half-written objective.
   */
  closeOnEscape?: boolean;
  /**
   * Smallest the analyst may drag it. The default suits a viewer; raise `minH` for a window with
   * fixed furniture of its own — the AI panel spends ~170px on its title bar and pinned composer, so
   * at the default 240 there is nothing left to read the transcript in.
   */
  minW?: number;
  minH?: number;
}) {
  const key = `iris.win.${storageKey}`;
  const min = useMemo<Mins>(() => ({ w: minW, h: minH }), [minW, minH]);
  const [box, setBox] = useState<WinBox>(() =>
    readBox(key, {
      x: defaultBox?.x ?? Math.max(24, window.innerWidth - (defaultBox?.w ?? 900) - 40),
      y: defaultBox?.y ?? 90,
      w: defaultBox?.w ?? 900,
      h: defaultBox?.h ?? Math.min(640, window.innerHeight - 140),
    }, { w: minW, h: minH }));
  const mode = useRef<Mode>(null);
  const ref = useRef<HTMLDivElement | null>(null);

  const persist = useCallback((b: WinBox) => {
    try { localStorage.setItem(key, JSON.stringify(b)); } catch { /* private mode: the window still works */ }
  }, [key]);

  // A saved geometry is only valid for the viewport it was saved in.
  useEffect(() => {
    const onResize = () => setBox((b) => clampBox(b, min));
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, [min]);

  useEffect(() => {
    if (!closeOnEscape) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose, closeOnEscape]);

  const onPointerMove = (e: React.PointerEvent) => {
    const m = mode.current;
    if (!m) return;
    if (m.kind === 'move') {
      setBox((b) => clampBox({ ...b, x: e.clientX - m.dx, y: e.clientY - m.dy }, min));
      return;
    }
    const dx = e.clientX - m.px;
    const dy = e.clientY - m.py;
    setBox(() => {
      const s = m.start;
      let { x, y, w, h } = s;
      if (m.edge.includes('e')) w = s.w + dx;
      if (m.edge.includes('s')) h = s.h + dy;
      if (m.edge.includes('w')) { w = s.w - dx; x = s.x + dx; }
      if (m.edge.includes('n')) { h = s.h - dy; y = s.y + dy; }
      // a west/north drag that hits the minimum must stop moving the far edge, not keep sliding it
      if (w < min.w && m.edge.includes('w')) x = s.x + (s.w - min.w);
      if (h < min.h && m.edge.includes('n')) y = s.y + (s.h - min.h);
      return clampBox({ x, y, w, h }, min);
    });
  };

  const endDrag = (e: React.PointerEvent) => {
    if (!mode.current) return;
    mode.current = null;
    try { (e.target as HTMLElement).releasePointerCapture(e.pointerId); } catch { /* already released */ }
    setBox((b) => { persist(b); return b; });
  };

  const startMove = (e: React.PointerEvent) => {
    if ((e.target as HTMLElement).closest('button')) return;   // the close/dock buttons are not a handle
    mode.current = { kind: 'move', dx: e.clientX - box.x, dy: e.clientY - box.y };
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
    e.preventDefault();
  };

  const startResize = (edge: string) => (e: React.PointerEvent) => {
    mode.current = { kind: 'resize', edge, start: box, px: e.clientX, py: e.clientY };
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
    e.preventDefault();
    e.stopPropagation();
  };

  return (
    <div
      ref={ref}
      className={cx('floatwin', mode.current && 'floatwin--dragging', className)}
      style={{ left: box.x, top: box.y, width: box.w, height: box.h, minWidth: minW, minHeight: minH }}
      role="dialog"
      aria-label={ariaLabel ?? (typeof title === 'string' ? title : 'Detached window')}
      onPointerMove={onPointerMove}
      onPointerUp={endDrag}
      onPointerCancel={endDrag}
    >
      <div className="floatwin__head" onPointerDown={startMove}>
        {head ?? (
          <>
            <div className="floatwin__ident">
              <div className="floatwin__title">{title}</div>
              {sub && <div className="floatwin__sub">{sub}</div>}
            </div>
            <div className="floatwin__actions">
              {actions}
              <button className="close-x" onClick={onClose} aria-label="Close">×</button>
            </div>
          </>
        )}
      </div>
      <div className={cx('floatwin__body', flush && 'floatwin__body--flush')}>{children}</div>
      {/* edges first, corner last: the corner must win the hit test where they overlap */}
      {(['n', 's', 'e', 'w'] as const).map((edge) => (
        <div key={edge} className={`floatwin__edge floatwin__edge--${edge}`} onPointerDown={startResize(edge)} />
      ))}
      {(['ne', 'nw', 'se', 'sw'] as const).map((edge) => (
        <div key={edge} className={`floatwin__corner floatwin__corner--${edge}`} onPointerDown={startResize(edge)}
          aria-hidden />
      ))}
      <div className="floatwin__grip" aria-hidden />
    </div>
  );
}
