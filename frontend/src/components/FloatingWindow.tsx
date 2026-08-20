/**
 * A detached, movable, resizable panel.
 *
 * The raw log viewer lived in the right-hand drawer, which is modal and fixed-width: reading a log line
 * while looking at the source row that produced it meant closing the drawer, and a 200-column line was
 * squeezed into 640px whatever the screen. Detaching it makes the log a window you place where you want
 * and size to the content — the rest of the page stays live behind it.
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
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { cx } from '../utils/format';

export interface WinBox { x: number; y: number; w: number; h: number }

const MIN_W = 380;
const MIN_H = 240;
const HEADER_GRAB = 28;   // keep at least this much of the title bar on screen

function clampBox(b: WinBox): WinBox {
  const vw = window.innerWidth;
  const vh = window.innerHeight;
  const w = Math.min(Math.max(b.w, MIN_W), Math.max(MIN_W, vw - 16));
  const h = Math.min(Math.max(b.h, MIN_H), Math.max(MIN_H, vh - 16));
  return {
    w,
    h,
    x: Math.min(Math.max(b.x, -(w - 120)), Math.max(0, vw - 120)),
    y: Math.min(Math.max(b.y, 0), Math.max(0, vh - HEADER_GRAB)),
  };
}

function readBox(key: string, fallback: WinBox): WinBox {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return clampBox(fallback);
    const p = JSON.parse(raw) as Partial<WinBox>;
    if (typeof p.x !== 'number' || typeof p.y !== 'number' || typeof p.w !== 'number' || typeof p.h !== 'number') {
      return clampBox(fallback);
    }
    return clampBox(p as WinBox);
  } catch {
    return clampBox(fallback);
  }
}

type Mode = null | { kind: 'move'; dx: number; dy: number } | { kind: 'resize'; edge: string; start: WinBox; px: number; py: number };

export function FloatingWindow({
  title, sub, actions, onClose, children, storageKey, defaultBox,
}: {
  title: ReactNode;
  sub?: ReactNode;
  /** Controls for the title bar — the dock button lives here. */
  actions?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  /** localStorage key for the remembered geometry. */
  storageKey: string;
  defaultBox?: Partial<WinBox>;
}) {
  const key = `iris.win.${storageKey}`;
  const [box, setBox] = useState<WinBox>(() =>
    readBox(key, {
      x: defaultBox?.x ?? Math.max(24, window.innerWidth - (defaultBox?.w ?? 900) - 40),
      y: defaultBox?.y ?? 90,
      w: defaultBox?.w ?? 900,
      h: defaultBox?.h ?? Math.min(640, window.innerHeight - 140),
    }));
  const mode = useRef<Mode>(null);
  const ref = useRef<HTMLDivElement | null>(null);

  const persist = useCallback((b: WinBox) => {
    try { localStorage.setItem(key, JSON.stringify(b)); } catch { /* private mode: the window still works */ }
  }, [key]);

  // A saved geometry is only valid for the viewport it was saved in.
  useEffect(() => {
    const onResize = () => setBox((b) => clampBox(b));
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const onPointerMove = (e: React.PointerEvent) => {
    const m = mode.current;
    if (!m) return;
    if (m.kind === 'move') {
      setBox((b) => clampBox({ ...b, x: e.clientX - m.dx, y: e.clientY - m.dy }));
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
      if (w < MIN_W && m.edge.includes('w')) x = s.x + (s.w - MIN_W);
      if (h < MIN_H && m.edge.includes('n')) y = s.y + (s.h - MIN_H);
      return clampBox({ x, y, w, h });
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
      className={cx('floatwin', mode.current && 'floatwin--dragging')}
      style={{ left: box.x, top: box.y, width: box.w, height: box.h }}
      role="dialog"
      aria-label={typeof title === 'string' ? title : 'Detached window'}
      onPointerMove={onPointerMove}
      onPointerUp={endDrag}
      onPointerCancel={endDrag}
    >
      <div className="floatwin__head" onPointerDown={startMove}>
        <div className="floatwin__ident">
          <div className="floatwin__title">{title}</div>
          {sub && <div className="floatwin__sub">{sub}</div>}
        </div>
        <div className="floatwin__actions">
          {actions}
          <button className="close-x" onClick={onClose} aria-label="Close">×</button>
        </div>
      </div>
      <div className="floatwin__body">{children}</div>
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
