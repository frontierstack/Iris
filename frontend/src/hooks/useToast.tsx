import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react';
import { errMsg } from '../utils/format';

export type ToastKind = 'error' | 'success' | 'info';
export interface Toast { id: number; kind: ToastKind; title: string; msg?: string }

interface ToastCtx {
  toasts: Toast[];
  push: (kind: ToastKind, title: string, msg?: string) => void;
  error: (title: string, e?: unknown) => void;
  success: (title: string, msg?: string) => void;
  info: (title: string, msg?: string) => void;
  dismiss: (id: number) => void;
}

const Ctx = createContext<ToastCtx | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const seq = useRef(0);
  const dismiss = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);
  const push = useCallback((kind: ToastKind, title: string, msg?: string) => {
    const id = ++seq.current;
    setToasts((t) => [...t.slice(-4), { id, kind, title, msg }]);
    window.setTimeout(() => dismiss(id), kind === 'error' ? 7000 : 4000);
  }, [dismiss]);
  const value = useMemo<ToastCtx>(() => ({
    toasts,
    push,
    dismiss,
    error: (title, e) => push('error', title, e === undefined ? undefined : errMsg(e)),
    success: (title, msg) => push('success', title, msg),
    info: (title, msg) => push('info', title, msg),
  }), [toasts, push, dismiss]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useToast(): ToastCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error('useToast must be used inside ToastProvider');
  return c;
}
