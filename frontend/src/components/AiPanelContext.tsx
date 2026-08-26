/**
 * The AI panel's HANDLE — the context every screen holds, split from the panel itself.
 *
 * `AiPanelProvider` wraps the whole app, so anything it imports statically is in the entry chunk and
 * is parsed before the first paint of every screen. The panel is ~70 KB of the app (its transcript
 * renderer, the markdown repair, the floating-window primitive, the prompt picker and its editor) and
 * it is not on screen until the analyst asks for it: `AiPanelProvider` renders `<AiPanel>` only when a
 * target is set. So the panel is a `lazy()` import and only this file — the context, the hook and the
 * target type — stays in the entry.
 *
 * The Suspense fallback here is `null` DELIBERATELY. Opening the panel is a click on the AI button;
 * the chunk is same-origin, content-hashed and immutable, so the fetch is a local cache read after the
 * first time. A spinner in the corner of the viewport for that would be noise, and a panel frame that
 * paints empty and then fills in would read as a broken panel. Nothing, then the panel, is honest.
 */
import { Suspense, createContext, lazy, useCallback, useContext, useMemo, useState, type ReactNode } from 'react';
import type { AiScope } from '../api/types';

const AiPanel = lazy(() => import('./AiPanel').then((m) => ({ default: m.AiPanel })));

export interface AiTarget { scope: AiScope; id?: string; eventIds?: string[]; label: string }

interface AiCtx {
  open: (target: AiTarget) => void;
  close: () => void;
  isOpen: boolean;
}
const Ctx = createContext<AiCtx | null>(null);

export function useAiPanel(): AiCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error('useAiPanel must be used inside AiPanelProvider');
  return c;
}

export function AiPanelProvider({ children }: { children: ReactNode }) {
  const [target, setTarget] = useState<AiTarget | null>(null);
  const open = useCallback((t: AiTarget) => setTarget(t), []);
  const close = useCallback(() => setTarget(null), []);
  const value = useMemo(() => ({ open, close, isOpen: target !== null }), [open, close, target]);
  return (
    <Ctx.Provider value={value}>
      {children}
      {target && (
        <Suspense fallback={null}>
          <AiPanel target={target} onClose={close} />
        </Suspense>
      )}
    </Ctx.Provider>
  );
}
