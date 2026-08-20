import { useEffect } from 'react';

function isTyping(el: Element | null): boolean {
  if (!el) return false;
  const tag = el.tagName;
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || (el as HTMLElement).isContentEditable;
}

/** Global single-key hotkey (ignored while typing in a field). */
export function useHotkey(key: string, handler: (e: KeyboardEvent) => void, opts?: { allowInInputs?: boolean }): void {
  useEffect(() => {
    const on = (e: KeyboardEvent) => {
      if (e.key !== key || e.ctrlKey || e.metaKey || e.altKey) return;
      if (!opts?.allowInInputs && isTyping(document.activeElement)) return;
      handler(e);
    };
    window.addEventListener('keydown', on);
    return () => window.removeEventListener('keydown', on);
  }, [key, handler, opts?.allowInInputs]);
}
