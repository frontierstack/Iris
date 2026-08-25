import { useCallback, useState } from 'react';

/** A collapsible section's open state, remembered per section under one localStorage key.
 *  Closed by default: the heads with their counts are the overview, and a section opens when it is the
 *  one being worked in (the Anomalies rule, now shared with the case screen). */
export function useSectionOpen(storageKey: string, section: string, defaultOpen = false): [boolean, () => void] {
  const read = (): Record<string, boolean> => {
    try { return JSON.parse(localStorage.getItem(storageKey) || '{}') as Record<string, boolean>; } catch { return {}; }
  };
  const [open, setOpen] = useState<boolean>(() => {
    const v = read()[section];
    return v === undefined ? defaultOpen : !!v;
  });
  const toggle = useCallback(() => {
    setOpen((v) => {
      const next = !v;
      try { localStorage.setItem(storageKey, JSON.stringify({ ...read(), [section]: next })); } catch { /* private mode */ }
      return next;
    });
  }, [storageKey, section]);
  return [open, toggle];
}
