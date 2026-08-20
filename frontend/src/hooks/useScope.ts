import { useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import type { Scope } from '../api/types';

/**
 * Analysis scope held in the URL (`?scope=case`), so a scoped view can be linked to and survives a
 * refresh — the case detail screen links straight to /timeline?scope=case.
 */
export function useScope(): [Scope, (s: Scope) => void] {
  const [sp, setSp] = useSearchParams();
  const scope: Scope = sp.get('scope') === 'case' ? 'case' : 'all';
  const setScope = useCallback((s: Scope) => {
    const p = new URLSearchParams(sp);
    if (s === 'case') p.set('scope', 'case');
    else p.delete('scope');
    setSp(p, { replace: true });
  }, [sp, setSp]);
  return [scope, setScope];
}
