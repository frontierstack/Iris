import type { ReactNode } from 'react';

/**
 * Pull the literal terms out of a search query so results can highlight what matched.
 *
 * The query DSL supports `field:value`, quoted phrases and boolean words; for highlighting we only
 * care about the literal text a human would expect to see marked, so operators are dropped and
 * `field:value` contributes just its value.
 */
export function queryTerms(q: string): string[] {
  if (!q) return [];
  const out: string[] = [];
  // quoted phrases first, so their spaces survive
  const rest = q.replace(/"([^"]+)"|'([^']+)'/g, (_m, a: string, b: string) => {
    const v = (a ?? b ?? '').trim();
    if (v) out.push(v);
    return ' ';
  });
  for (let tok of rest.split(/\s+/)) {
    tok = tok.trim();
    if (!tok) continue;
    if (/^(AND|OR|NOT)$/i.test(tok)) continue;
    tok = tok.replace(/^[-+!(]+/, '').replace(/[)]+$/, '');
    const colon = tok.indexOf(':');
    if (colon > 0) tok = tok.slice(colon + 1);
    tok = tok.replace(/^[><=]+/, '').replace(/^["']|["']$/g, '');
    // a bare wildcard or a 1-char fragment marks up half the row — not useful
    if (tok.length < 2 || /^\*+$/.test(tok)) continue;
    out.push(tok.replace(/\*/g, ''));
  }
  // longest first so "failed password" wins over "failed" when both are present
  return [...new Set(out.filter(Boolean))].sort((a, b) => b.length - a.length);
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Wrap every occurrence of `terms` in <mark>. Case-insensitive; returns the plain string when nothing matches. */
export function highlight(text: string, terms: string[]): ReactNode {
  if (!text || !terms.length) return text;
  let re: RegExp;
  try {
    re = new RegExp(`(${terms.map(escapeRe).join('|')})`, 'gi');
  } catch {
    return text;
  }
  const parts = text.split(re);
  if (parts.length === 1) return text;
  const lower = new Set(terms.map((t) => t.toLowerCase()));
  return parts.map((part, i) =>
    lower.has(part.toLowerCase()) ? <mark key={i} className="hl">{part}</mark> : part,
  );
}
