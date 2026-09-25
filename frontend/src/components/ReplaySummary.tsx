/**
 * The case summary under the replay's title, read as an INCIDENT BRIEF rather than a paragraph.
 *
 * The assistant writes summaries in a recognisable shape — "End-to-end investigation of X: **download
 * origin** (…), **install origin** (…), … . Single user `Tay`, single host `h`, two sources (…)." —
 * and rendered as one run of prose that is a wall of commas: every fact is there and none of them can
 * be found at a glance. `parseSummary` reads the shape back out, deterministically:
 *  - the clause before the first colon is the HEADLINE;
 *  - each `**facet** (details)` becomes a labelled card, its details split on TOP-LEVEL commas only
 *    (a parenthetical or a code span inside a detail never breaks it);
 *  - trailing "single user `x`, two sources (…)" sentences become SCOPE chips.
 * Other shapes the assistant writes are handled too — `Key: value` lines become the same cards, and
 * headings/bullets/plain prose get a lede plus the rest behind a disclosure.
 *
 * Nothing is ever dropped: text the parser did not place is shown as a note, and every structured form
 * also offers the summary exactly as written. A brief that silently loses a clause is worse than the
 * wall of text it replaced.
 */
import { useState } from 'react';
import { inlineMd, renderMarkdown, unescapeBreaks } from '../utils/markdown';

export interface SummaryFacet { label: string; items: string[] }
export interface SummaryScope { label: string; items: string[] }
export interface ParsedSummary {
  kind: 'facets' | 'keyvalue' | 'markdown' | 'prose' | 'empty';
  headline: string;        // one line; may carry inline markdown
  facets: SummaryFacet[];
  scope: SummaryScope[];
  notes: string[];         // text the structure did not absorb - shown, never dropped
  more: string;            // the rest of a prose/markdown summary, behind the disclosure
}

/* ── scanning helpers: all of them honour `code spans` and nested brackets ── */

/** Index of the bracket closing the one at `open`, or -1. Backtick spans are opaque. */
function closeOf(s: string, open: number): number {
  let depth = 0;
  let code = false;
  for (let i = open; i < s.length; i++) {
    const ch = s[i];
    if (ch === '`') { code = !code; continue; }
    if (code) continue;
    if (ch === '(' || ch === '[') depth++;
    else if (ch === ')' || ch === ']') { depth--; if (depth === 0) return i; }
  }
  return -1;
}

/** Split on `sep` where it is at depth 0 and outside a code span. */
export function splitTop(s: string, sep: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let code = false;
  let from = 0;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === '`') { code = !code; continue; }
    if (code) continue;
    if (ch === '(' || ch === '[') depth++;
    else if ((ch === ')' || ch === ']') && depth > 0) depth--;
    else if (depth === 0 && s.startsWith(sep, i)) { out.push(s.slice(from, i)); from = i + sep.length; i += sep.length - 1; }
  }
  out.push(s.slice(from));
  return out.map((x) => x.trim()).filter(Boolean);
}

/** Sentences: a . ! ? at depth 0, outside code, followed by space and a capital, digit, backtick or **. */
export function sentences(s: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let code = false;
  let from = 0;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === '`') { code = !code; continue; }
    if (code) continue;
    if (ch === '(' || ch === '[') depth++;
    else if ((ch === ')' || ch === ']') && depth > 0) depth--;
    else if (depth === 0 && (ch === '.' || ch === '!' || ch === '?') && /^\s+(?:[A-Z0-9`]|\*\*)/.test(s.slice(i + 1, i + 5))) {
      out.push(s.slice(from, i + 1));
      from = i + 1;
    }
  }
  out.push(s.slice(from));
  return out.map((x) => x.trim()).filter(Boolean);
}

const sentenceCase = (s: string) => {
  const t = s.trim().replace(/\s+/g, ' ');
  return t ? t[0]!.toUpperCase() + t.slice(1) : t;
};
/** Outside a code span at `at`? (an even number of backticks before it) */
const outsideCode = (s: string, at: number) => ((s.slice(0, at).match(/`/g)?.length ?? 0) % 2) === 0;
/** What may sit BETWEEN two facets and carries nothing: commas, "and", semicolons, a full stop. */
const JOINER = /^[\s,;.]*(?:(?:and|plus|&)\s*)?[\s,;]*$/i;
const trimEnds = (s: string) => s.replace(/^[\s,;:.–—-]+/, '').replace(/[\s,;:–—-]+$/, '').trim();

/** "Single user `Tay`", "two sources (`a` + `b`)", "3 hosts: a, b" -> a scope chip. */
const SCOPE_RE = /^(single|one|two|three|four|five|six|seven|eight|nine|ten|several|multiple|many|no|\d+)\s+(users?|accounts?|hosts?|machines?|devices?|endpoints?|sources?|logs?|files?|ips?|addresses|domains?|processes|process)\b[:\s]*(.*)$/i;
function scopeOf(part: string): SummaryScope | null {
  const m = SCOPE_RE.exec(part.trim().replace(/\.$/, ''));
  if (!m) return null;
  let rest = (m[3] ?? '').trim();
  if (rest.startsWith('(') && closeOf(rest, 0) === rest.length - 1) rest = rest.slice(1, -1).trim();
  // "(`a` + `b`)" / "a, b" / "a and b" are several values of one thing
  let items = splitTop(rest, ' + ');
  if (items.length === 1) items = splitTop(rest, ',');
  if (items.length === 1 && / and /.test(rest)) items = splitTop(rest, ' and ');
  return { label: sentenceCase(`${m[1]} ${m[2]}`), items };
}

/** A sentence that is ENTIRELY scope ("Single user X, single host Y, two sources (…)"), or null. */
function scopeSentence(s: string): SummaryScope[] | null {
  const parts = splitTop(s.replace(/\.$/, ''), ',').flatMap((p) => splitTop(p, ';'));
  const out: SummaryScope[] = [];
  for (const p of parts) {
    const sc = scopeOf(p.replace(/^and\s+/i, ''));
    if (!sc) return null;
    out.push(sc);
  }
  return out.length ? out : null;
}

const EMPTY: ParsedSummary = { kind: 'empty', headline: '', facets: [], scope: [], notes: [], more: '' };

/** `**facet** (details), **facet** (details) …` — two or more of them make the brief. */
function facetForm(text: string): ParsedSummary | null {
  const found: { label: string; start: number; end: number; body: string }[] = [];
  const re = /\*\*([^*\n]{1,60}?)\*\*\s*\(/g;
  for (const m of text.matchAll(re)) {
    const at = m.index ?? 0;
    if (found.length && at < found[found.length - 1]!.end) continue;
    if (!outsideCode(text, at)) continue;
    const open = at + m[0].length - 1;
    const close = closeOf(text, open);
    if (close < 0) continue;
    found.push({ label: m[1]!, start: at, end: close + 1, body: text.slice(open + 1, close) });
  }
  if (found.length < 2) return null;

  const notes: string[] = [];
  let headline = trimEnds(text.slice(0, found[0]!.start));
  // "…, covering:" / "…, including" - the lead-in word is part of the sentence, not of the headline
  headline = headline.replace(/[\s,]*(?:covering|including|incl\.|across|with)$/i, '').trim();
  for (let i = 1; i < found.length; i++) {
    const between = text.slice(found[i - 1]!.end, found[i]!.start);
    if (!JOINER.test(between)) notes.push(trimEnds(between));
  }
  const facets = found.map((f) => ({ label: sentenceCase(f.label), items: splitTop(f.body, ',') }));

  const scope: SummaryScope[] = [];
  for (const s of sentences(trimEnds(text.slice(found[found.length - 1]!.end)))) {
    const sc = scopeSentence(s);
    if (sc) scope.push(...sc); else notes.push(s);
  }
  return { kind: 'facets', headline, facets, scope, notes: notes.filter(Boolean), more: '' };
}

/** Two or more `Key: value` lines (optionally bulleted or bold) make cards; everything else is kept. */
const KV_LINE = /^\s*(?:[-*+]\s+|\d+[.)]\s+)?(?:\*\*)?([A-Za-z][A-Za-z0-9 /&'()-]{0,40}?)(?:\*\*)?\s*:(?:\*\*)?\s+(\S.*)$/;
function keyValueForm(text: string): ParsedSummary | null {
  const lines = text.split('\n');
  const kv = lines.map((l) => KV_LINE.exec(l));
  if (kv.filter(Boolean).length < 2) return null;
  const facets: SummaryFacet[] = [];
  const other: string[] = [];
  lines.forEach((l, i) => {
    const m = kv[i];
    if (m) facets.push({ label: sentenceCase(m[1]!), items: splitTop(m[2]!, ';') });
    else if (l.trim()) other.push(l);
  });
  // The first plain line is the headline; a heading only when there is nothing else to lead with.
  const firstProse = other.findIndex((l) => !/^\s*(#{1,6}\s|[-*+]\s|\d+[.)]\s)/.test(l));
  let headline = '';
  if (firstProse >= 0) {
    const ss = sentences(other[firstProse]!.trim());
    headline = ss[0] ?? '';
    const tail = ss.slice(1).join(' ');
    other.splice(firstProse, 1, ...(tail ? [tail] : []));
  }
  const scope: SummaryScope[] = [];
  const rest = other.filter((l) => {
    const sc = /^\s*#/.test(l) ? null : scopeSentence(l.trim());
    if (sc) { scope.push(...sc); return false; }
    return true;
  });
  return { kind: 'keyvalue', headline, facets, scope, notes: [], more: rest.join('\n').trim() };
}

export function parseSummary(raw: string): ParsedSummary {
  const text = unescapeBreaks(raw ?? '').replace(/\r\n?/g, '\n').trim();
  if (!text) return EMPTY;
  const oneBlock = !text.includes('\n');
  if (oneBlock) {
    const f = facetForm(text);
    if (f) return f;
  }
  const kv = keyValueForm(text);
  if (kv) return kv;
  if (!oneBlock) {
    // Markdown: lead with the first plain sentence; the rest renders as markdown behind the disclosure.
    const lines = text.split('\n');
    const i = lines.findIndex((l) => l.trim() && !/^\s*(#{1,6}\s|[-*+]\s|\d+[.)]\s|>|\||```)/.test(l));
    if (i < 0) return { ...EMPTY, kind: 'markdown', more: text };
    const ss = sentences(lines[i]!.trim());
    const tail = ss.slice(1).join(' ');
    lines.splice(i, 1, ...(tail ? [tail] : []));
    // the facet shape can still be the first paragraph of a longer note
    const f = facetForm(lines[i] ?? '');
    if (f && !tail) {
      lines.splice(i, 1);
      return { ...f, more: lines.join('\n').trim() };
    }
    return { ...EMPTY, kind: 'markdown', headline: ss[0] ?? '', more: lines.join('\n').trim() };
  }
  const ss = sentences(text);
  return { ...EMPTY, kind: 'prose', headline: ss.slice(0, 2).join(' '), more: ss.slice(2).join(' ') };
}

/* ── rendering ── */

function Scope({ scope }: { scope: SummaryScope[] }) {
  if (!scope.length) return null;
  return (
    <div className="rps-scope" aria-label="Scope">
      {scope.map((s, i) => (
        <span key={i} className="rps-scope__chip">
          <span className="rps-scope__k">{s.label}</span>
          {s.items.map((v, j) => <span key={j} className="rps-scope__v">{inlineMd(v, `rsv-${i}-${j}`)}</span>)}
        </span>
      ))}
    </div>
  );
}

export function ReplaySummary({ text, fallback }: { text: string; fallback: string }) {
  const [open, setOpen] = useState(false);
  const p = parseSummary(text);
  if (p.kind === 'empty') return <p className="rp-lede">{fallback}</p>;
  const structured = p.kind === 'facets' || p.kind === 'keyvalue';
  const hasMore = !!p.more;
  // Structured forms always offer the words as written; prose offers the rest when there is a rest.
  const canOpen = structured || hasMore;
  return (
    <div className="rps">
      {p.headline && <p className="rps-head">{inlineMd(p.headline, 'rsh')}</p>}
      {p.facets.length > 0 && (
        <dl className="rps-grid">
          {p.facets.map((f, i) => (
            <div key={i} className="rps-card">
              <dt className="rps-card__k">{f.label}</dt>
              <dd className="rps-card__v">
                {f.items.length === 1
                  ? <span>{inlineMd(f.items[0]!, `rsf-${i}`)}</span>
                  : <ul>{f.items.map((it, j) => <li key={j}>{inlineMd(it, `rsf-${i}-${j}`)}</li>)}</ul>}
              </dd>
            </div>
          ))}
        </dl>
      )}
      <Scope scope={p.scope} />
      {p.notes.map((n, i) => <p key={i} className="rps-note">{inlineMd(n, `rsn-${i}`)}</p>)}
      {canOpen && (
        <div className="rps-more">
          <button type="button" className="rps-more__btn" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
            {open ? 'Hide' : structured ? (hasMore ? 'Show the rest of the summary' : 'Show the summary as written')
              : 'Show full summary'}
          </button>
          {open && (
            <div className="rps-more__body">
              {renderMarkdown(hasMore ? p.more : text)}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
