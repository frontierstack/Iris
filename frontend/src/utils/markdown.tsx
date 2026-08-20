/** Tiny dependency-free markdown → React renderer for case notes.
 *
 *  Everything is emitted as React elements and text nodes — user text is never fed to
 *  dangerouslySetInnerHTML, so raw HTML in a note renders as literal characters and is inert.
 *  Link/image URLs are allow-listed (http(s), mailto, site-relative), which drops `javascript:`
 *  and `data:` payloads. Supported: #..### headings, **bold**, *italic*, `code`, ``` fences,
 *  - / * bullets and 1. numbers (one level of nesting), > quotes, [text](url), ![alt](url),
 *  --- rules and | pipe | tables.
 */
import type { ReactNode } from 'react';

const URL_OK = /^(?:https?:\/\/|mailto:|\/(?!\/)|\.{1,2}\/)/i;

function safeUrl(raw: string): string | null {
  const u = raw.trim().replace(/^<|>$/g, '');
  return u && URL_OK.test(u) ? u : null;
}

/* code | image | link | bold | italic */
const INLINE = /(`+)([^`]+?)\1|!\[([^\]]*)\]\(([^)\s]+)\)|\[([^\]]*)\]\(([^)\s]+)\)|\*\*([\s\S]+?)\*\*|\*([^*\n]+)\*/g;

/** Inline spans of one line/paragraph. (matchAll clones the regex, so the recursive calls below are safe.) */
export function inlineMd(src: string, key = 'i'): ReactNode[] {
  const out: ReactNode[] = [];
  let last = 0;
  let n = 0;
  for (const m of src.matchAll(INLINE)) {
    const at = m.index ?? 0;
    if (at > last) out.push(src.slice(last, at));
    const k = `${key}-${n++}`;
    if (m[2] !== undefined) out.push(<code key={k} className="md-code">{m[2]}</code>);
    else if (m[3] !== undefined && m[4] !== undefined) {
      const u = safeUrl(m[4]);
      // an unsafe URL (javascript:, data:…) keeps its literal markdown — never becomes a link or an image
      out.push(u ? <img key={k} className="md-img" src={u} alt={m[3]} loading="lazy" /> : <span key={k}>{m[0]}</span>);
    } else if (m[5] !== undefined && m[6] !== undefined) {
      const u = safeUrl(m[6]);
      out.push(u
        ? <a key={k} href={u} target="_blank" rel="noreferrer noopener">{inlineMd(m[5], k)}</a>
        : <span key={k}>{m[0]}</span>);
    } else if (m[7] !== undefined) out.push(<strong key={k}>{inlineMd(m[7], k)}</strong>);
    else if (m[8] !== undefined) out.push(<em key={k}>{inlineMd(m[8], k)}</em>);
    last = at + m[0].length;
  }
  if (last < src.length) out.push(src.slice(last));
  return out;
}

const FENCE = /^\s*```/;
const HEAD = /^(#{1,3})\s+(.*)$/;
const RULE = /^\s*(?:-{3,}|\*{3,}|_{3,})\s*$/;
const QUOTE = /^\s*>\s?(.*)$/;
const BULLET = /^(\s*)[-*]\s+(.*)$/;
const NUMBER = /^(\s*)\d+[.)]\s+(.*)$/;
const TABLE_SEP = /^\s*\|?[\s:|-]*-[\s:|-]*\|?\s*$/;

type Item = { text: string; children: string[] };

function cells(line: string): string[] {
  return line.trim().replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
}

/** One list block (consecutive bullet/number lines); indented lines become a nested list. */
function renderList(lines: string[], ordered: boolean, key: string): ReactNode {
  const items: Item[] = [];
  for (const line of lines) {
    const m = BULLET.exec(line) ?? NUMBER.exec(line);
    const indent = (m?.[1] ?? '').length;
    const text = m?.[2] ?? line.trim();
    const prev = items[items.length - 1];
    if (indent >= 2 && prev) prev.children.push(text);
    else items.push({ text, children: [] });
  }
  const body = items.map((it, i) => (
    <li key={`${key}-${i}`}>
      {inlineMd(it.text, `${key}-${i}`)}
      {it.children.length > 0 && <ul>{it.children.map((c, j) => <li key={j}>{inlineMd(c, `${key}-${i}-${j}`)}</li>)}</ul>}
    </li>
  ));
  return ordered ? <ol key={key}>{body}</ol> : <ul key={key}>{body}</ul>;
}

/**
 * A model that DOUBLE-ESCAPES its tool arguments writes the two characters backslash-n where it means
 * a line break. Measured on the analyst's own case: all four AI-written notes were stored that way —
 * headings, bullets and markdown tables all on ONE line, with the escapes visible in the text. The
 * backend repairs this at the point of writing (`ai/tools._prose`), and this is the same rule at the
 * point of READING, so notes already on disk render correctly without rewriting stored evidence.
 *
 * Deliberately narrow, and identical to the backend's test: only when the text has no real line break
 * of its own and carries at least two escape sequences. A backslash-n inside a quoted log line (a
 * Windows path, a regex) is DATA — a model that double-escapes does it to the whole string, so
 * all-or-nothing is exactly the signal, and anything ambiguous is left alone.
 */
const ESCAPED_BREAK = /\\(?:r\\n|n|r)/g;

export function unescapeBreaks(src: string): string {
  if (src.includes('\n') || src.includes('\r')) return src;
  const hits = src.match(ESCAPED_BREAK);
  return hits && hits.length >= 2 ? src.replace(ESCAPED_BREAK, '\n').replace(/\\t/g, '\t') : src;
}

/** Parse markdown into React nodes. */
export function renderMarkdown(src: string): ReactNode {
  const lines = unescapeBreaks(src ?? '').replace(/\r\n?/g, '\n').split('\n');
  const out: ReactNode[] = [];
  let i = 0;
  const key = () => `b${out.length}`;

  while (i < lines.length) {
    const line = lines[i] ?? '';

    if (FENCE.test(line)) {                                   // ``` fenced code
      const lang = line.replace(/^\s*```/, '').trim();
      const body: string[] = [];
      i++;
      while (i < lines.length && !FENCE.test(lines[i] ?? '')) { body.push(lines[i] ?? ''); i++; }
      i++;   // step over the closing fence
      out.push(<pre key={key()} className="md-pre" data-lang={lang || undefined}><code>{body.join('\n')}</code></pre>);
      continue;
    }
    if (!line.trim()) { i++; continue; }
    if (RULE.test(line)) { out.push(<hr key={key()} className="md-hr" />); i++; continue; }

    const h = HEAD.exec(line);
    if (h) {
      const level = (h[1] ?? '#').length;
      const text = inlineMd(h[2] ?? '', key());
      out.push(level === 1 ? <h3 key={key()} className="md-h1">{text}</h3>
        : level === 2 ? <h4 key={key()} className="md-h2">{text}</h4>
          : <h5 key={key()} className="md-h3">{text}</h5>);
      i++;
      continue;
    }

    if (QUOTE.test(line)) {                                   // > blockquote
      const body: string[] = [];
      while (i < lines.length && QUOTE.test(lines[i] ?? '')) {
        body.push(QUOTE.exec(lines[i] ?? '')?.[1] ?? '');
        i++;
      }
      out.push(<blockquote key={key()} className="md-quote">{inlineMd(body.join(' '), key())}</blockquote>);
      continue;
    }

    // | pipe | table | — header row followed by a --- separator row
    if (line.includes('|') && TABLE_SEP.test(lines[i + 1] ?? '') && (lines[i + 1] ?? '').includes('|')) {
      const head = cells(line);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && (lines[i] ?? '').includes('|') && (lines[i] ?? '').trim()) {
        rows.push(cells(lines[i] ?? ''));
        i++;
      }
      const k = key();
      out.push(
        <div key={k} className="md-tablewrap">
          <table className="md-table">
            <thead><tr>{head.map((c, j) => <th key={j}>{inlineMd(c, `${k}h${j}`)}</th>)}</tr></thead>
            <tbody>
              {rows.map((r, ri) => (
                <tr key={ri}>{head.map((_, ci) => <td key={ci}>{inlineMd(r[ci] ?? '', `${k}${ri}-${ci}`)}</td>)}</tr>
              ))}
            </tbody>
          </table>
        </div>,
      );
      continue;
    }

    const ordered = NUMBER.test(line);
    if (ordered || BULLET.test(line)) {
      const body: string[] = [];
      while (i < lines.length && (BULLET.test(lines[i] ?? '') || NUMBER.test(lines[i] ?? ''))) {
        body.push(lines[i] ?? '');
        i++;
      }
      out.push(renderList(body, ordered, key()));
      continue;
    }

    const para: string[] = [];                                // plain paragraph
    while (i < lines.length) {
      const l = lines[i] ?? '';
      if (!l.trim() || FENCE.test(l) || HEAD.test(l) || RULE.test(l) || QUOTE.test(l) || BULLET.test(l) || NUMBER.test(l)) break;
      para.push(l);
      i++;
    }
    out.push(<p key={key()} className="md-p">{inlineMd(para.join('\n'), key())}</p>);
  }
  return <>{out}</>;
}
