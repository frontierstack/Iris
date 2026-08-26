/** Tiny dependency-free markdown → React renderer for case notes.
 *
 *  Everything is emitted as React elements and text nodes — user text is never fed to
 *  dangerouslySetInnerHTML, so raw HTML in a note renders as literal characters and is inert.
 *  Link/image URLs are allow-listed (http(s), mailto, site-relative), which drops `javascript:`
 *  and `data:` payloads. Supported: #..###### headings, **bold**, *italic*, ~~strike~~, `code`,
 *  ``` fences, - / * bullets and 1. numbers (nested to any depth, each level keeping its own
 *  ordered/unordered kind), - [ ] / - [x] task lines, > quotes, [text](url), ![alt](url),
 *  --- rules and | pipe | tables (with :--: column alignment).
 *
 *  This is what an AI-written case note is made of, so the vocabulary here is the vocabulary the
 *  `add_note` tool description promises the model — the two must not drift. Anything unsupported
 *  degrades to its literal characters, which is honest: a note is evidence and must never be
 *  silently rewritten by its renderer.
 */
import type { ReactNode } from 'react';

const URL_OK = /^(?:https?:\/\/|mailto:|\/(?!\/)|\.{1,2}\/)/i;

function safeUrl(raw: string): string | null {
  const u = raw.trim().replace(/^<|>$/g, '');
  return u && URL_OK.test(u) ? u : null;
}

/* code | image | link | bold | italic | strike */
const INLINE = /(`+)([^`]+?)\1|!\[([^\]]*)\]\(([^)\s]+)\)|\[([^\]]*)\]\(([^)\s]+)\)|\*\*([\s\S]+?)\*\*|\*([^*\n]+)\*|~~([\s\S]+?)~~/g;

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
    else if (m[9] !== undefined) out.push(<del key={k} className="md-del">{inlineMd(m[9], k)}</del>);
    last = at + m[0].length;
  }
  if (last < src.length) out.push(src.slice(last));
  return out;
}

const FENCE = /^\s*```/;
const HEAD = /^(#{1,6})\s+(.*)$/;
const RULE = /^\s*(?:-{3,}|\*{3,}|_{3,})\s*$/;
const QUOTE = /^\s*>\s?(.*)$/;
const BULLET = /^(\s*)[-*]\s+(.*)$/;
const NUMBER = /^(\s*)\d+[.)]\s+(.*)$/;
const TABLE_SEP = /^\s*\|?[\s:|-]*-[\s:|-]*\|?\s*$/;
/** `- [ ] still to do` / `- [x] done` — a checklist line, once its bullet marker has been eaten. */
const TASK = /^\[([ xX])\]\s+(.*)$/;

function cells(line: string): string[] {
  return line.trim().replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
}

/** Column alignment declared by the separator row: `:--` left, `--:` right, `:-:` centre. */
type Align = 'left' | 'center' | 'right' | undefined;

function alignsOf(sep: string): Align[] {
  return cells(sep).map((c) => {
    const l = c.startsWith(':');
    const r = c.endsWith(':');
    return l && r ? 'center' : r ? 'right' : l ? 'left' : undefined;
  });
}

/* ── lists ──
 * A single flat pass could only ever manage one level of nesting, and an analyst's write-up nests:
 * a finding, its evidence, the event ids under that. Lines are read into rows carrying their own
 * indent, folded into a TREE, and rendered from it — so each level keeps its own ordered/unordered
 * kind (numbered evidence under a bulleted finding renders as <ol> inside <li>, not as another <ul>).
 */
type Row = { indent: number; ordered: boolean; text: string };
type ListItem = { text: string; kids: ListTree[] };
type ListTree = { ordered: boolean; items: ListItem[] };

function rowsOf(lines: string[]): Row[] {
  return lines.map((line) => {
    const n = NUMBER.exec(line);
    if (n) return { indent: (n[1] ?? '').length, ordered: true, text: n[2] ?? '' };
    const b = BULLET.exec(line);
    return { indent: (b?.[1] ?? '').length, ordered: false, text: b?.[2] ?? line.trim() };
  });
}

/** Fold the rows at `indent` (and everything deeper) into one tree; returns it and the next row. */
function foldList(rows: Row[], from: number, indent: number): [ListTree, number] {
  const tree: ListTree = { ordered: rows[from]!.ordered, items: [] };
  let i = from;
  while (i < rows.length) {
    const r = rows[i]!;
    if (r.indent < indent) break;
    if (r.indent > indent) {                                   // deeper: a sub-list of the last item
      const [kid, next] = foldList(rows, i, r.indent);
      const last = tree.items[tree.items.length - 1];
      if (last) last.kids.push(kid);
      else tree.items.push({ text: '', kids: [kid] });
      i = next;
      continue;
    }
    // A marker CHANGE at the same indent is a new list, not a new item — but only once this one has
    // something in it, or `foldList` could return without consuming a row and the caller would spin.
    if (r.ordered !== tree.ordered && tree.items.length) break;
    tree.items.push({ text: r.text, kids: [] });
    i++;
  }
  return [tree, i];
}

function renderTree(t: ListTree, key: string): ReactNode {
  let checklist = false;
  const body = t.items.map((it, i) => {
    const task = TASK.exec(it.text);
    if (task) checklist = true;
    const k = `${key}-${i}`;
    return (
      <li key={k} className={task ? 'md-task' : undefined}>
        {task ? (
          <>
            {/* readOnly + disabled: a rendered note is a record, not a form. It shows state, never takes it. */}
            <input type="checkbox" className="md-check" checked={(task[1] ?? '').toLowerCase() === 'x'} readOnly disabled />
            {/* The text is ONE flex item. Without this wrapper every inline span — a `code` chip, a
                bold run — becomes a flex child of its own and the line breaks between them. */}
            <span className="md-task__text">{inlineMd(task[2] ?? '', k)}</span>
          </>
        ) : inlineMd(it.text, k)}
        {it.kids.map((kid, j) => renderTree(kid, `${k}-${j}`))}
      </li>
    );
  });
  return t.ordered
    ? <ol key={key}>{body}</ol>
    : <ul key={key} className={checklist ? 'md-checklist' : undefined}>{body}</ul>;
}

/** One list block (consecutive bullet/number lines), nested to whatever depth it carries. */
function renderList(lines: string[], key: string): ReactNode {
  const rows = rowsOf(lines);
  const out: ReactNode[] = [];
  let i = 0;
  while (i < rows.length) {
    const [tree, next] = foldList(rows, i, rows[i]!.indent);
    out.push(renderTree(tree, `${key}-${i}`));
    i = next;
  }
  return out.length === 1 ? out[0] : <div key={key} className="md-lists">{out}</div>;
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
      // #### and deeper share the smallest step: a note is a POST, not a document with six levels.
      const level = Math.min(3, (h[1] ?? '#').length);
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
      const align = alignsOf(lines[i + 1] ?? '');
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && (lines[i] ?? '').includes('|') && (lines[i] ?? '').trim()) {
        rows.push(cells(lines[i] ?? ''));
        i++;
      }
      const k = key();
      out.push(
        // The SCROLLER is this wrapper — never the page and never each row (the repo's CSS gotcha).
        <div key={k} className="md-tablewrap" role="region" tabIndex={0} aria-label="table">
          <table className="md-table">
            <thead>
              <tr>{head.map((c, j) => (
                <th key={j} style={align[j] ? { textAlign: align[j] } : undefined}>{inlineMd(c, `${k}h${j}`)}</th>
              ))}</tr>
            </thead>
            <tbody>
              {rows.map((r, ri) => (
                <tr key={ri}>{head.map((_, ci) => (
                  <td key={ci} style={align[ci] ? { textAlign: align[ci] } : undefined}>
                    {inlineMd(r[ci] ?? '', `${k}${ri}-${ci}`)}
                  </td>
                ))}</tr>
              ))}
            </tbody>
          </table>
        </div>,
      );
      continue;
    }

    if (NUMBER.test(line) || BULLET.test(line)) {
      const body: string[] = [];
      while (i < lines.length && (BULLET.test(lines[i] ?? '') || NUMBER.test(lines[i] ?? ''))) {
        body.push(lines[i] ?? '');
        i++;
      }
      out.push(renderList(body, key()));
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
