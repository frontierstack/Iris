/**
 * The pieces of a case-timeline entry that more than one view renders: the list (CaseTimeline) and
 * the replay (TimelineReplay). One copy, so the two views can never word an entry differently.
 */
import { useMemo } from 'react';
import { humanizeStamps } from '../utils/format';
import { renderMarkdown, unescapeBreaks } from '../utils/markdown';

/** The marker that splits a note into its two views. The assistant is told to write it exactly
 *  (`prompts.TIMELINE_NOTE_RULE`); an analyst's hand-written `Why it matters:` line, with or without
 *  the bold and with a dash instead of a colon, splits the same way. */
export const WHY_RE = /(?:^|\n)[ \t]*(?:[-*]\s*)?\*{0,2}why it matters\*{0,2}\s*[:\u2014\u2013-]\s*/i;

/** A note split into what happened (the technical view) and what it means (the high-level one). */
export function splitWhy(note: string): { what: string; matters: string } {
  const src = unescapeBreaks(note);
  const m = WHY_RE.exec(src);
  if (!m) return { what: src, matters: '' };
  return { what: src.slice(0, m.index).trim(), matters: src.slice(m.index + m[0].length).trim() };
}

/** The pace of the sequence: how long after the entry that happened just before it in time this
 *  one happened (`older` is the neighbouring row — above when oldest-first, below when newest-first).
 *  A chronology whose entries are four seconds apart and one whose entries are four days apart look
 *  identical in a list of timestamps, and the difference is usually the finding. */
export function gapLabel(older: string | undefined, cur: string | undefined): string {
  if (!older || !cur) return '';
  const ms = Date.parse(cur) - Date.parse(older);
  if (!Number.isFinite(ms) || ms <= 0) return '';
  const s = Math.round(ms / 1000);
  if (s < 60) return `+${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `+${m}m${s % 60 ? ` ${s % 60}s` : ''}`;
  const h = Math.floor(m / 60);
  if (h < 24) return `+${h}h${m % 60 ? ` ${m % 60}m` : ''}`;
  const d = Math.floor(h / 24);
  return `+${d}d${h % 24 ? ` ${h % 24}h` : ''}`;
}

/** The row's one-line summary of a note. It goes through the same `unescapeBreaks` repair the renderer
 *  uses — a model that double-escapes its tool arguments writes the two characters backslash-n where it
 *  means a line break, and every AI-written note on disk is stored that way — and then its first real
 *  line is taken, with heading and bullet markers stripped, because `## Finding` is not a sentence. */
export function noteLine(note: string): string {
  const first = unescapeBreaks(note).split('\n').map((l) => l.trim()).find(Boolean) ?? '';
  const bare = first.replace(/^#{1,6}\s+/, '').replace(/^[-*+]\s+/, '').replace(/^>\s*/, '');
  // The same stamp repair the renderer applies, and with the same exception: text between backticks
  // is a quoted value and keeps the form the log gave it.
  return bare.split('`').map((seg, i) => (i % 2 === 0 ? humanizeStamps(seg) : seg)).join('`');
}

/** The note as TWO reading surfaces, side by side where there is room: the technical view (why this
 *  line is on the timeline — actor, action, time, outcome, log) and the high-level one (why it
 *  matters to the incident). They answer different readers and used to share one paragraph, with
 *  the second buried as a bullet under the first. A note without the marker is one block. */
export function WhyBlocks({ note }: { note: string }) {
  const { what, matters } = useMemo(() => splitWhy(note), [note]);
  if (!matters) return <div className="tl__note md tlx__why-one">{renderMarkdown(what)}</div>;
  return (
    <div className="tlx__why">
      <div className="tlx__whycol">
        <div className="tlx__whylbl">What happened</div>
        <div className="tl__note md">{renderMarkdown(what)}</div>
      </div>
      <div className="tlx__whycol tlx__whycol--matters">
        <div className="tlx__whylbl">Why it matters</div>
        <div className="tl__note md">{renderMarkdown(matters)}</div>
      </div>
    </div>
  );
}
