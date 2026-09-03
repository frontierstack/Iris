/**
 * The AI assistant panel: one free-text objective, a live conversation, and the history of every
 * conversation this workspace has had.
 *
 * THE SURFACE IS THE "MODERN AI ASSISTANT CHAT INTERFACE" TEMPLATE, transcribed — composition,
 * typography, shapes, sizes, spacing and interactions come from `.template-extract-ai/Assistant
 * Chat.dc.html`. What that buys, in the order it is read: a 58px header carrying a brand lozenge and
 * a serif wordmark; a CENTRED 792px thread column with 34px between messages; the objective as a
 * right-aligned BUBBLE with the 20/20/7/20 corner; THE ANSWER SET IN A SERIF at 19px/1.66, which is
 * the one thing that makes this read like a document rather than a console; an unnumbered,
 * collapsible steps card behind a 1px left rule; an artifact card for what the run changed; and a
 * 22px-radius composer pinned to the bottom of the scroller with a 34px round send button that
 * becomes a stop square while a run is live. The one deliberate deviation is COLOUR: every value in
 * `styles/ai-panel.css` is an Iris theme token, never the template's own hexes, so the panel belongs
 * to the same app as every other screen. Two places the product rules outrank the design and win:
 * the empty state offers NO canned suggestion pills (one free-text objective is a standing
 * instruction), and a WARNING is rendered outside the steps card and is never folded.
 *
 * There are deliberately NO suggested prompts. The analyst says what they want in their own words
 * ("trace everything to do with 45.83.140.22 and build me a case") and the agent carries it out with
 * the app's own tools.
 *
 * Four things this screen owes the analyst, all non-negotiable for an evidence tool:
 *   • the conversation SURVIVES a refresh, a tab switch and a server restart — it lives in
 *     `$IRIS_DATA_DIR/ai/history.json`, not in this component's state;
 *   • a Stop that actually stops the run server-side, reachable for the WHOLE duration of a run
 *     (it lives in the sticky composer, not in a metadata row that scrolls out of sight);
 *   • a visible, reversible record of everything the agent changed in the case; and
 *   • unresolved event ids called out, not buried.
 *
 * A CONVERSATION, NOT A SEQUENCE OF ONE-SHOTS. Typing into an open chat CONTINUES it: the follow-up
 * is a new run carrying `continueFrom`, so the server seeds it with what the earlier turns established
 * instead of re-investigating from scratch (the analyst's report was that asking it to continue made it
 * "redo the entire analysis"). The panel renders the whole thread — every turn, its answer and its
 * changes — because the run stays the unit of UNDO: "revert what it just did" has to mean one turn, and
 * a conversation-wide revert button would take back work the analyst kept.
 *
 * REJOINING A RUN. `POST /api/ai/investigate` now drives a background task and the SSE response is
 * only a live tail of it, so closing the panel or refreshing does not kill the investigation. The tab
 * that started a run reads it over SSE (per-token prose); any other tab, and this one after a refresh,
 * rejoins by POLLING `GET /api/ai/runs/{id}?since=<seq>`. Both write into the same
 * `AiTranscriptEntry[]`, so there is one renderer, not two.
 */
import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import type { AiAction, AiInvestigateRequest, AiRun, AiRunEvent, AiTranscriptEntry } from '../api/types';
import { qk, useSettings } from '../hooks/queries';
import { useToast } from '../hooks/useToast';
import { cx, errMsg } from '../utils/format';
import { renderMarkdown } from '../utils/markdown';
import { FloatingWindow } from './FloatingWindow';
import { PromptPicker } from './PromptPicker';
import { Icon } from './icons';
// The context, the `useAiPanel` hook and this type live in AiPanelContext.tsx, which is what the app
// imports. This module is loaded only when the panel is actually opened — see the note there.
import type { AiTarget } from './AiPanelContext';

const POLL_MS = 900;
/**
 * HOW STREAMED PROSE REACHES THE SCREEN.
 *
 * Tokens do not arrive evenly: a provider sends them in bursts, and the gaps between bursts are the
 * model thinking, the network, or Iris running a tool. Committing each burst as it lands — which a
 * fixed 90 ms timer effectively did — reproduces that shape exactly, so the report appeared as lumps
 * of a paragraph separated by stalls. That is what "very jumpy" is: the cadence of the wire, painted.
 *
 * So arrival is decoupled from painting. Deltas go into a buffer, and one requestAnimationFrame loop
 * drains a SLICE of it per frame, sized by how far behind the screen is (`elapsed / SMOOTH_MS` of what
 * is waiting). A burst therefore plays out over a few frames instead of landing at once, a trickle
 * still moves every frame, and the buffer can never fall further behind than that time constant —
 * it is a smoothing filter, not a queue. Painting is on the frame clock, which is the only clock the
 * screen actually has.
 *
 * A frame is only affordable because the transcript around the growing paragraph does not re-render:
 * `Markdown`, `ToolCall` and `StepsCard` are all memoised, so a commit re-parses the one block
 * that changed. Take those memos away and this rate becomes a stutter of a different kind.
 */
const STREAM_SMOOTH_MS = 130;

/**
 * DOCKED OR DETACHED, and the choice is remembered.
 *
 * The panel is a modal slide-over: it covers the right of the screen and an overlay takes every click
 * behind it. That is wrong for THIS panel specifically — the whole value of watching a run is reading
 * the evidence it cites while it works, and the docked panel makes that two alternating screens (open
 * the panel, read the answer, close it, find the event, open it again). Detached it is a window: put
 * it beside the search results, size it to the transcript, and the page underneath stays live.
 *
 * Same primitive as the raw log viewer (`FloatingWindow`), same storage-key convention, so the
 * geometry survives a close and a reload — re-arranging the window on every open is its own annoyance.
 */
const AI_DETACHED_KEY = 'iris.ai.detached';
const SP_KEY = 'iris.ai.systemPrompt';   // the composer's system-prompt choice; absent = the settings default

/**
 * THE TEMPLATE'S RIGHT-HAND CANVAS EXISTS ONLY WHERE THERE IS ROOM.
 *
 * The template puts a 470px panel on its own darker ground beside the thread; here that panel is the
 * conversation HISTORY. 470px of canvas next to 90px of thread is neither of them, so below this
 * width the history takes the panel instead — the same doctrine the tool rail was built on, and the
 * reason the number is a measurement rather than a breakpoint: 470 of canvas + 330 of readable
 * thread + the gutters.
 */
const CANVAS_MIN_CONTENT = 880;

/**
 * Which tools change the case. The PERSISTED transcript carries `writes` on every tool entry, but the
 * live `tool_call` SSE event does not, so the panel needs its own answer while a run is streaming —
 * and a write mislabelled as a read is exactly the distinction this screen exists to make. The real
 * set is fetched once from GET /api/ai/tools (that IS the registry); this literal is only the fallback
 * when that call fails, and it must stay in step with `writes=True` in backend/app/ai/tools.py.
 */
const WRITE_TOOLS = new Set([
  'create_case', 'update_case', 'activate_case',
  'add_events_to_case', 'remove_events_from_case', 'annotate_case_event', 'annotate_case_events',
  'add_ioc', 'update_ioc', 'delete_ioc',
  'add_note', 'update_note', 'delete_note',
  'add_graph_link', 'delete_graph_link', 'build_case_graph',
  'create_detection_rule', 'update_detection_rule', 'delete_detection_rule',
  'set_detection_rule_enabled', 'set_builtin_rule_params',
  'add_exclusion', 'delete_exclusion',
  // NOT preview_detection_rule: a dry run saves nothing and changes nothing on the case.
]);

function focusOf(t: AiTarget): string | undefined {
  if (t.scope === 'event' && t.id) return `event ${t.id}`;
  if (t.scope === 'cluster' && t.id) return `incident cluster ${t.id}${t.label ? ` (${t.label})` : ''}`;
  if (t.scope === 'selection' && t.eventIds?.length) return `a selection of ${t.eventIds.length} events: ${t.eventIds.slice(0, 20).join(', ')}`;
  if (t.scope === 'selection' && t.label) return t.label;
  return undefined;
}

/** One argument, rendered as a value rather than dumped: an array says what is in it and how many. */
function argValue(v: unknown): string {
  if (v === null || v === undefined || v === '') return '';
  if (Array.isArray(v)) {
    if (!v.length) return '';
    const head = v.slice(0, 6).map((x) => (typeof x === 'object' ? JSON.stringify(x) : String(x))).join(', ');
    return v.length > 6 ? `${head}, … (${v.length} in all)` : head;
  }
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

/** Tool arguments as key/value rows — a labelled list, not one run-on line. */
function argRows(args: Record<string, unknown>): Array<{ k: string; v: string }> {
  const out: Array<{ k: string; v: string }> = [];
  for (const [k, raw] of Object.entries(args ?? {})) {
    const v = argValue(raw);
    if (v) out.push({ k, v });
  }
  return out;
}

/** How many argument rows a call shows before it needs to be asked for the rest. */
const ARGS_SHOWN = 2;

function blank(seq: number, kind: AiTranscriptEntry['kind']): AiTranscriptEntry {
  return { seq, kind, text: '', step: 0, id: '', name: '', args: {}, writes: false, ok: null, summary: '', tookMs: 0 };
}

/** Merge a server tail (or a locally-built entry) into the transcript, keyed on `seq`. */
function mergeEntries(prev: AiTranscriptEntry[], incoming: AiTranscriptEntry[]): AiTranscriptEntry[] {
  if (!incoming.length) return prev;
  const bySeq = new Map(prev.map((e) => [e.seq, e]));
  for (const e of incoming) bySeq.set(e.seq, e);
  return [...bySeq.values()].sort((a, b) => a.seq - b.seq);
}

/**
 * The polling cursor. A streamed prose entry is COALESCED server-side — it keeps the same `seq` while
 * it grows — so asking for `since = lastSeq` would never see the rest of the paragraph being written.
 * While a run is live we therefore re-request the last entry each tick and let the merge replace it.
 */
function cursorOf(entries: AiTranscriptEntry[], live: boolean): number {
  const last = entries[entries.length - 1];
  if (!last) return 0;
  return live && last.kind === 'text' ? Math.max(0, last.seq - 1) : last.seq;
}

/** Relative time is a HOVER in this app, never a label — a conversation is read back weeks later. */
const RELATIVE = (iso: string): string => {
  if (!iso) return '';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
};

/** The label the analyst actually reads: full, and marked UTC. */
const UTC = (iso: string): string => {
  if (!iso) return '';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  return `${new Date(t).toISOString().slice(0, 16).replace('T', ' ')} UTC`;
};

/** How long the run took, for the run's own footer. */
function spanOf(from: string, to: string): string {
  const t0 = Date.parse(from);
  const t1 = to ? Date.parse(to) : Date.now();
  if (Number.isNaN(t0) || Number.isNaN(t1) || t1 < t0) return '';
  const s = Math.round((t1 - t0) / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  return s % 60 ? `${m}m ${s % 60}s` : `${m}m`;
}

const STATE_LABEL: Record<AiRun['state'], string> = {
  running: 'running', done: 'complete', stopped: 'stopped', error: 'failed',
};

/** Copy to the clipboard, quietly. There is no fallback worth the code: every target browser has it. */
async function copyText(t: string): Promise<boolean> {
  try { await navigator.clipboard.writeText(t); return true; } catch { return false; }
}

/* ─────────────────────────────────── structure ───────────────────────────────────
 * FOUR kinds of thing arrive on one stream and they do not weigh the same, so they are not drawn the
 * same: prose is the answer, a WRITE changed the analyst's case, a read did not, and a warning is an
 * evidence-integrity signal. Reads are quiet rows on the steps card, writes carry the accent rail and
 * are ALSO listed in the artifact card with a Revert, warnings are bordered and are never folded.
 *
 * There are no "step 1 / step 2 / … / step 19" labels: the analyst reads them as noise, and the
 * template's own steps card is unnumbered. The sequence is carried structurally instead — one row per
 * call in order behind a 1px rule, and a model turn boundary (`kind:'step'`) becomes a BREAK in that
 * rule rather than a numbered line.
 */
type Block =
  | { kind: 'activity'; key: number; entries: AiTranscriptEntry[] }
  | { kind: 'prose'; key: number; text: string }
  | { kind: 'warning'; key: number; text: string };

function toBlocks(entries: AiTranscriptEntry[]): Block[] {
  const out: Block[] = [];
  for (const e of entries) {
    if (e.kind === 'text') {
      out.push({ kind: 'prose', key: e.seq, text: e.text });
    } else if (e.kind === 'warning') {
      out.push({ kind: 'warning', key: e.seq, text: e.text });
    } else {
      const last = out[out.length - 1];
      if (last && last.kind === 'activity') last.entries.push(e);
      else out.push({ kind: 'activity', key: e.seq, entries: [e] });
    }
  }
  return out;
}

/**
 * One row of the steps card. `turn` marks the first node after a model-turn boundary — that gap is
 * what replaced the step numbers, so a reader can still see where one round of thinking ended.
 */
type TrailNode =
  | { k: 'tool'; key: number; e: AiTranscriptEntry; turn: boolean; lead: string }
  | { k: 'note'; key: number; text: string; turn: boolean }
  | { k: 'prose'; key: number; text: string; turn: boolean };

function trailNodes(blocks: Block[]): TrailNode[] {
  const out: TrailNode[] = [];
  let turn = false;
  for (const b of blocks) {
    if (b.kind === 'warning') continue;            // never folded into the card — rendered on its own
    if (b.kind === 'prose') {
      if (b.text.trim()) out.push({ k: 'prose', key: b.key, text: b.text, turn });
      turn = false;
      continue;
    }
    for (const e of b.entries) {
      if (e.kind === 'step') { turn = out.length > 0; continue; }   // a break, not a numbered line
      if (e.kind === 'status') {
        if (e.text.trim()) { out.push({ k: 'note', key: e.seq, text: e.text, turn }); turn = false; }
        continue;
      }
      // The model narrates what it is looking for in the SAME turn as the call (see the NARRATE
      // section of INVESTIGATOR_SYSTEM), so that sentence arrives as prose immediately before this
      // tool call. It is ABOUT this call — left as its own node it read as a floating remark one card
      // above the thing it explains, so it is folded into the card as its lead line. Only the prose
      // directly ahead of the call, and only within the same turn, is claimed this way; a sentence
      // that follows a result stays where it is, because there it is the conclusion drawn from it.
      const prev = out[out.length - 1];
      let lead = '';
      if (prev && prev.k === 'prose' && !turn) { lead = prev.text; out.pop(); }
      out.push({ k: 'tool', key: e.seq, e, turn: lead ? prev!.turn : turn, lead });
      turn = false;
    }
  }
  return out;
}

/**
 * Markdown, parsed only when ITS OWN text changes.
 *
 * The transcript re-renders on every streamed token, and `renderMarkdown` re-parses whatever it is
 * handed — so a run holding thirty tool cards and several paragraphs re-parsed all of them for each
 * token of the closing report. That is what "the response generation is very jumpy when the assistant
 * is building the summary" was: the paragraph being written is one small string, and the work being
 * redone around it was the whole conversation. Memoised on (text, className), the only block that
 * re-parses is the one actually growing.
 */
const Markdown = memo(function Markdown({ text, className }: { text: string; className: string }) {
  return <div className={className}>{renderMarkdown(text)}</div>;
});

/**
 * What a write DID, in the analyst's words — not the tool that did it.
 *
 * The row used to print the raw tool name under the summary: `create_case`, `annotate_case_events`.
 * That is the function Iris called, which is an implementation detail the analyst did not ask about
 * and cannot act on; snake_case in a column of prose reads as debug output left in by accident. The
 * summary above it already says WHAT happened ("created case CASE-0002 '…'"); this says what KIND of
 * change it was, so the list can be scanned for "did it write any indicators?" without reading every
 * line. Every write tool in `ai/tools.REGISTRY` is covered explicitly — a name that is not is shown
 * with its underscores opened up rather than as a raw identifier, so a tool added later degrades to
 * readable English instead of leaking a symbol.
 */
const WRITE_LABEL: Record<string, string> = {
  create_case: 'created a case',
  activate_case: 'switched case',
  update_case: 'updated the case',
  add_note: 'added a note',
  update_note: 'edited a note',
  delete_note: 'removed a note',
  add_ioc: 'added an indicator',
  update_ioc: 'edited an indicator',
  delete_ioc: 'removed an indicator',
  add_events_to_case: 'added events to the case',
  remove_events_from_case: 'removed events from the case',
  annotate_case_event: 'annotated a timeline entry',
  annotate_case_events: 'annotated timeline entries',
  add_graph_link: 'added a graph link',
  build_case_graph: 'drew the case graph',
  delete_graph_link: 'removed a graph link',
  create_detection_rule: 'created a detection rule',
  update_detection_rule: 'edited a detection rule',
  delete_detection_rule: 'removed a detection rule',
  set_detection_rule_enabled: 'enabled or disabled a rule',
  set_builtin_rule_params: 'tuned a built-in rule',
  add_exclusion: 'added an exclusion',
  delete_exclusion: 'removed an exclusion',
};

function writeLabel(tool: string): string {
  return WRITE_LABEL[tool] ?? tool.replace(/_/g, ' ');
}

/** A restrained line icon per tool FAMILY — the same glyph the screen that owns that data uses. */
function toolIcon(name: string): typeof Icon.Doc {
  if (name.includes('note')) return Icon.Note;
  if (name.includes('graph')) return Icon.Graph;
  if (name.includes('rule') || name.includes('detection') || name.includes('anomal')) return Icon.Anomalies;
  if (name.includes('ioc') || name.includes('indicator')) return Icon.Findings;
  if (name.includes('case')) return Icon.Cases;
  if (name.includes('timeline')) return Icon.Timeline;
  if (name.includes('source') || name.includes('field')) return Icon.Sources;
  if (name.includes('search') || name.includes('event') || name.includes('count')
      || name.includes('aggregate') || name.includes('distinct') || name.includes('sample')) return Icon.Search;
  return Icon.Doc;
}

/* ─────────────────────────────────── pieces ─────────────────────────────────── */

/** A mono uppercase micro-button — the template's action treatment under a message. */
function Micro({ label, onClick, title }: { label: string; onClick: () => void; title?: string }) {
  return (
    <button type="button" className="aic-micro" onClick={onClick} title={title}>{label}</button>
  );
}

/** Copy, with the label saying it worked. Used under the objective and under the answer. */
function CopyMicro({ text, what }: { text: string; what: string }) {
  const [done, setDone] = useState(false);
  const timer = useRef(0);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  return (
    <Micro
      label={done ? 'Copied' : 'Copy'}
      title={`Copy ${what}`}
      onClick={() => {
        void copyText(text).then((ok) => {
          if (!ok) return;
          setDone(true);
          window.clearTimeout(timer.current);
          timer.current = window.setTimeout(() => setDone(false), 1600);
        });
      }}
    />
  );
}

/**
 * One tool call AND its result in ONE card. They used to be two lines with nothing binding them, so a
 * long run read as alternating noise; the arguments are a labelled list and the outcome is a row of
 * its own with a glyph, so "what was asked" and "what came back" are readable at a glance.
 */
const ToolCall = memo(function ToolCall({ e, live, lead = '' }: { e: AiTranscriptEntry; live: boolean; lead?: string }) {
  const [open, setOpen] = useState(false);
  const rows = argRows(e.args ?? {});
  const shown = open ? rows : rows.slice(0, ARGS_SHOWN);
  const hidden = rows.length - shown.length;
  const Glyph = toolIcon(e.name);
  const bad = e.ok === false;
  return (
    <div className={cx('tcall', e.writes && 'tcall--write', bad && !e.writes && 'tcall--bad')}>
      {!!lead.trim() && <Markdown className="md tcall__lead" text={lead} />}
      {/* There is ONE card and ONE head, so `e.writes` is read here and nowhere else — the rule that
          stops one layout drawing a write as a read. Keep it that way if a variant is ever added. */}
      <div className="tcall__head">
        <Glyph className="tcall__glyph" />
        <span className="tcall__name">{e.name}</span>
        {e.writes && <span className="tcall__kind" title="this tool changed the case">write</span>}
        {e.ok === null && live && <span className="spinner" style={{ width: 9, height: 9, borderWidth: 1.5 }} />}
        {e.ok === null && !live && <span className="tcall__unknown" title="the run ended before this call reported back">—</span>}
        {!!e.tookMs && <span className="tcall__ms">{e.tookMs} ms</span>}
      </div>

      {!!shown.length && (
        <dl className="tcall__args">
          {shown.map((r) => (
            <div className="tcall__arg" key={r.k}>
              <dt>{r.k}</dt>
              <dd title={r.v}>{r.v}</dd>
            </div>
          ))}
        </dl>
      )}
      {(hidden > 0 || open) && rows.length > ARGS_SHOWN && (
        <button type="button" className="tcall__more" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
          {open ? 'fewer arguments' : `${hidden} more argument${hidden === 1 ? '' : 's'}`}
        </button>
      )}

      <div className={cx('tcall__result', bad && 'tcall__result--bad')}>
        {e.ok === null ? (
          <span className="tcall__pending">{live ? 'waiting for the result…' : 'no result recorded'}</span>
        ) : (
          <>
            {bad ? <Icon.Warn /> : <Icon.Check />}
            <span>{bad ? `refused — ${e.summary}` : (e.summary || 'done')}</span>
          </>
        )}
      </div>
    </div>
  );
});

/**
 * A trail node is a NEW object on every render — `trailNodes` rebuilds them from the transcript — so
 * the memos below compare what a node is MADE OF, not the wrapper. The transcript entry itself is
 * stable (it is replaced, never mutated, when its result lands), which is what makes `n.e === m.e` the
 * right test: a card re-renders exactly when its own call changes and at no other time.
 */
function sameNode(a: TrailNode, b: TrailNode): boolean {
  if (a.k !== b.k || a.key !== b.key || a.turn !== b.turn) return false;
  if (a.k === 'tool') return b.k === 'tool' && a.e === b.e && a.lead === b.lead;
  return a.text === (b as { text: string }).text;
}

/** The counts that head the steps card — one sentence, computed in one place. */
function countsOf(nodes: TrailNode[]): { bits: string[]; pending: boolean; tools: number } {
  const tools = nodes.filter((n): n is Extract<TrailNode, { k: 'tool' }> => n.k === 'tool');
  const writes = tools.filter((t) => t.e.writes).length;
  const failed = tools.filter((t) => t.e.ok === false).length;
  const bits: string[] = [];
  if (tools.length) bits.push(`${tools.length} tool call${tools.length === 1 ? '' : 's'}`);
  else if (nodes.length) bits.push(`${nodes.length} note${nodes.length === 1 ? '' : 's'}`);
  if (writes) bits.push(`${writes} write${writes === 1 ? '' : 's'}`);
  if (failed) bits.push(`${failed} refused`);
  return { bits, pending: tools.some((t) => t.e.ok === null), tools: tools.length };
}

/**
 * THE STEPS CARD — the template's collapsible activity block, and the audit trail of the run.
 * Deliberately secondary once the answer exists, but never hidden, because it is how the answer was
 * reached. Unnumbered: the rule down its left edge carries the order, and a break in that rule is
 * where one model turn ended.
 */
const StepsCard = memo(function StepsCard({ nodes, live, title, startOpen }: {
  nodes: TrailNode[]; live: boolean; title: string; startOpen: boolean;
}) {
  const [open, setOpen] = useState(startOpen);
  if (!nodes.length) return null;

  const tools = nodes.filter((n): n is Extract<TrailNode, { k: 'tool' }> => n.k === 'tool');
  // Nothing was CALLED — this is just the agent saying something (the opening line, a compaction
  // notice). Wrapping one sentence in a collapsible card labelled "0 tool calls" is chrome, not
  // structure, so it is rendered plainly.
  if (!tools.length) {
    return (
      <div className="aic-bare">
        {nodes.map((n) => (n.k === 'prose'
          ? <Markdown key={n.key} className="md aic-prose aic-prose--quiet" text={n.text} />
          // A note is a NOTE BODY: markdown, written by the agent, and often a table. Rendering it
          // raw made HTML collapse the newlines, so `| a | b |` rows ran together into one line of
          // pipes — the same class of bug CLAUDE.md records for NoteRow. Every surface that shows a
          // note body goes through renderMarkdown.
          : <Markdown key={n.key} className="md aic-bare__note" text={n.k === 'note' ? n.text : ''} />))}
      </div>
    );
  }

  const { bits, pending } = countsOf(nodes);

  return (
    <section className="aic-steps">
      <button type="button" className="aic-steps__head" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
        <span className={cx('aic-steps__dot', pending && live ? 'aic-steps__dot--live' : !live && 'aic-steps__dot--idle')} aria-hidden />
        <span className="aic-steps__sum">{title}{bits.length ? ` · ${bits.join(' · ')}` : ''}</span>
        <Icon.Chevron className={cx('aic-steps__chev', open && 'aic-steps__chev--open')} />
      </button>
      {open && (
        <div className="aic-steps__body">
          {nodes.map((n) => (
            <div key={n.key} className={cx('aic-step', n.turn && 'aic-step--turn')}>
              {n.k === 'tool' && <ToolCall e={n.e} live={live} lead={n.lead} />}
              {n.k === 'note' && <Markdown className="md aic-bare__note" text={n.text} />}
              {n.k === 'prose' && <Markdown className="md aic-prose aic-prose--quiet" text={n.text} />}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}, (a, b) => (
  a.live === b.live && a.title === b.title && a.startOpen === b.startOpen &&
  a.nodes.length === b.nodes.length && a.nodes.every((n, i) => sameNode(n, b.nodes[i]!))
));

/** An evidence-integrity signal. Never folded, never subdued — see the panel's header comment. */
function Warning({ text }: { text: string }) {
  return (
    <div className="aic-warn" role="alert">
      <Icon.Warn />
      <span>{text}</span>
    </div>
  );
}

/** The clock of a change, for the ledger's time column: `14:02:37` — the date is the run's. */
const clockOf = (iso: string): string => {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? '' : new Date(t).toISOString().slice(11, 19);
};

/** A short noun per change family, for the ledger's kind tag. */
function changeFamily(tool: string): string {
  if (tool.includes('note')) return 'note';
  if (tool.includes('ioc')) return 'indicator';
  if (tool.includes('graph')) return 'graph';
  if (tool.includes('rule')) return 'rule';
  if (tool.includes('exclusion')) return 'exclusion';
  if (tool.includes('annotate')) return 'timeline';
  if (tool.includes('events')) return 'case set';
  if (tool.includes('case')) return 'case';
  return 'change';
}

/** `2 notes · 1 indicator · 1 graph` — the head's one-line breakdown of what is still on the case. */
function changeBreakdown(actions: AiAction[]): string {
  const families = new Map<string, number>();
  for (const a of actions) {
    if (a.undone) continue;
    const f = changeFamily(a.tool);
    families.set(f, (families.get(f) ?? 0) + 1);
  }
  const plural = (f: string, n: number) => (n === 1 ? f : f === 'case set' ? 'case set entries' : `${f}s`);
  return [...families].map(([f, n]) => `${n} ${plural(f, n)}`).join(' · ');
}

/**
 * The template's ARTIFACT CARD, carrying what the run did to the case — second only to the answer,
 * because it is the part that persists. It reads as a LEDGER: one row per change, the change itself
 * as the line, the family it belongs to as a tag, the clock on the right. Every entry is reversible
 * in one click; a reverted one stays listed, struck through, rather than disappearing.
 */
function Changes({ actions, busy, onUndo }: { actions: AiAction[]; busy: boolean; onUndo: () => void }) {
  const active = actions.filter((a) => !a.undone).length;
  if (!actions.length) return null;
  const reverted = actions.length - active;
  return (
    <section className="aic-art" aria-label="Changes this run made to the case">
      <div className="aic-art__head">
        <span className="aic-art__tile" aria-hidden><Icon.Cases /></span>
        <span className="aic-art__ident">
          <span className="aic-art__name">Changes to this case</span>
          <span className="aic-art__meta">
            {active === 0 ? 'everything reverted' : changeBreakdown(actions)}
            {reverted > 0 && active > 0 ? ` · ${reverted} reverted` : ''}
          </span>
        </span>
        <span className="aic-art__count" aria-label={`${active} active changes`}>{active}</span>
        {active > 0 && (
          <button type="button" className="aic-art__act" onClick={onUndo} disabled={busy}>
            {busy ? 'Reverting…' : 'Revert all'}
          </button>
        )}
      </div>
      <ol className="aic-art__list">
        {actions.map((a) => {
          const Glyph = toolIcon(a.tool);
          const clock = clockOf(a.at);
          return (
            <li key={a.id} className={cx('aic-change', a.undone && 'aic-change--undone')}>
              <span className="aic-change__glyph" aria-hidden><Glyph /></span>
              <span className="aic-change__text">
                <span className="aic-change__summary">{a.summary}</span>
                <span className="aic-change__sub">
                  <span className="aic-change__kind" title={a.tool}>{changeFamily(a.tool)}</span>
                  <span className="aic-change__what">{writeLabel(a.tool)}</span>
                </span>
              </span>
              <span className="aic-change__side">
                {a.undone ? <span className="aic-change__tag">reverted</span> : null}
                {clock && <time className="aic-change__time" dateTime={a.at} title={UTC(a.at)}>{clock}</time>}
              </span>
            </li>
          );
        })}
      </ol>
    </section>
  );
}

/**
 * The history is a list of CONVERSATIONS, not of runs: a chat with four follow-ups is one entry, named
 * by the question that started it. Listing every turn separately would bury the conversation the
 * analyst is looking for under its own follow-ups, and opening turn three of a chat as if it were the
 * whole thing is exactly the context loss threads exist to fix.
 *
 * Grouping is by `threadId` over the page the server returned, so a thread whose earliest turns fell
 * off the end of the page is named by the oldest turn still present — degraded, never wrong.
 */
interface Thread { id: string; root: AiRun; latest: AiRun; turns: number; changes: number }

function threadsOf(runs: AiRun[]): Thread[] {
  const byThread = new Map<string, AiRun[]>();
  for (const r of runs) {
    const key = r.threadId || r.id;
    const got = byThread.get(key);
    if (got) got.push(r);
    else byThread.set(key, [r]);
  }
  const out: Thread[] = [];
  for (const [id, rows] of byThread) {
    // the listing is newest first; `startedAt` ties to the second, so `parentId` breaks the tie
    const ordered = [...rows].reverse();
    const root = ordered.find((r) => !r.parentId) ?? ordered[0]!;
    const latest = rows[0]!;
    out.push({
      id, root, latest, turns: rows.length,
      changes: rows.reduce((n, r) => n + r.actions.filter((a) => !a.undone).length, 0),
    });
  }
  return out;
}

/**
 * THE CANVAS PANEL: the template's 470px side panel, on its own darker ground, holding the
 * conversation history. Head (serif name, mono state, a pill-group of tabs, close), a body of
 * numbered mono lines, and a foot carrying a mono summary.
 */
function HistoryCanvas({ runs, busy, full, filter, onFilter, onOpen, onDelete, onClose }: {
  runs: AiRun[]; busy: boolean; full: boolean;
  filter: 'all' | 'changed'; onFilter: (v: 'all' | 'changed') => void;
  onOpen: (id: string) => void; onDelete: (id: string) => void; onClose: () => void;
}) {
  const threads = useMemo(() => threadsOf(runs), [runs]);
  const shown = useMemo(() => (filter === 'changed' ? threads.filter((t) => t.changes > 0) : threads), [threads, filter]);

  return (
    <aside className={cx('aic-canvas', full && 'aic-canvas--full')} aria-label="Past conversations">
      <div className="aic-canvas__head">
        <span className="aic-canvas__name">Conversations</span>
        <span className="aic-canvas__state">{busy && !runs.length ? 'loading' : `${threads.length} kept`}</span>
        <div className="aic-canvas__tabs" role="group" aria-label="Filter conversations">
          <button type="button" className={cx('aic-canvas__tab', filter === 'all' && 'is-on')}
            aria-pressed={filter === 'all'} onClick={() => onFilter('all')}>All</button>
          <button type="button" className={cx('aic-canvas__tab', filter === 'changed' && 'is-on')}
            aria-pressed={filter === 'changed'} onClick={() => onFilter('changed')}>Changed</button>
        </div>
        <button type="button" className="aic-canvas__close" onClick={onClose} aria-label="Close the conversation list">✕</button>
      </div>

      <div className="aic-canvas__body">
        {busy && !runs.length && (
          <div className="aic-hist__empty">
            <div className="aic-busy"><span className="spinner" style={{ width: 12, height: 12 }} />Loading conversations</div>
          </div>
        )}
        {!busy && !threads.length && (
          <div className="aic-hist__empty">
            <div className="aic-hist__empty-title">No conversations yet</div>
            <div className="aic-hist__empty-body">
              Ask the assistant to investigate something. Everything it says, every tool it calls and every change it
              makes to the case is kept here — a refresh, another tab or a server restart will not lose it.
            </div>
          </div>
        )}
        {!!threads.length && !shown.length && (
          <div className="aic-hist__empty">
            <div className="aic-hist__empty-body">
              None of the {threads.length} kept conversation{threads.length === 1 ? '' : 's'} changed the case.
            </div>
          </div>
        )}
        <ul className="aic-hist">
          {shown.map((t, i) => (
            <li key={t.id} className="aic-hist__row">
              <button type="button" className="aic-hist__open" onClick={() => onOpen(t.latest.id)}>
                <span className="aic-hist__n" aria-hidden>{String(i + 1).padStart(2, '0')}</span>
                <span className="aic-hist__text">
                  <span className="aic-hist__prompt">{t.root.prompt || '(no objective)'}</span>
                  <span className="aic-hist__meta">
                    <span className={cx('aic-state', `aic-state--${t.latest.state}`)}>{STATE_LABEL[t.latest.state]}</span>
                    <span title={RELATIVE(t.latest.startedAt)}>{UTC(t.latest.startedAt)}</span>
                    {t.turns > 1 && <span>{t.turns} turns</span>}
                    {t.root.caseName && <span>{t.root.caseName}</span>}
                    {t.changes > 0 && (
                      <span className="aic-hist__writes">
                        {t.changes} change{t.changes === 1 ? '' : 's'}
                      </span>
                    )}
                  </span>
                </span>
              </button>
              <button
                type="button"
                className="aic-hist__del"
                title={t.turns > 1 ? 'Delete the latest turn of this conversation' : 'Delete this conversation'}
                aria-label={`Delete conversation: ${t.root.prompt.slice(0, 60)}`}
                onClick={() => onDelete(t.latest.id)}
              >
                <Icon.Trash />
              </button>
            </li>
          ))}
        </ul>
      </div>

      <div className="aic-canvas__foot">
        <span>
          {shown.length} of {threads.length} shown · kept on the server
        </span>
      </div>
    </aside>
  );
}

/* ─────────────────────────────────── the panel ─────────────────────────────────── */

/**
 * ONE TURN of a conversation: the analyst's question as a bubble, then the assistant's work on it.
 *
 * The same component renders a past turn, the current finished turn and the live one, because they are
 * the same thing at different moments — and because two renderers would drift, which on this screen
 * means one of them eventually shows a write as a read.
 *
 * ORDER. Live, the order IS the point: the steps card sits above the prose (exactly where the template
 * puts it) and fills while the answer streams underneath, so the work can be watched. Finished, the
 * PRIORITY is the point and the documented rule stands — warnings, then the ANSWER, then what it
 * changed in the case, then how it got there, collapsed.
 */
function Turn({ run, entries, live, undoing, onUndo, onRetry }: {
  run: AiRun; entries: AiTranscriptEntry[]; live: boolean; undoing: boolean;
  onUndo: (id: string) => void; onRetry: (run: AiRun) => void;
}) {
  const blocks = useMemo(() => toBlocks(entries), [entries]);
  const warnings = useMemo(
    () => blocks.filter((b): b is Extract<Block, { kind: 'warning' }> => b.kind === 'warning'), [blocks]);
  const prose = useMemo(
    () => blocks.filter((b) => b.kind === 'prose').map((b) => (b as { text: string }).text).join('\n').trim(), [blocks]);
  // The stream usually IS the report, so `answer` prefers the persisted one and falls back to the
  // prose a stopped run managed to write. Prose already contained in the answer is not repeated in
  // the steps card; prose that is NOT part of it stays there rather than being silently dropped.
  const answer = ((run.answer ?? '').trim()) || (live ? '' : prose);
  const trailBlocks = useMemo(() => blocks.filter((b) => {
    if (b.kind === 'warning') return false;
    if (b.kind !== 'prose') return true;
    const t = b.text.trim();
    return !(t && answer.includes(t));
  }), [blocks, answer]);
  const ranFor = run.endedAt ? spanOf(run.startedAt, run.endedAt) : '';

  const nodes = useMemo(() => trailNodes(trailBlocks), [trailBlocks]);
  // The COMMENTARY: the one-line narration the assistant writes before each call ("Profiling X first
  // - one call gives me..."). Live, it is read in place. Finished, it used to survive only inside the
  // collapsed card, and the analyst who opened the panel after the run reported the commentary as
  // gone. It is its own quiet block now - the prose that is NOT part of the report, in order.
  const commentary = useMemo(
    () => trailBlocks.filter((b): b is Extract<Block, { kind: 'prose' }> => b.kind === 'prose'), [trailBlocks]);

  // LIVE: the calls are ONE card, above the prose, not a card per model turn interleaved with it.
  // Threading tool cards through the answer meant the thing being read moved down the page every time
  // a call landed, and the reading column was broken into fragments by cards that are deliberately
  // secondary. Turn breaks are kept, so the sequence is still legible inside the card.
  const liveNodes = useMemo(() => trailNodes(blocks.filter((b) => b.kind !== 'prose')), [blocks]);
  const liveProse = useMemo(
    () => blocks.filter((b): b is Extract<Block, { kind: 'prose' }> => b.kind === 'prose'), [blocks]);

  return (
    <>
      {/* THE OBJECTIVE — the template's right-aligned bubble. */}
      <div className="aic-user">
        <div className="aic-user__bubble">{run.prompt}</div>
        {run.focus && <div className="aic-user__ctx">context: {run.focus}</div>}
        <div className="aic-micros">
          <CopyMicro text={run.prompt} what="the objective" />
          <span className="aic-micro aic-micro--stamp" title={RELATIVE(run.startedAt)}>{UTC(run.startedAt)}</span>
        </div>
      </div>

      {/* THE ASSISTANT — no bubble: steps card, prose, artifact card, actions. */}
      <div className="aic-asst" {...(live ? { 'aria-live': 'polite' as const, 'aria-busy': true } : {})}>
        {live ? (
          <>
            {warnings.map((w) => <Warning key={w.key} text={w.text} />)}
            <StepsCard nodes={liveNodes} live title="Working" startOpen />
            {liveProse.map((b) => <Markdown key={b.key} className="md aic-prose" text={b.text} />)}
            {!blocks.length && (
              <div className="aic-busy"><span className="spinner" style={{ width: 12, height: 12 }} />Starting the investigation</div>
            )}
            {!!liveProse.length && <span className="aic-caret" aria-hidden />}
            <Changes actions={run.actions} busy={undoing} onUndo={() => onUndo(run.id)} />
          </>
        ) : (
          <>
            {warnings.map((w) => <Warning key={w.key} text={w.text} />)}
            {run.interrupted && <Warning text={run.error || 'The server restarted while this run was going.'} />}
            {!run.interrupted && run.state === 'error' && !!run.error && <Warning text={run.error} />}

            {answer
              ? <Markdown className="md aic-prose" text={answer} />
              : (
                <div className="aic-note">
                  {run.state === 'stopped'
                    ? 'Stopped before the assistant wrote a report. Anything it had already changed is listed below and can be reverted.'
                    : 'This run produced no report.'}
                </div>
              )}

            {!!commentary.length && answer && commentary.map((b) => (
              <Markdown key={b.key} className="md aic-prose aic-prose--quiet" text={b.text} />
            ))}

            <Changes actions={run.actions} busy={undoing} onUndo={() => onUndo(run.id)} />
            <StepsCard nodes={nodes} live={false} title="How it got there" startOpen={!answer} />

            {run.transcriptTruncated && (
              <div className="aic-note">This transcript was long and its earliest lines were dropped; the report and the change list are complete.</div>
            )}

            <div className="aic-acts">
              {!!answer && <CopyMicro text={answer} what="the answer" />}
              <Micro label="⟳ Retry" title="Ask the same objective again" onClick={() => onRetry(run)} />
              <span className="aic-acts__spacer" />
              <span className={cx('aic-state', `aic-state--${run.state}`)}>{STATE_LABEL[run.state]}</span>
              {run.endedAt && (
                <span className="aic-acts__time" title={RELATIVE(run.endedAt)}>{UTC(run.endedAt)}</span>
              )}
            </div>

            {(run.toolCalls > 0 || ranFor || !!run.model) && (
              <div className="aic-meta">
                {run.toolCalls > 0 && <span>{run.toolCalls} tool call{run.toolCalls === 1 ? '' : 's'}</span>}
                {ranFor && <span>ran for {ranFor}</span>}
                {run.model && <span>{run.model}</span>}
                {run.reason && run.reason !== 'complete' && <span title="how the run ended">{run.reason.replace(/_/g, ' ')}</span>}
              </div>
            )}
          </>
        )}
      </div>
    </>
  );
}


export function AiPanel({ target, onClose }: { target: AiTarget; onClose: () => void }) {
  const settings = useSettings();
  const qc = useQueryClient();
  const toast = useToast();
  const provider = settings.data?.ai.provider;

  const [view, setView] = useState<'chat' | 'history'>('history');
  const [histFilter, setHistFilter] = useState<'all' | 'changed'>('all');
  const [prompt, setPrompt] = useState('');
  // Which SAVED SYSTEM PROMPT the next run uses (Settings → System prompts). `null` = whatever the
  // settings default is, '' = the built-in prompt alone, an id = that prompt. Remembered per browser,
  // because an analyst who picked a prompt for a case is going to want it on the next question too.
  const systemPrompts = useQuery({ queryKey: qk.aiSystemPrompts, queryFn: api.aiSystemPrompts, staleTime: 60_000 });
  const [spChoice, setSpChoice] = useState<string | null>(() => {
    try { const v = localStorage.getItem(SP_KEY); return v === null ? null : v; } catch { return null; }
  });
  const pickSystemPrompt = useCallback((v: string | null) => {
    setSpChoice(v);
    try { if (v === null) localStorage.removeItem(SP_KEY); else localStorage.setItem(SP_KEY, v); } catch { /* ignore */ }
  }, []);
  const [run, setRun] = useState<AiRun | null>(null);
  // The FINISHED earlier turns of the open conversation, oldest first. `run` is always the latest one.
  const [thread, setThread] = useState<AiRun[]>([]);
  const [entries, setEntries] = useState<AiTranscriptEntry[]>([]);
  const [runs, setRuns] = useState<AiRun[]>([]);
  const [loadingRuns, setLoadingRuns] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stopping, setStopping] = useState(false);
  const [undoingId, setUndoingId] = useState<string | null>(null);
  // Whether the panel is following the bottom of the transcript. The REF is the one that decides —
  // see the scroll effect below for why state cannot; the state copy only renders "Jump to latest".
  const [atBottom, setAtBottom] = useState(true);
  const atBottomRef = useRef(true);
  const lastTopRef = useRef(0);
  const follow = useCallback((on: boolean) => {
    if (atBottomRef.current === on) return;
    atBottomRef.current = on;
    setAtBottom(on);
  }, []);
  const [detached, setDetached] = useState<boolean>(() => {
    try { return localStorage.getItem(AI_DETACHED_KEY) === '1'; } catch { return false; }
  });
  const setMode = useCallback((v: boolean) => {
    setDetached(v);
    try { localStorage.setItem(AI_DETACHED_KEY, v ? '1' : '0'); } catch { /* private mode: it still works, it just forgets */ }
  }, []);

  const abortRef = useRef<AbortController | null>(null);
  // The live `tool_call` event does not say whether a tool writes, and a write drawn as a read is the
  // one distinction this screen must not get wrong. Ask the registry once; fall back to the literal.
  const writeToolsRef = useRef<Set<string>>(WRITE_TOOLS);
  // The run THIS tab is reading over SSE. It is STATE, not a ref, because the polling effect below has
  // to re-evaluate the moment the stream ends — a dropped SSE connection must hand over to polling.
  const [streamingId, setStreamingId] = useState<string | null>(null);
  const sseSeqRef = useRef(0);
  const bodyRef = useRef<HTMLDivElement>(null);
  const shellRef = useRef<HTMLDivElement>(null);
  const promptRef = useRef<HTMLTextAreaElement>(null);
  const entriesRef = useRef<AiTranscriptEntry[]>([]);
  entriesRef.current = entries;
  // Read inside startRun to move the turn that is ending onto the thread. State would be stale there:
  // the callback closes over the render that created it, and a follow-up is sent from the NEXT one.
  const runRef = useRef<AiRun | null>(null);
  runRef.current = run;

  const live = run?.state === 'running';

  /** Anything the agent touched invalidates the screens that render it. */
  const refreshWorkspace = useCallback(() => {
    // `case-detail` and `cases` were missing here, so the case screen's own query (header, counts,
    // the graph section) never refetched on a write. The live bus (hooks/useLiveWorkspace.ts) now
    // does this for every tab; this stays as the immediate path for the tab holding the stream.
    for (const key of [['case'], ['cases'], ['case-detail'], ['iocs'], ['timeline'], ['timeline-iocs'], ['graph'], ['case-set'], ['notes'], ['events']]) {
      void qc.invalidateQueries({ queryKey: key });
    }
  }, [qc]);

  const loadHistory = useCallback(async () => {
    try {
      const r = await api.aiRuns(30);
      setRuns(r.runs);
      return r.runs;
    } catch {
      return [] as AiRun[];
    } finally {
      setLoadingRuns(false);
    }
  }, []);

  /**
   * Open a stored (or in-flight) CONVERSATION — every turn of it, not just the run that was clicked.
   * Opening one turn of a chat and calling it the conversation is how a follow-up loses the context
   * the analyst can see it should have.
   */
  const openRun = useCallback(async (id: string) => {
    setView('chat');
    setError(null);
    setEntries([]);
    setThread([]);
    sseSeqRef.current = 0;
    try {
      const t = await api.aiThread(id);
      const rows = t.runs;
      const last = rows[rows.length - 1];
      if (!last) return;
      setThread(rows.slice(0, -1));
      setRun({ ...last, transcript: [] });
      setEntries(last.transcript);
      follow(true);          // opening a conversation lands at its end
    } catch (e) {
      setError(errMsg(e));
    }
  }, []);

  /* ── the write surface, straight from the registry ──────────────────────────── */
  useEffect(() => {
    let alive = true;
    void api.aiTools()
      .then((r) => {
        if (!alive) return;
        const s = new Set(r.tools.filter((t) => t.writes).map((t) => t.name));
        if (s.size) writeToolsRef.current = s;
      })
      .catch(() => { /* keep the literal above — it is the same list, just compiled in */ });
    return () => { alive = false; };
  }, []);

  /* ── on mount: rejoin a run in flight, otherwise show the history ───────────── */
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const rows = await loadHistory();
      if (cancelled) return;
      const inflight = rows.find((r) => r.state === 'running');
      if (inflight) void openRun(inflight.id);
    })();
    return () => { cancelled = true; };
  }, [loadHistory, openRun]);

  /* ── polling: the rejoin path (any tab that is not the one streaming) ───────── */
  useEffect(() => {
    const id = run?.id;
    if (!id || run?.state !== 'running' || streamingId === id) return;
    let stop = false;
    let timer = 0;
    const tick = async () => {
      try {
        const r = await api.aiRun(id, cursorOf(entriesRef.current, true));
        if (stop) return;
        setEntries((prev) => mergeEntries(prev, r.transcript));
        setRun((prev) => (prev && prev.id === id ? { ...r, transcript: [] } : prev));
        if (r.state === 'running') timer = window.setTimeout(tick, POLL_MS);
        else { refreshWorkspace(); void loadHistory(); }
      } catch {
        if (!stop) timer = window.setTimeout(tick, POLL_MS * 3);
      }
    };
    timer = window.setTimeout(tick, POLL_MS);
    return () => { stop = true; window.clearTimeout(timer); };
  }, [run?.id, run?.state, streamingId, refreshWorkspace, loadHistory]);

  /* ── starting a run: SSE for per-token prose in the tab that asked ──────────── */
  const startRun = useCallback((objective: string, continueFrom?: string) => {
    const text = objective.trim();
    if (!text) return;
    // The turn that is ending moves onto the thread with the transcript this tab has, so the chat does
    // not blink back to a single turn while the follow-up starts.
    const previous = continueFrom ? runRef.current : null;
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    const rid = `run-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
    const focus = focusOf(target);

    setStreamingId(rid);
    sseSeqRef.current = 0;
    setView('chat');
    setError(null);
    setStopping(false);
    if (previous) setThread((prev) => [...prev, { ...previous, transcript: entriesRef.current }]);
    else setThread([]);
    setEntries([]);
    follow(true);            // a new turn always starts by following it
    setRun({
      id: rid, prompt: text, focus: focus ?? '', model: settings.data?.ai.model ?? '',
      parentId: continueFrom ?? '', threadId: previous?.threadId || rid,
      caseId: '', caseName: '', startedAt: new Date().toISOString(), endedAt: '', updatedAt: '',
      state: 'running', reason: '', steps: 0, toolCalls: 0, answer: '', error: '', interrupted: false,
      actions: [], unverifiedCitations: [], transcript: [], transcriptSeq: 0, transcriptTruncated: false,
    });
    setPrompt('');

    const body: AiInvestigateRequest = { prompt: text, runId: rid };
    if (focus) body.focus = focus;
    if (continueFrom) body.continueFrom = continueFrom;
    // A remembered choice that names a prompt since deleted is dropped here rather than sent: the
    // server would warn and run on the built-in prompt, but the picker should not keep offering it.
    const spKnown = spChoice === null || spChoice === '' || !!systemPrompts.data?.prompts.some((p) => p.id === spChoice);
    if (spChoice !== null && spKnown) body.systemPromptId = spChoice;

    // Prose arrives one TOKEN at a time, in bursts. See STREAM_SMOOTH_MS: deltas go into `buffered`
    // and a frame loop pours a slice of it onto the screen, so what is painted is a steady rate rather
    // than the shape of the wire. Every other event flushes the buffer FIRST, so the order on screen is
    // exactly the stream's — a tool card can never appear ahead of the sentence that introduced it.
    let buffered = '';
    let raf = 0;
    let prevTs = 0;

    const commit = (t: string) => {
      setEntries((prev) => {
        const last = prev[prev.length - 1];
        if (last?.kind === 'text') return [...prev.slice(0, -1), { ...last, text: last.text + t }];
        return [...prev, { ...blank(++sseSeqRef.current, 'text'), text: t }];
      });
    };

    const stopRaf = () => {
      if (raf) { cancelAnimationFrame(raf); raf = 0; }
      prevTs = 0;
    };

    /** Everything still buffered, at once. Used by every non-delta event and at end of stream. */
    const flushText = () => {
      stopRaf();
      const t = buffered;
      buffered = '';
      // A pending flush must never land on the NEXT conversation: `startRun` aborts the old stream, and
      // a frame that fires after that would append the previous run's tail to a fresh transcript.
      if (!t || ac.signal.aborted) return;
      commit(t);
    };

    const tick = (ts: number) => {
      raf = 0;
      if (ac.signal.aborted) { buffered = ''; prevTs = 0; return; }
      const dt = prevTs ? Math.min(160, ts - prevTs) : 16;
      prevTs = ts;
      let n = Math.max(1, Math.ceil((buffered.length * dt) / STREAM_SMOOTH_MS));
      if (n >= buffered.length) n = buffered.length;
      // Never cut between the halves of a surrogate pair: half of one is not a character, and React
      // would paint the replacement glyph for a frame before the other half arrived.
      else if ((buffered.charCodeAt(n - 1) & 0xfc00) === 0xd800) n += 1;
      commit(buffered.slice(0, n));
      buffered = buffered.slice(n);
      if (buffered) raf = requestAnimationFrame(tick);
      else prevTs = 0;
    };
    const push = (e: Partial<AiTranscriptEntry> & { kind: AiTranscriptEntry['kind'] }) => {
      flushText();
      setEntries((prev) => [...prev, { ...blank(++sseSeqRef.current, e.kind), ...e }]);
    };

    api
      .aiInvestigate(body, (ev: AiRunEvent) => {
        if (ev.type !== 'delta') flushText();
        switch (ev.type) {
          case 'run':
            setRun((r) => (r ? {
              ...r, id: ev.runId, model: ev.model,
              threadId: ev.threadId ?? r.threadId, parentId: ev.parentId ?? r.parentId,
            } : r));
            setStreamingId(ev.runId);
            break;
          case 'status':
            push({ kind: 'status', text: ev.text });
            break;
          case 'step':
            push({ kind: 'step', step: ev.step });
            break;
          case 'delta':
            buffered += ev.text;
            if (!raf) raf = requestAnimationFrame(tick);
            break;
          case 'tool_call':
            push({ kind: 'tool', id: ev.id, name: ev.name, args: ev.arguments, writes: writeToolsRef.current.has(ev.name) });
            break;
          case 'tool_result':
            // Match on the call id; fall back to the LAST unfinished call of the same name. The card's
            // spinner is what says "this is still running", so a result that matches nothing leaves it
            // spinning for the rest of the run — reported as "the spinner on tool calls does not stop
            // when the call is completed". The server now stamps both events with the same id (a
            // provider that omits one made every card carry `id: null`); this is the belt to that
            // brace, and it also covers a stream that drops a frame.
            setEntries((prev) => {
              let hit = prev.findIndex((e) => e.kind === 'tool' && e.id === ev.id && e.ok === null);
              if (hit < 0) hit = prev.findIndex((e) => e.kind === 'tool' && e.id === ev.id);
              if (hit < 0) {
                for (let i = prev.length - 1; i >= 0; i--) {
                  const e = prev[i]!;
                  if (e.kind === 'tool' && e.name === ev.name && e.ok === null) { hit = i; break; }
                }
              }
              if (hit < 0) return prev;
              const next = prev.slice();
              next[hit] = { ...next[hit]!, ok: ev.ok, summary: ev.summary, tookMs: ev.tookMs };
              return next;
            });
            break;
          case 'write':
            setRun((r) => (r ? { ...r, actions: [...r.actions, ev.action] } : r));
            refreshWorkspace();
            break;
          case 'warning':
            push({ kind: 'warning', text: ev.message });
            setRun((r) => (r ? { ...r, unverifiedCitations: ev.ids } : r));
            break;
          case 'answer':
            setRun((r) => (r ? { ...r, answer: ev.text } : r));
            break;
          case 'done':
            setRun((r) => (r ? {
              ...r, answer: ev.answer || r.answer, actions: ev.actions ?? r.actions,
              reason: ev.reason, state: (ev.state as AiRun['state']) || 'done', endedAt: new Date().toISOString(),
              steps: ev.steps, toolCalls: ev.toolCalls,
            } : r));
            refreshWorkspace();
            break;
          case 'error':
            setError(ev.message);
            setRun((r) => (r ? { ...r, state: 'error', error: ev.message } : r));
            break;
        }
      }, ac.signal)
      .then(() => flushText())
      .catch((e: unknown) => {
        flushText();
        if (ac.signal.aborted) return;
        setError(errMsg(e));
      })
      .finally(() => {
        // Hand over to the polling path: it reads the PERSISTED record, which is authoritative and is
        // exactly what a refresh would show. A dropped stream no longer means a lost run.
        //
        // The transcript is REPLACED wholesale here, not merged: while streaming, entries carry
        // locally-minted seq numbers (prose is coalesced differently server-side), so merging a server
        // tail onto them would collide on seq and interleave two numbering schemes.
        void api.aiRun(rid)
          .then((r) => {
            setEntries(r.transcript);
            setRun((prev) => (prev && (prev.id === rid || prev.id === r.id) ? { ...r, transcript: [] } : prev));
          })
          .catch(() => { /* offline: keep what the stream already showed */ })
          .finally(() => { setStreamingId(null); void loadHistory(); });
      });
  }, [target, settings.data?.ai.model, refreshWorkspace, loadHistory, spChoice, systemPrompts.data]);

  /** Stop the run SERVER-side. Aborting the fetch alone would leave the agent writing to the case. */
  const stop = useCallback(() => {
    const id = run?.id;
    if (!id) return;
    setStopping(true);
    api.aiStopRun(id)
      .catch(() => { /* it may already have finished */ })
      .finally(() => {
        window.setTimeout(async () => {
          try {
            const r = await api.aiRun(id, cursorOf(entriesRef.current, true));
            setEntries((prev) => mergeEntries(prev, r.transcript));
            setRun({ ...r, transcript: [] });
          } catch { /* the poll/SSE path will settle it */ }
          setStopping(false);
          promptRef.current?.focus();
          void loadHistory();
        }, 1200);
      });
  }, [run?.id, loadHistory]);

  /** Revert ONE turn. The run is the unit of undo — a whole-conversation revert would take back work
   *  the analyst deliberately kept from an earlier answer. */
  const undoRun = useCallback((id: string) => {
    if (!id) return;
    setUndoingId(id);
    api.aiUndoRun(id)
      .then((r) => {
        setRun((prev) => (prev && prev.id === id ? { ...prev, actions: r.actions } : prev));
        setThread((prev) => prev.map((t) => (t.id === id ? { ...t, actions: r.actions } : t)));
        toast.info('AI changes reverted', `${r.undone} change${r.undone === 1 ? '' : 's'} taken back off the case`);
        refreshWorkspace();
      })
      .catch((e: unknown) => toast.error('Could not revert the changes', e))
      .finally(() => setUndoingId(null));
  }, [refreshWorkspace, toast]);

  const remove = useCallback((id: string) => {
    api.aiDeleteRun(id)
      .then(() => {
        setRuns((prev) => prev.filter((r) => r.id !== id));
        setRun((prev) => (prev?.id === id ? null : prev));
        setThread((prev) => prev.filter((t) => t.id !== id));
      })
      .catch((e: unknown) => toast.error('Could not delete the conversation', e));
  }, [toast]);

  const newConversation = useCallback(() => {
    setView('chat');
    setRun(null);
    setThread([]);
    setEntries([]);
    setError(null);
    void loadHistory();
    window.setTimeout(() => promptRef.current?.focus(), 30);
  }, [loadHistory]);

  /* ── focus, escape, and follow-the-stream scrolling ─────────────────────────── */
  // Also on a dock/detach switch: the two shells are different elements, so the composer is a NEW
  // textarea each time and the caret would otherwise land back on the page.
  useEffect(() => { window.setTimeout(() => promptRef.current?.focus(), 50); }, [detached]);
  useEffect(() => () => abortRef.current?.abort(), []);
  // Escape closes the DOCKED panel, which is modal and covers what is behind it. A detached window is
  // not: it sits beside the work, Escape is being pressed at whatever the analyst is doing on the page
  // underneath, and closing on it would throw away a half-written objective. `FloatingWindow` is told
  // the same thing (closeOnEscape), so neither handler can close it.
  useEffect(() => {
    if (detached) return;
    const on = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', on);
    return () => window.removeEventListener('keydown', on);
  }, [onClose, detached]);

  /* ── is there room for the template's side canvas? ───────────────────────────
   * Measured, not guessed at with a media query: the panel is a slide-over in one shell and a window
   * the analyst drags in the other, so its width has nothing to do with the viewport's. */
  const [wide, setWide] = useState(false);
  useEffect(() => {
    const el = shellRef.current;
    if (!el || typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver((es) => {
      const w = es[0]?.contentRect.width ?? 0;
      setWide(w >= CANVAS_MIN_CONTENT);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [detached, provider]);

  /**
   * FOLLOWING THE STREAM, AND LETTING GO OF IT — reported as "the ai chat scroll doesn't allow me to
   * scroll, I have to undock and re-dock for the scroll to become responsive".
   *
   * The panel pins itself to the bottom on every commit while it is following, and whether it is
   * following was React STATE. State is not readable in time: the scroll event sets it, but the very
   * next commit's effect still sees the previous render's value and puts the analyst back at the
   * bottom. During a run that is a reset per commit, so the wheel appeared to do nothing at all —
   * and undocking "fixed" it only because the shell swap remounts the scroller, usually after the run
   * has ended and nothing is pinning any more. The frame-paced stream made it far worse: the fight
   * went from ~11 resets a second to one per frame.
   *
   * So the flag lives in a REF, written synchronously in the scroll handler, and the effect reads
   * that. The state copy exists only to render "Jump to latest".
   *
   * The second half is the threshold. "Near the bottom" was the whole test, so a small upward nudge —
   * a trackpad flick, one line of a wheel — stayed inside 48px, counted as still following, and was
   * pulled straight back. ANY deliberate upward scroll now stops the follow, however small; scrolling
   * back down to the end resumes it. Reading is an explicit act and it wins.
   */
  useEffect(() => {
    if (!atBottomRef.current) return;
    const el = bodyRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
    // Remember where WE put it, so the scroll event this causes is not read as the analyst moving up.
    lastTopRef.current = el.scrollTop;
    // `detached` is in here because the two shells hold DIFFERENT scroll containers: docking a window
    // that was following a live run must not silently jump the analyst back to the top of it.
  }, [entries, run?.answer, atBottom, detached]);

  const onScroll = useCallback(() => {
    const el = bodyRef.current;
    if (!el) return;
    const top = el.scrollTop;
    const movedUp = top < lastTopRef.current - 1;
    lastTopRef.current = top;
    if (movedUp) { follow(false); return; }
    follow(el.scrollHeight - top - el.clientHeight < 48);
  }, [follow]);

  const jumpToLatest = useCallback(() => {
    const el = bodyRef.current;
    if (el) { el.scrollTop = el.scrollHeight; lastTopRef.current = el.scrollTop; }
    follow(true);
  }, [follow]);

  /* ── auto-growing composer (the template's 24px floor / 150px ceiling) ─────── */
  useEffect(() => {
    const el = promptRef.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = `${Math.min(150, Math.max(24, el.scrollHeight))}px`;
  }, [prompt]);

  /* ── what the transcript becomes on screen ─────────────────────────────────── */
  const scopeNote = focusOf(target);
  const threadCount = useMemo(() => new Set(runs.map((r) => r.threadId || r.id)).size, [runs]);
  const canSend = !!prompt.trim() && !live;
  const savedPrompts = useMemo(() => systemPrompts.data?.prompts ?? [], [systemPrompts.data]);
  // a remembered id that no longer exists is not offered; the select falls back to the default row
  useEffect(() => {
    if (systemPrompts.data && spChoice && !savedPrompts.some((p) => p.id === spChoice)) pickSystemPrompt(null);
  }, [systemPrompts.data, savedPrompts, spChoice, pickSystemPrompt]);
  // Typing into an open, finished conversation CONTINUES it. A first turn, or a chat cleared with New,
  // starts a fresh one.
  const continueFrom = run && !live ? run.id : undefined;
  const send = useCallback(() => {
    if (!prompt.trim() || live) return;
    startRun(prompt, run && run.state !== 'running' ? run.id : undefined);
  }, [prompt, live, run, startRun]);
  /** Ask the same objective again, in the same thread it belonged to. */
  const retry = useCallback((r: AiRun) => {
    if (live) return;
    startRun(r.prompt, r.parentId || undefined);
  }, [live, startRun]);

  // The conversation's own identity in the header: named by the question that STARTED it, stamped
  // with when the latest turn moved. Relative here (the template's "edited 2m ago"); the absolute UTC
  // time is on every turn and is what a report cites.
  const rootRun = thread[0] ?? run;
  const convoTitle = run ? (rootRun?.prompt || run.prompt || 'Untitled conversation') : 'New conversation';
  const convoStamp = run ? RELATIVE(run.updatedAt || run.endedAt || run.startedAt) : '';

  const configured = !!provider && provider !== 'none';
  // The canvas is only ever on when there IS an assistant: without this, a workspace with no
  // provider at a narrow width rendered NEITHER branch (the history is gated on the provider, the
  // column on the history being off) and the panel came up blank.
  const showCanvas = view === 'history' && configured;

  /* ── one set of controls, one body, two shells ────────────────────────────────
   * Docked and detached must be the SAME panel — a second copy of the transcript, the composer or the
   * write list is a copy that eventually drifts, and on this screen drift means one of them draws a
   * write as a read. Only the frame around them changes.
   */
  const header = (
    <div className="aic__head">
      <div className="aic__brand">
        <span className="aic__mark" aria-hidden><i /></span>
        <span className="aic__wordmark">Assistant</span>
      </div>
      <span className="aic__rule" aria-hidden />
      <div className="aic__ident">
        <span className="aic__title" title={convoTitle}>{convoTitle}</span>
        {!!convoStamp && (
          <span className="aic__stamp" title={UTC(run?.updatedAt || run?.startedAt || '')}>{convoStamp}</span>
        )}
      </div>
      <div className="aic__spacer" />
      <button type="button" className="aic__pill" onClick={newConversation} title="Start a new conversation">New</button>
      <button
        type="button"
        className={cx('aic__pill', showCanvas && 'is-on')}
        aria-pressed={showCanvas}
        onClick={() => setView((v) => (v === 'history' ? 'chat' : 'history'))}
        title="Past conversations"
      >
        History{threadCount ? ` ${threadCount}` : ''}
      </button>
      <button
        type="button"
        className="aic__iconbtn"
        onClick={() => setMode(!detached)}
        title={detached ? 'Dock this back into the side panel' : 'Detach into a window you can move and resize'}
        aria-label={detached ? 'Dock the assistant' : 'Detach the assistant'}
      >
        <Icon.PanelLeft />
      </button>
      <button type="button" className="aic__iconbtn" onClick={onClose} aria-label="Close the assistant">✕</button>
    </div>
  );

  const thread$ = (
    <div className="aic__thread" ref={bodyRef} onScroll={onScroll}>
      {/* HISTORY, where the panel is too narrow for the canvas beside the thread: it takes the
          reading column, and the composer below it stays pinned — Stop has to remain reachable for
          the whole run whatever else is on screen. */}
      {showCanvas && !wide && (
        <HistoryCanvas
          runs={runs} busy={loadingRuns} full filter={histFilter} onFilter={setHistFilter}
          onOpen={openRun} onDelete={remove} onClose={() => setView('chat')}
        />
      )}

      {(!showCanvas || wide) && (
        <div className={cx('aic__column', configured && !run && 'aic__column--hero')}>
          {settings.isLoading && <div className="aic-busy"><span className="spinner" style={{ width: 12, height: 12 }} />Loading assistant settings</div>}
          {settings.isError && <div className="aic-warn" role="alert"><Icon.Warn /><span>{errMsg(settings.error)}</span></div>}

          {provider === 'none' && (
            <div className="ai-cta">
              <div className="ai-cta__title">The assistant is off</div>
              <div className="ai-cta__body">
                Add an OpenAI API key (or point the base URL at any OpenAI-compatible endpoint such as Ollama, LM Studio or vLLM)
                to let the assistant investigate the logs with the app&rsquo;s own search, timeline, graph and case tools. The model
                must support tool calling.
              </div>
              <Link to="/settings#ai" className="aic__pill" onClick={onClose}>Open settings</Link>
            </div>
          )}

          {provider && provider !== 'none' && !run && (
            <div className="aic-hero">
              {scopeNote && (
                <div className="aic-hero__ctx"><b>Context</b>{scopeNote}</div>
              )}
            </div>
          )}

          {provider && provider !== 'none' && run && (
            <>
              {thread.map((t) => (
                <Turn key={t.id} run={t} entries={t.transcript} live={false}
                      undoing={undoingId === t.id} onUndo={undoRun} onRetry={retry} />
              ))}
              <Turn run={run} entries={entries} live={live} undoing={undoingId === run.id}
                    onUndo={undoRun} onRetry={retry} />
            </>
          )}

          {error && <div className="aic-warn" role="alert"><Icon.Warn /><span>{error}</span></div>}
        </div>
      )}

      {/* THE COMPOSER, sticky at the bottom of the scroller — the template's own arrangement, and
          what keeps Stop reachable for the whole duration of a run. */}
      {provider && provider !== 'none' && (
        <div className="aic__dock">
          <div className="aic__dockin">
            {!atBottom && live && (
              <button type="button" className="aic__jump" onClick={jumpToLatest}>Jump to latest</button>
            )}
            <form
              className={cx('aic-comp', live && 'aic-comp--live')}
              onSubmit={(e) => { e.preventDefault(); send(); }}
            >
              <textarea
                ref={promptRef}
                className="aic-comp__input"
                rows={1}
                value={prompt}
                onChange={(e) => setPrompt(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
                }}
                placeholder={live
                  ? 'The assistant is working — stop it to ask something else'
                  : continueFrom
                    ? 'Ask a follow-up. It keeps everything this conversation established.'
                    : 'Describe the investigation — an entity to trace, a question, a case to build.'}
                aria-label="What should the assistant investigate?"
                disabled={live}
              />
              <div className="aic-comp__bar">
                <PromptPicker
                  prompts={savedPrompts}
                  defaultId={settings.data?.ai.systemPromptId ?? ''}
                  value={spChoice}
                  onChange={pickSystemPrompt}
                  disabled={live}
                  builtinEdited={!!systemPrompts.data?.builtinEdited}
                  onNavigate={onClose}
                />
                <span className="aic-comp__hint" aria-hidden>
                  {live ? 'running' : continueFrom ? 'Enter to continue' : 'Enter to send · Shift+Enter for a line'}
                </span>
                {live ? (
                  <button
                    type="button"
                    className="aic-comp__send"
                    onClick={stop}
                    disabled={stopping}
                    title={stopping ? 'Stopping the run…' : 'Stop the run on the server'}
                    aria-label="Stop the run"
                  >
                    <span className="aic-comp__stop" aria-hidden />
                  </button>
                ) : (
                  <button
                    type="submit"
                    className="aic-comp__send"
                    disabled={!canSend}
                    title={continueFrom ? 'Send the follow-up' : 'Start the investigation'}
                    aria-label={continueFrom ? 'Send the follow-up' : 'Start the investigation'}
                  >
                    <span className="aic-comp__arrow" aria-hidden>↑</span>
                  </button>
                )}
              </div>
            </form>
            <div className="aic-comp__note">
              {live
                ? 'Stop halts the run on the server at its next checkpoint — anything already written stays and can be reverted.'
                : continueFrom
                  ? 'This continues the conversation above — the assistant keeps what it already found and does not start over.'
                  : 'Everything is kept in History and survives a refresh. You can keep asking follow-ups in the same chat.'}
            </div>
          </div>
        </div>
      )}
    </div>
  );

  const body = (
    <div className="aic__shell" ref={shellRef}>
      {thread$}
      {showCanvas && wide && (
        <HistoryCanvas
          runs={runs} busy={loadingRuns} full={false} filter={histFilter} onFilter={setHistFilter}
          onOpen={openRun} onDelete={remove} onClose={() => setView('chat')}
        />
      )}
    </div>
  );

  if (detached) {
    return (
      <FloatingWindow
        storageKey="ai"
        flush
        closeOnEscape={false}
        ariaLabel="AI assistant"
        className="floatwin--aic aic"
        /* The window's title bar IS the template header, so there is never a header above a header
           and the whole 58px bar stays the drag handle. */
        head={header}
        title={<span className="aic-win__title">AI assistant</span>}
        onClose={onClose}
        /* Sized for READING first: the template's column is 792px plus its 26px gutters, so ~880 of
           content shows the answer at its intended measure AND leaves room for the 470px canvas
           beside it. FloatingWindow clamps to the viewport, so a laptop still gets a window that
           fits — it simply falls back to the single-column layout. */
        defaultBox={{ w: Math.min(1180, Math.max(700, window.innerWidth - 160)),
                      h: Math.min(820, window.innerHeight - 100) }}
        minW={420}
        minH={420}
      >
        {body}
      </FloatingWindow>
    );
  }

  return (
    <>
      <div className="overlay" onClick={onClose} />
      <aside className="ai-panel aic" role="dialog" aria-modal="true" aria-label="AI assistant">
        {header}
        {body}
      </aside>
    </>
  );
}
