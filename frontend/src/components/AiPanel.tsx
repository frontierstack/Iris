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
import { Fragment, memo, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState,
         useSyncExternalStore } from 'react';
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
 * So arrival is decoupled from painting. Deltas go into a buffer and one requestAnimationFrame loop
 * plays it out — and HOW MUCH it plays per frame is the part that was still wrong. The first cut
 * drained a fixed SHARE of the backlog per frame (`length * dt / 130`), which is an exponential decay:
 * a packet of five tokens went 3-2-2-1-1-1-1… characters a frame and then STOPPED until the next packet,
 * so the screen still pulsed with the wire, only rounded off. Reported as "skippy and not smooth".
 *
 * The loop is a JITTER BUFFER now, the way audio playback handles the same problem. It measures the
 * ARRIVAL rate over the recent window (`STREAM_RATE_WINDOW_MS`), runs a deliberate lag behind the
 * wire, and paints at that rate: a little under it while the backlog is still filling to the lag
 * (never below half, so a stall drains the last words rather than leaving them hanging), and over it
 * by whatever exceeds the lag, worked off across `STREAM_CATCHUP_MS` — so a burst plays out over a few
 * frames instead of landing at once, and the backlog is bounded whatever the wire does. Fractions of a
 * character carry between frames, so a slow model types at ITS rate rather than one whole character
 * per frame in spurts. Painting is on the frame clock, which is the only clock the screen has.
 *
 * The lag ADAPTS to the wire (`STREAM_LAG_MIN_MS` … `STREAM_LAG_MAX_MS`): a buffer can only absorb a
 * gap it is longer than, so it is sized from the largest gap between arrivals in the window. A
 * provider that streams per token pays the minimum; a gateway that coalesces 400 ms of tokens into one
 * packet pays ~500 ms once and then reads as a steady flow instead of a lump every 400 ms. Simulated
 * on that wire before shipping: 29 empty frames per 2.4 s down to 3.
 *
 * A frame is only affordable because the transcript around the growing paragraph does not re-render:
 * `Markdown`, `ToolCall` and `StepsCard` are all memoised, and the growing block itself is split by
 * `LiveMarkdown` so that only its unfinished tail is re-parsed. Take those away and this rate becomes a
 * stutter of a different kind.
 */
const STREAM_LAG_MIN_MS = 160;      // how far behind the wire the screen runs on a per-token stream
const STREAM_LAG_MAX_MS = 1200;     // and at most, however coarse the packets are
// ...raised from 600 on the third report of a skippy stream. A buffer can only absorb a gap it is
// LONGER than, and the lag is sized from the largest gap in the window (`1.2 * gap`), so a gateway
// that coalesces a second of tokens into one packet was clamped to 600 ms and still painted a lump
// every second. The window itself bounds this: gaps are measured inside STREAM_RATE_WINDOW_MS, so
// the lag can never exceed ~1.2x that, and a fine per-token stream still pays the MINIMUM — the cap
// only ever applies to a wire that has already been measured as coarse.
const STREAM_RATE_WINDOW_MS = 1200; // the window the arrival rate and the gaps are measured over
const STREAM_CATCHUP_MS = 400;      // a backlog beyond the lag is worked off across this long
const STREAM_DEFAULT_CPS = 180;     // characters per second assumed until there is a rate to measure
const EVENT_DRAIN_MS = 260;         // longest a tool card waits for the sentence that introduces it
const EVENT_DRAIN_MIN = 12;         // ...below which draining is a frame's work and not worth waiting

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

/**
 * Arguments that are PROSE the model wrote for the analyst — a note body, a case summary, a link's
 * `why`. They are markdown, and flattening one into a single ellipsised line turned a note into
 * `## Indicators | value | kind | … |---|---|`, which is the note's own table read as a string.
 */
const PROSE_ARGS = new Set(['text', 'summary', 'why', 'description', 'note', 'notes', 'body', 'title']);
function isProse(k: string, raw: unknown): boolean {
  // A LONE HYPHEN IS NOT MARKDOWN. The old test put `-` in the character class, so any short title
  // containing one — "Credential stuffing against svc-backup" — was promoted to the full prose
  // treatment and drawn as a bordered, 280px-tall scrolling panel for thirty-seven characters. A
  // dash only means a bullet at the START of a line, which is what this asks for instead.
  if (!PROSE_ARGS.has(k) || typeof raw !== 'string') return false;
  const md = /[\n#|`]/.test(raw) || /(^|\n)[ \t]*[-*+][ \t]/.test(raw);
  return raw.length > 80 || md || raw.includes('\\n');
}

/** Tool arguments as key/value rows — a labelled list, not one run-on line. */
function argRows(args: Record<string, unknown>): Array<{ k: string; v: string; prose: boolean }> {
  const out: Array<{ k: string; v: string; prose: boolean }> = [];
  for (const [k, raw] of Object.entries(args ?? {})) {
    const v = argValue(raw);
    if (v) out.push({ k, v, prose: isProse(k, raw) });
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
  | { k: 'note'; key: number; text: string; turn: boolean; agent?: string; phase?: string; task?: string; said?: string }
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
        // `agent`/`phase` ride along so the card can fold a delegation's per-agent lines into ONE
        // roster instead of a column of near-identical sentences. Persisted on the entry, so this
        // works in a polling tab and after a reload too.
        if (e.text.trim()) {
          out.push({ k: 'note', key: e.seq, text: e.text, turn, agent: e.agent, phase: e.phase, task: e.task, said: e.said });
          turn = false;
        }
        continue;
      }
      // The model narrates what it is looking for in the SAME turn as the call (see the NARRATE
      // section of INVESTIGATOR_SYSTEM), so that sentence arrives as prose immediately before this
      // tool call. It is ABOUT this call — left as its own node it read as a floating remark one card
      // above the thing it explains, so it is folded into the card as its lead line. Only the prose
      // directly ahead of the call, and only within the same turn, is claimed this way; a sentence
      // that follows a result stays where it is, because there it is the conclusion drawn from it.
      // ...and a STATUS LINE IN BETWEEN MUST NOT ORPHAN IT. The lane announcement ("3 tools
      // running in parallel: …") is emitted after the sentence that introduces those calls and
      // before the calls themselves, so looking only at the node immediately behind meant every
      // PARALLEL lane left its narration behind — and the more the assistant fanned out, the more
      // stray paragraphs collected under the report. Look back PAST the notes; stop at anything
      // else, so a sentence written after a result is still never claimed by a later call.
      let back = out.length - 1;
      while (back >= 0 && out[back]!.k === 'note') back -= 1;
      const prev = back >= 0 ? out[back]! : undefined;
      let lead = '';
      if (prev && prev.k === 'prose' && !turn) { lead = prev.text; out.splice(back, 1); }
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
 * The block that is still being WRITTEN.
 *
 * It goes through the same renderer as a finished one — headings, lists, tables and code render as they
 * stream, not once the turn ends — but the text is split at its last blank line that is not inside an
 * open fence. Everything before it is settled markdown and is parsed only when that boundary moves
 * (`LiveHead` is memoised on its own text); only the unfinished tail is re-parsed per frame, and it is
 * a paragraph, not the report. Blank-line splitting is exact for this renderer: a blank line already
 * ends a list, a quote and a table in `renderMarkdown`, so the two halves parse as the whole would —
 * a fence is the one construct that may span one, hence the parity check.
 *
 * The tail is also rendered with its dangling inline marks CLOSED: `**Finding 1` is drawn bold while
 * the closing mark is still on the wire, a half-typed `code` span as code. Without this the tail
 * reads as raw markdown for as long as a slow model takes to reach the closing mark — the last line
 * of the answer, the one being read, looking like source. Display only; the stored text is untouched.
 */
const FENCE_LINES = /^[ \t]*```/gm;
function splitLive(text: string): [string, string] {
  let at = text.lastIndexOf('\n\n');
  while (at > 0) {
    const head = text.slice(0, at);
    if ((head.match(FENCE_LINES) ?? []).length % 2 === 0) return [head, text.slice(at)];
    at = text.lastIndexOf('\n\n', at - 1);
  }
  return ['', text];
}
function closeDangling(tail: string): string {
  if ((tail.match(FENCE_LINES) ?? []).length % 2) return tail;      // inside a fence: it is code, not marks
  let out = tail;
  for (const mark of ['`', '**', '~~']) {
    if (out.endsWith(mark)) continue;                                // just opened: nothing to enclose yet
    if ((out.split(mark).length - 1) % 2) out += mark;
  }
  return out;
}
const LiveHead = memo(function LiveHead({ text }: { text: string }) {
  return <>{renderMarkdown(text)}</>;
});
const LiveMarkdown = memo(function LiveMarkdown({ text, className }: { text: string; className: string }) {
  const [head, tail] = splitLive(text.replace(/\r\n?/g, '\n'));
  return (
    <div className={className}>
      {head ? <LiveHead text={head} /> : null}
      {renderMarkdown(closeDangling(tail))}
    </div>
  );
});

/**
 * THE GROWING TAIL LIVES OUTSIDE REACT STATE, AND THAT IS WHAT MAKES THE STREAM SMOOTH.
 *
 * The jitter buffer above decides WHEN a character should appear. It cannot decide what that costs,
 * and the cost was the whole panel: each frame called `setEntries`, so `AiPanel` re-rendered, and
 * with it `toBlocks` over every entry, `trailNodes` twice, an `answer.includes` pass per prose block,
 * a fresh `nodes` array (so `StepsCard` reconciled every tool card it holds), the composer, the
 * header and the history rail. At sixty frames a second on a transcript holding thirty calls, the
 * frame budget went on rebuilding the conversation around the sentence being written — so frames were
 * dropped in clumps and the text arrived in the lumps the buffer had just smoothed out. Memoising the
 * markdown fixed the PARSING and left all of that in place.
 *
 * So the tail is a module-level store and one leaf subscribes to it. A frame now re-renders exactly
 * one component and re-parses exactly one paragraph; nothing above it in the tree is told anything.
 * The text is committed into `entries` only when a non-delta event arrives or the stream ends — the
 * same boundaries `flushText` always used, so the ORDER on screen is unchanged and a tool card can
 * still never appear ahead of the sentence that introduced it.
 *
 * `prefix` is the last committed prose block. The tail renders it in the same `<div>` so a sentence
 * that straddles a commit is one paragraph rather than two, and `splitLive`/`LiveHead` mean the
 * settled part of it is not re-parsed per frame either.
 */
const liveTail = {
  text: '',
  subs: new Set<() => void>(),
  get() { return this.text; },
  set(t: string) { if (t !== this.text) { this.text = t; this.subs.forEach((f) => f()); } },
  subscribe(f: () => void) { this.subs.add(f); return () => { this.subs.delete(f); }; },
};

const LiveTail = memo(function LiveTail({ prefix, className, onPaint }: {
  prefix: string; className: string; onPaint?: () => void;
}) {
  const tail = useSyncExternalStore(
    useCallback((f: () => void) => liveTail.subscribe(f), []),
    useCallback(() => liveTail.get(), []),
  );
  // Pinning to the bottom is a LAYOUT effect for the reason the panel's own one is: a passive effect
  // runs after the frame has painted, so the paragraph would grow a line with the scroller still at
  // its old bottom and jump a frame later — a stutter at exactly the line being read. It lives here
  // rather than in the panel because the panel no longer re-renders while the text grows.
  useLayoutEffect(() => { onPaint?.(); }, [tail, prefix, onPaint]);
  if (!prefix && !tail) return null;
  return (
    <>
      <LiveMarkdown className={className} text={prefix + tail} />
      <span className="aic-caret" aria-hidden />
    </>
  );
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
/**
 * A NARRATION LINE HAS A SHAPE, and the screen shows it.
 *
 * NARRATE in the system prompt asks for "what the last result established, with its numbers — then
 * what you are doing next". Drawn as one muted paragraph, the finding and the intention read the same
 * and a long run was a column of sentences to parse. Split on the dash (or semicolon) the prompt asks
 * for, the finding is the line that carries weight and the next step is a quieter line under it.
 * A line with no separator is ONE of the two, judged by how it opens — never invented into both.
 * A hyphen between digits is a range ("02:14 - 02:19"), not the separator.
 */
const NARR_SEP = /\s+[\u2014\u2013]\s+|(?<!\d)\s+-\s+(?!\d)|;\s+/;
const NARR_INTENT = /^(?:now|next|then|first|before|let me|i'll|i will|i'm|going to|to see|to check)\b|^[a-z]+ing\b/i;

export function splitNarration(text: string): { found: string; next: string } {
  const t = text.replace(/\s+/g, ' ').trim();
  const m = NARR_SEP.exec(t);
  if (m && m.index >= 8 && t.length - (m.index + m[0].length) >= 8) {
    const head = t.slice(0, m.index).trim();
    // "Profiling X first - one call gives me..." is an intention with its reason, not a finding:
    // labelling its first half "Found" would claim a result the run has not had yet.
    if (NARR_INTENT.test(head)) return { found: '', next: t };
    const rest = t.slice(m.index + m[0].length).trim();
    return { found: head, next: rest.charAt(0).toUpperCase() + rest.slice(1) };
  }
  return NARR_INTENT.test(t) ? { found: '', next: t } : { found: t, next: '' };
}

const Narration = memo(function Narration({ text, className }: { text: string; className?: string }) {
  const { found, next } = splitNarration(text);
  if (!found && !next) return null;
  return (
    <div className={cx('tnarr', className)}>
      {!!found && (
        <div className="tnarr__row tnarr__row--found">
          <span className="tnarr__k">Found</span>
          <Markdown className="md tnarr__v" text={found} />
        </div>
      )}
      {!!next && (
        <div className="tnarr__row tnarr__row--next">
          <span className="tnarr__k">Next</span>
          <Markdown className="md tnarr__v" text={next} />
        </div>
      )}
    </div>
  );
});

/** The narration lines of a trail, in order — each card's lead, once. */
function leadsOf(nodes: TrailNode[]): string[] {
  return nodes.flatMap((n) => (n.k === 'tool' && n.lead.trim() ? [n.lead] : []));
}

const OUTLINE_MAX = 8;

const ToolCall = memo(function ToolCall({ e, live, lead = '' }: { e: AiTranscriptEntry; live: boolean; lead?: string }) {
  const [open, setOpen] = useState(false);
  const rows = argRows(e.args ?? {});
  const shown = open ? rows : rows.slice(0, ARGS_SHOWN);
  const hidden = rows.length - shown.length;
  const Glyph = toolIcon(e.name);
  const bad = e.ok === false;
  return (
    <div className={cx('tcall', e.writes && 'tcall--write', bad && !e.writes && 'tcall--bad')}>
      {!!lead.trim() && <Narration className="tcall__lead" text={lead} />}
      {/* There is ONE card and ONE head, so `e.writes` is read here and nowhere else — the rule that
          stops one layout drawing a write as a read. Keep it that way if a variant is ever added. */}
      <div className="tcall__card">
      <div className="tcall__head">
        <span className="tcall__glyph" aria-hidden><Glyph /></span>
        <span className="tcall__name">{e.name}</span>
        {e.writes && <span className="tcall__kind" title="this tool changed the case">write</span>}
        {(e.lane ?? 1) > 1 && (
          <span className="tcall__kind tcall__kind--par"
                title={`dispatched at the same time as ${(e.lane ?? 1) - 1} other call${e.lane === 2 ? '' : 's'}`}>
            parallel
          </span>
        )}
        {e.ok === null && live && <span className="spinner" style={{ width: 9, height: 9, borderWidth: 1.5 }} />}
        {e.ok === null && !live && <span className="tcall__unknown" title="the run ended before this call reported back">—</span>}
        {!!e.tookMs && <span className="tcall__ms">{e.tookMs} ms</span>}
      </div>

      {!!shown.length && (
        <dl className="tcall__args">
          {shown.map((r) => (
            <div className={cx('tcall__arg', r.prose && 'tcall__arg--prose')} key={r.k}>
              <dt>{r.k}</dt>
              {r.prose
                ? <dd><Markdown className="md tcall__md" text={r.v} /></dd>
                : <dd title={r.v}>{r.v}</dd>}
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
  if (a.k === 'note') return b.k === 'note' && a.text === b.text && a.said === b.said;
  return a.text === (b as { text: string }).text;
}

/**
 * THE TRAIL IS GROUPED, because the work is grouped.
 *
 * A flat column of cards cannot show the one thing the analyst asked to be able to see: that several
 * calls are in flight AT THE SAME TIME. `lane` on an entry is the WIDTH of its dispatch group and
 * `laneId` is WHICH group — both persisted — so consecutive cards sharing a laneId are one block with
 * one head ("3 calls at the same time"), drawn inside a bracket. A call that ran alone is unchanged.
 *
 * The other grouping is the AGENT ROSTER. `delegate_investigation` reports per agent as it goes
 * (started / working / finished), which arrived as three or more separate status lines per agent —
 * the transcript noise this panel keeps deleting. Consecutive agent lines become one roster: a row
 * per agent, its latest state, and nothing repeated.
 */
type TrailGroup =
  | { g: 'one'; key: number; node: TrailNode }
  | { g: 'lane'; key: number; nodes: Array<Extract<TrailNode, { k: 'tool' }>>; turn: boolean }
  | { g: 'agents'; key: number; rows: AgentRow[]; turn: boolean };

// The status line the loop writes before a parallel lane ("3 tools running in parallel: …").
const LANE_NOTE = /^[0-9]+ tools running in parallel:/;

function groupTrail(nodes: TrailNode[]): TrailGroup[] {
  const out: TrailGroup[] = [];
  for (const [i, n] of nodes.entries()) {
    const last = out[out.length - 1];
    // The lane's own head already says "N calls at the same time", and the announcement sat BETWEEN
    // the narration and the group it introduces. Dropped only when the lane is actually drawn next.
    if (n.k === 'note' && !n.agent && LANE_NOTE.test(n.text)) {
      const nx = nodes[i + 1];
      if (nx && nx.k === 'tool' && (nx.e.lane ?? 1) > 1 && (nx.e.laneId ?? 0) > 0) continue;
    }
    if (n.k === 'tool' && (n.e.lane ?? 1) > 1 && (n.e.laneId ?? 0) > 0) {
      if (last && last.g === 'lane' && (last.nodes[0]!.e.laneId ?? -1) === n.e.laneId) {
        last.nodes.push(n);
        continue;
      }
      out.push({ g: 'lane', key: n.key, nodes: [n], turn: n.turn });
      continue;
    }
    if (n.k === 'note' && n.agent) {
      const row: AgentRow = { agent: n.agent, phase: n.phase ?? '', text: n.text, task: taskOf(n), said: n.said ?? '' };
      if (last && last.g === 'agents') {
        // one row per agent: the latest line about it wins, so "started" is replaced by "finished"
        // — but its QUESTION is carried across, because only the `start` line ever carries it and
        // a roster of three agents that does not say what any of them was asked is three names.
        // That is most of "I am not seeing multiple agents working".
        const at = last.rows.findIndex((r) => r.agent === row.agent);
        if (at >= 0) last.rows[at] = { ...row, task: row.task || last.rows[at]!.task, said: row.said || last.rows[at]!.said };
        else last.rows.push(row);
        continue;
      }
      out.push({ g: 'agents', key: n.key, rows: [row], turn: n.turn });
      continue;
    }
    // the rolled-up "agents working: A (3 calls), B (2 calls)" tick belongs to the roster above it
    if (n.k === 'note' && n.phase === 'tick' && last && last.g === 'agents') continue;
    out.push({ g: 'one', key: n.key, node: n });
  }
  return out;
}

function sameGroup(a: TrailGroup, b: TrailGroup): boolean {
  if (a.g !== b.g || a.key !== b.key) return false;
  if (a.g === 'one') return b.g === 'one' && sameNode(a.node, b.node);
  if (a.g === 'lane') {
    return b.g === 'lane' && a.turn === b.turn && a.nodes.length === b.nodes.length
      && a.nodes.every((n, i) => sameNode(n, b.nodes[i]!));
  }
  return b.g === 'agents' && a.turn === b.turn && a.rows.length === b.rows.length
    && a.rows.every((r, i) => r.agent === b.rows[i]!.agent && r.text === b.rows[i]!.text
      && r.task === b.rows[i]!.task && r.said === b.rows[i]!.said);
}

/** One worker agent in the roster. `task` is its question, which only the `start` line carries. */
type AgentRow = { agent: string; phase: string; text: string; task: string; said: string };

/** The question out of an agent status line: "agent <name> started: <the question>". */
function taskOf(n: Extract<TrailNode, { k: 'note' }>): string {
  // The entry's own `task` field first: the agent's line is PATCHED in place while it works, so by
  // the time anyone reloads the run its text says "finished" and the question is only here.
  if (n.task) return n.task;
  if ((n.phase ?? '') !== 'start') return '';
  const m = /started:\s*([\s\S]+)$/.exec(n.text);
  return (m ? m[1]! : '').trim();
}

/** The state of one worker agent, for the roster's tag. */
const AGENT_STATE: Record<string, string> = { start: 'working', call: 'working', end: 'finished' };

function AgentRoster({ rows, live }: { rows: AgentRow[]; live: boolean }) {
  const working = rows.filter((r) => r.phase !== 'end').length;
  return (
    <div className="aroster">
      <div className="aroster__head">
        <span className="aroster__tile" aria-hidden>{rows.length}</span>
        <span className="aroster__title">
          {rows.length} agent{rows.length === 1 ? '' : 's'} on separate questions
        </span>
        {live && working > 0 && (
          <span className="aic-par" title="each agent is a read-only tool loop of its own, running now">
            <span className="aic-par__dots" aria-hidden><i /><i /><i /></span>
            {working} working
          </span>
        )}
      </div>
      <ul className="aroster__list">
        {rows.map((r) => (
          <li key={r.agent} className={cx('aroster__row', r.phase === 'end' && 'aroster__row--done')}>
            <span className="aroster__line">
              <span className="aroster__who">{r.agent}</span>
              <span className="aroster__state">{AGENT_STATE[r.phase] ?? r.phase ?? ''}</span>
              {live && r.phase !== 'end' && <span className="spinner" style={{ width: 9, height: 9, borderWidth: 1.5 }} />}
              {/* the start line only restates the question, which has its own line below */}
              {r.phase !== 'start' && <span className="aroster__what">{r.text.replace(/^agent \S+ /, '')}</span>}
            </span>
            {!!r.task && <span className="aroster__task" title={r.task}>{r.task}</span>}
            {/* the agent's OWN account of its latest step — what a call count cannot say */}
            {!!r.said && <Narration className="aroster__said" text={r.said} />}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** The counts that head the steps card — one sentence, computed in one place. */
function countsOf(nodes: TrailNode[]): { bits: string[]; pending: boolean; tools: number; inflight: number } {
  const tools = nodes.filter((n): n is Extract<TrailNode, { k: 'tool' }> => n.k === 'tool');
  const writes = tools.filter((t) => t.e.writes).length;
  const failed = tools.filter((t) => t.e.ok === false).length;
  // Cards still waiting for a result. More than one at a time is the whole visible difference the
  // parallel lanes make, and it is what the analyst asked to be able to SEE.
  const inflight = tools.filter((t) => t.e.ok === null).length;
  // WORKER AGENTS COUNT AS WORK DONE. A delegation is one tool call on this card and three agents
  // doing their own research underneath it — so a run that fanned out read "9 tool calls" and said
  // nothing at all about the twenty-seven calls its agents made, which is the collapsed card the
  // analyst sees by default. Distinct names, because a roster reports each agent several times.
  const agents = new Set(nodes.filter((n): n is Extract<TrailNode, { k: 'note' }> => n.k === 'note')
    .map((n) => n.agent ?? '').filter(Boolean)).size;
  const bits: string[] = [];
  if (tools.length) bits.push(`${tools.length} tool call${tools.length === 1 ? '' : 's'}`);
  else if (nodes.length) bits.push(`${nodes.length} note${nodes.length === 1 ? '' : 's'}`);
  if (agents) bits.push(`${agents} agent${agents === 1 ? '' : 's'}`);
  if (writes) bits.push(`${writes} write${writes === 1 ? '' : 's'}`);
  if (failed) bits.push(`${failed} refused`);
  return { bits, pending: inflight > 0, tools: tools.length, inflight };
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

  const { bits, pending, inflight } = countsOf(nodes);
  const groups = groupTrail(nodes);
  // THE STORY OF THE RUN, from its own narration. Live, the latest line says what is happening NOW
  // on the card's head, so the analyst does not have to find the newest card to know. Finished and
  // collapsed, the card lists what each step ESTABLISHED — the account of how the answer was reached
  // without opening thirty cards to read it.
  const leads = leadsOf(nodes);
  const latest = leads.length ? splitNarration(leads[leads.length - 1]!) : null;
  const now = latest ? (latest.next || latest.found) : '';
  const outline = leads.map((l) => { const s = splitNarration(l); return s.found || s.next; }).filter(Boolean);

  return (
    <section className={cx('aic-disc', 'aic-steps', open && 'aic-disc--open')}>
      <div className="aic-disc__head">
        <button type="button" className="aic-disc__toggle" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
          <span className={cx('aic-disc__tile', !live && 'aic-disc__tile--idle')} aria-hidden>
            <Icon.Timeline />
            {pending && live && <span className="aic-disc__live" />}
          </span>
          <span className="aic-disc__ident">
            <span className="aic-disc__title">{title}</span>
            {live && inflight > 1 && (
              <span className="aic-par" title="independent reads of one turn are dispatched together; writes are not">
                <span className="aic-par__dots" aria-hidden><i /><i /><i /></span>
                {inflight} running in parallel
              </span>
            )}
            {!!bits.length && <span className="aic-disc__meta">{bits.join(' · ')}</span>}
            {live && !!now && <span className="aic-disc__now" title={now}><b>Now</b>{now}</span>}
          </span>
          <span className="aic-disc__state" aria-hidden>{open ? <><Icon.Minus /> Collapse</> : <><Icon.Plus /> Expand</>}</span>
        </button>
      </div>
      {!open && !live && outline.length > 0 && (
        <ol className="aic-outline" aria-label="what each step established">
          {outline.slice(0, OUTLINE_MAX).map((s, i) => (
            <li key={i} className="aic-outline__item"><Markdown className="md aic-outline__md" text={s} /></li>
          ))}
          {outline.length > OUTLINE_MAX && (
            <li className="aic-outline__more">
              <button type="button" onClick={() => setOpen(true)}>
                {outline.length - OUTLINE_MAX} more step{outline.length - OUTLINE_MAX === 1 ? '' : 's'} — expand to read them all
              </button>
            </li>
          )}
        </ol>
      )}
      {open && (
        <div className="aic-steps__body">
          {groups.map((g) => {
            if (g.g === 'lane') {
              const done = g.nodes.filter((n) => n.e.ok !== null).length;
              // The line that introduces a PARALLEL group belongs to the group, not to its first card:
              // it explains why these calls went out together.
              const laneLead = g.nodes.map((n) => n.lead).find((l) => l.trim()) ?? '';
              return (
                <div key={g.key} className={cx('aic-step', g.turn && 'aic-step--turn')}>
                  {!!laneLead && <Narration className="tlane__lead" text={laneLead} />}
                  <div className={cx('tlane', done < g.nodes.length && live && 'tlane--live')}>
                    <div className="tlane__head">
                      <span className="tlane__bars" aria-hidden><i /><i /><i /></span>
                      <span className="tlane__what">{g.nodes.length} calls at the same time</span>
                      <span className="tlane__prog">
                        {done < g.nodes.length && live
                          ? `${g.nodes.length - done} still running`
                          : `${done} of ${g.nodes.length} answered`}
                      </span>
                    </div>
                    <div className="tlane__body">
                      {g.nodes.map((n) => <ToolCall key={n.key} e={n.e} live={live} lead={n.lead === laneLead ? '' : n.lead} />)}
                    </div>
                  </div>
                </div>
              );
            }
            if (g.g === 'agents') {
              return (
                <div key={g.key} className={cx('aic-step', g.turn && 'aic-step--turn')}>
                  <AgentRoster rows={g.rows} live={live} />
                </div>
              );
            }
            const n = g.node;
            return (
              <div key={g.key} className={cx('aic-step', n.turn && 'aic-step--turn')}>
                {n.k === 'tool' && <ToolCall e={n.e} live={live} lead={n.lead} />}
                {n.k === 'note' && <Markdown className="md aic-bare__note" text={n.text} />}
                {n.k === 'prose' && <Markdown className="md aic-prose aic-prose--quiet" text={n.text} />}
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}, (a, b) => (
  a.live === b.live && a.title === b.title && a.startOpen === b.startOpen &&
  a.nodes.length === b.nodes.length && a.nodes.every((n, i) => sameNode(n, b.nodes[i]!))
));
// `sameGroup` is exported-in-module for the grouping above; keeping it next to `sameNode` is what
// stops the two drifting if the group shapes ever gain a field.
void sameGroup;

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
 * because it is the part that persists. CLOSED by default: the head says how much changed and of
 * what kind, and opening it shows a TIMELINE — the clock down a rail, one node per change, the
 * change itself as the line and the family it belongs to as a tag. Every entry is reversible in one
 * click; a reverted one stays on the rail as a hollow node, struck through, rather than disappearing.
 */
/**
 * The ledger is grouped by WHAT CHANGED, then chronological inside each group.
 *
 * A flat time-ordered list answered "in what order did it write?", which nobody asks. What the
 * analyst asks is "did it write any indicators?" and "what did it put on the timeline?" — and with
 * twenty rows of mixed families that is a scan of every line. Groups are ordered by the family's
 * first appearance, so the list still reads as the run's own sequence rather than as an alphabet.
 */
function byFamily(actions: AiAction[]): Array<[string, AiAction[]]> {
  const groups = new Map<string, AiAction[]>();
  for (const a of actions) {
    const f = changeFamily(a.tool);
    const bucket = groups.get(f);
    if (bucket) bucket.push(a); else groups.set(f, [a]);
  }
  return [...groups];
}

function Changes({ actions, busy, onUndo }: { actions: AiAction[]; busy: boolean; onUndo: () => void }) {
  const [open, setOpen] = useState(false);
  const active = actions.filter((a) => !a.undone).length;
  if (!actions.length) return null;
  const reverted = actions.length - active;
  const meta = (active === 0 ? 'everything reverted' : changeBreakdown(actions))
    + (reverted > 0 && active > 0 ? ` · ${reverted} reverted` : '');
  return (
    <section className={cx('aic-disc', 'aic-art', open && 'aic-disc--open')} aria-label="Changes this run made to the case">
      <div className="aic-disc__head">
        <button type="button" className="aic-disc__toggle" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
          <span className={cx('aic-disc__tile', active === 0 && 'aic-disc__tile--idle')} aria-label={`${active} active changes`}>{active}</span>
          <span className="aic-disc__ident">
            <span className="aic-disc__title">Changes to this case</span>
            <span className="aic-disc__meta">{meta}</span>
          </span>
          <span className="aic-disc__state" aria-hidden>{open ? <><Icon.Minus /> Collapse</> : <><Icon.Plus /> Expand</>}</span>
        </button>
        {active > 0 && (
          <button type="button" className="aic-disc__act" onClick={onUndo} disabled={busy}>
            {busy ? 'Reverting…' : 'Revert all'}
          </button>
        )}
      </div>
      {open && (
        <ol className="aic-tl">
          {byFamily(actions).map(([family, rows]) => (
            <Fragment key={`g-${family}`}>
              <li className="aic-tl__group" aria-hidden>
                <span className="aic-tl__gname">{family}</span>
                <span className="aic-tl__gn">
                  {rows.filter((r) => !r.undone).length || rows.length}
                </span>
              </li>
              {rows.map((a) => {
              const Glyph = toolIcon(a.tool);
              const clock = clockOf(a.at);
              return (
                <li key={a.id} className={cx('aic-tl__item', a.undone && 'aic-tl__item--undone')}>
                  <span className="aic-tl__when">
                    {clock && <time dateTime={a.at} title={UTC(a.at)}>{clock}</time>}
                  </span>
                  <span className="aic-tl__node" aria-hidden><Glyph /></span>
                  <span className="aic-tl__body">
                    <span className="aic-tl__summary">{a.summary}</span>
                    <span className="aic-tl__sub">
                      <span className="aic-tl__kind" title={a.tool}>{changeFamily(a.tool)}</span>
                      <span className="aic-tl__what">{writeLabel(a.tool)}</span>
                      {a.undone && <span className="aic-tl__tag">reverted</span>}
                    </span>
                  </span>
                  </li>
                );
              })}
            </Fragment>
          ))}
        </ol>
      )}
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
/** A run that ended on something other than its own conclusion — a limit, a provider that would
 *  not parse its calls, a fold that could not fit, an error — can be picked up from where it stopped
 *  with one click. The follow-up is seeded with the turn's record (ai/continuation.py marks a turn
 *  cut short by a limit as such), so it resumes rather than re-answers. */
const CONTINUE_PROMPT = 'Continue the investigation from where it stopped: pick up the lines of enquiry '
  + 'left unfinished, record what you find in the case as you go, then report.';
function canContinue(run: AiRun): boolean {
  if (run.state === 'running') return false;
  if (run.state === 'error' || run.state === 'stopped') return true;
  return !!run.reason && run.reason !== 'complete';
}

function Turn({ run, entries, live, undoing, onUndo, onRetry, onContinue, onStreamPaint }: {
  run: AiRun; entries: AiTranscriptEntry[]; live: boolean; undoing: boolean;
  onUndo: (id: string) => void; onRetry: (run: AiRun) => void; onContinue: (run: AiRun) => void;
  /** Called after each frame of the live tail paints — the panel pins the scroller with it,
   *  because the panel itself no longer re-renders while the text grows. */
  onStreamPaint?: () => void;
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
  // ...and ONLY the prose no card has claimed. `trailNodes` folds the sentence that introduces a
  // call into that call's own card as its lead line, so filtering `trailBlocks` here printed every
  // one of those a SECOND time — as a run of context-free serif paragraphs directly under the
  // report, reading like five non-sequiturs appended to the answer. What belongs here is what the
  // trail did NOT take: a sentence written after a result, which is a conclusion and has no card.
  const commentary = useMemo(
    () => nodes.filter((n): n is Extract<TrailNode, { k: 'prose' }> => n.k === 'prose'), [nodes]);

  // LIVE: the calls are ONE card, above the prose, not a card per model turn interleaved with it.
  // Threading tool cards through the answer meant the thing being read moved down the page every time
  // a call landed, and the reading column was broken into fragments by cards that are deliberately
  // secondary. Turn breaks are kept, so the sequence is still legible inside the card.
  // ...and the NARRATION RIDES WITH ITS CALLS while the run is live too. It used to be filtered out
  // of the card and printed underneath as a separate column of quiet paragraphs, so the account of
  // the work and the work itself were two lists the analyst had to line up by eye — and only once
  // the run finished did each line move onto its card. Only the TRAILING prose stays outside: until a
  // call arrives after it, it may be the report being written.
  const trailing = blocks.length && blocks[blocks.length - 1]!.kind === 'prose'
    ? blocks[blocks.length - 1] as Extract<Block, { kind: 'prose' }> : null;
  const liveNodes = useMemo(() => trailNodes(trailing ? blocks.slice(0, -1) : blocks), [blocks, trailing]);

  return (
    /* A TURN IS ONE THING, and it has to look like one. The question and its answer used to be two
       siblings of the thread column on the same 34px rhythm as everything else, so in a conversation
       of three exchanges nothing said where one ended and the next began — a follow-up's bubble sat
       below the previous answer's cards at exactly the gap that separated that answer's own parts.
       The turn is an <article> now: its parts sit closer together than turns sit apart, and a turn
       after the first opens on a hairline. */
    <article className="aic-turn">
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
        {/* WHO IS ANSWERING, AND HOW IT WENT — one quiet line, above the answer it belongs to.
            A user message is a bubble and an assistant message is deliberately not one (§9), which
            left the answer with nothing to start it: prose simply began, and what the run cost and
            how it ended was two separate rows of micro-text at the FOOT of the turn — `aic-acts`
            carrying the state and the clock, `aic-meta` carrying the calls, the span and the model.
            Both of those are the turn's identity, not its actions, so they read better as a header
            and leave `aic-acts` to hold only things you can press. */}
        <div className="aic-sig">
          <span className="aic-sig__who">{run.model || 'assistant'}</span>
          <span className="aic-sig__rule" aria-hidden />
          {live ? (
            <span className="aic-sig__live">
              <span className="spinner" style={{ width: 9, height: 9, borderWidth: 1.5 }} />working
            </span>
          ) : (
            <>
              {run.toolCalls > 0 && (
                <span className="aic-sig__fig">{run.toolCalls} call{run.toolCalls === 1 ? '' : 's'}</span>
              )}
              {!!ranFor && <span className="aic-sig__fig">{ranFor}</span>}
              {run.reason && run.reason !== 'complete' && (
                <span className="aic-sig__fig" title="how the run ended">{run.reason.replace(/_/g, ' ')}</span>
              )}
              <span className={cx('aic-state', `aic-state--${run.state}`)}>{STATE_LABEL[run.state]}</span>
            </>
          )}
        </div>
        {live ? (
          <>
            {warnings.map((w) => <Warning key={w.key} text={w.text} />)}
            <StepsCard nodes={liveNodes} live title="Working" startOpen />
            {/* Every SETTLED prose block, then the one still being written. The last settled block is
                handed to `LiveTail` as its prefix rather than rendered here, so a sentence that
                straddles a commit stays ONE paragraph — and so the only thing a frame re-renders is
                that leaf. See the note on `liveTail`. */}
            <LiveTail onPaint={onStreamPaint} className="md aic-prose" prefix={trailing ? trailing.text : ''} />
            {!blocks.length && (
              <div className="aic-busy"><span className="spinner" style={{ width: 12, height: 12 }} />Starting the investigation</div>
            )}
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
              {canContinue(run) && (
                <Micro label="→ Continue" title="Continue the investigation from where this turn stopped"
                  onClick={() => onContinue(run)} />
              )}
              <span className="aic-acts__spacer" />
              {run.endedAt && (
                <span className="aic-acts__time" title={RELATIVE(run.endedAt)}>{UTC(run.endedAt)}</span>
              )}
            </div>

          </>
        )}
      </div>
    </article>
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
    // The tail is module state, not React state, so it does NOT go with the transcript: a few
    // characters still playing out from the previous turn would be the first thing on the new one.
    liveTail.set('');
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

    // Prose arrives one TOKEN at a time, in bursts. See STREAM_LAG_MIN_MS: deltas go into `buffered` and
    // a frame loop plays it out at the measured ARRIVAL rate, a short lag behind the wire, so what is
    // painted is a steady flow rather than the shape of the packets. Every other event flushes the
    // buffer FIRST, so the order on screen is exactly the stream's — a tool card can never appear ahead
    // of the sentence that introduced it.
    let buffered = '';
    let raf = 0;
    let prevTs = 0;
    let carry = 0;                                   // the fraction of a character owed to the next frame
    const arrivals: Array<[number, number]> = [];    // [when, chars] inside the rate window
    let arrived = 0;                                 // chars inside the window
    let queued: AiRunEvent[] = [];                   // events waiting for the prose ahead of them
    let drainBy = 0;                                 // performance.now() the queue must be released by

    const noteArrival = (chars: number) => {
      arrivals.push([performance.now(), chars]);
      arrived += chars;
    };
    /** The wire as measured over the recent window: characters per ms, and the lag (ms) that absorbs
     *  its largest gap. Defaults until there are two arrivals to measure between. */
    const wire = (now: number): { rate: number; lagMs: number } => {
      while (arrivals.length && now - arrivals[0]![0] > STREAM_RATE_WINDOW_MS) arrived -= arrivals.shift()![1];
      if (arrivals.length < 2) return { rate: STREAM_DEFAULT_CPS / 1000, lagMs: STREAM_LAG_MIN_MS };
      let gap = 0;
      for (let i = 1; i < arrivals.length; i++) gap = Math.max(gap, arrivals[i]![0] - arrivals[i - 1]![0]);
      return {
        rate: arrived / Math.max(STREAM_LAG_MIN_MS, now - arrivals[0]![0]),
        lagMs: Math.min(STREAM_LAG_MAX_MS, Math.max(STREAM_LAG_MIN_MS, 1.2 * gap)),
      };
    };

    // WHAT A FRAME COSTS. `paint` puts the character on screen; it does NOT touch React state, so a
    // frame re-renders the one leaf subscribed to `liveTail` and nothing else. `commit` is the
    // expensive one — it moves the played-out text into the transcript — and it runs only at the
    // boundaries `flushText` always used, which is why the ORDER on screen is unchanged.
    const paint = (t: string) => liveTail.set(liveTail.get() + t);

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
      carry = 0;
      drainBy = 0;
    };

    /** End of stream: type nothing more, commit what is left, release anything still queued.
     *  The `done` event is in that queue, and it may not be held back waiting for a frame. */
    const endStream = () => {
      flushText();
      flushQueue();
    };

    /** Everything still buffered, at once, and the played-out tail folded into the transcript.
     *  Used at end of stream, and whenever a queued event has waited long enough (see `queue`). */
    const flushText = () => {
      stopRaf();
      const t = buffered;
      buffered = '';
      // A pending flush must never land on the NEXT conversation: `startRun` aborts the old stream, and
      // a frame that fires after that would append the previous run's tail to a fresh transcript.
      if (ac.signal.aborted) { liveTail.set(''); return; }
      const played = liveTail.get();
      liveTail.set('');
      if (played || t) commit(played + t);
    };

    /**
     * A TOOL CARD MUST NOT MAKE THE SENTENCE BEFORE IT APPEAR ALL AT ONCE.
     *
     * Everything above smooths the arrival of prose. None of it survived contact with the thing the
     * analyst actually watches, which is not a report streaming into an empty panel — it is the
     * running NARRATION: one line of prose, then the tool call it introduces, over and over. Those
     * two arrive in the SAME assistant message, milliseconds apart, and every non-delta event used to
     * dump the whole buffer instantly so that the card could not be drawn ahead of its sentence. So
     * the line was not typed at all: it appeared whole, then a card, then the next line appeared
     * whole. Measured on a twelve-call run against a local-gateway-shaped stream: a median frame
     * advanced the text by 2 characters and eight frames advanced it by SIXTY — those eight are the
     * jumps, and they are what "very skippy and not smooth" describes.
     *
     * The ordering constraint is real and is kept exactly: an event may never be applied before the
     * prose that precedes it. What changes is which side waits. A non-delta event now QUEUES, the
     * frame loop drains the buffer at whatever rate empties it within `EVENT_DRAIN_MS`, and the queue
     * is applied the moment the buffer is empty. The card is late by up to a quarter of a second and
     * the sentence is typed; nothing is reordered, nothing is dropped, and a queue that is already
     * empty of text (a `status` with no prose in front of it, the common case) is applied at once.
     */
    const flushQueue = () => {
      const evs = queued;
      queued = [];
      if (evs.length) {
        // the text that has PLAYED is committed first, so the card lands after its own sentence
        const played = liveTail.get();
        liveTail.set('');
        if (played) commit(played);
        for (const e of evs) apply(e);
      }
    };

    const queue = (ev: AiRunEvent) => {
      queued.push(ev);
      if (ac.signal.aborted) { queued = []; return; }
      // Nothing left to type, or so little that draining it is a frame's work: apply immediately and
      // keep the old behaviour exactly.
      if (buffered.length <= EVENT_DRAIN_MIN) { flushText(); flushQueue(); return; }
      if (!drainBy) drainBy = performance.now() + EVENT_DRAIN_MS;
      if (!raf) raf = requestAnimationFrame(tick);
    };

    const tick = (ts: number) => {
      raf = 0;
      if (ac.signal.aborted) { buffered = ''; prevTs = 0; carry = 0; liveTail.set(''); return; }
      const dt = prevTs ? Math.min(160, ts - prevTs) : 16;
      prevTs = ts;
      const { rate: r, lagMs } = wire(ts);
      const lag = Math.max(1, r * lagMs);
      const fill = Math.min(1, buffered.length / lag);
      const excess = Math.max(0, buffered.length - lag);
      let want = r * dt * (0.5 + 0.5 * fill) + (excess / STREAM_CATCHUP_MS) * dt + carry;
      // Something is WAITING behind this text (a tool card, a warning). Type the rest out at whatever
      // rate clears it by the deadline — faster than the wire, but still typed rather than dumped.
      if (drainBy) {
        const left = Math.max(dt, drainBy - ts);
        want = Math.max(want, (buffered.length / left) * dt + carry);
      }
      let n = Math.floor(want);
      carry = want - n;
      if (n >= buffered.length) { n = buffered.length; carry = 0; }
      // Never cut between the halves of a surrogate pair: half of one is not a character, and React
      // would paint the replacement glyph for a frame before the other half arrived.
      else if (n > 0 && (buffered.charCodeAt(n - 1) & 0xfc00) === 0xd800) n += 1;
      if (n > 0) {
        paint(buffered.slice(0, n));
        buffered = buffered.slice(n);
      }
      if (buffered) { raf = requestAnimationFrame(tick); return; }
      prevTs = 0;
      carry = 0;
      // The buffer is empty, so whatever was queued behind it can go now — in arrival order, after
      // the text it was waiting for. This is the ONLY place a queued event is released on the happy
      // path, which is what guarantees a card can never precede its own sentence.
      drainBy = 0;
      if (queued.length) flushQueue();
    };
    // NO `flushText()` here any more. It was the second half of the dump: `queue` holds an event
    // until the prose ahead of it has been typed out, and then `flushQueue` commits that text before
    // applying the event — so by the time `push` runs, the ordering is already settled. Flushing
    // again would empty a buffer that has only just started refilling from the NEXT delta, which is
    // the same instant-lump this exists to remove.
    const push = (e: Partial<AiTranscriptEntry> & { kind: AiTranscriptEntry['kind'] }) => {
      setEntries((prev) => [...prev, { ...blank(++sseSeqRef.current, e.kind), ...e }]);
    };

    api
      .aiInvestigate(body, (ev: AiRunEvent) => {
        // A NON-DELTA EVENT NO LONGER DUMPS THE BUFFER — it QUEUES BEHIND IT. See `queue`.
        if (ev.type !== 'delta') { queue(ev); return; }
        // ...and a delta that arrives while events are still queued belongs AFTER them. The queue
        // holds things that came off the wire BEFORE this token, so appending it to the buffer would
        // move it in front of them — and `commit` folds text into the last entry when that entry is
        // text, so the next model turn's narration was being merged into the previous turn's line,
        // jumping over the tool call that sits between them. Seen exactly once and it reads as a
        // typo: "…which rules have fired on it.4,000 events in one syslog source…". The queue is
        // cheap to release (the buffer is typed out, then the events apply in order), so release it.
        if (queued.length) { flushText(); flushQueue(); }
        apply(ev);
      }, ac.signal)
      .then(() => endStream())
      .catch((e: unknown) => {
        endStream();
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

    function apply(ev: AiRunEvent) {
      switch (ev.type) {
        case 'run':
          setRun((r) => (r ? {
            ...r, id: ev.runId, model: ev.model,
            threadId: ev.threadId ?? r.threadId, parentId: ev.parentId ?? r.parentId,
          } : r));
          setStreamingId(ev.runId);
          break;
        case 'status':
          // `agent` / `phase` / `task` MUST ride along. They were dropped here, so while a run was
          // STREAMING the trail could never fold worker-agent lines into the roster (no "3 working"
          // chip, no per-agent rows) — it appeared only after the run ended and the persisted
          // transcript replaced this one. Reported, three times, as "I'm not seeing multiple agents
          // working": they were working, and the one tab watching them live could not show it.
          push({ kind: 'status', text: ev.text, agent: ev.agent, phase: ev.phase, task: ev.task, said: ev.said });
          break;
        case 'step':
          push({ kind: 'step', step: ev.step });
          break;
        case 'delta':
          buffered += ev.text;
          noteArrival(ev.text.length);
          if (!raf) raf = requestAnimationFrame(tick);
          break;
        case 'tool_call':
          // ...and `laneId`, for the same reason: `groupTrail` brackets calls that share one, so
          // without it the "N calls at the same time" block never formed during a live run.
          push({ kind: 'tool', id: ev.id, name: ev.name, args: ev.arguments, lane: ev.lane ?? 1,
                 laneId: ev.laneId, writes: writeToolsRef.current.has(ev.name) });
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
    }
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
  /** Put the scroller at the bottom, if we are still following. Stable: it reads refs only, so the
   *  live tail can call it every frame without re-rendering anything that holds it. */
  const pinToBottom = useCallback(() => {
    if (!atBottomRef.current) return;
    const el = bodyRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
    // Remember where WE put it, so the scroll event this causes is not read as the analyst moving up.
    lastTopRef.current = el.scrollTop;
  }, []);

  // A LAYOUT effect, not a passive one: a passive effect runs after the frame has painted, so every
  // commit painted the paragraph one line taller with the container still scrolled to its OLD bottom
  // and pinned it a frame later — a per-frame stutter at exactly the line being read.
  //
  // The streaming text is no longer in `entries` (see `liveTail`), so this no longer fires per frame
  // and must not: `LiveTail` calls `pinToBottom` from its own layout effect instead. This one still
  // covers everything that IS state — a tool card landing, the answer arriving, the shell swapping.
  // `detached` is in here because the two shells hold DIFFERENT scroll containers: docking a window
  // that was following a live run must not silently jump the analyst back to the top of it.
  useLayoutEffect(pinToBottom, [entries, run?.answer, atBottom, detached, pinToBottom]);

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
  /** Pick the investigation up from where this turn stopped — a follow-up in the same thread. */
  const continueRun = useCallback((r: AiRun) => {
    if (live) return;
    startRun(CONTINUE_PROMPT, r.id);
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
                      undoing={undoingId === t.id} onUndo={undoRun} onRetry={retry} onContinue={continueRun} />
              ))}
              <Turn run={run} entries={entries} live={live} undoing={undoingId === run.id}
                    onUndo={undoRun} onRetry={retry} onContinue={continueRun}
                    onStreamPaint={pinToBottom} />
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
