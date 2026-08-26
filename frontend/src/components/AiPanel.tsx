/**
 * The AI assistant panel: one free-text objective, a live conversation, and the history of every
 * conversation this workspace has had.
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
import { createContext, memo, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import type { AiAction, AiInvestigateRequest, AiRun, AiRunEvent, AiScope, AiTranscriptEntry } from '../api/types';
import { qk, useSettings } from '../hooks/queries';
import { useToast } from '../hooks/useToast';
import { cx, errMsg } from '../utils/format';
import { renderMarkdown } from '../utils/markdown';
import { FloatingWindow } from './FloatingWindow';
import { Icon } from './icons';

export interface AiTarget { scope: AiScope; id?: string; eventIds?: string[]; label: string }

interface AiCtx {
  open: (target: AiTarget) => void;
  close: () => void;
  isOpen: boolean;
}
const Ctx = createContext<AiCtx | null>(null);

export function useAiPanel(): AiCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error('useAiPanel must be used inside AiPanelProvider');
  return c;
}

export function AiPanelProvider({ children }: { children: ReactNode }) {
  const [target, setTarget] = useState<AiTarget | null>(null);
  const open = useCallback((t: AiTarget) => setTarget(t), []);
  const close = useCallback(() => setTarget(null), []);
  const value = useMemo(() => ({ open, close, isOpen: target !== null }), [open, close, target]);
  return (
    <Ctx.Provider value={value}>
      {children}
      {target && <AiPanel target={target} onClose={close} />}
    </Ctx.Provider>
  );
}

const POLL_MS = 900;
// How often streamed prose is committed to state. Tokens arrive faster than anything can be read and
// each commit costs a re-render, a markdown parse and a scroll — batching them is what makes the
// report appear smoothly instead of stuttering. Low enough to still read as typing.
const STREAM_FLUSH_MS = 90;

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
 * Which tools change the case. The PERSISTED transcript carries `writes` on every tool entry, but the
 * live `tool_call` SSE event does not, so the panel needs its own answer while a run is streaming —
 * and a write mislabelled as a read is exactly the distinction this screen exists to make. The real
 * set is fetched once from GET /api/ai/tools (that IS the registry); this literal is only the fallback
 * when that call fails, and it must stay in step with `writes=True` in backend/app/ai/tools.py.
 */
const WRITE_TOOLS = new Set([
  'create_case', 'update_case', 'activate_case',
  'add_events_to_case', 'remove_events_from_case', 'annotate_case_event',
  'add_ioc', 'update_ioc', 'delete_ioc',
  'add_note', 'update_note', 'delete_note',
  'add_graph_link', 'delete_graph_link',
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

/* ─────────────────────────────────── structure ───────────────────────────────────
 * FOUR kinds of thing arrive on one stream and they do not weigh the same, so they are not drawn the
 * same: prose is the answer, a WRITE changed the analyst's case, a read did not, and a warning is an
 * evidence-integrity signal. Reads are quiet cards, writes carry the accent rail and are ALSO listed
 * in "Changes to this case", warnings are bordered alerts and are never folded.
 *
 * There are no "step 1 / step 2 / … / step 19" labels: the analyst reads them as noise. The sequence
 * is carried structurally instead — the activity trail is one rail, one card per call in order, and a
 * model turn boundary (`kind:'step'`) becomes a BREAK in that rail rather than a numbered line.
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
 * One line of the activity trail. `turn` marks the first node after a model-turn boundary — that gap
 * is what replaced the step numbers, so a reader can still see where one round of thinking ended.
 */
type TrailNode =
  | { k: 'tool'; key: number; e: AiTranscriptEntry; turn: boolean; lead: string }
  | { k: 'note'; key: number; text: string; turn: boolean }
  | { k: 'prose'; key: number; text: string; turn: boolean };

function trailNodes(blocks: Block[]): TrailNode[] {
  const out: TrailNode[] = [];
  let turn = false;
  for (const b of blocks) {
    if (b.kind === 'warning') continue;            // never folded into the trail — rendered on its own
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

/**
 * One tool call AND its result in ONE card. They used to be two lines with nothing binding them, so a
 * long run read as alternating noise; the arguments are a labelled list and the outcome is a row of
 * its own with a glyph, so "what was asked" and "what came back" are readable at a glance.
 */
function ToolCall({ e, live, lead = '' }: { e: AiTranscriptEntry; live: boolean; lead?: string }) {
  const [open, setOpen] = useState(false);
  const rows = argRows(e.args ?? {});
  const shown = open ? rows : rows.slice(0, ARGS_SHOWN);
  const hidden = rows.length - shown.length;
  const Glyph = toolIcon(e.name);
  const bad = e.ok === false;
  return (
    <div className={cx('tcall', e.writes && 'tcall--write', bad && 'tcall--bad')}>
      {!!lead.trim() && <Markdown className="md chat-md tcall__lead" text={lead} />}
      <div className="tcall__head">
        <Glyph className="tcall__glyph" />
        <span className="tcall__name mono">{e.name}</span>
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
              <dd className="mono" title={r.v}>{r.v}</dd>
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
}

/**
 * The audit trail: every tool call in order, on one rail, collapsible. Deliberately secondary — the
 * answer and the case changes come first — but never hidden, because it is how the answer was reached.
 */
function ActivityTrail({ blocks, live, title, startOpen }: {
  blocks: Block[]; live: boolean; title: string; startOpen: boolean;
}) {
  const nodes = useMemo(() => trailNodes(blocks), [blocks]);
  const [open, setOpen] = useState(startOpen);
  if (!nodes.length) return null;

  const tools = nodes.filter((n): n is Extract<TrailNode, { k: 'tool' }> => n.k === 'tool');
  // Nothing was CALLED — this is just the agent saying something (the opening line, a compaction
  // notice). Wrapping one sentence in a collapsible panel labelled "0 tool calls" is chrome, not
  // structure, so it is rendered plainly.
  if (!tools.length) {
    return (
      <div className="trail__bare">
        {nodes.map((n) => (n.k === 'prose'
          ? <Markdown key={n.key} className="md chat-md trail__prose" text={n.text} />
          // A note is a NOTE BODY: markdown, written by the agent, and often a table. Rendering it
          // raw made HTML collapse the newlines, so `| a | b |` rows ran together into one line of
          // pipes — the same class of bug CLAUDE.md records for NoteRow. Every surface that shows a
          // note body goes through renderMarkdown.
          : <Markdown key={n.key} className="trail__note md" text={n.k === 'note' ? n.text : ''} />))}
      </div>
    );
  }

  const writes = tools.filter((t) => t.e.writes).length;
  const failed = tools.filter((t) => t.e.ok === false).length;
  const pending = tools.some((t) => t.e.ok === null);
  const bits: string[] = [];
  if (tools.length) bits.push(`${tools.length} tool call${tools.length === 1 ? '' : 's'}`);
  if (writes) bits.push(`${writes} write${writes === 1 ? '' : 's'}`);
  if (failed) bits.push(`${failed} refused`);

  return (
    <section className={cx('trail', open && 'trail--open')}>
      <button type="button" className="trail__toggle" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
        <Icon.Chevron className={cx('trail__chev', open && 'trail__chev--open')} />
        <span className="trail__title">{title}</span>
        {!!bits.length && <span className="trail__counts">{bits.join(' · ')}</span>}
        {pending && live && <span className="spinner" style={{ width: 10, height: 10, borderWidth: 1.5 }} />}
        {!open && !!tools.length && (
          <span className="trail__peek mono ellipsis">{tools.map((t) => t.e.name).join(' → ')}</span>
        )}
      </button>
      {open && (
        <div className="trail__body">
          {nodes.map((n) => (
            <div key={n.key} className={cx('trail__node', n.turn && 'trail__node--turn')}>
              {n.k === 'tool' && <ToolCall e={n.e} live={live} lead={n.lead} />}
              {n.k === 'note' && <Markdown className="trail__note md" text={n.text} />}
              {n.k === 'prose' && <Markdown className="md chat-md trail__prose" text={n.text} />}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

/** The thing they asked for. First in the assistant turn once the run is over, and marked as such. */
function Answer({ text, state }: { text: string; state: AiRun['state'] }) {
  return (
    <section className="chat-answer" aria-label="The assistant's answer">
      <header className="chat-answer__head">
        <Icon.Findings />
        <span>{state === 'done' ? 'Answer' : 'Answer so far'}</span>
      </header>
      <Markdown className="md chat-md chat-answer__body" text={text} />
    </section>
  );
}

/** An evidence-integrity signal. Never folded, never subdued — see the panel's header comment. */
function Warning({ text }: { text: string }) {
  return (
    <div className="chat-warn" role="alert">
      <Icon.Warn />
      <span>{text}</span>
    </div>
  );
}

/**
 * What the run did to the case — second only to the answer, because it is the part that persists.
 * Every entry is reversible in one click; a reverted one stays listed rather than disappearing.
 */
function Changes({ actions, busy, onUndo }: { actions: AiAction[]; busy: boolean; onUndo: () => void }) {
  const active = actions.filter((a) => !a.undone).length;
  if (!actions.length) return null;
  return (
    <section className="chat-changes" aria-label="Changes this run made to the case">
      <header className="chat-changes__head">
        <span className="chat-changes__title">Changes to this case</span>
        <span className="chat-changes__count">
          {active} active{actions.length !== active ? ` · ${actions.length - active} reverted` : ''}
        </span>
        {active > 0 && (
          <button className="btn btn--sm btn--ghost" onClick={onUndo} disabled={busy}>
            {busy ? 'Reverting…' : 'Revert all'}
          </button>
        )}
      </header>
      <ul className="chat-changes__list">
        {actions.map((a) => {
          const Glyph = toolIcon(a.tool);
          return (
            <li key={a.id} className={cx('chat-change', a.undone && 'chat-change--undone')}>
              <Glyph className="chat-change__glyph" />
              <div className="chat-change__text">
                <span className="chat-change__summary">{a.summary}</span>
                <span className="chat-change__tool mono">{a.tool}</span>
              </div>
              {a.undone && <span className="tag">reverted</span>}
            </li>
          );
        })}
      </ul>
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

function HistoryList({ runs, busy, onOpen, onDelete }: {
  runs: AiRun[]; busy: boolean; onOpen: (id: string) => void; onDelete: (id: string) => void;
}) {
  const threads = useMemo(() => threadsOf(runs), [runs]);
  if (busy && !runs.length) {
    return <div className="state state--inline"><div className="spinner" /><div className="state__body">Loading conversations…</div></div>;
  }
  if (!runs.length) {
    return (
      <div className="chat-empty">
        <div className="chat-empty__title">No conversations yet</div>
        <div className="chat-empty__body">
          Ask the assistant to investigate something. Everything it says, every tool it calls and every change it
          makes to the case is kept here — a refresh, another tab or a server restart will not lose it.
        </div>
      </div>
    );
  }
  return (
    <ul className="chat-history" aria-label="Past conversations">
      {threads.map((t) => (
        <li key={t.id} className="chat-history__row">
          <button type="button" className="chat-history__open" onClick={() => onOpen(t.latest.id)}>
            <span className="chat-history__prompt">{t.root.prompt || '(no objective)'}</span>
            <span className="chat-history__meta">
              <span className={cx('chat-state', `chat-state--${t.latest.state}`)}>{STATE_LABEL[t.latest.state]}</span>
              <span title={RELATIVE(t.latest.startedAt)}>{UTC(t.latest.startedAt)}</span>
              {t.turns > 1 && <span>{t.turns} turns</span>}
              {t.root.caseName && <span className="ellipsis">{t.root.caseName}</span>}
              {t.changes > 0 && (
                <span className="chat-history__writes">
                  {t.changes} change{t.changes === 1 ? '' : 's'}
                </span>
              )}
            </span>
          </button>
          <button
            type="button"
            className="chat-history__del"
            title={t.turns > 1 ? 'Delete the latest turn of this conversation' : 'Delete this conversation'}
            aria-label={`Delete conversation: ${t.root.prompt.slice(0, 60)}`}
            onClick={() => onDelete(t.latest.id)}
          >
            <Icon.Trash />
          </button>
        </li>
      ))}
    </ul>
  );
}

/* ─────────────────────────────────── the panel ─────────────────────────────────── */

/**
 * ONE TURN of a conversation: the analyst's question, then the assistant's work on it.
 *
 * The same component renders a past turn, the current finished turn and the live one, because they are
 * the same thing at different moments — and because two renderers would drift, which on this screen
 * means one of them eventually shows a write as a read.
 */
function Turn({ run, entries, live, undoing, onUndo }: {
  run: AiRun; entries: AiTranscriptEntry[]; live: boolean; undoing: boolean; onUndo: (id: string) => void;
}) {
  const blocks = useMemo(() => toBlocks(entries), [entries]);
  const warnings = useMemo(
    () => blocks.filter((b): b is Extract<Block, { kind: 'warning' }> => b.kind === 'warning'), [blocks]);
  const prose = useMemo(
    () => blocks.filter((b) => b.kind === 'prose').map((b) => (b as { text: string }).text).join('\n').trim(), [blocks]);
  // The stream usually IS the report, so `answer` prefers the persisted one and falls back to the
  // prose a stopped run managed to write. Prose already contained in the answer is not repeated in
  // the trail; prose that is NOT part of it stays there rather than being silently dropped.
  const answer = ((run.answer ?? '').trim()) || (live ? '' : prose);
  const trailBlocks = useMemo(() => blocks.filter((b) => {
    if (b.kind === 'warning') return false;
    if (b.kind !== 'prose') return true;
    const t = b.text.trim();
    return !(t && answer.includes(t));
  }), [blocks, answer]);
  const ranFor = run.endedAt ? spanOf(run.startedAt, run.endedAt) : '';

  return (
    <>
      <section className="chat-objective">
        <header className="chat-objective__head">
          <span className="eyebrow">{run.parentId ? 'Follow-up' : 'Objective'}</span>
          {run.startedAt && (
            <span className="chat-objective__when" title={RELATIVE(run.startedAt)}>{UTC(run.startedAt)}</span>
          )}
        </header>
        <div className="chat-objective__text">{run.prompt}</div>
        {run.focus && <div className="chat-objective__focus mono">context: {run.focus}</div>}
      </section>

      <article className="chat-turn chat-turn--ai">
        <header className="chat-turn__role">
          <Icon.Sparkle className="chat-turn__glyph" />
          <span>Assistant</span>
          {run.model && <span className="mono chat-turn__model">{run.model}</span>}
          <span className={cx('chat-state', `chat-state--${run.state}`)}>{STATE_LABEL[run.state]}</span>
          {run.reason && run.reason !== 'complete' && (
            <span className="chat-turn__reason" title="how the run ended">{run.reason.replace(/_/g, ' ')}</span>
          )}
        </header>

        {live ? (
          /* LIVE: chronological, because watching the work is the point while it is happening */
          <div className="chat-turn__body" aria-live="polite" aria-busy>
            {blocks.map((b) => {
              if (b.kind === 'activity') {
                return <ActivityTrail key={b.key} blocks={[b]} live title="Activity" startOpen />;
              }
              if (b.kind === 'warning') return <Warning key={b.key} text={b.text} />;
              return <Markdown key={b.key} className="md chat-md" text={b.text} />;
            })}
            {!blocks.length && (
              <div className="state state--inline"><div className="spinner" /><div className="state__body">Starting the investigation…</div></div>
            )}
            <Changes actions={run.actions} busy={undoing} onUndo={() => onUndo(run.id)} />
          </div>
        ) : (
          /* FINISHED: the answer, then what it changed, then how it got there */
          <div className="chat-turn__body">
            {warnings.map((w) => <Warning key={w.key} text={w.text} />)}
            {run.interrupted && <Warning text={run.error || 'The server restarted while this run was going.'} />}
            {!run.interrupted && run.state === 'error' && !!run.error && <Warning text={run.error} />}
            {answer
              ? <Answer text={answer} state={run.state} />
              : (
                <div className="chat-note">
                  {run.state === 'stopped'
                    ? 'Stopped before the assistant wrote a report. Anything it had already changed is listed below and can be reverted.'
                    : 'This run produced no report.'}
                </div>
              )}
            <Changes actions={run.actions} busy={undoing} onUndo={() => onUndo(run.id)} />
            <ActivityTrail blocks={trailBlocks} live={false} title="How it got there" startOpen={!answer} />
            {run.transcriptTruncated && (
              <div className="chat-note">This transcript was long and its earliest lines were dropped; the report and the change list are complete.</div>
            )}
            {(run.toolCalls > 0 || ranFor) && (
              <footer className="chat-turn__meta">
                {run.toolCalls > 0 && <span>{run.toolCalls} tool call{run.toolCalls === 1 ? '' : 's'}</span>}
                {ranFor && <span>ran for {ranFor}</span>}
                {run.endedAt && <span title={RELATIVE(run.endedAt)}>finished {UTC(run.endedAt)}</span>}
              </footer>
            )}
          </div>
        )}
      </article>
    </>
  );
}


export function AiPanel({ target, onClose }: { target: AiTarget; onClose: () => void }) {
  const settings = useSettings();
  const qc = useQueryClient();
  const toast = useToast();
  const provider = settings.data?.ai.provider;

  const [view, setView] = useState<'chat' | 'history'>('history');
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
  const [atBottom, setAtBottom] = useState(true);
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
    for (const key of [['case'], ['iocs'], ['timeline'], ['timeline-iocs'], ['graph'], ['case-set'], ['notes'], ['events']]) {
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
      setAtBottom(true);
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
    setAtBottom(true);
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

    // Prose arrives one TOKEN at a time. A `setEntries` per token is a re-render, a markdown re-parse
    // and a scroll-to-bottom per token — the report visibly stuttered as it was written. Tokens are
    // buffered and flushed on a fixed cadence instead, which is far above what anyone reads at and
    // costs nothing in latency. Every other event flushes FIRST, so ordering is exactly the stream's.
    let buffered = '';
    let flushTimer = 0;
    const flushText = () => {
      if (flushTimer) { window.clearTimeout(flushTimer); flushTimer = 0; }
      const t = buffered;
      buffered = '';
      // A pending flush must never land on the NEXT conversation: `startRun` aborts the old stream, and
      // a timer that fires after that would append the previous run's tail to a fresh transcript.
      if (!t || ac.signal.aborted) return;
      setEntries((prev) => {
        const last = prev[prev.length - 1];
        if (last?.kind === 'text') return [...prev.slice(0, -1), { ...last, text: last.text + t }];
        return [...prev, { ...blank(++sseSeqRef.current, 'text'), text: t }];
      });
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
            if (!flushTimer) flushTimer = window.setTimeout(flushText, STREAM_FLUSH_MS);
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

  // Follow the stream ONLY when the analyst is already at the bottom. Yanking someone back while they
  // are reading is the single most annoying thing a chat UI does; "Jump to latest" is offered instead.
  useEffect(() => {
    if (!atBottom) return;
    const el = bodyRef.current;
    if (el) el.scrollTop = el.scrollHeight;
    // `detached` is in here because the two shells hold DIFFERENT scroll containers: docking a window
    // that was following a live run must not silently jump the analyst back to the top of it.
  }, [entries, run?.answer, atBottom, detached]);

  const onScroll = useCallback(() => {
    const el = bodyRef.current;
    if (!el) return;
    setAtBottom(el.scrollHeight - el.scrollTop - el.clientHeight < 48);
  }, []);

  const jumpToLatest = useCallback(() => {
    const el = bodyRef.current;
    if (el) el.scrollTop = el.scrollHeight;
    setAtBottom(true);
  }, []);

  /* ── auto-growing composer ─────────────────────────────────────────────────── */
  useEffect(() => {
    const el = promptRef.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = `${Math.min(200, Math.max(44, el.scrollHeight))}px`;
  }, [prompt]);

  /* ── what the transcript becomes on screen ───────────────────────────────────
   * While the run is LIVE the order is the point: prose, tool calls and warnings render in the order
   * they arrived, so the analyst can watch the work. Once it is over the ORDER stops being the point
   * and the priority does — the answer first, then what it changed in the case, then how it got there.
   */
  const scopeNote = focusOf(target);
  const threadCount = useMemo(() => new Set(runs.map((r) => r.threadId || r.id)).size, [runs]);
  const canSend = !!prompt.trim() && !live;
  const savedPrompts = useMemo(() => systemPrompts.data?.prompts ?? [], [systemPrompts.data]);
  // a remembered id that no longer exists is not offered; the select falls back to the default row
  useEffect(() => {
    if (systemPrompts.data && spChoice && !savedPrompts.some((p) => p.id === spChoice)) pickSystemPrompt(null);
  }, [systemPrompts.data, savedPrompts, spChoice, pickSystemPrompt]);
  const defaultPromptName = useMemo(() => {
    const id = settings.data?.ai.systemPromptId;
    return id ? (savedPrompts.find((p) => p.id === id)?.name ?? '') : '';
  }, [settings.data?.ai.systemPromptId, savedPrompts]);
  // Typing into an open, finished conversation CONTINUES it. A first turn, or a chat cleared with New,
  // starts a fresh one.
  const continueFrom = run && !live ? run.id : undefined;
  const send = useCallback(() => {
    if (!prompt.trim() || live) return;
    startRun(prompt, run && run.state !== 'running' ? run.id : undefined);
  }, [prompt, live, run, startRun]);

  /* ── one set of controls, one body, two shells ────────────────────────────────
   * Docked and detached must be the SAME panel — a second copy of the transcript, the composer or the
   * write list is a copy that eventually drifts, and on this screen drift means one of them draws a
   * write as a read. Only the frame around them changes.
   */
  const controls = (
    <>
      <button
        className="btn btn--sm btn--ghost"
        onClick={() => setView((v) => (v === 'history' ? 'chat' : 'history'))}
        aria-pressed={view === 'history'}
        title="Past conversations"
      >
        History{threadCount ? ` (${threadCount})` : ''}
      </button>
      <button className="btn btn--sm btn--ghost" onClick={newConversation} title="Start a new conversation">
        <Icon.Plus />New
      </button>
    </>
  );

  const body = (
    <>
      <div className="ai-panel__body" ref={bodyRef} onScroll={onScroll}>
        {settings.isLoading && <div className="muted">Loading assistant settings…</div>}
        {settings.isError && <div className="compute-error">{errMsg(settings.error)}</div>}

        {provider === 'none' && (
          <div className="ai-cta">
            <div className="ai-cta__title">AI assistant is off</div>
            <div className="ai-cta__body">
              Add an OpenAI API key (or point the base URL at any OpenAI-compatible endpoint such as Ollama, LM Studio or vLLM)
              to let the assistant investigate the logs with the app&rsquo;s own search, timeline, graph and case tools. The model
              must support tool calling.
            </div>
            <Link to="/settings#ai" className="btn btn--accent" onClick={onClose}>Open settings → AI assistant</Link>
          </div>
        )}

        {provider && provider !== 'none' && view === 'history' && (
          <HistoryList runs={runs} busy={loadingRuns} onOpen={openRun} onDelete={remove} />
        )}

        {provider && provider !== 'none' && view === 'chat' && !run && (
          <div className="chat-empty">
            <div className="chat-empty__title">Describe the investigation</div>
            <div className="chat-empty__body">
              The assistant searches the pool, opens events, walks the entity graph and writes what it finds into the
              case &mdash; citing the event ids behind every claim. Every change it makes is listed here and can be
              reverted in one click.
            </div>
            {scopeNote && (
              <div className="chat-empty__ctx">
                <span className="eyebrow">Context</span>
                <span className="mono">{scopeNote}</span>
              </div>
            )}
          </div>
        )}

        {provider && provider !== 'none' && view === 'chat' && run && (
          <div className="chat">
            {thread.map((t) => (
              <Turn key={t.id} run={t} entries={t.transcript} live={false}
                    undoing={undoingId === t.id} onUndo={undoRun} />
            ))}
            <Turn run={run} entries={entries} live={live} undoing={undoingId === run.id} onUndo={undoRun} />
          </div>
        )}

        {error && <div className="compute-error">{error}</div>}
      </div>

      {provider && provider !== 'none' && (
        <div className="ai-panel__foot">
          {!atBottom && live && (
            <button type="button" className="chat-jump" onClick={jumpToLatest}>Jump to latest</button>
          )}
          {/* Which prompt the next run uses. Always visible — a control that only appears once something
              is saved is a control nobody discovers; with nothing saved it says where to add one. */}
          <div className="chat-prompt-bar" title="The system prompt for the next run: the built-in prompt, plus the additional instructions you pick here. Manage both under Settings → System prompts.">
            <label className="chat-prompt-bar__label" htmlFor="chat-prompt-pick">Prompt</label>
            <select
              id="chat-prompt-pick"
              className="chat-prompt-bar__select"
              value={spChoice === null ? '__default' : spChoice}
              onChange={(e) => pickSystemPrompt(e.target.value === '__default' ? null : e.target.value)}
              disabled={live}
              aria-label="System prompt for the next run"
            >
              <option value="__default">{defaultPromptName ? `Default · ${defaultPromptName}` : 'Built-in prompt only (default)'}</option>
              {defaultPromptName && <option value="">Built-in prompt only</option>}
              {savedPrompts.length > 0 && <optgroup label="Saved prompts — added to the built-in prompt">
                {savedPrompts.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
              </optgroup>}
            </select>
            {systemPrompts.data?.builtinEdited && <span className="pill pill--warn" title="The built-in prompt has been edited under Settings → System prompts">built-in edited</span>}
            <Link to="/settings#prompts" className="chat-prompt-bar__manage" onClick={onClose}>
              {savedPrompts.length > 0 ? 'Manage' : 'Add a prompt'}
            </Link>
          </div>
          <form
            className="chat-composer"
            onSubmit={(e) => { e.preventDefault(); send(); }}
          >
            <textarea
              ref={promptRef}
              className="chat-composer__input"
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
                  : 'Describe the investigation. Enter to send, Shift+Enter for a new line.'}
              aria-label="What should the assistant investigate?"
              disabled={live}
            />
            {live ? (
              <button type="button" className="btn btn--danger chat-composer__go" onClick={stop} disabled={stopping}>
                {stopping ? 'Stopping…' : 'Stop'}
              </button>
            ) : (
              <button type="submit" className="btn btn--accent chat-composer__go" disabled={!canSend}>
                {continueFrom ? 'Send' : 'Investigate'}
              </button>
            )}
          </form>
          <div className="chat-composer__hint">
            {live
              ? 'Stop halts the run on the server at its next checkpoint — anything already written stays and can be reverted.'
              : continueFrom
                ? 'This continues the conversation above — the assistant keeps what it already found and does not start over. New begins a fresh one.'
                : 'Everything is kept in History and survives a refresh. You can keep asking follow-ups in the same chat.'}
          </div>
        </div>
      )}
    </>
  );

  if (detached) {
    return (
      <FloatingWindow
        storageKey="ai"
        flush
        closeOnEscape={false}
        ariaLabel="AI assistant"
        title={<span className="ai-win__title">AI assistant{live && <span className="spinner" style={{ width: 12, height: 12 }} />}</span>}
        sub={target.label}
        onClose={onClose}
        defaultBox={{ w: 620, h: Math.min(760, window.innerHeight - 120) }}
        minH={380}
        actions={
          <>
            {controls}
            <button className="btn btn--sm btn--ghost" onClick={() => setMode(false)}
              title="Dock this back into the side panel">Dock</button>
          </>
        }
      >
        {body}
      </FloatingWindow>
    );
  }

  return (
    <>
      <div className="overlay" onClick={onClose} />
      <aside className="ai-panel" role="dialog" aria-modal="true" aria-label="AI assistant">
        <div className="ai-panel__head">
          <div className="ai-panel__title">AI assistant</div>
          {live && <span className="spinner" style={{ width: 12, height: 12 }} />}
          <span className="ai-panel__ctx ellipsis" title={target.label}>{target.label}</span>
          {controls}
          <button className="btn btn--sm btn--ghost" onClick={() => setMode(true)}
            title="Detach into a window you can move and resize">Detach</button>
          <button className="close-x" onClick={onClose} aria-label="Close">×</button>
        </div>
        {body}
      </aside>
    </>
  );
}
