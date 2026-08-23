import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { SEVERITIES, type Anomaly, type Event, type GraphFinding, type Rule, type RuleCondition, type RuleField, type RuleInput, type RuleOp, type RuleParamKind, type RuleSuggestResult, type RuleTestResult, type Severity } from '../api/types';
import { DerivedPauseActions } from '../components/Enrichment';
import { Icon } from '../components/icons';
import { BuildingState, ConfirmDialog, Drawer, EmptyState, ErrorState, SectionHead, SevTag, SkeletonRows, Toggle } from '../components/ui';
import { qk, useAnomalies, useInvalidateCaseData, useRules, useSettings } from '../hooks/queries';
import { useDebounce } from '../hooks/useDebounce';
import { useToast } from '../hooks/useToast';
import { cx, fmtInt, fmtTs, sevVar } from '../utils/format';

/* ───────────────────────── Anomalies list ───────────────────────── */

function AnomalyRow({ a, open, onToggle }: { a: Anomaly; open: boolean; onToggle: () => void }) {
  const nav = useNavigate();
  return (
    <>
      <div
        className={cx('table__row table__row--sev anom-grid clickable', open && 'selected')}
        style={{ ['--row-sev' as string]: sevVar(a.sev) }}
        role="button"
        tabIndex={0}
        aria-expanded={open}
        onClick={onToggle}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onToggle(); } }}
      >
        <div className="sev-cell"><SevTag sev={a.sev} /></div>
        <div className="anom__name">
          <span className="cell-bright">{a.name}</span>
          <span className="cell-mono cell-dim" style={{ fontSize: 'var(--fs-xs)' }}>{a.ruleId}</span>
        </div>
        <div><span className={cx('badge', a.kind !== 'builtin' && 'badge--ok')}>{a.kind === 'builtin' ? 'built-in' : a.kind}</span></div>
        <div className="cell-mono num">{fmtInt(a.hits)}</div>
        <div className="cell-mono cell-dim" style={{ fontSize: 'var(--fs-xs)' }}>{a.firstSeen ? fmtTs(a.firstSeen) : '—'}</div>
        <div className="cell-mono cell-dim" style={{ fontSize: 'var(--fs-xs)' }}>{a.lastSeen ? fmtTs(a.lastSeen) : '—'}</div>
        <div className="anom__sources ellipsis" title={a.sources.join(', ')}>
          {a.sources.slice(0, 3).map((s) => <span key={s} className="tag">{s}</span>)}
          {a.sources.length > 3 && <span className="tag">+{a.sources.length - 3}</span>}
        </div>
        <div className="anom__caret"><Icon.Chevron style={{ transform: open ? 'rotate(180deg)' : undefined }} /></div>
      </div>
      {open && (
        <div className="anom__detail">
          <div className="anom__detail-head">
            <span className="eyebrow">Sample events</span>
            <button className="btn btn--sm" onClick={() => nav(`/search?q=${encodeURIComponent(`rule:${a.ruleId}`)}`)}>
              <Icon.Search /> Search these
            </button>
          </div>
          {a.sample.length === 0 && <div className="muted" style={{ fontSize: 'var(--fs-sm)' }}>No sample events returned.</div>}
          {a.sample.map((e) => (
            <div key={e.id} className="anom__sample clickable" role="link" tabIndex={0}
              onClick={() => nav(`/events/${encodeURIComponent(e.id)}`)}
              onKeyDown={(k) => { if (k.key === 'Enter') nav(`/events/${encodeURIComponent(e.id)}`); }}>
              <span className="cell-mono cell-dim">{fmtTs(e.ts)}</span>
              <span className="cell-mono cell-dim ellipsis">{e.source}</span>
              <span className="cell-mono ellipsis">{e.host || '—'}</span>
              <span className="cell-mono cell-bright ellipsis" title={e.msg}>{e.msg}</span>
            </div>
          ))}
        </div>
      )}
    </>
  );
}

function AnomaliesSection() {
  const [sevs, setSevs] = useState<Severity[]>([]);
  const [text, setText] = useState('');
  const [open, setOpen] = useState<string | null>(null);
  // One unfiltered fetch drives the per-severity counts on the chips AND the totals line. The endpoint
  // slices an already-built, already-sorted cache, so this is not a second aggregation — and a filter
  // chip that cannot say how many it would show is a guess the analyst has to click to resolve.
  const all = useAnomalies(useMemo(() => ({ limit: 200 }), []));
  const params = useMemo(() => ({ sev: sevs, limit: 200 }), [sevs]);
  const q = useAnomalies(params);
  const toggleSev = (s: Severity) => setSevs((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]));
  const bySev = useMemo(() => {
    const n: Partial<Record<Severity, number>> = {};
    for (const a of all.data?.anomalies ?? []) n[a.sev] = (n[a.sev] ?? 0) + 1;
    return n;
  }, [all.data]);
  const totalHits = useMemo(() => (all.data?.anomalies ?? []).reduce((n, a) => n + a.hits, 0), [all.data]);
  const needle = text.trim().toLowerCase();
  const list = (q.data?.anomalies ?? []).filter(
    (a) => !needle || a.name.toLowerCase().includes(needle) || a.ruleId.toLowerCase().includes(needle));
  // The server aggregates every rule's hits once per (pool version, rules revision), in the background.
  // While that runs the list is empty ON PURPOSE — showing "No rule has fired" there would be a false
  // statement about the evidence, so the build state replaces the table until it lands.
  const building = q.data?.status?.state === 'building' && list.length === 0;
  return (
    <section>
      <SectionHead
        eyebrow="01 · Anomalies"
        title="Rules with hits in the active case"
        hint={building ? 'aggregating rule hits across the pool…'
          : q.data ? `${fmtInt(q.data.total)} rule${q.data.total === 1 ? '' : 's'} fired` : 'sorted by severity, then hits'}
      />
      {/* Rules are evaluated against interpreted events. Until a source is enriched it has no parsed
          fields, no severity and no timestamp, so no rule has been given the chance to fire on it —
          and "no rule has fired" would be a false statement about that evidence. */}
      <div className="anom__toolbar">
        <div className="chip-row">
          <span className="chip-row__label">Severity</span>
          {SEVERITIES.map((s) => (
            <button key={s} className={cx('chip', sevs.includes(s) && 'on')} onClick={() => toggleSev(s)} aria-pressed={sevs.includes(s)}
              disabled={!bySev[s] && !sevs.includes(s)}
              title={bySev[s] ? `${bySev[s]} rule${bySev[s] === 1 ? '' : 's'} at ${s}` : `no ${s} rule has fired`}>
              <span className="sev__bar" style={{ background: sevVar(s), width: 3, height: 10, display: 'inline-block' }} />
              {s}<span className="chip__count">{bySev[s] ?? 0}</span>
            </button>
          ))}
          {sevs.length > 0 && <button className="btn btn--sm btn--ghost" onClick={() => setSevs([])}>clear</button>}
        </div>
        <div className="anom__search">
          <Icon.Search className="anom__search-icon" aria-hidden />
          <input value={text} onChange={(e) => setText(e.target.value)} placeholder="Filter by rule name or id"
            aria-label="Filter anomalies" spellCheck={false} />
          {text && <button className="anom__search-x" onClick={() => setText('')} aria-label="Clear filter">×</button>}
        </div>
      </div>
      {/* The two numbers that decide what to look at first, stated once instead of counted off the table. */}
      {!building && (all.data?.total ?? 0) > 0 && (
        <div className="anom__summary">
          <span><b>{fmtInt(list.length)}</b> of {fmtInt(all.data!.total)} rule{all.data!.total === 1 ? '' : 's'}</span>
          <span className="anom__summary-sep">·</span>
          <span><b>{fmtInt(totalHits)}</b> total hit{totalHits === 1 ? '' : 's'}</span>
        </div>
      )}
      {q.isError ? (
        <ErrorState title="Could not load anomalies" error={q.error} onRetry={() => void q.refetch()} />
      ) : building ? (
        <BuildingState what="anomaly aggregation" status={q.data?.status} action={<DerivedPauseActions />} />
      ) : (
        <div className="table" style={{ opacity: q.isFetching && list.length ? 0.7 : 1, transition: 'opacity var(--t-fast)' }}>
          <div className="table__head anom-grid">
            <div>Sev</div><div>Rule</div><div>Kind</div><div className="num">Hits</div><div>First seen</div><div>Last seen</div><div>Sources</div><div />
          </div>
          {q.isLoading && <SkeletonRows n={5} />}
          {!q.isLoading && list.length === 0 && (
            <div className="table__empty">
              {needle ? `No rule matches “${text}”.`
                : sevs.length ? 'No anomalies at the selected severities.'
                : 'No rule has fired in the active case yet — ingest sources or add a detection rule below.'}
            </div>
          )}
          {list.map((a) => <AnomalyRow key={a.ruleId} a={a} open={open === a.ruleId} onToggle={() => setOpen((o) => (o === a.ruleId ? null : a.ruleId))} />)}
        </div>
      )}
    </section>
  );
}

/* ───────────────────────── Rule drawer ───────────────────────── */

const FIELD_OPTIONS: { value: string; label: string }[] = [
  { value: 'any', label: 'any (message, raw, host, user, fields)' },
  { value: 'msg', label: 'msg — normalized message' },
  { value: 'raw', label: 'raw — original line' },
  { value: 'host', label: 'host' },
  { value: 'user', label: 'user' },
  { value: 'source', label: 'source — parser family' },
  { value: 'file', label: 'file — source file name' },
  { value: '__custom', label: 'custom fields[] key…' },
];
const KNOWN_FIELDS = new Set(FIELD_OPTIONS.map((f) => f.value));

/* ── condition builder vocabulary (mirrors backend/app/detect.py CONDITION_OPS / CONDITION_FIELDS) ── */
const OPS: { value: RuleOp; label: string; phrase: string; input: 'text' | 'regex' | 'list' | 'number' | 'none' }[] = [
  { value: 'equals', label: 'equals', phrase: 'equals', input: 'text' },
  { value: 'not_equals', label: 'does not equal', phrase: 'does not equal', input: 'text' },
  { value: 'contains', label: 'contains', phrase: 'contains', input: 'text' },
  { value: 'not_contains', label: 'does not contain', phrase: 'does not contain', input: 'text' },
  { value: 'starts_with', label: 'starts with', phrase: 'starts with', input: 'text' },
  { value: 'ends_with', label: 'ends with', phrase: 'ends with', input: 'text' },
  { value: 'regex', label: 'matches regex', phrase: 'matches the regex', input: 'regex' },
  { value: 'in', label: 'is one of', phrase: 'is one of', input: 'list' },
  { value: 'not_in', label: 'is none of', phrase: 'is none of', input: 'list' },
  { value: 'gt', label: 'greater than', phrase: 'is greater than', input: 'number' },
  { value: 'lt', label: 'less than', phrase: 'is less than', input: 'number' },
  { value: 'exists', label: 'is present', phrase: 'is present', input: 'none' },
];
type OpSpec = (typeof OPS)[number];
const OP_BY_VALUE = new Map<RuleOp, OpSpec>(OPS.map((o) => [o.value, o]));
const DEFAULT_OP: OpSpec = { value: 'contains', label: 'contains', phrase: 'contains', input: 'text' };
/** Fields offered by name; anything else is looked up in the event's parsed fields[] map. */
const COND_FIELDS: { value: string; label: string }[] = [
  { value: 'msg', label: 'msg — normalized message' },
  { value: 'raw', label: 'raw — original line' },
  { value: 'host', label: 'host' },
  { value: 'user', label: 'user' },
  { value: 'source', label: 'source — parser family' },
  { value: 'file', label: 'file — source file name' },
  { value: 'sev', label: 'sev — severity' },
  { value: 'ts', label: 'ts — timestamp' },
  { value: 'detection', label: 'detection — rule already fired' },
  { value: 'entity', label: 'entity — extracted entity' },
  { value: '__custom', label: 'parsed field key…' },
];
const COND_FIELD_SET = new Set(COND_FIELDS.map((f) => f.value));
const EMPTY_CONDITION: RuleCondition = { field: 'msg', op: 'contains', value: '' };

function conditionRowText(c: RuleCondition): string {
  const op = OP_BY_VALUE.get(c.op);
  if (!op) return '';
  return op.input === 'none' ? `${c.field} ${op.phrase}` : `${c.field} ${op.phrase} "${c.value ?? ''}"`;
}
/**
 * Local preview of the TRIGGER the server generates and serves back as `Rule.logic`. Read-only on
 * purpose: it is what the engine evaluates, unlike the Description box, which is notes only.
 */
function previewTrigger(d: Draft): string {
  if (d.mode === 'regex') {
    if (!d.pattern) return '';
    const f = draftField(d);
    const where = f === 'any' ? 'the message, raw line, host, user and parsed fields' : `the ${f} field`;
    const scope = d.sourceFilter.trim() ? `, limited to sources matching "${d.sourceFilter.trim()}"` : '';
    return `Flags every event where ${where} matches the regex ${d.pattern}${scope}.`;
  }
  const rows = d.conditions.filter((c) => c.field.trim()).map(conditionRowText).filter(Boolean);
  if (rows.length === 0) return '';
  const where = rows.join(d.combinator === 'or' ? ' OR ' : ' AND ');
  const scope = d.sourceFilter.trim() ? ` in sources matching "${d.sourceFilter.trim()}"` : '';
  if (d.useThreshold) {
    const grouped = d.thGroupBy.trim() ? ` grouped by ${d.thGroupBy.trim()}` : ' across the whole case';
    return `Counts events${scope} where ${where}${grouped}. Fires on the densest ${d.thWindow || '0'}-second window `
      + `holding ${d.thCount || '0'} or more, tagging the last event of that window.`;
  }
  return `Flags every event${scope} where ${where}.`;
}

interface Draft {
  name: string; description: string; sev: Severity; field: string; customField: string; pattern: string;
  ignoreCase: boolean; multiline: boolean; sourceFilter: string; tags: string; enabled: boolean;
  /** how the custom rule is built: typed condition rows, or a raw regex (the original shape) */
  mode: 'conditions' | 'regex';
  conditions: RuleCondition[]; combinator: 'and' | 'or';
  useThreshold: boolean; thCount: string; thWindow: string; thGroupBy: string;
}
const EMPTY_DRAFT: Draft = {
  name: '', description: '', sev: 'medium', field: 'any', customField: '', pattern: '', ignoreCase: true,
  multiline: false, sourceFilter: '', tags: '', enabled: true,
  mode: 'conditions', conditions: [{ ...EMPTY_CONDITION }], combinator: 'and',
  useThreshold: false, thCount: '5', thWindow: '300', thGroupBy: '',
};

function ruleToDraft(r: Rule): Draft {
  const f = r.field ?? 'any';
  const known = KNOWN_FIELDS.has(f) && f !== '__custom';
  // a built-in has no `pattern`, but the regexes it matches with come back in `patterns` — seed the
  // editor with the first one so it is visible and tunable rather than buried in the description
  const builtinRx = r.builtin ? r.patterns?.[0]?.pattern ?? '' : '';
  const conds = r.conditions ?? [];
  return {
    name: r.name, description: r.description ?? '', sev: r.sev, field: known ? f : '__custom', customField: known ? '' : f,
    pattern: r.pattern ?? builtinRx,
    ignoreCase: r.flags?.ignoreCase ?? true, multiline: r.flags?.multiline ?? false, sourceFilter: r.sourceFilter ?? '',
    tags: (r.tags ?? []).join(', '), enabled: r.enabled,
    mode: conds.length > 0 ? 'conditions' : 'regex',
    conditions: conds.length > 0 ? conds.map((c) => ({ ...c, value: c.value ?? '' })) : [{ ...EMPTY_CONDITION }],
    combinator: r.combinator ?? 'and',
    useThreshold: !!r.threshold,
    thCount: String(r.threshold?.count ?? 5), thWindow: String(r.threshold?.window ?? 300),
    thGroupBy: r.threshold?.groupBy ?? '',
  };
}
/** The condition rows worth sending: a row with no field (or no value where one is required) is dropped. */
function draftConditions(d: Draft): RuleCondition[] {
  return d.conditions
    .map((c) => ({ field: c.field.trim(), op: c.op, value: (c.value ?? '').trim() }))
    .filter((c) => c.field && (OP_BY_VALUE.get(c.op)?.input === 'none' || c.value));
}
function draftField(d: Draft): RuleField { return d.field === '__custom' ? d.customField.trim() || 'any' : d.field; }
function draftTags(d: Draft): string[] { return d.tags.split(',').map((t) => t.trim()).filter(Boolean); }
function draftToInput(d: Draft, createdBy: 'user' | 'ai'): RuleInput {
  const base = {
    name: d.name.trim(), description: d.description.trim(), sev: d.sev, enabled: d.enabled, builtin: false,
    sourceFilter: d.sourceFilter.trim(), tags: draftTags(d), createdBy,
  };
  if (d.mode === 'conditions') {
    return {
      ...base, kind: 'conditions', conditions: draftConditions(d), combinator: d.combinator,
      threshold: d.useThreshold
        ? { count: Number(d.thCount) || 0, window: Number(d.thWindow) || 0, groupBy: d.thGroupBy.trim() }
        : null,
    };
  }
  return {
    ...base, kind: 'regex', pattern: d.pattern, field: draftField(d),
    flags: { ignoreCase: d.ignoreCase, multiline: d.multiline },
  };
}
/**
 * A built-in's *shape* is Python (bursts, cross-event joins), but every value that shape compares
 * against travels as `params` and really does change what fires. field/flags/sourceFilter are ignored
 * by the server — they only mean something for custom regex rules.
 */
function draftToBuiltinInput(d: Draft, params: Record<string, string>): RuleInput {
  return {
    name: d.name.trim(), description: d.description.trim(), sev: d.sev, enabled: d.enabled,
    kind: 'builtin', builtin: true, tags: draftTags(d), createdBy: 'system', params,
  };
}

/** Compile a JS approximation of the (Python-syntax) pattern for client-side highlighting; null if not compilable. */
function jsRegex(pattern: string, ignoreCase: boolean, multiline: boolean): RegExp | null {
  if (!pattern) return null;
  const src = pattern.replace(/\(\?P<([A-Za-z_]\w*)>/g, '(?<$1>').replace(/\(\?P=([A-Za-z_]\w*)\)/g, '\\k<$1>');
  try { return new RegExp(src, `g${ignoreCase ? 'i' : ''}${multiline ? 'm' : ''}`); } catch { return null; }
}

function Highlight({ text, re }: { text: string; re: RegExp | null }) {
  if (!re) return <>{text}</>;
  const out: ReactNode[] = [];
  let last = 0;
  re.lastIndex = 0;
  let m: RegExpExecArray | null;
  let guard = 0;
  while ((m = re.exec(text)) && guard++ < 50) {
    if (m[0].length === 0) { re.lastIndex++; continue; }
    if (m.index > last) out.push(text.slice(last, m.index));
    out.push(<mark key={m.index} className="rx-mark">{m[0]}</mark>);
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return <>{out}</>;
}

function sampleText(e: Event, field: RuleField): string {
  switch (field) {
    case 'msg': return e.msg;
    case 'raw': return e.raw;
    case 'host': return e.host;
    case 'user': return e.user;
    case 'source': return e.source;
    case 'file': return e.file;
    case 'any': return e.msg || e.raw;
    default: return e.fields?.[field] ?? e.msg;
  }
}

/** How a built-in decides, in the analyst's words. `detail` explains the mechanism for the rules that
 *  have no editable regex, so "nothing to edit here" never reads as "we won't tell you what it does". */
/** Short badge per parameter kind, so the expected input format is obvious without reading the help. */
const PARAM_KIND: Record<RuleParamKind, string> = {
  values: 'list', regex: 'regex', text: 'exact', int: 'number', seconds: 'seconds', bytes: 'bytes',
};

function fmtDuration(v: string): string {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return '—';
  if (n < 60) return `${n}s`;
  if (n < 3600) return `${+(n / 60).toFixed(n % 60 ? 1 : 0)} min`;
  if (n < 86400) return `${+(n / 3600).toFixed(n % 3600 ? 1 : 0)} h`;
  return `${+(n / 86400).toFixed(1)} days`;
}
function fmtBytes(v: string): string {
  let n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return '—';
  for (const u of ['B', 'KB', 'MB', 'GB', 'TB']) {
    if (n < 1024 || u === 'TB') return `${u === 'B' ? n : +n.toFixed(2)} ${u}`;
    n /= 1024;
  }
  return `${n} TB`;
}

const MECHANISM: Record<NonNullable<Rule['mechanism']>, { label: string; detail: string }> = {
  regex: { label: 'regex match', detail: 'It fires on a regular-expression match.' },
  fields: { label: 'field match', detail: 'It fires when specific parsed fields hold specific values — an exact comparison, no pattern involved.' },
  threshold: { label: 'threshold + time window', detail: 'It counts matching events inside a sliding time window and fires when the count crosses the threshold.' },
  correlation: { label: 'cross-event correlation', detail: 'It joins this event to something another rule already flagged, so it depends on that rule still being enabled.' },
  graph: { label: 'entity graph', detail: 'It reads the entity graph — how many different accounts, addresses or hosts one entity is linked to — rather than any single event. It tags no event: its hits are findings, listed under Graph findings above.' },
};

/** One (field, operator, value) row of the condition builder. */
function ConditionRow({ c, i, onChange, onRemove, canRemove }: {
  c: RuleCondition; i: number; onChange: (next: RuleCondition) => void; onRemove: () => void; canRemove: boolean;
}) {
  const known = COND_FIELD_SET.has(c.field) && c.field !== '__custom';
  const op = OP_BY_VALUE.get(c.op) ?? DEFAULT_OP;
  return (
    <div className="rule-cond__row" style={{ display: 'grid', gap: 6 }}>
      <div className="form-row" style={{ gap: 8, alignItems: 'flex-start' }}>
        <select aria-label={`Condition ${i + 1} field`} value={known ? c.field : '__custom'} style={{ flex: '1 1 180px', minWidth: 0 }}
          onChange={(e) => onChange({ ...c, field: e.target.value === '__custom' ? '' : e.target.value })}>
          {COND_FIELDS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
        </select>
        <select aria-label={`Condition ${i + 1} operator`} value={c.op} style={{ flex: '0 1 150px', minWidth: 0 }}
          onChange={(e) => onChange({ ...c, op: e.target.value as RuleOp })}>
          {OPS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        {op.input !== 'none' && (
          <input aria-label={`Condition ${i + 1} value`} className="mono" spellCheck={false} style={{ flex: '2 1 200px', minWidth: 0 }}
            inputMode={op.input === 'number' ? 'numeric' : undefined}
            placeholder={op.input === 'list' ? '401, 403' : op.input === 'regex' ? String.raw`GET\s+/admin` : op.input === 'number' ? '10000' : 'value'}
            value={c.value ?? ''} onChange={(e) => onChange({ ...c, value: e.target.value })} />
        )}
        <button className="btn btn--sm btn--icon btn--ghost" onClick={onRemove} disabled={!canRemove}
          title="Remove this condition" aria-label={`Remove condition ${i + 1}`}><Icon.Trash /></button>
      </div>
      {!known && (
        <input aria-label={`Condition ${i + 1} custom field key`} className="mono" spellCheck={false}
          placeholder="parsed field key, e.g. http.status or EventID"
          value={c.field} onChange={(e) => onChange({ ...c, field: e.target.value })} />
      )}
    </div>
  );
}

function RuleDrawer({ open, rule, onClose }: { open: boolean; rule: Rule | null; onClose: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const settings = useSettings();
  const invalidate = useInvalidateCaseData();
  const isBuiltin = !!rule?.builtin;
  const [draft, setDraft] = useState<Draft>(EMPTY_DRAFT);
  const [createdBy, setCreatedBy] = useState<'user' | 'ai'>('user');
  const [aiOpen, setAiOpen] = useState(false);
  const [aiPrompt, setAiPrompt] = useState('');
  const [aiExamples, setAiExamples] = useState('');
  const [suggestion, setSuggestion] = useState<RuleSuggestResult | null>(null);
  // live values of the built-in's condition parameters, keyed by param key
  const [params, setParams] = useState<Record<string, string>>({});

  useEffect(() => {
    if (!open) return;
    setDraft(rule ? ruleToDraft(rule) : EMPTY_DRAFT);
    setParams(Object.fromEntries((rule?.params ?? []).map((p) => [p.key, p.value])));
    setCreatedBy(rule?.createdBy === 'ai' ? 'ai' : 'user');
    setSuggestion(null);
    setAiOpen(false);
  }, [open, rule]);

  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setDraft((d) => ({ ...d, [k]: v }));
  const setParam = (key: string, v: string) => setParams((p) => ({ ...p, [key]: v }));
  const paramsDirty = (rule?.params ?? []).some((p) => (params[p.key] ?? p.value) !== p.value);
  const paramsEdited = (rule?.params ?? []).filter((p) => (params[p.key] ?? p.value) !== p.default);
  /** The regex parameter the live-test box exercises, if the rule has one. */
  const rxParam = (rule?.params ?? []).find((p) => p.kind === 'regex');
  const builtinField = rxParam?.field ?? '';
  const editableRx = isBuiltin && !!rxParam;
  // the pattern under test: a built-in's comes from its regex parameter, a custom rule's from the draft
  const livePattern = editableRx ? (params[rxParam!.key] ?? rxParam!.value) : draft.pattern;

  // live validation (debounced 500 ms)
  // only a raw-regex custom rule (or a built-in's regex param) has a single pattern to live-test
  const regexMode = isBuiltin ? editableRx : draft.mode === 'regex';
  const testKey = useDebounce(JSON.stringify({
    p: regexMode ? livePattern : '',
    f: editableRx ? (builtinField || 'raw') : draftField(draft),
    ic: draft.ignoreCase, ml: draft.multiline, sf: editableRx ? '' : draft.sourceFilter,
  }), 500);
  const [test, setTest] = useState<RuleTestResult | null>(null);
  const [testing, setTesting] = useState(false);
  const seq = useRef(0);
  useEffect(() => {
    if (!open || !regexMode) { setTest(null); return; } // nothing to test on a field/threshold/condition rule
    const k = JSON.parse(testKey) as { p: string; f: string; ic: boolean; ml: boolean; sf: string };
    if (!k.p) { setTest(null); return; }
    const my = ++seq.current;
    setTesting(true);
    api.testRule({ pattern: k.p, field: k.f, flags: { ignoreCase: k.ic, multiline: k.ml }, sourceFilter: k.sf || undefined })
      .then((r) => { if (my === seq.current) setTest(r); })
      .catch((e: unknown) => { if (my === seq.current) setTest({ hits: 0, sample: [], tookMs: 0, error: e instanceof Error ? e.message : String(e) }); })
      .finally(() => { if (my === seq.current) setTesting(false); });
  }, [testKey, open, regexMode]);

  // a built-in has no regex to test — show what it actually matched in the active case instead
  const builtinHits = useQuery({
    queryKey: qk.events({ rule: rule?.id, limit: 10 }),
    queryFn: () => api.events({ q: `rule:${rule!.id}`, limit: 10 }),
    enabled: open && isBuiltin && !!rule,
  });

  const re = useMemo(() => jsRegex(livePattern, draft.ignoreCase, draft.multiline), [livePattern, draft.ignoreCase, draft.multiline]);
  const localErr = regexMode && livePattern && !re ? 'Pattern is not a valid regular expression (JS check — the server validates Python syntax).' : null;
  // condition builder helpers
  const conditions = draft.conditions;
  const setCondition = (i: number, next: RuleCondition) =>
    setDraft((d) => ({ ...d, conditions: d.conditions.map((c, j) => (j === i ? next : c)) }));
  const addCondition = () => setDraft((d) => ({ ...d, conditions: [...d.conditions, { ...EMPTY_CONDITION }] }));
  const removeCondition = (i: number) => setDraft((d) => ({ ...d, conditions: d.conditions.filter((_, j) => j !== i) }));
  const readyConditions = draftConditions(draft);
  const thresholdErr = draft.mode === 'conditions' && draft.useThreshold
    ? (!(Number(draft.thCount) >= 1) ? 'Count must be at least 1.'
      : !(Number(draft.thWindow) >= 1 && Number(draft.thWindow) <= 604800) ? 'Window must be between 1 second and 7 days.' : null)
    : null;
  const triggerPreview = isBuiltin ? '' : previewTrigger(draft);

  const save = useMutation({
    mutationFn: () => {
      if (rule && isBuiltin) return api.updateRule(rule.id, draftToBuiltinInput(draft, params));
      return rule ? api.updateRule(rule.id, draftToInput(draft, createdBy)) : api.createRule(draftToInput(draft, createdBy));
    },
    onSuccess: (r) => {
      toast.success(rule ? 'Rule updated' : 'Rule created', `${r.name} — re-evaluating the active case`);
      void qc.invalidateQueries({ queryKey: qk.rules });
      void qc.invalidateQueries({ queryKey: ['anomalies'] });
      invalidate();
      onClose();
    },
    onError: (e) => toast.error('Could not save rule', e),
  });

  const suggest = useMutation({
    mutationFn: () => api.suggestRule({ prompt: aiPrompt.trim(), examples: aiExamples.split(/\r?\n/).map((l) => l.trim()).filter(Boolean) }),
    onSuccess: (res) => {
      setSuggestion(res);
      const d = ruleToDraft(res.rule);
      setDraft((cur) => ({ ...d, enabled: cur.enabled }));
      setCreatedBy(res.source === 'ai' ? 'ai' : 'user');
    },
    onError: (e) => toast.error('Could not build a rule', e),
  });

  const restore = useMutation({
    mutationFn: () => api.restoreRule(rule!.id),
    onSuccess: (r) => {
      toast.success('Rule restored', `${r.name} is back to its shipped definition`);
      void qc.invalidateQueries({ queryKey: qk.rules });
      void qc.invalidateQueries({ queryKey: ['anomalies'] });
      invalidate();
      onClose();
    },
    onError: (e) => toast.error('Could not restore rule', e),
  });

  const aiOff = settings.data ? settings.data.ai.provider === 'none' : false;
  // an empty condition value would 400 on the server, so block the save and say why up front
  const emptyParam = (rule?.params ?? []).find((p) => !(params[p.key] ?? p.value).trim());
  const canSave = draft.name.trim().length > 0 && !save.isPending && !(editableRx && localErr) && !emptyParam
    && (isBuiltin
      || (draft.mode === 'conditions'
        ? readyConditions.length > 0 && !thresholdErr
        : draft.pattern.length > 0 && !localErr && (draft.field !== '__custom' || draft.customField.trim().length > 0)));

  return (
    <Drawer
      open={open}
      onClose={onClose}
      wide
      title={rule ? `Edit rule · ${rule.name}` : 'New detection rule'}
      sub={rule
        ? <span className="mono">{rule.id}{isBuiltin ? ' · built-in' : ''}{rule.overridden ? ' · edited' : ''}</span>
        : 'built from conditions or a regex — evaluated at ingest and re-applied to the active case'}
      footer={
        <>
          <button className="btn btn--ghost" onClick={onClose}>Cancel</button>
          {isBuiltin && rule?.overridden && (
            <button className="btn btn--ghost" onClick={() => restore.mutate()} disabled={restore.isPending}
              title="Discard your edits and go back to the definition Iris ships">
              {restore.isPending && <span className="btn__spinner" />}Reset to default
            </button>
          )}
          <span style={{ flex: 1 }} />
          {emptyParam && <span className="rule-cond__err">{emptyParam.label} cannot be empty</span>}
          {!emptyParam && thresholdErr && <span className="rule-cond__err">{thresholdErr}</span>}
          {!emptyParam && !thresholdErr && paramsDirty && <span className="muted" style={{ fontSize: 'var(--fs-xs)' }}>condition changed — save to re-evaluate</span>}
          <button className="btn btn--accent" onClick={() => save.mutate()} disabled={!canSave}>
            {save.isPending && <span className="btn__spinner" />}{rule ? 'Save changes' : 'Create rule'}
          </button>
        </>
      }
    >
      <div className="rule-form">
        {isBuiltin && (
          <div className="rule-logic">
            <div className="rule-logic__head">
              <span className="eyebrow">What makes this rule fire</span>
              <span className={cx('rule-mech', `rule-mech--${rule?.mechanism ?? 'fields'}`)}>
                {MECHANISM[rule?.mechanism ?? 'fields'].label}
              </span>
              <span style={{ flex: 1 }} />
              {rule?.hits !== undefined && (
                <span className={cx('badge', rule.hits > 0 && 'badge--ok')}>{fmtInt(rule.hits)} hit{rule.hits === 1 ? '' : 's'} in the workspace</span>
              )}
            </div>
            <div className="rule-logic__text">{rule?.logic || rule?.description}</div>

            {/* Every constant in that condition, editable. This is the rule — changing anything here
                changes what gets flagged, unlike the Description field further down. */}
            {(rule?.params?.length ?? 0) > 0 && (
              <div className="rule-cond">
                <div className="rule-cond__head">
                  <span className="eyebrow">Condition — editable</span>
                  {paramsEdited.length > 0 && (
                    <button className="linklike" onClick={() =>
                      setParams(Object.fromEntries((rule?.params ?? []).map((p) => [p.key, p.default])))}>
                      reset {paramsEdited.length} change{paramsEdited.length === 1 ? '' : 's'}
                    </button>
                  )}
                </div>
                {rule!.params!.map((p) => {
                  const val = params[p.key] ?? p.value;
                  const changed = val !== p.default;
                  return (
                    <div key={p.key} className={cx('rule-cond__row', changed && 'rule-cond__row--changed')}>
                      <label className="rule-cond__label" htmlFor={`param-${p.key}`}>
                        <span className="rule-cond__name">{p.label}</span>
                        {p.field && <code className="rule-cond__field">{p.field}</code>}
                        <span className={cx('rule-cond__kind', `rule-cond__kind--${p.kind}`)}>{PARAM_KIND[p.kind]}</span>
                      </label>
                      {p.kind === 'regex' ? (
                        <>
                          <textarea id={`param-${p.key}`} rows={2} spellCheck={false}
                            className={cx('mono', p.key === rxParam?.key && (localErr || test?.error) && 'invalid')}
                            value={val} onChange={(e) => setParam(p.key, e.target.value)} />
                          {/* live match count for the regex the test box is wired to */}
                          {p.key === rxParam?.key && (
                            <div className="rule-cond__test">
                              {testing && <span className="spinner" style={{ width: 10, height: 10, display: 'inline-block' }} />}
                              {!testing && (localErr || test?.error) ? (
                                <span className="rule-cond__err">{test?.error ?? localErr}</span>
                              ) : !testing && test ? (
                                <span className={cx('badge', test.hits > 0 && 'badge--ok')}>
                                  {fmtInt(test.hits)} event{test.hits === 1 ? '' : 's'} match this regex · {test.tookMs < 1 ? '<1' : Math.round(test.tookMs)} ms
                                </span>
                              ) : null}
                              <span className="rule-cond__testnote">
                                counted across the whole case — the rule's other conditions narrow it further
                              </span>
                            </div>
                          )}
                        </>
                      ) : (
                        <input id={`param-${p.key}`} className="mono" spellCheck={false}
                          inputMode={p.kind === 'int' || p.kind === 'seconds' || p.kind === 'bytes' ? 'numeric' : undefined}
                          value={val} onChange={(e) => setParam(p.key, e.target.value)} />
                      )}
                      <div className="rule-cond__help">
                        {p.help}
                        {p.kind === 'values' && ' Comma separated.'}
                        {p.kind === 'seconds' && ` Currently ${fmtDuration(val)}.`}
                        {p.kind === 'bytes' && ` Currently ${fmtBytes(val)}.`}
                        {changed && (
                          <>
                            {' '}<button className="linklike" onClick={() => setParam(p.key, p.default)}>
                              revert to {p.kind === 'regex' ? 'shipped regex' : p.default}
                            </button>
                          </>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            <div className="rule-logic__hint">
              <b>Everything above is the rule.</b> {MECHANISM[rule?.mechanism ?? 'fields'].detail}{' '}
              The shape of the condition is code, but every value it compares against is editable here and
              takes effect on save. The <b>Description</b> field below is <b>notes only</b>: it documents what
              a hit means and never affects what gets flagged. Reset to default restores everything.
            </div>
          </div>
        )}

        {/* Build with AI — regex rules only */}
        {!isBuiltin && (
        <div className={cx('rule-ai', aiOpen && 'open')}>
          <button className="rule-ai__head" onClick={() => setAiOpen((v) => !v)} aria-expanded={aiOpen}>
            <Icon.Sparkle />
            <span>Build with AI</span>
            <span className="muted" style={{ fontWeight: 400 }}>describe what to detect — the draft fills the form below for review</span>
            <Icon.Chevron className="rule-ai__caret" />
          </button>
          {aiOpen && (
            <div className="rule-ai__body">
              {aiOff && (
                <div className="rule-ai__hint">
                  AI assistant is disabled — a heuristic draft (keyword alternation) will be generated instead. <Link to="/settings#ai">Enable a provider in Settings</Link>.
                </div>
              )}
              <div className="field">
                <label className="field__label" htmlFor="ai-prompt">What should this rule detect?</label>
                <textarea id="ai-prompt" rows={2} value={aiPrompt} onChange={(e) => setAiPrompt(e.target.value)} placeholder="e.g. failed SSH logins for root from external IPs" />
              </div>
              <div className="field">
                <label className="field__label" htmlFor="ai-examples">Example lines <span className="muted">(optional, one per line)</span></label>
                <textarea id="ai-examples" rows={3} className="mono" value={aiExamples} onChange={(e) => setAiExamples(e.target.value)} placeholder="Failed password for root from 203.0.113.9 port 51234 ssh2" spellCheck={false} />
              </div>
              <div className="form-row" style={{ justifyContent: 'space-between' }}>
                {suggestion ? (
                  <span className={cx('badge', suggestion.source === 'ai' ? 'badge--ok' : 'badge--warn')}>{suggestion.source === 'ai' ? 'AI draft' : 'Heuristic draft'}</span>
                ) : <span />}
                <button className="btn btn--sm btn--accent" onClick={() => suggest.mutate()} disabled={!aiPrompt.trim() || suggest.isPending}>
                  {suggest.isPending && <span className="btn__spinner" />}Draft rule
                </button>
              </div>
              {suggestion && (
                <div className="rule-ai__rationale">
                  <div className="eyebrow">Rationale</div>
                  <div>{suggestion.rationale}</div>
                </div>
              )}
            </div>
          )}
        </div>
        )}

        {/* Condition builder — the custom-rule equivalent of a built-in's editable condition block.
            Everything here is what fires; the Description field below is notes only. */}
        {!isBuiltin && (
          <div className="rule-logic">
            <div className="rule-logic__head">
              <span className="eyebrow">What makes this rule fire</span>
              <span className={cx('rule-mech', `rule-mech--${draft.mode === 'regex' ? 'regex' : draft.useThreshold ? 'threshold' : 'fields'}`)}>
                {draft.mode === 'regex' ? MECHANISM.regex.label : draft.useThreshold ? MECHANISM.threshold.label : MECHANISM.fields.label}
              </span>
              <span style={{ flex: 1 }} />
              <div className="chip-row">
                <button className={cx('chip', draft.mode === 'conditions' && 'on')} aria-pressed={draft.mode === 'conditions'}
                  onClick={() => set('mode', 'conditions')}>conditions</button>
                <button className={cx('chip', draft.mode === 'regex' && 'on')} aria-pressed={draft.mode === 'regex'}
                  onClick={() => set('mode', 'regex')}>regex pattern</button>
              </div>
            </div>

            {draft.mode === 'conditions' && (
              <div className="rule-cond">
                <div className="rule-cond__head">
                  <span className="eyebrow">Conditions</span>
                  <div className="chip-row" style={{ marginLeft: 8 }}>
                    <span className="chip-row__label">match</span>
                    {(['and', 'or'] as const).map((k) => (
                      <button key={k} className={cx('chip', draft.combinator === k && 'on')} aria-pressed={draft.combinator === k}
                        onClick={() => set('combinator', k)}>{k === 'and' ? 'all (AND)' : 'any (OR)'}</button>
                    ))}
                  </div>
                </div>
                {conditions.map((c, i) => (
                  <ConditionRow key={i} c={c} i={i} canRemove={conditions.length > 1}
                    onChange={(next) => setCondition(i, next)} onRemove={() => removeCondition(i)} />
                ))}
                <div className="form-row" style={{ justifyContent: 'space-between' }}>
                  <button className="btn btn--sm" onClick={addCondition}><Icon.Plus /> Add condition</button>
                  <span className="muted" style={{ fontSize: 'var(--fs-xs)' }}>
                    comparisons are case-insensitive · a field the event does not carry satisfies the negative operators
                  </span>
                </div>

                <div className="rule-cond__row" style={{ marginTop: 4 }}>
                  <Toggle on={draft.useThreshold} onChange={(v) => set('useThreshold', v)}
                    label="Only fire on a burst (count within a time window)" />
                  {draft.useThreshold && (
                    <>
                      <div className="form-row" style={{ gap: 12, marginTop: 8, flexWrap: 'wrap' }}>
                        <div className="field" style={{ flex: '0 1 120px' }}>
                          <label className="field__label" htmlFor="th-count">Events to fire</label>
                          <input id="th-count" className="mono" inputMode="numeric" value={draft.thCount}
                            onChange={(e) => set('thCount', e.target.value)} />
                        </div>
                        <div className="field" style={{ flex: '0 1 140px' }}>
                          <label className="field__label" htmlFor="th-window">Window (seconds)</label>
                          <input id="th-window" className="mono" inputMode="numeric" value={draft.thWindow}
                            onChange={(e) => set('thWindow', e.target.value)} />
                        </div>
                        <div className="field" style={{ flex: '1 1 180px' }}>
                          <label className="field__label" htmlFor="th-group">Group by <span className="muted">(optional field)</span></label>
                          <input id="th-group" className="mono" spellCheck={false} placeholder="src_ip, user, host…"
                            value={draft.thGroupBy} onChange={(e) => set('thGroupBy', e.target.value)} />
                        </div>
                      </div>
                      <div className="rule-cond__help">
                        Counts matches in a sliding {fmtDuration(draft.thWindow)} window{draft.thGroupBy.trim() ? ` per ${draft.thGroupBy.trim()}` : ' across the whole case'} and
                        tags the last event of the densest window — the same shape the built-in burst rules use.
                        {thresholdErr && <span className="rule-cond__err"> {thresholdErr}</span>}
                      </div>
                    </>
                  )}
                </div>
              </div>
            )}

            {/* The generated trigger. Read-only on purpose: this is what the engine evaluates. */}
            <div className="rule-logic__text">
              {triggerPreview || 'Add a condition (or a regex pattern) — the trigger is generated from it.'}
            </div>
            <div className="rule-logic__hint">
              <b>Everything above is the rule.</b> The line just above is the <b>trigger</b>: it is generated from what
              you built and is what the engine evaluates. The <b>Description</b> field below is <b>notes only</b> — it
              documents what a hit means and never affects what gets flagged.
            </div>
          </div>
        )}

        <div className="form-grid">
          <div className="field" style={{ gridColumn: '1 / -1' }}>
            <label className="field__label" htmlFor="r-name">Name</label>
            <input id="r-name" value={draft.name} onChange={(e) => set('name', e.target.value)} placeholder="Root SSH brute force" />
          </div>
          <div className="field" style={{ gridColumn: '1 / -1' }}>
            <label className="field__label" htmlFor="r-desc">
              Description <span className="muted">— notes only, does not affect what gets flagged</span>
            </label>
            <input id="r-desc" value={draft.description} onChange={(e) => set('description', e.target.value)}
              placeholder="what a hit means and why it matters" />
          </div>
          <div className="field">
            <label className="field__label" htmlFor="r-sev">Severity</label>
            <select id="r-sev" value={draft.sev} onChange={(e) => set('sev', e.target.value as Severity)}>
              {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          {!isBuiltin && draft.mode === 'regex' && (
          <div className="field">
            <label className="field__label" htmlFor="r-field">Field</label>
            <select id="r-field" value={draft.field} onChange={(e) => set('field', e.target.value)}>
              {FIELD_OPTIONS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
            </select>
            {draft.field === '__custom' && (
              <input value={draft.customField} onChange={(e) => set('customField', e.target.value)} placeholder="fields[] key, e.g. src_ip" aria-label="Custom field key" style={{ marginTop: 6 }} />
            )}
          </div>
          )}
          {/* built-ins edit their regex in the Condition block above — this is the custom-rule editor */}
          {!isBuiltin && draft.mode === 'regex' && (
          <div className="field" style={{ gridColumn: '1 / -1' }}>
            <label className="field__label" htmlFor="r-pattern">
              Regex pattern <span className="muted">(Python syntax)</span>
              <span className="rule-form__status">
                {testing && <span className="spinner" style={{ width: 10, height: 10, display: 'inline-block' }} />}
                {!testing && test && !test.error && !localErr && (
                  <span className={cx('badge', test.hits > 0 && 'badge--ok')}>{fmtInt(test.hits)} hit{test.hits === 1 ? '' : 's'} · {test.tookMs < 1 ? '<1' : Math.round(test.tookMs)} ms</span>
                )}
                {!testing && (localErr || test?.error) && <span className="badge badge--bad">invalid</span>}
              </span>
            </label>
            <textarea id="r-pattern" className={cx('mono rule-form__pattern', (localErr || test?.error) && 'invalid')} rows={3} value={draft.pattern} onChange={(e) => set('pattern', e.target.value)}
              placeholder={String.raw`Failed password for (invalid user )?root from (?P<ip>\d+\.\d+\.\d+\.\d+)`} spellCheck={false} />
            {(localErr || test?.error) && <div className="field__hint" style={{ color: 'var(--bad)' }}>{test?.error ?? localErr}</div>}
          </div>
          )}
          {!isBuiltin && draft.mode === 'regex' && (
          <div className="field">
            <span className="field__label">Flags</span>
            <div className="form-row" style={{ gap: 16 }}>
              <Toggle on={draft.ignoreCase} onChange={(v) => set('ignoreCase', v)} label="Ignore case" />
              <Toggle on={draft.multiline} onChange={(v) => set('multiline', v)} label="Multiline" />
            </div>
          </div>
          )}
          {!isBuiltin && (
          <div className="field">
            <label className="field__label" htmlFor="r-src">Source filter <span className="muted">(family or file substring)</span></label>
            <input id="r-src" value={draft.sourceFilter} onChange={(e) => set('sourceFilter', e.target.value)} placeholder="e.g. syslog or auth.log" />
          </div>
          )}
          <div className="field">
            <label className="field__label" htmlFor="r-tags">Tags <span className="muted">(comma-separated)</span></label>
            <input id="r-tags" value={draft.tags} onChange={(e) => set('tags', e.target.value)} placeholder="ssh, brute-force, T1110" />
          </div>
          <div className="field">
            <span className="field__label">State</span>
            <Toggle on={draft.enabled} onChange={(v) => set('enabled', v)} label={draft.enabled ? 'Enabled' : 'Disabled'} />
          </div>
        </div>

        {/* What this built-in actually matched in the active case */}
        {isBuiltin && (builtinHits.data?.rows.length ?? 0) > 0 && (
          <div className="rule-samples">
            <div className="rule-samples__head">
              <span className="eyebrow">Matched events</span>
              <span className="muted mono" style={{ fontSize: 'var(--fs-xs)' }}>
                {builtinHits.data!.rows.length} of {fmtInt(builtinHits.data!.total)}
              </span>
            </div>
            {builtinHits.data!.rows.map((e) => (
              <div key={e.id} className="rule-samples__row">
                <span className="cell-mono cell-dim">{fmtTs(e.ts)}</span>
                <span className="cell-mono cell-dim ellipsis" title={e.source}>{e.source}</span>
                <span className="cell-mono rule-samples__text">{e.msg}</span>
              </div>
            ))}
          </div>
        )}
        {isBuiltin && builtinHits.isSuccess && builtinHits.data.rows.length === 0 && (
          <div className="muted" style={{ fontSize: 'var(--fs-sm)' }}>This rule has not matched anything in the active case.</div>
        )}

        {/* Live sample matches */}
        {!isBuiltin && test && !test.error && test.sample.length > 0 && (
          <div className="rule-samples">
            <div className="rule-samples__head">
              <span className="eyebrow">Sample matches</span>
              <span className="muted mono" style={{ fontSize: 'var(--fs-xs)' }}>{test.sample.length} of {fmtInt(test.hits)}</span>
            </div>
            {test.sample.slice(0, 10).map((e) => (
              <div key={e.id} className="rule-samples__row">
                <span className="cell-mono cell-dim">{fmtTs(e.ts)}</span>
                <span className="cell-mono cell-dim ellipsis" title={e.source}>{e.source}</span>
                <span className="cell-mono rule-samples__text"><Highlight text={sampleText(e, draftField(draft))} re={re} /></span>
              </div>
            ))}
          </div>
        )}
        {test && !test.error && test.hits === 0 && draft.pattern && !testing && (
          <div className="muted" style={{ fontSize: 'var(--fs-sm)' }}>Nothing ingested matches yet — the rule still saves and applies to future ingests.</div>
        )}
      </div>
    </Drawer>
  );
}

/* ───────────────────────── Rules manager ───────────────────────── */

function RulesSection() {
  const rules = useRules(true); // includes removed built-ins so the "removed" filter can restore them
  const qc = useQueryClient();
  const toast = useToast();
  const invalidate = useInvalidateCaseData();
  const [drawer, setDrawer] = useState<{ open: boolean; rule: Rule | null }>({ open: false, rule: null });
  const [toDelete, setToDelete] = useState<Rule | null>(null);
  const [clearing, setClearing] = useState(false);
  const [filter, setFilter] = useState<'all' | 'builtin' | 'custom' | 'removed'>('all');
  const [ruleText, setRuleText] = useState('');

  const afterChange = () => {
    void qc.invalidateQueries({ queryKey: qk.rules });
    void qc.invalidateQueries({ queryKey: ['anomalies'] });
    invalidate();
  };
  const toggle = useMutation({
    mutationFn: (id: string) => api.toggleRule(id),
    onMutate: async (id) => {
      await qc.cancelQueries({ queryKey: qk.rules });
      const prev = qc.getQueryData<Rule[]>(qk.rules);
      qc.setQueryData<Rule[]>(qk.rules, (rs) => rs?.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r)));
      return { prev };
    },
    onError: (e, _id, ctx) => { if (ctx?.prev) qc.setQueryData(qk.rules, ctx.prev); toast.error('Could not toggle rule', e); },
    onSettled: afterChange,
  });
  const del = useMutation({
    mutationFn: (r: Rule) => api.deleteRule(r.id),
    onSuccess: (_d, r) => {
      toast.success(r.builtin ? 'Rule removed' : 'Rule deleted',
        r.builtin ? `${r.name} stops firing — restore it from the "removed" filter` : undefined);
      setToDelete(null);
      afterChange();
    },
    onError: (e) => toast.error('Could not delete rule', e),
  });
  const restore = useMutation({
    mutationFn: (id: string) => api.restoreRule(id),
    onSuccess: (r) => { toast.success('Rule restored', `${r.name} is back to its shipped definition`); afterChange(); },
    onError: (e) => toast.error('Could not restore rule', e),
  });
  // Clear all: custom rules really are deleted, built-ins are only taken out of the catalogue, so the
  // toast tells the analyst which half is recoverable rather than implying everything is gone.
  const clearAll = useMutation({
    mutationFn: (scope: 'all' | 'custom') => api.clearRules(scope),
    onSuccess: (r) => {
      setClearing(false);
      toast.success('Rules cleared',
        `${r.custom} custom rule${r.custom === 1 ? '' : 's'} deleted${r.builtin ? ` · ${r.builtin} built-in${r.builtin === 1 ? '' : 's'} removed — restore them with "Restore defaults"` : ''}`);
      afterChange();
    },
    onError: (e) => toast.error('Could not clear rules', e),
  });
  const restoreAll = useMutation({
    mutationFn: () => api.restoreDefaultRules(),
    onSuccess: (r) => { toast.success('Defaults restored', `${r.restored} built-in rule${r.restored === 1 ? '' : 's'} back, all edits discarded`); afterChange(); },
    onError: (e) => toast.error('Could not restore defaults', e),
  });

  const list = useMemo(() => {
    const all = rules.data ?? [];
    const f = filter === 'all' ? all.filter((r) => !r.removed)
      : filter === 'removed' ? all.filter((r) => r.removed)
      : all.filter((r) => !r.removed && (filter === 'builtin' ? r.builtin : !r.builtin));
    const needle = ruleText.trim().toLowerCase();
    const hit = (r: Rule) => !needle || r.name.toLowerCase().includes(needle) || r.id.toLowerCase().includes(needle)
      || (r.tags ?? []).some((t) => t.toLowerCase().includes(needle));
    return [...f.filter(hit)].sort((a, b) => Number(a.builtin) - Number(b.builtin) || (b.hits ?? 0) - (a.hits ?? 0) || a.name.localeCompare(b.name));
  }, [rules.data, filter, ruleText]);
  const live = rules.data?.filter((r) => !r.removed) ?? [];
  const nCustom = live.filter((r) => !r.builtin).length;
  const nBuiltin = live.filter((r) => r.builtin).length;
  const nRemoved = rules.data?.filter((r) => r.removed).length ?? 0;

  return (
    <section>
      <SectionHead
        eyebrow="02 · Rules"
        title="Detection rules"
        hint={rules.data ? `${nBuiltin} built-in · ${nCustom} custom` : 'built-in Sigma-like rules plus your regex rules'}
        actions={
          <>
            {nRemoved > 0 && (
              <button className="btn btn--sm btn--ghost" onClick={() => restoreAll.mutate()} disabled={restoreAll.isPending}
                title="Put every built-in back and discard all edits to them">
                {restoreAll.isPending && <span className="btn__spinner" />}Restore defaults
              </button>
            )}
            <button className="btn btn--sm btn--ghost" onClick={() => setClearing(true)} disabled={live.length === 0}
              title="Empty the rule list">
              <Icon.Trash /> Clear all rules
            </button>
            <button className="btn btn--accent btn--sm" onClick={() => setDrawer({ open: true, rule: null })}>
              <Icon.Plus /> New rule
            </button>
          </>
        }
      />
      <div className="anom__toolbar">
        <div className="chip-row">
          <span className="chip-row__label">Show</span>
          {(['all', 'builtin', 'custom'] as const).map((f) => (
            <button key={f} className={cx('chip', filter === f && 'on')} onClick={() => setFilter(f)} aria-pressed={filter === f}>
              {f === 'builtin' ? 'built-in' : f}
              <span className="chip__count">{f === 'all' ? live.length : f === 'builtin' ? nBuiltin : nCustom}</span>
            </button>
          ))}
          {nRemoved > 0 && (
            <button className={cx('chip', filter === 'removed' && 'on')} onClick={() => setFilter('removed')} aria-pressed={filter === 'removed'}>
              removed <span className="chip__count">{nRemoved}</span>
            </button>
          )}
        </div>
        {/* 33 built-ins plus your own: finding "the SSH brute force one" by scrolling is the cost this
            removes. Matches name, id and tags. */}
        <div className="anom__search">
          <Icon.Search className="anom__search-icon" aria-hidden />
          <input value={ruleText} onChange={(e) => setRuleText(e.target.value)} placeholder="Filter rules by name, id or tag"
            aria-label="Filter rules" spellCheck={false} />
          {ruleText && <button className="anom__search-x" onClick={() => setRuleText('')} aria-label="Clear filter">×</button>}
        </div>
      </div>
      {rules.isError ? (
        <ErrorState title="Could not load rules" error={rules.error} onRetry={() => void rules.refetch()} />
      ) : (
        <div className="table">
          <div className="table__head rules-grid">
            <div>On</div><div>Sev</div><div>Rule</div><div>Kind</div><div>What flags it</div><div className="num">Hits</div><div>Tags</div><div />
          </div>
          {rules.isLoading && <SkeletonRows n={6} />}
          {!rules.isLoading && list.length === 0 && (
            <div className="table__empty">
              <EmptyState inline title={filter === 'custom' ? 'No custom rules yet' : 'No rules'} body={filter === 'custom' ? 'Build one from conditions, write a regex, or draft one with AI.' : undefined}
                actions={filter === 'custom' ? <button className="btn btn--accent btn--sm" onClick={() => setDrawer({ open: true, rule: null })}><Icon.Plus /> New rule</button> : undefined} />
            </div>
          )}
          {list.map((r) => (
            <div
              key={r.id}
              className={cx('table__row rules-grid clickable', !r.enabled && 'rules__row--off', r.removed && 'rules__row--removed')}
              role="button"
              tabIndex={0}
              onClick={() => setDrawer({ open: true, rule: r })}
              onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setDrawer({ open: true, rule: r }); } }}
              title={`Open ${r.name}`}
            >
              {/* stopPropagation everywhere interactive: the row itself opens the drawer */}
              <div onClick={(e) => e.stopPropagation()}><Toggle on={r.enabled} onChange={() => toggle.mutate(r.id)} disabled={r.removed} /></div>
              <div className="sev-cell"><SevTag sev={r.sev} /></div>
              <div className="rules__name">
                <span className="cell-bright">{r.name}</span>
                <span className="cell-mono cell-dim ellipsis" style={{ fontSize: 'var(--fs-xs)' }} title={r.description}>{r.id}{r.description ? ` · ${r.description}` : ''}</span>
              </div>
              <div>
                <span className={cx('badge', !r.builtin && 'badge--ok')}>{r.builtin ? 'built-in' : r.kind}</span>
                {r.createdBy === 'ai' && <span className="badge" style={{ marginLeft: 4 }} title="Drafted by the AI assistant">ai</span>}
                {r.overridden && <span className="badge badge--warn" style={{ marginLeft: 4 }} title="You edited this built-in — reset it from the drawer">edited</span>}
                {r.removed && <span className="badge badge--bad" style={{ marginLeft: 4 }}>removed</span>}
              </div>
              <div className="rules__pattern ellipsis" title={r.kind === 'regex' ? r.pattern : (r.logic || r.patterns?.map((p) => `${p.field}: ${p.pattern}`).join(' · ') || '')}>
                {r.kind === 'regex' ? (
                  <><span className="cell-dim">{r.field ?? 'any'}</span> <span className="cell-mono">{r.pattern}</span></>
                ) : r.kind === 'conditions' ? (
                  <span className="cell-dim">{r.logic ?? 'composed conditions'}</span>
                ) : r.patterns?.[0] ? (
                  <><span className="cell-dim">{r.patterns[0].field}</span> <span className="cell-mono">{r.patterns[0].pattern}</span></>
                ) : <span className="cell-dim">{r.logic ?? 'Sigma-like logic'}</span>}
              </div>
              <div className="cell-mono num">{r.hits === undefined ? '—' : fmtInt(r.hits)}</div>
              <div className="rules__tags ellipsis">{(r.tags ?? []).slice(0, 3).map((t) => <span key={t} className="tag">{t}</span>)}{(r.tags?.length ?? 0) > 3 && <span className="tag">+{r.tags.length - 3}</span>}</div>
              <div className="rules__actions" onClick={(e) => e.stopPropagation()}>
                {r.removed ? (
                  <button className="btn btn--sm" onClick={() => restore.mutate(r.id)} disabled={restore.isPending} title="Put this built-in back in the catalogue">
                    {restore.isPending && restore.variables === r.id && <span className="btn__spinner" />}Restore
                  </button>
                ) : (
                  <>
                    <button className="btn btn--sm btn--ghost" onClick={() => setDrawer({ open: true, rule: r })}>Edit</button>
                    <button className="btn btn--sm btn--icon btn--ghost" onClick={() => setToDelete(r)}
                      title={r.builtin ? 'Remove from the catalogue' : 'Delete rule'} aria-label={`${r.builtin ? 'Remove' : 'Delete'} ${r.name}`}><Icon.Trash /></button>
                  </>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
      <RuleDrawer open={drawer.open} rule={drawer.rule} onClose={() => setDrawer((d) => ({ ...d, open: false }))} />
      <ConfirmDialog
        open={toDelete !== null}
        title={toDelete?.builtin ? 'Remove built-in rule' : 'Delete rule'}
        danger
        confirmLabel={toDelete?.builtin ? 'Remove' : 'Delete'}
        busy={del.isPending}
        text={toDelete?.builtin ? (
          <>Remove <b>{toDelete?.name}</b> from the rule catalogue? It stops firing and its detections are dropped on
            re-evaluation. Because it ships with Iris you can put it back any time from the <b>removed</b> filter.</>
        ) : (
          <>Delete <b>{toDelete?.name}</b>? Its detections are removed from the active case on re-evaluation. This cannot be undone.</>
        )}
        onConfirm={() => { if (toDelete) del.mutate(toDelete); }}
        onCancel={() => setToDelete(null)}
      />
      <ConfirmDialog
        open={clearing}
        title="Clear all rules"
        danger
        confirmLabel={`Clear all ${live.length}`}
        busy={clearAll.isPending}
        text={
          <>
            Empty the rule list: <b>{nCustom} custom rule{nCustom === 1 ? '' : 's'}</b> and <b>{nBuiltin} built-in{nBuiltin === 1 ? '' : 's'}</b>.
            Detections from all of them are dropped from the active case on re-evaluation.
            <br /><br />
            The built-ins are only taken out of the catalogue — <b>Restore defaults</b> brings them all back.
            The custom rules are <b>deleted for good</b>.
            {nCustom > 0 && (
              <>
                {' '}To keep yours, clear only the built-ins instead:{' '}
                <button className="linklike" onClick={() => clearAll.mutate('custom')} disabled={clearAll.isPending}>
                  delete just the {nCustom} custom rule{nCustom === 1 ? '' : 's'}
                </button>.
              </>
            )}
          </>
        }
        onConfirm={() => clearAll.mutate('all')}
        onCancel={() => setClearing(false)}
      />
    </section>
  );
}

/* ───────────────────────── Entity-graph findings ─────────────────────────
 * A whole class of detection cannot be phrased per event: "this address authenticated as fourteen
 * different accounts" is a property of the SHAPE of the relationships, and every one of those lines is
 * unremarkable on its own. So these rows name an ENTITY rather than a rule-with-hits, and every one
 * carries the way through to the thing it is about: the graph, focused on that node, and the events it
 * was derived from. A finding you cannot open is an assertion. */
function GraphFindingRow({ f }: { f: GraphFinding }) {
  const q = `entity:"${f.nodeValue.replace(/"/g, '\\"')}"`;
  return (
    <div className="table__row table__row--sev gfind-grid" style={{ ['--row-sev' as string]: sevVar(f.sev) }}>
      <div className="sev-cell"><SevTag sev={f.sev} /></div>
      <div className="gfind__what">
        <span className="cell-bright">{f.name}</span>
        <span className="cell-mono cell-dim" style={{ fontSize: 'var(--fs-xs)' }}>{f.ruleId}</span>
      </div>
      <div className="gfind__summary">
        <span className="chip chip--mono chip--static">{f.nodeType}</span>{' '}
        {f.summary}
      </div>
      <div className="cell-mono num" title={f.metricLabel}>{fmtInt(f.metric)}</div>
      <div className="gfind__go">
        <Link className="btn btn--sm btn--ghost" to={`/graph?focus=${encodeURIComponent(f.nodeId)}`}
          title="Open the entity graph focused on this node">Graph</Link>
        <Link className="btn btn--sm btn--ghost" to={`/search?q=${encodeURIComponent(q)}`}
          title="Every event this entity appears in">Events</Link>
      </div>
    </div>
  );
}

function GraphFindingsSection() {
  const [sev, setSev] = useState<Severity[]>([]);
  const q = useQuery({
    queryKey: ['graph-anomalies'],
    queryFn: () => api.graphAnomalies({ limit: 200 }),
    // Only while the graph is still being built. A finding list is derived from a structure that is
    // itself cached per store version, so polling a ready one is a request that can never say anything
    // new — and the sidebar polling /api/graph is what started a six-worker extraction every few seconds.
    refetchInterval: (query) => (query.state.data && !query.state.data.evaluated ? 3000 : false),
  });
  const rows = useMemo(() => {
    const all = q.data?.findings ?? [];
    return sev.length ? all.filter((f) => sev.includes(f.sev)) : all;
  }, [q.data, sev]);
  const counts = useMemo(() => {
    const m: Partial<Record<Severity, number>> = {};
    for (const f of q.data?.findings ?? []) m[f.sev] = (m[f.sev] ?? 0) + 1;
    return m;
  }, [q.data]);

  return (
    <section>
      <SectionHead
        eyebrow="02 · Entity graph"
        title={<>Graph findings {q.data?.evaluated && <span className="sec__count">{q.data.findings.length}</span>}</>}
        hint={
          <>
            Detections that read the entity graph rather than one line at a time — fan-out, pivots and
            failure-heavy relationships. {q.data ? `${q.data.rules} graph rule${q.data.rules === 1 ? '' : 's'} enabled` : ''}
            {' '}· tune them in the rule catalogue below.
          </>
        }
      />
      {q.isError && <ErrorState error={q.error} onRetry={() => void q.refetch()} />}
      {q.isLoading && <SkeletonRows n={3} />}
      {/* NOT built is not the same as nothing found, and the screen must never render the first as the
          second: an empty list under a heading reads as "your graph is clean", which nothing checked. */}
      {q.data && !q.data.evaluated && (
        <>
          <BuildingState what="entity graph" status={q.data.status} />
          <DerivedPauseActions />
        </>
      )}
      {q.data?.evaluated && q.data.findings.length === 0 && (
        <EmptyState
          icon={<Icon.Graph />}
          title="No graph findings"
          body="Every enabled graph rule ran against the current entity graph and none of them matched. Their thresholds are editable in the rule catalogue below."
        />
      )}
      {q.data?.evaluated && q.data.findings.length > 0 && (
        <>
          <div className="anom__toolbar">
            <div className="chip-row">
              <span className="chip-row__label">Severity</span>
              {SEVERITIES.map((s) => {
                const n = counts[s] ?? 0;
                return (
                  <button key={s} type="button" disabled={n === 0}
                    className={cx('chip', sev.includes(s) && 'chip--on')}
                    onClick={() => setSev((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]))}>
                    {s}<span className="chip__count">{n}</span>
                  </button>
                );
              })}
              {sev.length > 0 && <button className="linklike" onClick={() => setSev([])}>clear</button>}
            </div>
          </div>
          <div className="table">
            <div className="table__head gfind-grid">
              <div>Sev</div><div>Rule</div><div>What the graph shows</div><div className="num">Size</div><div />
            </div>
            {rows.map((f) => <GraphFindingRow key={`${f.ruleId}|${f.nodeId}`} f={f} />)}
          </div>
        </>
      )}
    </section>
  );
}

export function AnomaliesScreen() {
  return (
    <div className="page anomalies">
      <AnomaliesSection />
      <GraphFindingsSection />
      <RulesSection />
    </div>
  );
}
