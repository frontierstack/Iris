import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { SEVERITIES, type Event, type EventSort, type EventsHistogram, type FieldFacet, type Severity } from '../api/types';
import { NoteAboutButton } from '../components/CaseNotes';
import { AddToCaseButton } from '../components/CaseSet';
import { FieldQueryNote } from '../components/Enrichment';
import { Icon } from '../components/icons';
import { ErrorState, SevTag, SkeletonRows } from '../components/ui';
import { qk, useCase, useEventFields } from '../hooks/queries';
import { useDebounce } from '../hooks/useDebounce';
import { useHotkey } from '../hooks/useHotkey';
import { Link } from 'react-router-dom';
import { cx, fmtBytes, fmtInt, fmtTs, fromLocalInputValue, toLocalInputValue } from '../utils/format';
import { highlight, queryTerms } from '../utils/highlight';

const PAGE = 200;
type Preset = '1h' | '24h' | '7d' | 'all' | 'custom';
const PRESET_LABEL: Record<Preset, string> = { '1h': 'Last 1h', '24h': 'Last 24h', '7d': 'Last 7d', all: 'All time', custom: 'Custom' };

function presetRange(p: Preset): { from?: string; to?: string } {
  const now = Date.now();
  const h = 3600_000;
  if (p === '1h') return { from: new Date(now - h).toISOString() };
  if (p === '24h') return { from: new Date(now - 24 * h).toISOString() };
  if (p === '7d') return { from: new Date(now - 7 * 24 * h).toISOString() };
  return {};
}

/* ───────────── Query DSL helpers (mirror backend/app/query.py) ─────────────
   `field:value` splits on the first UNESCAPED colon; a backslash makes the next char literal (`\:`, `\ `),
   `\\` is a literal backslash; a quoted value (`field:"a b"`) keeps everything but `\"`. */
const FIELDS_RAIL_KEY = 'iris.search.fields';
const MAX_FIELD_VALUES = 500;   // the endpoint's own ceiling for values-per-field
const FIELDS_LIMIT = 300;
const SAFE_FIELD = /^[\w.\-]+$/;

/** Build one `field:value` term the DSL parses back to exactly this field and value. */
export function dslTerm(field: string, value: string): string {
  const f = field.replace(/([\\:\s()"])/g, '\\$1');
  // whitespace, quotes or parens → quoted (the tokenizer only quotes after a plain [\w.-] field name);
  // a colon (or anything else) → bare with `\:` escaping, the same fix the "no results" tip offers
  if (SAFE_FIELD.test(field) && /[\s"()]/.test(value)) return `${f}:"${value.replace(/"/g, '\\"')}"`;
  return `${f}:${value.replace(/([\\:\s()"])/g, '\\$1')}`;
}

/** Tokens the same way the backend does: parens, field:"quoted", "quoted", bare words with escapes. */
const TOKEN_RX = /\(|\)|[\w.\-]+:"(?:[^"\\]|\\.)*"|"(?:[^"\\]|\\.)*"|(?:\\.|[^\s()])+/g;
function tokens(q: string): string[] {
  return q.match(TOKEN_RX) ?? [];
}
/** Is this term already in the query? A term may be SEVERAL tokens (`NOT user:"svc"`), so this looks for
 *  a consecutive run, not a single token — otherwise every − click appended another copy. */
function hasTerm(q: string, term: string): boolean {
  const want = tokens(term);
  if (want.length <= 1) return tokens(q).includes(term);
  const have = tokens(q);
  return have.some((_, i) => want.every((w, j) => have[i + j] === w));
}
function appendTerm(q: string, term: string): string {
  return hasTerm(q, term) ? q : (q.trim() ? `${q.trim()} ${term}` : term);
}
function removeTerm(q: string, term: string): string {
  const want = tokens(term);
  const have = tokens(q);
  const out: string[] = [];
  for (let i = 0; i < have.length;) {
    if (want.length && want.every((w, j) => have[i + j] === w)) { i += want.length; continue; }
    out.push(have[i]!);
    i++;
  }
  return out.join(' ').replace(/\(\s+/g, '(').replace(/\s+\)/g, ')');
}

/* ───────────── Which fields a raw source can never answer ─────────────
   Two-phase ingest lands a source as RAW LINES first: searchable as text, but with no timestamp, no
   severity and no parsed fields at all (`enrich.raw_events` sets id / file / source / raw / msg and
   nothing else). So `status:200` or `EventID:4625` cannot match one event of an un-interpreted source,
   while free text reaches every line of it — which is why the note this feeds only fires on a
   field-scoped term, and why it is not the workspace banner's job.

   The rule is deliberately conservative and stated rather than guessed:
   * aliases resolve exactly as `query.FIELD_ALIASES` does, so `hostname:` / `username:` / `entity:` /
     `ip:` are recognised as the fields the raw phase leaves empty;
   * the five fields a phase-1 event still carries never raise it;
   * `sev` is raw-safe only for `info` — the placeholder every raw event carries before severity is
     inferred;
   * only POSITIVE atoms count. `NOT status:200` matches every raw event, so it over-includes rather
     than silently omitting, and flagging it would be noise.
   Where the client cannot decide — a field name inside parentheses under a NOT — it errs towards
   SHOWING the note: an omission the analyst cannot see is the failure this whole surface exists for. */
const FIELD_ALIASES: Record<string, string> = {
  severity: 'sev', level: 'sev', src: 'source', parser: 'source', hostname: 'host', username: 'user',
  message: 'msg', text: 'msg', raw: 'raw', ip: '_ip', entity: '_entity',
};
/** Fields a phase-1 event still carries, so a query on them reaches a raw source unchanged. */
const RAW_SAFE_FIELDS = new Set(['msg', 'raw', 'file', 'source', 'id']);

/** Drop one level of backslash escaping — the mirror of `query.unescape`. */
function unescapeDsl(s: string): string {
  if (!s.includes('\\')) return s;
  let out = '';
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '\\' && i + 1 < s.length) { out += s[i + 1]; i++; } else out += s[i]!;
  }
  return out;
}

/** Split on the first UNESCAPED colon, or null when the term is plain text — mirrors `query.split_field`
 *  (a leading colon is not a field either). */
function splitFieldTerm(text: string): [string, string] | null {
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '\\') { i++; continue; }
    if (text[i] === ':') return i === 0 ? null : [text.slice(0, i), text.slice(i + 1)];
  }
  return null;
}

/** Left-hand sides that are almost never a field name: an IPv4, a bare number (a clock time), a URL
 *  scheme, or anything holding a slash. `12:30` and `https://x/y` parse as field:value and match
 *  NOTHING — enriched or not — so they are a typo, not incompleteness. The "no results" tip already
 *  offers the `\:` escape for them, and this is the same test so the two can never disagree. */
function looksLikeColonTypo(lhs: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(lhs) || /^\d+$/.test(lhs) || /^https?$/i.test(lhs) || lhs.includes('/');
}

/** The distinct field names this query scopes on that a raw source cannot answer, in the order typed
 *  and with the casing typed (`EventID:`, not `eventid:`) — the note quotes them back as query text. */
export function unqueryableFields(q: string): string[] {
  const toks = tokens(q);
  const seen = new Set<string>();
  const out: string[] = [];
  for (let i = 0; i < toks.length; i++) {
    let t = toks[i]!;
    if (t === '(' || t === ')' || t.startsWith('"')) continue;  // a whole quoted token is free text
    if (/^(AND|OR|NOT)$/i.test(t)) continue;
    let negated = /^NOT$/i.test(toks[i - 1] ?? '');
    if (t.startsWith('-') && t.length > 1) { negated = true; t = t.slice(1); }
    if (negated) continue;
    const parts = splitFieldTerm(t);
    if (!parts) continue;
    const typed = unescapeDsl(parts[0]);
    if (looksLikeColonTypo(typed)) continue;
    const key = typed.toLowerCase();
    const field = FIELD_ALIASES[key] ?? key;
    if (RAW_SAFE_FIELDS.has(field)) continue;
    if (field === 'sev') {
      const vals = unescapeDsl(parts[1]).replace(/^"|"$/g, '').toLowerCase().split(',');
      if (vals.every((v) => v === 'info')) continue;
    }
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(typed);
  }
  return out;
}

/* ───────────── Columns ─────────────
   The result table used to be seven fixed columns, and the one an analyst wants is often a parsed field
   that had nowhere to go (status, src_ip, EventID…). Columns are now chosen — built-ins plus ANY parsed
   field — and the choice is remembered. The message column shows the RAW line by default: the normalized
   `msg` is a summary, and when you are reading a log you want the log. */
type ColKey = string;
interface ColDef { key: ColKey; label: string; width: string; kind: 'ts' | 'file' | 'sev' | 'text' | 'field' | 'raw' | 'msg' | 'actions' }

const BUILTIN_COLS: ColDef[] = [
  { key: 'ts', label: 'Timestamp', width: '150px', kind: 'ts' },
  { key: 'file', label: 'File', width: 'minmax(160px, 1.1fr)', kind: 'file' },
  { key: 'host', label: 'Host', width: 'minmax(90px, 0.7fr)', kind: 'text' },
  { key: 'user', label: 'Principal', width: 'minmax(96px, 0.8fr)', kind: 'text' },
  { key: 'raw', label: 'Message (raw)', width: 'minmax(240px, 3fr)', kind: 'raw' },
  { key: 'msg', label: 'Message (normalized)', width: 'minmax(220px, 2fr)', kind: 'msg' },
  { key: 'source', label: 'Parser', width: 'minmax(84px, 0.6fr)', kind: 'text' },
  { key: 'id', label: 'Event id', width: '96px', kind: 'text' },
  { key: 'sev', label: 'Sev', width: '84px', kind: 'sev' },
];
/* The template's row, in its order: a severity dot, the time, the level, the thing it came from,
   then the line. Host and principal are still one click away in Columns — they were in the default
   set and pushed the message, which is the row's headline, into the last third of the width. */
const DEFAULT_COLS: ColKey[] = ['ts', 'sev', 'file', 'raw'];
const COLS_KEY = 'iris.search.columns';

function readCols(): ColKey[] {
  try {
    const raw = localStorage.getItem(COLS_KEY);
    if (!raw) return DEFAULT_COLS;
    const v = JSON.parse(raw) as unknown;
    return Array.isArray(v) && v.length ? (v as ColKey[]) : DEFAULT_COLS;
  } catch { return DEFAULT_COLS; }
}

function colDef(key: ColKey): ColDef {
  return BUILTIN_COLS.find((c) => c.key === key)
    ?? { key, label: key, width: 'minmax(90px, 0.8fr)', kind: 'field' };
}

/** The value a column shows for one event — parsed fields fall through to `fields`. */
function cellValue(e: Event, col: ColDef): string {
  switch (col.kind) {
    case 'ts': return e.ts ?? '';
    case 'file': return e.file ?? '';
    case 'sev': return e.sev;
    case 'raw': return e.raw || e.msg || '';
    case 'msg': return e.msg || '';
    default: {
      const direct = (e as unknown as Record<string, unknown>)[col.key];
      if (typeof direct === 'string') return direct;
      return e.fields?.[col.key] ?? '';
    }
  }
}

/** `field:value` for a cell, escaped so a colon or a space in the value cannot re-split the term. */
function termFor(col: ColDef, value: string): string {
  const field = col.kind === 'file' ? 'file' : col.key;
  return `${field}:${quoteValue(value)}`;
}
function quoteValue(v: string): string {
  const esc = v.split('\\').join('\\\\').split('"').join('\\"');
  return /[\s:()"]/.test(v) ? `"${esc}"` : esc;
}

/** The + / − that turn any cell into a filter. Include appends `field:value`, exclude appends
 *  `NOT field:value` — the two questions an analyst asks of a value they can see ("only these" and
 *  "everything but these"), which previously meant typing the query by hand. */
function FilterPins({ term, onAppend }: { term: string; onAppend: (t: string) => void }) {
  return (
    <span className="pins" onClick={(e) => e.stopPropagation()}>
      <button className="pin pin--in" title={`Only events where ${term}`} aria-label={`Include ${term}`}
        onClick={() => onAppend(term)}>+</button>
      <button className="pin pin--out" title={`Exclude events where ${term}`} aria-label={`Exclude ${term}`}
        onClick={() => onAppend(`NOT ${term}`)}>−</button>
    </span>
  );
}

/* ───────────── Fields rail ───────────── */
function FieldsRail({ params, query, onAppend, onRemove, onClose }: {
  params: { q: string; sources: string[]; sev: Severity[]; from?: string; to?: string };
  query: string;
  onAppend: (term: string) => void;
  onRemove: (term: string) => void;
  onClose: () => void;
}) {
  const [filter, setFilter] = useState('');
  const [open, setOpen] = useState<Set<string>>(() => new Set());
  // How many VALUES each field offers. Eight is the right default for a rail, and exactly wrong for
  // `source` on a workspace with hundreds of logs: eight of them, with the rest behind a count, reads
  // as "these are the sources you can pick". One click asks the server for the rest.
  const [valueCap, setValueCap] = useState(8);
  const facets = useEventFields({ q: params.q, sources: params.sources, sev: params.sev, from: params.from,
                                  to: params.to, limit: FIELDS_LIMIT, values: valueCap });

  const active = useMemo(() => {
    // field:value terms currently in the query — shown as removable chips
    return tokens(query).filter((t) => !t.startsWith('"') && !t.startsWith('-') && !t.startsWith('(') && !t.startsWith(')') && /^(?:\\.|[^:\\])+:/.test(t) && !/^(AND|OR|NOT)$/i.test(t));
  }, [query]);

  const list = useMemo(() => {
    const all = facets.data?.fields ?? [];
    const f = filter.trim().toLowerCase();
    return f ? all.filter((x) => x.name.toLowerCase().includes(f)) : all;
  }, [facets.data, filter]);

  const toggle = (name: string) => setOpen((s) => {
    const n = new Set(s);
    if (n.has(name)) n.delete(name); else n.add(name);
    return n;
  });

  return (
    <aside className="fields-rail" aria-label="Fields">
      <div className="fields-rail__head">
        <span className="fields-rail__title">Fields</span>
        <span className="fields-rail__meta">
          {facets.data ? `${fmtInt(facets.data.total)}${facets.data.sampled ? ' · sampled' : ''}` : facets.isLoading ? '…' : ''}
        </span>
        <button className="close-x" onClick={onClose} aria-label="Hide fields" title="Hide fields">×</button>
      </div>
      <div className="fields-rail__filter">
        <Icon.Search width={12} height={12} />
        <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter fields" aria-label="Filter fields" spellCheck={false} autoComplete="off" />
        {filter && <button className="close-x" onClick={() => setFilter('')} aria-label="Clear field filter">×</button>}
      </div>
      {active.length > 0 && (
        <div className="fields-rail__active">
          {active.map((t) => (
            <span key={t} className="fields-chip" title={t}>
              <span className="fields-chip__text">{t}</span>
              <button className="fields-chip__x" onClick={() => onRemove(t)} aria-label={`Remove ${t}`} title="Remove from query">×</button>
            </span>
          ))}
        </div>
      )}
      <div className="fields-rail__list">
        {facets.isLoading && <div className="fields-rail__empty">Loading fields…</div>}
        {facets.isError && <div className="fields-rail__empty">Could not load fields.</div>}
        {facets.data && list.length === 0 && <div className="fields-rail__empty">{filter ? 'No field matches the filter.' : 'No fields in this result set.'}</div>}
        {list.map((f) => (
          <FieldRow key={f.name} facet={f} open={open.has(f.name)} onToggle={() => toggle(f.name)} query={query}
            onAppend={onAppend} onRemove={onRemove}
            onShowAll={valueCap < MAX_FIELD_VALUES ? () => setValueCap(MAX_FIELD_VALUES) : undefined} />
        ))}
      </div>
      {facets.data?.sampled && (
        <div className="fields-rail__note">Counts are over the first {fmtInt(facets.data.scanned)} of {fmtInt(facets.data.events)} matches.</div>
      )}
    </aside>
  );
}

function FieldRow({ facet, open, onToggle, query, onAppend, onRemove, onShowAll }: {
  facet: FieldFacet; open: boolean; onToggle: () => void; query: string; onAppend: (t: string) => void;
  onRemove: (t: string) => void; onShowAll?: () => void;
}) {
  return (
    <div className={cx('field-row', open && 'open')}>
      <button className="field-row__head" onClick={onToggle} aria-expanded={open} title={facet.sample.length ? `e.g. ${facet.sample.slice(0, 3).join(' · ')}` : facet.name}>
        <Icon.Chevron width={10} height={10} className="field-row__chev" />
        <span className="field-row__name">{facet.name}</span>
        <span className="field-row__count">{fmtInt(facet.count)}</span>
      </button>
      {open && (
        <div className="field-row__values">
          {facet.topValues.length === 0 && <div className="fields-rail__empty">no values</div>}
          {facet.topValues.map((tv) => {
            const term = dslTerm(facet.name, tv.value);
            const on = hasTerm(query, term);
            const off = hasTerm(query, `NOT ${term}`) || hasTerm(query, `-${term}`);
              // The 3px meter under a value is driven from here: CSS cannot derive a ratio, and an
              // always-empty track under every value would read as "0 %" — a claim about the data
              // that nothing supports. `--val-pct` is this value's share of the field's own events.
              const pct = facet.count ? Math.max(1, Math.round((tv.count / facet.count) * 100)) : 0;
              return (
              <div key={tv.value} className={cx('field-val', on && 'on', off && 'off')}
                style={{ ['--val-pct' as string]: `${pct}%`, ['--val-on' as string]: on ? 1 : 0 }}
                title={`${tv.value} — ${fmtInt(tv.count)} of ${fmtInt(facet.count)} (${pct}%)`}>
                <button className="field-val__btn" onClick={() => (on ? onRemove(term) : onAppend(term))} title={on ? `Remove ${term} from the query` : `Add ${term} to the query`} aria-pressed={on}>
                  <span className="field-val__text">{tv.value}</span>
                  <span className="field-val__count">{fmtInt(tv.count)}</span>
                </button>
                {/* Same two questions as a result cell: only these, or everything but these. Clicking the
                    value includes it; the − excludes it without having to type NOT by hand. */}
                <span className="pins">
                  <button className="pin pin--in" title={on ? `Remove ${term}` : `Narrow to ${term}`}
                    aria-label={on ? `Stop narrowing to ${term}` : `Narrow to ${term}`} aria-pressed={on}
                    onClick={() => (on ? onRemove(term) : onAppend(term))}>+</button>
                  <button className="pin pin--out" title={off ? `Remove NOT ${term}` : `Exclude ${term}`}
                    aria-label={off ? `Stop excluding ${term}` : `Exclude ${term}`} aria-pressed={off}
                    onClick={() => (off ? onRemove(`NOT ${term}`) : onAppend(`NOT ${term}`))}>−</button>
                </span>
                {on && <button className="field-val__x" onClick={() => onRemove(term)} aria-label={`Remove ${term}`}>×</button>}
              </div>
            );
          })}
          {facet.distinct > facet.topValues.length && (
            onShowAll
              ? <button className="field-row__more field-row__more--btn" onClick={onShowAll}>
                  show all {fmtInt(facet.distinct)} value{facet.distinct === 1 ? '' : 's'}
                </button>
              : <div className="field-row__more">{fmtInt(facet.distinct - facet.topValues.length)} more distinct value{facet.distinct - facet.topValues.length === 1 ? '' : 's'}</div>
          )}
        </div>
      )}
    </div>
  );
}

/* ───────────── The histogram above the result list ─────────────
   The defining element of a log console: the query's own shape in time, so "when did this start"
   is answered before a single row is read. It is a SEPARATE request from the page of rows
   (`GET /api/events/histogram`) because it describes every match, not the 200 rows on screen — a
   chart drawn from the page would describe the page.

   Two things it will not do, both of which would be a picture of evidence that does not exist:
   * it never presents a partial read as the whole picture. The backend bounds how many matches it
     will walk; when it stopped early, `exact` is false and the caption says how many it read.
   * an event with no parsed timestamp is never placed in a bucket. Two-phase ingest lands a source
     as raw lines with no time at all, and inventing one would draw a spike where the log is silent.
     They are counted beside the chart instead. */
const HISTO_H = 118;
const HISTO_W = 1000;
/** Bottom to top, least severe first — so the level that matters is the one on the skyline. */
const STACK: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

function bucketLabel(sec: number): string {
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.round(sec / 60)}m`;
  if (sec < 86400) return `${Math.round(sec / 3600)}h`;
  return `${Math.round(sec / 86400)}d`;
}
/** hh:mm for a same-day window, else a date — a chronology is read by day first. */
function tickLabel(iso: string, spanSec: number): string {
  const t = iso.slice(11, 16);
  return spanSec > 86400 ? iso.slice(5, 10) : t;
}

function SearchHistogram({ h, loading }: { h?: EventsHistogram; loading: boolean }) {
  const view = useMemo(() => {
    if (!h || h.buckets.length === 0) return null;
    const idx = new Map(h.levels.map((l, i) => [l, i]));
    const peak = Math.max(1, h.peak);
    // A round ceiling, so the axis reads 40 / 20 / 0 rather than 37 / 18.5 / 0.
    const step = Math.pow(10, Math.max(0, Math.floor(Math.log10(peak)) - 1));
    const yMax = Math.max(step, Math.ceil(peak / step) * step);
    const n = h.buckets.length;
    const slot = HISTO_W / n;
    const w = Math.max(1, slot * 0.62);
    const bars = h.buckets.map((b, i) => {
      const segs: { sev: Severity; y: number; h: number }[] = [];
      let acc = 0;
      for (const sev of STACK) {
        const cnt = b.levels[idx.get(sev) ?? -1] ?? 0;
        if (!cnt) continue;
        const hh = (cnt / yMax) * HISTO_H;
        acc += hh;
        segs.push({ sev, y: HISTO_H - acc, h: hh });
      }
      return { key: b.start, x: i * slot + (slot - w) / 2, w, segs, b };
    });
    const span = h.start && h.end ? (Date.parse(h.end) - Date.parse(h.start)) / 1000 : 0;
    const present = STACK.filter((s) => h.buckets.some((b) => (b.levels[idx.get(s) ?? -1] ?? 0) > 0));
    // Six evenly spaced ticks read off the buckets themselves, so a label always names a real edge.
    const ticks = Array.from({ length: Math.min(6, n) }, (_, k) =>
      h.buckets[Math.round((k * (n - 1)) / Math.max(1, Math.min(6, n) - 1))]!.start);
    return { bars, yMax, span, present, ticks };
  }, [h]);

  const alarming = h ? h.levels.reduce((sum, lvl, i) =>
    sum + (lvl === 'critical' || lvl === 'high' ? h.buckets.reduce((s, b) => s + (b.levels[i] ?? 0), 0) : 0), 0) : 0;
  const rate = h && h.counted ? (alarming / h.counted) * 100 : 0;

  return (
    <div className="histo">
      <div className="histo__head">
        <div className="histo__figs">
          <span className="histo__total num">{h ? fmtInt(h.total) : '—'}{h && !h.exact ? '+' : ''}</span>
          <span className="histo__label">event{h?.total === 1 ? '' : 's'} matched</span>
          {alarming > 0 && (
            <span className="histo__rate num" title={`${fmtInt(alarming)} of the matches are critical or high`}>
              {rate < 0.1 ? '<0.1' : rate.toFixed(1)}% critical or high
            </span>
          )}
          {!!h?.withoutTimestamp && (
            <span className="histo__undated" title="These events have no parsed timestamp — a source that is still raw lines has none. They are counted here rather than placed in a bucket they cannot support.">
              {fmtInt(h.withoutTimestamp)} undated
            </span>
          )}
        </div>
        <div className="histo__legend">
          {(view?.present ?? []).map((s) => (
            <span key={s} className="histo__key"><i style={{ background: `var(--sev-${s})` }} />{s}</span>
          ))}
          {h && view && <span className="histo__bucket">{bucketLabel(h.bucketSec)} buckets</span>}
        </div>
      </div>

      <div className="histo__plot">
        <svg viewBox={`0 0 ${HISTO_W} ${HISTO_H}`} preserveAspectRatio="none" role="img"
          aria-label={h ? `${fmtInt(h.total)} events over ${view ? view.bars.length : 0} time buckets` : 'no data'}>
          {[0.5, HISTO_H / 3, (HISTO_H / 3) * 2, HISTO_H - 0.5].map((y, i) => (
            <line key={y} x1="0" y1={y} x2={HISTO_W} y2={y} vectorEffect="non-scaling-stroke"
              className={i === 3 ? 'histo__axis' : 'histo__grid'} />
          ))}
          {view?.bars.map((bar) => (
            <g key={bar.key}>
              <title>{`${bar.b.start} · ${fmtInt(bar.b.count)} events`}</title>
              {bar.segs.map((s) => (
                <rect key={s.sev} x={bar.x} y={s.y} width={bar.w} height={s.h} fill={`var(--sev-${s.sev})`}
                  opacity={s.sev === 'info' ? 0.62 : 1} />
              ))}
            </g>
          ))}
        </svg>
        <div className="histo__y">
          <span className="num">{view ? fmtInt(view.yMax) : ''}</span>
          <span className="num">{view ? fmtInt(Math.round(view.yMax / 2)) : ''}</span>
          <span className="num">{view ? '0' : ''}</span>
        </div>
        {!view && (
          <div className="histo__empty">
            {loading ? 'reading the matches…' : h?.withoutTimestamp ? 'none of these events carries a parsed timestamp' : 'nothing to plot'}
          </div>
        )}
      </div>

      <div className="histo__ticks">
        {(view?.ticks ?? []).map((t, i) => <span key={`${t}-${i}`} className="num">{tickLabel(t, view!.span)}</span>)}
      </div>
      {h && !h.exact && (
        <div className="histo__partial">
          Shape read from the first {fmtInt(h.counted)} of {fmtInt(h.total)}+ matches — narrow the query or the range for the whole picture.
        </div>
      )}
    </div>
  );
}

/* ───────────── Which logs to search ─────────────
   The chips were two wrapped rows above the results and pushed them below the fold on every load.
   This is the same control as one menu: what is selected is stated on the button, so the row you act
   in stays one row. Every chip, its event count, the ERROR marking and the clear are unchanged. */
function SourcePicker({ all, picked, onToggle, onClear }: {
  all: { id: string; label: string; parser: string; events: number; state: string }[];
  picked: string[];
  onToggle: (id: string) => void;
  onClear: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [filter, setFilter] = useState('');
  const list = useMemo(() => {
    const f = filter.trim().toLowerCase();
    return f ? all.filter((s) => s.label.toLowerCase().includes(f) || s.parser.toLowerCase().includes(f)) : all;
  }, [all, filter]);
  const label = picked.length === 0
    ? `all (${fmtInt(all.length)})`
    : picked.length === 1
      ? (all.find((s) => s.id === picked[0])?.label ?? picked[0]!)
      : `${picked.length} of ${fmtInt(all.length)}`;

  return (
    <div className="srcpick">
      <button className={cx('srcpick__btn', open && 'open', picked.length > 0 && 'on')} onClick={() => setOpen((o) => !o)}
        aria-haspopup="menu" aria-expanded={open} title="Which logs this query reads">
        <span className="srcpick__k">source</span>
        <span className="srcpick__v num">{label}</span>
        <Icon.Chevron className="srcpick__caret" />
      </button>
      {open && (
        <>
          <div className="srccase__scrim" onClick={() => setOpen(false)} aria-hidden />
          <div className="srcpick__menu" role="menu">
            <div className="srcpick__head">
              <span className="lbl">Sources</span>
              {picked.length > 0 && <button className="btn btn--sm btn--ghost" onClick={onClear}>clear</button>}
            </div>
            <div className="srcpick__filter">
              <Icon.Search width={12} height={12} />
              <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter files"
                aria-label="Filter sources" spellCheck={false} autoComplete="off" />
            </div>
            <div className="srcpick__list">
              {all.length === 0 && <div className="srcpick__empty">Nothing ingested yet.</div>}
              {all.length > 0 && list.length === 0 && <div className="srcpick__empty">No file matches the filter.</div>}
              {list.map((s) => {
                const on = picked.includes(s.id);
                return (
                  <label key={s.id} className={cx('srcpick__row', on && 'on', s.state === 'ERROR' && 'bad')}
                    title={s.parser ? `${s.parser} · ${fmtInt(s.events)} events` : undefined}>
                    <input type="checkbox" checked={on} onChange={() => onToggle(s.id)} />
                    <span className="ellipsis">{s.label}</span>
                    <span className="srcpick__n num">{s.events > 0 ? fmtInt(s.events) : ''}</span>
                  </label>
                );
              })}
            </div>
            <div className="srcpick__foot">
              {picked.length === 0 ? 'Every ingested log is searched.' : `${picked.length} selected — the rest are excluded.`}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

/** Severity as ONE segmented control: a filter has one answer, and four loose pills read as four
 *  independent buttons. Multi-select is still multi-select — the segments are toggles inside one box. */
function SevSegs({ picked, onToggle }: { picked: Severity[]; onToggle: (s: Severity) => void }) {
  return (
    <div className="segbar" role="group" aria-label="Severity">
      {SEVERITIES.map((s) => (
        <button key={s} type="button" className={cx('seg', picked.includes(s) && 'seg--on')} onClick={() => onToggle(s)} aria-pressed={picked.includes(s)}>
          <span className="seg__dot" style={{ background: `var(--sev-${s})` }} aria-hidden />
          <span className="seg__label">{s}</span>
        </button>
      ))}
    </div>
  );
}

export function SearchScreen() {
  const [sp, setSp] = useSearchParams();
  const nav = useNavigate();
  const c = useCase();
  const inputRef = useRef<HTMLInputElement>(null);

  const [q, setQ] = useState(sp.get('q') ?? '');
  const [submitted, setSubmitted] = useState(sp.get('q') ?? '');
  const debounced = useDebounce(q, 350);
  // Same rule as the graph: the URL wins when it names sources, else the last selection on this browser.
  // A source chip that unticks itself on every navigation is a chip nobody trusts.
  const [sources, setSourcesState] = useState<string[]>(() => {
    const fromUrl = (sp.get('sources') ?? '').split(',').filter(Boolean);
    if (fromUrl.length) return fromUrl;
    try { return JSON.parse(localStorage.getItem('iris.search.sources') ?? '[]') as string[]; } catch { return []; }
  });
  const setSources = useCallback((next: string[] | ((cur: string[]) => string[])) => {
    setSourcesState((cur) => {
      const v = typeof next === 'function' ? next(cur) : next;
      try { localStorage.setItem('iris.search.sources', JSON.stringify(v)); } catch { /* private mode */ }
      return v;
    });
  }, []);
  const [sevs, setSevs] = useState<Severity[]>(() => (sp.get('sev') ?? '').split(',').filter((s): s is Severity => (SEVERITIES as string[]).includes(s)));
  const [preset, setPreset] = useState<Preset>(() => (sp.get('range') as Preset | null) ?? 'all');
  const [from, setFrom] = useState(sp.get('from') ?? '');
  const [to, setTo] = useState(sp.get('to') ?? '');
  const [sort, setSort] = useState<EventSort>(() => (sp.get('sort') === 'ts_asc' ? 'ts_asc' : 'ts_desc'));
  const [rangeOpen, setRangeOpen] = useState(false);
  const [cols, setCols] = useState<ColKey[]>(readCols);
  const [colsOpen, setColsOpen] = useState(false);
  const setColumns = useCallback((next: ColKey[]) => {
    setCols(next);
    try { localStorage.setItem(COLS_KEY, JSON.stringify(next)); } catch { /* private mode */ }
  }, []);
  const rangeRef = useRef<HTMLDivElement>(null);
  const [railOpen, setRailOpen] = useState<boolean>(() => {
    try { return localStorage.getItem(FIELDS_RAIL_KEY) !== '0'; } catch { return true; }
  });
  useEffect(() => {
    try { localStorage.setItem(FIELDS_RAIL_KEY, railOpen ? '1' : '0'); } catch { /* private mode */ }
  }, [railOpen]);
  // rail clicks apply immediately (no debounce): the user asked for a filter, not a keystroke
  const applyQuery = useCallback((next: string) => { setQ(next); setSubmitted(next); }, []);
  const appendToQuery = useCallback((term: string) => applyQuery(appendTerm(submitted, term)), [applyQuery, submitted]);
  const removeFromQuery = useCallback((term: string) => applyQuery(removeTerm(submitted, term)), [applyQuery, submitted]);

  useEffect(() => setSubmitted(debounced), [debounced]);

  // sync to URL
  useEffect(() => {
    const p = new URLSearchParams();
    if (submitted) p.set('q', submitted);
    if (sources.length) p.set('sources', sources.join(','));
    if (sevs.length) p.set('sev', sevs.join(','));
    if (preset !== 'all') p.set('range', preset);
    if (sort !== 'ts_desc') p.set('sort', sort);
    if (preset === 'custom') {
      if (from) p.set('from', from);
      if (to) p.set('to', to);
    }
    setSp(p, { replace: true });
  }, [submitted, sources, sevs, preset, from, to, sort, setSp]);

  useHotkey('/', (e) => {
    e.preventDefault();
    inputRef.current?.focus();
    inputRef.current?.select();
  });

  useEffect(() => {
    if (!rangeOpen) return;
    const on = (e: MouseEvent) => {
      if (rangeRef.current && !rangeRef.current.contains(e.target as Node)) setRangeOpen(false);
    };
    const key = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setRangeOpen(false);
    };
    document.addEventListener('mousedown', on);
    window.addEventListener('keydown', key);
    return () => {
      document.removeEventListener('mousedown', on);
      window.removeEventListener('keydown', key);
    };
  }, [rangeOpen]);

  const range = useMemo(() => (preset === 'custom' ? { from: from || undefined, to: to || undefined } : presetRange(preset)), [preset, from, to]);
  const params = useMemo(() => ({ q: submitted, sources, sev: sevs, from: range.from, to: range.to, sort }), [submitted, sources, sevs, range, sort]);

  // terms come from the SUBMITTED query, so highlights match the rows actually on screen
  const terms = useMemo(() => queryTerms(submitted), [submitted]);
  // the fields this query scopes on that a still-raw source has no value for (see unqueryableFields)
  const unreachableFields = useMemo(() => unqueryableFields(submitted), [submitted]);
  /**
   * A term like `10.0.0.9:3001` or `12:30` parses as field:value and matches nothing, which reads as
   * "no results" rather than "wrong syntax". Detect the shapes that are almost never field names —
   * an IPv4, a bare number (clock time), a URL scheme, or anything with a slash — and offer the escape.
   */
  const colonTypoTerm = useMemo(() => {
    if (!submitted.includes(':')) return null;
    return submitted.trim().split(/\s+/).find((t) => {
      if (t.startsWith('"') || t.includes('\\:')) return false; // quoted or already escaped
      const i = t.indexOf(':');
      if (i <= 0) return false;
      return looksLikeColonTypo(t.slice(0, i));
    }) ?? null;
  }, [submitted]);

  // The chart's own request. It describes every match, so it cannot be derived from the page of
  // rows below it; `placeholderData` keeps the previous shape on screen while a new one is read,
  // which is what stops the panel collapsing to zero height on every keystroke.
  const histogram = useQuery({
    queryKey: qk.eventsHistogram(params),
    queryFn: () => api.eventsHistogram({ ...params, buckets: 56 }),
    placeholderData: (prev) => prev,
  });

  const query = useInfiniteQuery({
    queryKey: qk.events(params),
    queryFn: ({ pageParam }) => api.events({ ...params, limit: PAGE, offset: pageParam }),
    initialPageParam: 0,
    getNextPageParam: (last, pages) => {
      const loaded = pages.reduce((n, p) => n + p.rows.length, 0);
      return loaded < last.total && last.rows.length > 0 ? loaded : undefined;
    },
    placeholderData: (prev) => prev,
  });

  const rows: Event[] = useMemo(() => query.data?.pages.flatMap((p) => p.rows) ?? [], [query.data]);
  const total = query.data?.pages[0]?.total ?? 0;
  // A floor, not a total: while the index is still building the scan stops counting once it has the
  // page plus a margin (counting every match took minutes on a large pool). Shown as "10,000+", never
  // as a bare number that reads exact.
  const totalExact = query.data?.pages[0]?.totalExact !== false;
  const engine = query.data?.pages[0]?.engine;
  const tookMs = query.data?.pages[0]?.tookMs;
  const indexState = query.data?.pages[0]?.index;

  // Source chips = the files actually ingested into the case (from /api/case), never a hard-coded list.
  // Filter value is the source id (the API matches sourceId, family or file name).
  const chipSources = useMemo(() => {
    // every source in the workspace pool, case-filed or not — search spans all of them by default
    const list = [...(c.data?.sources ?? []), ...(c.data?.librarySources ?? [])]
      .map((src) => ({ id: src.id, label: src.file, parser: src.parser, events: src.events, state: src.state }));
    list.sort((a, b) => a.label.localeCompare(b.label));
    // keep any selected value that is no longer in the case visible so it can be cleared
    for (const x of sources) if (!list.some((l) => l.id === x)) list.push({ id: x, label: x, parser: '', events: 0, state: 'READY' });
    return list;
  }, [c.data, sources]);

  const toggleSource = (s: string) => setSources((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]));
  const toggleSev = (s: Severity) => setSevs((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]));

  const rangeLabel = preset === 'custom' ? `${from ? fmtTs(from).slice(0, 16) : '…'} → ${to ? fmtTs(to).slice(0, 16) : '…'}` : PRESET_LABEL[preset];

  const onKey = useCallback(
    (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === 'Enter') setSubmitted(q);
      if (e.key === 'Escape') {
        setQ('');
        setSubmitted('');
      }
    },
    [q],
  );

  const sentinelRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = sentinelRef.current;
    if (!el || !query.hasNextPage) return;
    const io = new IntersectionObserver((entries) => {
      if (entries.some((e) => e.isIntersecting) && !query.isFetchingNextPage) void query.fetchNextPage();
    });
    io.observe(el);
    return () => io.disconnect();
  }, [query.hasNextPage, query.isFetchingNextPage, query.fetchNextPage, query]);

  const activeFilters = sources.length + sevs.length + (preset !== 'all' || from || to ? 1 : 0);
  const clearFilters = () => { setSources([]); setSevs([]); setFrom(''); setTo(''); setPreset('all'); };
  const fieldFacets = useEventFields({ q: submitted, sources, sev: sevs, from: range.from, to: range.to, limit: 40 });
  const parsedFieldNames = useMemo(
    () => (fieldFacets.data?.fields ?? []).map((f) => f.name).filter((f) => !BUILTIN_COLS.some((c) => c.key === f)),
    [fieldFacets.data]);
  const colDefs = useMemo(() => cols.map(colDef), [cols]);
  // the grid is built from the chosen columns; the trailing 84px is the per-row case/note actions
  // The leading 22px column is the template's severity dot, and the trailing 84px is the row's
  // case/note actions.
  const gridStyle = useMemo(
    () => ({ gridTemplateColumns: `22px ${colDefs.map((c) => c.width).join(' ')} 84px` }) as React.CSSProperties,
    [colDefs]);

  return (
    <div className="page search">
      {/* THE ROW YOU ACT IN. Scope, then the thing you type in, then the primary action - and
          nothing else, so the query box is never the busiest element on the page. The source chips
          used to be two wrapped rows here and pushed the results below the fold on every load. */}
      <div className="qbar">
        <SourcePicker all={chipSources} picked={sources} onToggle={toggleSource} onClear={() => setSources([])} />
        <div className="qbox">
          {/* The template's search mark is a ring, drawn at the same weight as the nav glyphs. */}
          <span className="qbox__icon" aria-hidden />
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={onKey}
            placeholder="user:svc_deploy AND src_ip:45.83.140.22"
            aria-label="Search events"
            spellCheck={false}
            autoComplete="off"
          />
          {q && (
            <button className="qbox__clear" onClick={() => { setQ(''); inputRef.current?.focus(); }}
              aria-label="Clear the query" title="Clear">×</button>
          )}
          <span className="kbd" title="Press / to focus">/</span>
        </div>
        <button className="btn btn--lg btn--primary" onClick={() => setSubmitted(q)} title="Run this query now (Enter)">Run</button>
        <div className="search__cols">
          <button className={cx('btn btn--lg', colsOpen && 'btn--accent')} onClick={() => setColsOpen((v) => !v)}
            aria-expanded={colsOpen} title="Choose which columns this table shows">
            <Icon.Sliders />Columns <span className="chip__count">{cols.length}</span>
          </button>
          {colsOpen && (
            <>
              <div className="srccase__scrim" onClick={() => setColsOpen(false)} aria-hidden />
              <div className="search__colmenu" role="menu">
                <div className="search__colmenu-head">
                  <span className="lbl">Columns</span>
                  <button className="btn btn--sm btn--ghost" onClick={() => setColumns(DEFAULT_COLS)}>reset</button>
                </div>
                <div className="search__collist">
                  {BUILTIN_COLS.map((c) => {
                    const on = cols.includes(c.key);
                    return (
                      <label key={c.key} className={cx('search__colrow', on && 'on')}>
                        <input type="checkbox" checked={on}
                          onChange={() => setColumns(on ? cols.filter((k) => k !== c.key) : [...cols, c.key])} />
                        <span className="ellipsis">{c.label}</span>
                      </label>
                    );
                  })}
                  {/* every PARSED field is a possible column — that is where status codes, source ips and
                      event ids live, and they had nowhere to go before */}
                  {parsedFieldNames.length > 0 && <div className="search__colsep">parsed fields</div>}
                  {parsedFieldNames.map((f) => {
                    const on = cols.includes(f);
                    return (
                      <label key={f} className={cx('search__colrow', on && 'on')}>
                        <input type="checkbox" checked={on}
                          onChange={() => setColumns(on ? cols.filter((k) => k !== f) : [...cols, f])} />
                        <span className="ellipsis mono">{f}</span>
                      </label>
                    );
                  })}
                </div>
              </div>
            </>
          )}
        </div>
        <button
          className={cx('btn btn--lg btn--icon', railOpen && 'btn--accent')}
          onClick={() => setRailOpen((o) => !o)}
          aria-pressed={railOpen}
          title={railOpen ? 'Hide the fields sidebar' : 'Show the fields sidebar'}
          aria-label={railOpen ? 'Hide fields' : 'Show fields'}
        >
          <Icon.PanelLeft />
        </button>
      </div>

      {/* The scoping strip: what the query is being asked OVER, on one 34px line under the row you
          type in. Severity is one segmented control — a filter has one answer, and four loose pills
          read as four independent buttons. */}
      <div className="qbar qbar--sub">
        <SevSegs picked={sevs} onToggle={toggleSev} />
        <div className="search__range" ref={rangeRef}>
          <button className={cx('qbtn', rangeOpen && 'open')} onClick={() => setRangeOpen((o) => !o)} aria-haspopup="dialog" aria-expanded={rangeOpen}>
            <Icon.Clock width={11} height={11} />
            <span className="num">{rangeLabel}</span>
            <Icon.Chevron className="qbtn__caret" />
          </button>
          {rangeOpen && (
            <div className="range-pop" role="dialog" aria-label="Time range">
              <div className="range-pop__presets">
                {(['1h', '24h', '7d', 'all'] as Preset[]).map((pr) => (
                  <button key={pr} className={cx('chip', preset === pr && 'on')} style={{ justifyContent: 'center' }} onClick={() => { setPreset(pr); setRangeOpen(false); }}>
                    {PRESET_LABEL[pr]}
                  </button>
                ))}
              </div>
              <div className="range-pop__custom">
                <div className="field">
                  <label className="field__label" htmlFor="range-from">From (UTC)</label>
                  <input id="range-from" type="datetime-local" value={toLocalInputValue(from)} onChange={(e) => { setFrom(fromLocalInputValue(e.target.value)); setPreset('custom'); }} />
                </div>
                <div className="field">
                  <label className="field__label" htmlFor="range-to">To (UTC)</label>
                  <input id="range-to" type="datetime-local" value={toLocalInputValue(to)} onChange={(e) => { setTo(fromLocalInputValue(e.target.value)); setPreset('custom'); }} />
                </div>
                <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                  <button className="btn btn--sm btn--ghost" onClick={() => { setFrom(''); setTo(''); setPreset('all'); }}>Clear</button>
                  <button className="btn btn--sm btn--accent" onClick={() => setRangeOpen(false)}>Apply</button>
                </div>
              </div>
            </div>
          )}
        </div>
        <button
          className="qbtn"
          onClick={() => setSort((v) => (v === 'ts_desc' ? 'ts_asc' : 'ts_desc'))}
          title={sort === 'ts_desc' ? 'Newest first — click for oldest first' : 'Oldest first — click for newest first'}
          aria-label={`Sort by timestamp, ${sort === 'ts_desc' ? 'newest' : 'oldest'} first`}
        >
          <Icon.Sort style={{ transform: sort === 'ts_asc' ? 'scaleY(-1)' : undefined }} />
          {sort === 'ts_desc' ? 'Newest' : 'Oldest'}
        </button>
        {activeFilters > 0 && (
          <button className="btn btn--sm btn--ghost" onClick={clearFilters}>
            clear {activeFilters} filter{activeFilters === 1 ? '' : 's'}
          </button>
        )}
        <span className="qbar__gap" />
        {/* A field-scoped query cannot reach a source that is still raw lines. It is the one
            incompleteness that depends on what was TYPED, so it belongs on the row that says what
            the query is being asked over — and never next to the caret. */}
        <FieldQueryNote fields={unreachableFields} sourceIds={sources} />
      </div>

      <div className={cx('search-layout', railOpen && 'with-rail')}>
        <section className="search__main">
          {/* Search is where a missing source does the most damage: an unloaded file looks exactly
              like "no events match". Say it on every result set, not only the empty one. */}
          {(c.data?.poolSkippedFiles.length ?? 0) > 0 && (
            <div className="notloaded notloaded--inline search__notloaded">
              <Icon.Warn />
              <span>
                <b>{fmtInt(c.data!.poolSkippedFiles.length)}</b> source
                {c.data!.poolSkippedFiles.length === 1 ? ' is' : 's are'} not loaded
                ({fmtBytes(c.data!.poolSkippedFiles.reduce((n, s) => n + s.size, 0))}), so these results do NOT
                include them: {c.data!.poolSkippedFiles.map((s) => s.displayName).join(', ')}.{' '}
                <Link to="/ingest">Load them on Sources</Link>.
              </span>
            </div>
          )}

          <SearchHistogram h={histogram.data} loading={histogram.isFetching} />

          {query.isError ? (
            <div className="search__error"><ErrorState title="Search failed" error={query.error} onRetry={() => void query.refetch()} /></div>
          ) : (
            <div className="search__results" style={{ opacity: query.isFetching && !query.isFetchingNextPage && rows.length ? 0.6 : 1, transition: 'opacity var(--t-fast)' }}>
              <div className="table__head results-grid" style={gridStyle}>
                <div />
                {colDefs.map((col) => (col.kind === 'ts' ? (
                  <button key={col.key} className="table__sort" onClick={() => setSort((v) => (v === 'ts_desc' ? 'ts_asc' : 'ts_desc'))} title="Sort by timestamp">
                    {col.label} <span className="table__sort-arrow">{sort === 'ts_desc' ? '↓' : '↑'}</span>
                  </button>
                ) : (
                  <div key={col.key} title={col.kind === 'field' ? `parsed field: ${col.key}` : undefined}>{col.label}</div>
                )))}
                <div title="Add to case · note">Case</div>
              </div>
              <div className="search__rows">
                {query.isLoading && <SkeletonRows n={10} />}
                {!query.isLoading && rows.length === 0 && (
                  <div className="table__empty">
                    {c.data?.poolLoading
                      ? `Still loading ${c.data.poolPending} source${c.data.poolPending === 1 ? '' : 's'} — results will fill in.`
                      : c.data && c.data.poolEventCount === 0 && c.data.poolSkippedFiles.length > 0
                      ? `Nothing is loaded: ${c.data.poolSkippedFiles.length} staged source${c.data.poolSkippedFiles.length === 1 ? '' : 's'} could not be parsed into the workspace, so there is nothing to search yet. Sources → "not loaded" says why.`
                      : c.data && c.data.poolEventCount === 0
                      ? 'Nothing ingested yet — add logs on the Sources page. A case is optional; search works without one.'
                      : <>
                          No events match this query. Try fewer filters or a broader time range.
                          {colonTypoTerm && (
                            <div className="search__tip">
                              <span className="mono">{colonTypoTerm}</span> is being read as <span className="mono">field:value</span>,
                              so it looks for a field named <span className="mono">{colonTypoTerm.slice(0, colonTypoTerm.indexOf(':'))}</span>.
                              To search for the literal text, escape the colon:{' '}
                              <button className="search__tip-fix" onClick={() => { const fixed = submitted.replace(colonTypoTerm, colonTypoTerm.replace(/:/g, '\\:')); setQ(fixed); setSubmitted(fixed); }}>
                                <span className="mono">{colonTypoTerm.replace(/:/g, '\\:')}</span>
                              </button>{' '}
                              or wrap it in quotes.
                            </div>
                          )}
                        </>}
                  </div>
                )}
                {rows.map((e) => (
                  <div key={e.id} className="table__row results-grid clickable" style={{ ['--row-sev' as string]: `var(--sev-${e.sev})`, ...gridStyle }} role="link" tabIndex={0} onClick={() => nav(`/events/${encodeURIComponent(e.id)}`)} onKeyDown={(k) => { if (k.key === 'Enter') nav(`/events/${encodeURIComponent(e.id)}`); }}>
                    {/* The row opens on its severity, the way the template's does. It replaces the
                        left rail rather than joining it: a rail AND a dot AND the level tag would
                        state one fact three times on one line. */}
                    <div className="res__dot" aria-hidden><i style={{ background: `var(--sev-${e.sev})` }} /></div>
                    {colDefs.map((col) => {
                      const v = cellValue(e, col);
                      if (col.kind === 'sev') return <div key={col.key}><SevTag sev={e.sev} /></div>;
                      if (col.kind === 'file') {
                        return (
                          <div key={col.key} className="cell-mono cell-dim ellipsis res__cell" title={`${e.file}  ·  parsed as ${e.source}`}>
                            <span className="res__file">{highlight(e.file, terms)}</span>
                            <span className="res__family">{e.source}</span>
                            <FilterPins term={termFor(col, e.file)} onAppend={appendToQuery} />
                          </div>
                        );
                      }
                      if (col.kind === 'ts') return <div key={col.key} className="cell-mono cell-ts">{fmtTs(e.ts)}</div>;
                      const isMessage = col.kind === 'raw' || col.kind === 'msg';
                      return (
                        <div key={col.key}
                          className={cx('cell-mono ellipsis res__cell', isMessage ? 'cell-msg' : 'cell-small')}
                          title={v || undefined}>
                          {v ? highlight(v, terms) : <span className="muted">—</span>}
                          {isMessage && !!e.labels?.length && <span className="row-labels">{e.labels.map((l) => <span key={l} className="tag tag--label">{l}</span>)}</span>}
                          {!isMessage && v && <FilterPins term={termFor(col, v)} onAppend={appendToQuery} />}
                        </div>
                      );
                    })}
                    <div className="row-actions">
                      <AddToCaseButton event={e} compact />
                      {c.data && <NoteAboutButton caseId={c.data.id} compact refToAttach={{ kind: 'event', value: e.id, label: e.msg.slice(0, 60) }} />}
                    </div>
                  </div>
                ))}
                {query.hasNextPage && (
                  <div className="search__more">
                    <button className="btn" onClick={() => void query.fetchNextPage()} disabled={query.isFetchingNextPage}>
                      {query.isFetchingNextPage && <span className="btn__spinner" />}Load {fmtInt(Math.min(PAGE, Math.max(0, total - rows.length)))} more
                    </button>
                    <div ref={sentinelRef} style={{ width: 1, height: 1 }} />
                  </div>
                )}
              </div>

              {/* The status strip: the quietest text on the screen, stating what the query cost.
                  Never a place to put something the analyst has to act on. */}
              <div className="table__foot search__statusbar">
                <span>
                  {query.isFetching && !query.isFetchingNextPage
                    ? 'searching…'
                    : `${fmtInt(rows.length)} of ${fmtInt(total)}${totalExact ? '' : '+'} loaded`}
                </span>
                {!totalExact && (
                  <span className="search__floor" title="The exact count needs the search index, which is still building — this is at least this many.">
                    count is a floor
                  </span>
                )}
                <span className="qbar__gap" />
                {indexState?.state === 'building' && (
                  <span title="The vectorized search index is still being built; this query used the slower scan. It will speed up once the index is ready.">
                    index warming {Math.round(indexState.pct)}%
                  </span>
                )}
                {engine && (
                  <span title={engine === 'cuda' ? 'Searched on the GPU (vectorized index on CUDA)' : engine === 'vector' ? 'Vectorized search on CPU (numpy)' : 'Sequential scan (small pool)'}>
                    {engine === 'cuda' ? 'cuda' : engine === 'vector' ? 'cpu · vector' : 'cpu'}
                    {tookMs != null ? ` · ${tookMs < 1 ? '<1' : Math.round(tookMs)} ms` : ''}
                  </span>
                )}
              </div>
            </div>
          )}

          <div className="search__note">
            <span>Rows are normalized across every parser — the same fields whether the line came from EVTX XML or an nginx string.</span>
            <span className="search__note-syntax">
              <b>Syntax</b> free text · <span className="mono">field:value</span> · AND / OR / NOT · &quot;quoted phrase&quot; ·{' '}
              <span className="mono">\:</span> for a literal colon (<span className="mono">10.0.0.9\:3001</span>)
            </span>
          </div>
        </section>

        {/* The facet rail is on the RIGHT, after the answer in DOM order as well as on screen. */}
        {railOpen && (
          <FieldsRail
            params={{ q: submitted, sources, sev: sevs, from: range.from, to: range.to }}
            query={submitted}
            onAppend={appendToQuery}
            onRemove={removeFromQuery}
            onClose={() => setRailOpen(false)}
          />
        )}
      </div>
    </div>
  );
}
