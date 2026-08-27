import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback, useEffect, useMemo, useRef, useState, type DragEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import type { Case, EnrichState, MappingSuggestion, ParserInfo, RawLine, Source, SourceState, UploadJob } from '../api/types';
import { Icon } from '../components/icons';
import { ENRICH_META, ENRICH_ORDER, EnrichActions, EnrichChip, enrichOf, useEnrichAll } from '../components/Enrichment';
import { Bar, ConfirmDialog, Drawer, EmptyState, ErrorState, SectionHead, SkeletonRows } from '../components/ui';
import { AddSources } from '../components/AddSources';
import { FloatingWindow } from '../components/FloatingWindow';
import { AutoMapAll } from '../components/AutoMapAll';
import { qk, useCase, useInvalidateCaseData, useLibrary, usePendingMappings, useSettings } from '../hooks/queries';
import { useToast } from '../hooks/useToast';
import { useDebounce } from '../hooks/useDebounce';
import { cx, fmtBytes, fmtEta, fmtInt, fmtRange, fmtRate, fmtSize, fmtTs, pct, totalSize } from '../utils/format';
import { highlight } from '../utils/highlight';

const STATE_PILL: Record<SourceState, string> = { READY: 'pill--ok', REVIEW: 'pill--warn', MAP: 'pill--high', PARSING: 'pill--accent', ERROR: 'pill--bad' };
function confColor(c: number): string {
  if (c >= 0.9) return 'var(--ok)';
  if (c >= 0.85) return 'var(--warn)';
  return 'var(--sev-high)';
}


/* Upload/parse progress lives on the SERVER (GET /api/jobs) so it survives a tab switch, a refresh and a
   second tab; see docs/API_CONTRACT.md → "Upload & parse jobs". The only thing this tab knows better is
   how many bytes it has pushed so far — XHR onprogress — which is merged over the server record below
   and pushed back with PATCH /api/jobs/{id} so other tabs can render it too. */
const JOB_POLL_ACTIVE = 1000;
const JOB_POLL_IDLE = 20_000;
// A job that SUCCEEDED clears itself: the file is parsed and it is in the Sources table below with its
// parser, state and event count, so the transfer row has nothing left to say. This mirrors the
// server's own jobs.READY_RETAIN_SEC (20 s) — the row must not linger here after the server has
// dropped it, or a refresh would make finished transfers reappear and then vanish.
const JOB_DONE_MS = 20_000;
// A FAILURE is the one thing on this panel restated nowhere else in a form the analyst can act on,
// so it stays until it is dismissed. Never auto-clear an error: that is silent loss of the report
// that evidence did not make it into the pool.
const JOB_FAILED_MS = 30 * 60_000;
const JOB_ROWS = 8;
const PROGRESS_PUSH_MS = 900;       // throttle for the bytes-received PATCH
/* How often this tab tells the server which transfers it still owns. Only three files are sent at a
   time, so everything behind them is registered and silent — and the server's watchdog buries a silent
   upload after 10 minutes. That is how a drop of packet captures came back as eight rows reading "the
   upload stopped before the server received the whole file" without one of them having had a turn.
   Well under the watchdog's window, so a single dropped tick is not a bury. */
const HEARTBEAT_MS = 20_000;
const HEARTBEAT_BATCH = 500;        // ids per heartbeat request

/* ───────────── Parser groups ───────────── */
type GroupId = 'logs' | 'documents' | 'images' | 'network' | 'binary' | 'archives';
const GROUPS: { id: GroupId; label: string }[] = [
  { id: 'logs', label: 'Logs' },
  { id: 'documents', label: 'Documents' },
  { id: 'images', label: 'Images (OCR)' },
  { id: 'network', label: 'Network captures' },
  { id: 'binary', label: 'Binary & memory dumps' },
  { id: 'archives', label: 'Archives' },
];
function groupOf(p: ParserInfo): GroupId {
  const t = `${p.family} ${p.name}`.toLowerCase();
  if (/pcap|capture|packet/.test(t)) return 'network';
  if (/ocr|image|tesseract/.test(t)) return 'images';
  if (/archive|zip|gzip|\bgz\b|tar/.test(t)) return 'archives';
  if (/binary|dump|memory|strings|\bmem\b|raw/.test(t)) return 'binary';
  if (/document|pdf|xlsx|xls|docx|word|excel|sheet/.test(t)) return 'documents';
  return 'logs';
}

function SupportedTypes() {
  const q = useQuery({ queryKey: ['parsers'], queryFn: api.parsers, staleTime: 5 * 60_000 });
  const groups = useMemo(() => {
    const m = new Map<GroupId, ParserInfo[]>();
    for (const p of q.data?.parsers ?? []) {
      const g = groupOf(p);
      if (!m.has(g)) m.set(g, []);
      m.get(g)!.push(p);
    }
    return m;
  }, [q.data]);
  if (q.isLoading) return <div className="types types--loading"><span className="skeleton" style={{ width: 240 }} /></div>;
  if (q.isError || !q.data) return null;
  return (
    <div className="types">
      {GROUPS.filter((g) => groups.has(g.id)).map((g) => (
        <div key={g.id} className="types__group">
          <span className="types__label">{g.label}</span>
          <div className="types__chips">
            {groups.get(g.id)!.map((p) => (
              <span
                key={p.name}
                className={cx('chip chip--mono chip--static tip', !p.available && 'off')}
                data-tip={p.available ? `${p.description}${p.extensions.length ? ` · ${p.extensions.join(' ')}` : ''}` : `${p.note ?? 'Unavailable on this server'}${p.description ? ` — ${p.description}` : ''}`}
              >
                {p.name}
                {!p.available && <Icon.Lock width={10} height={10} />}
              </span>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}


/* ───────────── AI suggestion ───────────── */
function SuggestBox({ source, onApply }: { source: Source; onApply: (s: MappingSuggestion) => void }) {
  const settings = useSettings();
  const aiOn = settings.data?.ai.provider === 'openai';
  const [sug, setSug] = useState<MappingSuggestion | null>(null);
  const mut = useMutation({
    mutationFn: () => api.suggestMapping(source.id),
    onSuccess: (s) => { setSug(s); onApply(s); },
  });
  return (
    <div className="suggest">
      <div className="suggest__row">
        <button className="btn btn--sm btn--accent" onClick={() => mut.mutate()} disabled={mut.isPending}>
          {mut.isPending ? <span className="btn__spinner" /> : <Icon.Sparkle />}
          {mut.isPending ? 'Analyzing sample…' : sug ? 'Suggest again' : 'Suggest with AI'}
        </button>
        {sug && (
          <>
            <span className={cx('pill', sug.source === 'ai' ? 'pill--accent' : 'pill--muted')}>{sug.source === 'ai' ? 'AI' : 'heuristic'}</span>
            <span className="pill" style={{ color: confColor(sug.confidence) }}>{pct(sug.confidence)} confidence</span>
          </>
        )}
        {!aiOn && settings.data && (
          <span className="field__hint" style={{ marginLeft: 'auto' }}>
            AI assistant is off — suggestions use heuristics. <Link to="/settings#ai">Enable in Settings → AI</Link>
          </span>
        )}
      </div>
      {mut.isError && <div className="compute-error">{mut.error instanceof Error ? mut.error.message : 'Suggestion failed'}</div>}
      {sug && (
        <div className="suggest__rationale">
          <span className="eyebrow" style={{ marginRight: 8 }}>Rationale</span>
          {sug.rationale || 'No rationale returned.'}
        </div>
      )}
    </div>
  );
}

/* ───────────── Raw log viewer ───────────── */
const RAW_PAGE = 500;
// after this many lines are stacked in one window, infinite scroll stops and the user pages instead —
// a 2M-line file must never end up as 2M DOM rows
const RAW_WINDOW_MAX = 4000;

/** What a structured/binary source looks like when you "view the log".
 *
 * EVTX, SQLite, XLSX, PDF, memory dumps and mail archives have no lines to page through, and the viewer
 * used to say so and stop — a dead end on a file that Iris had parsed perfectly well ("data is parsed and
 * searchable, but in sources I get Not line-addressable"). The records ARE the file's readable form, so
 * they are what the viewer shows: the same paging and text filter as the line viewer, over events instead
 * of lines. The download stays, because the original bytes are the evidence.
 */
function ParsedRecords({ source, hint }: { source: Source; hint: string | null }) {
  const [find, setFind] = useState('');
  const q = useDebounce(find.trim(), 300);
  const [limit, setLimit] = useState(RAW_PAGE);
  const rows = useQuery({
    queryKey: ['source-records', source.id, q, limit],
    queryFn: () => api.events({ q, sources: [source.id], limit, sort: 'ts_asc' }),
  });
  const total = rows.data?.total ?? 0;
  const shown = rows.data?.rows ?? [];
  const download = api.sourceDownloadUrl(source.id);

  return (
    <div className="rawlog">
      <div className="rawlog__bar">
        <div className="rawlog__find">
          <Icon.Search />
          <input value={find} onChange={(e) => setFind(e.target.value)} placeholder="Filter these records (same syntax as Search)"
            aria-label="Filter records" spellCheck={false} />
          {find && <button className="rawlog__x" onClick={() => setFind('')} aria-label="Clear">×</button>}
        </div>
        <span className="rawlog__status">
          {rows.isFetching ? <span className="spinner" /> : <>{fmtInt(shown.length)} of {fmtInt(total)} record{total === 1 ? '' : 's'}</>}
        </span>
        <a className="btn btn--sm" href={download} download title={`Download the original file (${fmtBytes(source.size)})`}>
          <Icon.Download />Download
        </a>
      </div>
      <div className="rawlog__note">
        {hint || 'This file has no lines to page through — it is a structured container.'} These are the records Iris parsed from it.
      </div>
      <div className="rawlog__body" tabIndex={0}>
        {!rows.isLoading && shown.length === 0 && (
          <div className="rawlog__empty">{q ? `No record matches "${q}".` : 'This file produced no records.'}</div>
        )}
        <div className="records">
          {shown.map((e, i) => (
            <div key={e.id} className="records__row" role="link" tabIndex={0}
              onClick={() => window.open(`/events/${encodeURIComponent(e.id)}`, '_self')}
              onKeyDown={(k) => { if (k.key === 'Enter') window.open(`/events/${encodeURIComponent(e.id)}`, '_self'); }}>
              <span className="records__n">{i + 1}</span>
              <span className="records__ts cell-mono cell-dim">{e.ts ? fmtTs(e.ts) : '—'}</span>
              <span className="records__msg cell-mono" title={e.raw || e.msg}>{e.msg}</span>
            </div>
          ))}
        </div>
      </div>
      {shown.length < total && (
        <div className="rawlog__pager">
          <button className="btn btn--sm" disabled={rows.isFetching} onClick={() => setLimit((n) => n + RAW_PAGE)}>
            {rows.isFetching && <span className="btn__spinner" />}Load {Math.min(RAW_PAGE, total - shown.length)} more
          </button>
        </div>
      )}
    </div>
  );
}

function RawLogViewer({ source }: { source: Source }) {
  const nav = useNavigate();
  const [find, setFind] = useState('');
  const q = useDebounce(find.trim(), 300);
  const [start, setStart] = useState(0);
  const [lines, setLines] = useState<RawLine[]>([]);
  const [meta, setMeta] = useState<{ totalLines: number; matches: number; binary: boolean; hint: string | null; truncated: boolean } | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const bodyRef = useRef<HTMLDivElement>(null);
  const seq = useRef(0);
  const sid = source.id;

  useEffect(() => setStart(0), [q]);

  const load = useCallback(async (offset: number, append: boolean) => {
    const my = ++seq.current;
    setLoading(true);
    setError(null);
    try {
      const page = await api.sourceRaw(sid, { offset, limit: RAW_PAGE, q });
      if (my !== seq.current) return;
      setMeta((m) => ({ totalLines: page.totalLines, matches: page.matches, binary: page.binary, hint: page.hint, truncated: (append && m?.truncated) || page.truncatedLine }));
      setLines((prev) => (append ? [...prev, ...page.lines] : page.lines));
      if (!append) bodyRef.current?.scrollTo({ top: 0 });
    } catch (e) {
      if (my === seq.current) setError(e instanceof Error ? e.message : 'Could not load the file');
    } finally {
      if (my === seq.current) setLoading(false);
    }
  }, [sid, q]);

  useEffect(() => { void load(start, false); }, [load, start]);

  const total = meta ? (q ? meta.matches : meta.totalLines) : 0;
  const end = start + lines.length;
  const hasMore = !!meta && end < total;
  const canScrollMore = hasMore && lines.length < RAW_WINDOW_MAX;
  const loadMore = () => { if (hasMore && !loading) void load(end, true); };
  const onScroll = () => {
    const el = bodyRef.current;
    if (!el || !canScrollMore || loading) return;
    if (el.scrollTop + el.clientHeight >= el.scrollHeight - 240) loadMore();
  };
  const terms = useMemo(() => (q ? [q] : []), [q]);
  const download = api.sourceDownloadUrl(sid);

  if (meta?.binary) return <ParsedRecords source={source} hint={meta.hint} />;

  return (
    <div className="rawlog">
      <div className="rawlog__bar">
        <div className="rawlog__find">
          <Icon.Search width={12} height={12} />
          <input value={find} onChange={(e) => setFind(e.target.value)} placeholder="Find in file" aria-label="Find in file" spellCheck={false} autoComplete="off" />
          {find && <button className="close-x" onClick={() => setFind('')} aria-label="Clear find">×</button>}
        </div>
        <span className="rawlog__status">
          {loading && lines.length === 0 ? <span className="spinner" /> : meta ? (
            q ? <>{fmtInt(meta.matches)} match{meta.matches === 1 ? '' : 'es'} · {fmtInt(meta.totalLines)} lines</> : <>{fmtInt(meta.totalLines)} lines</>
          ) : ''}
        </span>
        <div className="rawlog__pager">
          <button className="btn btn--sm btn--ghost" disabled={start === 0 || loading} onClick={() => setStart(Math.max(0, start - RAW_PAGE))} title="Previous page">‹ Prev</button>
          <span className="rawlog__range">{total ? `${fmtInt(start + 1)}–${fmtInt(Math.min(end, total))} of ${fmtInt(total)}` : '—'}</span>
          <button className="btn btn--sm btn--ghost" disabled={!hasMore || loading} onClick={() => setStart(end)} title="Next page">Next ›</button>
        </div>
        <a className="btn btn--sm" href={download} download title={`Download the original file (${fmtBytes(source.size)})`}><Icon.Download />Download</a>
      </div>
      {error && <div className="compute-error">{error}</div>}
      <div className="rawlog__body" ref={bodyRef} onScroll={onScroll} tabIndex={0}>
        {lines.length === 0 && !loading && meta && (
          <div className="rawlog__empty">{q ? `No line contains "${q}".` : 'The file is empty.'}</div>
        )}
        <pre className="rawlog__pre">
          {lines.map((l) => (
            <div key={l.n} className="rawlog__line">
              <button className="rawlog__n" onClick={() => nav(`/search?sources=${encodeURIComponent(sid)}`)} title="Search this file's events">{l.n}</button>
              <span className="rawlog__text">{terms.length ? highlight(l.text, terms) : l.text}</span>
            </div>
          ))}
        </pre>
        {lines.length > 0 && (
          <div className="rawlog__foot">
            {loading && <span className="spinner" />}
            {!loading && hasMore && (
              canScrollMore
                ? <button className="btn btn--sm" onClick={loadMore}>Load {fmtInt(Math.min(RAW_PAGE, total - end))} more</button>
                : <button className="btn btn--sm" onClick={() => setStart(end)}>Next page ›</button>
            )}
            {!loading && !hasMore && <span className="muted">end of {q ? 'matches' : 'file'}</span>}
            {meta?.truncated && <span className="muted" title="Lines are cut at 2000 characters in the viewer; the download has them whole">some lines truncated at 2000 chars</span>}
          </div>
        )}
      </div>
    </div>
  );
}

/** Docked in the side drawer, or detached as a window you can move and resize.
 *
 *  A 200-column log line squeezed into a 640px modal drawer, with the source row that produced it hidden
 *  behind the overlay, is the complaint this answers. The choice is remembered: someone who detaches it
 *  once wants it detached next time. */
const RAWLOG_DETACHED_KEY = 'iris.rawlog.detached';

function RawLogDrawer({ source, onClose }: { source: Source | null; onClose: () => void }) {
  const [detached, setDetached] = useState<boolean>(() => {
    try { return localStorage.getItem(RAWLOG_DETACHED_KEY) === '1'; } catch { return false; }
  });
  const setMode = (v: boolean) => {
    setDetached(v);
    try { localStorage.setItem(RAWLOG_DETACHED_KEY, v ? '1' : '0'); } catch { /* private mode */ }
  };
  if (!source) return null;
  const sub = `raw log · ${source.parser} · ${fmtInt(source.events)} events · ${fmtBytes(source.size)}`;

  if (detached) {
    return (
      <FloatingWindow
        storageKey="rawlog"
        title={source.file}
        sub={sub}
        onClose={onClose}
        actions={<button className="btn btn--sm btn--ghost" onClick={() => setMode(false)} title="Dock this back into the side panel">Dock</button>}
      >
        <RawLogViewer key={source.id} source={source} />
      </FloatingWindow>
    );
  }
  return (
    <Drawer open onClose={onClose} wide title={source.file} sub={sub}
      actions={<button className="btn btn--sm btn--ghost" onClick={() => setMode(true)} title="Detach into a window you can move and resize">Detach</button>}>
      <RawLogViewer key={source.id} source={source} />
    </Drawer>
  );
}

/* ───────────── Mapping drawer ───────────── */
function MappingDrawer({ source, onClose, onViewRaw }: { source: Source | null; onClose: () => void; onViewRaw?: (s: Source) => void }) {
  const toast = useToast();
  const invalidate = useInvalidateCaseData();
  const [fields, setFields] = useState<string[]>([]);
  const [delimiter, setDelimiter] = useState('');

  // `sample` is a raw excerpt of the log — 1.5-2.4 kB per source, against ~365 B for the whole rest
  // of the row — and this drawer is the only thing that reads it. Shipping it in the /api/case list
  // was ~1.6 MB of raw log text in every poll of the most-polled endpoint at 680 files, so the list
  // no longer carries it and the drawer fetches the one source it is actually showing.
  const detail = useQuery({
    queryKey: ['source', source?.id],
    queryFn: () => api.getSource(source!.id),
    enabled: !!source,
    staleTime: 60_000,
  });
  const full = detail.data ?? source;

  useEffect(() => {
    if (!full) return;
    setDelimiter(full.delimiter ?? '');
    const guessed = full.guessedFields ?? [];
    if (guessed.length) setFields(guessed);
    else {
      const d = full.delimiter ?? '';
      const n = full.sample && d ? full.sample.split(d).length : 1;
      setFields(Array.from({ length: n }, (_, i) => `field_${i + 1}`));
    }
    // reset only when a different source opens, or when its detail arrives (the case poll refreshes
    // the object identity, which is why this cannot depend on the object itself)
  }, [source?.id, detail.data?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  const sampleParts = useMemo(() => {
    if (!full?.sample) return [];
    const d = delimiter || full.delimiter || '';
    return d ? full.sample.split(d) : [full.sample];
  }, [full, delimiter]);

  const mut = useMutation({
    mutationFn: () => api.setMapping(source!.id, { fields: fields.map((f) => f.trim()).filter(Boolean), delimiter: delimiter || undefined }),
    onSuccess: (s) => {
      toast.success('Mapping applied', `${s.file} re-parsed as ${s.parser} · ${fmtInt(s.events)} events`);
      invalidate();
      onClose();
    },
    onError: (e) => toast.error('Mapping failed', e),
  });

  const setField = (i: number, v: string) => setFields((f) => f.map((x, j) => (j === i ? v : x)));
  const removeField = (i: number) => setFields((f) => f.filter((_, j) => j !== i));
  const addField = () => setFields((f) => [...f, `field_${f.length + 1}`]);
  const canEdit = source?.state === 'MAP' || source?.state === 'REVIEW' || source?.state === 'ERROR';
  const applySuggestion = (s: MappingSuggestion) => {
    if (s.fields.length) setFields(s.fields);
    if (s.delimiter) setDelimiter(s.delimiter);
  };

  return (
    <Drawer open={!!source} onClose={onClose} title={source?.file ?? ''} sub={source ? `${source.parser} · ${fmtInt(source.events)} events · ${fmtBytes(source.size)}` : ''}
      footer={canEdit ? (
        <>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn btn--primary" disabled={mut.isPending || !fields.some((f) => f.trim())} onClick={() => mut.mutate()}>
            {mut.isPending && <span className="btn__spinner" />}Accept mapping &amp; re-parse
          </button>
        </>
      ) : <button className="btn" onClick={onClose}>Close</button>}
    >
      {source && (
        <>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            {/* The drawer is opened to ask "what is this file doing?" — so the parse gets the same
                percentage, rate and ETA here as it does in the table it was opened from. */}
            {source.state === 'PARSING'
              ? <ParsingCell source={source} />
              : <span className={cx('pill', 'pill--state', STATE_PILL[source.state])}>{source.state}</span>}
            {/* The other half of the file's status: has it been interpreted at all (phase 2)? */}
            <EnrichChip source={source} />
            <EnrichActions source={source} />
            {source.error && <span className="field__hint" style={{ color: 'var(--bad)' }}>{source.error}</span>}
            {enrichOf(source) === 'error' && source.enrichError && (
              <span className="field__hint" style={{ color: 'var(--bad)', flexBasis: '100%' }}>enrichment failed — {source.enrichError}</span>
            )}
            {onViewRaw && (
              <button className="btn btn--sm" style={{ marginLeft: 'auto' }} onClick={() => onViewRaw(source)} title="Open the entire original file, line by line">
                <Icon.Doc />View raw log
              </button>
            )}
          </div>
          <div>
            <div className="eyebrow">Sample line</div>
            <div className="sample" style={{ marginTop: 8 }}>{source.sample || '— no sample available —'}</div>
          </div>
          <div className="kv-list">
            <div className="kv"><span className="kv__k">Detected parser</span><span className="kv__v">{source.parser}</span></div>
            <div className="kv"><span className="kv__k">Confidence</span><span className="kv__v" style={{ color: confColor(source.confidence) }}>{pct(source.confidence)}</span></div>
            <div className="kv"><span className="kv__k">Time range</span><span className="kv__v">{fmtRange(source.range)}</span></div>
            {source.guessedFields && source.guessedFields.length > 0 && (
              <div className="kv"><span className="kv__k">Guessed fields</span><span className="kv__v" style={{ color: 'var(--accent)' }}>{source.guessedFields.join(' · ')}</span></div>
            )}
          </div>
          {canEdit ? (
            <>
              <SuggestBox key={source.id} source={source} onApply={applySuggestion} />
              <div className="field" style={{ maxWidth: 220 }}>
                <label className="field__label" htmlFor="map-delim">Delimiter</label>
                <input id="map-delim" value={delimiter} onChange={(e) => setDelimiter(e.target.value)} placeholder={source.delimiter || 'e.g. | , \\t ;'} />
                <div className="field__hint">Leave blank to keep the detected delimiter{source.delimiter ? ` (${JSON.stringify(source.delimiter)})` : ''}.</div>
              </div>
              <div>
                <div className="section-head" style={{ marginBottom: 8 }}>
                  <div className="section-title">Field mapping</div>
                  <div className="section-hint">one name per column, in order</div>
                </div>
                <div className="mapping-fields">
                  {fields.map((f, i) => (
                    <div key={i} className="mapping-field">
                      <span className="mapping-field__idx">{i + 1}</span>
                      <input value={f} onChange={(e) => setField(i, e.target.value)} aria-label={`Field ${i + 1} name`} spellCheck={false} />
                      <span className="mapping-field__sample" title={sampleParts[i] ?? ''}>{sampleParts[i] ?? <span className="muted">—</span>}</span>
                      <button className="close-x" onClick={() => removeField(i)} aria-label={`Remove field ${i + 1}`} title="Remove">×</button>
                    </div>
                  ))}
                </div>
                <div style={{ marginTop: 8, display: 'flex', gap: 8 }}>
                  <button className="btn btn--sm" onClick={addField}>+ Add field</button>
                  {source.guessedFields && source.guessedFields.length > 0 && (
                    <button className="btn btn--sm btn--ghost" onClick={() => setFields(source.guessedFields ?? [])}>Reset to guess</button>
                  )}
                </div>
                <div className="field__hint" style={{ marginTop: 8 }}>Use canonical names where possible: <span className="mono">timestamp, host, user, src_ip, dst_ip, action, msg</span> — they light up in search and the entity graph.</div>
              </div>
            </>
          ) : (
            <div className="field__hint">This source parsed cleanly with a known parser — no mapping needed. {source.state === 'PARSING' ? 'Parsing is still in progress.' : ''}</div>
          )}
        </>
      )}
    </Drawer>
  );
}

/* Which half of the two-phase ingest a tracker row is reporting on. Phase 2 is 'interpreting', never
   'parsing': telling the analyst the file is still being read when it is already being interpreted
   understates how far along it is and overstates what is left. */
const PHASE_LABEL: Record<string, string> = {
  reading: 'reading', parsing: 'parsing', enriching: 'interpreting',
  finishing: 'assigning ids', detecting: 'running detection rules', merging: 'merging into the pool',
  caching: 'writing the cache',
};
/* The phases whose progress is NOT the byte bar. For these the row shows the phase's own 0-100
   (`stagePct`) and drives the bar with it — a full bar under "parsing 100 %" for five minutes was the
   report "hangs for a long time even when shown to be at 100%". */
const STAGE_PHASES = new Set(['finishing', 'detecting', 'merging', 'caching']);
function phaseText(p: { phase: string; pct: number; stagePct?: number | null }): { label: string; pct: number } {
  const label = PHASE_LABEL[p.phase] ?? p.phase;
  if (STAGE_PHASES.has(p.phase)) {
    const sp = typeof p.stagePct === 'number' ? Math.round(p.stagePct) : null;
    return { label: sp === null ? label : `${label} ${sp}%`, pct: sp ?? 0 };
  }
  return { label: `${label} ${Math.round(p.pct)}%`, pct: p.pct };
}

/* ───────────── The state cell of the Sources table ─────────────
   A spinner says "something is happening" and nothing else. On a 639 MB capture that is twenty minutes
   of a screen the analyst cannot tell apart from a hang — reported as "when a log is parsing, all that
   happens is a spinner but there is no % indicator". Every number that answers it already existed
   server-side, keyed by this source's id (jobs.PARSE_PROGRESS); `Source.progress` is that row.

   What it says, in order of what is being asked: WHICH HALF is running (reading the lines vs
   interpreting them — two different amounts of remaining work), how far through, how fast, and how long
   is left. The bar is under the pill rather than beside it because the pill column is narrow and the
   percentage has to stay legible at a glance down a table of hundreds of rows.

   `progress` absent while PARSING is a real state and must not read as 0 %: a source waiting for the
   enrichment worker, or one whose tracker row has not been created yet, is not a stalled parse. It
   falls back to the bare pill, which is exactly what it used to be. */
function ParsingCell({ source }: { source: Source }) {
  const p = source.progress;
  const pt = p ? phaseText(p) : null;
  const phase = p ? (PHASE_LABEL[p.phase] ?? p.phase) : '';
  // Only claim a byte percentage when the file's size is known — `pct` is computed from bytes, and a
  // container with no byte total would otherwise sit at a confident, meaningless 0 %. A stage phase
  // carries its own count and is always shown.
  const shown = p ? (STAGE_PHASES.has(p.phase) ? Math.round(pt!.pct) : (p.bytesTotal ? Math.round(p.pct) : null)) : null;
  const detail = p
    ? [p.events ? `${fmtInt(p.events)} events` : '', fmtRate(p.bytesPerSec), fmtEta(p.etaSec),
       p.workers > 1 ? `${p.workers} workers` : ''].filter(Boolean).join(' · ')
    : '';
  const title = p
    ? `${phase}${shown !== null ? ` — ${shown}%` : ''}${p.bytesTotal ? `, ${fmtBytes(p.bytesDone)} of ${fmtBytes(p.bytesTotal)}` : ''}${detail ? ` · ${detail}` : ''}`
    : 'parsing — no progress reported yet';
  return (
    <div className="parsing-cell" title={title}>
      <span className="pill pill--accent">
        <span className="spinner" />
        {phase || 'PARSING'}{shown !== null ? ` ${shown}%` : ''}
      </span>
      {p && (p.bytesTotal > 0 || STAGE_PHASES.has(p.phase)) && <Bar pct={pt!.pct} color="var(--accent)" />}
      {detail && <span className="parsing-cell__detail ellipsis">{detail}</span>}
      {/* No tracker row: say so. A bar at 0 % for a source nothing is working on is the exact reading
          that made a settled workspace look like a hang. */}
      {!p && <span className="parsing-cell__detail">no progress reported yet</span>}
    </div>
  );
}

/* ───────────── Upload / parse progress row ───────────── */
function JobRow({ job, pct, localError }: { job: UploadJob; pct?: number; localError?: string }) {
  // The server's verdict wins; the request's own error covers the case where the server never got
  // to record one (the handler died with a 500 before failing the job).
  const error = job.error || (job.state !== 'ready' ? localError : '') || '';
  const failed = job.state === 'error' || (!!localError && job.state !== 'ready');
  // uploading = bytes still in flight (client knowledge); parsing = the server working on the file.
  // Conflating the two is what made a 6-minute parse look like a stuck upload.
  // `parsing` alone was almost as bad: a 263 MB CSV showed that one word for ten minutes with no way to
  // tell it apart from a hang. job.progress is the server's real answer — bytes consumed, rate and ETA.
  const inFlight = job.state === 'uploading' || job.state === 'queued';
  const prog = job.state === 'parsing' ? job.progress : null;
  // A `parsing` job with NO progress row is the server saying "parsing, no detail" — the parse thread
  // has not registered, or the work is waiting on something. Drawing a full bar for that claims the
  // file is done, and drawing 0 % claims it is stuck; the bar is simply not drawn.
  const noDetail = job.state === 'parsing' && !prog;
  const stage = prog ? phaseText(prog) : null;
  const shown = inFlight ? (pct ?? (job.size ? Math.round((job.received / job.size) * 100) : 0))
    : stage ? stage.pct : 100;
  const label = failed ? (job.interrupted ? 'interrupted' : 'failed')
    : job.state === 'ready' ? (job.target === 'library' ? 'in library' : `${fmtInt(job.events)} events`)
    // A parse the server picked up again after a restart: the staged copy is being re-read, and the
    // row says so instead of asking for a re-upload (see jobs.reconcile).
    : job.state === 'parsing' && job.interrupted ? (stage ? `${stage.label} · resumed` : 'resumed after restart')
    // name the PHASE: 'reading' is now visible from the first tick of a big file (the job adopts its
    // tracker row before it knows its source ids), and calling phase 2 'parsing' told the analyst the
    // file was still being read when it was already being interpreted.
    : job.state === 'parsing' ? (stage ? stage.label : 'parsing')
    // 'queued' is a real, healthy state and it can last a while: this tab sends three files at a time, so
    // everything behind them waits. It used to read as an unexplained stall, and the server used to
    // agree with that reading and fail it at ten minutes.
    : job.state === 'queued' ? 'waiting its turn'
    : `uploading ${shown}%`;
  const pill = failed ? 'pill--bad' : job.state === 'ready' ? 'pill--ok' : job.state === 'queued' ? 'pill--muted' : 'pill--accent';
  const detail = prog
    ? [prog.bytesTotal ? `${fmtBytes(prog.bytesDone)} of ${fmtBytes(prog.bytesTotal)}` : '',
       prog.events ? `${fmtInt(prog.events)} events` : '',
       fmtRate(prog.bytesPerSec), fmtEta(prog.etaSec),
       prog.workers > 1 ? `${prog.workers} workers` : ''].filter(Boolean).join(' · ')
    : '';
  return (
    <div className="upload-item">
      <span className="ellipsis" title={job.file}>
        {job.file} <span className="muted">· {fmtBytes(job.size)}{job.parser ? ` · ${job.parser}` : ''}{job.target === 'library' ? ' · library' : ''}</span>
      </span>
      <span className={cx('pill', pill)}>
        {(job.state === 'uploading' || job.state === 'parsing') && <span className="spinner" />}
        {label}
      </span>
      {noDetail ? <span className="muted" style={{ fontSize: 12 }}>no progress reported yet</span>
        : <Bar pct={shown} color={failed ? 'var(--bad)' : job.state === 'ready' ? 'var(--ok)' : 'var(--accent)'} />}
      {detail && !failed && <span className="muted" style={{ gridColumn: '1 / -1', fontSize: 12 }}>{detail}</span>}
      {/* The failure names its file (the row's first cell) and says exactly what went wrong. */}
      {error && <span className="upload-item__err" role="alert">{error}</span>}
    </div>
  );
}

/* ───────────── Sources that are NOT loaded ───────────── */
/* The pool has a memory budget, and files past it are never parsed. On the real library that silently
   dropped the TWO LARGEST files (263 MB each of 589 MB), and the only trace was an aggregate count.
   A file absent from search is indistinguishable from a search that found nothing, so it gets a real
   warning here — named, sized, explained, with the remedy attached. */
/** One label per reason. A skip's reason decides what the analyst should DO about it, so collapsing
 *  them (as a two-way ternary did) is not a wording problem — it is the wrong instruction. */
const SKIP_LABEL: Record<string, string> = {
  budget: 'over budget',
  memory: 'not enough memory',
  unreadable: 'unreadable',
  'parse-error': 'parse failed',
  'not-parsed': 'not expanded',
};

function NotLoaded() {
  const c = useCase();
  const qc = useQueryClient();
  const invalidate = useInvalidateCaseData();
  const toast = useToast();
  const [busy, setBusy] = useState('');
  const load = useMutation({
    mutationFn: (fileName: string) => { setBusy(fileName); return api.loadUnattached(fileName); },
    onSettled: () => setBusy(''),
    onSuccess: (f) => {
      toast.success(`${f.displayName} loaded into the workspace`,
        f.events ? `${fmtInt(f.events)} events are searchable now` : 'parsing — events will appear as it finishes');
      invalidate();
      void qc.invalidateQueries({ queryKey: qk.library });
    },
    // the server refuses when the machine genuinely cannot hold the file; it says so with real numbers
    onError: (e) => toast.error('Still not loaded', e),
  });

  const skips = c.data?.poolSkippedFiles ?? [];
  if (!skips.length) return null;
  const budget = c.data?.poolBudgetBytes ?? 0;
  const missing = skips.reduce((n, s) => n + s.size, 0);
  // The explanation has to come from the reasons ACTUALLY present, not from the budget. It used to
  // print "The workspace pool holds at most unlimited of log (IRIS_POOL_MAX_MB)" — a broken sentence
  // naming an env var that had nothing to do with why the file was skipped. There is no cap by default
  // (deliberately), so on the common path that line explained a limit that does not exist.
  const kinds = new Set(skips.map((s) => s.reason));
  const why: string[] = [];
  if (kinds.has('memory')) {
    why.push('this machine did not have the memory to hold them at the time — nothing is misconfigured, '
      + 'the workspace is simply bigger than the box. Free memory, delete a source below, or give the '
      + 'machine more RAM, then load it.');
  }
  if (kinds.has('budget') && budget) {
    why.push(`the pool cap of ${fmtBytes(budget)} refused them — raise IRIS_POOL_MAX_MB or remove sources below.`);
  }
  if (kinds.has('unreadable')) why.push('their bytes could not be read from disk — this one is a file or permissions problem.');
  if (kinds.has('not-parsed')) why.push('they are containers Iris only expands when attached to a case.');
  if (kinds.has('parse-error')) why.push('the parser failed on them.');

  return (
    <section>
      <div className="notloaded">
        <div className="notloaded__head">
          <Icon.Warn />
          <div>
            <div className="notloaded__title">
              {fmtInt(skips.length)} source{skips.length === 1 ? ' is' : 's are'} not loaded — {fmtBytes(missing)} of evidence is missing from search
            </div>
            <div className="notloaded__sub">
              These files are staged on disk but were never parsed, so Search, Timeline, Anomalies and the graph
              cannot see a single event from them.{why.length ? ` Why: ${why.join(' Also, ')}` : ''}
            </div>
          </div>
        </div>
        <div className="notloaded__list">
          {skips.map((s) => (
            <div key={s.fileName} className="notloaded__row">
              <span className="cell-mono cell-bright ellipsis" title={s.fileName}>{s.displayName}</span>
              <span className="cell-mono num">{fmtBytes(s.size)}</span>
              {/* Name the ACTUAL reason. This was a two-way ternary over a five-value enum, so every
                  reason that was not 'budget' printed "unreadable" — including 'memory', which sent the
                  analyst looking for a disk fault instead of freeing RAM. */}
              <span className="badge badge--warn">{SKIP_LABEL[s.reason] ?? s.reason}</span>
              <span className="notloaded__why">{s.detail}</span>
              {(s.reason === 'budget' || s.reason === 'memory') && (
                // 'memory' is exactly the case that needs this and did not have it: the detail text
                // said "free memory and load it from Sources" while offering no control to do so. The
                // server re-checks live headroom and refuses with real numbers, so the button is safe.
                <button className="btn btn--sm" disabled={load.isPending}
                  title="Parse it into the workspace anyway. Refused, with numbers, if the machine cannot hold it."
                  onClick={() => load.mutate(s.fileName)}>
                  {busy === s.fileName && <span className="btn__spinner" />}Load anyway
                </button>
              )}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ───────────── Screen ───────────── */
export function IngestScreen() {
  const c = useCase();
  const qc = useQueryClient();
  const toast = useToast();
  const invalidate = useInvalidateCaseData();
  const [over, setOver] = useState(false);
  const [openSrc, setOpenSrc] = useState<Source | null>(null);
  const [rawSrc, setRawSrc] = useState<Source | null>(null);
  const [srcFilter, setSrcFilter] = useState('');
  const [srcState, setSrcState] = useState<string>('');
  const [srcEnrich, setSrcEnrich] = useState<EnrichState | ''>('');
  const [confirmReset, setConfirmReset] = useState(false);
  const [resetTyped, setResetTyped] = useState('');
  // EVERY upload lands in the library. Evidence is collected first and filed into a case later — the
  // destination toggle that used to sit in the drop box asked a question the analyst cannot answer at
  // upload time ("does this belong to the case?"), and answering it wrong meant a detach to undo.
  // A library file is fully parsed, searchable, graphed and correlated with no case at all; the Sources
  // row's case picker files it whenever an investigation needs it.
  const noCase = !!c.data?.pending;
  const fileRef = useRef<HTMLInputElement>(null);

  // Server-side job list. Poll fast while anything is moving, slowly otherwise — this is also what a
  // freshly loaded tab rebuilds its progress UI from.
  const jobsQ = useQuery({
    queryKey: ['jobs'],
    queryFn: () => api.jobs(50),
    refetchInterval: (q) => (q.state.data?.active ? JOB_POLL_ACTIVE : JOB_POLL_IDLE),
  });
  // bytes this tab has pushed, per job id — the server cannot know it until the body is complete
  const [localPct, setLocalPct] = useState<Record<string, number>>({});
  // What the upload REQUEST said when it failed, per job. A 500 from the server never reaches the
  // job registry (the handler died before it could fail the job), so without this the row sat at
  // "parsing" and the only trace of the message was a toast that said "details are on the file below".
  const [localErr, setLocalErr] = useState<Record<string, string>>({});
  // Files this tab has just accepted, shown BEFORE the server knows about them. Registering the transfer
  // is itself a round trip, and on a slow link (or a big drop) that left the analyst staring at a page
  // that had visibly done nothing — "I drag and drop and I often don't see a status".
  const [dropped, setDropped] = useState<{ name: string; size: number; at: number }[]>([]);
  const lastPush = useRef<Record<string, number>>({});
  const refreshJobs = useCallback(() => { void qc.invalidateQueries({ queryKey: ['jobs'] }); }, [qc]);

  const doUpload = useCallback(
    async (files: File[]) => {
      if (!files.length) return;
      const toLibrary = true;
      const stamp = Date.now();
      setDropped((cur) => [...cur, ...files.map((f) => ({ name: f.name, size: f.size, at: stamp }))]);
      // Register the transfer BEFORE any byte moves, so another tab (and this one after a refresh) sees
      // it from the start. If that call fails the upload still works — the server creates jobs itself.
      let ids: string[] = [];
      try {
        const decl = await api.createJobs(files.map((f) => ({ file: f.name, size: f.size })), toLibrary ? 'library' : 'case');
        ids = decl.jobs.map((j) => j.id);
      } catch { ids = []; }
      refreshJobs();
      let added = 0;
      let bg = 0;
      let failed = 0;
      const queue = files.map((f, i) => ({ f, id: ids[i] }));
      // Every job in this batch is this tab's responsibility until it resolves — the ones waiting their
      // turn most of all, since nothing else will say a word about them. Ids leave the set as each
      // upload settles, so the last file is still heartbeaten while it is the only one left.
      const mine = new Set(ids.filter(Boolean));
      const beat = window.setInterval(() => {
        if (!mine.size) return;
        // In batches: one request naming thousands of ids is the kind of body a proxy or the server
        // caps, and a capped heartbeat is worse than none — the ids past the cap are the queued
        // files the watchdog will call abandoned.
        const ids = [...mine];
        for (let i = 0; i < ids.length; i += HEARTBEAT_BATCH) {
          void api.jobHeartbeat(ids.slice(i, i + HEARTBEAT_BATCH)).catch(() => undefined);
        }
      }, HEARTBEAT_MS);
      const worker = async () => {
        for (;;) {
          const job = queue.shift();
          if (!job) return;
          const id = job.id;
          const report = (p: number, loaded: number) => {
            if (!id) return;
            setLocalPct((m) => (m[id] === p ? m : { ...m, [id]: p }));
            const now = Date.now();
            if (p >= 100 || now - (lastPush.current[id] ?? 0) > PROGRESS_PUSH_MS) {
              lastPush.current[id] = now;
              void api.jobProgress(id, loaded).catch(() => undefined);
            }
          };
          try {
            // library uploads are staged bytes only — nothing is parsed and no case is touched
            const res = toLibrary
              ? await api.uploadToLibrary([job.f], report, id ? [id] : undefined)
              : await api.uploadSources([job.f], report, id ? [id] : undefined);
            added += res.length;
            if (toLibrary) {
              void qc.invalidateQueries({ queryKey: ['library'] });
            } else {
              bg += (res as Source[]).filter((x) => x.state === 'PARSING').length;
              invalidate();
            }
          } catch (e) {
            failed++;
            const msg = e instanceof Error ? e.message : String(e);
            if (id) setLocalErr((m) => ({ ...m, [id]: msg }));
            toast.error(`${job.f.name} was not ingested`, msg);
          } finally {
            if (id) mine.delete(id);
          }
          refreshJobs();
        }
      };
      try {
        // Four transfers at a time (was three). Each upload request is its own server thread and the
        // raw split is a few string operations per line, so the limit is the link and the disk, not
        // the CPU; more lanes overlap network with the write. Beyond four the gain was not measurable
        // and every extra lane is another file's bytes in flight on a memory-tight machine.
        await Promise.all(Array.from({ length: Math.min(4, queue.length) }, worker));
      } finally {
        window.clearInterval(beat);
      }
      refreshJobs();
      setDropped((cur) => cur.filter((d) => d.at !== stamp));
      if (added) {
        toast.success(`${added} file${added === 1 ? '' : 's'} ingested`,
          'searchable now — file them into a case from the Case column whenever you need one');
      }
      if (failed > 1) toast.error(`${failed} uploads failed`, 'each failure names its file and the reason in Transfers below');
    },
    [toast, qc, refreshJobs],
  );

  // What the progress list shows: everything still moving, every failure, and results from the last few
  // minutes. Server-side retention (30 min) is the outer bound; this is just what is still interesting.
  // The list ages rows out by wall clock, so it has to be re-evaluated on a clock and not only when the
  // query returns: the idle poll is 20 s, and a finished transfer that hangs around for another 20 s
  // after the server has already dropped it is exactly the stale row this change exists to remove.
  const [tick, setTick] = useState(0);
  const jobRows = useMemo(() => {
    const now = Date.now();
    const caseId = c.data?.id;
    return (jobsQ.data?.jobs ?? [])
      // library jobs belong to no case; case jobs only show on the case they were started in
      .filter((j) => j.target === 'library' || !j.caseId || j.caseId === caseId)
      .filter((j) => {
        if (j.state === 'ready') return now - Date.parse(j.updatedAt) < JOB_DONE_MS;
        if (j.state === 'error') return now - Date.parse(j.updatedAt) < JOB_FAILED_MS;
        return true;
      });
  }, [jobsQ.data, c.data?.id, tick]);
  // Every FAILURE is shown, first, however many there are — a drop of 300 files that lost nine of
  // them used to show the eight newest transfers and nothing else, so the failures were invisible
  // until everything in front of them aged out. Only the in-flight/finished rows are capped, and the
  // cap says how many it is hiding.
  const { shownRows, hiddenRows } = useMemo(() => {
    const failed = jobRows.filter((j) => j.state === 'error');
    const rest = jobRows.filter((j) => j.state !== 'error');
    return { shownRows: [...failed, ...rest.slice(0, JOB_ROWS)], hiddenRows: Math.max(0, rest.length - JOB_ROWS) };
  }, [jobRows]);
  // Only while something is actually counting down — a panel showing nothing but failures has no
  // deadline and must not hold a timer open for the half hour they stay.
  const hasDoneRows = jobRows.some((j) => j.state === 'ready');
  useEffect(() => {
    if (!hasDoneRows) return;
    const t = window.setInterval(() => setTick((n) => n + 1), 2500);
    return () => window.clearInterval(t);
  }, [hasDoneRows]);
  const pendingDrops = useMemo(() => {
    const known = new Set(jobRows.map((j) => j.file));
    return dropped.filter((d) => !known.has(d.name));
  }, [dropped, jobRows]);
  const failedJobs = jobRows.filter((j) => j.state === 'error').length;
  const finishedJobs = jobRows.filter((j) => j.state === 'ready').length + failedJobs;
  const activeJobs = jobRows.length - finishedJobs;
  const clearJobs = useMutation({ mutationFn: api.clearJobs, onSuccess: refreshJobs });
  const lib = useLibrary();
  const stagedCount = (lib.data ?? []).filter((f) => !f.caseId && !f.inActiveCase).length;

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setOver(false);
    void doUpload(Array.from(e.dataTransfer.files));
  };

  const reset = useMutation({
    mutationFn: api.resetCase,
    onSuccess: (data: Case) => {
      qc.setQueryData(qk.case, data);
      invalidate();
      setConfirmReset(false);
      toast.info('Case reset', 'All sources and events cleared');
    },
    onError: (e) => toast.error('Reset failed', e),
  });
  // Deleting is immediate: the row goes at once and the request runs behind it. A modal that locks the
  // screen until the server answers turns a one-click action into a wait — and the server answer is not
  // interesting, only its failure is. `deleting` drives a spinner on the row until the list refreshes.
  const [deleting, setDeleting] = useState<Set<string>>(new Set());
  const del = useMutation({
    mutationFn: (id: string) => api.deleteSource(id),
    onMutate: (id: string) => {
      setDeleting((cur) => new Set(cur).add(id));
    },
    onSuccess: (_r, id) => {
      const gone = allPool.find((s) => s.id === id);
      invalidate();
      toast.info('Source deleted', gone ? `${gone.file} · ${fmtInt(gone.events)} events left the workspace` : undefined);
    },
    onError: (e, id) => {
      setDeleting((cur) => { const n = new Set(cur); n.delete(id); return n; });
      toast.error('Delete failed', e);
    },
    onSettled: (_r, _e, id) => {
      // the row is gone from the server's answer by now; clear the marker on the next list either way
      window.setTimeout(() => setDeleting((cur) => { const n = new Set(cur); n.delete(id); return n; }), 400);
    },
  });

  const data = c.data;
  const firstMap = data?.sources.find((s) => s.state === 'MAP');
  const acceptMapping = useMutation({
    mutationFn: (s: Source) => api.setMapping(s.id, { fields: s.guessedFields ?? [], delimiter: s.delimiter }),
    onSuccess: (s) => {
      toast.success('Mapping accepted', `${s.file} · ${fmtInt(s.events)} events`);
      invalidate();
    },
    onError: (e) => toast.error('Could not accept mapping', e),
  });

  // keep drawer source fresh
  useEffect(() => {
    if (!openSrc || !data) return;
    const fresh = [...data.sources, ...data.librarySources].find((s) => s.id === openSrc.id);
    if (fresh && fresh !== openSrc) setOpenSrc(fresh);
  }, [data, openSrc]);

  // The workspace POOL: the case's own sources plus the case-less ones staged in the library. Both are
  // parsed and searchable, so both belong in this table — a case only decides which are filed into it.
  const allPool = useMemo(() => [...(data?.sources ?? []), ...(data?.librarySources ?? [])], [data]);
  // 30+ files is normal on a real workstation, and the answer to "where is the firewall log" was
  // scrolling. Filter matches the file name and the detected parser; the state chips carry their counts.
  const stateCounts = useMemo(() => {
    const n: Record<string, number> = {};
    for (const s of allPool) n[s.state] = (n[s.state] ?? 0) + 1;
    return n;
  }, [allPool]);
  // Two-phase ingest: `state` is how the PARSE went, `enrich` is whether the file has been interpreted
  // at all. They are different questions — a READY source can still be raw — so they get their own
  // counts and their own filter chips.
  const enrichCounts = useMemo(() => {
    const n: Partial<Record<EnrichState, number>> = {};
    for (const s of allPool) { const e = enrichOf(s); n[e] = (n[e] ?? 0) + 1; }
    return n;
  }, [allPool]);
  const rawSources = useMemo(() => allPool.filter((s) => enrichOf(s) === 'raw'), [allPool]);
  const outstandingSources = useMemo(
    () => allPool.filter((s) => { const e = enrichOf(s); return e === 'raw' || e === 'queued' || e === 'enriching'; }),
    [allPool]);
  const enrichAll = useEnrichAll();
  const pool = useMemo(() => {
    const q = srcFilter.trim().toLowerCase();
    return allPool.filter((s) =>
      (!q || s.file.toLowerCase().includes(q) || (s.parser ?? '').toLowerCase().includes(q))
      && (!srcState || s.state === srcState)
      && (!srcEnrich || enrichOf(s) === srcEnrich));
  }, [allPool, srcFilter, srcState, srcEnrich]);
  const pendingMappings = usePendingMappings();
  const nParsing = allPool.filter((s) => s.state === 'PARSING').length;
  // What actually needs a DECISION, which is not the same as what is not READY. On the analyst's
  // workspace 343 sources sat in MAP/REVIEW/ERROR, and 340 of them were JSON lines that parsed
  // perfectly and merely scored under the READY threshold — they name their own fields and there is
  // nothing to map. "343 need review" next to a mapper that could act on 1 read as a broken button;
  // the honest count is the files waiting for a field mapping plus the files that failed to parse.
  // The full state breakdown is still one row below, in the state chips.
  const nFailed = allPool.filter((s) => s.state === 'ERROR').length;
  const nToMap = pendingMappings.data?.total ?? 0;
  const nAction = nToMap + nFailed;
  // Size of the WHOLE table, split the same way the table is: a total that covered only the case rows
  // while library rows sat right underneath it would read as the total of everything shown.
  const caseBytes = useMemo(() => totalSize(data?.sources ?? []), [data]);
  const libBytes = useMemo(() => totalSize(data?.librarySources ?? []), [data]);
  const poolBytes = { bytes: caseBytes.bytes + libBytes.bytes, unknown: caseBytes.unknown + libBytes.unknown };
  const mixedOrigins = (data?.sources.length ?? 0) > 0 && (data?.librarySources.length ?? 0) > 0;

  return (
    <div className="page ingest">
      {/* ── 1. Upload ── */}
      {/* The box is the drop target and Choose files — nothing else. Everything that used to stack up
          inside it (format list, the destination toggle, the no-case explanation, transfer rows, the
          library count) now sits BELOW it or is gone, so the control reads as one calm thing. The two
          signals that must never be lost are still on this page: transfer progress directly under the
          box, and the not-loaded warning in its own panel further down. */}
      <section>
        <SectionHead eyebrow="01 · Ingest" title="Upload evidence"
          hint="fingerprinted, parsed and searchable on arrival — no case required; file them into one later" />
        <div
          className={cx('dropzone', over && 'over')}
          onDragOver={(e) => { e.preventDefault(); setOver(true); }}
          onDragLeave={() => setOver(false)}
          onDrop={onDrop}
          onClick={() => fileRef.current?.click()}
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileRef.current?.click(); } }}
          role="button"
          tabIndex={0}
          aria-label="Upload log files"
        >
          <input ref={fileRef} type="file" multiple hidden onChange={(e) => { void doUpload(Array.from(e.target.files ?? [])); e.target.value = ''; }} />
          <div className="dropzone__main">
            <div className="dropzone__plus"><Icon.Upload width={16} height={16} /></div>
            <div>
              <div className="dropzone__title">Drop files here</div>
              <div className="dropzone__sub">
                or use Choose files · everything lands in the workspace, searchable at once · file it into a case later
              </div>
            </div>
            <div className="dropzone__actions" onClick={(e) => e.stopPropagation()}>
              <button className="btn btn--primary" onClick={() => fileRef.current?.click()}><Icon.Upload />Choose files</button>
            </div>
          </div>
        </div>

        {/* Live transfer + parse progress. Rebuilt from the server on every mount: a refresh mid-upload
            or mid-parse lands here with the real state, and a second tab shows exactly the same rows.
            It moved OUT of the drop box so the box stays one control, but it stays directly under it —
            a running parse must never be invisible. */}
        {(jobRows.length > 0 || pendingDrops.length > 0) && (
          <div className="uploads">
            <div className="uploads__head">
              <span className="eyebrow">Transfers</span>
              {(activeJobs > 0 || pendingDrops.length > 0) && (
                <span className="pill pill--accent"><span className="spinner" />{activeJobs + pendingDrops.length} in progress</span>
              )}
              {finishedJobs > 0 && (
                <button className="btn btn--sm btn--ghost" style={{ marginLeft: 'auto' }} disabled={clearJobs.isPending} onClick={() => clearJobs.mutate()}>
                  {failedJobs === finishedJobs ? `Dismiss ${failedJobs === 1 ? 'failure' : 'failures'}` : 'Clear finished'}
                </button>
              )}
            </div>
            <div className="upload-list">
              {/* accepted here, not yet acknowledged by the server — same row shape so nothing jumps
                  when the real job takes over */}
              {pendingDrops.map((d) => (
                <div key={`${d.name}-${d.at}`} className="upload-item upload-item--pending">
                  <span className="ellipsis" title={d.name}>
                    {d.name} <span className="muted">· {fmtBytes(d.size)}</span>
                  </span>
                  <span className="pill pill--accent"><span className="spinner" />starting</span>
                </div>
              ))}
              {shownRows.map((j) => <JobRow key={j.id} job={j} pct={localPct[j.id]} localError={localErr[j.id]} />)}
              {hiddenRows > 0 && (
                <div className="muted" style={{ fontSize: 'var(--fs-sm)', padding: '4px 0' }}>
                  and {fmtInt(hiddenRows)} more waiting their turn
                </div>
              )}
            </div>
          </div>
        )}

        {/* Condensed footer for the box: what formats are accepted (folded away), and how many files are
            sitting in the library. Both used to be permanent blocks inside the drop box. */}
        <div className="ingest__foot">
          <details className="disclose">
            <summary>Supported formats</summary>
            <SupportedTypes />
          </details>
          {stagedCount > 0 && (
            <span className="field__hint">
              {fmtInt(stagedCount)} file{stagedCount === 1 ? '' : 's'} in the library
              {noCase ? ' — searchable now; attach them once a case exists' : ' — attach them with “Add existing sources” below'}.
            </span>
          )}
        </div>
      </section>

      {/* Evidence that is on disk but NOT in the workspace — the loudest thing on this page when it happens */}
      <NotLoaded />

      {/* ── 2. Sources ── */}
      <section>
        <SectionHead
          eyebrow="02 · Sources"
          title={<>Sources {data && <span className="sec__count">{allPool.length}</span>}</>}
          actions={<AddSources />}
          hint={<>
            {nParsing > 0 && <span className="pill pill--accent" style={{ marginRight: 8 }}><span className="spinner" />{nParsing} parsing</span>}
            {nAction > 0 && (
              <span className="pill pill--warn tip" style={{ marginRight: 8 }}
                data-tip={[nToMap ? `${nToMap} waiting for a field mapping` : '',
                           nFailed ? `${nFailed} failed to parse` : ''].filter(Boolean).join(' · ')}>
                {nAction} need{nAction === 1 ? 's' : ''} attention
              </span>
            )}
            {/* Raw means "in the pool and searchable, but not interpreted". It is the one state on this
                table that silently narrows every other screen, so it is stated here as well as per row. */}
            {outstandingSources.length > 0 && (
              <span className="pill pill--warn tip" style={{ marginRight: 8 }}
                data-tip="Their lines are searchable, but they carry no timestamp, severity, parsed field or entity — the timeline, the entity graph and the detections cannot see them yet.">
                {outstandingSources.length} not interpreted
              </span>
            )}
            click a row to inspect or fix its mapping
          </>}
        />
        {allPool.length > 3 && (
          <div className="sources__toolbar">
            <div className="sources__search">
              <Icon.Search className="sources__search-icon" aria-hidden />
              <input value={srcFilter} onChange={(e) => setSrcFilter(e.target.value)} placeholder="Filter by file name or parser"
                aria-label="Filter sources" spellCheck={false} />
              {srcFilter && <button className="sources__search-x" onClick={() => setSrcFilter('')} aria-label="Clear filter">×</button>}
            </div>
            <div className="chip-row">
              <span className="chip-row__label">Parse</span>
              {(['READY', 'REVIEW', 'MAP', 'ERROR', 'PARSING'] as const).filter((st) => stateCounts[st]).map((st) => (
                <button key={st} className={cx('chip', srcState === st && 'on')} aria-pressed={srcState === st}
                  onClick={() => setSrcState((v) => (v === st ? '' : st))}
                  title={st === 'MAP' ? 'Unrecognised layout — waiting for a field mapping'
                    : st === 'ERROR' ? 'The parser failed on this file' : undefined}>
                  {st.toLowerCase()}<span className="chip__count">{stateCounts[st]}</span>
                </button>
              ))}
            </div>
            {/* The second question about a file, and a different one: has it been INTERPRETED yet. A
                chip with no rows behind it is disabled rather than hidden — "nothing at this level" is
                an answer, and a filter that silently disappears is one the analyst has to guess at. */}
            <div className="chip-row">
              <span className="chip-row__label">Interpreted</span>
              {ENRICH_ORDER.map((st) => {
                const n = enrichCounts[st] ?? 0;
                return (
                  <button key={st} className={cx('chip', srcEnrich === st && 'on')} aria-pressed={srcEnrich === st}
                    disabled={!n && srcEnrich !== st}
                    onClick={() => setSrcEnrich((v) => (v === st ? '' : st))}
                    title={ENRICH_META[st].help}>
                    {ENRICH_META[st].label}<span className="chip__count">{n}</span>
                  </button>
                );
              })}
              {(srcState || srcFilter || srcEnrich) && (
                <button className="btn btn--sm btn--ghost" onClick={() => { setSrcState(''); setSrcFilter(''); setSrcEnrich(''); }}>clear</button>
              )}
            </div>
          </div>
        )}
        {pool.length > 0 && (
          <div className="sources-sum">
            <span><b>{fmtInt(pool.length)}</b> source{pool.length === 1 ? '' : 's'}</span>
            <span className="sources-sum__sep">·</span>
            <span title="Total bytes of every file listed below, case and library together">
              <b>{fmtBytes(poolBytes.bytes)}</b> on disk
            </span>
            {mixedOrigins && (
              <span className="sources-sum__split">
                ({fmtInt(data?.sources.length ?? 0)} in case {fmtBytes(caseBytes.bytes)} · {fmtInt(data?.librarySources.length ?? 0)} in library {fmtBytes(libBytes.bytes)})
              </span>
            )}
            {poolBytes.unknown > 0 && (
              <span className="sources-sum__split" title="Their size is not known, so they are not counted in the total">
                · {fmtInt(poolBytes.unknown)} of unknown size, not in the total
              </span>
            )}
            {rawSources.length > 0 && (
              <button className="btn btn--sm" style={{ marginLeft: 'auto' }} disabled={enrichAll.isPending}
                title="Parse and normalize every raw file: timestamps, severities, parsed fields, entities and detections. They run one at a time in the background."
                onClick={() => enrichAll.mutate(rawSources.map((s) => s.id))}>
                {enrichAll.isPending && <span className="btn__spinner" />}Enrich {fmtInt(rawSources.length)} raw source{rawSources.length === 1 ? '' : 's'}
              </button>
            )}
          </div>
        )}
        <div className="table">
          <div className="table__head sources-grid">
            <div>File</div><div>Detected parser</div><div>Events</div><div className="num">Size</div><div>Time range</div><div>Confidence</div><div>State</div>
            <div title="Whether the file has been parsed and normalized (phase 2), or is still raw text in the pool">Interpreted</div>
            <div title="Delete this log and its events">Delete</div>
          </div>
          {c.isLoading && <SkeletonRows n={5} />}
          {c.isError && <div style={{ padding: 16 }}><ErrorState inline error={c.error} onRetry={() => void c.refetch()} /></div>}
          {data && pool.length === 0 && (
            <div className="table__empty">
              {allPool.length ? (
                <EmptyState inline icon={<Icon.Search />} title="No source matches"
                  body={`Nothing in ${allPool.length} file${allPool.length === 1 ? '' : 's'} matches the current filter.`}
                  actions={<button className="btn btn--sm" onClick={() => { setSrcState(''); setSrcFilter(''); setSrcEnrich(''); }}>Clear filter</button>} />
              ) : (
                <EmptyState inline icon={<Icon.Inbox />} title="No sources yet"
                  body="Drop files above or use Choose files. Parsed sources appear here — a case is not required." />
              )}
            </div>
          )}
          {pool.map((s) => (
            <div key={s.id} className={cx('table__row sources-grid clickable', deleting.has(s.id) && 'row--going')}
              role="button" tabIndex={0} onClick={() => setOpenSrc(s)} onKeyDown={(e) => { if (e.key === 'Enter') setOpenSrc(s); }}>
              <div className="cell-mono cell-bright ellipsis rawlog-cell" title={s.file}>
                <span className="ellipsis">{s.file}</span>
                {s.origin === 'library' && (
                  <span className="pill" title="In the library — analysed, but filed in no case">library</span>
                )}
                <button className="rawlog-open" onClick={(e) => { e.stopPropagation(); setRawSrc(s); }} aria-label={`View raw log of ${s.file}`} title="View raw log">
                  <Icon.Doc />
                </button>
              </div>
              <div style={{ fontSize: 'var(--fs-md)' }} className="ellipsis">{s.parser}</div>
              {/* A parsing source has a real, rising event count in the tracker — an ellipsis threw it away
                  and left the one column that proves the parse is producing something blank. */}
              <div className="cell-mono">
                {s.state === 'PARSING'
                  ? (s.progress?.events ? <span title="events parsed so far">{fmtInt(s.progress.events)}</span>
                                        : <span className="muted">…</span>)
                  : fmtInt(s.events)}
              </div>
              <div className="cell-mono cell-dim num" title={s.size > 0 ? `${s.size.toLocaleString('en-US')} bytes` : 'size unknown'}>{fmtSize(s.size)}</div>
              <div className="cell-mono cell-dim" style={{ fontSize: 'var(--fs-sm)' }}>{fmtRange(s.range)}</div>
              <div className="conf">
                <Bar pct={s.confidence * 100} color={confColor(s.confidence)} width={52} />
                <span className="conf__pct" style={{ color: confColor(s.confidence) }}>{pct(s.confidence)}</span>
              </div>
              <div>
                {s.state === 'PARSING' ? <ParsingCell source={s} /> : (
                  <span className={cx('pill', 'pill--state', STATE_PILL[s.state], s.error && 'tip')} data-tip={s.error || undefined}>
                    {s.state === 'ERROR' && <Icon.Warn width={10} height={10} />}
                    {s.state}
                  </span>
                )}
              </div>
              {/* Phase 2: has this file been interpreted, and the two ways to change that. */}
              <div className="enrich-cell">
                <EnrichChip source={s} />
                <EnrichActions source={s} />
              </div>
              {/* One click, no dialog. The tooltip carries the consequence, and the toast that follows
                  names what left the workspace. */}
              <button className="row-del" aria-label={`Delete ${s.file}`} disabled={deleting.has(s.id)}
                title={`Delete ${s.file} — its ${fmtInt(s.events)} events leave the workspace and the file is removed from disk`}
                onClick={(e) => { e.stopPropagation(); del.mutate(s.id); }}>
                {deleting.has(s.id) ? <span className="spinner" /> : <Icon.Trash />}
              </button>
              {/* A failure the analyst cannot read is not a report. The tooltip is not enough: the
                  message is what says whether this file needs a mapping, a different parser, or is
                  simply not what it claimed to be. */}
              {/* Same rule for a parse failure: the tooltip on the state pill was the only place the
                  message lived, and a tooltip is not a report. The row already names the file. */}
              {s.state === 'ERROR' && s.error && (
                <div className="enrich-err" title="Parse error">
                  failed — {s.error}
                </div>
              )}
              {enrichOf(s) === 'error' && s.enrichError && (
                <div className="enrich-err" title="Enrichment error">
                  enrichment failed — {s.enrichError}
                </div>
              )}
              {!!s.lostCitations?.length && (
                <div
                  className="enrich-err"
                  title={`Case-set entries that no longer resolve to a line in this file: ${s.lostCitations.join(', ')}`}
                >
                  {s.lostCitations.length === 1
                    ? '1 timeline entry lost its evidence link'
                    : `${s.lostCitations.length} timeline entries lost their evidence link`}
                  {' '}— they are still on the case, but no longer point at a line here
                </div>
              )}
            </div>
          ))}
        </div>
      </section>

      {/* ── 3. Mapping / queue ── */}
      <section>
        <SectionHead eyebrow="03 · Normalize" title="Mapping & queue" hint="unknown layouts wait for your call; everything else flows through"
          actions={<AutoMapAll />} />
        <div className="ingest__bottom">
          <div className="panel">
            <div className="eyebrow">Unknown format · needs your call</div>
            {firstMap ? (
              <>
                <div className="sample">{firstMap.sample || firstMap.file}</div>
                <div className="unknown__text">
                  {firstMap.delimiter ? <>{delimName(firstMap.delimiter)}-delimited, {firstMap.guessedFields?.length ?? '?'} fields. </> : <>Unrecognized structure. </>}
                  Iris guessed{' '}
                  <b>{firstMap.guessedFields?.length ? firstMap.guessedFields.join(' · ') : 'no fields'}</b> at {pct(firstMap.confidence)} confidence.
                </div>
                <div style={{ marginTop: 12, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <button className="btn btn--primary btn--sm" disabled={acceptMapping.isPending || !firstMap.guessedFields?.length} onClick={() => acceptMapping.mutate(firstMap)}>
                    {acceptMapping.isPending && <span className="btn__spinner" />}Accept mapping
                  </button>
                  <button className="btn btn--sm" onClick={() => setOpenSrc(firstMap)}>Edit fields</button>
                  <button className="btn btn--sm btn--accent" onClick={() => setOpenSrc(firstMap)} title="Open the mapping editor and ask the AI for a suggestion"><Icon.Sparkle />Suggest with AI</button>
                </div>
              </>
            ) : (
              <div className="unknown__text muted">{data && data.sources.length ? 'Every source in the case has a confident parser. Nothing to review.' : 'Sources with an unrecognized layout will appear here for a manual field mapping.'}</div>
            )}
          </div>

          <div className="panel">
            <div className="eyebrow">Normalization queue</div>
            <div className="queue-list">
              {data && data.queue.length === 0 && <div className="muted" style={{ fontSize: 'var(--fs-base)' }}>Queue is empty.</div>}
              {data?.queue.map((q, i) => (
                <div key={i} className="queue-item">
                  <span className="queue-item__mark" style={{ color: q.done ? 'var(--ok)' : 'var(--warn)' }}>{q.done ? '✓' : '◐'}</span>
                  <span className="queue-item__label">{q.label}</span>
                  <span className="queue-item__detail">{q.detail}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <MappingDrawer source={openSrc} onClose={() => setOpenSrc(null)} onViewRaw={(s) => { setOpenSrc(null); setRawSrc(s); }} />
      <RawLogDrawer source={rawSrc} onClose={() => setRawSrc(null)} />
      {/* Reset DELETES every uploaded file for this case. It sat behind a single click and has cost
          real data, so it is gated the same way as deleting a case: type the name to confirm. */}
      <ConfirmDialog
        open={confirmReset}
        title="Reset this case?"
        confirmLabel="Reset case"
        danger
        busy={reset.isPending}
        confirmDisabled={resetTyped.trim() !== (data?.name ?? '')}
        onConfirm={() => reset.mutate()}
        onCancel={() => { setConfirmReset(false); setResetTyped(''); }}
        text={
          <div className="danger-confirm">
            <div>This permanently deletes, for <b>{data?.name}</b>:</div>
            <ul>
              <li><b>{fmtInt(data?.sources.length ?? 0)}</b> uploaded file{(data?.sources.length ?? 0) === 1 ? '' : 's'} on disk</li>
              <li><b>{fmtInt(data?.eventCount ?? 0)}</b> normalized events</li>
              <li>the case set, notes and findings</li>
            </ul>
            <div>The uploaded files cannot be recovered — you would have to re-ingest them.</div>
            <label className="field__label" htmlFor="reset-confirm" style={{ marginTop: 8 }}>
              Type <b className="mono">{data?.name}</b> to confirm
            </label>
            <input id="reset-confirm" autoFocus value={resetTyped} onChange={(e) => setResetTyped(e.target.value)}
              placeholder={data?.name} spellCheck={false} autoComplete="off" />
          </div>
        }
      />

    </div>
  );
}

function delimName(d: string): string {
  switch (d) {
    case '|': return 'Pipe';
    case ',': return 'Comma';
    case '\t': return 'Tab';
    case ';': return 'Semicolon';
    case ' ': return 'Space';
    default: return `"${d}"`;
  }
}
