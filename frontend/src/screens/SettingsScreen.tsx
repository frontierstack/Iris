import { PerfPanel } from '../components/PerfPanel';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import type { AiTestResult, ComputeMode, ComputeStatus, Settings, SystemPrompt, SystemPromptMode, ThemeName } from '../api/types';
import { Icon } from '../components/icons';
import { useAuthStatus } from '../components/LoginGate';
import { Bar, ConfirmDialog, ErrorState, Loading, Toggle } from '../components/ui';
import { qk, useCase, useCases, useInvalidateCaseData, useLibrary, useSaveSettings, useSettings } from '../hooks/queries';
import { useToast } from '../hooks/useToast';
import { useTheme } from '../theme/ThemeProvider';
import { MONO_FONTS, THEMES, UI_FONTS, type Density } from '../theme/themes';
import { cx, fmtInt, fmtMB, fmtRelative, fmtTs } from '../utils/format';

const DEFAULT_MODEL = 'gpt-4o-mini';

const COMPUTE_MODES: { id: ComputeMode; title: string; desc: string }[] = [
  { id: 'auto', title: 'Parse with CUDA (auto)', desc: 'Use the GPU when a CUDA-capable device and runtime are present; fall back to CPU silently.' },
  { id: 'cuda', title: 'Force CUDA', desc: 'Always attempt GPU parsing. Ingest fails loudly if CUDA is unavailable — useful for benchmarking.' },
  { id: 'cpu', title: 'CPU only', desc: 'Never touch the GPU. Slower on very large files but fully deterministic.' },
];

const NAV: { id: string; label: string }[] = [
  { id: 'appearance', label: 'Appearance' },
  { id: 'compute', label: 'Compute' },
  { id: 'ai', label: 'AI assistant' },
  { id: 'prompts', label: 'System prompts' },
  { id: 'mcp', label: 'MCP server' },
  { id: 'security', label: 'Security' },
  { id: 'data', label: 'Data' },
];

const COLLAPSE_KEY = 'iris.settings.collapsed';
function readCollapsedSections(): Record<string, boolean> {
  try { return JSON.parse(localStorage.getItem(COLLAPSE_KEY) ?? '{}') as Record<string, boolean>; } catch { return {}; }
}

function Section({ id, title, desc, children, footer, danger, collapsible, defaultCollapsed }: {
  id: string; title: string; desc: string; children: React.ReactNode; footer?: React.ReactNode;
  danger?: boolean; collapsible?: boolean; defaultCollapsed?: boolean;
}) {
  const [open, setOpen] = useState(() => {
    if (!collapsible) return true;
    const saved = readCollapsedSections()[id];
    return saved === undefined ? !defaultCollapsed : !saved;
  });
  const { hash } = useLocation();
  // a deep link (/settings#ai) must reveal the section it points at
  useEffect(() => { if (collapsible && hash === `#${id}`) setOpen(true); }, [hash, id, collapsible]);

  const toggle = () => setOpen((v) => {
    const next = !v;
    try {
      const all = readCollapsedSections();
      all[id] = !next;
      localStorage.setItem(COLLAPSE_KEY, JSON.stringify(all));
    } catch { /* ignore */ }
    return next;
  });

  return (
    <section className={cx('settings__section', danger && 'settings__section--danger', collapsible && 'settings__section--collapsible', collapsible && !open && 'collapsed')}
      id={id} aria-labelledby={`${id}-title`}>
      {collapsible ? (
        <button className="settings__head settings__head--btn" onClick={toggle} aria-expanded={open} aria-controls={`${id}-body`}>
          <div>
            <div className="settings__title" id={`${id}-title`}>{title}</div>
            <div className="settings__desc">{desc}</div>
          </div>
          <Icon.Chevron className="settings__caret" />
        </button>
      ) : (
        <div className="settings__head">
          <div className="settings__title" id={`${id}-title`}>{title}</div>
          <div className="settings__desc">{desc}</div>
        </div>
      )}
      {open && <div className="settings__body" id={`${id}-body`}>{children}</div>}
      {open && footer && <div className="settings__foot">{footer}</div>}
    </section>
  );
}

/* ───────── Appearance ───────── */
function Appearance({ settings }: { settings: Settings }) {
  const { theme, density, font, mono, setTheme, setDensity, setFont, setMono } = useTheme();
  const save = useSaveSettings();
  const toast = useToast();
  const pick = (t: ThemeName) => {
    setTheme(t);
    if (settings.theme !== t) save.mutate({ theme: t }, { onError: (e) => toast.error('Theme saved locally only', e) });
  };
  return (
    <Section id="appearance" title="Appearance" desc="theme, fonts and density · applied instantly, persisted in this browser (the theme also on the server)">
      <div className="themes" role="radiogroup" aria-label="Theme">
        {THEMES.map((t) => {
          const s = t.swatch;
          return (
            <button key={t.id} role="radio" aria-checked={theme === t.id} className={cx('theme-card', theme === t.id && 'on')} onClick={() => pick(t.id)}>
              <div className="theme-card__preview" style={{ background: s.bg, borderColor: s.border }}>
                <div className="theme-card__side" style={{ background: s.sidebar, borderColor: s.border }} />
                <div className="theme-card__main">
                  <div className="theme-card__line" style={{ background: s.text }} />
                  <div className="theme-card__line short" style={{ background: s.muted }} />
                  <div className="theme-card__line" style={{ background: s.muted, width: '55%' }} />
                  <div className="theme-card__accent" style={{ background: s.accent }} />
                </div>
              </div>
              <div className="theme-card__name">{t.name}</div>
              <div className="theme-card__desc">{t.desc}</div>
            </button>
          );
        })}
      </div>
      {/* Each option previews ITSELF: a font list that describes faces in the current face tells you
          nothing about the one you are choosing. */}
      <div className="field">
        <span className="field__label">Interface font</span>
        <div className="fontpick" role="radiogroup" aria-label="Interface font">
          {UI_FONTS.map((f) => (
            <button key={f.id} role="radio" aria-checked={font === f.id}
              className={cx('fontpick__item', font === f.id && 'on')} onClick={() => setFont(f.id)}
              title={f.desc}>
              <span className="fontpick__sample" style={{ fontFamily: f.stack }}>Aa</span>
              <span className="fontpick__name" style={{ fontFamily: f.stack }}>{f.name}</span>
            </button>
          ))}
        </div>
      </div>
      <div className="field">
        <span className="field__label">Monospace font</span>
        <div className="fontpick" role="radiogroup" aria-label="Monospace font">
          {MONO_FONTS.map((f) => (
            <button key={f.id} role="radio" aria-checked={mono === f.id}
              className={cx('fontpick__item', mono === f.id && 'on')} onClick={() => setMono(f.id)}
              title={f.desc}>
              <span className="fontpick__name" style={{ fontFamily: f.stack }}>{f.name}</span>
            </button>
          ))}
        </div>
        <div className="field__hint">
          Used for every log line, event id, address and hash. All faces are bundled with Iris — nothing
          is fetched at runtime.
        </div>
      </div>
      <div className="field">
        <span className="field__label">Density</span>
        <div className="density" role="radiogroup" aria-label="Density">
          {(['comfortable', 'compact'] as Density[]).map((d) => (
            <button key={d} role="radio" aria-checked={density === d} className={cx('chip', density === d && 'on')} onClick={() => setDensity(d)}>
              {d}
            </button>
          ))}
        </div>
        <div className="field__hint">Compact tightens the type scale and row padding for large monitors.</div>
      </div>
    </Section>
  );
}

/* ───────── Machine + worker sizing ─────────
   What the process can actually use (not the host's core count — a container quota or the WSL VM's
   allotment is what decides) and the worker pools Iris derived from it, with the reasoning. The
   numbers are the answer to "is it using all my cores?", so they are printed, not implied. */
function ResourceBlock({ r }: { r: NonNullable<ComputeStatus['resources']> }) {
  const { machine: m, profile: p } = r;
  const gb = (mb: number) => `${(mb / 1024).toFixed(1)} GB`;
  const pinned = Object.entries(p.pinned ?? {});
  return (
    <div className="field">
      <span className="field__label">Machine &amp; worker sizing</span>
      <div className="compute-head">
        <span className="badge">{m.cpuUsable} usable cores{m.cpuUsable !== m.cpuLogical ? ` of ${m.cpuLogical}` : ''} · {m.cpuPhysical} physical</span>
        {m.cpuQuota != null && <span className="badge badge--warn">container CPU quota {m.cpuQuota}</span>}
        <span className="badge">{m.memTotalMB ? `${gb(m.memAvailableMB)} free of ${gb(m.memTotalMB)}` : 'memory unknown'}</span>
        {m.memLimitMB != null && <span className="badge badge--warn">memory limit {gb(m.memLimitMB)}</span>}
        <span className="badge">{m.container ? 'container' : m.platform}</span>
      </div>
      <div className="res-grid">
        <div className="res-tile"><span className="res-tile__n">{p.parseWorkers}</span><span className="res-tile__l">parse workers<br /><span className="muted">files over the parallel threshold</span></span></div>
        <div className="res-tile"><span className="res-tile__n">{p.graphWorkers}</span><span className="res-tile__l">graph workers<br /><span className="muted">entity extraction</span></span></div>
        <div className="res-tile"><span className="res-tile__n">{p.enrichWorkers}</span><span className="res-tile__l">enrichment lanes<br /><span className="muted">small sources, in parallel</span></span></div>
      </div>
      <div className="field__hint">
        {p.reasons.map((line, i) => <div key={i}>{line}</div>)}
        {pinned.length > 0
          ? <div>Pinned by environment: {pinned.map(([k, v]) => `${k}=${v}`).join(', ')} — unset to let Iris size it.</div>
          : <div>Sized automatically on every start. IRIS_PARSE_WORKERS, IRIS_GRAPH_WORKERS and IRIS_ENRICH_WORKERS pin any one of them.</div>}
      </div>
    </div>
  );
}

/* ───────── Compute ───────── */
function Compute({ settings }: { settings: Settings }) {
  const qc = useQueryClient();
  const toast = useToast();
  const status = useQuery({ queryKey: qk.compute, queryFn: api.compute, refetchInterval: 30_000 });
  const recheck = useMutation({
    mutationFn: api.recheckCompute,
    onSuccess: (s) => qc.setQueryData(qk.compute, s),
    onError: (e) => toast.error('Re-check failed', e),
  });
  const save = useSaveSettings();
  const s = status.data;
  const mode = settings.compute.mode;
  const setMode = (m: ComputeMode) => save.mutate({ compute: { mode: m } }, { onSuccess: () => toast.success('Compute mode saved', COMPUTE_MODES.find((x) => x.id === m)?.title), onError: (e) => toast.error('Could not save compute mode', e) });
  // Two-phase ingest: on by default, and absent settings must read as ON — the shipped behaviour is
  // that a file interprets itself, and defaulting a missing flag to OFF would silently leave a whole
  // workspace raw.
  const autoEnrich = settings.ingest?.autoEnrich !== false;
  const setAutoEnrich = (v: boolean) => save.mutate({ ingest: { autoEnrich: v } }, {
    onSuccess: () => toast.success(v ? 'Sources are interpreted automatically' : 'Enrichment is on demand',
      v ? 'Each upload is queued for the full parse as it lands.'
        : 'New uploads stay raw and searchable until you enrich them from the Sources row.'),
    onError: (e) => toast.error('Could not save the ingest setting', e),
  });

  return (
    <Section id="compute" title="Compute" desc="where parsing runs · detection and correlation always run in the background"
      footer={<>
        <button className="btn btn--sm" onClick={() => recheck.mutate()} disabled={recheck.isPending || s?.checking}>{(recheck.isPending || s?.checking) ? <span className="btn__spinner" /> : <Icon.Refresh />}Re-check now</button>
        <span className="field__hint">Last check {s ? `${fmtRelative(s.lastCheck)} (${fmtTs(s.lastCheck)} UTC)` : '—'} · polls every 30s</span>
      </>}
    >
      {status.isLoading && <Loading inline label="Probing compute backends…" />}
      {status.isError && <ErrorState inline title="Compute status unavailable" error={status.error} onRetry={() => void status.refetch()} />}
      {s && (
        <>
          <div className="compute-head">
            <span className={cx('badge', s.active === 'cuda' ? 'badge--ok' : 'badge--warn')}><span className="badge__dot" />{s.active === 'cuda' ? 'CUDA' : 'CPU'} active</span>
            <span className="badge">backend · {s.backend}</span>
            {s.cudaVersion && <span className="badge">CUDA {s.cudaVersion}</span>}
            <span className="badge">{s.available ? 'GPU available' : 'no GPU detected'}</span>
            <span className="badge">pref · {s.mode}</span>
          </div>
          {s.error && <div className="compute-error">{s.error}</div>}
          {s.note && <div className="compute-note">{s.note}</div>}
          <div className="gpu-list">
            {s.gpus.length === 0 && <div className="field__hint">No CUDA devices reported. Install a CUDA-enabled build (see backend/requirements-gpu.txt) and re-check.</div>}
            {s.gpus.map((g) => {
              const p = g.memoryTotalMB > 0 ? (g.memoryUsedMB / g.memoryTotalMB) * 100 : 0;
              return (
                <div key={g.index} className="gpu">
                  <div className="gpu__row">
                    <span className="gpu__name">#{g.index} · {g.name}</span>
                    <span className="gpu__mem">{fmtMB(g.memoryUsedMB)} / {fmtMB(g.memoryTotalMB)}{g.driver ? ` · driver ${g.driver}` : ''}</span>
                  </div>
                  <Bar pct={p} color={p > 90 ? 'var(--bad)' : p > 70 ? 'var(--warn)' : 'var(--accent)'} />
                </div>
              );
            })}
          </div>
        </>
      )}
      {s?.resources && <ResourceBlock r={s.resources} />}
      <div className="field">
        <span className="field__label">Live processing &amp; performance</span>
        <PerfPanel />
      </div>
      <div className="field">
        <span className="field__label">Parsing backend preference</span>
        <div className="compute-modes" role="radiogroup" aria-label="Compute mode">
          {COMPUTE_MODES.map((m) => (
            <label key={m.id} className={cx('radio', mode === m.id && 'on')}>
              <input type="radio" name="compute-mode" checked={mode === m.id} onChange={() => setMode(m.id)} disabled={save.isPending} />
              <div>
                <div className="radio__title">{m.title}</div>
                <div className="radio__desc">{m.desc}</div>
              </div>
            </label>
          ))}
        </div>
        <div className="field__hint">Only the parse/normalize stage is accelerated. Sigma detection, correlation and entity linking run as background jobs after ingest, on either backend.</div>
      </div>
      {/* Two-phase ingest. It belongs next to the parsing preference because that is exactly what it
          schedules: WHEN the expensive parse runs, not whether it runs. */}
      <div className="field">
        <span className="field__label">Two-phase ingest</span>
        <Toggle on={autoEnrich} onChange={setAutoEnrich} disabled={save.isPending}
          label="Interpret each source automatically after upload" />
        <div className="field__hint">
          Phase 1 lands every line of a log in the pool the moment it arrives: searchable at once, but with
          no timestamp, no severity, no parsed fields and no entities. Phase 2 runs the real parser and
          normalization on a background worker, one source at a time, and replaces that source's events in
          place — their ids do not move.
        </div>
        <div className="field__hint">
          {autoEnrich
            ? 'On — every upload is queued for phase 2 as it lands, so a file interprets itself without being asked.'
            : 'Off — nothing is interpreted until you ask for it, file by file, with “Enrich now” on the Sources row. Every new log stays raw text, and the case timeline, the entity graph and the anomaly list answer over only the sources you have enriched.'}
        </div>
      </div>
    </Section>
  );
}

/* ───────── AI (OpenAI only) ───────── */
function AiAssistant({ settings }: { settings: Settings }) {
  const toast = useToast();
  const save = useSaveSettings();
  const [enabled, setEnabled] = useState(settings.ai.provider === 'openai');
  const [model, setModel] = useState(settings.ai.model || DEFAULT_MODEL);
  const [baseUrl, setBaseUrl] = useState(settings.ai.baseUrl);
  const [apiKey, setApiKey] = useState('');
  const [agents, setAgents] = useState(settings.ai.agents || 1);
  const [test, setTest] = useState<AiTestResult | null>(null);
  const [showKey, setShowKey] = useState(false);
  const [advanced, setAdvanced] = useState(!!settings.ai.baseUrl || settings.ai.verifyTls === false);
  const [verifyTls, setVerifyTls] = useState(settings.ai.verifyTls !== false);
  const [caBundle, setCaBundle] = useState(settings.ai.caBundle ?? '');
  const masked = settings.ai.apiKey;

  // Re-seed the form ONLY when the server values actually change. Depending on `settings.ai` (a fresh object on
  // every settings refetch) wiped whatever was half-typed — including the API key — whenever anything invalidated
  // the settings query, which is what made the key field look like it kept going blank on its own.
  const serverSnapshot = JSON.stringify(settings.ai);
  const lastSnapshot = useRef<string | null>(null);
  useEffect(() => {
    if (lastSnapshot.current === serverSnapshot) return;
    lastSnapshot.current = serverSnapshot;
    setEnabled(settings.ai.provider === 'openai');
    setModel(settings.ai.model || DEFAULT_MODEL);
    setBaseUrl(settings.ai.baseUrl);
    setAgents(settings.ai.agents || 1);
    setApiKey('');
    setVerifyTls(settings.ai.verifyTls !== false);
    setCaBundle(settings.ai.caBundle ?? '');
    if (settings.ai.baseUrl || settings.ai.verifyTls === false) setAdvanced(true);
  }, [serverSnapshot, settings.ai]);

  const provider = enabled ? 'openai' : 'none';
  const dirty = provider !== settings.ai.provider || model !== (settings.ai.model || DEFAULT_MODEL) || baseUrl !== settings.ai.baseUrl || agents !== settings.ai.agents || apiKey !== ''
    || verifyTls !== (settings.ai.verifyTls !== false) || caBundle !== (settings.ai.caBundle ?? '');

  const testMut = useMutation({
    mutationFn: () => api.aiTest({ provider: 'openai', model: model || DEFAULT_MODEL, baseUrl, apiKey: apiKey || masked, verifyTls, caBundle }),
    onSuccess: (r) => setTest(r),
    onError: (e) => setTest({ ok: false, message: e instanceof Error ? e.message : 'Test failed' }),
  });

  const onSave = () => {
    const patch: Partial<Settings['ai']> = { provider, model: model || DEFAULT_MODEL, baseUrl: baseUrl.trim(), agents, verifyTls, caBundle: caBundle.trim() };
    if (apiKey) patch.apiKey = apiKey;
    save.mutate({ ai: patch }, {
      onSuccess: () => { toast.success('AI settings saved', enabled ? `OpenAI · ${model || DEFAULT_MODEL}` : 'Assistant disabled'); setApiKey(''); },
      onError: (e) => toast.error('Could not save AI settings', e),
    });
  };

  return (
    <Section id="ai" title="AI assistant" desc="parallel analysis agents over the case · keys are stored server-side and masked on read" collapsible
      footer={<>
        <button className="btn btn--primary" onClick={onSave} disabled={save.isPending || !dirty}>{save.isPending && <span className="btn__spinner" />}Save</button>
        {enabled && (
          <button className="btn" onClick={() => testMut.mutate()} disabled={testMut.isPending || (!apiKey && !masked)}>{testMut.isPending && <span className="btn__spinner" />}Test connection</button>
        )}
        {test && (
          <span className={cx('badge', test.ok ? 'badge--ok' : 'badge--bad')} title={test.message}>
            <span className="badge__dot" />{test.ok ? 'connected' : 'failed'}{test.latencyMs !== undefined ? ` · ${test.latencyMs} ms` : ''}
          </span>
        )}
        {test && <span className="field__hint ellipsis" style={{ maxWidth: 420 }} title={test.message}>{test.message}</span>}
        {dirty && !save.isPending && <span className="field__hint" style={{ marginLeft: 'auto' }}>unsaved changes</span>}
      </>}
    >
      <div className="ai-toggle-row">
        <Toggle on={enabled} onChange={(v) => { setEnabled(v); setTest(null); }} label="Enable AI assistant" />
        <span className="field__hint">{enabled ? 'Triage, timeline, entity and IOC agents run in parallel on the backend and stream into the assistant panel.' : 'AI features are hidden; nothing leaves this machine.'}</span>
      </div>
      {enabled && (
        <>
          <div className="form-grid">
            <div className="field">
              <span className="field__label">Provider</span>
              <div className="provider-fixed">
                <span className="provider-fixed__name">OpenAI</span>
                <span className="pill pill--muted">fixed</span>
              </div>
              <div className="field__hint">Chat Completions API. Any OpenAI-compatible endpoint works via the base URL override under Advanced.</div>
            </div>
            <div className="field">
              <label className="field__label" htmlFor="ai-model">Model</label>
              <input id="ai-model" value={model} onChange={(e) => setModel(e.target.value)} placeholder={DEFAULT_MODEL} spellCheck={false} />
              <div className="field__hint">Default: {DEFAULT_MODEL}. Any chat-capable model name the endpoint accepts.</div>
            </div>
            <div className="field" style={{ gridColumn: '1 / -1' }}>
              <label className="field__label" htmlFor="ai-key">
                API key
                {/* the input is write-only by design — this badge is how you can tell a key is actually stored */}
                {masked && <span className="badge badge--ok" style={{ marginLeft: 8 }} title="A key is saved on the server">stored · {masked}</span>}
              </label>
              <div className="form-row">
                <input id="ai-key" type={showKey ? 'text' : 'password'} value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder={masked ? `${masked} (stored — leave blank to keep)` : 'sk-…'} autoComplete="off" spellCheck={false} />
                <button className="btn btn--sm btn--ghost" onClick={() => setShowKey((s) => !s)} aria-label={showKey ? 'Hide key' : 'Show key'}>{showKey ? 'hide' : 'show'}</button>
              </div>
              <div className="field__hint">{masked ? `A key is stored (${masked}). Type a new one to replace it.` : 'No key stored yet.'}</div>
            </div>
          </div>
          <div className="field">
            <label className="field__label" htmlFor="ai-agents">Parallel analysis agents</label>
            <div className="slider-row">
              <input id="ai-agents" type="range" min={1} max={4} step={1} value={agents} onChange={(e) => setAgents(Number(e.target.value))} />
              <span className="slider-row__val">{agents}</span>
              <span className="field__hint">{['', 'triage only', 'triage + timeline', 'triage + timeline + entities', 'triage + timeline + entities + IOCs'][agents]} → synthesizer</span>
            </div>
          </div>
          <div className="advanced">
            <button className="advanced__head" onClick={() => setAdvanced((a) => !a)} aria-expanded={advanced}>
              <Icon.Chevron className={cx('advanced__caret', advanced && 'open')} />
              Advanced
              {baseUrl && !advanced && <span className="pill pill--accent" style={{ marginLeft: 8 }}>base URL set</span>}
            </button>
            {advanced && (
              <div className="advanced__body">
                <div className="field">
                  <label className="field__label" htmlFor="ai-base">Base URL override (OpenAI-compatible endpoints)</label>
                  <input id="ai-base" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="https://api.openai.com/v1" spellCheck={false} />
                  <div className="field__hint">Leave blank for api.openai.com. Set for a proxy/gateway or a local server speaking the OpenAI chat-completions API (Ollama http://localhost:11434/v1, LM Studio http://localhost:1234/v1, vLLM, OpenRouter…).</div>
                </div>
                <div className="field">
                  <label className="field__label" htmlFor="ai-ca">Custom CA bundle (PEM path inside the container)</label>
                  <input id="ai-ca" value={caBundle} onChange={(e) => setCaBundle(e.target.value)} placeholder="auto: /data/ca.pem · $IRIS_CA_BUNDLE · system store" spellCheck={false} />
                  <div className="field__hint">
                    Behind a corporate proxy / antivirus that re-signs HTTPS (error <span className="mono">CERTIFICATE_VERIFY_FAILED … self-signed</span>)? Export its root CA as PEM and
                    drop it in the data volume: <span className="mono">docker cp corp-root.pem iris:/data/ca.pem</span> — picked up automatically, no restart needed.
                  </div>
                </div>
                <div className="field">
                  <div className="ai-toggle-row">
                    <Toggle on={verifyTls} onChange={setVerifyTls} label="Verify TLS certificates" />
                  </div>
                  <div className="field__hint">
                    {verifyTls ? 'Recommended. Certificates are validated against the CA bundle above / the system store.' : <span style={{ color: 'var(--warn)' }}>Verification disabled — your API key is exposed to anyone able to intercept traffic. Only use on trusted networks as a last resort.</span>}
                  </div>
                </div>
              </div>
            )}
          </div>
        </>
      )}
    </Section>
  );
}

/* ───────── System prompts ─────────
   Standing instructions for the investigator, saved on the server. The built-in prompt carries the
   operating rules the loop depends on (answer first, cite real ids, record as you go, the search DSL);
   an `extend` prompt is appended to it, a `replace` prompt is sent instead of it. One of them can be
   the default; the panel can pick another per run.                                                  */
const MODE_HELP: Record<SystemPromptMode, string> = {
  extend: 'Added to the built-in prompt as an "Analyst instructions" section — the tool discipline and citation rules stay in force.',
  replace: 'Sent INSTEAD of the built-in prompt, verbatim. Iris still refuses invented event ids and still sends its record / summary nudges; everything else the model knows about the workspace has to be in your text.',
};

function SystemPrompts({ settings }: { settings: Settings }) {
  const toast = useToast();
  const qc = useQueryClient();
  const save = useSaveSettings();
  const list = useQuery({ queryKey: qk.aiSystemPrompts, queryFn: api.aiSystemPrompts });
  const prompts = list.data?.prompts ?? [];
  const activeId = settings.ai.systemPromptId ?? '';

  const [editing, setEditing] = useState<SystemPrompt | 'new' | null>(null);
  const [name, setName] = useState('');
  const [text, setText] = useState('');
  const [mode, setMode] = useState<SystemPromptMode>('extend');
  const [confirmDel, setConfirmDel] = useState<SystemPrompt | null>(null);
  const [showBuiltin, setShowBuiltin] = useState(false);
  const [effective, setEffective] = useState<{ id: string; text: string } | null>(null);

  const invalidate = () => { void qc.invalidateQueries({ queryKey: qk.aiSystemPrompts }); };
  const open = (p: SystemPrompt | 'new') => {
    setEditing(p);
    setEffective(null);
    if (p === 'new') { setName(''); setText(''); setMode('extend'); } else { setName(p.name); setText(p.text); setMode(p.mode); }
  };
  const close = () => { setEditing(null); setEffective(null); };

  const upsert = useMutation({
    mutationFn: () => editing === 'new' || !editing
      ? api.aiCreateSystemPrompt({ name: name.trim(), text, mode })
      : api.aiUpdateSystemPrompt(editing.id, { name: name.trim(), text, mode }),
    onSuccess: (row) => { toast.success(editing === 'new' ? 'System prompt saved' : 'System prompt updated', row.name); invalidate(); close(); },
    onError: (e) => toast.error('Could not save the system prompt', e),
  });
  const del = useMutation({
    mutationFn: (p: SystemPrompt) => api.aiDeleteSystemPrompt(p.id),
    onSuccess: (r, p) => {
      toast.success('System prompt deleted', r.defaultReset ? `${p.name} — the assistant is back on the built-in prompt` : p.name);
      setConfirmDel(null);
      if (editing && editing !== 'new' && editing.id === p.id) close();
      invalidate();
      if (r.defaultReset) void qc.invalidateQueries({ queryKey: qk.settings });
    },
    onError: (e) => toast.error('Could not delete the system prompt', e),
  });
  const setDefault = (id: string) => {
    save.mutate({ ai: { systemPromptId: id } }, {
      onSuccess: () => toast.success('Default system prompt', id ? (prompts.find((p) => p.id === id)?.name ?? id) : 'Built-in prompt'),
      onError: (e) => toast.error('Could not change the default prompt', e),
    });
  };
  const viewEffective = (p: SystemPrompt) => {
    if (effective?.id === p.id) { setEffective(null); return; }
    api.aiEffectiveSystemPrompt(p.id).then((r) => setEffective({ id: p.id, text: r.text })).catch((e) => toast.error('Could not load the effective prompt', e));
  };

  const canSave = !!name.trim() && !!text.trim() && !upsert.isPending;
  const dirty = editing === 'new' ? (!!name || !!text) : editing ? (name !== editing.name || text !== editing.text || mode !== editing.mode) : false;

  return (
    <Section id="prompts" title="System prompts" desc="standing instructions for the AI assistant · saved on this server · one is the default, the panel can pick another per run" collapsible
      footer={<>
        {editing ? (
          <>
            <button className="btn btn--primary" onClick={() => upsert.mutate()} disabled={!canSave || !dirty}>{upsert.isPending && <span className="btn__spinner" />}{editing === 'new' ? 'Save prompt' : 'Save changes'}</button>
            <button className="btn" onClick={close} disabled={upsert.isPending}>Cancel</button>
            {dirty && !upsert.isPending && <span className="field__hint" style={{ marginLeft: 'auto' }}>unsaved changes</span>}
          </>
        ) : (
          <button className="btn btn--primary" onClick={() => open('new')}><Icon.Plus /> New system prompt</button>
        )}
      </>}
    >
      {list.isError && <ErrorState inline title="System prompts unavailable" error={list.error} onRetry={() => void list.refetch()} />}

      <div className="field">
        <label className="field__label" htmlFor="sp-default">Default prompt</label>
        <select id="sp-default" value={activeId} onChange={(e) => setDefault(e.target.value)} disabled={save.isPending}>
          <option value="">Built-in prompt only</option>
          {prompts.map((p) => <option key={p.id} value={p.id}>{p.name} · {p.mode}</option>)}
        </select>
        <div className="field__hint">Used by every investigation unless the assistant panel picks another for that run. The built-in prompt is what Iris ships with — how to search, how to cite, when to stop.</div>
      </div>

      {prompts.length > 0 && (
        <ul className="sp-list" aria-label="Saved system prompts">
          {prompts.map((p) => (
            <li key={p.id} className={cx('sp-row', editing !== 'new' && editing?.id === p.id && 'sp-row--editing')}>
              <div className="sp-row__main">
                <div className="sp-row__name">
                  {p.name}
                  <span className={cx('pill', p.mode === 'replace' ? 'pill--accent' : 'pill--muted')} title={MODE_HELP[p.mode]}>{p.mode === 'replace' ? 'replaces built-in' : 'extends built-in'}</span>
                  {p.id === activeId && <span className="badge badge--ok"><span className="badge__dot" />default</span>}
                </div>
                <div className="sp-row__meta" title={fmtTs(p.updatedAt)}>{p.text.length.toLocaleString()} characters · updated {fmtRelative(p.updatedAt)}</div>
              </div>
              <div className="sp-row__actions">
                {p.id !== activeId && <button className="btn btn--sm btn--ghost" onClick={() => setDefault(p.id)} disabled={save.isPending}>Use by default</button>}
                <button className="btn btn--sm" onClick={() => viewEffective(p)} aria-expanded={effective?.id === p.id}>{effective?.id === p.id ? 'Hide effective' : 'View effective'}</button>
                <button className="btn btn--sm" onClick={() => open(p)}>Edit</button>
                <button className="btn btn--sm btn--ghost" onClick={() => setConfirmDel(p)} aria-label={`Delete ${p.name}`}><Icon.Trash /> Delete</button>
              </div>
              {effective?.id === p.id && (
                <div className="sp-row__effective">
                  <div className="field__hint">Exactly what the model receives as its system message with this prompt selected.</div>
                  <pre className="sp-pre">{effective.text}</pre>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      {!list.isLoading && prompts.length === 0 && !editing && (
        <div className="field__hint">No saved prompts yet. The assistant runs on the built-in prompt. Save one to give it standing instructions — a report format, what counts as critical in your environment, sources to distrust, a language.</div>
      )}

      {editing && (
        <div className="sp-editor">
          <div className="form-grid">
            <div className="field">
              <label className="field__label" htmlFor="sp-name">Name</label>
              <input id="sp-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. House report format" maxLength={120} spellCheck={false} autoFocus />
            </div>
            <div className="field">
              <span className="field__label">Mode</span>
              <div className="sp-modes" role="radiogroup" aria-label="How the prompt is used">
                {(['extend', 'replace'] as SystemPromptMode[]).map((m) => (
                  <label key={m} className={cx('sp-mode', mode === m && 'active')}>
                    <input type="radio" name="sp-mode" value={m} checked={mode === m} onChange={() => setMode(m)} />
                    <span className="sp-mode__name">{m === 'extend' ? 'Extend the built-in prompt' : 'Replace the built-in prompt'}</span>
                    <span className="sp-mode__desc">{MODE_HELP[m]}</span>
                  </label>
                ))}
              </div>
            </div>
          </div>
          <div className="field">
            <label className="field__label" htmlFor="sp-text">Prompt text</label>
            <textarea id="sp-text" className="sp-textarea" value={text} onChange={(e) => setText(e.target.value)} rows={12} spellCheck={false}
              placeholder={mode === 'extend'
                ? 'Standing instructions, e.g. "Write findings in British English. Treat anything from 10.0.0.0/8 as internal. Every note ends with a confidence rating."'
                : 'The whole system prompt. The built-in one is shown below for reference — copy what you need from it.'} />
            <div className="field__hint">{text.length.toLocaleString()} / 40,000 characters. {mode === 'replace' && <span style={{ color: 'var(--warn)' }}>Replace mode drops the built-in guidance on the search DSL, aggregation tools and stopping rules — the assistant will only know what you tell it here.</span>}</div>
          </div>
        </div>
      )}

      <div className="advanced">
        <button className="advanced__head" onClick={() => setShowBuiltin((v) => !v)} aria-expanded={showBuiltin}>
          <Icon.Chevron className={cx('advanced__caret', showBuiltin && 'open')} />
          Built-in prompt
          <span className="field__hint" style={{ marginLeft: 8 }}>read-only · {list.data ? `${list.data.builtin.length.toLocaleString()} characters` : ''}</span>
        </button>
        {showBuiltin && (
          <div className="advanced__body">
            <pre className="sp-pre">{list.data?.builtin ?? ''}</pre>
          </div>
        )}
      </div>

      <ConfirmDialog open={!!confirmDel} title="Delete this system prompt?" danger busy={del.isPending}
        text={confirmDel ? `"${confirmDel.name}" will be removed.${confirmDel.id === activeId ? ' It is the default — the assistant goes back to the built-in prompt.' : ''} Conversations already run on it are unaffected.` : ''}
        confirmLabel="Delete" onConfirm={() => confirmDel && del.mutate(confirmDel)} onCancel={() => setConfirmDel(null)} />
    </Section>
  );
}

/* ───────── MCP server ─────────
   Iris as a tool PROVIDER: the same registry the built-in investigator drives, offered over MCP so
   Cursor / Claude Code / Claude Desktop can query the evidence pool. Two switches, because they carry
   different risk: `enabled` exposes the pool to a remote model at all, `allowWrites` lets it curate
   the case. Off by default — this panel is where the analyst turns it on knowingly.                  */
function CopyBlock({ label, text, hint }: { label: string; text: string; hint?: React.ReactNode }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setDone(true);
      window.setTimeout(() => setDone(false), 1600);
    } catch { /* clipboard blocked (http origin / permissions) — the text is on screen and selectable */ }
  };
  return (
    <div className="mcp-block">
      <div className="mcp-block__head">
        <span className="field__label">{label}</span>
        <button className="btn btn--sm btn--ghost" onClick={() => void copy()}>{done ? 'copied' : 'copy'}</button>
      </div>
      <pre className="mcp-code"><code>{text}</code></pre>
      {hint && <div className="field__hint">{hint}</div>}
    </div>
  );
}

const MCP_CLIENTS = [
  { id: 'cursor', label: 'Cursor' },
  { id: 'claude-code', label: 'Claude Code' },
  { id: 'desktop', label: 'Claude Desktop / stdio' },
] as const;
type McpClientId = (typeof MCP_CLIENTS)[number]['id'];

/**
 * Sign-in: a password and a PIN, both required, both hashed server-side (PBKDF2-HMAC-SHA256) in
 * `auth.json` — never in settings.json, never returned by any endpoint.
 *
 * What this is and is not, stated on the screen because the difference matters: it keeps a person at
 * this machine, and a page open in this browser, out of the pool. It is not encryption of the
 * evidence, and it is not a second CHANNEL — a PIN stored beside the password is not MFA. The other
 * control, `IRIS_AUTH_TOKEN`, is for headless clients and is set where the process is started, which
 * is why it cannot be edited here.
 */
function SecuritySection() {
  const toast = useToast();
  const qc = useQueryClient();
  const status = useAuthStatus();
  const [password, setPassword] = useState('');
  const [pin, setPin] = useState('');
  const [confirm, setConfirm] = useState('');
  const [confirmRemove, setConfirmRemove] = useState(false);

  const refresh = () => { void qc.invalidateQueries({ queryKey: ['auth-status'] }); void qc.invalidateQueries({ queryKey: qk.settings }); };
  const clear = () => { setPassword(''); setPin(''); setConfirm(''); };

  const save = useMutation({
    mutationFn: () => api.setCredentials(password, pin, true),
    onSuccess: () => { clear(); refresh(); toast.success('Sign-in enabled', 'You stay signed in on this browser; other tabs and devices will be asked.'); },
    onError: (e) => toast.error('Could not set the sign-in', e),
  });
  const toggle = useMutation({
    mutationFn: (on: boolean) => api.setLoginEnabled(on),
    onSuccess: (st) => { refresh(); toast.success(st.enabled ? 'Sign-in required' : 'Sign-in switched off', st.enabled ? undefined : 'The password and PIN are kept, so you can switch it back on without retyping them.'); },
    onError: (e) => toast.error('Could not change the sign-in', e),
  });
  const remove = useMutation({
    mutationFn: () => api.clearCredentials(),
    onSuccess: () => { setConfirmRemove(false); refresh(); toast.info('Sign-in removed', 'Anything that can reach this port can read the pool again.'); },
    onError: (e) => toast.error('Could not remove the sign-in', e),
  });
  const signOut = useMutation({
    mutationFn: () => api.logout(),
    onSuccess: () => { void qc.invalidateQueries(); },
    onError: (e) => toast.error('Could not sign out', e),
  });

  const minPw = status.data?.minPassword ?? 8;
  const minPin = status.data?.minPin ?? 4;
  const maxPin = status.data?.maxPin ?? 12;
  const configured = !!status.data?.configured;
  const enabled = !!status.data?.enabled;
  const mismatch = confirm.length > 0 && confirm !== password;
  const ready = password.length >= minPw && pin.length >= minPin && pin.length <= maxPin
    && /^\d+$/.test(pin) && confirm === password && pin !== password;

  return (
    <Section id="security" title="Security"
      desc="who can open this workspace · credentials are hashed on this server and never returned by the API"
      collapsible defaultCollapsed>
      <div className="ai-toggle-row">
        <Toggle on={enabled} disabled={!configured || toggle.isPending}
          onChange={(v) => toggle.mutate(v)} label="Require sign-in" />
        <span className="field__hint">
          {enabled
            ? 'Every screen and every API call needs a session. Sign-in is per browser and lasts 12 hours.'
            : configured
              ? 'Off. The password and PIN are still stored — switching this on asks for them again.'
              : `Off. Set a password (${minPw}+ characters) and a PIN (${minPin}-${maxPin} digits) below to turn it on.`}
        </span>
      </div>

      <div className="field">
        <label className="field__label" htmlFor="sec-pw">{configured ? 'New password' : 'Password'}</label>
        <input id="sec-pw" type="password" autoComplete="new-password" value={password}
          onChange={(e) => setPassword(e.target.value)} placeholder={`at least ${minPw} characters`} />
      </div>
      <div className="field">
        <label className="field__label" htmlFor="sec-pw2">Confirm password</label>
        <input id="sec-pw2" type="password" autoComplete="new-password" value={confirm}
          onChange={(e) => setConfirm(e.target.value)} />
        {mismatch && <div className="field__hint" style={{ color: 'var(--bad)' }}>The two passwords do not match.</div>}
      </div>
      <div className="field">
        <label className="field__label" htmlFor="sec-pin">PIN</label>
        <input id="sec-pin" type="password" inputMode="numeric" autoComplete="off" value={pin}
          onChange={(e) => setPin(e.target.value.replace(/\D/g, '').slice(0, maxPin))}
          placeholder={`${minPin}-${maxPin} digits`} />
        <div className="field__hint">
          Asked for together with the password, on the same page. Both are stored on this server as
          salted hashes — they are not a second factor in the phone-app sense, and this screen will not
          pretend otherwise.
        </div>
      </div>

      <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
        <button className="btn btn--accent btn--sm" disabled={!ready || save.isPending} onClick={() => save.mutate()}>
          {save.isPending && <span className="btn__spinner" />}{configured ? 'Replace and require sign-in' : 'Set and require sign-in'}
        </button>
        {enabled && (
          <button className="btn btn--sm" disabled={signOut.isPending} onClick={() => signOut.mutate()}>Sign out of this browser</button>
        )}
        {configured && (
          <button className="btn btn--danger btn--sm" onClick={() => setConfirmRemove(true)}>Remove sign-in…</button>
        )}
      </div>

      <div className="field__hint" style={{ marginTop: 12 }}>
        Forgotten both? Delete <span className="mono">auth.json</span> from the data directory
        (<span className="mono">docker exec iris rm /data/auth.json</span>) — that needs access to the
        disk, which this control never claimed to defend against. For scripts and MCP clients that
        cannot sign in, set <span className="mono">IRIS_AUTH_TOKEN</span> where the server is started.
      </div>

      <ConfirmDialog
        open={confirmRemove}
        title="Remove the sign-in?"
        text={<>The password and PIN are deleted and this workspace opens without asking. Anything that can reach this port — including a page open in this browser — can read every ingested log and delete every case.</>}
        confirmLabel="Remove sign-in"
        danger
        onCancel={() => setConfirmRemove(false)}
        onConfirm={() => remove.mutate()}
      />
    </Section>
  );
}


function McpServer({ settings }: { settings: Settings }) {
  const toast = useToast();
  const save = useSaveSettings();
  const qc = useQueryClient();
  const [tab, setTab] = useState<McpClientId>('cursor');
  const [freshToken, setFreshToken] = useState('');
  const mcp = settings.mcp ?? { enabled: false, allowWrites: false, token: '' };

  const status = useQuery({ queryKey: ['mcp', 'status'], queryFn: api.mcpStatus, staleTime: 5_000 });
  const refresh = () => { void qc.invalidateQueries({ queryKey: ['mcp', 'status'] }); };

  const patch = (p: Partial<Settings['mcp']>, msg: string) =>
    save.mutate({ mcp: p }, {
      onSuccess: () => { toast.success(msg); refresh(); },
      onError: (e) => toast.error('Could not save MCP settings', e),
    });

  const newToken = useMutation({
    mutationFn: api.mcpNewToken,
    onSuccess: (r) => { setFreshToken(r.token); refresh(); toast.success('Token generated', 'Copy it now — it is masked from here on.'); },
    onError: (e) => toast.error('Could not generate a token', e),
  });

  const url = status.data?.url ?? `${window.location.origin}/api/mcp`;
  // The token is masked once stored, so a config snippet can only carry a real one right after it was
  // generated. Putting `••••1234` inside JSON the analyst is meant to paste would be a trap.
  const tokenForConfig = freshToken;
  const authLine = tokenForConfig ? `,\n      "headers": { "Authorization": "Bearer ${tokenForConfig}" }` : '';
  const cursorJson = `{\n  "mcpServers": {\n    "iris": {\n      "url": "${url}"${authLine}\n    }\n  }\n}`;
  const claudeCmd = `claude mcp add --transport http iris ${url}`
    + (tokenForConfig ? ` --header "Authorization: Bearer ${tokenForConfig}"` : '');
  const stdioEnv = tokenForConfig ? `,\n        "IRIS_MCP_TOKEN": "${tokenForConfig}"` : '';
  const stdioJson = `{\n  "mcpServers": {\n    "iris": {\n      "command": "python",\n      "args": ["<path to Iris>/mcp/iris-mcp-stdio.py"],\n      "env": {\n        "IRIS_URL": "${window.location.origin}"${stdioEnv}\n      }\n    }\n  }\n}`;

  const reads = status.data?.readTools ?? [];
  const writes = status.data?.writeTools ?? [];

  return (
    <Section id="mcp" title="MCP server"
      desc="expose this workspace to Cursor, Claude Code and other MCP clients · the same tools the built-in assistant uses"
      collapsible defaultCollapsed>
      <div className="ai-toggle-row">
        <Toggle on={mcp.enabled} onChange={(v) => patch({ enabled: v }, v ? 'MCP server enabled' : 'MCP server disabled')} label="Enable MCP server" />
        <span className="field__hint">
          {mcp.enabled
            ? (status.data && !status.data.serving
                ? <span style={{ color: 'var(--warn)' }}>{status.data.blockedReason}</span>
                : <>Serving at <span className="mono">{url}</span> — no restart needed.</>)
            : 'Off. Enabling lets any MCP client that can reach this port search the pool, read events and inspect detections.'}
        </span>
      </div>

      {mcp.enabled && (
        <>
          <div className="ai-toggle-row">
            <Toggle on={mcp.allowWrites} onChange={(v) => patch({ allowWrites: v }, v ? 'Write tools exposed' : 'Write tools hidden')} label="Allow write tools" />
            <span className="field__hint">
              {mcp.allowWrites
                ? <span style={{ color: 'var(--warn)' }}>A connected model can create a case, curate the case set, add indicators, notes, graph links and detection rules. Every change is attributed to the client in case.json — and nothing exposed here can delete a case, a source or your data.</span>
                : 'Read-only: search, aggregate, timeline, graph, detections, event detail. A write tool is not even listed to the client.'}
            </span>
          </div>

          <div className="field">
            <span className="field__label">
              Bearer token
              {status.data?.hasToken
                ? <span className="badge badge--ok" style={{ marginLeft: 8 }}>required · {status.data.token}</span>
                : <span className="badge badge--warn" style={{ marginLeft: 8 }}>none — the server refuses every request</span>}
            </span>
            <div className="form-row">
              <button className="btn btn--sm" onClick={() => newToken.mutate()} disabled={newToken.isPending}>
                {newToken.isPending && <span className="btn__spinner" />}{status.data?.hasToken ? 'Regenerate token' : 'Generate token'}
              </button>
              {status.data?.hasToken && (
                <button className="btn btn--sm btn--ghost" onClick={() => { setFreshToken(''); patch({ token: '' }, 'Token removed'); }}>Remove token</button>
              )}
            </div>
            {freshToken
              ? <div className="field__hint"><span className="mono">{freshToken}</span> — shown once. It is already filled into the snippets below.</div>
              : <div className="field__hint">
                  {status.data?.hasToken
                    ? 'A token is stored and is masked from here on. Regenerate to get a fresh one you can copy (existing clients must then be updated).'
                    : 'A token is required. Iris has no other authentication, so an untokened MCP endpoint would hand the whole evidence pool to anything that can reach this port — the server fails closed instead and answers 503 until you generate one.'}
                </div>}
          </div>

          <div className="field">
            <span className="field__label">Connect a client</span>
            <div className="mcp-tabs" role="tablist">
              {MCP_CLIENTS.map((c) => (
                <button key={c.id} role="tab" aria-selected={tab === c.id} className={cx('mcp-tab', tab === c.id && 'on')} onClick={() => setTab(c.id)}>{c.label}</button>
              ))}
            </div>

            {tab === 'cursor' && (
              <CopyBlock label="~/.cursor/mcp.json (global) or .cursor/mcp.json (this project)" text={cursorJson}
                hint={<>Cursor reads the same file in the editor and in the terminal CLI, so configure it once. Reload the window, then check <span className="mono">Settings → MCP</span>: <span className="mono">iris</span> should list {status.data?.toolCount ?? reads.length} tools. In the CLI, <span className="mono">cursor mcp list</span> shows which servers are connected. Ask for it by name — <span className="mono">&quot;Use iris to find every event for 10.0.0.100&quot;</span>. Not showing up? The JSON must be valid and the URL reachable from that machine.</>} />
            )}
            {tab === 'claude-code' && (
              <CopyBlock label="Run in your terminal" text={claudeCmd}
                hint={<>Adds Iris over HTTP transport. <span className="mono">claude mcp list</span> verifies it; <span className="mono">/mcp</span> inside a session shows the tools. Add <span className="mono">--scope project</span> to write it into the project&apos;s <span className="mono">.mcp.json</span> instead of your user config.</>} />
            )}
            {tab === 'desktop' && (
              <CopyBlock label="claude_desktop_config.json — for clients that can only launch a command" text={stdioJson}
                hint={<>Only needed where HTTP transport is unavailable. <span className="mono">mcp/iris-mcp-stdio.py</span> is a standard-library-only bridge that forwards to the URL above; it needs Python 3.9+ and a running Iris, and never parses logs itself — there is only ever one event pool.</>} />
            )}
          </div>

          <div className="field">
            <span className="field__label">What a client gets</span>
            <div className="field__hint">
              <span className="mono">{reads.length}</span> read tools{mcp.allowWrites ? <> and <span className="mono">{writes.length}</span> write tools</> : <> (write tools hidden)</>}
              {' · '}MCP protocol <span className="mono">{status.data?.protocol ?? '2025-06-18'}</span> · streamable HTTP
            </div>
            <details className="mcp-tools">
              <summary>List the tools</summary>
              <div className="mcp-tools__list">
                {reads.map((t) => <span key={t} className="pill pill--muted mono">{t}</span>)}
                {mcp.allowWrites && writes.map((t) => <span key={t} className="pill pill--accent mono">{t}</span>)}
              </div>
            </details>
          </div>

          <div className="field">
            <span className="field__label">What it needs</span>
            <ul className="mcp-req">
              <li>Iris running and reachable from the client machine — the snippets use this page&apos;s own origin.</li>
              <li>Evidence already ingested: the tools read the workspace pool, so an empty pool answers &quot;no events&quot;, not an error.</li>
              <li>A case only for the write tools that curate one. Search, graph, timeline and detections work with no case at all.</li>
              <li>If the client runs on another host, replace <span className="mono">localhost</span> with this machine&apos;s address and set a token.</li>
            </ul>
          </div>
        </>
      )}
    </Section>
  );
}

/* ───────── Case ───────── */

/* ───────── Data ───────── */
// Typed-to-confirm phrase for the workspace wipe. Same gate the Cases page puts in front of a case
// delete (type the case name) — this one has no name to type, so it is the action itself.
const CLEAR_PHRASE = 'clear all data';

function DataSection() {
  const c = useCase();
  const qc = useQueryClient();
  const toast = useToast();
  const nav = useNavigate();
  const invalidate = useInvalidateCaseData();
  const caseList = useCases();
  const library = useLibrary();
  const trash = useQuery({ queryKey: ['case-trash'], queryFn: api.caseTrash });
  const aiRuns = useQuery({ queryKey: ['ai-runs'], queryFn: () => api.aiRuns(100) });
  const [confirmReset, setConfirmReset] = useState(false);
  const [confirmClear, setConfirmClear] = useState(false);
  const [resetSettings, setResetSettings] = useState(false);
  const [clearConfirm, setClearConfirm] = useState('');
  const clearReady = clearConfirm.trim().toLowerCase() === CLEAR_PHRASE;

  const reset = useMutation({
    mutationFn: api.resetCase,
    onSuccess: (data) => {
      qc.setQueryData(qk.case, data);
      invalidate();
      setConfirmReset(false);
      toast.info('Case reset', 'All sources and events cleared');
    },
    onError: (e) => toast.error('Reset failed', e),
  });
  const clear = useMutation({
    mutationFn: () => api.clearAll(resetSettings),
    onSuccess: async (r) => {
      closeClear();
      const rm = r.removed;
      toast.success('All data cleared',
        `${fmtInt(rm.cases)} cases · ${fmtInt(rm.sources)} sources · ${fmtInt(rm.events)} events · ${fmtInt(rm.files)} files · ${fmtInt(rm.aiRuns)} AI conversations · ${fmtInt(rm.cache)} cache files removed${resetSettings ? ' · settings reset' : ''}`);
      // Every screen is now looking at data that no longer exists. resetQueries DROPS the cached
      // payloads (invalidate alone leaves stale rows on screen until each query refetches) and
      // refetches whatever is mounted, so the empty state shows immediately.
      await qc.resetQueries();
      nav('/ingest');
    },
    onError: (e) => toast.error('Clear failed', e),
  });

  const openClear = () => { setResetSettings(false); setClearConfirm(''); setConfirmClear(true); };
  /** Cancel / Escape / success all land here — the typed phrase never survives a close. */
  const closeClear = () => { setConfirmClear(false); setClearConfirm(''); };

  const d = c.data;
  const nCases = caseList.data?.length ?? 0;
  const nStaged = library.data?.filter((f) => f.caseId === '').length ?? 0;
  const nTrash = trash.data?.length ?? 0;
  const nAiRuns = aiRuns.data?.runs.length ?? 0;
  return (
    <Section id="data" title="Data" desc="what lives on this server, and how to remove it" danger collapsible defaultCollapsed>
      <div className="data-grid">
        <div className="card">
          <div className="card__head"><div className="card__title">Reset case</div><div className="card__desc">keeps settings and the API key</div></div>
          <div className="card__body">
            <div className="field__hint" style={{ marginBottom: 12 }}>
              Removes every source, event, pin and finding from the active case ({d ? `${d.sources.length} sources · ${fmtInt(d.eventCount)} events` : '…'}). Uploaded files are deleted; the case ID and your settings stay.
              Files staged in the library belong to no case and are left alone.
            </div>
            <button className="btn btn--danger btn--sm" onClick={() => setConfirmReset(true)}><Icon.Refresh />Reset case</button>
          </div>
        </div>
        <div className="card card--danger">
          <div className="card__head"><div className="card__title" style={{ color: 'var(--bad)' }}>Clear all data</div><div className="card__desc">the nuclear option</div></div>
          <div className="card__body">
            <div className="field__hint" style={{ marginBottom: 12 }}>
              Wipes the whole workspace: every case and its uploads, notes and attachments, the recently-deleted
              case bin, every file staged in the library, all parsed events, the upload history, every AI
              assistant conversation, and the derived caches on disk (the saved entity graph and the parsed-pool
              cache). Detection rules and your settings are kept. Cannot be undone.
            </div>
            <button className="btn btn--danger btn--sm" onClick={openClear}><Icon.Trash />Clear all data…</button>
          </div>
        </div>
      </div>
      <ConfirmDialog open={confirmReset} title="Reset this case?" text="All sources, events, pins and findings will be removed. This cannot be undone." confirmLabel="Reset case" danger busy={reset.isPending} onConfirm={() => reset.mutate()} onCancel={() => setConfirmReset(false)} />
      <ConfirmDialog
        open={confirmClear}
        title="Clear all data?"
        danger
        confirmLabel="Clear everything"
        busy={clear.isPending}
        confirmDisabled={!clearReady}
        text="Everything ingested on this server is deleted from disk and from memory. There is no undo and no trash to restore from."
        onConfirm={() => { if (clearReady) clear.mutate(); }}
        onCancel={closeClear}
      >
        <div className="case-del__list">
          <span className="case-del__n">{fmtInt(nCases)}</span>
          <span className="case-del__l">case{nCases === 1 ? '' : 's'} — uploads, notes, attachments, case set, manual IOCs, graph links</span>
          <span className="case-del__n">{fmtInt(nStaged)}</span>
          <span className="case-del__l">file{nStaged === 1 ? '' : 's'} staged in the library</span>
          <span className="case-del__n">{fmtInt(d?.poolEventCount ?? 0)}</span>
          <span className="case-del__l">parsed events in the workspace pool</span>
          <span className="case-del__n">{fmtInt(nTrash)}</span>
          <span className="case-del__l">recently deleted case{nTrash === 1 ? '' : 's'} — the bin is emptied too</span>
          {/* transcripts quote the evidence verbatim, so the analyst has to be told they go too */}
          <span className="case-del__n">{fmtInt(nAiRuns)}</span>
          <span className="case-del__l">AI assistant conversation{nAiRuns === 1 ? '' : 's'} — prompts, answers and the tool calls behind them</span>
        </div>
        <div className="field__hint">
          Kept: your detection rules (custom rules and edited built-ins) and your exclusions — both are
          configuration rather than evidence; clear them under Anomalies → Rules and Anomalies → Exclusions
          {resetSettings ? '.' : ', and your settings: theme, compute preference, analyst name and the stored AI key.'}
        </div>
        <label>
          <input type="checkbox" checked={resetSettings} onChange={(e) => setResetSettings(e.target.checked)} style={{ marginTop: 2 }} />
          <span>Also reset settings <span className="muted">(removes the API key, theme, compute preference and analyst name)</span></span>
        </label>
        <label className="case-del__prompt" htmlFor="clear-all-confirm">
          Type <code className="mono">{CLEAR_PHRASE}</code> to confirm.
        </label>
        <input
          id="clear-all-confirm"
          className="case-del__input"
          value={clearConfirm}
          onChange={(e) => setClearConfirm(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter' && clearReady && !clear.isPending) clear.mutate(); }}
          placeholder={CLEAR_PHRASE}
          autoComplete="off"
          spellCheck={false}
          aria-label="Type the confirmation phrase to clear all data"
          autoFocus
        />
      </ConfirmDialog>
    </Section>
  );
}

/**
 * The network posture, stated where it is configured. Every item here was found by a red team rather
 * than by this screen, and each one is invisible by nature: "no authentication" looks exactly like a
 * working app, and a `verifyTls: false` checkbox looks exactly like a working AI assistant. No
 * section chrome and nothing when there is nothing to say — this must not become a banner the analyst
 * learns to scroll past.
 */
function SecurityNotices({ settings }: { settings: Settings }) {
  const warnings = settings.security?.warnings ?? [];
  if (!warnings.length) return null;
  return (
    <div className="settings__security" role="status">
      {warnings.map((w) => (
        <div key={w.code} className="settings__security-item">
          <Icon.Warn />
          <span>{w.message}</span>
        </div>
      ))}
    </div>
  );
}

export function SettingsScreen() {
  const s = useSettings();
  const { hash } = useLocation();
  const [active, setActive] = useState(hash.replace('#', '') || 'appearance');
  useEffect(() => {
    if (!hash || !s.data) return;
    const el = document.querySelector(hash);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    setActive(hash.replace('#', ''));
  }, [hash, s.data]);

  // scroll-spy
  useEffect(() => {
    if (!s.data) return;
    const els = NAV.map((n) => document.getElementById(n.id)).filter((x): x is HTMLElement => !!x);
    if (!els.length) return;
    const io = new IntersectionObserver(
      (entries) => {
        const vis = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (vis[0]) setActive(vis[0].target.id);
      },
      { rootMargin: '-80px 0px -60% 0px', threshold: [0, 0.2] },
    );
    els.forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, [s.data]);

  if (s.isLoading) return <div className="page settings"><Loading label="Loading settings…" /></div>;
  if (s.isError || !s.data) return <div className="page settings"><ErrorState title="Settings unavailable" error={s.error} onRetry={() => void s.refetch()} /></div>;
  return (
    <div className="page settings">
      <nav className="settings__nav" aria-label="Settings sections">
        {NAV.map((n) => (
          <a key={n.id} href={`#${n.id}`} className={cx('settings__nav-item', active === n.id && 'active')} onClick={() => setActive(n.id)}>
            {n.label}
          </a>
        ))}
      </nav>
      <div className="settings__sections">
        <SecurityNotices settings={s.data} />
        <Appearance settings={s.data} />
        <Compute settings={s.data} />
        <AiAssistant settings={s.data} />
        <SystemPrompts settings={s.data} />
        <McpServer settings={s.data} />
        <SecuritySection />
        <DataSection />
      </div>
    </div>
  );
}
