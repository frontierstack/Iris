import type {
  AiAnalyzeRequest, AiStreamEvent, AiTestRequest, AiTestResult, Case, ClearAllResult, ComputeStatus, DeepPartial, Entity, EventDetail,
  EventsPage, EventsQuery, ExportFormat, Health, MappingSuggestion, ParsersResponse, Report, Settings, Source, Timeline, MetricsResponse,
  Attachment, CaseSummary, CaseDetail, CaseNote, CaseSetEntry, CaseSetResponse, NoteRef, Scope, IocResponse, IocInput, Ioc, EventLocation, GraphV2, GraphQuery, GraphNodeDetail, GraphPath, GraphEdge, GraphReviewEvent, PendingMappings, AutoMapResponse, LibraryFile, TrashEntry, Rule, RuleInput, RuleTestRequest, RuleTestResult, RuleSuggestRequest, RuleSuggestResult, AnomaliesResponse, Severity,
} from './types';
import type { FieldFacetsQuery, FieldFacetsResponse, JobsResponse, RawLogPage, UploadJob } from './types';
import type { AiInvestigateRequest, AiRun, AiRunEvent, AiThread, AiToolsResponse, AiUndoResult, IocMarkers } from './types';
import type { SystemPrompt, SystemPromptsResponse } from './types';
import type { AuthStatus, Exclusion, ExclusionInput, ExclusionsResponse, GraphFindingsResponse, McpStatus, RulePreviewResult } from './types';

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function parseError(res: Response): Promise<ApiError> {
  let msg = `${res.status} ${res.statusText || 'Request failed'}`;
  try {
    const body: unknown = await res.json();
    if (body && typeof body === 'object') {
      const b = body as Record<string, unknown>;
      if (typeof b.detail === 'string') msg = b.detail;
      else if (typeof b.message === 'string') msg = b.message;
      else if (b.detail !== undefined) msg = JSON.stringify(b.detail);
    }
  } catch {
    /* non-JSON error body */
  }
  return new ApiError(res.status, msg);
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(url, init);
  } catch {
    throw new ApiError(0, 'Backend unreachable — is the API running on :8000?');
  }
  if (!res.ok) throw await parseError(res);
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

function json(method: string, body?: unknown): RequestInit {
  return {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  };
}

/**
 * Multipart upload with progress. `url` decides where the bytes land:
 *   /api/sources        - ingest into the ACTIVE case (parses immediately)
 *   /api/library/upload - stage with no case at all; link to a case later
 */
function uploadTo<T>(url: string, files: File[], onProgress?: (pct: number, loaded: number, total: number) => void,
                     jobIds?: string[]): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const fd = new FormData();
    for (const f of files) fd.append('files', f, f.name);
    const xhr = new XMLHttpRequest();
    // jobIds tie this transfer to jobs already registered server-side (POST /api/jobs), so its progress
    // is visible in every other tab and survives a refresh. Positional against `files`.
    const ids = (jobIds ?? []).filter(Boolean);
    xhr.open('POST', ids.length ? `${url}${url.includes('?') ? '&' : '?'}jobIds=${ids.map(encodeURIComponent).join(',')}` : url);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable && onProgress) onProgress(Math.round((e.loaded / e.total) * 100), e.loaded, e.total);
    };
    xhr.onerror = () => reject(new ApiError(0, 'Network error during upload'));
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          resolve(JSON.parse(xhr.responseText) as T);
        } catch {
          reject(new ApiError(xhr.status, 'Malformed upload response'));
        }
      } else {
        let msg = `${xhr.status} ${xhr.statusText || 'Upload failed'}`;
        try {
          const b = JSON.parse(xhr.responseText) as { detail?: unknown };
          if (typeof b.detail === 'string') msg = b.detail;
        } catch {
          /* ignore */
        }
        reject(new ApiError(xhr.status, msg));
      }
    };
    xhr.send(fd);
  });
}

const uploadSources = (files: File[], onProgress?: (pct: number, loaded: number, total: number) => void, jobIds?: string[]) =>
  uploadTo<Source[]>('/api/sources', files, onProgress, jobIds);
const uploadToLibrary = (files: File[], onProgress?: (pct: number, loaded: number, total: number) => void, jobIds?: string[]) =>
  uploadTo<LibraryFile[]>('/api/library/upload', files, onProgress, jobIds);

/** Upload an image for a case note (paste / drop / picker). Returns the URL to reference from markdown. */
async function uploadAttachment(caseId: string, file: File): Promise<Attachment> {
  const fd = new FormData();
  fd.append('file', file, file.name || 'screenshot.png');
  let res: Response;
  try {
    res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/attachments`, { method: 'POST', body: fd });
  } catch {
    throw new ApiError(0, 'Backend unreachable — is the API running on :8000?');
  }
  if (!res.ok) throw await parseError(res);
  return (await res.json()) as Attachment;
}

async function exportReport(format: ExportFormat, scope: Scope = 'all'): Promise<{ blob: Blob; filename: string }> {
  const res = await fetch(`/api/report/export?format=${format}${scope === 'case' ? '&scope=case' : ''}`);
  if (!res.ok) throw await parseError(res);
  const cd = res.headers.get('content-disposition') ?? '';
  const m = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(cd);
  const fallback = format === 'md' ? 'iris-report.md'
    : format === 'stix' ? 'iris-report.stix.json'
    : format === 'pdf' ? 'iris-case-report.pdf' : 'iris-report.json';
  const filename = m && m[1] ? decodeURIComponent(m[1]) : fallback;
  return { blob: await res.blob(), filename };
}

/** Stream the AI graph reviewer (SSE) — same framing as aiAnalyze. */
async function graphAiReview(body: { scope?: Scope; focus?: string; question?: string }, onEvent: (e: GraphReviewEvent) => void, signal?: AbortSignal): Promise<void> {
  let res: Response;
  try {
    res = await fetch('/api/graph/ai-review', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream' },
      body: JSON.stringify(body), signal,
    });
  } catch (e) {
    if ((e as Error).name === 'AbortError') return;
    throw new ApiError(0, 'Backend unreachable — is the API running on :8000?');
  }
  if (!res.ok) throw await parseError(res);
  if (!res.body) throw new ApiError(0, 'Empty stream');
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  const flush = (block: string) => {
    const lines = block.split(/\r?\n/).filter((l) => l.startsWith('data:')).map((l) => l.slice(5).replace(/^ /, ''));
    if (!lines.length) return;
    const payload = lines.join('\n').trim();
    if (!payload || payload === '[DONE]') return;
    try { onEvent(JSON.parse(payload) as GraphReviewEvent); } catch { onEvent({ type: 'thinking', text: payload }); }
  };
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let idx: number;
      while ((idx = buf.search(/\r?\n\r?\n/)) >= 0) {
        flush(buf.slice(0, idx));
        buf = buf.slice(idx).replace(/^\r?\n\r?\n/, '');
      }
    }
  } catch (e) {
    if ((e as Error).name === 'AbortError') return;
    throw e;
  }
  if (buf.trim()) flush(buf);
}

/**
 * Stream the tool-using investigator. Same SSE framing as the other two; the run id comes back on the
 * `X-Iris-Run-Id` header AND as the first event, so the caller can stop the run the moment it starts.
 */
async function aiInvestigate(body: AiInvestigateRequest, onEvent: (e: AiRunEvent) => void, signal?: AbortSignal): Promise<void> {
  let res: Response;
  try {
    res = await fetch('/api/ai/investigate', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream' },
      body: JSON.stringify(body), signal,
    });
  } catch (e) {
    if ((e as Error).name === 'AbortError') return;
    throw new ApiError(0, 'Backend unreachable — is the API running on :8000?');
  }
  if (!res.ok) throw await parseError(res);
  if (!res.body) throw new ApiError(0, 'Empty stream');
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  const flush = (block: string) => {
    const lines = block.split(/\r?\n/).filter((l) => l.startsWith('data:')).map((l) => l.slice(5).replace(/^ /, ''));
    if (!lines.length) return;
    const payload = lines.join('\n').trim();
    if (!payload || payload === '[DONE]') return;
    try { onEvent(JSON.parse(payload) as AiRunEvent); } catch { onEvent({ type: 'status', text: payload }); }
  };
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let idx: number;
      while ((idx = buf.search(/\r?\n\r?\n/)) >= 0) {
        flush(buf.slice(0, idx));
        buf = buf.slice(idx).replace(/^\r?\n\r?\n/, '');
      }
    }
  } catch (e) {
    if ((e as Error).name === 'AbortError') return;
    throw e;
  }
  if (buf.trim()) flush(buf);
}

async function aiAnalyze(body: AiAnalyzeRequest, onEvent: (e: AiStreamEvent) => void, signal?: AbortSignal): Promise<void> {
  let res: Response;
  try {
    res = await fetch('/api/ai/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream' },
      body: JSON.stringify(body),
      signal,
    });
  } catch (e) {
    if ((e as Error).name === 'AbortError') return;
    throw new ApiError(0, 'Backend unreachable — is the API running on :8000?');
  }
  if (!res.ok) throw await parseError(res);
  if (!res.body) throw new ApiError(0, 'Empty stream');
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  const flushBlock = (block: string) => {
    const dataLines = block
      .split(/\r?\n/)
      .filter((l) => l.startsWith('data:'))
      .map((l) => l.slice(5).replace(/^ /, ''));
    if (!dataLines.length) return;
    const payload = dataLines.join('\n');
    if (!payload.trim() || payload.trim() === '[DONE]') return;
    try {
      onEvent(JSON.parse(payload) as AiStreamEvent);
    } catch {
      onEvent({ type: 'agent', agent: 'stream', text: payload });
    }
  };
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let idx: number;
      while ((idx = buf.search(/\r?\n\r?\n/)) >= 0) {
        const block = buf.slice(0, idx);
        buf = buf.slice(idx).replace(/^\r?\n\r?\n/, '');
        flushBlock(block);
      }
    }
  } catch (e) {
    if ((e as Error).name === 'AbortError') return;
    throw e;
  }
  if (buf.trim()) flushBlock(buf);
}

export const api = {
  health: () => request<Health>('/api/health'),

  // Case
  getCase: () => request<Case>('/api/case'),
  patchCase: (patch: { name?: string; analyst?: string }) => request<Case>('/api/case', json('PATCH', patch)),
  resetCase: () => request<Case>('/api/case/reset', json('POST')),
  clearAll: (resetSettings = false) => request<ClearAllResult>('/api/admin/clear-all', json('POST', { resetSettings })),
  parsers: () => request<ParsersResponse>('/api/parsers'),

  // Cases (multi-case)
  cases: () => request<CaseSummary[]>('/api/cases'),
  createCase: (body: { name: string; analyst?: string }) => request<CaseSummary>('/api/cases', json('POST', body)),
  activateCase: (id: string) => request<Case>(`/api/cases/${encodeURIComponent(id)}/activate`, json('POST')),
  caseDetail: (id: string) => request<CaseDetail>(`/api/cases/${encodeURIComponent(id)}`),

  // Case notes — a timestamped feed; entries can link to events, searches, entities…
  notes: (caseId: string) => request<CaseNote[]>(`/api/cases/${encodeURIComponent(caseId)}/notes`),
  addNote: (caseId: string, body: { text: string; refs?: NoteRef[] }) =>
    request<CaseNote>(`/api/cases/${encodeURIComponent(caseId)}/notes`, json('POST', body)),
  updateNote: (caseId: string, noteId: string, body: { text?: string; refs?: NoteRef[] }) =>
    request<CaseNote>(`/api/cases/${encodeURIComponent(caseId)}/notes/${encodeURIComponent(noteId)}`, json('PATCH', body)),
  /** Images attached to notes — stored inside the case directory and deleted with the case. */
  uploadAttachment,
  deleteNote: (caseId: string, noteId: string) =>
    request<{ ok: true }>(`/api/cases/${encodeURIComponent(caseId)}/notes/${encodeURIComponent(noteId)}`, { method: 'DELETE' }),
  patchCaseById: (id: string, patch: { name?: string; analyst?: string; notes?: string }) => request<CaseSummary>(`/api/cases/${encodeURIComponent(id)}`, json('PATCH', patch)),
  // Deleting MOVES the case to the trash — these recover it. See docs/API_CONTRACT.md → Cases.
  deleteCase: (id: string) => request<{ ok: true }>(`/api/cases/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  caseTrash: () => request<TrashEntry[]>('/api/cases/trash'),
  restoreTrashedCase: (entry: string) =>
    request<CaseSummary>(`/api/cases/trash/${encodeURIComponent(entry)}/restore`, json('POST')),

  // Detection rules & anomalies
  rules: (includeRemoved = false) => request<Rule[]>(`/api/rules${includeRemoved ? '?includeRemoved=true' : ''}`),
  createRule: (body: RuleInput) => request<Rule>('/api/rules', json('POST', body)),
  updateRule: (id: string, body: RuleInput) => request<Rule>(`/api/rules/${encodeURIComponent(id)}`, json('PUT', body)),
  deleteRule: (id: string) => request<{ ok: true }>(`/api/rules/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  /** Built-ins only: undo a removal and drop any metadata override, back to the shipped definition. */
  restoreRule: (id: string) => request<Rule>(`/api/rules/${encodeURIComponent(id)}/restore`, json('POST')),
  toggleRule: (id: string) => request<Rule>(`/api/rules/${encodeURIComponent(id)}/toggle`, json('POST')),
  clearRules: (scope: 'all' | 'custom' = 'all') =>
    request<{ ok: true; custom: number; builtin: number }>(`/api/rules/clear?scope=${scope}`, json('POST')),
  restoreDefaultRules: () => request<{ ok: true; restored: number }>('/api/rules/restore-defaults', json('POST')),
  testRule: (body: RuleTestRequest, signal?: AbortSignal) => request<RuleTestResult>('/api/rules/test', { ...json('POST', body), signal }),
  suggestRule: (body: RuleSuggestRequest) => request<RuleSuggestResult>('/api/rules/suggest', json('POST', body)),
  /** Dry-run a whole rule definition: what it WOULD flag, without saving it or tagging any event. */
  previewRule: (body: RuleInput, signal?: AbortSignal) =>
    request<RulePreviewResult>('/api/rules/preview', { ...json('POST', body), signal }),
  // Exclusions — the suppressions that stop a rule claiming evidence already judged benign. Every write
  // re-runs the catalogue server-side, so the caller invalidates anomalies and rules afterwards.
  exclusions: () => request<ExclusionsResponse>('/api/exclusions'),
  createExclusion: (body: ExclusionInput) => request<Exclusion>('/api/exclusions', json('POST', body)),
  updateExclusion: (id: string, body: ExclusionInput) =>
    request<Exclusion>(`/api/exclusions/${encodeURIComponent(id)}`, json('PUT', body)),
  toggleExclusion: (id: string) =>
    request<Exclusion>(`/api/exclusions/${encodeURIComponent(id)}/toggle`, json('POST')),
  deleteExclusion: (id: string) =>
    request<{ ok: true }>(`/api/exclusions/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  clearExclusions: () => request<{ ok: true; removed: number }>('/api/exclusions/clear', json('POST')),

  /** Detections that read the entity graph (fan-out, pivots, failure-heavy relationships). */
  graphAnomalies: (q: { scope?: 'all' | 'case'; sev?: Severity[]; limit?: number } = {}) => {
    const p = new URLSearchParams();
    if (q.scope) p.set('scope', q.scope);
    if (q.sev?.length) p.set('sev', q.sev.join(','));
    if (q.limit) p.set('limit', String(q.limit));
    const qs = p.toString();
    return request<GraphFindingsResponse>(`/api/graph/anomalies${qs ? `?${qs}` : ''}`);
  },
  anomalies: (q: { sev?: Severity[]; limit?: number } = {}) => {
    const p = new URLSearchParams();
    if (q.sev?.length) p.set('sev', q.sev.join(','));
    if (q.limit) p.set('limit', String(q.limit));
    const qs = p.toString();
    return request<AnomaliesResponse>(`/api/anomalies${qs ? `?${qs}` : ''}`);
  },

  // Upload & parse jobs — server-side progress that survives a refresh or a second tab.
  // Polling, not SSE: see docs/API_CONTRACT.md → "Upload & parse jobs".
  jobs: (limit = 100) => request<JobsResponse>(`/api/jobs?limit=${limit}`),
  createJobs: (files: { file: string; size: number }[], target: 'case' | 'library' = 'case') =>
    request<{ jobs: UploadJob[] }>('/api/jobs', json('POST', { files, target })),
  /** Bytes in flight — only the sending tab knows this, so it pushes it (throttled). */
  jobProgress: (id: string, received: number) =>
    request<UploadJob>(`/api/jobs/${encodeURIComponent(id)}`, json('PATCH', { received })),
  /** "these transfers are still mine". A drop of twelve files registers twelve jobs and sends three at a
   *  time, so the rest sit queued with nothing arriving for them — indistinguishable server-side from a
   *  closed tab, and the watchdog used to call them dead at ten minutes. The sending tab reports in until
   *  its queue drains; anything the watchdog already buried is revived. */
  jobHeartbeat: (ids: string[]) =>
    request<{ alive: string[]; revived: string[] }>('/api/jobs/heartbeat', json('POST', { ids })),
  clearJobs: () => request<{ ok: true; cleared: number }>('/api/jobs/clear', json('POST')),

  // Sources
  uploadSources,
  getSource: (id: string) => request<Source>(`/api/sources/${encodeURIComponent(id)}`),
  deleteSource: (id: string) => request<{ ok: true }>(`/api/sources/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  setMapping: (id: string, body: { fields: string[]; delimiter?: string }) =>
    request<Source>(`/api/sources/${encodeURIComponent(id)}/mapping`, json('POST', body)),
  /** Phase 2 of ingest, on demand: queue the real parse + normalization for this source. Returns the
   *  source with its new `enrich` state — the work itself happens on the background worker. */
  enrichSource: (id: string) => request<Source>(`/api/sources/${encodeURIComponent(id)}/enrich`, json('POST')),
  /** Leave this source raw on purpose. It stays searchable as text and out of the timeline, the graph
   *  and the detections — a decision, so it is not counted as outstanding. */
  skipEnrichSource: (id: string) => request<Source>(`/api/sources/${encodeURIComponent(id)}/enrich/skip`, json('POST')),
  // Upload library — attach files that are already on disk to the active case
  library: () => request<LibraryFile[]>('/api/library'),
  uploadToLibrary,
  /** Parse a skipped staged file into the pool anyway. Rejects (507) with a message naming the RAM it
   *  needs vs the RAM there is when it truly cannot fit — the file then stays skipped, not half-loaded. */
  loadUnattached: (fileName: string) =>
    request<LibraryFile>(`/api/library/unattached/${encodeURIComponent(fileName)}/load`, { method: 'POST' }),
  deleteUnattached: (fileName: string) =>
    request<{ ok: true }>(`/api/library/unattached/${encodeURIComponent(fileName)}`, { method: 'DELETE' }),
  /** File already-uploaded logs into a case. `targetCaseId` picks WHICH case (blank = the active one);
   *  naming one activates it, because the store holds exactly one case in memory. */
  attachFromLibrary: (items: { caseId: string; fileName: string }[], targetCaseId = '') =>
    request<Source[]>('/api/library/attach', json('POST', { items, targetCaseId })),
  /** Take a source back out of the case. The events stay in the workspace pool — this is not a delete. */
  detachCaseSource: (caseId: string, sid: string) =>
    request<Source[]>(`/api/cases/${encodeURIComponent(caseId)}/sources/${encodeURIComponent(sid)}/detach`, json('POST')),

  // Bulk AI mapping over every source still awaiting field names
  pendingMappings: () => request<PendingMappings>('/api/sources/mapping/pending'),
  autoMapAll: (opts: { apply?: boolean; minConfidence?: number } = {}) => {
    const p = new URLSearchParams();
    if (opts.apply === false) p.set('apply', 'false');
    if (opts.minConfidence !== undefined) p.set('minConfidence', String(opts.minConfidence));
    const qs = p.toString();
    return request<AutoMapResponse>(`/api/sources/mapping/auto${qs ? `?${qs}` : ''}`, json('POST'));
  },
  suggestMapping: (id: string) => request<MappingSuggestion>(`/api/sources/${encodeURIComponent(id)}/mapping/suggest`, json('POST')),

  // Events
  events: (q: EventsQuery) => {
    const p = new URLSearchParams();
    if (q.q) p.set('q', q.q);
    if (q.sources?.length) p.set('sources', q.sources.join(','));
    if (q.sev?.length) p.set('sev', q.sev.join(','));
    if (q.from) p.set('from', q.from);
    if (q.to) p.set('to', q.to);
    p.set('limit', String(q.limit ?? 200));
    p.set('offset', String(q.offset ?? 0));
    if (q.scope && q.scope !== 'all') p.set('scope', q.scope);
    if (q.sort) p.set('sort', q.sort);
    return request<EventsPage>(`/api/events?${p.toString()}`);
  },
  event: (id: string) => request<EventDetail>(`/api/events/${encodeURIComponent(id)}`),
  /** Which line of the original log file this event came from (resolved on demand). */
  eventLocation: (id: string) => request<EventLocation>(`/api/events/${encodeURIComponent(id)}/location`),

  // Timeline / graph — `scope` decides whether the analyzer runs over every event or only the case set
  timeline: (scope: Scope = 'all') => request<Timeline>(`/api/timeline${scope === 'case' ? '?scope=case' : ''}`),
  /** Indicators as timeline markers (first-seen). A separate request from `timeline` on purpose: IOC
   *  extraction is its own O(pool) pass and must not hold the clusters up. */
  timelineIocs: (scope: Scope = 'all') => request<IocMarkers>(`/api/timeline/iocs${scope === 'case' ? '?scope=case' : ''}`),
  /** v2 typed graph — see GraphQuery for filters. */
  graph: (gq: GraphQuery = {}) => {
    const p = new URLSearchParams();
    if (gq.scope && gq.scope !== 'all') p.set('scope', gq.scope);
    if (gq.types?.length) p.set('types', gq.types.join(','));
    if (gq.relations?.length) p.set('relations', gq.relations.join(','));
    if (gq.minCount && gq.minCount > 1) p.set('minCount', String(gq.minCount));
    if (gq.minDegree && gq.minDegree > 1) p.set('minDegree', String(gq.minDegree));
    if (gq.focus) p.set('focus', gq.focus);
    if (gq.hops !== undefined) p.set('hops', String(gq.hops));
    if (gq.limit) p.set('limit', String(gq.limit));
    if (gq.q) p.set('q', gq.q);
    if (gq.sources?.length) p.set('sources', gq.sources.join(','));
    if (gq.maxEdges) p.set('maxEdges', String(gq.maxEdges));
    if (gq.lean) p.set('lean', '1');
    const qs = p.toString();
    return request<GraphV2>(`/api/graph${qs ? `?${qs}` : ''}`);
  },
  graphNode: (id: string, scope: Scope = 'all') => request<GraphNodeDetail>(`/api/graph/node/${encodeURIComponent(id)}${scope === 'case' ? '?scope=case' : ''}`),
  graphPath: (from: string, to: string, maxHops = 4) =>
    request<GraphPath>(`/api/graph/path?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}&maxHops=${maxHops}`),
  addGraphLink: (body: { source: string; target: string; relation: string; why?: string; confidence?: number | null; ai?: boolean }) =>
    request<GraphEdge>('/api/graph/links', json('POST', body)),
  deleteGraphLink: (id: string) => request<{ ok: true }>(`/api/graph/links/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  graphAiReview,
  entity: (name: string, scope: Scope = 'all') =>
    request<Entity>(`/api/graph/${encodeURIComponent(name)}${scope === 'case' ? '?scope=case' : ''}`),

  // Case set — curated events that are part of the investigation
  caseSet: () => request<CaseSetResponse>('/api/case-set'),
  addToCase: (eventId: string, body: { labels?: string[]; note?: string } = {}) =>
    request<CaseSetEntry>(`/api/case-set/${encodeURIComponent(eventId)}`, json('POST', body)),
  updateCaseEntry: (eventId: string, body: { labels?: string[]; note?: string }) =>
    request<CaseSetEntry>(`/api/case-set/${encodeURIComponent(eventId)}`, json('PATCH', body)),
  /** Add / remove every event of one log file (the + on a Sources row). */
  addSourceToCase: (sourceId: string, labels?: string[]) =>
    request<{ ok: true; added: number; total: number; truncated: boolean; file: string }>(
      `/api/case-set/source/${encodeURIComponent(sourceId)}`, json('POST', labels ? { labels } : {})),
  removeSourceFromCase: (sourceId: string) =>
    request<{ ok: true; removed: number }>(`/api/case-set/source/${encodeURIComponent(sourceId)}`, { method: 'DELETE' }),
  removeFromCase: (eventId: string) =>
    request<{ ok: true }>(`/api/case-set/${encodeURIComponent(eventId)}`, { method: 'DELETE' }),

  // Indicators of compromise, each carrying the events/log files it was seen in
  iocs: (scope: Scope = 'all') => request<IocResponse>(`/api/iocs${scope === 'case' ? '?scope=case' : ''}`),
  addIoc: (body: IocInput) => request<Ioc>('/api/iocs', json('POST', body)),
  updateIoc: (id: string, body: IocInput) => request<Ioc>(`/api/iocs/${encodeURIComponent(id)}`, json('PATCH', body)),
  deleteIoc: (id: string) => request<{ ok: true }>(`/api/iocs/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  // Report
  report: (scope: Scope = 'all') => request<Report>(`/api/report${scope === 'case' ? '?scope=case' : ''}`),
  exportReport,

  // Settings / compute
  settings: () => request<Settings>('/api/settings'),

  /* ── sign-in (password + PIN). The session is an HttpOnly cookie the page cannot read, so there is
     nothing to store client-side and nothing to attach to a request — the browser does it. ── */
  authStatus: () => request<AuthStatus>('/api/auth/status'),
  login: (password: string, pin: string) => request<AuthStatus>('/api/auth/login', json('POST', { password, pin })),
  logout: () => request<{ ok: true }>('/api/auth/logout', json('POST')),
  setCredentials: (password: string, pin: string, enabled = true) =>
    request<AuthStatus>('/api/auth/credentials', json('POST', { password, pin, enabled })),
  setLoginEnabled: (enabled: boolean) => request<AuthStatus>('/api/auth/enabled', json('POST', { enabled })),
  clearCredentials: () => request<AuthStatus>('/api/auth/credentials', json('DELETE')),
  putSettings: (patch: DeepPartial<Settings>) => request<Settings>('/api/settings', json('PUT', patch)),
  compute: () => request<ComputeStatus>('/api/compute'),

  // MCP server (Iris as a tool provider for Cursor / Claude Code / Claude Desktop)
  mcpStatus: () => request<McpStatus>('/api/mcp/status'),
  mcpNewToken: () => request<{ token: string }>('/api/mcp/token', json('POST')),
  recheckCompute: () => request<ComputeStatus>('/api/compute/recheck', json('POST')),
  metrics: (window = 150) => request<MetricsResponse>(`/api/compute/metrics?window=${window}`),

  // AI
  aiTest: (body: AiTestRequest) => request<AiTestResult>('/api/ai/test', json('POST', body)),
  aiAnalyze,

  // AI investigator — one free-form objective, a bounded tool-calling loop, streamed
  aiInvestigate,
  /** Ask a live run to stop; it halts at its next checkpoint (before a step / after the tool in flight). */
  aiStopRun: (runId: string) => request<{ ok: boolean; runId: string }>(`/api/ai/investigate/${encodeURIComponent(runId)}/stop`, json('POST')),
  /**
   * One conversation, in full. `since` returns only transcript entries newer than that seq — this is how
   * the panel rejoins a run that is still in flight after a refresh, without re-downloading it each poll.
   */
  aiRun: (runId: string, since = 0) =>
    request<AiRun>(`/api/ai/runs/${encodeURIComponent(runId)}${since ? `?since=${since}` : ''}`),
  /** The persisted conversation history, newest first. Summaries only — `transcript` is [] here. */
  aiRuns: (limit = 30) => request<{ runs: AiRun[] }>(`/api/ai/runs?limit=${limit}`),
  /** Every turn of the conversation a run belongs to, oldest first, transcripts included. */
  aiThread: (runId: string) => request<AiThread>(`/api/ai/runs/${encodeURIComponent(runId)}/thread`),
  /** Delete ONE stored conversation. Case artefacts it created are untouched — use aiUndoRun for those. */
  aiDeleteRun: (runId: string) => request<{ ok: boolean; runId: string }>(`/api/ai/runs/${encodeURIComponent(runId)}`, { method: 'DELETE' }),
  aiClearRuns: () => request<{ ok: boolean; removed: number }>('/api/ai/runs', { method: 'DELETE' }),
  /** Reverse every change one run made — the other half of "writes apply immediately". */
  aiUndoRun: (runId: string) => request<AiUndoResult>(`/api/ai/runs/${encodeURIComponent(runId)}/undo`, json('POST')),
  aiTools: () => request<AiToolsResponse>('/api/ai/tools'),
  // Saved system prompts for the investigator (Settings → System prompts)
  aiSystemPrompts: () => request<SystemPromptsResponse>('/api/ai/system-prompts'),
  aiCreateSystemPrompt: (body: { name: string; text: string }) =>
    request<SystemPrompt>('/api/ai/system-prompts', json('POST', body)),
  aiUpdateSystemPrompt: (id: string, body: Partial<{ name: string; text: string }>) =>
    request<SystemPrompt>(`/api/ai/system-prompts/${encodeURIComponent(id)}`, json('PUT', body)),
  aiDeleteSystemPrompt: (id: string) =>
    request<{ ok: boolean; id: string; defaultReset: boolean }>(`/api/ai/system-prompts/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  /** The exact text the model receives with this prompt selected: the built-in prompt with the instructions appended. */
  aiEffectiveSystemPrompt: (id: string) =>
    request<{ id: string; name: string; text: string }>(`/api/ai/system-prompts/${encodeURIComponent(id)}/effective`),

  // Search field facets — same filters as `events`, so the sidebar reflects the current result set
  eventFields: (q: FieldFacetsQuery) => {
    const p = new URLSearchParams();
    if (q.q) p.set('q', q.q);
    if (q.sources?.length) p.set('sources', q.sources.join(','));
    if (q.sev?.length) p.set('sev', q.sev.join(','));
    if (q.from) p.set('from', q.from);
    if (q.to) p.set('to', q.to);
    if (q.scope && q.scope !== 'all') p.set('scope', q.scope);
    if (q.limit) p.set('limit', String(q.limit));
    if (q.values) p.set('values', String(q.values));
    return request<FieldFacetsResponse>(`/api/events/fields?${p.toString()}`);
  },

  // Raw log viewer — a numbered page of the original upload; `q` filters lines server-side
  sourceRaw: (id: string, opts: { offset?: number; limit?: number; q?: string } = {}) => {
    const p = new URLSearchParams();
    p.set('offset', String(opts.offset ?? 0));
    p.set('limit', String(opts.limit ?? 500));
    if (opts.q) p.set('q', opts.q);
    return request<RawLogPage>(`/api/sources/${encodeURIComponent(id)}/raw?${p.toString()}`);
  },
  /** URL of the original bytes (Content-Disposition: attachment) — use as an <a href download>. */
  sourceDownloadUrl: (id: string) => `/api/sources/${encodeURIComponent(id)}/download`,
};

export type Api = typeof api;
