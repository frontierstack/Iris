export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export type SourceState = 'READY' | 'REVIEW' | 'MAP' | 'PARSING' | 'ERROR';

/**
 * Two-phase ingest (backend/app/enrich.py). Phase 1 lands every line of a log in the pool at once —
 * searchable, but with no timestamp, no severity, no parsed fields and no entities. Phase 2 runs the
 * real parser and normalization on a background worker and replaces that source's events.
 *
 * 'raw' therefore means "in the pool, NOT interpreted": the timeline, the entity graph and the
 * detections cannot see it. 'skipped' is the same technical state but a deliberate analyst decision,
 * which is why it is not counted as outstanding. Binary/structured containers (EVTX, SQLite, PDF,
 * XLSX, OCR, mail) have no raw form and are born 'enriched'.
 */
export type EnrichState = 'raw' | 'queued' | 'enriching' | 'enriched' | 'skipped' | 'error';

export interface Source {
  id: string;
  file: string;
  parser: string;
  events: number;
  range: [string, string] | null;
  confidence: number;
  state: SourceState;
  size: number;
  error?: string;
  guessedFields?: string[];
  sample?: string;
  delimiter?: string;
  /** 'case' = in the active case; 'library' = staged with no case at all, parsed and searchable anyway */
  origin?: 'case' | 'library';
  /** phase 2 of ingest — see EnrichState. Absent on an older server: treat that as 'enriched'. */
  enrich?: EnrichState;
  /** why phase 2 failed. Only meaningful with enrich === 'error'; the raw lines are still in the pool. */
  enrichError?: string | null;
  /** when the full parse finished, ISO-8601 UTC */
  enrichedAt?: string | null;
  /** Curated case-set entries whose event id this source's phase-2 parse dropped and that
   *  `_reanchor_case_set` could not re-point at their own line. The entries are KEPT — they are the
   *  analyst's work — but they no longer resolve to evidence, and until now nothing said so.
   *  Empty, never null: "nothing lost" is a real answer. */
  lostCitations?: string[];
  /** LIVE parse detail — the same shape a job row carries, read straight off the server's tracker.
   *  Non-null ONLY while this source is actually being read (state 'PARSING', or enrich 'enriching').
   *  The Sources table could otherwise only show a spinner, which on a 639 MB capture is twenty minutes
   *  of a screen that cannot be told apart from a hang. In memory server-side: absent after a restart
   *  until the work resumes. */
  progress?: ParseProgress | null;
}

export interface Detection { name: string; id: string; level: Severity }

export interface Event {
  id: string;
  ts: string;
  source: string;
  sourceId: string;
  file: string;
  host: string;
  user: string;
  msg: string;
  sev: Severity;
  raw: string;
  fields: Record<string, string>;
  /** case-set membership, stamped by the server so lists need no second request */
  inCase?: boolean;
  labels?: string[];
  entities: string[];
  detections: Detection[];
  baseline?: string;
}

export interface Correlation { id: string; ts: string; msg: string; sev: Severity; reason: string }
/** `analysis` is present ONLY when the correlation analysis was not available, and then
 *  `correlations` is empty because it could not be computed — not because there are none. Rendering
 *  the empty list as "nothing correlates with this event" would state something the server did not. */
export type EventDetail = Event & { correlations: Correlation[]; analysis?: DerivedState | null };

export type ClusterTag = 'FREQUENCY' | 'ENTITY LINK' | 'ANOMALY';
export interface Cluster {
  id: string; title: string; start: string; end: string; span: string; tag: ClusterTag;
  sev: Severity; count: number; sources: string[]; why: string; eventIds: string[];
}

export interface EntityLink { name: string; shared: number; via: string }
export interface Entity { name: string; kind: string; first: string; count: number; facts: [string, string][]; links: EntityLink[] }
export interface Edge { a: string; b: string; weight: number }
export interface Graph { entities: Entity[]; edges: Edge[] }

/* ───── Entity graph v2: typed nodes joined by typed relations ───── */
export type EntityType = 'ip' | 'user' | 'host' | 'process' | 'pid' | 'file' | 'hash' | 'domain' | 'url' | 'port' | 'email' | 'key' | 'session' | 'pod' | 'service' | 'registry' | 'other';
export const ENTITY_TYPES: EntityType[] = ['ip', 'user', 'host', 'process', 'pid', 'file', 'hash', 'domain', 'port', 'email', 'key', 'session', 'pod', 'service', 'registry', 'other'];
export type Relation = 'auth_from' | 'connected_to' | 'ran' | 'spawned' | 'wrote' | 'read' | 'deleted' | 'resolved' | 'requested' | 'used_key' | 'on_host' | 'session' | 'co_occurred';
export const RELATIONS: Relation[] = ['auth_from', 'connected_to', 'ran', 'spawned', 'wrote', 'read', 'deleted', 'resolved', 'requested', 'used_key', 'on_host', 'session', 'co_occurred'];
export interface GraphNode {
  id: string; type: EntityType; value: string; label: string; count: number; first: string; last: string;
  sev: Severity; detections: number; facts: [string, string][]; inCase?: boolean; ai?: boolean;
  /** AUTHORED, not extracted: drawn by the analyst or the agent as part of an investigation, and
   *  stored on the case. `count` is 0 — it is a conclusion about evidence, not a count of it — and
   *  `why` says on what grounds. Rendered with the dashed ring so the two can never be confused. */
  manual?: boolean; why?: string;
}
export interface GraphEdge {
  id: string; source: string; target: string; relation: Relation; count: number; first: string; last: string;
  sev: Severity; outcome?: 'success' | 'failure' | 'denied' | 'mixed' | null; eventIds: string[]; why: string;
  ai?: boolean; manual?: boolean; confidence?: number | null;
}
/** State of a DERIVED structure (entity graph, correlation analysis) that is built once per store
 *  version in a background thread. A request never builds one at pool scale: while `state` is
 *  'building' the payload is empty and this says how far along it is, so the screen shows progress
 *  instead of a spinner (90 s of nothing reads as a hang) or an empty result (which reads as no data). */
export interface DerivedState {
  state: 'idle' | 'building' | 'ready';
  events: number; target: number; pct: number; elapsedSec: number; buildMs: number;
  /** Set while the build is deliberately NOT running (the library is still loading and any build now
   *  would be discarded on the next bump). The screen must say so — a progress bar at 0 % that never
   *  moves reads as a hang. */
  note?: string;
}
export interface GraphStats { nodes: number; edges: number; truncated: boolean; totalNodes?: number; totalEdges?: number; byType: Partial<Record<EntityType, number>>; byRelation: Partial<Record<Relation, number>>; query?: string; status?: DerivedState;
  /** How many nodes `minDegree` removed. Reported so the screen can say the filter did it, rather than
   *  quietly showing a smaller graph. */
  hiddenByDegree?: number;
  /** Edges the strongest-first cap (`maxEdges`, default 20 000) left out, and the cap itself. */
  hiddenEdges?: number; maxEdges?: number;
  /** The graph covers `sourcesIncluded` sources; `sourcesPending` are still being interpreted and join
   *  it the moment they land — it no longer waits for the queue to drain. */
  sourcesIncluded?: number; sourcesPending?: number }
export interface GraphV2 { nodes: GraphNode[]; edges: GraphEdge[]; stats: GraphStats }
export interface GraphQuery { scope?: Scope; types?: EntityType[]; relations?: Relation[]; minCount?: number; minDegree?: number; focus?: string; hops?: number; limit?: number; q?: string;
  /** Source ids the graph is restricted to — entities and relations actually seen in those files.
   *  Empty/omitted means the whole pool; the Graph screen starts with none selected. */
  sources?: string[];
  /** Keep the strongest N edges (by event count); overlays are never dropped. Default 20 000. */
  maxEdges?: number;
  /** Omit per-edge event ids and first/last stamps — the canvas never reads them. */
  lean?: boolean }
export interface GraphNodeDetail extends GraphNode {
  neighbours: GraphEdge[]; timeline: { ts: string; eventId: string; msg: string; sev: Severity }[];
  /** Which rules fired on this entity's events and how often — exact, over the node's own query. */
  detectionRules?: { id: string; name: string; sev: Severity; count: number }[];
  /** The search DSL query that returns EXACTLY this node's events (`entity:"…"`, colons escaped). Built
   *  by the graph, which owns the extraction rules — the UI must not guess it from the value. */
  query?: string;
}
export interface GraphPath { found: boolean; path: GraphNode[]; edges: GraphEdge[] }
export type GraphReviewEvent =
  | { type: 'thinking'; text: string }
  | { type: 'link'; edge: GraphEdge }
  | { type: 'alias'; a: string; b: string; reason: string }
  | { type: 'narrative'; text: string }
  | { type: 'done'; links: number; aliases: number }
  | { type: 'error'; message: string };

/** A staged library file whose events are NOT in the pool — i.e. NOT searchable.
 *  'budget' = it would have taken the pool past its memory cap (budgetBytes), 'unreadable' = the bytes
 *  could not be read off disk. A file that failed to PARSE is never here: it is a Source in state ERROR. */
/** Why a staged file is NOT in the pool. The union was declared as just 'budget'|'unreadable', which
 *  made a two-way ternary in the UI look exhaustive — so a 'memory' skip was labelled "unreadable" and
 *  sent the analyst to check the disk for a file the machine simply had no RAM for. They have different
 *  fixes and the API has always kept them apart; only this type did not. */
export type PoolSkipReason = 'budget' | 'memory' | 'unreadable' | 'parse-error' | 'not-parsed';
export interface PoolSkip {
  fileName: string; displayName: string; size: number;
  reason: PoolSkipReason;
  detail: string; budgetBytes: number; usedBytes: number;
}

/** Byte-level progress of the background pool load (see Case.poolProgress). */
export interface PoolProgress {
  bytesDone: number; bytesTotal: number; pct: number;
  filesDone: number; filesTotal: number;
  /** '' between files */
  currentFile: string; currentBytesDone: number; currentBytesTotal: number; currentPct: number;
  /** parse workers on the current file; > 1 means the multi-process path */
  workers: number;
  bytesPerSec: number; etaSec: number | null; elapsedSec: number;
  /** per-file breakdown of the same load, in library order — the aggregate plus `currentFile` could not
   *  say which of 40 files were already in the pool. `bytesDone`/`pct` are live for the parsing file. */
  files: PoolFileProgress[];
}
export interface PoolFileProgress {
  file: string; size: number;
  /** 'skipped' = not loaded (no memory headroom); its events are NOT searchable. Distinct from
   *  'error', which means the file WAS read and the parser failed. */
  state: 'pending' | 'parsing' | 'done' | 'error' | 'skipped';
  bytesDone: number; pct: number; events: number;
}

/** Phase-2 progress across the whole workspace (GET /api/case).
 *  `outstanding` deliberately EXCLUDES 'skipped': that is an analyst decision, not an omission, and it
 *  must never keep an incompleteness warning alive. */
export interface EnrichCounts {
  raw: number; queued: number; enriching: number; enriched: number; skipped: number; error: number;
}
export interface CaseEnrichment {
  counts: EnrichCounts;
  /** source id being enriched right now, '' when the worker is idle */
  /** the source in phase 2 RIGHT NOW, '' when nothing is. Reconciled server-side against `counts`,
   *  so it never names a file that has already finished. */
  running: string;
  /** a finished batch is being merged into the pool — real work, tens of seconds on a large pool, and
   *  it belongs to no single source because every member of it is already `enriched`. */
  committing?: boolean;
  /** WHAT phase 2 is doing right now, with elapsed time. The counts say how much is left; this says
   *  what is being waited on — the difference between "1 queued" and "merging 2 sources into a
   *  13.8M-event pool, 4m". */
  activity?: EnrichActivity;
  /** the pool-wide (windowed-rule) detection pass is running in the background. Holds nothing up,
   *  but it is minutes of one core on a big workspace and deserves a line rather than silence. */
  detectionsRefreshing?: boolean;
  detectionsRefreshSec?: number;
  /** rough 0-100 by catalogue section; null before the first section reports */
  detectionsRefreshPct?: number | null;
  /** queued + enriching — is work IN FLIGHT? This is what a progress banner counts down. */
  pending: number;
  /** raw + queued + enriching — is my ANSWER incomplete? Those sources are in the pool as raw lines,
   *  so the timeline, the entity graph and the anomaly list are running over PART of the corpus. */
  outstanding: number;
  /** What the source in phase 2 is doing right now. A source takes tens of seconds on a large pool,
   *  so a bare "1 running" changes once a minute and reads as frozen. Absent when nothing runs. */
  runningFile?: string;
  runningPct?: number | null;
  runningPhase?: string;
  runningEtaSec?: number | null;
  /** Sources only a PERSON can move: `error` (retryable) plus `raw` when nothing is in flight
   *  (automatic interpretation is off). Different from `pending`, which just needs patience. */
  needsAction?: number;
}
/** @deprecated the type is named after the backend model — use CaseEnrichment. */
export type Enrichment = CaseEnrichment;

export interface Posture { label: string; value: string; pct: number; color: 'ok' | 'warn' | 'bad' }
export interface QueueItem { label: string; detail: string; done: boolean }
export interface Case {
  id: string; name: string; analyst: string; createdAt: string;
  /** one-paragraph description of the investigation (analyst- or AI-authored) */
  summary: string;
  /** the CASE's own sources and event total — empty/0 while no case exists */
  sources: Source[];
  eventCount: number;
  /** the case-less pool: files staged in the library, parsed and analysable with no case at all */
  librarySources: Source[];
  /** events across the WHOLE pool (case + library) — what Search/Timeline/Anomalies/Graph run over */
  poolEventCount: number;
  /** a large library loads in the background; while true the analysis screens must say "still loading" */
  poolLoading: boolean;
  poolPending: number;
  poolLoaded: number;
  /** real progress for that load, in BYTES of source log — null when nothing is loading.
   *  A file count is not progress when one of 16 files is 263 MB and the rest are 2 MB. */
  poolProgress: PoolProgress | null;
  /** staged files left unparsed because the pool hit its memory budget — still attachable to a case.
   *  Always equal to poolSkippedFiles.length: the count is the header, the list is the truth. */
  poolSkipped: number;
  poolSkippedFiles: PoolSkip[];
  /** the pool memory budget in force, in bytes of SOURCE LOG (0 = unlimited, IRIS_POOL_MAX_MB) */
  poolBudgetBytes: number;
  /** the workspace's phase-2 picture — how much of the pool has actually been interpreted.
   *  Derived from per-source metadata, never from a walk of the pool: GET /api/case is O(1) in the
   *  event count and must stay that way. */
  enrichment: CaseEnrichment;
  caseSet: CaseSetEntry[]; notes: CaseNote[];
  /** no case exists yet — the id is reserved but nothing is on disk and the Cases list is empty.
   *  This is a normal working state: analysis stays available, only case-only features are not. */
  pending?: boolean;
  posture: Posture[]; queue: QueueItem[];
}

export type ThemeName = 'iris-dark' | 'graphite' | 'midnight-blue' | 'solar' | 'paper'
  | 'nord' | 'ember' | 'daylight' | 'contrast';
/** Interface and monospace faces, both bundled — see styles/base.css for the stacks. */
export type FontName = 'space-grotesk' | 'inter' | 'ibm-plex-sans' | 'source-sans' | 'system';
export type MonoName = 'jetbrains-mono' | 'ibm-plex-mono' | 'source-code-pro' | 'system';
export type ComputeMode = 'auto' | 'cuda' | 'cpu';
export type AiProvider = 'none' | 'openai';

/** `systemPromptId` names the saved system prompt the investigator uses by default; '' = the built-in prompt alone. */
export interface AiSettings {
  provider: AiProvider; model: string; baseUrl: string; apiKey: string; agents: number;
  verifyTls: boolean; caBundle: string; systemPromptId: string;
  /**
   * The investigator's run budget. `enforceLimits: false` removes the step, wall-clock and write
   * ceilings entirely — for a case that has to be worked to the end. It does NOT remove the per-call
   * deadline, the context ceiling, or Stop: none of those is policy.
   */
  enforceLimits: boolean; maxSteps: number; maxSeconds: number; maxWrites: number;
}
/**
 * A saved prompt for the investigator (Settings → System prompts): ADDITIONAL instructions for a kind of
 * investigation, always appended to the built-in prompt — the tool discipline and citation rules stay.
 */
export interface SystemPrompt { id: string; name: string; text: string; createdAt: string; updatedAt: string }
/** `builtin` is the built-in prompt IN FORCE (the analyst's edit when `builtinEdited`); `builtinDefault` is always the shipped text. */
export interface SystemPromptsResponse { prompts: SystemPrompt[]; activeId: string; builtin: string; builtinDefault: string; builtinEdited: boolean }
/** The MCP server Iris exposes to outside agents. `token` is masked on read, like ai.apiKey. */
export interface McpSettings { enabled: boolean; allowWrites: boolean; token: string }
/** Ingest behaviour. `autoEnrich` false means phase 2 never runs unless it is asked for, per source. */
export interface IngestSettings { autoEnrich: boolean }
/**
 * Read-only network posture, returned on GET/PUT /api/settings and never persisted or accepted back.
 * It exists because the dangerous states here are the INVISIBLE ones — "no authentication at all",
 * "MCP switched on but refusing every request", "TLS verification off for the host every quoted log
 * line is sent to". Render `warnings` where they are configured, not in a separate audit screen.
 */
export interface SecurityPosture {
  authRequired: boolean;
  corsOrigins: string[];
  allowedHosts: string[];
  mcpServing: boolean;
  warnings: { code: string; message: string }[];
}

export interface Settings { theme: string; compute: { mode: ComputeMode }; ai: AiSettings; mcp: McpSettings; ingest: IngestSettings; analyst: string; security?: SecurityPosture }

/** GET /api/auth/status — whether this instance asks for a password + PIN, and whether this browser
 *  has a live session. Carries no credential and is reachable without one (the SPA must be able to
 *  ask before it can decide to render the login page). */
export interface AuthStatus {
  enabled: boolean;        // a login is required right now
  configured: boolean;     // credentials exist (they may be set but switched off)
  authenticated: boolean;  // this browser has a live session (always true when not enabled)
  minPassword: number;
  minPin: number;
  maxPin: number;
}

/** GET /api/mcp/status — state plus paste-ready client configuration for the Settings panel. */
export interface McpStatus {
  enabled: boolean; allowWrites: boolean; hasToken: boolean; token: string;
  /**
   * `enabled` is the switch the analyst set; `serving` is whether a client actually gets an answer.
   * They differ in exactly one state — enabled with no token, which fails closed — so the UI must
   * render `serving` and `blockedReason`, never `enabled` alone.
   */
  serving: boolean; blockedReason: string;
  url: string; protocol: string; transport: 'http';
  toolCount: number; readTools: string[]; writeTools: string[];
  config: {
    /**
     * The Authorization values here are a PLACEHOLDER, never the live token: this endpoint carries no
     * credential of its own, so anything that could read it could read the token. The token is
     * returned in the clear exactly once, from POST /api/mcp/token, and the panel fills that value
     * into the snippets it renders itself.
     */
    cursor: { mcpServers: Record<string, { url: string; headers?: Record<string, string> }> };
    claudeCode: string;
    stdioBridge: { mcpServers: Record<string, { command: string; args: string[]; env: Record<string, string> }> };
  };
}

export interface Gpu { index: number; name: string; memoryTotalMB: number; memoryUsedMB: number; driver?: string }
export interface ComputeStatus {
  available: boolean; active: 'cuda' | 'cpu'; mode: ComputeMode; gpus: Gpu[]; cudaVersion?: string;
  backend: 'cupy' | 'torch' | 'numpy'; lastCheck: string; checking: boolean; error?: string;
  /** Informational, not a failure (e.g. a CPU install with no GPU libraries) — render as a hint, never as an error. */
  note?: string;
  /** What the machine has and the worker counts Iris sized itself to (backend/app/resources.py). */
  resources?: {
    machine: { cpuLogical: number; cpuPhysical: number; cpuUsable: number; cpuQuota?: number | null; memTotalMB: number;
               memAvailableMB: number; memLimitMB?: number | null; container: boolean; platform: string };
    profile: { parseWorkers: number; graphWorkers: number; enrichWorkers: number; uploadLanes: number;
               pinned: Record<string, number>; reasons: string[] };
  } | null;
}

export interface EventLocationLine { n: number; text: string; current: boolean }
export interface EventLocation {
  file: string;
  /** null when the format has no one-line-per-event mapping (JSON array, EVTX, binary) */
  line: number | null;
  totalLines: number | null;
  exact: boolean;
  reason: string | null;
  context: EventLocationLine[];
}

export type EventSort = 'ts_desc' | 'ts_asc';
export interface EventsQuery { q?: string; sources?: string[]; sev?: Severity[]; from?: string; to?: string; limit?: number; offset?: number; scope?: Scope; sort?: EventSort }
/** State of the vectorised search index. A query NEVER builds it — if it is not ready the request
 *  scans (engine 'cpu') and the build runs in the background, so a warming index shows as progress
 *  instead of a query that never returns. */
export interface SearchIndexState {
  state: 'idle' | 'building' | 'ready';
  events: number; target: number; pct: number; elapsedSec: number; bytes: number; buildMs: number;
}
export interface EventsPage {
  total: number; rows: Event[]; engine?: 'cuda' | 'vector' | 'cpu'; tookMs?: number; candidates?: number;
  index?: SearchIndexState;
  /** False when the count is a FLOOR, not a total. The scan path (used while the index is still
   *  building) stops counting once it has the page plus a margin — counting every match on an 11 M
   *  event pool took minutes for a number nobody asked for. A count an analyst might quote has to be
   *  exact or visibly not, so the UI renders "10,000+" rather than a bare number. */
  totalExact?: boolean;
}

export interface TimelineStats { window: string; clusters: number; entities: number; egress: string }
export interface Timeline { stats: TimelineStats; clusters: Cluster[]; status?: DerivedState }

export interface Finding { level: Severity; title: string; body: string; evidence: string }
export interface IocHit { eventId: string; ts: string; sourceId: string; file: string }
/** 'extracted' is derived from detections; the other two are recorded artefacts with an author. */
export type IocAuthor = 'extracted' | 'analyst' | 'ai';
export interface Ioc {
  id: string; kind: string; value: string; count: number; files: string[];
  firstSeen: string | null; lastSeen: string | null; hits: IocHit[];
  /** entered by the analyst rather than extracted from a detection */
  manual: boolean;
  note: string;
  /** who recorded it — an AI-recorded indicator must be distinguishable from one the analyst typed */
  addedBy: IocAuthor;
  addedAt: string;
  /** the events the author cited as its origin; what places it on the timeline */
  citedEventIds: string[];
}
export interface IocInput { kind: string; value: string; note?: string; citedEventIds?: string[] }
export interface IocResponse { total: number; iocs: Ioc[] }

/** An indicator placed on the incident chronology, at the moment it was first seen. */
export interface IocMarker {
  id: string; kind: string; value: string; ts: string; lastSeen: string | null; count: number;
  manual: boolean; addedBy: IocAuthor; note: string; eventId: string; file: string; sourceId: string;
}
export interface IocMarkers { total: number; iocs: IocMarker[] }
export interface Report {
  caseId: string; caseName: string; analyst: string; generatedAt: string; severity: Severity; summary: string;
  findings: Finding[]; caseSet: Event[]; iocs: Ioc[]; notes: CaseNote[];
}
export type ExportFormat = 'md' | 'json' | 'stix' | 'pdf';

export type AiScope = 'case' | 'event' | 'cluster' | 'selection';
export interface AiAnalyzeRequest { scope: AiScope; id?: string; eventIds?: string[]; question?: string }
export type AiStreamEvent =
  | { type: 'agent'; agent: string; text: string }
  | { type: 'done'; summary: string; findings: Finding[] }
  | { type: 'error'; message: string };
/* ───── AI investigator: a tool-using agent driven by one free-form objective ───── */
export interface AiInvestigateRequest {
  prompt: string;
  /** supply your own so the run can be stopped before the first byte arrives */
  runId?: string;
  maxSteps?: number;
  maxSeconds?: number;
  /** what the panel was opened from, e.g. "event e412" — appended to the objective as context */
  focus?: string;
  /**
   * The run this one CONTINUES — the latest turn of the conversation that is open. The new run joins
   * that thread and starts from what the earlier turns established instead of investigating from
   * scratch. An unknown or deleted id degrades to a fresh conversation rather than failing.
   */
  continueFrom?: string;
  /** Which saved system prompt to run on. Omitted = the settings default; '' = the built-in prompt alone. */
  systemPromptId?: string;
}
/** One change a run made to the workspace, and how to take it back. */
export interface AiAction { id: string; runId: string; tool: string; at: string; summary: string; undo: Record<string, unknown>; undone: boolean }
/**
 * One persisted line of a conversation — the same shape the panel builds from the live SSE stream, so
 * a run being watched and a run read back out of history render through one code path.
 */
export interface AiTranscriptEntry {
  seq: number;
  kind: 'status' | 'step' | 'text' | 'tool' | 'warning';
  text: string; step: number;
  id: string; name: string; args: Record<string, unknown>; writes: boolean;
  ok: boolean | null; summary: string; tookMs: number;
  /**
   * When this entry was last CHANGED, on the same counter as `seq`. A tool entry is patched in place
   * when its result lands, so `?since=<lastSeq>` alone never resent it and the card kept spinning in
   * every polling tab. Merge by `seq` (the entry keeps its place); this only decides what is SENT.
   */
  updSeq?: number;
}
export interface AiRun {
  id: string; prompt: string; focus: string; model: string;
  /**
   * A CONVERSATION is a chain of runs: `threadId` is the first turn's id (its own, on a first turn)
   * and `parentId` is the turn this one continues. The RUN stays the unit of budget, of stopping and
   * of undo — "revert what it just did" has to mean one turn — while the thread is the chat.
   */
  parentId: string; threadId: string;
  /** the case active when the run STARTED — '' in the case-less workspace. History is global. */
  caseId: string; caseName: string;
  startedAt: string; endedAt: string; updatedAt: string;
  state: 'running' | 'done' | 'stopped' | 'error';
  reason: string; steps: number; toolCalls: number; answer: string; error: string;
  /** the server restarted while this run was still going */
  interrupted: boolean;
  actions: AiAction[]; unverifiedCitations: string[];
  /** empty in the listing; `?since=` returns only entries newer than a seq */
  transcript: AiTranscriptEntry[]; transcriptSeq: number; transcriptTruncated: boolean;
}
export type AiRunEvent =
  | { type: 'run'; runId: string; model: string; threadId?: string; parentId?: string; maxSteps: number; maxSeconds: number; maxContextTokens: number; maxWrites: number; maxCompactions?: number; maxToolSeconds?: number }
  /* `compactions`/`droppedMessages` are set on the status event that reports an automatic context
     compaction ("compacted N earlier steps into a running brief"). Never silent: the analyst has to be
     able to see that the model's view of the run was summarised. */
  /* `checkIn` marks the "your last N calls returned nothing new — another angle, or the report?" nudge,
     `budgetNotice` the "leave room to write it up" one and `documentCheck` the "you recorded nothing in
     the case" one. All three are ordinary status lines; the flags exist so the panel can tell a nudge
     from a step announcement. */
  | { type: 'status'; text: string; compactions?: number; droppedMessages?: number; checkIn?: number; budgetNotice?: boolean; documentCheck?: boolean; recordNudge?: number; summaryCheck?: boolean }
  | { type: 'step'; step: number; elapsedSec: number }
  | { type: 'delta'; text: string; step: number }
  | { type: 'tool_call'; id: string; name: string; arguments: Record<string, unknown>; step: number }
  | { type: 'tool_result'; id: string; name: string; ok: boolean; tookMs: number; summary: string; data: unknown }
  | { type: 'write'; action: AiAction }
  /** contextCeiling: the provider refused the transcript for its size and Iris folded it — this run now
      compacts at that many (estimated) tokens. retry: a transient provider failure being retried. */
  | { type: 'warning'; message: string; ids: string[]; contextCeiling?: number; compactions?: number; retry?: number }
  | { type: 'answer'; text: string }
  | { type: 'done'; runId: string; reason: string; state: string; steps: number; toolCalls: number; writes: number; actions: AiAction[]; unverifiedCitations: string[]; answer: string; elapsedSec: number;
      /* compactions = how many times the transcript was summarised; cachedToolCalls = repeated reads served
         from the run cache; textToolCalls = the provider never did NATIVE tool calling and Iris parsed the
         model's text-form calls instead. */
      compactions?: number; cachedToolCalls?: number; textToolCalls?: boolean }
  | { type: 'error'; message: string; actions?: AiAction[] };
export interface AiToolInfo { name: string; description: string; writes: boolean; parameters: string[] }
export interface AiToolsResponse { tools: AiToolInfo[]; limits: { maxSteps: number; maxSeconds: number; maxContextTokens: number; maxWrites: number; maxCompactions: number; maxToolSeconds?: number } }
/** Every turn of one conversation, oldest first — what the panel renders as a single chat. */
export interface AiThread { threadId: string; runs: AiRun[] }
export interface AiUndoResult { ok: true; undone: number; actions: AiAction[] }

export interface AiTestRequest { provider: AiProvider; model: string; baseUrl: string; apiKey: string; verifyTls?: boolean; caBundle?: string }
export interface AiTestResult { ok: boolean; message: string; latencyMs?: number }

export interface Health { ok: boolean; version: string }

export interface ClearAllResult {
  ok: true;
  // everything the wipe removed: pool sources/events, files on disk (cases + library + trash),
  // whole cases, trash entries and upload/parse jobs
  // plus aiRuns: the assistant's stored conversation transcripts, which quote the evidence verbatim
  // `cache` is the derived-cache tree (persisted graph, parsed-pool cache): built from the
  // evidence, quoting the evidence, so a wipe takes it too.
  removed: { sources: number; events: number; files: number; cases: number; trash: number; jobs: number; aiRuns: number; cache: number };
}
export interface ParserInfo { name: string; family: string; extensions: string[]; description: string; available: boolean; note?: string }
export interface MappingSuggestion { fields: string[]; delimiter: string | null; confidence: number; rationale: string; source: 'ai' | 'heuristic' }
export interface ParsersResponse { parsers: ParserInfo[] }

/* ───── Upload library: files already on disk, attachable to the active case ───── */
/** A deleted case still sitting in the trash. Deleting moves the folder aside instead of destroying it —
 *  a case holds the only copy of its uploads, so an rmtree lost the evidence for good. */
export interface TrashEntry {
  /** folder name in the trash, "<CASE-000N>-<timestamp>" — the handle for restoring */
  entry: string;
  caseId: string; name: string; deletedAt: string;
  events: number; sources: number; sizeBytes: number;
  caseSet: number; noteCount: number; iocCount: number; graphLinkCount: number;
}

export interface LibraryFile {
  /** '' for an UNATTACHED file — staged in the library, belonging to no case, safe from any case delete */
  caseId: string;
  fileName: string; displayName: string; size: number;
  /** already a registered source of the case it lives in */
  attached: boolean;
  /** already ingested into the case you are working on */
  inActiveCase: boolean;
  /** unattached files only */
  uploadedAt?: string;
  /** Detection metadata — unattached files only, from a bounded sniff at stage time (no parsing, no case). */
  parser?: string;
  confidence?: number;
  /** '' when unknown (case uploads); otherwise the same scale as Source.state */
  state?: '' | 'READY' | 'REVIEW' | 'MAP';
  /** line/record count; extrapolated for files larger than the probe window */
  lines?: number;
  linesEstimated?: boolean;
  sample?: string;
  /** the pool source this staged file was parsed into ('' when it is not in the pool, e.g. an archive) */
  sourceId?: string;
  events?: number;
  /** true when this file's events are NOT in the workspace — it is missing from search, per file */
  skipped?: boolean;
  /** which problem it is; they have different fixes and must not be conflated:
   *  'budget' the pool memory cap · 'unreadable' bytes unreachable on disk ·
   *  'parse-error' the parser failed (skipDetail is its message) · 'not-parsed' an unexpanded container */
  skipReason?: '' | 'budget' | 'unreadable' | 'parse-error' | 'not-parsed';
  skipDetail?: string;
  /** the pool budget in force, for 'budget' skips */
  budgetBytes?: number;
  /** Two-phase ingest. The Sources TABLE is built from this model, so without these the per-row chip
   *  had nothing to read and every row rendered as 'enriched'. '' means there is no pool source to
   *  report on (an unexpanded archive). When one staged file expands to several sources this is the
   *  LEAST finished of them — a row claiming 'enriched' while one source is still raw is the same lie. */
  enrich?: EnrichState | '';
  enrichError?: string;
  enrichedAt?: string;
}

/* ───── Upload & parse jobs (server-side, survive a refresh) ───── */
export type JobState = 'queued' | 'uploading' | 'parsing' | 'ready' | 'error';
export interface UploadJob {
  id: string;
  file: string;
  size: number;
  /** bytes the client reported sending — the server only ever sees a complete body */
  received: number;
  state: JobState;
  target: 'case' | 'library';
  /** '' for a library job: staged bytes belong to no case by design */
  caseId: string;
  parser: string;
  confidence: number;
  events: number;
  error: string;
  /** the server restarted while this job was in flight */
  interrupted: boolean;
  /** failed by the WATCHDOG, not by the parser — a heartbeat, a byte or the ingest request revives it.
   *  A job the parser actually failed is never stale, and never comes back. */
  stale?: boolean;
  sourceIds: string[];
  /** live PARSE progress — non-null only while state === 'parsing'. Server-side, so every tab sees it. */
  progress: ParseProgress | null;
  createdAt: string;
  updatedAt: string;
}
/** `received` above is the upload; this is the parse, which on a big file is the long half. */
export interface ParseProgress {
  bytesDone: number; bytesTotal: number; pct: number; events: number;
  /** > 1 when the file is being parsed across worker processes */
  workers: number;
  /** which half of the two-phase ingest is running: 'reading' = phase 1 (raw lines into the pool),
   *  'enriching' = phase 2 (the real parser, on the enrichment worker), 'parsing' = a container with no
   *  raw phase (binary/structured), 'merging' = folding the events into the pool. */
  phase: 'reading' | 'parsing' | 'enriching' | 'finishing' | 'detecting' | 'merging' | 'caching' | (string & {});
  /** 0-100 of the CURRENT phase when that phase is not a byte count (finishing / detecting / merging /
   *  caching). The byte bar hit 100 % the moment the last byte was read and then sat there for minutes
   *  under "parsing 100 %"; this is what moves instead. null while the phase is byte-measured. */
  stagePct?: number | null;
  bytesPerSec: number; etaSec: number | null; elapsedSec: number;
}
/** See CaseEnrichment.activity. `kind` names the state; `detail` is the sentence to show.
 *  'merging' is the long one and belongs to no source — it rebuilds the whole pool index. */
export interface EnrichActivity {
  kind: 'idle' | 'parsing' | 'merging' | 'waitingForPool' | 'noWorker';
  detail: string;
  elapsedSec: number;
  file: string;
  pct: number | null;
  etaSec: number | null;
  /** merging only */
  sources: number; events: number; stage: string; stageIndex: number; stageCount: number;
}

export interface JobsResponse { jobs: UploadJob[]; active: number; total: number }

/* ───── Bulk AI field mapping (Ingest → mapping queue) ───── */
export interface PendingMapping { id: string; file: string; state: SourceState; confidence: number; events: number }
export interface PendingMappings { total: number; sources: PendingMapping[] }
export interface AutoMapResult {
  id: string; file: string; state: string; status: 'applied' | 'suggested' | 'skipped' | 'failed';
  fields?: string[]; confidence?: number; rationale?: string; source?: 'ai' | 'heuristic';
  newState?: string; events?: number; reason?: string; error?: string;
}
export interface AutoMapResponse { total: number; applied: number; skipped: number; failed: number; results: AutoMapResult[] }

export type DeepPartial<T> = { [K in keyof T]?: T[K] extends object ? DeepPartial<T[K]> : T[K] };

/* live performance metrics (GET /api/compute/metrics) */
export interface GpuSample { index: number; name: string; util: number; memUtil: number; memUsedMB: number; memTotalMB: number; tempC: number | null; powerW: number | null; smClockMHz: number | null }
export interface MetricSample { t: string; gpus: GpuSample[]; active: 'cuda' | 'cpu'; eventsPerSec: number; bytesPerSec: number; totalParsedEvents: number; cpuPct: number | null; rssMB: number | null; sysCpuPct: number | null; sysMemPct: number | null; threads: number }
export interface MetricsResponse { intervalSec: number; samples: MetricSample[]; current: MetricSample | null }

/* ───── Cases (multi-case) ───── */
export interface CaseSummary {
  id: string; name: string; analyst: string; createdAt: string; updatedAt: string;
  sources: number; events: number; caseSet: number; active: boolean; sizeBytes: number;
  /** what the case HOLDS besides evidence — a curation-only case has 0 sources and 0 events but is
      not empty, and a delete confirmation that only counts the first three says it is. */
  noteCount: number; iocCount: number; graphLinkCount: number;
}

/* ───── Case set: the curated events that ARE the case (replaces pins) ───── */
export interface CaseSetEntry { eventId: string; labels: string[]; note: string; addedAt: string }
export interface CaseSetResponse { entries: CaseSetEntry[]; events: Event[]; labels: string[] }
/** 'all' = every ingested event; 'case' = re-run the analysis over only the case set. */
export type Scope = 'all' | 'case';

export interface CaseSnapshot {
  events: number; sev: Partial<Record<Severity, number>>; range: [string, string] | null;
  clusters: number; detections: number; entities: number;
}
export interface SourceBrief {
  id: string; file: string; parser: string; events: number; size: number; state: string;
  /** attached from the case-less library — it can be taken back out of the case without deleting it */
  fromLibrary?: boolean;
}
export interface CaseDetail extends CaseSummary {
  notes: CaseNote[]; snapshot: CaseSnapshot | null; sourceList: SourceBrief[];
}

/* ───── Case notes: a timestamped feed, each entry optionally linking to evidence ───── */
export type NoteRefKind = 'event' | 'search' | 'entity' | 'cluster' | 'source';
export interface NoteRef { kind: NoteRefKind; value: string; label?: string }
export interface CaseNote {
  id: string; text: string; author: string; createdAt: string;
  /** set only when the note was edited */
  updatedAt: string;
  refs: NoteRef[];
}
/** An image uploaded for a note; referenced from the note markdown as ![name](url). */
export interface Attachment { id: string; name: string; url: string; contentType: string; size: number }

/* ───── Detection rules & anomalies ───── */
export type RuleField = 'any' | 'msg' | 'raw' | 'host' | 'user' | 'source' | 'file' | (string & {});
export type RuleKind = 'regex' | 'builtin' | 'conditions';
/** Operators a custom rule's condition rows can use. The value input is typed by the operator. */
export type RuleOp = 'equals' | 'not_equals' | 'contains' | 'not_contains' | 'starts_with' | 'ends_with'
  | 'regex' | 'in' | 'not_in' | 'gt' | 'lt' | 'exists';
/**
 * One row of a condition-built custom rule: <field> <operator> <value>. The same idea as a built-in's
 * RuleParam, pointed at an event field: `value` is a regex for 'regex', a comma list for in/not_in, a
 * number for gt/lt, ignored for 'exists', and a literal otherwise.
 */
export interface RuleCondition { field: string; op: RuleOp; value?: string }
/** Windowed burst semantics for a condition rule: `count` matches inside `window` seconds, grouped by a field. */
export interface RuleThreshold { count: number; window: number; groupBy?: string }
export interface RuleFlags { ignoreCase: boolean; multiline?: boolean }
export interface RulePattern { field: string; pattern: string }
export type RuleParamKind = 'values' | 'regex' | 'text' | 'int' | 'seconds' | 'bytes';
/**
 * One editable knob of a built-in's condition. Built-ins match in Python, but every constant that
 * shape compares against — event id, status codes, burst threshold, window, byte cutoff, regex — is a
 * parameter, so editing one genuinely changes what the rule flags. `value` is live, `default` is stock.
 */
export interface RuleParam {
  key: string; label: string; kind: RuleParamKind; value: string; default: string;
  /** the event field this is compared against, when there is one */
  field: string;
  help: string;
}
export interface Rule {
  id: string; name: string; description: string; sev: Severity; enabled: boolean; builtin: boolean;
  kind: RuleKind; pattern?: string; field?: RuleField; flags?: RuleFlags; sourceFilter?: string; tags: string[];
  /** custom rules: typed condition rows instead of a raw regex (kind 'conditions') */
  conditions?: RuleCondition[];
  /** how the condition rows are joined; defaults to 'and' */
  combinator?: 'and' | 'or';
  /** optional windowed-burst semantics for a condition rule */
  threshold?: RuleThreshold | null;
  createdBy: 'user' | 'ai' | 'system'; createdAt: string; updatedAt: string; hits?: number; error?: string;
  /** built-in whose name/description/sev/tags the analyst changed */
  overridden?: boolean;
  /** built-in removed from the catalogue — only present when the list was fetched with includeRemoved */
  removed?: boolean;
  /**
   * The TRIGGER — the exact condition the engine evaluates (fields, values, regex, thresholds, windows).
   * Read-only: Python for a built-in, generated from the pattern/conditions for a custom rule. This, not
   * `description`, is what does the flagging.
   */
  logic?: string;
  /** how the rule decides. Drives the badge next to the trigger in the editor. */
  /** 'graph' reads the ENTITY GRAPH rather than one event at a time (see GraphFinding): it tags no
   *  event, so its `hits` is null until a graph roll-up has been computed — never 0. */
  mechanism?: 'regex' | 'fields' | 'threshold' | 'correlation' | 'graph';
  /** the regexes it actually matches with — derived from the regex params / conditions, never hand-maintained */
  patterns?: RulePattern[];
  /** built-in only: every editable knob of the condition */
  params?: RuleParam[];
}
export type RuleInput = Omit<Rule, 'id' | 'createdAt' | 'updatedAt' | 'hits' | 'builtin' | 'kind' | 'createdBy'
  | 'overridden' | 'removed' | 'logic' | 'mechanism' | 'patterns' | 'params' | 'error'> &
  Partial<Pick<Rule, 'builtin' | 'kind' | 'createdBy'>> & {
    /** built-in only: {param key: value} edits to the condition. Unknown keys 400. */
    params?: Record<string, string>;
  };
export interface RuleTestRequest { pattern: string; field: RuleField; flags?: RuleFlags; sourceFilter?: string }
export interface RuleTestResult { hits: number; sample: Event[]; tookMs: number; error?: string }
/** A dry run of a whole rule definition (POST /api/rules/preview) — nothing is saved and no event is
 *  tagged. `trigger` is what the ENGINE would evaluate, in words; it is never the analyst's description. */
export interface RulePreviewResult extends RuleTestResult { trigger: string; mechanism: string }
export interface RuleSuggestRequest { prompt: string; examples?: string[] }
export interface RuleSuggestResult { rule: Rule; rationale: string; source: 'ai' | 'heuristic' }
/** Where a rule's hits are: a case the file was filed into, or the library (caseId ''). */
export interface AnomalyCase { caseId: string; caseName: string; hits: number }
export interface Anomaly {
  ruleId: string; name: string; sev: Severity; hits: number; firstSeen: string | null; lastSeen: string | null;
  sources: string[]; cases: AnomalyCase[]; sample: Event[]; kind: RuleKind;
}
/** The per-rule aggregation is a DERIVED structure (see DerivedState): built once per store version AND
 *  rules revision, in the background. While `status.state === 'building'` the list is empty on purpose —
 *  render the build state, because an empty anomaly list reads as "nothing fired". */
export interface AnomaliesResponse { total: number; anomalies: Anomaly[]; status?: DerivedState }

/* ───── Exclusions (GET /api/exclusions) ─────
 * The one feature in Iris that can HIDE things, so the type carries what makes that safe: `suppressed`
 * is how many detections it actually removed on the last pass (null = no pass since it changed, which
 * is NOT zero), and `appliesToGraph` says whether it can be evaluated against an entity-graph node at
 * all — a node has a type and a value and no fields, so a condition on `dst_port` cannot be checked
 * against one and is declared rather than half-applied. */
export interface Exclusion {
  id: string;
  name: string;
  conditions: RuleCondition[];
  combinator: 'and' | 'or';
  /** empty = EVERY rule; otherwise the rule ids it is scoped to */
  ruleIds: string[];
  note: string;
  enabled: boolean;
  createdBy: 'user' | 'ai' | 'system';
  createdAt: string;
  updatedAt: string;
  suppressed: number | null;
  appliesToGraph: boolean;
  error?: string | null;
  /** generated, read-only sentence describing what it suppresses */
  logic?: string | null;
}
export interface ExclusionInput {
  name: string;
  conditions: RuleCondition[];
  combinator?: 'and' | 'or';
  ruleIds?: string[];
  note?: string;
  enabled?: boolean;
}
/** Offered, never applied: shipping suppressions enabled would mean an analyst's first search silently
 *  omitted evidence they never chose to omit. Each one says WHY. */
export interface ExclusionSuggestion {
  name: string; why: string; conditions: RuleCondition[]; combinator: 'and' | 'or'; ruleIds: string[];
}
export interface ExclusionsResponse {
  exclusions: Exclusion[]; suggestions: ExclusionSuggestion[]; suppressed: number;
}

/* ───── Entity-graph findings (GET /api/graph/anomalies) ─────
 * A whole class of detection cannot be phrased per event: one address authenticating as fourteen
 * accounts is a property of the SHAPE of the relationships, and every one of those lines is
 * unremarkable. These rules read the built graph and name the ENTITY, citing real event ids. */
export interface GraphFinding {
  ruleId: string; name: string; sev: Severity;
  nodeId: string; nodeType: string; nodeValue: string;
  /** one sentence, already in the analyst's terms */
  summary: string;
  /** the number the threshold was compared against, and what it counts */
  metric: number; metricLabel: string;
  /** neighbour node ids that make up the fan-out (capped) */
  related: string[];
  citedEventIds: string[];
  first: string; last: string;
}
export interface GraphFindingsResponse {
  findings: GraphFinding[];
  /** graph rules that are switched on */
  rules: number;
  /** FALSE means the graph is not built, so nobody has looked. Render that state — an empty list would
   *  say the graph is clean, which is a claim nothing has checked. */
  evaluated: boolean;
  status?: DerivedState;
  tookMs: number;
}

/* ───── Search field facets (GET /api/events/fields) ───── */
export interface FieldFacetValue { value: string; count: number }
export interface FieldFacet {
  name: string;
  /** events in the current result set that carry this field */
  count: number;
  /** ≤ 5 distinct values, first-seen order */
  sample: string[];
  /** ≤ 8 most common values */
  topValues: FieldFacetValue[];
  /** distinct values seen (over the scanned events) */
  distinct: number;
}
export interface FieldFacetsResponse {
  fields: FieldFacet[];
  /** distinct field names in the result set (before `limit`) */
  total: number;
  /** matching events */
  events: number;
  /** events actually walked (≤ 20 000) */
  scanned: number;
  /** true when the result set was larger than the scan cap — counts are over the first 20 000 matches */
  sampled: boolean;
  engine: 'cuda' | 'vector' | 'cpu';
  tookMs: number;
}
/** `values` is values-per-field (8 by default). The rail asks for more when a field is opened that
 *  has more — on a workspace with hundreds of sources, eight of them reads as "these are the sources". */
export type FieldFacetsQuery = Omit<EventsQuery, 'limit' | 'offset' | 'sort'> & { limit?: number; values?: number };

/* ───── Raw log viewer (GET /api/sources/{sid}/raw) ───── */
export interface RawLine { n: number; text: string }
export interface RawLogPage {
  file: string;
  size: number;
  /** lines in the whole file (0 when binary) */
  totalLines: number;
  /** lines matching `q` (== totalLines when no q) */
  matches: number;
  offset: number;
  limit: number;
  q: string;
  lines: RawLine[];
  /** some line on this page was cut at 2000 chars */
  truncatedLine: boolean;
  /** file is not line-addressable (EVTX, dumps, sqlite, NUL bytes) — lines is empty, see hint */
  binary: boolean;
  hint: string | null;
}
