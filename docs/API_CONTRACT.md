# Iris — API contract (backend ⇄ frontend)

Backend: FastAPI on port 8000, all routes under `/api`. Frontend (Vite dev) proxies `/api` → `http://localhost:8000`.
In production the FastAPI app also serves the built frontend from `frontend/dist` (SPA fallback to index.html).

All timestamps are ISO-8601 UTC strings. IDs are strings.

## Types
```ts
type Severity = 'critical'|'high'|'medium'|'low'|'info';

/* Phase 2 of a two-phase ingest — see "Two-phase ingest" below.
     raw       the lines are in the pool and searchable, NOTHING is interpreted: no timestamp, no
               severity, no parsed fields, no entities, no detections. A screen showing any of those for
               this source is showing a DEFAULT, not a finding, and has to say so.
     queued    waiting for the enrichment worker.      enriching  being parsed right now.
     enriched  done — and also the BIRTH state of a container that has no raw form (EVTX, SQLite, pcap, PDF,
               XLSX, OCR'd image, mail): there is no readable text until its parser has run, so those
               parse fully on ingest exactly as before.
     skipped   the analyst declined it. Technically identical to `raw`, but a DECISION — it is never
               counted as outstanding and never raises an incompleteness warning.
     error     phase 2 failed; `enrichError` carries the message and `state` is 'ERROR' too. The raw
               lines survive in the pool, and POST /api/sources/{id}/enrich retries it. */
type EnrichState = 'raw'|'queued'|'enriching'|'enriched'|'skipped'|'error';

/* A source's `file` carries provenance: `incident.zip!var/log/auth.log` names the archive it was
   staged inside AND the path within it. For such a member `Source.size` is the MEMBER's size, and
   /raw and /download serve the MEMBER — not the container, which is what they used to do. */
interface Source { id:string; file:string; parser:string; events:number; range:[string,string]|null;
  confidence:number /*0..1*/; state:'READY'|'REVIEW'|'MAP'|'PARSING'|'ERROR'; size:number; error?:string;
  guessedFields?:string[]; sample?:string; delimiter?:string;
  /* Where the bytes live. 'case' = cases/<id>/uploads/. 'library' = $IRIS_DATA_DIR/library/, belonging to
     NO case — parsed and searchable all the same. Attaching it to a case flips this to 'case'. */
  origin?:'case'|'library';
  /* Always sent by this server. `range` is null and every event carries ts:'' until enrich === 'enriched'. */
  enrich:EnrichState; enrichError?:string|null; enrichedAt?:string|null /*ISO-8601 UTC*/;
  /* Case-set event ids this source's phase 2 could no longer resolve, and that re-anchoring could not
     heal either — the line is genuinely gone (a CSV header row phase 2 correctly drops, a record the
     two phases split differently). The curated entry is KEPT and still on the timeline; what it has
     lost is its pointer at the evidence, and the screens must SAY so rather than showing an entry that
     silently resolves to nothing. Empty for every source that lost nothing, never null. Computed per
     RESPONSE from the last phase-2 merge and never persisted, exactly like `progress` — a restart does
     not replay a warning about curation that may since have been re-anchored or removed. An entry the
     remap carried over, or that `_reanchor_case_set` re-pointed at its own line, is NOT reported here:
     it lost nothing. */
  lostCitations?:string[];
  /* LIVE parse detail for this source — the same ParseProgress a job row carries (see "Upload & parse
     jobs"), read straight off jobs.PARSE_PROGRESS. Non-null ONLY while this source is actually being
     read: state 'PARSING' or enrich 'enriching'. A spinner says "something is happening"; on a 639 MB
     capture that is indistinguishable from a hang for twenty minutes, and the percentage, the event
     count and the ETA all already existed server-side. In-memory only, so it is absent after a restart
     until the work resumes. */
  progress?:ParseProgress|null }

interface Event { id:string; ts:string; source:string /*parser family e.g. nginx.access*/; sourceId:string; file:string;
  host:string; user:string; msg:string; sev:Severity; raw:string;
  fields:Record<string,string>; entities:string[];
  detections:{name:string;id:string;level:Severity}[]; baseline?:string }

interface Cluster { id:string; title:string; start:string; end:string; span:string; tag:'FREQUENCY'|'ENTITY LINK'|'ANOMALY';
  sev:Severity; count:number; sources:string[]; why:string; eventIds:string[] }

interface Entity { name:string; kind:string; first:string; count:number;
  facts:[string,string][]; links:{name:string; shared:number; via:string}[] }
interface Edge { a:string; b:string; weight:number }

/* A staged library file whose events are NOT in the workspace pool, i.e. NOT searchable.
   `reason` is 'budget' (it would have taken the pool past its memory cap — `budgetBytes` is that cap and
   `usedBytes` what the files ahead of it took) or 'unreadable' (the bytes could not be read off disk).
   A file that FAILED TO PARSE is never reported here: it IS in the pool, as a Source with state 'ERROR'
   carrying the parser's message. The two are different problems with different fixes and the API keeps
   them apart. */
interface PoolSkip { fileName:string /*on disk*/; displayName:string; size:number /*bytes of log*/;
  reason:'budget'|'unreadable'; detail:string /*one actionable sentence*/;
  budgetBytes:number; usedBytes:number }

interface PoolProgress { bytesDone:number; bytesTotal:number; pct:number /*0..100*/;
  filesDone:number; filesTotal:number;
  currentFile:string /*'' between files*/; currentBytesDone:number; currentBytesTotal:number; currentPct:number;
  workers:number /*parse workers on the current file; >1 = multi-process path*/;
  bytesPerSec:number; etaSec:number|null; elapsedSec:number;
  /* per-file breakdown of the SAME load, in library order. The aggregate plus `currentFile` could not say
     which of 40 files were already in the pool and which had not been touched. Populated for the whole
     plan from the moment the load starts; `bytesDone`/`pct` are live for the file being parsed. */
  files:PoolFileProgress[] }
interface PoolFileProgress { file:string; size:number;
  /* 'skipped' = the file was NOT loaded (no memory headroom) and its events are NOT searchable.
     It is a distinct outcome from 'error' (parsed, parser failed) and must never be shown as 'done'
     — a file silently absent from search is indistinguishable from a search that found nothing.
     `Case.poolSkipped` / `LibraryFile.skipReason` carry the reason. */
  state:'pending'|'parsing'|'done'|'error'|'skipped';
  bytesDone:number; pct:number; events:number }

/* The WORKSPACE, seen through the (optional) active case.
   `sources` / `eventCount` describe the CASE and are empty while none exists.
   `librarySources` / `poolEventCount` describe the whole analysable POOL: sources + librarySources is
   everything the default (scope=all) analysis runs over, so Search, Timeline, Anomalies, the graph and
   IOC extraction all work with zero cases on disk. */
interface Case { id:string; name:string; analyst:string; createdAt:string; sources:Source[];
  /* one-paragraph description of the investigation, persisted in case.json. Written by the analyst or
     set by the AI investigator's update_case tool. "" when never set. */
  summary:string;
  eventCount:number; librarySources:Source[]; poolEventCount:number;
  /* A large library is parsed in a BACKGROUND thread so the API is reachable immediately (parsing 589 MB
     inside the startup lifespan kept /api/health from ever answering). While poolLoading is true the
     analysis screens must say "still loading N sources" rather than show an empty result as if it were
     final. poolSkipped counts staged files left unparsed because the pool hit its memory budget
     (IRIS_POOL_MAX_MB) — they stay listed in the library and stay attachable to a case.
     poolSkippedFiles is the PER-FILE truth behind that count (poolSkipped === poolSkippedFiles.length):
     an aggregate alone cannot say WHICH file is missing from search, and on the real library the two
     skipped files were the two largest (263 MB each of 589 MB total). Any screen that could read as
     "nothing found" must say that N sources are not loaded. poolBudgetBytes is the budget in force, in
     bytes of SOURCE LOG (0 = unlimited), so the UI can state the remedy with real numbers. */
  poolLoading:boolean; poolPending:number; poolLoaded:number; poolSkipped:number;
  poolSkippedFiles:PoolSkip[]; poolBudgetBytes:number;
  /* Real progress for that background load, in BYTES of source log — null when nothing is loading.
     "16 more sources" is not progress when one of them is 263 MB and the rest are 2 MB: the count sat
     still for ten minutes. `currentFile` + `currentBytesDone/Total` come from the live per-source parse
     tracker, so a single huge file still visibly moves. `workers` > 1 means that file is being parsed by
     the multi-process path. */
  poolProgress:PoolProgress|null;
  /* How much of the pool has actually been INTERPRETED (two-phase ingest). Derived from per-source
     metadata only — GET /api/case is O(1) in the event count and must stay that way. */
  enrichment:CaseEnrichment;
  pinned:string[]; posture:{label:string;value:string;pct:number;color:'ok'|'warn'|'bad'}[];
  queue:{label:string;detail:string;done:boolean}[];
  /* PENDING = an id held in reserve after the last case was deleted: nothing on disk, absent from
     GET /api/cases, and GET /api/cases/{that id} 404s. The UI MUST read this as "no active case" -
     rendering it as one is what made a deleted case look like it was still there. An EXPLICIT write
     (create, rename, note, library attach) materialises the case and clears the flag; UPLOADING never
     does - POST /api/sources stages to the library instead of inventing a case. "No active case" is a
     normal working state, NOT an error: the analysis screens stay fully usable, only case-only features
     (case set, notes, manual IOCs, accepted graph links, findings/report) are unavailable. */
  pending?:boolean }

/* Two numbers because there are two questions, and they have different answers:
     pending     = queued + enriching — is work IN FLIGHT? This is what a progress banner counts down.
     outstanding = raw + queued + enriching — is my ANSWER incomplete? Those sources are in the pool as
                   raw lines, so the timeline, the entity graph and the anomaly list are answering over
                   PART of the corpus and every one of those screens has to say so. An empty graph that
                   is really "not enriched yet" is a lie about the evidence.
   A `skipped` source is in NEITHER: the analyst declined it, and a warning that can never be cleared is
   noise. It is still visible in `counts`. */
interface EnrichCounts { raw:number; queued:number; enriching:number; enriched:number; skipped:number; error:number }
/* `running` is RECONCILED against `counts`, not taken from the queue: the worker keeps the name of
   what it popped through the batch COMMIT that follows it, during which that source is already
   `enriched`. Reporting it made the banner say "Interpreting capture20110811.binetflow" about a file
   that had finished, and count it as one of the queued sources ("2 waiting behind it" when 3 were).
   A sid appears here only while its source's `enrich` really is 'enriching'.
   `committing` is that merge: real work, O(the whole pool) and tens of seconds at 16 M events, and it
   belongs to NO source — every member of the batch is already enriched — so a screen names it for
   what it is rather than blaming the last file it read.
   "Interpreted" means `counts.enriched` and nothing else. A UI that computes it as "not raw" counts
   queued and enriching sources as done, which is how "14 of 14 sources interpreted" came to sit
   directly above a line saying three of them were still to come. */
interface CaseEnrichment { counts:EnrichCounts;
  running:string /*source in phase 2 right now, '' when none is*/;
  committing:boolean /*a finished batch is merging into the pool*/;
  pending:number; outstanding:number;
  activity:EnrichActivity;
  /* The pool-wide detection pass is running in the BACKGROUND. After a commit the per-event rules are
     stamped on the NEW events before they enter the pool (proportional to the batch); the windowed
     rules read the density of the whole pool and are re-evaluated afterwards, off the worker,
     coalesced across commits. It holds nothing up — the events are searchable, the queue moves — but
     on a large workspace it is minutes of one core, and a pass nobody can see is exactly the "nothing
     is happening" `activity` exists to prevent. Measured at 1 M events the full catalogue is 38 s, 68 %
     of it `re.search` over every raw line; running it on the worker after every batch was what
     "committing" spent half an hour on with the merge itself long finished. */
  detectionsRefreshing:boolean; detectionsRefreshSec:number;
  runningFile:string; runningPct:number|null; runningPhase:string; runningEtaSec:number|null;
  needsAction:number }

/* Phase 2 parses SMALL queued sources in PARALLEL worker processes (one file per process, up to the
   memory-aware worker count) and commits them in the parent in completion order; big files keep the
   chunked pool. A queue of forty one-second files no longer takes forty seconds a core. The commit
   is still one merge per batch. */

/* WHAT phase 2 is doing right now — the answer to "what is it waiting on?". The counts say how much is
   LEFT and never said what was happening: a 16.9 MB file behind a batch merge reported "1 queued to
   interpret" for minutes while the 13.8 M-event pool rebuild it was queued behind ran unannounced.
   Every kind below used to render as that one sentence.
     parsing         a source is being read and normalized (this one has `file`/`pct`/`etaSec`)
     merging         a finished batch is being folded into the pool — O(THE WHOLE POOL), the long one.
                     Belongs to NO source (its members are already `enriched`), carries `sources`,
                     `events` and which of the merge's stages is running, and OUTRANKS `running`.
     waitingForPool  the library is still loading; the worker yields rather than compete with it
     noWorker        nothing is servicing the queue — those sources stay raw until Iris restarts
     idle            nothing to do (with a queue: between items, which is not "a file is being read")
   `detail` is the sentence to show, written where the facts are. `elapsedSec` is what turns "it is
   doing something" into "it has been doing this for four minutes". */
interface EnrichActivity { kind:'idle'|'parsing'|'merging'|'waitingForPool'|'noWorker';
  detail:string; elapsedSec:number;
  file:string; pct:number|null; etaSec:number|null;
  sources:number; events:number; stage:string; stageIndex:number; stageCount:number }

interface Settings {
  theme:string;                                   // 'iris-dark' | 'graphite' | 'paper' | 'midnight-blue' | 'solar'
  compute:{ mode:'auto'|'cuda'|'cpu' };           // user preference
  ai:{ provider:'none'|'openai'; model:string /*default gpt-4o-mini*/; baseUrl:string /*optional; blank = https://api.openai.com/v1; any OpenAI-compatible endpoint works*/;
       apiKey:string /*masked on read: '••••'+last4 or ''*/ ; agents:number /*1..4 parallel analysis agents*/ ;
       systemPromptId:string /*the saved instructions appended to the built-in prompt by default; '' = the built-in prompt alone*/ ;
       /* The investigator's RUN BUDGET, editable on Settings -> AI assistant. `enforceLimits:false`
          removes the step, wall-clock and write ceilings entirely, for a case that has to be worked
          to the end; `limits()` then reports `enforced:0` and those three come back as a sentinel no
          counter reaches. It does NOT remove the per-CALL deadline, the context ceiling/compaction or
          Stop - none of those is a policy choice. IRIS_AI_MAX_STEPS / _MAX_SECONDS still SEED the
          defaults for a headless install; a value saved in the UI wins. */
       enforceLimits:boolean; maxSteps:number /*default 40*/; maxSeconds:number /*default 600*/;
       maxWrites:number /*default 200*/ }
  /* The MCP server Iris EXPOSES to outside agents (Cursor / Claude Code / Claude Desktop). Off by default:
     enabling it hands a remote model the whole evidence pool. `allowWrites` is a second switch — a read
     cannot change a case, a write can. `token` is REQUIRED, not optional: enabled with no token FAILS
     CLOSED (503 on every /api/mcp request), because Iris has no other authentication and in a forensics
     tool the READS are the sensitive asset. Masked on read like apiKey; unlike apiKey an EMPTY token on
     PUT means "remove it" — which now closes the server rather than opening it. */
  mcp:{ enabled:boolean; allowWrites:boolean; token:string };
  /* Two-phase ingest. autoEnrich=false means phase 2 NEVER starts on its own — a log lands as raw lines
     and stays that way until POST /api/sources/{id}/enrich asks for it, per source. That is the mode for
     someone who wants grep over raw text and nothing else. It survives a restart: an untouched `raw`
     source is not re-queued at startup either (a restart is not a request), while a source that was
     already queued/enriching WAS asked for and that request is honoured. Default true. */
  ingest:{ autoEnrich:boolean };
  analyst:string;
  /* READ-ONLY. Derived per request, never persisted, ignored on PUT (echoing the whole object back is
     safe). It exists because the dangerous states are the invisible ones: "no authentication at all",
     "MCP switched on but refusing every request", "TLS verification off for the host every quoted log
     line is sent to". `warnings[].code` is stable — 'no-auth' | 'mcp-no-token' | 'ai-tls-unverified'. */
  security?:{ authRequired:boolean; corsOrigins:string[]; allowedHosts:string[]; mcpServing:boolean;
              warnings:{code:string; message:string}[] };
}

interface McpStatus {                              // GET /api/mcp/status — drives Settings → MCP server
  enabled:boolean; allowWrites:boolean; hasToken:boolean; token:string /*masked*/;
  /* `enabled` is the switch the analyst set; `serving` is whether a client actually gets an answer.
     They differ in exactly one state — enabled with no token — so the UI renders `serving`. */
  serving:boolean; blockedReason:string;
  url:string;                                      // the client-facing endpoint, derived from the request origin
  protocol:string; transport:'http';
  toolCount:number; readTools:string[]; writeTools:string[];
  /* The Authorization values in `config` are a PLACEHOLDER ('<your Iris MCP token>'), never the live
     token: this endpoint carries no credential of its own, so anything that could read it could read
     the token. The one clear-text delivery is POST /api/mcp/token, and the Settings panel fills that
     value into the snippets it renders itself. */
  config:{ cursor:{mcpServers:Record<string,{url:string; headers?:Record<string,string>}>};
           claudeCode:string;                      // a ready-to-run `claude mcp add …` command
           stdioBridge:{mcpServers:Record<string,{command:string; args:string[]; env:Record<string,string>}>} };
}

interface ComputeStatus { available:boolean; active:'cuda'|'cpu'; mode:'auto'|'cuda'|'cpu'; gpus:{index:number;name:string;memoryTotalMB:number;memoryUsedMB:number;driver?:string}[];
  cudaVersion?:string; backend:'cupy'|'torch'|'numpy'; lastCheck:string; checking:boolean; error?:string; note?:string;
  resources?: { machine: { cpuLogical:number; cpuPhysical:number; cpuUsable:number; cpuQuota?:number; memTotalMB:number;
                           memAvailableMB:number; memLimitMB?:number; container:boolean; platform:string };
                profile: { parseWorkers:number; graphWorkers:number; enrichWorkers:number; uploadLanes:number;
                           pinned:Record<string,number>; reasons:string[] } } }
// resources = what the machine has (cores this process may USE — affinity and container quota, not the host count —
//             and memory, the container limit when there is one) and the worker counts Iris derived from it
//             (app/resources.py). `pinned` lists every IRIS_*_WORKERS env var that overrode the derived value.
// error = something is wrong (mode 'cuda' with no backend, or a GPU lib that is installed but broken — raw probe detail included).
// note  = informational, not a failure: on a CPU install in mode 'auto'/'cpu' neither cupy nor torch is present, which is the
//         expected supported configuration. The UI must render `note` as a hint, never as an error.
```

## Transport rules that apply to EVERY endpoint — added

Implemented once, as raw ASGI, in `backend/app/security.py`. They are part of the contract because a
client that trips one gets a `403`/`401`/`415` from no route at all, with `{detail:string}` naming the fix.

| Rule | Effect | Who it affects |
|---|---|---|
| **CORS is an allowlist, never `*`** (`IRIS_CORS_ORIGINS`; default localhost/127.0.0.1 on the app port + `:5173`) | A foreign origin gets no `access-control-allow-*` header, on the simple request **and on the preflight**. `OPTIONS` asking for a non-safe method from a foreign origin is **403** before CORS is consulted. | Nothing legitimate — the SPA is same-origin; the list exists for `npm run dev`. |
| **Cross-site writes are refused → 403** | `POST`/`PUT`/`PATCH`/`DELETE` carrying a foreign `Origin`, or `Sec-Fetch-Site: cross-site`/`same-site` when `Origin` is absent. An allowed `Origin` settles it (so the Vite dev server, which a browser labels `same-site`, still works). | Browsers only. curl, the MCP stdio bridge, Cursor and Claude Code send no `Origin`. |
| **Form-shaped bodies on `/api` → 415** | `application/x-www-form-urlencoded` and `text/plain` on a non-safe method. These are the two body shapes a browser can post cross-site with **no preflight**, i.e. the ones CORS never gets a say about. | Nothing: Iris clients send `application/json`, uploads send `multipart/form-data` (still accepted). |
| **`Host` must be `localhost`, an IP literal, or in `IRIS_ALLOWED_HOSTS` → 403** | DNS-rebinding defence (also what the MCP spec asks for): a rebound name makes the attacker's page same-origin, so every other check passes by construction. | Reverse proxies — name them in `IRIS_ALLOWED_HOSTS`. |
| **`IRIS_AUTH_TOKEN`, when set → 401** | `Authorization: Bearer <token>`, `X-Iris-Token: <token>`, or the `iris_token` cookie planted by opening `/?token=<token>` once (HttpOnly, SameSite=strict). Exempt: `GET /api/health` (healthchecks, `start.*`) and `POST /api/mcp` (it carries its own mandatory token). `/api/mcp/status` and `/api/mcp/token` are **not** exempt. | Opt-in; unset by default. |

`GET`/`HEAD` are never refused by the cross-site guard — a safe method cannot change evidence, and CORS is
what stops the body being read. Loopback binding (`IRIS_BIND_HOST`, default `127.0.0.1`) is a defence
against the **network**, not against a web page: a browser on this machine reaches `localhost` regardless.

## Endpoints
- `GET  /api/health` → `{ok:true, version}`
- `GET  /api/case` → Case (the workspace: the active case plus the case-less pool. On a fresh install / after
   deleting them all there is NO case — the id is reserved and `pending:true`, and the UI must render "no active
   case" while keeping every analysis screen usable. Poll it while `poolLoading` or any source is `PARSING`.)
- `PATCH /api/case` body `{name?, analyst?}` → Case
- `POST /api/case/reset` → Case (clears the CASE's sources/events and deletes its uploads; the case-less library
   pool is untouched — it belongs to no case)
- `POST /api/sources` multipart `files[]` → `Source[]`
   - A line-oriented TEXT log comes back with `enrich:'raw'` and its full `events` count within the
     request: phase 1 splits it into lines and lands them in the pool, searchable at once. `range` is
     null and every event carries `ts:''` until phase 2 has run — see **Two-phase ingest** below.
     A binary/structured container (EVTX, SQLite, PDF, XLSX, image, mail, pcap) has no raw form and parses
     fully here, synchronously for files ≤ 50 MB and in a background thread above that (poll GET /api/case).
   - **Never creates a case.** With no active case (`Case.pending`) the bytes are staged in the library and
     parsed into the case-less pool: `X-Iris-Staged-To-Library` holds the number of files staged, the returned
     Sources carry `origin:'library'`, and `/api/cases` stays `[]` with no `cases/<id>/` directory written.
     The events are immediately searchable — a case is not required to analyse anything. `POST
     /api/library/attach` moves them into a case later, without re-parsing them.
   - **Archives expand into one Source per contained file** (zip, tar, tar.gz/tgz, tar.bz2, tar.xz, gz, bz2, xz,
     7z; `.rar` only if the caller installed rarfile plus an unrar/bsdtar binary — the unrar licence is non-free,
     so Iris does not ship it and a `.rar` upload comes back as an ERROR source saying so). `Source.file` keeps the provenance as
     `archive.zip!path/inside.log`, and that same string is `Event.file`. Nested archives expand 3 levels deep.
   - A container Iris **refuses** to expand — password protected/encrypted, a member escaping the archive root
     (zip-slip), the zip-bomb caps (5,000 entries / 512 MB uncompressed) tripping, or a format whose optional
     package is missing — comes back as an extra `Source` with `state:'ERROR'` and a user-facing `error` string
     explaining why nothing was ingested. It carries `parser:'archive'` and is not persisted across restarts.
     The same applies to `POST /api/library/attach`.
- `GET  /api/sources/{id}` → Source
- `DELETE /api/sources/{id}` → `{ok:true}`
- `POST /api/sources/{id}/enrich` → Source — run phase 2 for this source NOW, whatever `settings.ingest.autoEnrich`
   says (the setting governs what happens AUTOMATICALLY; an explicit request is not automatic). Enqueues a
   source that is `raw` (never asked for), `skipped` (the analyst changed their mind) or `error` (a retry —
   a failed phase-2 parse leaves the raw lines in the pool and is worth another attempt after a field
   mapping or a rule change), and returns it with `enrich:'queued'`. **200 with no change** when it is
   already `queued`/`enriching`: the outcome is already pending, and failing a double-click, a second tab
   or a retried request would be a lie about what is happening. **409** when it is already `enriched` —
   there is nothing left to queue, and answering 200 would let the UI report "queued" for a source that
   will never be parsed again; the refusal names `POST /api/sources/{id}/mapping`, which is the real
   re-parse. **404** for an unknown id. Nothing parses on the request thread: the work happens on the
   single background enrichment worker and the response is only the new state.
- `POST /api/sources/{id}/enrich/skip` → Source — decline phase 2. The source stays in the pool as raw,
   searchable lines and nothing more; it is cancelled from the queue if it was waiting, and `skipped` is
   excluded from `Case.enrichment.outstanding` so it raises no incompleteness warning.
   **409 when it is already `enriching`** — that bell cannot be un-rung: the parse is running on the
   worker and will replace this source's events when it lands, so recording "skipped" would be a claim
   about the pool that stops being true a few seconds later. Wait for it (it becomes `enriched`); nothing
   is lost either way, because the raw lines were never removed. **409** when already `enriched` for the
   same reason — the interpreted events are in the pool and declining them now would describe evidence
   that is there. Skipping an already-`skipped` source is a 200 no-op. **404** for an unknown id.
- `POST /api/sources/{id}/mapping` body `{fields:string[], delimiter?:string}` → Source (re-parses an unknown delimited file with user mapping)
- `POST /api/sources/{id}/mapping/suggest` → `{ fields:string[]; delimiter:string|null; confidence:number; rationale:string; source:'ai'|'heuristic' }`
   Sends ~20 sample lines + the current heuristic guess to the OpenAI provider (non-streaming, JSON mode) and returns column names in
   order (canonical names: timestamp, host, user, action, src_ip, src_port, dst_ip, dst_port, proto, bytes, status, method, path, message,
   level, pid, program, ...). Nothing is applied — the client accepts via `POST /api/sources/{id}/mapping`. If AI is disabled/unconfigured
   or the call fails, returns the heuristic guess with `source:'heuristic'` and a note in `rationale` (always HTTP 200).
- `GET  /api/events?q=&sources=a,b&sev=critical,high&from=&to=&limit=200&offset=0` → `{total:number; rows:Event[]}`
   - `q` supports free text and `field:value` terms (e.g. `user:svc_deploy AND src_ip:45.83.140.22`); AND/OR/NOT, quotes.
   - Escaping: `\` makes the next character literal. `10.0.0.9\:3001` searches for that string instead of reading
     `10.0.0.9` as a field name (which silently matches nothing); `\ ` keeps a space in one term; `\` is a backslash.
     A quoted phrase does the same thing for a whole term. query.py `_atom_pred` and `atom_parts` must split
     identically — the vector path masks on `atom_parts` and confirms with the predicate.
   - Response also carries `engine:'cuda'|'vector'|'cpu'`, `tookMs`, `candidates` and `index:SearchIndexState`.
     ```ts
     interface SearchIndexState { state:'idle'|'building'|'ready'; events:number; target:number; pct:number;
       elapsedSec:number; bytes:number; buildMs:number }
     ```
     **A search NEVER builds the index.** It used to: the first query after a big ingest built the whole
     vectorised index inline, holding the index lock, and on a 2.5 M-event pool that query simply never came
     back (>60 s, 100 % CPU, RSS climbing 11.6 → 14.4 GiB) — an apparent hang. Now the request answers from the
     scan path (`engine:'cpu'`), kicks off the background build if one is not already running, and reports
     `index.state === 'building'` with `pct` so the UI can say *index warming, N %* instead of looking stuck.
     Building is single-flight: concurrent searches never start a second multi-gigabyte build.
- `GET  /api/events/{id}` → `Event & { correlations:{id:string; ts:string; msg:string; sev:Severity; reason:string}[]; analysis?: DerivedState }`
  `correlations` and `baseline` come from the whole-pool correlation analysis. This endpoint NEVER builds it (it used to, which cost minutes on a large pool for what is otherwise a dictionary lookup): when the analysis is not current the list is empty and `analysis` carries the same `{state,pct,note,…}` block the graph and timeline endpoints use. `analysis` is ABSENT when the correlations are real — an empty list with no explanation would claim that nothing correlates with the event.
- `GET  /api/timeline` → `{ stats:{window:string; clusters:number; entities:number; egress:string}; clusters:Cluster[];
   status:DerivedState }` — see **Derived structures are built in the background** below. While
   `status.state === 'building'` the response is prompt and EMPTY (`clusters: []`, zeroed stats); it is not a
   result, and the screen must say so rather than render "no activity".
- `GET  /api/graph` → `{ entities:Entity[]; edges:Edge[] }`. Query: `limit` caps NODES (≤ 2000); `maxEdges` (default 20 000, ≤ 500 000) keeps the strongest edges by severity then event count — the cut is `stats.hiddenEdges`, and analyst/AI overlay links are never subject to it; `lean=1` omits per-edge `eventIds`/`first`/`last` (the canvas never reads them; `/graph/node/{id}` carries them). The response is gzip-encoded when the client accepts it.
   `?sources=<id,id>` restricts the graph to entities and relations SEEN IN those log files. Exact on both
   sides — a node keeps a per-file tally, an edge keeps the set of files that produced it — so a relation
   is never inferred from its endpoints appearing in a selected file. Unknown ids resolve to nothing, which
   yields an EMPTY view rather than silently widening back to the whole pool. Omitted = the whole pool
   (report, AI review and the agent tools rely on that); the Graph screen starts with none selected.
- `GET  /api/graph/node/{id}` → node detail + `detectionRules: {id,name,sev,count}[]` (which rules fired on this entity's events, exact — tallied over the node's own `entity:` query; `[]` when the node has no detections) + `query`: the search DSL string that returns exactly this
   node's events (`entity:"…"` with colons escaped). The graph owns the extraction rules, so it builds the
   query; the UI must not guess it from the value.
- `GET  /api/graph/{name}` → Entity
- `GET  /api/pins` → `string[]`;  `POST /api/pins/{eventId}` toggles → `string[]`
- `GET  /api/report` → `{ caseId, caseName, analyst, generatedAt, severity:Severity, summary:string, findings:{level:Severity;title:string;body:string;evidence:string}[], pinned:Event[], iocs:{kind:string;value:string}[] }`
- `GET  /api/report/export?format=md|json|stix|pdf` (+ `&scope=all|case`) → file download.
   `Content-Disposition: attachment; filename="<caseId>_<caseName>.<ext>"`; media types `text/markdown`,
   `application/json`, `application/stix+json`, `application/pdf`. Any other format → 400.
   **pdf** renders the whole case as a paginated deliverable (title page + Case overview / Ingested sources /
   Timeline of key events / Detections and findings / Indicators of compromise / Entity graph highlights /
   Analyst notes / Case set, page-numbered footer). It is built with reportlab (pure Python, no system
   binaries); if the wheel is missing the endpoint returns **503** with a message and the rest of the app
   is unaffected. `ExportFormat` in `frontend/src/api/types.ts` includes `'pdf'`.
- `POST /api/library/attach` body `{items:[{caseId,fileName}], targetCaseId?:string}` → Source[]
   `targetCaseId` picks WHICH case receives them (blank = the active one) and ACTIVATES it first — the
   store holds one case in memory, so "file into that case" and "work on that case" are one operation.
   A blank target with no active case is a **409**, never a silently created case.
- `POST /api/cases/{id}/sources/{sid}/detach` → Source[] — take a source OUT of the case; the events stay
   in the pool with the same ids. A file uploaded straight into the case is STAGED into `library/` first
   (`Store._stage_into_library`) so it becomes case-less like any other library file; only unreadable
   bytes still 409. This is never a delete — that is `DELETE /api/sources/{id}`.
- `GET  /api/settings` → Settings (apiKey masked);  `PUT /api/settings` body Partial<Settings> → Settings (apiKey only overwritten if non-empty and not masked)
   - **400** when `ai.baseUrl` is not an `http(s)` URL, or carries a **query string or fragment**. Iris
     appends the API path to that value, so `http://127.0.0.1:8000/api/admin/clear-all?x=` would make
     the appended path land harmlessly in the query and the request hit Iris's own wipe endpoint. A
     private-IP blocklist is deliberately NOT applied — analysts run real gateways on `10.x`, and a
     control that refuses the working setup gets switched off.
- `GET  /api/compute` → ComputeStatus;  `POST /api/compute/recheck` → ComputeStatus (forces a re-probe)
- `GET  /api/compute/metrics?window=N` → `{ intervalSec:number; samples:MetricSample[]; current:MetricSample|null }`
  — the live 2 s sampler ring (GPU util/mem/temp/power, process CPU/RSS, parse throughput), newest last,
  `window` capped at the 900-sample / 30-minute ring. It returns the WHOLE window on every poll, so the
  response is gzip-encoded when the client accepts it: measured 310,319 → 33,751 B at `window=900`.
  There is deliberately no incremental `?since=` cursor — compression takes the poll to ~6 KB at the
  panel's default `window=150`, and a cursor that silently skipped a sample would be a hole in a chart.
- **MCP server** — Iris as a tool PROVIDER for outside agents. The tool surface is `app/ai/tools.REGISTRY`
  itself (never a second declaration), so an external client and the built-in investigator see one case.
  - `POST /api/mcp` — Streamable-HTTP MCP endpoint, JSON-RPC 2.0. Methods: `initialize`, `ping`,
    `tools/list`, `tools/call`, `resources/list`, `prompts/list`; `notifications/*` get **202** and no body.
    A single JSON response is returned rather than an SSE stream (the spec allows it — this server never
    pushes). **404** when `settings.mcp.enabled` is false, **503** when it is enabled with no token
    (fail-closed: that state used to serve every read tool unauthenticated), **401** when the token is
    not presented or is wrong.
    A tool that fails answers `{result:{isError:true, content:[{type:'text',text:…}]}}` — a JSON-RPC error
    is reserved for protocol faults, so a refused tool call never looks like a broken server.
    Write tools are only listed/callable when `settings.mcp.allowWrites` is true.
  - `GET  /api/mcp` → **405** (no server→client stream is offered).
  - `GET  /api/mcp/status` → McpStatus.   `POST /api/mcp/token` → `{token:string}` (generated, returned in
    the clear exactly once; every later read is masked).
- `POST /api/ai/analyze` body `{ scope:'case'|'event'|'cluster'|'selection'; id?:string; eventIds?:string[]; question?:string }`
   → SSE stream (`text/event-stream`). Events: `data: {"type":"agent","agent":"triage","text":"..."}` (delta chunks), `data: {"type":"done","summary":"...","findings":[...]}`, `data: {"type":"error","message":"..."}`
   Runs N parallel agents (settings.ai.agents): triage, timeline, entities, (optionally) iocs — then a synthesizer. Streams each agent's output.
- `POST /api/ai/test` body `{provider, model, baseUrl, apiKey}` → `{ok:boolean; message:string; latencyMs?:number}`
  - `baseUrl` goes through the same `config.validate_base_url` as `PUT /api/settings` → **400** on a
    non-http(s) scheme, a missing host, or any query string / fragment (Iris APPENDS its API path, so
    anything after `?` or `#` silently changes which URL is requested).
  - **The stored `ai.apiKey` is only ever sent to the stored `ai.baseUrl`.** A blank or masked `apiKey`
    with a DIFFERENT `baseUrl` sends no credential at all; test a new endpoint with its own key.
  - `message` names the status and the URL Iris called but never quotes the upstream response body —
    that goes to the server log. This response is returned with 200, so an echoed body would disclose
    whatever the chosen host replied with.
- `POST /api/demo` → Case  (loads the bundled sample dataset that mirrors the mockup: 7 sources / credential-stuffing → egress scenario)
## Sign-in (password + PIN)
Optional, off until configured. Credentials are stored HASHED (PBKDF2-HMAC-SHA256, per-credential
salt) in `$IRIS_DATA_DIR/auth.json`, never in settings.json and never returned by any endpoint. The
session is an HttpOnly, SameSite=strict cookie (`iris_session`, 12 h, in memory server-side — a
restart signs everyone out). Every `/api/auth/*` path is exempt from the gate itself, so the writes
below check the session explicitly.
- `GET /api/auth/status` → `{enabled, configured, authenticated, minPassword, minPin, maxPin}` —
  no credential, reachable without one (the SPA must be able to ask before rendering a login page).
- `POST /api/auth/login` `{password, pin}` → 200 + `Set-Cookie`, or **401** with one message for a
  wrong password AND a wrong PIN (naming which half was right halves an attacker's work). Repeated
  failures are throttled per client address: 5 failures then 30/60/300/900 s, stated in the refusal.
- `POST /api/auth/logout` → clears the session and the cookie.
- `POST /api/auth/credentials` `{password, pin, enabled?}` → sets both and signs the caller in.
  400 on a weak credential (password < 8, PIN not 4-12 digits, PIN equal to the password). Requires a
  session once a login exists; open before that (creating the FIRST one cannot need a session).
- `POST /api/auth/enabled` `{enabled}` → turn the gate on/off keeping the stored credentials. 400 if
  no credentials are set — `enabled` with nothing to check would be an un-openable door.
- `DELETE /api/auth/credentials` → remove the login entirely. Requires a session.
- `GET /api/settings` → `security` now also carries `loginRequired` and `tokenRequired`;
  `authRequired` is true when EITHER is on, and the `no-auth` warning is replaced by `auth-ui-only`
  when the UI login is the only control (an API client cannot obtain the cookie).

- `POST /api/admin/clear-all` body `{resetSettings?:boolean}` → `{ok:true, removed:{sources:number, events:number, files:number, cases:number, trash:number, jobs:number, aiRuns:number, cache:number}}`
  `cache` counts files removed from `$IRIS_DATA_DIR/cache/` (the persisted entity graph and the parsed-pool cache). They are derived FROM the evidence and quote it, so a wipe takes them; they are also counted in `files`.
   (`aiRuns` = AI conversation transcripts — they quote the evidence, so they are wiped too)
   Wipes the whole WORKSPACE, disk and memory: every case (`cases/` — uploads, case.json, notes, attachments, case set, manual IOCs, graph links),
   the deleted-case trash (`.trash/`), every file staged in the library (`library/` + its index), the entire parsed event pool and the search index
   over it, and the upload/parse job registry (`jobs.json`). Afterwards `/api/cases` is `[]`, `/api/case` is `pending` with `eventCount` and
   `poolEventCount` 0, and a restart comes up empty. DELIBERATELY PRESERVED: `rules.json` (custom rules + built-in overrides — clear those with
   `POST /api/rules/clear`) and `settings.json`; with `resetSettings:true` settings.json is removed and defaults reloaded (incl. the AI key).
- `GET /api/parsers` → `{ parsers:{name:string; family:string; extensions:string[]; description:string; available:boolean; note?:string}[] }`
   (e.g. OCR reports available:false with a note when tesseract is not installed)

## Two-phase ingest — raw first, understood afterwards — added
Pulling FIELDS out of a line is 11-17 % of ingest; the other 83-89 % is normalization — timestamp
parsing, severity inference, entity extraction and building the event. That cost is paid identically on
a file that yields 26 useful fields and on one that yields none. So the split is not "parse vs raw", it
is WHEN:

* **Phase 1** — the container is split into records and the plainest possible events are built: the raw
  text, its file, its id. No timestamp, no severity, no entities, no fields. In the pool and in the
  search index before the upload request returns. `Source.enrich` is `raw`.
* **Phase 2** — the real parser and the full normalization, on ONE background worker, one source at a
  time, replacing that source's events in place. This is what the timeline, the entity graph, the
  detections and field filters need, and it is exactly the work that can wait.

The contract that makes it safe to build a UI on:
- **Raw is never a lie.** An unenriched event carries `ts:''`, `sev:'info'` and no fields — not a guessed
  timestamp and not an inferred severity. Every screen that renders one of those must read
  `Source.enrich` and say what it is looking at. `Source.range` is `null` until enrichment.
- **Event ids do not move** when the parse is one record per raw line (nginx, syslog, CSV, JSONL — the
  common case): they are reused positionally, so a case-set entry, a note or an indicator citing one is
  still citing the same line afterwards. When it is not 1:1 the ids are reassigned, curation follows the
  RAW TEXT (the one thing both phases agree on), and a citation that cannot be mapped is REPORTED, never
  silently dropped.
- **Binary and structured containers have no phase 1** and are born `enriched` (see `EnrichState`).
- **A phase-2 failure is still THE PARSE FAILING**: `enrich:'error'` *and* `state:'ERROR'` with the
  message on both `enrichError` and `error`, so nothing reads as successfully parsed. The raw lines stay.
- **`GET /api/case` carries the whole picture** in `enrichment` (see `CaseEnrichment`), derived from
  per-source metadata only — never from a walk of the pool, which is what once made that endpoint take
  15-20 s. Poll it while `enrichment.pending > 0`; warn on every analysis screen while
  `enrichment.outstanding > 0`.
- **The two controls** are `POST /api/sources/{id}/enrich` and `POST /api/sources/{id}/enrich/skip`
  (above); the automatic behaviour is `settings.ingest.autoEnrich`.

### POST /api/rules/preview
Dry-run a rule definition against the pool **without saving it**. Body is the same `RuleInput` as
`POST /api/rules`; nothing is written, no event is tagged and the catalogue is untouched.

```
-> { name, sev, pattern?, field?, sourceFilter?, conditions?[], combinator?, threshold? }
<- { hits, sample: EventOut[], tookMs, error?, trigger, mechanism }
```
`trigger` is the generated, read-only sentence describing what the ENGINE would evaluate — never the
analyst's description. The matcher is the same one `apply_rule` uses, so a preview and the rule that
follows it cannot disagree. An unsafe pattern (ReDoS screen) or one that runs past the sandbox deadline
comes back as `error`, not as `hits: 0`.

### GET /api/graph/anomalies?scope=all|case&sev=&limit=
Detections that read the **entity graph** rather than one event at a time (`app/graph_rules.py`).

```
<- { findings: GraphFinding[], rules: <graph rules enabled>, evaluated: bool,
     status?: DerivedState, tookMs }
GraphFinding = { ruleId, name, sev, nodeId, nodeType, nodeValue, summary, metric, metricLabel,
                 related: string[], citedEventIds: string[], first, last }
```
* A finding names an **entity**, not an event: a fan-out is a property of a node, so these never appear
  in `Event.detections` and never in `GET /api/anomalies`.
* `citedEventIds` are real ids from that node's own events, resolved against the pool the graph was
  built from — a finding that cannot be opened is an assertion.
* **`evaluated: false` means the graph is not built and nobody has looked.** The endpoint NEVER builds
  one. Render the state; an empty `findings` list under `evaluated: false` is not "the graph is clean".
* The rules are ordinary built-ins on `GET /api/rules` with `mechanism: "graph"` — same toggle, same
  parameter overrides, same restore. Their `hits` is `null` (not `0`) until a roll-up exists.

## Exclusions
`GET /api/exclusions` · `POST /api/exclusions` · `PUT /api/exclusions/{id}` ·
`POST /api/exclusions/{id}/toggle` · `DELETE /api/exclusions/{id}` · `POST /api/exclusions/clear`

A suppression: evidence matching it is not TAGGED by the rules it is scoped to. It never touches the
event — the line stays in the pool, in search, in the raw viewer and on the timeline; only the rule's
claim about it is dropped.

```
Exclusion = { id, name, conditions: RuleCondition[], combinator: 'and'|'or',
              ruleIds: string[],        // empty = EVERY rule
              note, enabled, createdBy, createdAt, updatedAt,
              suppressed: int | null,   // detections removed on the LAST pass; null = not evaluated
              appliesToGraph: bool,     // can its conditions be checked against a graph node?
              logic }                   // generated, read-only sentence
GET -> { exclusions: Exclusion[], suggestions: ExclusionSuggestion[], suppressed: <total> }
```
* **Conditions use the same typed vocabulary as a custom rule** (`detect.parse_condition`), so there is
  one condition language in the app. `_ip` matches any address field on the event.
* **Nothing is excluded by default.** `suggestions` is a ready-made library (public resolvers, loopback,
  NTP, machine accounts, Kubernetes system identities, health checkers), each with a `why`. Adding one
  is a deliberate POST. Shipping suppressions enabled would mean an analyst's first search silently
  omitted evidence they never chose to omit.
* **`suppressed: null` is not `0`.** Null means no detection pass has run since the exclusion changed;
  zero means it ran and this exclusion matched nothing (which usually means it is wrong).
* **`appliesToGraph`** is false when any condition reads an event FIELD: a graph node has a type and a
  value and nothing else, so such an exclusion is left out of graph findings rather than half-applied.
* Every write re-runs the catalogue over the pool (O(pool)) — a suppression that has not been applied is
  worse than none. Exclusions are configuration, so `POST /api/admin/clear-all` KEEPS them, like
  `rules.json` and `settings.json`.

## Supported input types (parsers)
Text logs: nginx/apache access, syslog, EVTX (.evtx binary + .xml export), CloudTrail JSON, k8s audit JSONL, generic JSON / JSONL / JSON arrays,
CSV/TSV/pipe-delimited (header row auto-detected → field names), plaintext (timestamp regex). Documents: PDF (text extraction per page → lines),
XLSX/XLS (each row → event; header row → fields; sheet name in fields), DOCX (paragraphs). Images (.png .jpg .jpeg .tif .bmp .webp): OCR via
tesseract → lines, after a preprocessing search (rescale to a measured text height, deskew, contrast/binarize/denoise variants scored by
tesseract's own confidence); each event carries `ocr_variant`, `ocr_confidence` and `ocr_quality` (high|medium|low) in fields so a weak read is
visible as one. Packet captures (.pcap .pcapng .cap): libpcap and pcapng decoded with the standard library alone (no scapy/tshark) - one event per packet, with
`src_ip`/`dst_ip`/`src_port`/`dst_port`/`protocol`/`tcp_flags`/`ttl`/`vlan` in fields, plus the application layer a capture is opened for: DNS
question and answers (`dns_query`, `dns_qtype`, `dns_answers`, `dns_rcode`), HTTP (`http_method`, `http_host`, `url`, `user_agent`, `http_status`)
and the TLS ClientHello SNI (`tls_sni`, also `domain`). Ethernet + VLAN, raw IP, Linux cooked v1/v2 and loopback link types; IPv4 and IPv6. A
malformed packet becomes one event carrying `parse_error`, and a truncated capture keeps every packet before the cut. E-mail: .eml, .mbox (one event per message) and Outlook .msg (extract-msg; body, attachment names + SHA-256 merged in). Binary / memory dumps (.dmp .raw .mem .bin .img .vmem, or any file that fails UTF-8 decode): printable-strings extraction
(ASCII + UTF-16LE, min length 6) → each string an event, timestamps/IPs/URLs/paths/emails/registry keys extracted as fields+entities, offset in fields.
Archives: .zip .gz expanded. Unknown text → plaintext parser.

## Themes
Frontend defines CSS variables on `:root[data-theme=...]`. Default theme `iris-dark` matches the mockup palette:
bg #0a0b0a, panel #0e110e, border #1c211c, text #d6dcd4, muted #5c665b, accent #6ee787, sev colors critical #ff6b5e, high #ffa657, medium #e3c96e, low #6f7a6d, info #5c8f6a.
Fonts: 'Space Grotesk' (UI) + 'JetBrains Mono' (data). Bundle fonts locally (npm @fontsource) — no external fetch required at runtime.

## Entity graph v2 — typed nodes and typed relations — changed
The graph is no longer "which names co-occurred in an event". Every node has a **type** and every edge a
**relation kind**, extracted deterministically per event, so an IP, a username, a PID, a file, a hash and a domain
are distinct things joined by named relationships — and relations can span events (the same PID in a process-start
line and a later file-write line becomes one chain).
```ts
type EntityType = 'ip'|'user'|'host'|'process'|'pid'|'file'|'hash'|'domain'|'url'|'port'|'email'|'key'|'session'|'pod'|'service'|'registry'|'other';
type Relation =
  | 'auth_from'      // user  ← ip     (login/auth attempts, success or failure — see `outcome`)
  | 'connected_to'   // ip/host → ip:port  (network flow, HTTP request)
  | 'ran'            // user/host → process[pid]
  | 'spawned'        // process → process   (parent → child)
  | 'wrote'|'read'|'deleted'   // process/user → file
  | 'resolved'       // ip/host → domain
  | 'requested'      // ip/user → url
  | 'used_key'       // user → key
  | 'on_host'        // user/process/pid/file → host   (where it happened)
  | 'session'        // user ↔ session id
  | 'co_occurred';   // fallback: seen together with nothing more specific
interface GraphNode { id:string /*"<type>:<value>"*/; type:EntityType; value:string; label:string; count:number;
  first:string; last:string; sev:Severity /*max*/; detections:number; facts:[string,string][];
  inCase?:boolean /*appears in the case set*/; ai?:boolean /*created by the AI reviewer*/   /** AUTHORED, not extracted: drawn by the analyst or the agent and stored on the CASE
      (case.json graph_nodes). count is 0 — a conclusion about evidence, not a count of it —
      and `why` says on what grounds. Overlaid per response, exempt from minCount/minDegree. */
  manual?:boolean; why?:string;
}
interface GraphEdge { id:string; source:string; target:string; relation:Relation; count:number; first:string; last:string;
  sev:Severity; outcome?:'success'|'failure'|'denied'|'mixed'; eventIds:string[] /*≤ 20 sample*/;
  why:string /*plain-English*/; ai?:boolean; confidence?:number /*AI edges only, 0-1*/ }
interface GraphV2 { nodes:GraphNode[]; edges:GraphEdge[]; stats:GraphStats }
/* `stats.sourcesIncluded` / `stats.sourcesPending`: the graph BUILDS FROM THE SOURCES THAT ARE READY
   and no longer waits for the interpretation queue to drain — extraction is per source with a per-source
   partial cache (app/graph_parts.py), so a rebuild after one more source lands costs that source. A
   source in phase 2 right now is left out (its events are about to be replaced) and counted in
   `sourcesPending`; it joins on the next build. A graph over part of the workspace must say so. */
interface GraphStats { hiddenEdges?:number; maxEdges?:number;  // edges dropped by the strongest-first edge cap (`?maxEdges=`, default 20000)
   nodes:number; edges:number; truncated:boolean;
  totalNodes:number; totalEdges:number;          // the whole built graph, before limit/filters
  byType:Record<EntityType,number>; byRelation:Record<Relation,number>;
  /* How many nodes `minDegree` removed. Reported so the screen can say the FILTER did it rather than
     showing a thinner graph with no explanation. 0 when minDegree is 1. */
  hiddenByDegree:number; status?:DerivedState;
  /* The case's AUTHORED nodes/links (`graph_links` / `graph_nodes`) are overlaid only where the case is
     what is being looked at: `scope=case`, or the whole pool with no `sources` filter. Under a source
     selection they are LEFT OUT — a selection asks what those files say, and an authored node is a
     conclusion, not a line in any of them — and this counts the links withheld, so the screen can say
     where the picture went. 0 when the overlay was drawn. */
  hiddenCaseLinks?:number }
```
- `GET /api/graph?scope=all|case&types=ip,user&relations=auth_from,ran&minCount=1&minDegree=1&focus=<nodeId>&hops=1&limit=50` → GraphV2
   `focus`+`hops` returns the neighbourhood of one node — the way to explore a big case without a 5,000-node hairball.
   `limit` caps nodes (10…2000, default 50 = `graph.DEFAULT_LIMIT`, mirrored by the UI's "max nodes" control;
   ranked by detections, then degree, then count). `stats.truncated` says whether it bit.
   `minCount` is **relationship strength** — changed: it drops every EDGE supported by fewer than that many
   events and then every node left with no edge. It does NOT filter how many events mention an entity (which is
   what it used to do, and which was invisible: the ranking already puts the busiest entities first, so at the
   50-node cap every value up to five figures returned the same picture). The UI control is labelled
   "min link events". Analyst-added / accepted-AI `graph_links` carry no event count and are exempt.
   `minDegree` (1…100, default 1) is **how connected an entity is** — a genuinely different question from
   `minCount`, and the one analysts describe while asking for the other: an IP seen once, linked to one
   busy host, survives any `minCount`. It drops every node with fewer than that many links AMONG THE EDGES
   BEING RETURNED, and it PEELS to a fixed point (a k-core) rather than making one pass — removing a leaf
   removes its edge, which drops a survivor below the threshold it was just measured against, so a single
   pass would render nodes with fewer links than the control claims to show. `stats.hiddenByDegree` says
   how many it removed. The UI control is labelled "min connections". Overlay `graph_links` are applied
   after the peel, exactly as for `minCount`.
   The payload is always a CLOSED graph: every `edge.source`/`edge.target` is one of the `nodes` returned, and
   `edge.id` is unique. Edges to a node the cap or a filter removed — including persisted `graph_links` — are
   dropped, never emitted dangling. A node PAIR is not an edge identity (two relations may join the same pair),
   so renderers must key elements off `edge.id`.
- `GET /api/graph/node/{id}` → GraphNode & { neighbours:GraphEdge[]; timeline:{ts,eventId,msg,sev}[] /*≤ 50*/ }
- `GET /api/graph/path?from=<id>&to=<id>&maxHops=4` → `{ found:boolean; path:GraphNode[]; edges:GraphEdge[] }`
   shortest chain between two entities — "how does this IP get to that file?"
- The old `/api/graph/{name}` (Entity by bare name) still answers for backwards compatibility.

### Derived structures are built in the background — added
The typed graph and the correlation analysis are each O(the whole pool) to build. Measured on the real
1,224,226-event workspace, `GET /api/graph?limit=50` took **90 s** (past the client timeout) and
`GET /api/timeline` **29.8 s**, every time the store version moved, because the build ran INLINE on
whichever request arrived first. Both now follow the same contract the search index already had:

```ts
interface DerivedState { state:'idle'|'building'|'ready'; events:number; target:number;
  pct:number /*0..100*/; elapsedSec:number; buildMs:number /*of the last completed build*/ }
```
- The structure is built ONCE per store version, in a background thread, single-flight — a burst of polls
  cannot start two builds.
- A request arriving before the build finishes **returns immediately** with an empty payload and
  `status.state === 'building'` + `pct`. The Graph and Timeline screens render that as *building the entity
  graph, 42 %*, not as an empty result and not as a spinner: at 1.2 M events an unexplained 90-second wait
  is indistinguishable from a hang, and an empty graph is indistinguishable from a graph with nothing in it.
- Every filter on `GET /api/graph` (`limit`, `focus`+`hops`, `types`, `relations`, `minCount`, `q`) SLICES
  the cached graph. Nothing re-extracts entities from events per request, so a filter change is milliseconds.
- Freshness is not best-effort: the cache key carries the store `version` (plus the case-set revision for
  `scope=case`), so anything that calls `Store.bump()` — a new source, a deleted source, a rule re-apply,
  a cleared workspace, a case switch — makes the key MISS by construction. A stale graph is worse than a
  slow one. Accepted `graph_links` are not part of the built structure at all: they are overlaid on every
  response, so an accepted link shows on the very next request without invalidating anything.
- **`state` is never `idle` while there is work outstanding** — fixed. The endpoint starts a build on every
  cache miss and publishes `building` synchronously, before the build thread exists; and `invalidate()` (which
  `Store.bump()` calls on every ingest, rule re-apply and case switch) keeps the `building` status of a build
  that is still running. An `idle` state with an empty payload reads to a screen as "this pool has no
  entities", and the screens only poll while `building` — so a bump landing mid-build used to blank the Graph
  page until restart. Clients should still treat `state !== 'ready'` + empty as "keep polling".
- Pools at or below 20,000 events (`IRIS_GRAPH_SYNC_MAX` / `IRIS_ANALYSIS_SYNC_MAX` / `IRIS_ANOMALY_SYNC_MAX`)
  are still built on the request thread — sub-second, and simpler than a `building` flash followed by a poll.
- `GET /api/anomalies` joined this contract: the per-rule aggregation walked all 1,224,226 events under the
  store lock on every request (~1 s, and both the sidebar count and the Anomalies screen ask for it). Its key
  is `version` **plus `RULES_STORE.rev`**, because anomalies depend on the RULE CATALOGUE as well as the pool —
  a rename, a severity change, a toggle, a delete, `restore-defaults` and `clear?scope=` each move that
  revision, so a stale detection list cannot be served even if a future caller forgets to re-run detections.
- `GET /api/graph/node/{id}`, `/api/graph/path` and `POST /api/graph/links` still build if they must: they
  are only reachable from a graph the analyst is already looking at, so the structure is warm.
- The GRAPH build is multi-process since `app/graph_parallel.py`: entity extraction (~80 % of it) runs in
  `spawn` workers, so `status.pct` advances a chunk at a time and `buildMs` drops accordingly (measured
  1,224,226 events, 8 logical cores: 187.4 s → 55.3 s at 6 workers, 3.4x). No shape change — the payload, the status
  object and the graph itself are byte-identical to the single-process build, which is the point.
  `IRIS_GRAPH_WORKERS=1` pins the old in-process path, and every failure mode falls back to it silently.

### AI graph review — added
- `POST /api/graph/ai-review` body `{ scope?:'all'|'case'; focus?:string /*nodeId*/; question?:string }` → SSE
   (`text/event-stream`). The AI is handed the deterministic graph plus sample events and asked to (a) propose links
   the extractor could not see (an alias, a pivot implied by timing, a hostname that is really the same box as an
   IP), and (b) narrate the attack path. Stream events:
   `data: {"type":"thinking","text":"…"}` · `data: {"type":"link","edge":GraphEdge /*ai:true, confidence*/}` ·
   `data: {"type":"alias","a":nodeId,"b":nodeId,"reason":"…"}` · `data: {"type":"narrative","text":"…"}` ·
   `data: {"type":"done","links":number,"aliases":number}` · `data: {"type":"error","message":"…"}`
   Proposed links are NOT persisted automatically: the client shows them dashed and the analyst accepts each one.
   Server-side validation (ai/graph_review.py) before anything is streamed: both ends must be node ids that exist in the
   builder, `relation` must be in the Relation vocab, self-links and links the extractor (or an accepted link) already
   has in either direction are dropped, `confidence` is clamped to [0,1] (non-numeric → null), ≤ 40 links / ≤ 20 aliases.
   Proposed edges carry `count:0`, `eventIds:[]`, `sev:'info'`, `id:"<source>|<relation>|<target>"`; the `link` event also
   repeats `confidence` at the top level. Errors are terminal (AI disabled, empty graph, provider/model failure) — the
   stream never 500s.
- `POST /api/graph/links` body `{ source, target, relation, why, confidence? }` → GraphEdge — persist an accepted (or
   hand-drawn) link into case.json. `DELETE /api/graph/links/{edgeId}` removes it. Persisted links come back on every
   `GET /api/graph` with `ai:true` (or `manual:true`) so they survive re-ingest.

## Cases (multi-case) — added
```ts
interface CaseSummary { id:string; name:string; analyst:string; createdAt:string; updatedAt:string; sources:number; events:number; pinned:number; active:boolean; sizeBytes:number   /** what the case HOLDS besides evidence — a curation-only case has 0 sources/events but is
      not empty, and a delete confirmation that counts only evidence says it is. */
  noteCount:number; iocCount:number; graphLinkCount:number;
}
```
- `GET  /api/cases` → `CaseSummary[]` (all cases on disk, active flagged)
- `POST /api/cases` body `{name:string; analyst?:string}` → CaseSummary (created AND activated)
- `POST /api/cases/{id}/activate` → Case (loads that case: restores its uploads/events into memory; previous case stays on disk)
- `PATCH /api/cases/{id}` body `{name?, analyst?}` → CaseSummary
- `DELETE /api/cases/{id}` → `{ok:true}` — MOVES the case folder to `$IRIS_DATA_DIR/.trash/<id>-<timestamp>` rather than
   destroying it; a case holds the only copy of its uploads, so an rmtree was an unrecoverable loss of evidence. If it was
   active, the most recent remaining case is activated; if nothing remains the store holds a pending id (see `Case.pending`).
   `.trash` is a SIBLING of `cases/`, so `case_ids()` never lists it. The newest `config.TRASH_KEEP` (5) entries are kept,
   older ones are pruned oldest-first on each delete. **A deleted case takes its ATTACHED files out of the workspace
   with it**: the staged `library/` copy an attach left behind is released (only when the trash entry holds the
   bytes), so the file does not come straight back into the pool as a library source — with its detections — on
   the next library load or restart. A restore re-parses the case's uploads; a later detach re-stages the file.
   Files never attached to the case are untouched (the library is case-less).
- `GET  /api/cases/trash` → `{entry, caseId, name, deletedAt, events, sources, sizeBytes}[]` — restorable deletes, newest
   first. Declared BEFORE `/{case_id}` in the router: FastAPI matches in order and a dynamic route would swallow `/trash`.
- `POST /api/cases/trash/{entry}/restore` → CaseSummary — moves the folder back and re-parses its uploads. If the original
   id has since been reused it returns under a fresh id rather than overwriting the case that now holds it. 404 on an
   unknown entry or any name that resolves outside `.trash`.
- Storage: `$IRIS_DATA_DIR/cases/<id>/{case.json, uploads/}`; legacy single-case files at the data root are migrated into `cases/CASE-0001` on first start.
- `GET /api/case` keeps returning the ACTIVE case (unchanged shape) and all existing endpoints operate on the active case.

## Case set — curated events that ARE the case — added
Sources put events into a case; the **case set** is the subset the analyst has explicitly marked as part of the
investigation. It replaces the old pin concept entirely (`/api/pins` is gone): one action, one list, and it now drives
correlation scope as well as report evidence. Membership is a list of event ids in `case.json`, so it survives restarts
and costs nothing to store; events themselves still come only from that case's own sources.
```ts
interface CaseSetEntry { eventId:string; labels:string[]; note:string; addedAt:string   /** the ANCHOR: what this entry points at. Event ids are assigned from a counter that depends
      on what else is in the pool, so a re-parse both moves and REUSES them — an entry that
      resolved to the wrong line looked perfectly healthy. file+rawHash is authoritative and
      the id is re-pointed from it on every restore and phase-2 swap. */
  file:string; rawHash:string;
}
interface CaseSetResponse { entries:CaseSetEntry[]; events:Event[] /*resolved, same order*/; labels:string[] /*distinct, for autocomplete*/ }
```
- `GET    /api/case-set` → CaseSetResponse
- `POST   /api/case-set/{eventId}` body `{labels?:string[]; note?:string}` → CaseSetEntry (idempotent; 404 if the event isn't in the active case)
- `PATCH  /api/case-set/{eventId}` body `{labels?:string[]; note?:string}` → CaseSetEntry (only the given fields change)
- `DELETE /api/case-set/{eventId}` → `{ok:true}`
- `Case.caseSet: CaseSetEntry[]` replaces `Case.pinned`; `Event.inCase:boolean` + `Event.labels:string[]` are set on
  every event the case set contains, so lists can render membership without a second request.

### Scope
`GET /api/timeline`, `/api/graph`, `/api/graph/{name}`, `/api/report`, `/api/report/export` and `/api/events` all take
`?scope=all|case` (default `all`). `all` means EVERYTHING INGESTED — the active case's sources plus every file
staged in the library — so it is meaningful with zero cases on disk. With `scope=case` the analyzer runs over ONLY
the case-set events — clusters,
entity graph, baselines and findings are all recomputed on that subset, so narrowing changes the analysis rather than
just filtering the view. An empty case set with `scope=case` returns empty results (it does not silently fall back).

`/api/report` and `/api/report/export` are the exception to "all means everything ingested": a report is CASE
documentation, so `scope=all` there means every event of the active case and never the case-less library pool.

## Case notes — a timestamped feed — added
Notes are a chat-style log, not one blob. Entries carry an author + timestamp, are individually editable, and can
link to the evidence behind them. Works for INACTIVE cases too (read/written straight to that case's case.json).
```ts
type NoteRefKind = 'event'|'search'|'entity'|'cluster'|'source';
interface NoteRef { kind:NoteRefKind; value:string; label?:string }
interface CaseNote { id:string; text:string; author:string; createdAt:string; updatedAt:string /* '' unless edited */; refs:NoteRef[] }
```
- `GET    /api/cases/{id}/notes` → `CaseNote[]` (oldest first)
- `POST   /api/cases/{id}/notes` body `{text, refs?}` → CaseNote (400 if both text and refs are empty)
- `PATCH  /api/cases/{id}/notes/{noteId}` body `{text?, refs?}` → CaseNote (stamps `updatedAt`, keeps `createdAt`)
- `DELETE /api/cases/{id}/notes/{noteId}` → `{ok:true}`
- `Case.notes` / `CaseDetail.notes` / `Report.notes` are `CaseNote[]`. A pre-existing string `notes` migrates to one entry.

## Indicators of compromise — added
Every indicator records where it was seen so the UI can link back to the log file it came from.
```ts
interface IocHit { eventId:string; ts:string; sourceId:string; file:string }
interface Ioc { id:string /*"<kind>:<value>"*/; kind:string; value:string; count:number; files:string[];
  firstSeen:string|null; lastSeen:string|null; hits:IocHit[] /*≤5*/; manual:boolean; note:string;
  /** who put it there — 'extracted' is derived from detections, the other two are recorded artefacts */
  addedBy:'extracted'|'analyst'|'ai'; addedAt:string;
  /** events the AUTHOR cited as its origin (manual/AI indicators). `hits` says where the string appears
      now; this says where it came from, and it is what lets an indicator sit on the timeline even when
      its literal value never appears verbatim in a log line. Ids that no longer resolve are dropped. */
  citedEventIds:string[] }
```
- `GET    /api/iocs?scope=all|case&kind=` → `{ total, iocs }` — most-seen first. Two sources merged:
   **extracted** (derived from detection-bearing events on every read) and **manual** (persisted in case.json).
- `POST   /api/iocs` body `{kind, value, note?, citedEventIds?}` → Ioc — 409 if already tracked. The value is then
   looked up across the case (raw, msg, entities, field values) so a hand-entered indicator immediately reports where
   it appears; cited ids that are not real events are dropped at save time, never stored.
- `PATCH  /api/iocs/{id}` body `{kind, value, note?}` → Ioc;  `DELETE /api/iocs/{id}` → `{ok:true}`
   Manual indicators only — an extracted one is derived from events, so there is nothing to edit or delete (404).

### Indicators on the timeline — added
An indicator is a point in time, not just a row in a panel: "when did we first see this" has to be answerable from
the incident chronology.
```ts
interface IocMarker { id:string; kind:string; value:string; ts:string /*firstSeen — its place on the timeline*/;
  lastSeen:string|null; count:number; manual:boolean; addedBy:'extracted'|'analyst'|'ai'; note:string;
  eventId:string /*first event it was seen in — click-through*/; file:string; sourceId:string }
```
- `GET /api/timeline/iocs?scope=all|case&limit=200` → `{ total, iocs:IocMarker[] }`, earliest first.
   An indicator with no timestamp anywhere (never seen, no citation) is LEFT OFF rather than parked at epoch zero;
   it is still listed by `/api/iocs`. Deliberately a separate request from `GET /api/timeline`: indicator extraction
   is its own O(pool) pass and must not put the clusters behind it, so the screen renders each with its own
   loading state and interleaves the two by timestamp.

## Upload library — added
The library lists every raw upload on disk across all cases (including files whose case.json entry was lost) so it can
be pulled in without re-uploading. Attaching copies the bytes into the active case, so cases stay independent on disk.

It also holds **unattached** uploads: logs staged with no case, carrying `caseId:''`. Those live in
`$IRIS_DATA_DIR/library/` — a SIBLING of `cases/`, never inside it, so `case_ids()` cannot see them and deleting a
case (which rmtree's the whole case folder) cannot destroy them. **They are parsed into the workspace pool** and are
searchable, correlated, detected on and graphed with zero cases on disk (`Source.origin:'library'`). Attaching one
MOVES that source into the active case — the events already exist and keep their ids, so nothing is re-parsed and
nothing is double counted; the staged bytes stay in `library/` so the file can be attached to another case later.
```ts
interface LibraryFile { caseId:string /*'' = unattached*/; fileName:string /*on disk*/; displayName:string;
  size:number; attached:boolean;
  /* already a source OF THE ACTIVE CASE — not merely present in the workspace pool. Every staged file is
     also a pool source, so comparing against the whole pool marked all of them "in this case" and the
     Add-sources drawer offered nothing to add. */
  inActiveCase:boolean; uploadedAt?:string /*unattached only*/;
  // detection metadata — unattached files only, filled at stage time (changed)
  parser:string; confidence:number; state:''|'READY'|'REVIEW'|'MAP'; lines:number; linesEstimated:boolean; sample:string;
  sourceId:string /*the pool source it was parsed into; '' when it is not in the pool (an archive)*/; events:number;
  // NOT IN THE POOL = NOT SEARCHABLE, per file. `skipped` is true whenever this file's events are absent
  // from search, and `skipReason` says which problem it is — they have different fixes and are never
  // conflated:
  //   'budget'      the pool memory cap (IRIS_POOL_MAX_MB) stopped it being parsed; `budgetBytes` is the cap
  //   'unreadable'  the staged bytes could not be read off disk
  //   'parse-error' it WAS parsed and the parser failed; `skipDetail` is the parser's own message and no
  //                 amount of extra budget will help (the file is also a Source with state 'ERROR')
  //   'not-parsed'  a container Iris only expands when it is attached to a case
  skipped:boolean; skipReason:''|'budget'|'unreadable'|'parse-error'|'not-parsed'; skipDetail:string; budgetBytes:number }
```
- `GET  /api/library` → `LibraryFile[]` — every case upload, then the unattached ones
- `POST /api/library/upload?jobIds=a,b` multipart `files` → `LibraryFile[]` — stage logs with **no case at all**, and
   parse them into the workspace pool. Writes only to `library/`: no `cases/<id>/` directory is created and a pending
   case is NOT materialised. Works when `GET /api/cases` is `[]`, and the events are searchable immediately.
   Staging also runs **format detection** (a bounded sniff of at most 2 MB, `jobs.probe_upload`) and caches
   `parser/confidence/state/lines/sample` on the library entry. `lines` is extrapolated (`linesEstimated:true`) for
   files larger than the probe window. An archive Iris refuses to expand is staged unparsed (`sourceId:''`) and is
   only expanded when it is attached to a case.
- `POST /api/library/attach` body `{items:[{caseId, fileName}]}` → `Source[]` — files logs into the ACTIVE case.
   `caseId:''` reads from the unattached library: that source is MOVED into the case (same id, same events, no
   re-parse), so event totals do not change. Idempotent — attaching a file already in the case is a no-op.
   `caseId:'CASE-000x'` copies another case's upload and ingests it as a new source.
- `POST /api/cases/{id}/sources/{sid}/detach` → `Source[]` — the INVERSE of attach: takes a source back out of
   the case and leaves it in the case-less pool. The events keep their ids, nothing is re-parsed and nothing
   leaves search — only the case stops claiming the file. 409 when the case is not the active one, or when the
   source was uploaded straight into the case (no staged library copy to fall back to; `DELETE /api/sources/{id}`
   removes that one outright). `SourceBrief.fromLibrary` says which rows this is available for.
- `POST /api/library/unattached/{fileName}/load` → `LibraryFile` — parse a SKIPPED staged file into the pool
   anyway, ignoring the startup budget (that budget is a per-machine guess; the file it skipped may be the
   evidence that matters). Idempotent — a file already in the pool comes back unchanged. It is checked against
   LIVE free memory first, not against the budget: if the file cannot fit, the call returns **507** with a message
   giving the RAM it needs versus the RAM there is, the file stays skipped and nothing is half-loaded — an OOM
   kill would take every other loaded source with it. Success clears the `PoolSkip` record; a large file parses
   in a background thread exactly like an upload (poll `GET /api/case`).
- `DELETE /api/library/unattached/{fileName}` → `{ok:true}` — discard a staged file. Only ever touches `library/`,
   and drops the pool source it was parsed into (and any `PoolSkip` record naming it).
- `GET|POST /api/library/prune` → `PruneResult` — unreferenced case uploads + empty case folders. POST needs
   `?confirm=true`. Never touches unattached library files.

## Bulk field mapping — added
- `GET  /api/sources/mapping/pending` → `{total, sources:[{id,file,state,confidence,events}]}` — sources in MAP/REVIEW
- `POST /api/sources/mapping/auto?apply=true&minConfidence=0.5` →
   `{total, applied, skipped, failed, results:[{id,file,status:'applied'|'suggested'|'skipped'|'failed', fields?, confidence?, rationale?, source?, newState?, events?, reason?, error?}]}`
   Runs the AI mapper over every pending source **sequentially** (one LLM call each; a case can hold dozens) and
   applies suggestions at/above `minConfidence`. One source failing never aborts the batch.
- `POST /api/sources/{id}/mapping/suggest` now also receives the field names already in use in the case, so the AI
   reuses them instead of inventing synonyms — correlation joins on shared field VALUES, so `src_ip` in one file and
   `source_address` in another would never link. Near-miss names are snapped onto the existing vocabulary.

## Event location & search ordering — added
- `GET /api/events?sort=ts_desc|ts_asc` (default `ts_desc`, newest first). Events are stored ascending, so this is a
   reversed walk, not a re-sort.
- `GET /api/events/{id}/location?context=0..20` →
   `{ file, line:number|null, totalLines:number|null, exact:boolean, reason:string|null, context:[{n,text,current}] }`
   Resolved on demand by matching the event's raw text against the file — exact for cases ingested before this
   existed. Formats with no one-line-per-event mapping (JSON array, EVTX, binary dumps) return `line:null`.

## Case id allocation — changed
Case ids are monotonic and NEVER reused: `cases/index.json` carries a `seq` high-water mark alongside `active`.
Previously `next_id()` took the lowest free number, so deleting your only case recreated `CASE-0001` and the Cases
page looked untouched — the delete appeared broken even though the case and its uploads were really gone.
`DELETE /api/cases/{id}` on the last remaining case still creates a fresh empty one, but with a new id.

## Case detail — added
- `GET /api/cases/{id}` → `CaseDetail` = `CaseSummary` + `{ notes:string; caseSet:number; snapshot:CaseSnapshot|null; sources:SourceBrief[] }`
- `PATCH /api/cases/{id}` additionally accepts `notes?:string`
```ts
interface CaseSnapshot { events:number; sev:Record<Severity,number>; range:[string,string]|null; clusters:number; detections:number; entities:number }
interface SourceBrief { id:string; file:string; parser:string; events:number; size:number; state:SourceState;
  fromLibrary?:boolean /*attached from the case-less library, so it can be detached instead of deleted*/ }
```
- `CaseSnapshot.events` (and every other field on it) counts the CASE's OWN events — never the workspace pool.
  It used to report `len(pool)`, so a brand-new empty case displayed every ingested log as its own total and
  read as though creating a case had swallowed the whole workspace. A case starts EMPTY: no sources, no case
  set, and nothing is filed into it until the analyst attaches it.
- The snapshot is written into `case.json` whenever the active case changes, so an **inactive** case still reports
  meaningful totals without re-parsing its uploads. Live sections (timeline, case-set event bodies) require the case
  to be active — only one case is in memory at a time — so the client shows an "activate to load" affordance instead.

## Detection rules & anomalies — added
```ts
type RuleField = 'any'|'msg'|'raw'|'host'|'user'|'source'|'file'|string /* a specific fields[] key */;
interface Rule { id:string; name:string; description:string; sev:Severity; enabled:boolean; builtin:boolean;
  kind:'regex'|'builtin'|'conditions'; pattern?:string /*regex, Python syntax*/; field?:RuleField; flags?:{ignoreCase:boolean; multiline?:boolean};
  sourceFilter?:string /*family/file substring or ''*/; tags:string[]; createdBy:'user'|'ai'|'system'; createdAt:string; updatedAt:string;
  hits?:number /*events matched in the active case*/;
  overridden?:boolean /*builtin whose name/sev/description/tags the analyst changed*/;
  removed?:boolean /*builtin removed from the catalogue — only returned when includeRemoved=true*/;
  logic?:string /*builtin only: the TRIGGER — the exact condition the engine evaluates (fields, values, regex,
    thresholds, time windows). Read-only: it is Python. This is distinct from `description`, which is analyst
    prose and matches nothing; they used to be the same string, which made the editable Description box look
    like it was what did the flagging.*/;
  mechanism?:'regex'|'fields'|'threshold'|'correlation' /*builtin only: the PRIMARY method it decides by. A
    'threshold' rule may still use a regex to select what it counts (SIGMA-APP-0061 does).*/;
  patterns?:{field:string; pattern:string}[] /*builtin only: the regexes it actually matches with. 9 of the built-ins
    use one; the rest match purely on fields/thresholds. Only ever part of the condition — windows, counts and
    cross-event joins stay in code.*/ }
interface RuleTestResult { hits:number; sample:Event[] /*≤ 20*/; tookMs:number; error?:string }
interface AnomalyCase { caseId:string /* '' = library, not filed in a case */; caseName:string; hits:number }
interface Anomaly { ruleId:string; name:string; sev:Severity; hits:number; firstSeen:string|null; lastSeen:string|null; sources:string[];
                    cases:AnomalyCase[] /* WHICH case the hits are in — the active case and/or the library; hits descending */;
                    sample:Event[] /*≤ 5*/; kind:'regex'|'builtin'|'conditions' }
```

### Custom rules built from conditions — added
A custom rule is no longer only a raw regex: it can be composed from typed conditions, the same way a built-in's
condition is composed from typed `params`. Same four-piece model — the auto-generated `logic` (trigger) stays
distinct from the analyst-editable `description`.
```ts
type RuleOp = 'equals'|'not_equals'|'contains'|'not_contains'|'starts_with'|'ends_with'
            | 'regex'|'in'|'not_in'|'gt'|'lt'|'exists';
interface RuleCondition { field:string /*msg|raw|host|user|source|file|id|ts|sev|detection|entity or any fields[] key*/;
  op:RuleOp; value?:string /*'' for 'exists'; comma-separated for in/not_in; a number for gt/lt; a regex for 'regex'*/ }
interface RuleThreshold { count:number /*≥1*/; window:number /*seconds, 1…7 days*/; groupBy?:string /*field, '' = whole case*/ }
// on Rule and RuleInput:
//   kind:'regex'|'builtin'|'conditions'
//   conditions?:RuleCondition[]; combinator?:'and'|'or' /*default 'and'*/; threshold?:RuleThreshold|null
```
- `POST`/`PUT /api/rules` accept **either** `pattern` (legacy raw-regex rule, unchanged) **or** a non-empty
  `conditions[]`. Supplying neither is a 400. A rule with conditions comes back `kind:'conditions'`.
- Values are validated per operator with the same typed machinery as built-in params (`detect.parse_param`:
  `regex` compiles, `in`/`not_in` are a non-empty comma list, `gt`/`lt` are numeric, `equals`… are literals) —
  a bad operator, empty field or uncompilable regex is a **400 at save time** and is re-checked on load. A stored
  value that no longer parses degrades safely: the rule reports `error` and matches nothing instead of raising.
- Semantics: comparisons are case-insensitive; negative operators (`not_equals`, `not_contains`, `not_in`) are true
  when the field is absent, matching the search DSL's `NOT field:value`. `gt`/`lt` coerce the field value to a number
  (non-numeric ⇒ no match). `combinator` joins the rows with AND or OR.
- `threshold` turns the rule into a windowed burst: matches are grouped by `groupBy` (whole case when empty) and the
  rule fires on the densest `window`-second span holding `count` or more, tagging the **last event** of that window —
  the same shape (and the same `find_bursts`) the built-in threshold rules use.
- Derived, read-only, served on every custom rule too: `logic` (the trigger, auto-generated prose — never the
  description), `mechanism` (`regex` | `fields` | `threshold`) and `patterns` (projection of the `regex` conditions).
- Backward compatible: a `rules.json` holding plain regex custom rules keeps loading and firing unchanged.
- `GET  /api/rules?includeRemoved=` → `Rule[]` (built-ins with kind 'builtin' plus custom regex rules), each with `hits` for the active case.
   `includeRemoved=true` also returns removed built-ins (flagged `removed:true`); default omits them.
- `POST /api/rules` body RuleInput (without id/timestamps) → Rule — custom regex rules only (`pattern` required)
- `PUT /api/rules/{id}` body RuleInput → Rule. Custom rules: full edit. **Built-ins: editable too**, but only the metadata —
   `name`, `description`, `sev`, `tags`, `enabled` are stored as an override in rules.json and the rule comes back `overridden:true`;
   `pattern`/`field`/`flags`/`sourceFilter` are ignored because the matching logic is Python (bursts, cross-event joins), not a regex.
   An overridden `sev` is what subsequent detections are tagged with.
- `DELETE /api/rules/{id}` → `{ok:true}`. Custom rules are deleted outright. Built-ins are *removed from the catalogue*: persisted in
   `removedBuiltins`, they stop firing and disappear from `GET /api/rules` — reversible via restore, since the logic still lives in code.
- `POST /api/rules/{id}/restore` → Rule — un-removes a removed built-in AND drops any metadata override (back to the shipped definition).
   404 for custom rules (nothing to restore to).
- `POST /api/rules/{id}/toggle` → Rule
- `POST /api/rules/clear?scope=all|custom` → `{ok:true, custom:n, builtin:n}` — empties the rule list. `custom` deletes every
   custom rule and leaves the built-ins; `all` (default) also removes every built-in from the catalogue. Custom rules are gone
   for good; built-ins are only *removed*, so restore-defaults brings them back. Detections are re-evaluated from scratch.
   400 on any other scope.
- `POST /api/rules/restore-defaults` → `{ok:true, restored:n}` — puts every removed built-in back and drops ALL overrides
   (renames, severities, tuned regexes, disabled flags). Custom rules are untouched.
- `POST /api/rules/test` body `{pattern, field, flags?, sourceFilter?}` → RuleTestResult (evaluates against the active case, does not save)
- `POST /api/rules/suggest` body `{prompt:string; examples?:string[] /*sample raw lines*/}` → `{rule:Rule /*draft, not saved*/, rationale:string, source:'ai'|'heuristic'}` — uses the OpenAI provider (JSON mode) to turn a natural-language description into a regex rule; heuristic fallback (keyword → escaped alternation) when AI is off/fails, HTTP 200 always
- Custom rules persist in `$IRIS_DATA_DIR/rules.json` (global, apply to every case). Rules run at ingest and are re-applied to the active case whenever a rule is created/updated/toggled/deleted (async re-evaluation; `GET /api/case` posture reflects it).
- `GET /api/anomalies?sev=&limit=` → `{ total:number; anomalies:Anomaly[]; status?:DerivedState }` — every rule with ≥1 hit in the active case, sorted by severity then hits. Rule hits appear on events as `detections[]` like built-ins. The aggregation is a DERIVED structure (see below): built once per store version **and rules revision**, in the background; `sev`/`limit` slice the cached list. While `status.state === 'building'` the list is empty on purpose — clients must render that as progress, never as "no rule fired".
- `GET /api/events` search supports `rule:<ruleId>` / `detection:<id or name>` terms (already: detection:/rule:/sigma:).

## Rich case notes & attachments — added
- `CaseNote.text` is **markdown** (unchanged wire type). The client renders it with a dependency-free renderer
  (`frontend/src/utils/markdown.tsx`): `#..###` headings, `**bold**`, `*italic*`, `` `code` ``, ``` fences, `-`/`*` bullets
  and `1.` numbers (one nesting level), `>` quotes, `[text](url)`, `![alt](url)`, `---` rules and `|` pipe tables.
  Output is React nodes only — raw HTML in a note is rendered literally, and link/image URLs are allow-listed
  (http(s) / mailto / site-relative), so `javascript:` and `data:` never reach the DOM.
- `POST /api/cases/{id}/attachments` — multipart, field `file` → `Attachment`
```ts
interface Attachment { id:string /*generated on-disk name*/; name:string /*sanitized display name, alt text*/;
  url:string /*/api/cases/{id}/attachments/{id}*/; contentType:string; size:number }
```
   415 for a content type outside `image/png|jpeg|gif|webp|bmp` **or** when the magic bytes disagree with it (SVG is not
   accepted — it can carry script); 413 above 10 MB; 400 on an empty body; 404 for an unknown case.
- `GET /api/cases/{id}/attachments/{name}` → the image bytes (`nosniff`, `Content-Security-Policy: default-src 'none'; sandbox`).
   Only generated names (`att-<32 hex>.<ext>`) are servable, so the client filename can never become a path.
- Stored at `$IRIS_DATA_DIR/cases/<id>/attachments/` — inside the case directory, so `DELETE /api/cases/{id}` removes them with the case.
- A successful upload MATERIALISES a pending case (it is a real write, like ingest/rename/note). Without that the
  upload succeeded but the note referencing the image 404'd, so the screenshot could never be saved anywhere.
  A rejected upload (415/413/400) creates nothing — the case directory is only made once the bytes are accepted.

## Search field facets — added
- `GET /api/events/fields?q=&sources=&sev=&from=&to=&scope=&limit=40` → `FieldFacetsResponse`. Takes the SAME filters as
  `GET /api/events` (identical parsing, shared helper in routers/events.py) so the Search fields sidebar always describes the
  current result set. Field names = every `Event.fields` key plus the fixed columns `host`, `user`, `source`, `file`, `sev`
  (a parser field named like a fixed column folds into it). Sorted by `count` desc, then name. Only the first 20 000 matching
  events (newest first) are walked — `sampled:true` says the counts are over that prefix. `limit` ≤ 500.
```ts
interface FieldFacetValue { value:string; count:number }
interface FieldFacet { name:string; count:number /*events carrying it*/; sample:string[] /*≤ 5 distinct, first-seen order*/;
  topValues:FieldFacetValue[] /*≤ 8, most common first*/; distinct:number /*distinct values seen*/ }
interface FieldFacetsResponse { fields:FieldFacet[]; total:number /*distinct field names before limit*/; events:number /*matching events*/;
  scanned:number /*events walked, ≤ 20000*/; sampled:boolean; engine:'cuda'|'vector'|'cpu'; tookMs:number }
```
- UI: Search has a collapsible fields rail (persisted in localStorage `iris.search.fields`, `'1'|'0'`). Clicking a value appends a
  `field:value` term built by `dslTerm()` in SearchScreen.tsx: a value with whitespace / quotes / parens becomes `field:"…"`
  (inner `"` → `\"`); anything else (incl. colons) is a bare term with `\` escaping (`src:10.0.0.9\:3001`, `\` for a literal
  backslash) — exactly what `backend/app/query.py` unescapes. The × on an active chip removes that exact token from the query.

## Raw log viewer & download — added
- `GET /api/sources/{sid}/raw?offset=0&limit=500&q=` → `RawLogPage`. A numbered page of the ORIGINAL upload
  (`STORE.source_paths[sid]`, utf-8 with replacement, universal newlines). `q` filters to lines containing the substring
  (case-insensitive) and offset/limit then page over the MATCHES; `matches` is their count (== `totalLines` without `q`).
  Lines are cut at 2000 chars — `truncatedLine:true` when any line on the page was. `limit` 1…2000 (422 outside). Files that
  are not line-addressable (extension EVTX/.dmp/.bin/.sqlite/…, or a NUL byte in the first 8 KB) return `binary:true`,
  `lines:[]` and a `hint`. 404 when the source is unknown or its upload is no longer on disk.
```ts
interface RawLine { n:number /*1-based*/; text:string }
interface RawLogPage { file:string; size:number; totalLines:number; matches:number; offset:number; limit:number; q:string;
  lines:RawLine[]; truncatedLine:boolean; binary:boolean; hint:string|null }
```
- `GET /api/sources/{sid}/download` → the original bytes, `application/octet-stream`, `Content-Disposition: attachment;
  filename="<original file name>"`. 404 like `/raw`.
- UI: Sources rows have a "View raw log" action (hover icon in the File cell, and a button inside the mapping drawer) opening a
  wide full-height drawer: find box (server-side `q`), prev/next paging, load-more / infinite scroll (windowed at 4 000 rows),
  monospace pre-wrap body scrolling in its own container, Download button; binary files show the hint plus Download.

## Upload & parse jobs — added
Upload/parse progress used to live only in the browser tab that started it, so a tab switch or refresh lost it — and a
file over `store.SYNC_LIMIT` (50 MB) parses in a background thread that outlives the request, so a 263 MB CSV was
invisible for minutes. Jobs are now server state, persisted at `$IRIS_DATA_DIR/jobs.json` (atomic tmp+replace under a
registry lock; parse threads and concurrent uploads write through the same lock).
```ts
type JobState = 'queued'|'uploading'|'parsing'|'ready'|'error';
interface UploadJob { id:string; file:string; size:number; received:number; state:JobState;
  target:'case'|'library'; caseId:string /*'' for a library job*/; parser:string; confidence:number; events:number;
  error:string; interrupted:boolean /*the server restarted while it was in flight*/;
  note?:string /*a sentence that is NOT a failure: a parse resumed from the staged library copy after a restart*/;
  stale:boolean /*failed by the watchdog, not by the parser — a heartbeat or a byte revives it*/;
  sourceIds:string[];
  progress:ParseProgress|null /*live parse detail; non-null only while state === 'parsing'*/;
  createdAt:string; updatedAt:string }
/* `received` is the UPLOAD (bytes the browser has sent). This is the PARSE, which is the long half:
   a 263 MB CSV uploads in seconds and then parses for minutes. `bytesDone` is source bytes consumed —
   approximate for the single-worker path (summed record lengths), exact per finished chunk for the
   multi-process one. `phase` names which half of the two-phase ingest is running: 'reading' (phase 1,
   splitting the container into raw lines), 'enriching' (phase 2, the real parser on the enrichment
   worker), 'parsing' (a source with no raw phase — binary/structured containers) or 'merging' (folding
   the events into the pool). `workers` > 1 means the file is being parsed across processes. */
interface ParseProgress { bytesDone:number; bytesTotal:number; pct:number /*0..100*/; events:number;
  workers:number; phase:'reading'|'parsing'|'enriching'|'merging'; bytesPerSec:number;
  etaSec:number|null; elapsedSec:number }
interface JobsResponse { jobs:UploadJob[] /*newest first*/; active:number; total:number }
```
- `progress` is IN-MEMORY ONLY and is never written to `jobs.json`: it ticks thousands of times per file, and after a
   restart it is meaningless anyway (`reconcile()` buries interrupted jobs). It is keyed by source id server-side, so
   ANY request sees it — a second tab, a refresh, or `curl`.
- `progress` covers phase 1 as well, even though `sourceIds` is still `[]` at that point: the job only learns its ids
   when the ingest request returns, so `GET /api/jobs` ADOPTS an unclaimed tracker row that matches the job's file name
   (`jobs.JobRegistry._adopt_locked`). Display only — it never writes `sourceIds`, so it cannot resolve a job. Before
   this, a 1 GB file showed 0 % for its whole raw split.
- `GET   /api/jobs?limit=100` → `JobsResponse`. Reading also RECONCILES: threaded parses are resolved by reading the
   source states back out of the store, uploads nothing has advanced or heartbeaten for 10 min become `error` with
   `stale:true`, and finished jobs older than 30 min are pruned (hard cap 200, oldest finished first).
- **A job is resolved by whether work is IN FLIGHT, not by whether the file is fully interpreted.**
   `sync()` holds a job in `parsing` while any of its sources is `queued`/`enriching`, and while one is
   `raw` only when `ingest.autoEnrich` is on (there, `raw` is the moment between the lines landing and
   the queue taking them). With autoEnrich OFF phase 2 is strictly on demand, so `raw` is settled: the
   events are in the pool and searchable and nothing will move them but the analyst. Before this, seven
   captures holding 11.2 M events sat in `parsing` forever behind a 0 % bar — "the parsing indicator
   spins a long time and says number in progress, but there's nothing happening". It is the same split
   `GET /api/case` already reports as `enrichment.pending` vs `enrichment.outstanding`.
- **`progress` on a `parsing` job with no tracker row is a 30-second placeholder, then null.** The gap
   before a parse thread registers is real and brief; unbounded, a synthesised `pct: 0` is a progress
   bar for work that does not exist. `null` with state `parsing` means "parsing, no detail" — which is
   honest — and the UI must render it as such rather than as 0 %.
- **A job WAITING ITS TURN is not a dead upload.** The Ingest screen declares every dropped file up front and then
   sends three at a time, so file #4 onwards sits in `queued` with `received:0` for as long as the queue ahead of it
   takes. The watchdog measured that wait from job CREATION and buried all of them at exactly 600 s with "the upload
   stopped before the server received the whole file" — uploads that had never been given a chance to start. Liveness
   is therefore something only the sending tab knows, and it says so: `POST /api/jobs/heartbeat`. A job the watchdog
   buried carries `stale:true` and is REVIVED by the next heartbeat, `PATCH` or ingest — a job `finish()` failed is
   not, because that failure is real. The message also names the actual state now: a job that never received a byte
   says the transfer never started.
- `POST  /api/jobs` body `{files:[{file,size}], target:'case'|'library'}` → `{jobs:UploadJob[]}` — declare uploads BEFORE
   the bytes move, so another tab sees them from the first byte. Bookkeeping only: never touches the store, never
   materialises a case.
- `PATCH /api/jobs/{id}` body `{received}` → `UploadJob` — bytes in flight. That number only exists in the uploading
   tab (XHR `upload.onprogress`), so the client pushes it; the frontend throttles to ~1/s.
- `POST  /api/jobs/heartbeat` body `{ids:string[]}` → `{alive:string[], revived:string[]}` — "these transfers are
   still mine". The sending tab posts the ids it has not finished (queued AND in flight) every 20 s until its batch
   drains; the server touches each one and un-buries any it had marked `stale`. Unknown or already-finished ids are
   ignored, so a tab that is a version behind, or one whose batch resolved between ticks, is never an error.
- `POST  /api/jobs/clear` → `{ok:true, cleared:n}` — drop finished jobs; running ones are left alone.
- `POST /api/sources?jobIds=a,b` and `POST /api/library/upload?jobIds=a,b` bind a request to already-declared jobs
   (positional against `files`). Callers that omit them still get jobs created server-side, so ingest is never invisible.
- **Transport is polling, not SSE**, deliberately: the states are coarse, the only high-frequency number is pushed in by
  the client, and a stream would have to poll the parse threads internally (they have no event loop to publish from).
  The Sources screen already polls `/api/case`; the jobs query polls at 1 s while anything is active, 20 s otherwise.
- **Restart:** `jobs.REGISTRY.reconcile()` runs in `main.lifespan` AFTER the case is restored — jobs whose sources came
  back complete resolve to `ready`. A `parsing` LIBRARY job whose staged copy is intact on disk is RESUMED, not failed:
  it keeps `parsing` with `interrupted:true` and a `note`, takes the source id the staged name derives, and settles
  through `sync()` when the startup library load lands that source. Anything still queued/uploading, or a parse with
  no staged copy, becomes `error` with `interrupted:true` and a message that says which.
- UI: the Ingest ("Sources") screen rebuilds its upload list from `GET /api/jobs` on mount, so a refresh mid-upload or
  mid-parse shows the real state and a second tab shows the same thing. Local XHR percentage is merged over the server
  record for the tab doing the sending; the pill says `uploading` vs `parsing` so the two phases are never conflated.

## AI investigator — a tool-using agent, not a canned pipeline — added
The analyst types an objective in plain English ("trace every event involving 45.83.140.22 and build me a case",
"investigate the logs and build me a timeline") and the model **drives the app itself**: think → call a tool →
read the result → continue, until it produces a report. `POST /api/ai/analyze` (the fixed triage/timeline/
entities/iocs pipeline) is unchanged and still used by nothing but its own tests; the panel drives
`/api/ai/investigate`. **The canned prompt suggestions are gone** — there is one free-text field.

```ts
interface AiInvestigateRequest { prompt:string; runId?:string; maxSteps?:number; maxSeconds?:number;
  /** optional context the panel was opened from, e.g. "event e412" — appended to the objective */
  focus?:string;
  /** the run this one CONTINUES — the latest turn of the open conversation. The new run joins that
      thread and starts from what the earlier turns established. Unknown/deleted id ⇒ fresh chat. */
  continueFrom?:string }
interface AiAction { id:string; runId:string; tool:string; at:string; summary:string;
  undo:Record<string,unknown>; undone:boolean }
/** One persisted line of a conversation — exactly what the panel renders, live or from history. */
interface AiTranscriptEntry { seq:number; kind:'status'|'step'|'text'|'tool'|'warning'; text:string;
  step:number; id:string; name:string; args:Record<string,unknown>; writes:boolean;
  ok:boolean|null; summary:string; tookMs:number;
  /* when this entry was last patched, on the same counter as `seq`. A `tool` entry is updated in place
     when its result lands and keeps its `seq`, so `?since=` selects on BOTH — without it a polling
     client never received the result and the call rendered as still running. 0 = never patched. */
  updSeq?:number }
interface AiRun { id:string; prompt:string; focus:string; model:string;
  /** a CONVERSATION is a chain of runs: threadId = the first turn's id (its own on a first turn),
      parentId = the turn this one continues ('' on a first turn). The RUN stays the unit of budget,
      of stopping and of undo; the thread is what the panel renders as one chat. */
  parentId:string; threadId:string;
  caseId:string; caseName:string;                  // the case active when the run STARTED ('' = case-less)
  startedAt:string; endedAt:string; updatedAt:string;
  state:'running'|'done'|'stopped'|'error';
  reason:string /*complete|max_steps|timeout|stopped|budget|tool_arguments|unfinished|interrupted|error*/;
  /* tool_arguments: the provider could not parse the model's own tool-call arguments MAX_ARG_FAILURES turns running, so the tool channel was abandoned; unfinished: the model kept describing calls it never made. Both take the wrap-up turn, so `state` is 'done' and there IS a report — the nuance is in `reason`. */
  steps:number; toolCalls:number; answer:string; error:string;
  interrupted:boolean;                             // the server restarted while this run was going
  actions:AiAction[]; unverifiedCitations:string[];
  transcript:AiTranscriptEntry[]; transcriptSeq:number; transcriptTruncated:boolean }
type AiRunEvent =
  | { type:'run'; runId:string; model:string; threadId:string; parentId:string; maxSteps:number; maxSeconds:number; maxContextTokens:number; maxWrites:number; maxCompactions:number; maxToolSeconds:number }
  /** checkIn = the "your last N tool calls returned nothing new — another angle, or the report?" nudge
      (it fires on a BARREN STREAK, never on the call count: a run still finding things is never
      interrupted); budgetNotice = the "leave room to write it up" one; documentCheck = the "you
      recorded nothing in the case" one. All three are ordinary status lines. */
  | { type:'status'; text:string; checkIn?:number; budgetNotice?:boolean; documentCheck?:boolean;
      recordNudge?:number; summaryCheck?:boolean }
  /** recordNudge = the "record as you go" nudge: N productive reads and nothing written to the case yet — record
      what is solid, then CONTINUE (never a request to finish; at most 3 per run). summaryCheck = the end-of-run
      "you recorded findings as you went, now write the summary note + case summary" one (once, only when the run
      wrote something and no add_note / update_case landed). */
  | { type:'step'; step:number; elapsedSec:number }
  | { type:'delta'; text:string; step:number }                       // the model's prose, streamed
  | { type:'tool_call'; id:string; name:string; arguments:object; step:number }
  | { type:'tool_result'; id:string; name:string; ok:boolean; tookMs:number; summary:string; data:unknown }
  | { type:'write'; action:AiAction }                                // something in the case actually changed
  | { type:'warning'; message:string; ids:string[];                  // cited ids that do not exist, or:
      contextCeiling?:number; compactions?:number; retry?:number }
  /** contextCeiling: the PROVIDER refused the transcript for its size (HTTP 400/413 naming the context window —
      llama.cpp's "exceeds the available context size", OpenAI's context_length_exceeded). Iris folded the
      transcript, lowered this run's ceiling to that many estimated tokens, and re-sent the SAME turn; nothing of
      the turn had reached the transcript. Bounded (4 per turn, 12 per run); when even the objective alone does
      not fit, the run ends with an `error` naming the real fix (a larger n_ctx). retry: a transient provider
      failure (5xx / 429 / timeout / dropped connection) being retried with a backoff, 3 times, before the run
      fails. Both are warnings because they are facts about the run the analyst should see. */
  | { type:'answer'; text:string }
  | { type:'done'; runId:string; threadId:string; parentId:string; reason:string; state:string; steps:number;
      toolCalls:number; writes:number;
      actions:AiAction[]; unverifiedCitations:string[]; answer:string; elapsedSec:number;
      compactions:number; contextCeiling:number; recordNudges:number }
  | { type:'error'; message:string; actions?:AiAction[] };
```
- `POST /api/ai/investigate` body `AiInvestigateRequest` → SSE (`text/event-stream`) of `AiRunEvent`. The response
   header `X-Iris-Run-Id` carries the run id, and the first event is always `run` with the same id and the limits in
   force. The stream NEVER 500s: a provider failure, a disabled provider or an internal error is one terminal
   `error` event. **A failed run is not a lost one**: the error message says how many tool calls and case writes
   are kept, and a follow-up (`continueFrom` = that run's id) is seeded with the failed turn's calls AND the prose
   it wrote along the way, marked "ended early — continue from where it stopped", so "continue" resumes rather
   than re-running the investigation.
- `POST /api/ai/investigate/{runId}/stop` → `{ok:boolean, runId}` — ask a live run to stop. Checked before every
   step and after every tool call, so a stop lands within one tool call. `ok:false` means there is no live run with
   that id (already finished, or never started). Pass your own `runId` on the request if you want to be able to stop
   it before the first byte arrives. Closing the stream also ends the run.
- **Saved system prompts** (`app/ai/system_prompts.py`, `$IRIS_DATA_DIR/ai/system_prompts.json` — CONFIGURATION,
   kept by clear-all like rules.json). `SystemPrompt {id, name, text, createdAt, updatedAt}` — ADDITIONAL instructions
   for a kind of investigation, always appended to the built-in investigator prompt under an "ADDITIONAL INSTRUCTIONS"
   header (the tool discipline and the citation rules stay in force; there is no way to replace the built-in prompt —
   a legacy `mode` field in a request or on disk is ignored). `settings.ai.systemPromptId`
   names the default; `AiInvestigateRequest.systemPromptId` picks one per run (omitted = the default, `''` = the
   built-in prompt alone). An id that no longer exists never fails a run and is never swapped for another prompt:
   the run streams a `warning` and uses the built-in prompt. A run on a saved prompt streams one `status` event
   carrying `systemPrompt:{id,name}`.
   - `GET  /api/ai/system-prompts` → `{prompts:SystemPrompt[], activeId:string, builtin:string, builtinDefault:string,
     builtinEdited:boolean}` — `builtin` is the built-in prompt IN FORCE (the analyst's edit when `builtinEdited`),
     `builtinDefault` the shipped text
   - `PUT  /api/ai/system-prompts/builtin` body `{text}` → `{builtin, builtinEdited}` — replace the built-in prompt for
     every run from now on (400 empty / > 60,000 chars; saving the shipped text verbatim clears the edit). Saved
     prompts compose on top of whatever built-in text is in force. A run on an edited built-in prompt says so in its
     `status` event (`systemPrompt.builtinEdited`).
   - `DELETE /api/ai/system-prompts/builtin` → `{builtin, builtinEdited:false}` — back to the shipped prompt
   - `POST /api/ai/system-prompts` body `{name, text}` → `SystemPrompt` (201; 400 names the problem —
     empty name/text, name > 120 chars, text > 40,000 chars, more than 50 prompts)
   - `PUT  /api/ai/system-prompts/{id}` body `{name?, text?}` → `SystemPrompt` (404 unknown)
   - `DELETE /api/ai/system-prompts/{id}` → `{ok, id, defaultReset:boolean}` — deleting the default resets
     `settings.ai.systemPromptId` to `''`, so no run starts with a warning about a prompt that is gone
   - `GET  /api/ai/system-prompts/{id}/effective` → `{id, name, text}` — the EXACT system message the model
     receives with this prompt selected (the built-in prompt, then the instructions)
- `GET  /api/ai/tools` → `{ tools:{name,description,writes,parameters:string[]}[], limits:{...} }` — the exact tool
   surface, so the UI and a reviewer can see what the agent is able to do.
- `GET  /api/ai/runs?limit=30&caseId=` → `{runs:AiRun[]}` — the conversation history, newest first. Summaries
   only: `transcript` is always `[]` here (`transcriptSeq` still tells you how long it is). `caseId` filters to
   runs started against that case; `caseId=` (empty) means the case-less ones; omit it for everything.
- `GET  /api/ai/runs/{id}?since=0` → `AiRun` (404 unknown) — one TURN in full. `since` returns only
   transcript entries with `seq > since`, which is how a reconnecting panel tails a live run.
- `GET  /api/ai/runs/{id}/thread` → `{threadId:string, runs:AiRun[]}` (404 unknown) — every turn of the
   conversation that run belongs to, oldest first, transcripts included. This is what the panel opens: showing
   one turn as if it were the conversation is the context loss threads exist to fix. Grouped by the stored
   `threadId`, never by walking `parentId` — a walk breaks the moment retention prunes a middle turn.
- `DELETE /api/ai/runs/{id}` → `{ok:true, runId}` (404 unknown) — delete ONE conversation. The case artefacts it
   created are untouched; `/undo` is the tool for those. `DELETE /api/ai/runs` → `{ok:true, removed:number}` clears
   the whole history.
- `GET  /api/ai/live` → SSE (`text/event-stream`), one stream for the WHOLE workspace, kept open for the app's
  lifetime: `{type:'hello',subscribers}` on connect, then `{type:'run',runId,caseId}` when an investigation starts,
  `{type:'write',runId,action:AiAction}` for every write it lands, `{type:'done',runId,state,writes}` when it ends,
  `{type:'undo',runId,undone}` after an undo; a `: keepalive` comment every 15 s while idle. It carries ids and the
  action, never data — the SPA turns each event into a TanStack Query invalidation so the case screens refetch
  what they show (`hooks/useLiveWorkspace.ts`). No history: a subscriber sees what happens after it connects.
- `POST /api/ai/runs/{id}/undo` → `{ok:true, undone:number, actions:AiAction[]}` — reverse every write of that run,
   newest first. Idempotent; already-undone actions are skipped. Creating a CASE is deliberately not undone —
   deleting a case is not an operation this path may perform. The `undone` flags are persisted, so a refresh does
   not offer to revert the same change twice.

### Conversations — a follow-up continues, it does not start over
The analyst's report: *"when asked for it to continue, it didn't even have context into all the work it had
already done and redid the entire analysis."* Every POST was a cold start. Now:
- **A follow-up is a new RUN in the same THREAD.** `continueFrom` names the previous turn; the server records
  `parentId`/`threadId` and seeds the new run with a deterministic brief of the earlier turns
  (`app/ai/continuation.py`): their objectives, the reports they produced, the tool calls already made and what
  they returned, **every verified event id seen**, and **what is already written to the case**. Citations are
  load-bearing, which is why the ids are carried explicitly rather than left to be re-derived.
- **The run stays the unit of budget, of stopping and of undo.** A follow-up gets fresh limits, its own Stop and
  its own `/undo` — "revert what it just did" has to mean one turn, and a conversation-wide revert would take
  back work the analyst deliberately kept.
- **The brief rides in `messages[1]`**, the one message `ai/compaction.py` keeps verbatim. Carried as a separate
  message it would be the first thing a long follow-up compacted away — precisely the context it needs most.
- **Two nudges the loop injects**, both ordinary user turns, both bounded, neither able to force the model's hand:
  `CHECK_IN` every 8 tool calls (max 3) asks whether it can answer yet — the budgets are a runaway-loop ceiling,
  not a plan, and a model reads them as a plan; and `DOCUMENT_CHECK`, once, when a run that made ≥ 3 tool calls is
  about to finish having written NOTHING to the case, listing the case set, the timeline (`annotate_case_events`),
  the indicators and the note it should be recording. It may decline in one line — a plain question needs no case
  artefacts, and inventing a finding to have something to file is worse than filing nothing. Both are reported as
  `status` events (`checkIn` / `documentCheck`), never silently.
- An unknown, pruned or deleted `continueFrom` degrades to a fresh conversation. It never fails the run.

### Conversation history — the run outlives the request
`POST /api/ai/investigate` starts a **background task**; the SSE response is only a live TAIL of it. Closing the
stream (a refresh, a tab switch, a dropped connection, closing the panel) therefore no longer kills the
investigation. Everything the stream emits is also appended to a persisted transcript, so:
- **On mount** the panel calls `GET /api/ai/runs`. If the newest run is `running`, it rejoins by polling
  `GET /api/ai/runs/{id}?since=<last seq it has>` (~1 s) until the run is terminal; otherwise it shows the history.
- **Storage**: `$IRIS_DATA_DIR/ai/history.json`, one file, atomic tmp+replace under a lock, the same shape as
  `jobs.json`. Structural events (step / tool call / result / write) flush immediately; streamed prose is
  coalesced and flushed at most once a second, because it arrives per token.
- **Reconciled on startup** exactly like `jobs.reconcile()`: a run that was mid-flight when the process died
  becomes `state:'error'`, `reason:'interrupted'`, `interrupted:true` — it can never display as still running.
- **Scoping: GLOBAL, with a case ASSOCIATION.** A run records `caseId`/`caseName` as they were when it started
  (both `''` in the case-less workspace) but transcripts live at the workspace level, never under `cases/<id>/`.
  A run may target no case at all; filing them under a case would send them to `.trash/` on a case delete and
  RESURRECT them on a restore; and the transcript records what the analyst asked, which outlives the case.
  **Deleting a case therefore keeps its conversations**, tagged with the now-gone case name.
- **Retention**: 50 conversations, 8 MB of `history.json`, 400 transcript lines per run, 8 000 chars per prose
  entry, 20 000 per report, 800 per tool-argument blob. Pruning is oldest-first and never drops a `running` run;
  if a single live run is over the byte cap on its own its transcript is clamped (`transcriptTruncated:true`)
  rather than the run being lost.
- **Nothing secret is stored.** `model` is a name; the API key never reaches this file.
- **`POST /api/admin/clear-all` wipes the history**, and reports it as `removed.aiRuns`. A transcript quotes the
  evidence verbatim, so it is evidence: leaving it behind would mean "clear all data" left copies of the log
  lines on disk, and `history.json` would repopulate the panel on the next restart.

### The tools (the app's own operations, never a second implementation)
Read — **aggregation first, rows only for reading, and one call per QUESTION not per row**:
`entity_profile` (everything about one IP/user/host/process/file/hash in ONE call), `count_events` (exact
total), `aggregate_events` (`groupBy` = source/sourceId/file/host/user/sev/detection/entity or any parsed field
→ exact per-group counts), `distinct_values`, `events_over_time` (minute/hour/day histogram), `sample_events`
(a spread sample, for reading lines), then `get_case_state`, `list_sources`, `search_events` (≤50 rows,
`include=raw,fields,entities`), `get_events` (**batch read, ≤25 ids**), `get_event` (the deep dive on ONE
event: correlations, baseline, file context), `list_event_fields`, `get_timeline`, `list_detections`,
`list_anomalies`, `list_detection_rules`, `build_graph`, `graph_sources`, `graph_find`, `graph_node`,
`graph_path`, `list_iocs`, `list_notes`, `list_cases`, `get_case_set`, `list_graph_links`.
Write: `create_case`, `update_case` (name/summary), `activate_case`, `add_events_to_case`,
`remove_events_from_case`, `annotate_case_event`, `annotate_case_events` (**batch — a whole case timeline in
one call**), `add_ioc`/`update_ioc`/`delete_ioc`, `add_note`/`update_note`/`delete_note`,
`add_graph_link`/`delete_graph_link`, and the detection catalogue: `create_detection_rule`,
`update_detection_rule` (custom rules), `set_builtin_rule_params` (a built-in's condition constants),
`set_detection_rule_enabled`, `delete_detection_rule` (**custom rules only**).
There is deliberately **no** tool that deletes a case, deletes a source, clears data, deletes a built-in rule or
clears/restores the rule catalogue.

**Enumeration is the failure mode on the READ side too.** The counting lesson below was learned for totals and
then un-learned for reads: `search_events` returned identity and a normalized message but never the raw log
line, the parsed fields or the entities, so an agent told to open an event before citing it had to call
`get_event` once per hit. Measured on the sample pool, reading twenty hits cost **21 of a 40-step budget** and
the run ended with no answer. Three things fix it and all three are part of the contract:
`search_events(include='raw,fields,entities')` returns what it found in the same call; `get_events(eventIds:[…])`
reads up to 25 events in one; and `annotate_case_events(entries:[{eventId,labels,note}])` writes a whole
timeline in one. Over-long batches are **refused with the cap named**, never silently truncated, and ids that do
not exist come back in `missing` rather than being dropped.

**`entity_profile` answers the entity question in one call.** "Tell me everything this IP is involved with"
needs the exact count, the first/last seen, the per-source/host/user/severity/detection breakdown, the typed
graph relations, an activity histogram and a few citable lines — all of which Iris already computes, none of
which any single tool returned. Stitched out of the separate tools that was 18 tool calls; it is now 1. It
composes the existing services only (`search.search` + the same `_aggregate` as `aggregate_events`, plus
`GraphBuilder.node_detail`), so a profile and an `aggregate_events` of the same query can never disagree. It
returns `query` = `entity:"<value>"` — the one DSL field that matches EXACTLY — so drilling down is one more
call and does not fall back to substring free text.

**A multi-event result is budgeted, never truncated from the end.** `investigator._clip` cuts a tool result at
`TOOL_RESULT_CHARS` from the END, so an over-long batch loses its LAST rows silently. `entity_profile` and every
row-returning tool shed detail in a defined order (shorter raw lines → fewer fields → entities → …) until the
payload fits, keep every row and every count, and report what went in `trimmed`.

**Why aggregation is the headline.** "What logs does 10.0.0.100 exist in?" used to be answered by paging rows
until the budget ran out, ending in "confirmed in one source; the other 29 neither confirmed nor ruled out".
`aggregate_events` answers it in ONE call with exact counts over EVERY match; a group that is absent from the
result genuinely does not contain the term. `search_events` now says so in a `note` whenever its rows are a
subset, and every search-ish result carries `engine` and `tookMs` so the transcript shows what a query cost.

**The query language is taught, and malformed queries are refused.** `app/query.py` is deliberately forgiving,
so a broken query silently returns zero matches — indistinguishable from real absence of evidence. The tool layer
screens it first (unbalanced quote/paren, a dangling AND/OR/NOT, `field:` with no value) and refuses with a
correction that restates the grammar including the backslash escape (`10.0.0.9\:3001`). The orientation block
also lists the most common parsed field names, so a trivial question does not cost a discovery call.

**Within-run dedupe.** An identical read (same tool, same arguments) is served from the run's own cache with
`cached:true`; any write clears it. Repeated identical results are pure context waste.

**Rule tools go through the existing validated path** (`routers/rules.py` → `RULES_STORE`), never a parallel
implementation: `detect.parse_param` validation, the save-time ReDoS screen, the `RULES_STORE.rev` bump the
anomaly cache keys on, and `STORE.reapply_rule` afterwards. A rejected value changes NOTHING (the rule keeps
running as it was) and the reason goes back to the model. AI-authored rules carry `createdBy:'ai'`, land in
`AiRun.actions` and are reversible by `/undo`. Re-running detections is O(pool) — the result reports `reapplyMs`,
`poolEvents` and `hits` so the cost is visible rather than a silent multi-second stall.

### Grounding, provenance and control — the rules the design rests on
- **Citations are verified before anything persists.** `add_ioc`, `add_note` and `add_graph_link` require
  `citedEventIds`; `add_events_to_case` requires real ids. If any id is not an event in the workspace the tool
  REFUSES the whole call and tells the model which ids were bad, so it has to go and find the real ones. The final
  answer is scanned too: ids in it that do not resolve come back as a `warning` event and in
  `AiRun.unverifiedCitations`. A fabricated event id in an incident report is a serious harm, so it is a refusal,
  never a silent drop.
- **Every write is attributed.** Indicators get `addedBy:'ai'` + the run id, notes get
  `author:"AI assistant (<model>)"`, graph links get `ai:true`, case-set entries get an `ai` label. All of it lands
  in case.json, so an analyst reading the case later can tell AI-authored artefacts from their own.
- **Writes are applied immediately and are reversible, not confirmed one at a time.** An investigation that stops
  to ask permission twelve times is not an investigation, and the write surface is additive-only. The bargain is:
  every change is streamed as a `write` event as it happens, listed in `AiRun.actions`, and `POST
  /api/ai/runs/{id}/undo` takes the whole run back off the case.
- **Creating a case is an explicit tool call.** Nothing else materialises one; with no active case every case-scoped
  write refuses and tells the model to call `create_case` first.
- **Bounds**, all four, because each fails differently: steps (`IRIS_AI_MAX_STEPS`, default 40, cap 120), wall
  clock (`IRIS_AI_MAX_SECONDS`, default 600, cap 900), estimated context tokens (`IRIS_AI_MAX_CONTEXT_TOKENS`,
  default 60 000 — tool results are what actually grow without limit), and 200 writes per run. When steps or the
  clock trip, the run does ONE final turn with `tool_choice:'none'` so the analyst still gets the report the work
  earned; a `stop` request skips that turn and ends immediately, and Stop keeps working during and after a
  compaction. That final turn takes the answer from the streamed deltas **or from the assembled message**,
  whichever is present, and never lets an empty wrap-up erase what the run had already established: collecting
  only `text` deltas meant a provider that streams no prose deltas (legal — `client.stream_chat` always yields
  the assembled `message`) produced an EMPTY report after a full-length run, which is exactly the "it ran for
  ages and gave me no answer" complaint. The report the model wrote was in the message the whole time.
- **Malformed tool arguments cost the call, never the run.** A small local model writing a long call fails in
  two places: Iris's own parse of `function.arguments`, and the gateway's (llama.cpp answers HTTP 500 "Failed to
  parse tool call arguments as JSON"). Both were seen live on the same investigation — `build_case_graph` cut off
  at char 3313, `add_note` at char 2308 — and both are the argument text RUNNING OUT OF TOKENS, not a model that
  cannot write JSON. **Iris sends no `max_tokens` on any request** — that 1400-token cap was Iris's own and is
  gone; the backend model knows its own context window and enforces its own ceiling, and a second blind limit in
  front of it can only truncate replies that were going to finish. What remains handles the truncation Iris does
  not control: `ai/argrepair.repair_arguments`, a mechanical repair (escape raw control characters and bare quotes inside
  a string, drop a trailing comma, and for a truncated blob discard the incomplete trailing record and close the
  JSON) whose every repair is streamed as a `warning`, recorded in the transcript and returned to the model as
  `argumentsRepaired` on the tool result — a repaired write that landed nine of ten links must never look like
  ten; and, when the PROVIDER refuses the turn, `prompts.ARG_TOO_BIG` telling the model its call never ran and
  asking for a smaller one, up to `investigator.MAX_ARG_FAILURES` (3) times before the run fails. An unsalvageable
  blob is refused with advice that names the truncation, because "send valid JSON" makes a model re-send the same
  oversized call.
- **The context ceiling COMPACTS instead of stopping.** Reaching it folds the middle of the transcript into one
  running brief — the objective verbatim, the tool calls already made and what they returned, every event id seen
  (citations are load-bearing: a claim whose citation was compacted away would become uncited and the citation
  validator would then flag the model's own correct finding), what has already been written to the case, and the
  model's prose findings — keeping the system message, the objective and a recent tail verbatim. The brief is
  built deterministically, not by a second model call. Bounded by `IRIS_AI_MAX_COMPACTIONS` (default 6, cap 20)
  and by a floor: if compacting cannot get the estimate under 80 % of the ceiling the run stops on `budget` as
  before, so it can never loop. Every compaction emits a `status` event ("compacted N earlier steps into a running
  brief …") that is persisted in the transcript — an analyst reading a run back must know the model's view was
  summarised. `done` reports `compactions`, `cachedToolCalls` and `textToolCalls`.
- **Tool calling is verified, not assumed.** A provider that rejects the `tools` body key fails with a specific
  message naming the endpoint and the model. A provider that silently ignores it — the model writes
  `<tool_call><function=…><parameter=…>` or a `{"name":…,"arguments":…}` block as PROSE — has that text parsed
  into a real tool call, with a `warning` saying the provider is not doing native tool calling. Raw tool-call
  markup is stripped from the assistant message either way and can NEVER reach the final report: if the wrap-up
  turn contains any, it is removed and reported as "the model tried to call X after its budget ran out".
- **Arguments are schema-checked before a handler runs.** A parameter the tool does not declare (the real model
  invented `create_case(severity=…, status=…)`, neither of which exists on `Case`) is refused with the tool's
  actual parameter list, rather than being silently dropped so the model believes it set something it did not.
- Tool handlers run on a worker thread (`asyncio.to_thread`) — a search over a million events on the event loop
  would stall every other request in the process.
- With no provider configured the stream is a single `error` event naming the setting to change; nothing else in
  the app is affected.
