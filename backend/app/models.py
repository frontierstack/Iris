"""Shared data models (pydantic v2) matching docs/API_CONTRACT.md."""
from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
SEV_ORDER: dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def max_sev(a: str, b: str) -> str:
    return a if SEV_ORDER.get(a, 0) >= SEV_ORDER.get(b, 0) else b


class Detection(BaseModel):
    name: str
    id: str
    level: Severity


# --------------------------------------------------------------- the pooled event
# `Event` is NOT a pydantic model, and that is the single largest memory decision in the app: the pool
# holds ONE of these per log line, so the per-instance cost IS the ceiling on how much evidence Iris can
# hold. Measured on this machine, 200 k events of a 124-byte DNS line, each owning a distinct string
# (sharing one string object hides the text cost, which is the trap the first measurement fell into):
#
#     pydantic BaseModel (before) ..... 1,827 B/event   = 13.7x the source bytes  -> 14.7 GB for a 1.07 GB log
#     __slots__, same 16 attributes ...   664 B/event   =  5.0x                   ->  5.3 GB
#     THIS CLASS ......................   419 B/event   =  3.1x                   ->  3.4 GB
#
# ~173 B of that last figure is the log text itself — evidence, not overhead, and the floor of this
# work. A `BaseModel` instance carries a `__dict__`, a `__pydantic_fields_set__` set and (with
# `Field(default_factory=...)`) three freshly allocated empty containers per event; none of that is
# the analyst's data. On the analyst's real DNS_Logs.csv the raw phase measures 4.0x source bytes.
#
# Three rules hold this together. Break any one of them and the saving is gone or, worse, silent:
#
#   1. **The empty containers are SHARED and frozen.** `fields`/`entities`/`detections`/`labels` point at
#      one module-level empty object when there is nothing in them. That object refuses mutation
#      (`_FrozenDict` / `_FrozenList`) — a shared container that could be mutated in place would write one
#      event's field onto every other event in the pool, which in an evidence tool is not a performance
#      bug but a fabrication. Writers go through `set_field` / `set_field_default` / `add_detection`,
#      which copy on write.
#   2. **`msg` is stored only when it is not `raw[:200]`.** For plain line logs the normalizer already
#      sets `msg = raw[:200]`, and CPython returns `raw` itself for that slice when the line is short, so
#      the two are the SAME object and storing both is pure waste. Structured parsers (SQLite
#      `summarise()`, EVTX, JSONL) synthesise a genuinely different message and it is stored verbatim —
#      the distinction is real evidence and is never flattened.
#   3. **Serialization is explicit.** A slotted object is not JSON-serializable and FastAPI will not
#      encode it, so every API boundary goes through `model_dump()` or the `EventOut` pydantic model
#      below. Nothing may hand a pooled `Event` to `jsonable_encoder` / `orjson`.
_MSG_DERIVE_LEN = 200


class _FrozenDict(dict):
    """The shared empty `Event.fields`. Every mutator raises rather than corrupting the whole pool."""
    __slots__ = ()

    def _frozen(self, *a: Any, **k: Any) -> Any:
        raise TypeError("Event.fields is the shared empty default and cannot be mutated in place — "
                        "use event.set_field(key, value) / event.set_field_default(key, value)")

    __setitem__ = __delitem__ = _frozen
    update = setdefault = pop = popitem = clear = _frozen  # type: ignore[assignment]


class _FrozenList(list):
    """The shared empty `Event.entities` / `.detections` / `.labels`. Same reasoning as `_FrozenDict`."""
    __slots__ = ()

    def _frozen(self, *a: Any, **k: Any) -> Any:
        raise TypeError("this Event list is the shared empty default and cannot be mutated in place — "
                        "assign a new list, or use event.add_detection(...)")

    append = extend = insert = remove = pop = clear = sort = reverse = _frozen  # type: ignore[assignment]
    __setitem__ = __delitem__ = __iadd__ = __imul__ = _frozen  # type: ignore[assignment]


EMPTY_FIELDS: dict[str, str] = _FrozenDict()
EMPTY_LIST: list = _FrozenList()


class Event:
    """One normalized log record, as held in the workspace pool. See the note above before changing it."""

    __slots__ = ("id", "ts", "source", "sourceId", "file", "host", "user", "_msg", "sev", "raw",
                 "fields", "entities", "detections")

    # NOT slots — three attributes the POOL never holds. `baseline` is computed by the analyzer on the
    # detail endpoint, `inCase`/`labels` are case-set membership stamped on read (Store.stamp_membership).
    # Carrying them per pooled event was 24 B x every log line to store `None`, `False` and an empty
    # list. They stay readable (`e.inCase`, `e.baseline` are used) but only the boundary can set them,
    # which is also the honest statement: the pool does not know what a case is.
    baseline: Optional[str] = None
    inCase: bool = False
    labels: list = EMPTY_LIST

    def __init__(self, id: str = "", ts: str = "", source: str = "", sourceId: str = "", file: str = "",
                 host: str = "", user: str = "", msg: str = "", sev: str = "info", raw: str = "",
                 fields: Optional[dict] = None, entities: Optional[list] = None,
                 detections: Optional[list] = None) -> None:
        self.id = id
        self.ts = ts
        self.source = source
        self.sourceId = sourceId
        self.file = file
        self.host = host
        self.user = user
        self.sev = sev
        self.raw = raw
        # store msg only where it says something raw[:200] does not (see rule 2 above)
        self._msg = None if msg == raw[:_MSG_DERIVE_LEN] else msg
        self.fields = fields if fields else EMPTY_FIELDS
        self.entities = entities if entities else EMPTY_LIST
        self.detections = detections if detections else EMPTY_LIST

    # ------------------------------------------------------------ msg
    @property
    def msg(self) -> str:
        m = self._msg
        return self.raw[:_MSG_DERIVE_LEN] if m is None else m

    @msg.setter
    def msg(self, value: str) -> None:
        self._msg = None if value == self.raw[:_MSG_DERIVE_LEN] else value

    # ------------------------------------------------- copy-on-write writers
    def set_field(self, key: str, value: str) -> None:
        f = self.fields
        if type(f) is _FrozenDict:
            f = self.fields = {}
        f[key] = value

    def set_field_default(self, key: str, value: str) -> None:
        f = self.fields
        if type(f) is _FrozenDict:
            f = self.fields = {}
        f.setdefault(key, value)

    def add_detection(self, det: "Detection") -> None:
        d = self.detections
        if type(d) is _FrozenList:
            d = self.detections = []
        d.append(det)

    # ------------------------------------------------------ serialization
    def model_dump(self) -> dict:
        """The API shape, key for key what the pydantic model produced. Containers are COPIES: a
        response must never hand out a reference into the pool, least of all the shared empties."""
        return {"id": self.id, "ts": self.ts, "source": self.source, "sourceId": self.sourceId,
                "file": self.file, "host": self.host, "user": self.user, "msg": self.msg,
                "sev": self.sev, "raw": self.raw, "fields": dict(self.fields),
                "entities": list(self.entities),
                "detections": [d.model_dump() for d in self.detections],
                "baseline": self.baseline, "inCase": self.inCase, "labels": list(self.labels)}

    def model_copy(self, *, update: Optional[dict] = None, deep: bool = False) -> "Event":
        """`BaseModel.model_copy` without resurrecting a `__dict__`. `update` may only name a real slot:
        `inCase`/`labels`/`baseline` are boundary fields and belong on a dict or an `EventOut`."""
        e = Event.__new__(Event)
        for name in Event.__slots__:
            object.__setattr__(e, name, getattr(self, name))
        if update:
            for k, v in update.items():
                setattr(e, k, v)          # 'msg' goes through the property setter, as it must
        return e

    # Pickled once per event across the ProcessPoolExecutor boundary in parsers/parallel.py, so the
    # generic `__reduce_ex__` slots path (a dict per instance) is not good enough — a flat tuple is.
    def __getstate__(self) -> tuple:
        return (self.id, self.ts, self.source, self.sourceId, self.file, self.host, self.user,
                self._msg, self.sev, self.raw, self.fields, self.entities, self.detections)

    def __setstate__(self, s: tuple) -> None:
        (self.id, self.ts, self.source, self.sourceId, self.file, self.host, self.user,
         self._msg, self.sev, self.raw, self.fields, self.entities, self.detections) = s

    def __repr__(self) -> str:
        return f"Event(id={self.id!r}, ts={self.ts!r}, source={self.source!r}, msg={self.msg[:60]!r})"


class Correlation(BaseModel):
    id: str
    ts: str
    msg: str
    sev: Severity
    reason: str


class EventOut(BaseModel):
    """The API boundary shape of an `Event` — validated, JSON-serializable, built for the <=200 rows a
    response actually returns. `from_attributes` lets a pooled `Event` be validated straight into one,
    which is what every `list[EventOut]` field below relies on."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    ts: str
    source: str
    sourceId: str
    file: str
    host: str
    user: str
    msg: str
    sev: Severity
    raw: str
    fields: dict[str, str] = Field(default_factory=dict)
    entities: list[str] = Field(default_factory=list)
    detections: list[Detection] = Field(default_factory=list)
    baseline: Optional[str] = None
    # case-set membership, stamped on read so lists can show it without a second request
    inCase: bool = False
    labels: list[str] = Field(default_factory=list)


class EventDetail(EventOut):
    """One event, plus what the CORRELATION ANALYSIS says about it — when that analysis exists.

    `correlations` and `baseline` come from a derived structure built over the whole pool, which on a
    large workspace takes minutes. Opening an event must never wait for it (that is what made this
    page slow), so when it is not current the two fields are empty and `analysis` says why. An empty
    `correlations` with no explanation would be a claim — "nothing correlates with this event" — and
    that is exactly the silent-omission failure this project keeps closing.
    """
    correlations: list[Correlation] = Field(default_factory=list)
    # Same shape as the graph/timeline/anomaly status blocks ({state,events,target,pct,note,...}),
    # which is what the screens already know how to render. Present ONLY when correlations were
    # unavailable; absent means they are real.
    analysis: Optional[dict[str, Any]] = None


class ParseProgressInfo(BaseModel):
    """Live parse detail for ONE source, straight off `jobs.PARSE_PROGRESS`.

    The same shape a job row carries, attached to the source as well, because the Sources table is where
    a long parse is actually watched and all it could say was `PARSING` with a spinner. On a 639 MB
    capture that is twenty minutes of a screen that cannot be told apart from a hang — and every number
    that answers "is it moving?" already existed server-side, keyed by this source's id.

    In memory only: absent after a restart until the work resumes, and never persisted anywhere.
    """
    bytesDone: int = 0
    bytesTotal: int = 0
    pct: float = 0.0
    events: int = 0
    workers: int = 1
    # 'reading' = phase 1 (raw lines into the pool), 'enriching' = phase 2 (the real parser),
    # 'parsing' = a container with no raw phase, 'merging' = folding the events into the pool.
    phase: str = "parsing"
    bytesPerSec: int = 0
    etaSec: Optional[int] = None
    elapsedSec: int = 0


class Source(BaseModel):
    id: str
    file: str
    parser: str
    events: int = 0
    range: Optional[tuple[str, str]] = None
    confidence: float = 0.0
    state: Literal["READY", "REVIEW", "MAP", "PARSING", "ERROR"] = "PARSING"
    size: int = 0
    error: Optional[str] = None
    guessedFields: Optional[list[str]] = None
    sample: Optional[str] = None
    delimiter: Optional[str] = None
    # 'case'    — belongs to the active case (bytes under cases/<id>/uploads/)
    # 'library' — staged in $IRIS_DATA_DIR/library/ and belongs to NO case. Parsed and searchable all the
    #             same: analysis never requires a case. Attaching it to one flips this to 'case'.
    origin: Literal["case", "library"] = "case"
    # Two-phase ingest (see app/enrich.py). 'raw' means the lines are in the pool and searchable but
    # nothing has been interpreted: no timestamps, no severities, no fields, no entities. A screen that
    # shows a time, a severity or a field MUST say so rather than presenting the defaults as findings.
    #   raw -> queued -> enriching -> enriched | error, or 'skipped' when the analyst declines it.
    #   'enriched' is also the birth state of a container that has no raw form (EVTX, SQLite, PDF, …).
    enrich: Literal["raw", "queued", "enriching", "enriched", "skipped", "error"] = "enriched"
    enrichError: Optional[str] = None
    enrichedAt: Optional[str] = None
    # Live parse detail, attached per RESPONSE (never stored on the source and never persisted) — see
    # ParseProgressInfo. Non-null only while this source is genuinely being read.
    progress: Optional[ParseProgressInfo] = None


class Cluster(BaseModel):
    id: str
    title: str
    start: str
    end: str
    span: str
    tag: Literal["FREQUENCY", "ENTITY LINK", "ANOMALY"]
    sev: Severity
    count: int
    sources: list[str]
    why: str
    eventIds: list[str]


class EntityLink(BaseModel):
    name: str
    shared: int
    via: str


class Entity(BaseModel):
    name: str
    kind: str
    first: str
    count: int
    facts: list[tuple[str, str]]
    links: list[EntityLink]


class Edge(BaseModel):
    a: str
    b: str
    weight: float


# ------------------------------------------------------------------ graph v2 (typed)
EntityType = Literal["ip", "user", "host", "process", "pid", "file", "hash", "domain", "url", "port", "email", "key",
                     "session", "pod", "service", "registry", "other"]
Relation = Literal["auth_from", "connected_to", "ran", "spawned", "wrote", "read", "deleted", "resolved", "requested",
                   "used_key", "on_host", "session", "co_occurred"]


class GraphNode(BaseModel):
    id: str                       # "<type>:<value>"
    type: EntityType
    value: str
    label: str
    count: int = 0
    first: str = ""
    last: str = ""
    sev: Severity = "info"
    detections: int = 0
    facts: list[tuple[str, str]] = Field(default_factory=list)
    inCase: bool = False
    ai: bool = False
    # Drawn by hand or by the agent rather than found by extraction. The screen must be able to tell
    # the two apart: an extracted node is what the LOGS say, an authored one is what someone CONCLUDED.
    manual: bool = False
    why: str = ""                 # why it was added, when it was authored rather than extracted


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relation: Relation
    count: int = 0
    first: str = ""
    last: str = ""
    sev: Severity = "info"
    outcome: Optional[Literal["success", "failure", "denied", "mixed"]] = None
    eventIds: list[str] = Field(default_factory=list)
    why: str = ""
    ai: bool = False          # proposed/accepted from the AI reviewer
    manual: bool = False      # drawn by the analyst
    confidence: Optional[float] = None


class GraphV2(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    stats: dict[str, Any] = Field(default_factory=dict)


class GraphLink(BaseModel):
    """A link the analyst accepted from the AI reviewer or drew by hand — persisted in case.json."""
    id: str
    source: str
    target: str
    relation: Relation
    why: str = ""
    confidence: Optional[float] = None
    ai: bool = False
    createdAt: str = ""


class Posture(BaseModel):
    label: str
    value: str
    pct: float
    color: Literal["ok", "warn", "bad"]


class QueueItem(BaseModel):
    label: str
    detail: str
    done: bool


class CaseSetEntry(BaseModel):
    """An event the analyst marked as part of the investigation (replaces the old pin).

    An entry is ANCHORED to the line it points at, not only to its id. Event ids are assigned at parse
    time from a counter that depends on what else is in the pool, so the same file re-parsed in a
    different order gets different ids — and a curated timeline whose ids no longer resolve used to be
    silently pruned and written back empty ("the timeline events disappear and do not show up again").
    `file` + `rawHash` are what let `Store.restore` find the line again and re-key the entry. They are
    written for new entries; an older entry without them still loads, it just cannot self-heal.
    """
    eventId: str
    labels: list[str] = Field(default_factory=list)
    note: str = ""
    addedAt: str = ""
    file: str = ""            # the log the line came from
    rawHash: str = ""         # sha1(raw)[:16] — the line itself, without storing it twice


class CaseSetResponse(BaseModel):
    entries: list[CaseSetEntry]
    events: list[EventOut]
    labels: list[str] = Field(default_factory=list)


class NoteRef(BaseModel):
    """Something a note points at — rendered as a chip that navigates to it."""
    kind: Literal["event", "search", "entity", "cluster", "source"]
    value: str          # event id, query string, entity name, cluster id, source id
    label: str = ""     # what to show on the chip (falls back to `value`)


class CaseNote(BaseModel):
    id: str
    text: str
    author: str = ""
    createdAt: str = ""
    updatedAt: str = ""     # set only when edited, so the UI can show "(edited)"
    refs: list[NoteRef] = Field(default_factory=list)


class CaseSnapshot(BaseModel):
    """Totals persisted into case.json so an INACTIVE case still reports something useful."""
    events: int = 0
    sev: dict[str, int] = Field(default_factory=dict)
    range: Optional[tuple[str, str]] = None
    clusters: int = 0
    detections: int = 0
    entities: int = 0


class SourceBrief(BaseModel):
    id: str
    file: str
    parser: str = ""
    events: int = 0
    size: int = 0
    state: str = "READY"
    # attached from the case-less library (its bytes are still staged there), so it can be taken back
    # out of the case without deleting anything — see POST /api/cases/{id}/sources/{sid}/detach
    fromLibrary: bool = False


class PoolSkip(BaseModel):
    """A staged library file that is NOT in the workspace pool, and why.

    An aggregate count ("2 files skipped") is useless when the two are 263 MB each: a file absent from
    search looks exactly like "no matching events". Every skip is therefore named, sized and explained.

    `reason` has FIVE values, listed on the field below, and they must never be collapsed: each one
    tells the analyst to do something different. This docstring used to name only two of them, and the
    UI's own type declared only those two — so a two-way ternary looked exhaustive and printed
    "unreadable" for a 'memory' skip, sending the analyst to check the disk for a file the machine
    simply had no RAM for.
    """
    fileName: str            # the on-disk name in $IRIS_DATA_DIR/library/
    displayName: str         # the original upload name
    size: int                # bytes of source log
    # 'budget'    — the configured pool cap (IRIS_POOL_MAX_MB) refused it
    # 'unreadable' — the bytes could not be read from disk
    # 'memory'     — this machine does not have the RAM to hold it RIGHT NOW. Different from budget:
    #                nothing is misconfigured, the workspace is simply bigger than the box. Loading it
    #                anyway is offered, checked against live free memory, because refusing a file the
    #                analyst needs is only acceptable while it is reversible.
    reason: str = "budget"   # 'budget' | 'unreadable' | 'memory' | 'parse-error' | 'not-parsed'
    detail: str = ""         # one sentence the analyst can act on
    budgetBytes: int = 0     # the pool budget in force (bytes of source log); 0 = not applicable
    usedBytes: int = 0       # how much of that budget the files ahead of it had already taken


class PoolFileProgress(BaseModel):
    """One file of the background pool load. The aggregate says 16 files / 41 % — this says WHICH file
    is being parsed right now and which of the others are already in the pool. Without it the only
    per-file information in the whole payload was `currentFile`."""
    file: str
    size: int = 0
    # "skipped" is load-bearing: `Store._plan_state(name, "skipped")` runs when a file will not fit in
    # memory, and its events are NOT in the pool. Leaving it out of this Literal made GET /api/case
    # raise a ValidationError (a 500 on the most-called endpoint in the app) for the whole window a
    # skipped file was in the plan. Never coerce it to "error" or "done": "the parser failed" and
    # "this file was never read" have different fixes, and the analyst is told which.
    state: Literal["pending", "parsing", "done", "error", "skipped"] = "pending"
    bytesDone: int = 0
    pct: float = 0.0
    events: int = 0


class PoolProgress(BaseModel):
    """How far the background pool load has actually got.

    `poolPending` alone ("16 more sources") is not progress: on a real library one of those files is
    263 MB and the rest are 2 MB each, so the count barely moves for ten minutes. These are BYTES of
    source log, plus the file currently being parsed and its own share, which is what makes a percentage
    and an ETA meaningful.
    """
    bytesDone: int = 0
    bytesTotal: int = 0
    pct: float = 0.0
    filesDone: int = 0
    filesTotal: int = 0
    currentFile: str = ""          # "" between files
    currentBytesDone: int = 0
    currentBytesTotal: int = 0
    currentPct: float = 0.0
    workers: int = 1               # parse workers on the current file (>1 = the multi-process path)
    bytesPerSec: int = 0
    etaSec: Optional[int] = None
    elapsedSec: int = 0
    # per-file breakdown of the same load, in library order. Was declared by the UI but never populated.
    files: list[PoolFileProgress] = Field(default_factory=list)


class EnrichCounts(BaseModel):
    """Sources per `Source.enrich` state, across the WHOLE pool (case + library)."""
    raw: int = 0
    queued: int = 0
    enriching: int = 0
    enriched: int = 0
    skipped: int = 0
    error: int = 0


class EnrichActivity(BaseModel):
    """What phase 2 is doing RIGHT NOW — the answer to "what is it waiting on?".

    `counts` says how much is left; it never said what was happening. A 16.9 MB file behind a batch
    merge reported "1 queued to interpret" and nothing else, for minutes, while the pool rebuild it was
    queued behind ran unannounced. Every state below used to render as that same sentence:

      parsing         a source is being read and normalized (this one has a percentage)
      merging         a finished batch is being folded into the pool — O(the whole pool), the long one
      waitingForPool  the library is still loading; the worker yields to it rather than compete
      noWorker        nothing is servicing the queue, so those sources will stay raw until it restarts
      idle            nothing to do

    `detail` is the sentence to show. `elapsedSec` is what turns "it is doing something" into "it has
    been doing this for four minutes", which is the difference between waiting and worrying.
    """
    kind: Literal["idle", "parsing", "merging", "waitingForPool", "noWorker"] = "idle"
    detail: str = ""
    elapsedSec: int = 0
    # parsing only
    file: str = ""
    pct: Optional[float] = None
    etaSec: Optional[int] = None
    # merging only: how many interpreted sources are in the batch, how many events are being rebuilt,
    # and which of the merge's O(pool) stages is running.
    sources: int = 0
    events: int = 0
    stage: str = ""
    stageIndex: int = 0
    stageCount: int = 0


class CaseEnrichment(BaseModel):
    """How much of the pool has been through phase 2 of the ingest (see app/enrich.py).

    Two numbers, because there are two questions and they have different answers:
      * `pending` (queued + enriching) — is work in flight? This is what a progress banner counts down.
      * `outstanding` (raw + queued + enriching) — is my ANSWER incomplete? Those sources are in the pool
        as raw lines: searchable, but with no timestamps, severities, fields, entities or detections. The
        timeline, the entity graph and the anomaly list are therefore answering over PART of the corpus,
        and every one of those screens has to say so. An empty graph that is really "not enriched yet" is
        a lie about the evidence.
    A `skipped` source is in neither: the analyst declined it deliberately, so warning about it forever
    would be noise. It is still visible in `counts`.
    """
    counts: EnrichCounts = Field(default_factory=EnrichCounts)
    # The source currently in phase 2, "" when the worker is idle. RECONCILED against `counts`: the
    # queue keeps its own idea of what it is working on, and it still names the last source through
    # the batch commit that follows it. A screen that reports that says "Interpreting <file>" about a
    # file that finished a minute ago, so a sid only appears here while its source really is
    # `enriching`.
    running: str = ""
    pending: int = 0
    outstanding: int = 0
    # A finished batch is being merged into the pool. Real work with no source of its own — every
    # member of it is already `enriched` — and on a large pool it is tens of seconds. Reported so the
    # screen can say what is happening instead of naming a file that is no longer being read.
    committing: bool = False
    # The one field a screen needs to answer "what is it waiting on?". Everything above is a COUNT.
    activity: EnrichActivity = Field(default_factory=EnrichActivity)
    # The pool-wide detection pass is running in the BACKGROUND. Per-event rules are stamped on new
    # events before they enter the pool; the windowed rules read the density of the whole pool and are
    # re-evaluated afterwards, off the worker, coalesced. It holds nothing up — the queue moves, the
    # events are searchable — but it is minutes of one core on a large workspace and a pass nobody can
    # see is exactly the "nothing is happening" the activity field exists to prevent.
    detectionsRefreshing: bool = False
    detectionsRefreshSec: int = 0
    detectionsRefreshPct: Optional[float] = None   # rough, by catalogue section; None = not started
    # What the RUNNING source is doing, so a screen can show movement rather than a number that changes
    # once a minute. A source takes tens of seconds on a large pool, so "1 running" on its own is
    # indistinguishable from "stuck" — which is exactly how it was read. Straight off
    # `jobs.PARSE_PROGRESS`, which phase 2 already publishes into; absent when nothing is running.
    runningFile: str = ""
    runningPct: Optional[float] = None
    runningPhase: str = ""
    runningEtaSec: Optional[int] = None
    # A source the analyst has to decide about: `raw` with nothing queued (automatic interpretation is
    # off) or `error` (the parse failed and can be retried). Separated from `pending` because pending
    # needs patience and this needs a person.
    needsAction: int = 0


class Case(BaseModel):
    id: str
    name: str
    analyst: str
    # one-paragraph description of what is being investigated. Written by the analyst or set by the AI
    # investigator via its update_case tool; persisted in case.json.
    summary: str = ""
    createdAt: str
    # the CASE's own sources and event total — both empty/0 while no case exists
    sources: list[Source]
    eventCount: int
    # the case-less pool: sources staged in the library, parsed and analysable with no case at all.
    # sources + librarySources = everything the default (scope=all) analysis runs over.
    librarySources: list[Source] = Field(default_factory=list)
    # events across the WHOLE pool (case + library) — what Search, Timeline, Anomalies and the graph see
    poolEventCount: int = 0
    # A large library loads in the background so the API is available immediately. While poolLoading is
    # true the analysis screens MUST say so — otherwise a half-loaded pool reads as data loss.
    poolLoading: bool = False
    poolPending: int = 0    # staged files still to parse
    poolLoaded: int = 0     # staged files parsed so far in this load
    # byte-level progress of that load (null when nothing is loading) — see PoolProgress
    poolProgress: Optional[PoolProgress] = None
    # staged files left unparsed because the case-less pool hit its memory budget (IRIS_POOL_MAX_MB).
    # They are still listed in the library and still attachable to a case — nothing is lost.
    # poolSkipped is exactly len(poolSkippedFiles); the per-file list is the truth, the count is the header.
    poolSkipped: int = 0
    poolSkippedFiles: list[PoolSkip] = Field(default_factory=list)
    # the pool memory budget in force, in bytes of source log (0 = unlimited). The remedy for a skip is
    # to raise IRIS_POOL_MAX_MB or to free the pool, so the number has to be visible.
    poolBudgetBytes: int = 0
    # two-phase ingest: how much of the pool is still raw lines, and what phase 2 is doing right now.
    # Derived from per-source metadata only — /api/case must stay O(1) in the event count.
    enrichment: CaseEnrichment = Field(default_factory=CaseEnrichment)
    caseSet: list[CaseSetEntry] = Field(default_factory=list)
    notes: list[CaseNote] = Field(default_factory=list)
    # True when no case exists yet: the id is reserved but nothing is on disk and /api/cases is empty
    pending: bool = False
    posture: list[Posture]
    queue: list[QueueItem]


class ComputeSettings(BaseModel):
    mode: Literal["auto", "cuda", "cpu"] = "auto"


class AISettings(BaseModel):
    provider: Literal["none", "openai"] = "none"
    model: str = "gpt-4o-mini"
    baseUrl: str = ""
    apiKey: str = ""
    agents: int = Field(default=3, ge=1, le=4)
    verifyTls: bool = True      # False = skip certificate verification (corporate TLS-inspection proxies)
    caBundle: str = ""          # optional path to a PEM CA bundle; blank = auto ($IRIS_CA_BUNDLE, /data/ca.pem, certifi)


class McpSettings(BaseModel):
    """The MCP server Iris exposes to OUTSIDE agents (Cursor, Claude Code, Claude Desktop).

    Default OFF: it hands a tool-using model the analyst's whole evidence pool on a port that is already
    unauthenticated, so it is an explicit decision, not something a fresh install starts doing.
    `allowWrites` is a second, separate switch — reads cannot change the case, writes can.
    `token`, when set, is required as `Authorization: Bearer <token>`; masked on read like ai.apiKey."""
    enabled: bool = False
    allowWrites: bool = False
    token: str = ""


class IngestSettings(BaseModel):
    """Two-phase ingest (app/enrich.py).

    A log lands as RAW LINES immediately — in the pool, in the search index, readable, and WITH ITS
    TIMESTAMP, which phase 1 reads off the line. The expensive interpretation (severity, per-field
    columns, entities, detections) happens afterwards, on a background worker, per source.

    `autoEnrich` decides whether that second phase starts on its own, and it defaults to OFF because
    of what the second phase costs. Measured on a 20-column proxy export: **534 bytes per event raw
    against 1,617 interpreted**, an index of 286 bytes per event against 770, and an ingest of 0.7 s
    against 10.7 s — 3.4 bytes of RAM per byte of log instead of 16.5. Almost all of that difference
    is a per-event dict holding one string per column: the same line, stored again in pieces.

    What raw still gives you: full-text search over every line, time filters and a timeline (the
    timestamp is there), the raw log viewer, and an AI assistant that can read any line and pull
    fields out of it when a note or a finding needs them. What it does not: `field:value` queries,
    extracted entities and the graph built from them, severity, and the detection rules that read
    parsed fields. Those come back per source, on demand, from the Sources table — and every screen
    that depends on them says when a source has not been interpreted."""
    autoEnrich: bool = False


class Settings(BaseModel):
    theme: str = "iris-dark"
    compute: ComputeSettings = Field(default_factory=ComputeSettings)
    ai: AISettings = Field(default_factory=AISettings)
    mcp: McpSettings = Field(default_factory=McpSettings)
    ingest: IngestSettings = Field(default_factory=IngestSettings)
    analyst: str = "Analyst"


class GPUInfo(BaseModel):
    index: int
    name: str
    memoryTotalMB: int
    memoryUsedMB: int
    driver: Optional[str] = None


class ComputeStatus(BaseModel):
    available: bool
    active: Literal["cuda", "cpu"]
    mode: Literal["auto", "cuda", "cpu"]
    gpus: list[GPUInfo]
    cudaVersion: Optional[str] = None
    backend: Literal["cupy", "torch", "numpy"]
    lastCheck: str
    checking: bool
    error: Optional[str] = None
    note: Optional[str] = None  # informational (e.g. CPU install with no GPU libs) — not a failure
    # what the machine has and how many workers Iris sized itself to — see app/resources.py
    resources: Optional[dict] = None


class Finding(BaseModel):
    level: Severity
    title: str
    body: str
    evidence: str


class IOCHit(BaseModel):
    """One place an indicator was seen — enough to link straight to the event and its log file."""
    eventId: str
    ts: str
    sourceId: str = ""
    file: str = ""


class IOC(BaseModel):
    id: str = ""              # "<kind>:<value>" — stable, so manual entries can be edited/deleted
    kind: str
    value: str
    manual: bool = False      # added by the analyst rather than extracted from a detection
    note: str = ""
    count: int = 0
    files: list[str] = Field(default_factory=list)   # log files it appears in
    firstSeen: Optional[str] = None
    lastSeen: Optional[str] = None
    hits: list[IOCHit] = Field(default_factory=list)  # <= 5, for click-through
    # WHO put it there. An indicator recorded by the AI investigator is evidence-shaped output of a model
    # and must be distinguishable from one the analyst typed — 'extracted' is neither (it is derived).
    addedBy: Literal["extracted", "analyst", "ai"] = "extracted"
    addedAt: str = ""
    # The events the author cited as the origin of a MANUAL indicator. `hits` says where the string turns
    # up now; this says where it came from — which is what makes an indicator placeable on the timeline
    # even when the literal value never appears verbatim in a log line.
    citedEventIds: list[str] = Field(default_factory=list)


class IOCResponse(BaseModel):
    total: int
    iocs: list[IOC]


class IocMarker(BaseModel):
    """An indicator positioned on the timeline: when it was FIRST seen, and in which event.

    "When did we first see this indicator" used to be answerable only by opening the IOC panel and
    reading `firstSeen`; the timeline showed clusters and nothing else. A marker is the same indicator
    projected onto the incident chronology so it sits between the clusters it belongs to.
    """
    id: str
    kind: str
    value: str
    ts: str                       # firstSeen — where it sits on the timeline
    lastSeen: Optional[str] = None
    count: int = 0
    manual: bool = False
    addedBy: Literal["extracted", "analyst", "ai"] = "extracted"
    note: str = ""
    eventId: str = ""             # the first event it was seen in (click-through target)
    file: str = ""
    sourceId: str = ""


class AiAction(BaseModel):
    """One change an AI investigation made to the workspace, and how to take it back.

    Writes are applied immediately (not queued behind a per-action confirm), so this log IS the control
    surface: it tells the analyst exactly what changed and `POST /api/ai/runs/{id}/undo` reverses it.
    """
    id: str
    runId: str
    tool: str
    at: str
    summary: str
    undo: dict[str, Any] = Field(default_factory=dict)
    undone: bool = False


class AiTranscriptEntry(BaseModel):
    """One line of a persisted conversation — exactly what the panel renders.

    The panel builds the same shape from the live SSE stream, so a reconnecting client renders history
    and an in-flight run through one code path. `tool` entries are appended when the call starts and
    patched in place when its result lands.
    """
    seq: int = 0
    kind: Literal["status", "step", "text", "tool", "warning"] = "status"
    text: str = ""
    step: int = 0
    id: str = ""              # tool_call id, for matching the result back onto the entry
    name: str = ""            # tool name
    args: dict[str, Any] = Field(default_factory=dict)
    writes: bool = False
    ok: Optional[bool] = None
    summary: str = ""
    tookMs: int = 0
    # When this entry was last CHANGED, on the same counter as `seq`. A tool entry is patched in place
    # when its result lands, which keeps its `seq` — so `?since=<lastSeq>` never resent it and a polling
    # client (any tab that is not the one streaming) kept the card's spinner turning for the rest of the
    # run. `as_model` selects on this as well as on `seq`; 0 means "never patched".
    updSeq: int = 0


class AiRun(BaseModel):
    """A tool-using investigation: its prompt, its transcript, how it ended, and everything it changed.

    Persisted (see app/ai/history.py) so a refresh, a tab switch, a second tab or a server restart never
    loses the conversation. Nothing secret is stored — `model` is a name, never the API key.
    """
    id: str
    prompt: str = ""
    focus: str = ""           # what the panel was opened from, e.g. "event e412"
    # A CONVERSATION is a chain of runs. `threadId` is the first run's id (its own, for a first turn)
    # and `parentId` is the turn this one continues — empty on a first turn. The run stays the unit of
    # budget, stop and undo; the thread is what the panel renders as one chat.
    parentId: str = ""
    threadId: str = ""
    model: str = ""
    caseId: str = ""          # the case active when the run STARTED ("" in the case-less workspace)
    caseName: str = ""
    startedAt: str = ""
    endedAt: str = ""
    updatedAt: str = ""
    state: Literal["running", "done", "stopped", "error"] = "running"
    reason: str = ""          # complete | max_steps | timeout | stopped | budget | interrupted | error
    steps: int = 0
    toolCalls: int = 0
    answer: str = ""
    error: str = ""
    interrupted: bool = False  # the server restarted while this run was still going
    actions: list[AiAction] = Field(default_factory=list)
    unverifiedCitations: list[str] = Field(default_factory=list)
    transcript: list[AiTranscriptEntry] = Field(default_factory=list)
    transcriptSeq: int = 0     # highest seq that exists server-side; poll with ?since=<this>
    transcriptTruncated: bool = False


class Report(BaseModel):
    caseId: str
    caseName: str
    analyst: str
    generatedAt: str
    severity: Severity
    summary: str
    findings: list[Finding]
    caseSet: list[EventOut]  # the curated evidence (was `pinned`)
    iocs: list[IOC]
    notes: list[CaseNote] = Field(default_factory=list)


# ------------------------------------------------------------------ cases
class CaseSummary(BaseModel):
    id: str
    name: str
    analyst: str
    createdAt: str
    updatedAt: str
    sources: int = 0
    events: int = 0
    caseSet: int = 0
    # What a case holds BESIDES its evidence. A case in a case-optional workspace is often pure
    # curation — every log staying in the library, nothing attached — so sources/events/sizeBytes are
    # legitimately 0 while the case still holds the entire investigation. The delete confirmation used
    # to report only the first three and told the analyst they were deleting "0 files, 0 events, 0 B"
    # from a case that held four notes and a set of indicators.
    # `noteCount`, not `notes`: CaseDetail extends this and its `notes` is the list of CaseNote. One
    # name meaning a count in one model and a list in its subclass is how a field silently changes shape.
    noteCount: int = 0
    iocCount: int = 0
    graphLinkCount: int = 0
    active: bool = False
    sizeBytes: int = 0


class CaseDetail(CaseSummary):
    """Everything the case detail screen needs — works for inactive cases via the persisted snapshot."""
    notes: list[CaseNote] = Field(default_factory=list)
    snapshot: Optional[CaseSnapshot] = None
    sourceList: list[SourceBrief] = Field(default_factory=list)


# ------------------------------------------------------------------ rules
class RuleFlags(BaseModel):
    ignoreCase: bool = True
    multiline: Optional[bool] = False


class RulePattern(BaseModel):
    """A regex a built-in matches with, and the field it runs against."""
    field: str
    pattern: str


class RuleParam(BaseModel):
    """One editable knob of a built-in's condition.

    Built-ins match in Python, so their conditions used to be uneditable constants — an analyst could see
    "Security event 4720" and change nothing. Every constant that decides whether a rule fires is now a
    named parameter instead: the event id, the status codes, the burst threshold, the time window, the
    byte cutoff, the regex. `value` is what the engine is using right now; `default` is what Iris ships.

    kind drives both the editor widget and how the value is parsed:
      values  — comma-separated list; matched per the rule's own semantics (exact / prefix / substring)
      regex   — a Python regular expression
      text    — a single literal value
      int     — a plain count
      seconds — a time window, in seconds
      bytes   — a size threshold, in bytes
    """
    key: str
    label: str
    kind: Literal["values", "regex", "text", "int", "seconds", "bytes"]
    value: str
    default: str
    field: str = ""  # the event field this parameter is compared against, when there is one
    help: str = ""


RuleOp = Literal["equals", "not_equals", "contains", "not_contains", "starts_with", "ends_with",
                 "regex", "in", "not_in", "gt", "lt", "exists"]


class RuleCondition(BaseModel):
    """One row of a condition-built custom rule: <field> <operator> <value>.

    The same idea as a built-in's Param, pointed at an event field instead of a hard-coded constant:
    `value` is typed by the operator (regex compiles, in/not_in is a comma list, gt/lt is numeric,
    everything else is a literal) and validated with the same machinery.
    """
    field: str
    # RuleOp lists the legal operators; the field is a plain str so an unknown one is rejected by
    # detect.parse_condition with a readable 400 rather than by pydantic with a 422.
    op: str = "contains"
    value: str = ""  # ignored (and stored as "") for `exists`


class RuleThreshold(BaseModel):
    """Windowed burst semantics for a condition-built rule: count matches inside a sliding window."""
    count: int = 5
    window: int = 300  # seconds
    groupBy: str = ""  # event field the counts are grouped by; "" counts across the whole case


class Rule(BaseModel):
    id: str
    name: str
    description: str = ""
    sev: Severity = "medium"
    enabled: bool = True
    builtin: bool = False
    kind: Literal["regex", "builtin", "conditions"] = "regex"
    pattern: Optional[str] = None
    field: Optional[str] = "any"
    flags: Optional[RuleFlags] = None
    sourceFilter: Optional[str] = ""
    # custom rules may be composed from typed conditions instead of a raw regex (kind='conditions')
    conditions: list[RuleCondition] = Field(default_factory=list)
    combinator: Literal["and", "or"] = "and"
    threshold: Optional[RuleThreshold] = None
    tags: list[str] = Field(default_factory=list)
    createdBy: Literal["user", "ai", "system"] = "user"
    createdAt: str = ""
    updatedAt: str = ""
    hits: Optional[int] = None
    error: Optional[str] = None
    overridden: bool = False  # built-in whose metadata the analyst edited
    removed: bool = False  # built-in removed from the catalogue (only surfaced with includeRemoved)
    logic: Optional[str] = None  # the TRIGGER - the exact condition the engine evaluates. Read-only: for a built-in it
                                 # is Python, for a custom rule it is generated from the pattern/conditions. Distinct
                                 # from `description`, which is analyst prose and matches nothing.
    # 'graph' is a rule that reads the ENTITY GRAPH rather than one event at a time (app/graph_rules.py):
    # it tags no event and its hits are findings, so `hits` is None rather than 0 when nothing has
    # evaluated it yet. See GraphFinding.
    mechanism: Optional[Literal["regex", "fields", "threshold", "correlation", "graph"]] = None  # how it decides
    patterns: list[RulePattern] = Field(default_factory=list)  # the regexes it uses (derived, never maintained by hand)
    params: list[RuleParam] = Field(default_factory=list)  # built-in only: the editable knobs of its condition


class RuleInput(BaseModel):
    """Body for POST/PUT /api/rules (id / timestamps / builtin are server-owned).

    `pattern` is required for custom regex rules. PUT on a built-in ignores field/flags/sourceFilter (its
    matching is Python) and stores name/description/sev/tags/enabled plus `params` as an override -
    `params` is {key: value} over the rule's own RuleParam keys and IS what the engine then matches with.
    """
    name: str
    description: str = ""
    sev: Severity = "medium"
    enabled: bool = True
    kind: Literal["regex", "builtin", "conditions"] = "regex"
    pattern: Optional[str] = None
    field: str = "any"
    flags: Optional[RuleFlags] = None
    sourceFilter: Optional[str] = ""
    # custom rules: build the condition from typed rows instead of (or as well as) a raw regex. A non-empty
    # `conditions` list makes `pattern` optional; every value is validated per operator at save time.
    conditions: Optional[list[RuleCondition]] = None
    combinator: Literal["and", "or"] = "and"
    threshold: Optional[RuleThreshold] = None
    tags: list[str] = Field(default_factory=list)
    createdBy: Literal["user", "ai", "system"] = "user"
    # built-in only: {param key: value} edits to the condition. Unknown keys are rejected, values are
    # validated per kind, and an empty dict clears every override back to the shipped defaults.
    params: Optional[dict[str, str]] = None


class RuleTestInput(BaseModel):
    pattern: str
    field: str = "any"
    flags: Optional[RuleFlags] = None
    sourceFilter: Optional[str] = ""


class RuleTestResult(BaseModel):
    hits: int
    sample: list[EventOut]
    tookMs: int
    error: Optional[str] = None


class ExclusionInput(BaseModel):
    """Body for POST/PUT /api/exclusions (id and timestamps are server-owned)."""
    name: str
    conditions: list[RuleCondition] = Field(default_factory=list)
    combinator: Literal["and", "or"] = "and"
    # Empty = EVERY rule. A non-empty list scopes the exclusion to those rule ids, which is the
    # difference between "this address is never interesting" and "this address is not interesting FOR
    # THIS ONE RULE" - and an analyst who means the second must never be given the first.
    ruleIds: list[str] = Field(default_factory=list)
    note: str = ""
    enabled: bool = True


class Exclusion(ExclusionInput):
    """A suppression: evidence that matches it does not get tagged by the rules it is scoped to.

    Exclusions are the one feature here that can HIDE evidence, so every part of the design points at
    making that visible: `suppressed` counts what it actually removed on the last detection pass,
    `appliesToGraph` says whether it can be evaluated against a graph node at all, and nothing is ever
    enabled by default. An exclusion never deletes an event - it only stops a rule claiming it.
    """
    id: str
    createdBy: Literal["user", "ai", "system"] = "user"
    createdAt: str = ""
    updatedAt: str = ""
    # Detections this exclusion suppressed on the last full pass. None = no pass has run since it
    # changed, which is NOT the same as zero and must not be rendered as it.
    suppressed: Optional[int] = None
    # Whether its conditions can be evaluated against an entity-graph node (which has a type and a
    # value, and no fields). False means graph findings are NOT filtered by it - stated, never guessed.
    appliesToGraph: bool = False
    error: Optional[str] = None
    # The read-only sentence describing what it suppresses, generated like a rule's trigger.
    logic: Optional[str] = None


class ExclusionSuggestion(BaseModel):
    """A ready-made exclusion Iris offers but never applies by itself.

    Shipping these ENABLED would silently hide evidence in a forensics tool, which is not a trade to
    make on the analyst's behalf - so they are offered, with the reason stated, and adding one is a
    deliberate click.
    """
    name: str
    why: str
    conditions: list[RuleCondition]
    combinator: Literal["and", "or"] = "or"
    ruleIds: list[str] = Field(default_factory=list)


class ExclusionsResponse(BaseModel):
    exclusions: list[Exclusion] = Field(default_factory=list)
    suggestions: list[ExclusionSuggestion] = Field(default_factory=list)
    # Total detections suppressed across every exclusion on the last pass - the headline number that
    # keeps a suppression list from becoming invisible.
    suppressed: int = 0


class RulePreviewResult(RuleTestResult):
    """A dry run of a whole rule definition (POST /api/rules/preview).

    Extends the regex test with the two derived things an author needs before saving: `trigger` is what
    the ENGINE will evaluate, in words, and `mechanism` is how it decides. Neither is the analyst's
    description, which matches nothing.
    """
    trigger: str = ""
    mechanism: str = ""


class GraphFindingOut(BaseModel):
    """One hit from a graph rule (app/graph_rules.py).

    It names an ENTITY, not an event, because that is what the finding is about: a fan-out is a property
    of the node. `citedEventIds` are real ids from that node's own events so the claim can be opened —
    the same rule every AI-written artefact in this app follows.
    """
    ruleId: str
    name: str
    sev: Severity
    nodeId: str
    nodeType: str
    nodeValue: str
    summary: str
    metric: int
    metricLabel: str
    related: list[str] = Field(default_factory=list)
    citedEventIds: list[str] = Field(default_factory=list)
    first: str = ""
    last: str = ""


class GraphFindings(BaseModel):
    findings: list[GraphFindingOut] = Field(default_factory=list)
    rules: int = 0                      # graph rules that were evaluated (enabled ones)
    # None while the graph is still building - NOT an empty list. "we have not looked" and "nothing
    # matched" are different answers and the screen says which.
    evaluated: bool = False
    status: Optional[dict] = None
    tookMs: int = 0


class AnomalyCase(BaseModel):
    """Where a rule's hits live: a CASE (the file was filed into it) or the case-less library.

    The pool holds the ACTIVE case's sources plus the library, so at most one real case appears —
    but with many cases on disk the analyst needs the row to SAY which one, rather than reading
    "hits in the active case" and guessing which case that was when the screenshot is looked at later.
    `caseId` is '' for library (unfiled) hits."""
    caseId: str
    caseName: str
    hits: int


class Anomaly(BaseModel):
    ruleId: str
    name: str
    sev: Severity
    hits: int
    firstSeen: Optional[str]
    lastSeen: Optional[str]
    sources: list[str]
    cases: list[AnomalyCase] = []
    sample: list[EventOut]
    kind: Literal["regex", "builtin", "conditions"]
