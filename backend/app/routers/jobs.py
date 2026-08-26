"""Upload / parse job endpoints — server-side progress that survives a refresh.

Transport is POLLING, not SSE, deliberately: the states here are coarse (five of them) and the only
high-frequency number, bytes-in-flight, is produced by the uploading browser itself and pushed in with
PATCH. A stream would have to poll the parse threads internally anyway (they have no event loop to
publish from), and the Sources screen already polls /api/case for source states. See docs/API_CONTRACT.md.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from ..jobs import REGISTRY
from ..store import STORE

router = APIRouter(prefix="/jobs", tags=["jobs"])


class JobDecl(BaseModel):
    file: str
    size: int = 0


class JobCreate(BaseModel):
    files: list[JobDecl]
    target: str = "case"           # 'case' | 'library'


class JobProgress(BaseModel):
    received: int


class JobHeartbeat(BaseModel):
    ids: list[str] = []


@router.get("")
def list_jobs(limit: int = Query(100, ge=1, le=500)) -> dict:
    """Active + recent jobs, newest first. Reading also reconciles threaded parses (jobs.sync)."""
    return REGISTRY.snapshot(limit)


@router.post("")
def create_jobs(body: JobCreate) -> dict:
    """Register uploads BEFORE the bytes move, so another tab sees them from the first byte.

    Creating a job never touches the store and never materialises a case — it is bookkeeping only.

    ONE call for the whole drop, never `create()` per file: each of those rewrites the entire registry,
    so declaring the analyst's real 680-file drop cost 680 rewrites of a 680-row file under the registry
    lock — 9.0 s measured, before a byte had moved, in front of the request that exists to make the drop
    visible immediately. See `JobRegistry.create_many`.
    """
    if not body.files:
        raise HTTPException(400, "no files declared")
    target = "library" if body.target == "library" else "case"
    case_id = "" if (target == "library" or STORE.pending) else STORE.case_id
    jobs = REGISTRY.create_many(((f.file, f.size) for f in body.files), target, case_id)
    return {"jobs": [j.live() for j in jobs]}


@router.patch("/{job_id}")
def patch_job(job_id: str, body: JobProgress) -> dict:
    job = REGISTRY.progress(job_id, body.received)
    if job is None:
        raise HTTPException(404, "job not found")
    return job.live()


@router.post("/heartbeat")
def heartbeat(body: JobHeartbeat) -> dict:
    """"These transfers are still mine" — from the tab that holds the files.

    A drop of twelve files registers twelve jobs and then sends three at a time, so the rest sit in
    `queued` with nothing arriving for them. The server cannot tell that apart from a closed tab, and the
    watchdog used to call it dead at exactly ten minutes: a whole drop of packet captures came back as
    "the upload stopped before the server received the whole file" without one of them having been given
    a turn. The sending tab is the only party that knows, so it reports in every 20 s until its queue
    drains, and a job the watchdog already buried is revived here.
    """
    if not body.ids:
        return {"alive": [], "revived": []}
    # EVERY id, never a prefix. This used to take `body.ids[:500]`, silently: on a drop of more than
    # 500 files the tab reported all of them and the server touched the first 500, so ten minutes
    # in the watchdog buried file #501 onward as "the tab that queued it is gone" while that tab was
    # still working down the queue. The client chunks its request; the bound here is only sanity.
    if len(body.ids) > 20_000:
        raise HTTPException(413, "too many job ids in one heartbeat (send them in batches)")
    alive, revived = REGISTRY.heartbeat(body.ids)
    return {"alive": alive, "revived": revived}


@router.post("/clear")
def clear_jobs() -> dict:
    """Drop every finished job. Running ones are left alone."""
    return {"ok": True, "cleared": REGISTRY.clear_finished()}


def resolve_job(job_id: Optional[str], file: str, size: int, target: str, case_id: str) -> str:
    """The job id an ingest endpoint should report against.

    A client that pre-registered passes its id; anything else (curl, a test, an older tab) still gets a
    job created here, so the registry is never blind to work that is actually happening.
    """
    if job_id:
        existing = REGISTRY.get(job_id)
        if existing is not None:
            return existing.id
    return REGISTRY.create(file, size, target, case_id).id
