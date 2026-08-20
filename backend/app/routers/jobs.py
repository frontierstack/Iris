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


@router.get("")
def list_jobs(limit: int = Query(100, ge=1, le=500)) -> dict:
    """Active + recent jobs, newest first. Reading also reconciles threaded parses (jobs.sync)."""
    return REGISTRY.snapshot(limit)


@router.post("")
def create_jobs(body: JobCreate) -> dict:
    """Register uploads BEFORE the bytes move, so another tab sees them from the first byte.

    Creating a job never touches the store and never materialises a case — it is bookkeeping only.
    """
    if not body.files:
        raise HTTPException(400, "no files declared")
    target = "library" if body.target == "library" else "case"
    case_id = "" if (target == "library" or STORE.pending) else STORE.case_id
    jobs = [REGISTRY.create(f.file, f.size, target, case_id) for f in body.files]
    return {"jobs": [j.live() for j in jobs]}


@router.patch("/{job_id}")
def patch_job(job_id: str, body: JobProgress) -> dict:
    job = REGISTRY.progress(job_id, body.received)
    if job is None:
        raise HTTPException(404, "job not found")
    return job.live()


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
