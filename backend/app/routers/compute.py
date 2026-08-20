"""Compute status endpoints."""
from __future__ import annotations

from fastapi import APIRouter
from starlette.concurrency import run_in_threadpool

from .. import compute, metrics
from ..models import ComputeStatus

router = APIRouter(prefix="/compute", tags=["compute"])


@router.get("", response_model=ComputeStatus)
def get_status() -> ComputeStatus:
    return compute.status()


@router.post("/recheck", response_model=ComputeStatus)
async def recheck() -> ComputeStatus:
    return await run_in_threadpool(compute.probe)


@router.get("/metrics")
def get_metrics(window: int = 300) -> dict:
    """Ring-buffer of live GPU / process / throughput samples (2 s interval) for the performance graphs."""
    return metrics.history(window)
