"""Case endpoints."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel

from ..models import Case
from ..store import STORE

router = APIRouter(prefix="/case", tags=["case"])


class CasePatch(BaseModel):
    name: Optional[str] = None
    analyst: Optional[str] = None


@router.get("", response_model=Case)
def get_case() -> Case:
    return STORE.case()


@router.patch("", response_model=Case)
def patch_case(body: CasePatch) -> Case:
    with STORE.lock:
        if body.name is not None:
            STORE.name = body.name.strip() or STORE.name
        if body.analyst is not None:
            STORE.analyst = body.analyst.strip() or STORE.analyst
        STORE._materialise()  # naming a pending case is what brings it into existence on disk
    STORE.save_meta()
    return STORE.case()


@router.post("/reset", response_model=Case)
def reset_case() -> Case:
    STORE.reset()
    return STORE.case()
