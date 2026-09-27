"""Settings endpoints (apiKey masked on read)."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, HTTPException
from pydantic import ValidationError

from ..config import SettingsError, public_settings, update_settings

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("")
def get_settings_route() -> dict[str, Any]:
    return public_settings()


@router.put("")
def put_settings(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    try:
        return update_settings(body)
    except SettingsError as exc:
        # 400, not 500: the value is the problem and the message names the fix. Nothing is written —
        # validate_base_url runs before the merged dict reaches the file.
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValidationError as exc:
        # A value of the wrong type is the caller's mistake, not a server fault: 400 with the field
        # named, never a 500. Nothing was written.
        errs = "; ".join(f"{'.'.join(str(x) for x in e.get('loc', ()))}: {e.get('msg')}" for e in exc.errors()[:5])
        raise HTTPException(status_code=400, detail=f"invalid setting — {errs}") from exc
