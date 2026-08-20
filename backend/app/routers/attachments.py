"""Case-note attachments: images referenced from note markdown.

Stored at $IRIS_DATA_DIR/cases/<id>/attachments/ — inside the case directory, so cases.delete_case()
(shutil.rmtree of the case dir) removes them with the case. The client filename is never used as a path:
the stored name is generated (`att-<16 hex>.<ext>`) and the declared content type must agree with the
file's magic bytes. SVG is deliberately not accepted — it can carry script.
"""
from __future__ import annotations

import asyncio

import re
import secrets
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .. import cases, config
from ..store import STORE

router = APIRouter(prefix="/cases", tags=["cases"])

MAX_BYTES = 10 * 1024 * 1024
_CHUNK = 256 * 1024
# content type -> (stored extension, accepted magic prefixes)
ALLOWED: dict[str, tuple[str, tuple[bytes, ...]]] = {
    "image/png": (".png", (b"\x89PNG\r\n\x1a\n",)),
    "image/jpeg": (".jpg", (b"\xff\xd8\xff",)),
    "image/gif": (".gif", (b"GIF87a", b"GIF89a")),
    "image/webp": (".webp", (b"RIFF",)),
    "image/bmp": (".bmp", (b"BM",)),
}
_ALIASES = {"image/jpg": "image/jpeg", "image/pjpeg": "image/jpeg", "image/x-png": "image/png",
            "image/x-ms-bmp": "image/bmp"}
_STORED_NAME = re.compile(r"^att-[0-9a-f]{32}\.(?:png|jpg|gif|webp|bmp)$")
_EXT_TYPE = {v[0]: k for k, v in ALLOWED.items()}


class Attachment(BaseModel):
    id: str            # the generated on-disk name
    name: str          # sanitized display name (alt text) — never used as a path
    url: str           # /api/cases/<id>/attachments/<id>
    contentType: str
    size: int


def _dir_for(case_id: str) -> Path:
    if case_id != STORE.case_id and case_id not in cases.case_ids():
        raise HTTPException(404, "case not found")
    d = config.attachment_dir(case_id)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _materialise(case_id: str) -> None:
    """Attaching an image is a real write, so it must promote a PENDING case to a real one.

    Without this the pending id accepted the upload (it is STORE.case_id) but the note that references
    the image could not be saved: cases.add_note treats a pending id as "case not found" and 404s, so
    the analyst uploaded a screenshot and ended up with no note and no image anywhere. See the pending
    rules in CLAUDE.md — any genuine write materialises the case.
    """
    if case_id == STORE.case_id and STORE.pending:
        with STORE.lock:
            STORE._materialise()
        STORE.save_meta()


def _display_name(raw: str, fallback: str) -> str:
    """Client filename reduced to something safe to drop into markdown alt text."""
    base = Path(raw or "").name
    base = re.sub(r"[^A-Za-z0-9 ._-]", "", base).strip()
    return base[:120] or fallback


@router.post("/{case_id}/attachments", response_model=Attachment)
async def upload_attachment(case_id: str, file: UploadFile = File(...)) -> Attachment:
    if case_id != STORE.case_id and case_id not in cases.case_ids():
        raise HTTPException(404, "case not found")   # checked before any directory is created
    ctype = (file.content_type or "").split(";")[0].strip().lower()
    ctype = _ALIASES.get(ctype, ctype)
    spec = ALLOWED.get(ctype)
    if spec is None:
        raise HTTPException(415, "only PNG, JPEG, GIF, WEBP or BMP images can be attached")
    ext, magics = spec
    buf = bytearray()
    while True:
        chunk = await file.read(_CHUNK)
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) > MAX_BYTES:
            raise HTTPException(413, f"attachment is larger than {MAX_BYTES // (1024 * 1024)} MB")
    data = bytes(buf)
    if not data:
        raise HTTPException(400, "empty upload")
    if not any(data[:16].startswith(m) for m in magics):
        raise HTTPException(415, "file content is not a valid image of that type")
    _materialise(case_id)   # only once the bytes are known-good, so a rejected upload creates nothing
    d = _dir_for(case_id)
    name = f"att-{secrets.token_hex(16)}{ext}"
    await asyncio.to_thread((d / name).write_bytes, data)   # bind-mount writes are slow; never on the loop
    return Attachment(id=name, name=_display_name(file.filename or "", "screenshot"),
                      url=f"/api/cases/{quote(case_id)}/attachments/{name}", contentType=ctype, size=len(data))


@router.get("/{case_id}/attachments/{name}")
def get_attachment(case_id: str, name: str) -> FileResponse:
    if not _STORED_NAME.match(name):
        raise HTTPException(404, "attachment not found")
    d = _dir_for(case_id)
    path = d / name
    try:
        inside = path.resolve().parent == d.resolve()
    except OSError:
        inside = False
    if not inside or not path.is_file():
        raise HTTPException(404, "attachment not found")
    return FileResponse(str(path), media_type=_EXT_TYPE.get(path.suffix, "application/octet-stream"),
                        headers={"Cache-Control": "private, max-age=86400", "X-Content-Type-Options": "nosniff",
                                 "Content-Security-Policy": "default-src 'none'; sandbox"})
