"""Note attachments: image-only uploads, size cap, and no path escape from the case directory."""
from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from app import config
from app.main import app
from app.routers import attachments
from app.store import STORE

# 1x1 transparent PNG
PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)


@pytest.fixture()
def client():
    with TestClient(app) as c:
        c.post("/api/case/reset")
        yield c


def _case_id(c: TestClient) -> str:
    return str(c.get("/api/case").json()["id"])


def test_upload_png_and_fetch_back(client):
    cid = _case_id(client)
    r = client.post(f"/api/cases/{cid}/attachments", files={"file": ("shot.png", PNG, "image/png")})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["contentType"] == "image/png" and body["size"] == len(PNG)
    assert body["url"] == f"/api/cases/{cid}/attachments/{body['id']}"
    stored = config.attachment_dir(cid) / body["id"]
    assert stored.is_file() and stored.read_bytes() == PNG
    # inside the case dir, so deleting the case removes it too
    assert stored.resolve().is_relative_to(config.case_dir(cid).resolve())

    got = client.get(body["url"])
    assert got.status_code == 200 and got.content == PNG
    assert got.headers["content-type"].startswith("image/png")

    # and it can be referenced from a note as markdown
    n = client.post(f"/api/cases/{cid}/notes", json={"text": f"**boom**\n\n![{body['name']}]({body['url']})"})
    assert n.status_code == 200 and body["url"] in n.json()["text"]


def test_rejects_non_image_content_type(client):
    cid = _case_id(client)
    r = client.post(f"/api/cases/{cid}/attachments", files={"file": ("notes.txt", b"hello", "text/plain")})
    assert r.status_code == 415
    # and a lying content type is caught by the magic-byte check
    r2 = client.post(f"/api/cases/{cid}/attachments", files={"file": ("evil.png", b"<svg onload=alert(1)>", "image/png")})
    assert r2.status_code == 415


def test_rejects_oversize(client, monkeypatch):
    cid = _case_id(client)
    monkeypatch.setattr(attachments, "MAX_BYTES", 512)
    r = client.post(f"/api/cases/{cid}/attachments", files={"file": ("big.png", PNG + b"\x00" * 1024, "image/png")})
    assert r.status_code == 413


def test_client_filename_cannot_escape_the_case_dir(client):
    cid = _case_id(client)
    hostile = "../../../../pwned.png"
    r = client.post(f"/api/cases/{cid}/attachments", files={"file": (hostile, PNG, "image/png")})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "/" not in body["id"] and ".." not in body["id"] and body["id"].startswith("att-")
    stored = (config.attachment_dir(cid) / body["id"]).resolve()
    assert stored.is_relative_to(config.attachment_dir(cid).resolve()) and stored.is_file()
    assert not (config.DATA_DIR / "pwned.png").exists()
    # the display name is sanitized down to the basename, never a path
    assert "/" not in body["name"] and ".." not in body["name"]

    # only generated names are servable — anything else 404s before touching the filesystem
    assert client.get(f"/api/cases/{cid}/attachments/case.json").status_code == 404
    assert client.get(f"/api/cases/{cid}/attachments/att-00.png").status_code == 404


def test_deleting_the_case_removes_its_attachments(client):
    made = client.post("/api/cases", json={"name": "Attachment case"}).json()
    cid = made["id"]
    body = client.post(f"/api/cases/{cid}/attachments", files={"file": ("s.png", PNG, "image/png")}).json()
    stored = config.attachment_dir(cid) / body["id"]
    assert stored.is_file()
    assert client.delete(f"/api/cases/{cid}").status_code == 200
    assert not stored.exists() and not config.case_dir(cid).exists()
    assert STORE.case_id != cid


def test_unknown_case_404s(client):
    r = client.post("/api/cases/CASE-9999/attachments", files={"file": ("s.png", PNG, "image/png")})
    assert r.status_code == 404
