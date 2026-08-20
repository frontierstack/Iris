"""Images in case notes, end to end: upload → markdown reference → serve the bytes back.

The regression this file locks down: an attachment could be uploaded against a PENDING case id
(it is STORE.case_id, so the upload endpoint accepted it) but the note referencing it could not be
saved — cases.add_note treats a pending id as "case not found" and 404s. The analyst pasted a
screenshot and ended up with neither a note nor an image. Uploading an attachment is a real write,
so it now materialises the case like every other write does.
"""
from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from app import cases, config
from app.main import app
from app.store import STORE

# 1x1 transparent PNG / minimal GIF
PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)
GIF = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")


@pytest.fixture()
def client():
    with TestClient(app) as c:
        c.post("/api/case/reset")
        yield c


def test_note_image_round_trip(client):
    """Upload an image, reference it from a note, read the note back and fetch the bytes."""
    cid = client.post("/api/cases", json={"name": "Screenshots"}).json()["id"]

    up = client.post(f"/api/cases/{cid}/attachments", files={"file": ("screen shot(1).png", PNG, "image/png")})
    assert up.status_code == 200, up.text
    att = up.json()
    # the alt text the UI writes into the markdown must not contain [] () - they would break the link
    assert not set("[]()") & set(att["name"])
    assert att["url"] == f"/api/cases/{cid}/attachments/{att['id']}"

    md = f"Evidence:\n\n![{att['name']}]({att['url']})"
    note = client.post(f"/api/cases/{cid}/notes", json={"text": md})
    assert note.status_code == 200, note.text

    # persisted verbatim - the markdown must survive the round trip untouched
    back = client.get(f"/api/cases/{cid}/notes").json()
    assert back[-1]["text"] == md
    assert client.get(f"/api/cases/{cid}").json()["notes"][-1]["text"] == md

    # and the URL in that markdown really serves the image
    got = client.get(att["url"])
    assert got.status_code == 200
    assert got.content == PNG
    assert got.headers["content-type"] == "image/png"


def test_attaching_materialises_a_pending_case(client):
    """A pasted screenshot on a pending case must produce a real case, not a 404 on the note."""
    # delete everything so the store holds a reserved-but-unwritten id
    for c in client.get("/api/cases").json():
        client.delete(f"/api/cases/{c['id']}")
    assert client.get("/api/cases").json() == []
    assert STORE.pending is True
    cid = STORE.case_id

    att = client.post(f"/api/cases/{cid}/attachments", files={"file": ("shot.gif", GIF, "image/gif")})
    assert att.status_code == 200, att.text
    assert STORE.pending is False and cid in cases.case_ids()
    assert config.case_path(cid).is_file()

    note = client.post(f"/api/cases/{cid}/notes", json={"text": f"![shot.gif]({att.json()['url']})"})
    assert note.status_code == 200, note.text
    assert client.get(att.json()["url"]).status_code == 200


def test_rejected_upload_does_not_create_the_case(client):
    """A 415 must leave a pending case exactly as it was - no half-created case directory."""
    for c in client.get("/api/cases").json():
        client.delete(f"/api/cases/{c['id']}")
    cid = STORE.case_id
    assert STORE.pending is True

    r = client.post(f"/api/cases/{cid}/attachments", files={"file": ("notes.txt", b"hello", "text/plain")})
    assert r.status_code == 415
    assert STORE.pending is True
    assert cases.case_ids() == [] and not config.case_dir(cid).exists()
