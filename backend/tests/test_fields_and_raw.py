"""GET /api/events/fields (search facets) and GET /api/sources/{sid}/raw + /download (raw log viewer)."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from tests.conftest import load_sample_case

FIX = Path(__file__).resolve().parent / "fixtures" / "sample_case"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        load_sample_case(c)
        yield c


def _source_id(client, name: str) -> str:
    case = client.get("/api/case").json()
    return next(s["id"] for s in case["sources"] if s["file"] == name)


# ----------------------------------------------------------------------------- fields
def test_fields_shape_and_order(client):
    r = client.get("/api/events/fields")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] >= len(body["fields"]) > 0
    assert body["sampled"] is False  # the sample case is far below the 20k scan cap
    counts = [f["count"] for f in body["fields"]]
    assert counts == sorted(counts, reverse=True)
    names = {f["name"] for f in body["fields"]}
    for fixed in ("source", "file", "sev"):
        assert fixed in names
    for f in body["fields"]:
        assert set(f) >= {"name", "count", "sample", "topValues"}
        assert len(f["sample"]) <= 5 and len(f["topValues"]) <= 8
        assert all(set(tv) == {"value", "count"} for tv in f["topValues"])
    # every event carries sev — its count is the whole result set
    sev = next(f for f in body["fields"] if f["name"] == "sev")
    assert sev["count"] == body["events"] == client.get("/api/events?limit=1").json()["total"]


def test_fields_counts_match_field_search(client):
    body = client.get("/api/events/fields?limit=200").json()
    fields = {f["name"]: f for f in body["fields"]}
    # sev is an exact enum match in the DSL, so each top value must equal the events search total
    for tv in fields["sev"]["topValues"]:
        total = client.get("/api/events", params={"q": f"sev:{tv['value']}", "limit": 1}).json()["total"]
        assert total == tv["count"], tv
    # a parser field: `name:*` matches every event that carries the field, whatever its value
    custom = [f for f in body["fields"] if f["name"] not in ("host", "user", "source", "file", "sev")]
    assert custom, "sample case has parser fields"
    for f in custom[:5]:
        total = client.get("/api/events", params={"q": f"{f['name']}:*", "limit": 1}).json()["total"]
        assert total == f["count"], f["name"]
    # and a concrete field:value search returns at least the facet count (substring matching may add more)
    f = custom[0]
    tv = f["topValues"][0]
    val = tv["value"]
    quoted = f'"{val}"' if (" " in val or ":" in val) else val
    total = client.get("/api/events", params={"q": f"{f['name']}:{quoted}", "limit": 1}).json()["total"]
    assert total >= tv["count"]


def test_fields_respect_filters(client):
    fw = _source_id(client, "fw-edge-2.pipe.log")
    body = client.get("/api/events/fields", params={"sources": fw}).json()
    assert body["events"] == client.get("/api/events", params={"sources": fw, "limit": 1}).json()["total"]
    files = next(f for f in body["fields"] if f["name"] == "file")
    assert [tv["value"] for tv in files["topValues"]] == ["fw-edge-2.pipe.log"]
    # a query narrows the facets the same way it narrows the results
    narrowed = client.get("/api/events/fields", params={"q": "sev:critical"}).json()
    assert narrowed["events"] == client.get("/api/events?q=sev:critical&limit=1").json()["total"]
    sev = next(f for f in narrowed["fields"] if f["name"] == "sev")
    assert [tv["value"] for tv in sev["topValues"]] == ["critical"]
    # limit caps the list but not the total
    small = client.get("/api/events/fields?limit=3").json()
    full = client.get("/api/events/fields?limit=500").json()
    assert len(small["fields"]) == 3
    assert small["total"] == full["total"] == len(full["fields"])


# ----------------------------------------------------------------------------- raw
def test_raw_pages_and_numbers_lines(client):
    sid = _source_id(client, "fw-edge-2.pipe.log")
    raw_lines = (FIX / "fw-edge-2.pipe.log").read_text(encoding="utf-8").splitlines()
    r = client.get(f"/api/sources/{sid}/raw", params={"offset": 0, "limit": 10})
    assert r.status_code == 200
    body = r.json()
    assert body["binary"] is False
    assert body["file"] == "fw-edge-2.pipe.log"
    assert body["totalLines"] == len(raw_lines)
    assert body["offset"] == 0
    assert [l["n"] for l in body["lines"]] == list(range(1, 11))
    assert [l["text"] for l in body["lines"]] == raw_lines[:10]
    assert body["truncatedLine"] is False
    # second page continues where the first left off, and the last page is short
    p2 = client.get(f"/api/sources/{sid}/raw", params={"offset": 10, "limit": 10}).json()
    assert [l["n"] for l in p2["lines"]] == list(range(11, 21))
    tail = client.get(f"/api/sources/{sid}/raw", params={"offset": len(raw_lines) - 3, "limit": 10}).json()
    assert [l["n"] for l in tail["lines"]] == [len(raw_lines) - 2, len(raw_lines) - 1, len(raw_lines)]
    assert tail["totalLines"] == len(raw_lines)


def test_raw_q_filters_case_insensitively_and_pages_matches(client):
    sid = _source_id(client, "fw-edge-2.pipe.log")
    raw_lines = (FIX / "fw-edge-2.pipe.log").read_text(encoding="utf-8").splitlines()
    expect = [(i + 1, t) for i, t in enumerate(raw_lines) if "deny" in t.lower()]
    assert expect
    body = client.get(f"/api/sources/{sid}/raw", params={"q": "DeNy", "limit": 5}).json()
    assert body["matches"] == len(expect)
    assert body["totalLines"] == len(raw_lines)
    assert [(l["n"], l["text"]) for l in body["lines"]] == expect[:5]
    p2 = client.get(f"/api/sources/{sid}/raw", params={"q": "DeNy", "limit": 5, "offset": 5}).json()
    assert [(l["n"], l["text"]) for l in p2["lines"]] == expect[5:10]
    none = client.get(f"/api/sources/{sid}/raw", params={"q": "definitely-not-in-this-file"}).json()
    assert none["matches"] == 0 and none["lines"] == []


def test_raw_limit_cap_and_truncation(client):
    sid = _source_id(client, "fw-edge-2.pipe.log")
    assert client.get(f"/api/sources/{sid}/raw", params={"limit": 5000}).status_code == 422
    assert client.get(f"/api/sources/{sid}/raw", params={"limit": 0}).status_code == 422
    # a file with one very long line is cut at 2000 chars and flagged
    long_line = "x" * 5000
    files = [("files", ("long.log", (f"short line\n{long_line}\nlast\n").encode(), "application/octet-stream"))]
    r = client.post("/api/sources", files=files)
    assert r.status_code == 200
    lid = r.json()[0]["id"]
    body = client.get(f"/api/sources/{lid}/raw").json()
    assert body["totalLines"] == 3
    assert body["truncatedLine"] is True
    assert len(body["lines"][1]["text"]) == 2000
    assert body["lines"][2]["text"] == "last"
    client.delete(f"/api/sources/{lid}")


def test_raw_flags_binary(client):
    payload = b"MDMP" + b"\x00" * 64 + b"garbage" + b"\x00" * 64
    files = [("files", ("mem.dmp", payload, "application/octet-stream"))]
    r = client.post("/api/sources", files=files)
    assert r.status_code == 200
    bid = r.json()[0]["id"]
    body = client.get(f"/api/sources/{bid}/raw").json()
    assert body["binary"] is True
    assert body["lines"] == []
    assert body["hint"]
    # download still hands over the original bytes
    d = client.get(f"/api/sources/{bid}/download")
    assert d.status_code == 200
    assert d.content == payload
    client.delete(f"/api/sources/{bid}")


def test_download_sets_content_disposition(client):
    sid = _source_id(client, "fw-edge-2.pipe.log")
    r = client.get(f"/api/sources/{sid}/download")
    assert r.status_code == 200
    cd = r.headers.get("content-disposition", "")
    assert cd.startswith("attachment")
    assert "fw-edge-2.pipe.log" in cd
    assert r.content == (FIX / "fw-edge-2.pipe.log").read_bytes()
    assert client.get("/api/sources/nope/download").status_code == 404
    assert client.get("/api/sources/nope/raw").status_code == 404
