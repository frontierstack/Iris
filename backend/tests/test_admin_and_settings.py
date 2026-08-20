"""Tests for /api/admin/clear-all, /api/parsers, JSON-array parsing, mapping suggest, and settings migration."""
from __future__ import annotations

import io

import pytest
from fastapi.testclient import TestClient

from app import config
from app.main import app
from app.parsers.jsonl import JsonlParser


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


def test_parsers_endpoint(client):
    body = client.get("/api/parsers").json()
    names = {p["name"] for p in body["parsers"]}
    assert {"CSV (header)", "PDF (text)", "Excel workbook", "Word document (DOCX)", "Image (OCR)", "Binary strings"} <= names
    ocr = next(p for p in body["parsers"] if p["name"] == "Image (OCR)")
    assert "available" in ocr
    if not ocr["available"]:
        assert "note" in ocr and "tesseract" in ocr["note"].lower()
    for p in body["parsers"]:
        assert isinstance(p["extensions"], list) and p["family"] and p["description"]


def test_clear_all_endpoint(client):
    # upload something, then wipe
    csv = b"timestamp,host,message\n2026-08-11T03:14:47Z,web-1,hello\n2026-08-11T03:15:00Z,web-2,world\n"
    r = client.post("/api/sources", files={"files": ("audit.csv", csv, "text/csv")})
    assert r.status_code == 200
    assert client.get("/api/case").json()["eventCount"] > 0
    r = client.post("/api/admin/clear-all", json={})
    body = r.json()
    assert body["ok"] is True
    assert body["removed"]["sources"] >= 1
    assert body["removed"]["events"] >= 1
    assert "files" in body["removed"]
    case = client.get("/api/case").json()
    assert case["eventCount"] == 0 and case["sources"] == []
    from app.store import STORE
    assert not STORE.case_path.exists()


def test_clear_all_reset_settings(client):
    client.put("/api/settings", json={"analyst": "Temp Analyst"})
    assert client.get("/api/settings").json()["analyst"] == "Temp Analyst"
    client.post("/api/admin/clear-all", json={"resetSettings": True})
    assert client.get("/api/settings").json()["analyst"] == "Analyst"  # back to default


def test_json_array_of_objects():
    p = JsonlParser()
    arr = '[\n {"ts":"2026-08-11T03:27:15Z","msg":"a","host":"h1"},\n {"ts":"2026-08-11T03:27:16Z","msg":"b","host":"h2"}\n]'
    assert p.sniff(arr.splitlines()) > 0.6
    evs = list(p.parse(arr.splitlines()))
    assert [e.msg for e in evs] == ["a", "b"]
    assert evs[0].host == "h1"


def test_json_wrapped_records():
    p = JsonlParser()
    wrapped = '{"Records":[{"time":"2026-08-11T03:27:15Z","message":"x"},{"time":"2026-08-11T03:27:16Z","message":"y"}]}'
    evs = list(p.parse([wrapped]))
    assert [e.msg for e in evs] == ["x", "y"]


def test_settings_migration_anthropic(tmp_path, monkeypatch):
    # simulate an old persisted settings file with a dropped provider
    monkeypatch.setattr(config, "_settings", None)
    monkeypatch.setattr(config, "SETTINGS_PATH", tmp_path / "settings.json")
    (tmp_path / "settings.json").write_text(
        '{"theme":"paper","ai":{"provider":"anthropic","model":"claude-3-5-haiku-latest","apiKey":"sk-xyz","baseUrl":"https://api.anthropic.com"}}',
        encoding="utf-8")
    s = config.load_settings()
    assert s.ai.provider == "openai"
    assert s.ai.model == "gpt-4o-mini"  # anthropic model dropped -> default
    assert s.theme == "paper"


def test_settings_migration_compatible(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_settings", None)
    monkeypatch.setattr(config, "SETTINGS_PATH", tmp_path / "settings.json")
    (tmp_path / "settings.json").write_text(
        '{"ai":{"provider":"openai-compatible","model":"llama3.1","baseUrl":"http://localhost:11434/v1","apiKey":"k"}}',
        encoding="utf-8")
    s = config.load_settings()
    assert s.ai.provider == "openai"
    assert s.ai.baseUrl == "http://localhost:11434/v1"  # compatible endpoint preserved
    assert s.ai.model == "llama3.1"


def test_provider_enum_rejects_legacy_via_migration():
    from app.config import migrate_provider
    assert migrate_provider("anthropic") == "openai"
    assert migrate_provider("openai-compatible") == "openai"
    assert migrate_provider("openai") == "openai"
    assert migrate_provider("") == "none"
    assert migrate_provider("bogus") == "none"


def test_mapping_suggest_heuristic_fallback(client, monkeypatch):
    # AI disabled -> heuristic guess with source 'heuristic', HTTP 200
    monkeypatch.setattr(config, "_settings", None)
    pipe = b"2026-08-11T03:29:50Z|fw-edge-2|ALLOW|10.22.4.19:51993|45.83.140.22:8443|tcp|2297851\n" * 5
    r = client.post("/api/sources", files={"files": ("fw.pipe.log", pipe, "text/plain")})
    sid = r.json()[0]["id"]
    body = client.post(f"/api/sources/{sid}/mapping/suggest").json()
    assert body["source"] == "heuristic"
    assert isinstance(body["fields"], list) and body["fields"]
    assert "confidence" in body and "rationale" in body
    client.delete(f"/api/sources/{sid}")


def test_mapping_suggest_ai_mocked(client, monkeypatch):
    import app.ai.mapping as mapping

    async def fake_json(self, system, user, max_tokens=800, temperature=0.0):
        return {"delimiter": "|", "confidence": 0.91, "rationale": "clear firewall columns",
                "fields": ["timestamp", "host", "action", "src_ip", "dst_ip", "proto", "bytes"]}

    monkeypatch.setattr(mapping.LLMClient, "complete_json", fake_json)
    monkeypatch.setattr(mapping.LLMClient, "configured", property(lambda self: True))

    pipe = b"2026-08-11T03:29:50Z|fw-edge-2|ALLOW|10.22.4.19:51993|45.83.140.22:8443|tcp|2297851\n" * 5
    r = client.post("/api/sources", files={"files": ("fw2.pipe.log", pipe, "text/plain")})
    sid = r.json()[0]["id"]
    body = client.post(f"/api/sources/{sid}/mapping/suggest").json()
    assert body["source"] == "ai"
    assert body["fields"][0] == "timestamp" and "src_ip" in body["fields"]
    assert body["delimiter"] == "|"
    assert body["confidence"] == 0.91
    client.delete(f"/api/sources/{sid}")
