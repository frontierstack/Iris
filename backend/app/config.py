"""Settings persistence (JSON at $IRIS_DATA_DIR/settings.json) with env overrides."""
from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path
from typing import Any

from .models import Settings

VERSION = "0.1.0"

DATA_DIR = Path(os.environ.get("IRIS_DATA_DIR", "./data")).resolve()
SETTINGS_PATH = DATA_DIR / "settings.json"
CASES_DIR = DATA_DIR / "cases"                 # cases/<CASE-0001>/{case.json, uploads/}
CASES_INDEX = CASES_DIR / "index.json"         # {"active": "CASE-0001"}
RULES_PATH = DATA_DIR / "rules.json"           # custom detection rules (global, all cases)
# legacy single-case layout (migrated into cases/CASE-0001 on first start)
LEGACY_UPLOAD_DIR = DATA_DIR / "uploads"
LEGACY_CASE_PATH = DATA_DIR / "case.json"


# Deleted cases are MOVED here, not destroyed. A case folder holds the only copy of its uploads, so an
# rmtree was unrecoverable - one stray call (a misclick, a script pointed at the wrong data dir, a bug)
# took the evidence with it. Trashed cases are restorable and are pruned oldest-first past TRASH_KEEP.
TRASH_DIR = DATA_DIR / ".trash"
TRASH_KEEP = 5

# Unattached uploads: logs that belong to no case yet. Deliberately a SIBLING of CASES_DIR, never
# inside it — case_ids() only scans CASES_DIR for CASE-\d{4,} folders and delete_case rmtree's a whole
# case folder, so anything staged under a case would be invisible here and destroyed by a delete.
LIBRARY_DIR = DATA_DIR / "library"
# Derived-from-evidence caches (the persisted entity graph, the parsed-pool cache). Deletable at any
# time; `clear-all` wipes the tree, because a cache built from the evidence quotes the evidence.
CACHE_DIR = DATA_DIR / "cache"
LIBRARY_INDEX = LIBRARY_DIR / "index.json"


# A case id is this shape and nothing else. The check lives HERE, at the four functions that turn an id
# into a filesystem path, rather than only in the callers — because a caller that validates one
# statement too late is exactly the bug that was found: `GET /api/cases/{id}` called summary() (which
# reads case.json and iterates uploads/) BEFORE its `case_id not in case_ids()` guard. uvicorn unquotes
# the path before routing, so `%5C` survives as a literal backslash, and on Windows
# `CASES_DIR / "..\\..\\Users\\Tay"` escapes the data dir, `CASES_DIR / "C:\\Windows"` replaces it
# outright, and `CASES_DIR / "\\\\host\\share"` makes Windows open an outbound SMB connection and
# authenticate — an NTLM hash leak from an unauthenticated GET. Guarding the sink closes all of it, and
# closes it for the next caller too.
CASE_ID_RE = re.compile(r"^CASE-(\d{4,})$")


def _checked(case_id: str) -> str:
    if not CASE_ID_RE.match(str(case_id or "")):
        # KeyError, not ValueError: every case route already maps KeyError to 404 ("case not found"),
        # which is also the honest answer — no such case can exist under that name.
        raise KeyError(case_id)
    return case_id


def case_dir(case_id: str) -> Path:
    return CASES_DIR / _checked(case_id)


def upload_dir(case_id: str) -> Path:
    return CASES_DIR / _checked(case_id) / "uploads"


def attachment_dir(case_id: str) -> Path:
    """Note attachments (images) — inside the case dir so deleting the case takes them with it."""
    return CASES_DIR / _checked(case_id) / "attachments"


def case_path(case_id: str) -> Path:
    return CASES_DIR / _checked(case_id) / "case.json"

_lock = threading.Lock()
_settings: Settings | None = None


def _ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CASES_DIR.mkdir(parents=True, exist_ok=True)


def _apply_env(s: Settings) -> Settings:
    """Seed settings from IRIS_* env vars. Only used when no settings.json exists yet (first run) — after
    that the file is the source of truth, otherwise env defaults from docker-compose/.env would silently
    overwrite what the user saved in the UI on every restart. Set IRIS_ENV_OVERRIDES=1 to force env to win."""
    key = os.environ.get("IRIS_AI_API_KEY")
    if key:
        s.ai.apiKey = key
    prov = os.environ.get("IRIS_AI_PROVIDER")
    if prov:
        prov = migrate_provider(prov)
        if prov in ("none", "openai"):
            s.ai.provider = prov  # type: ignore[assignment]
    model = os.environ.get("IRIS_AI_MODEL")
    if model:
        s.ai.model = model
    base = os.environ.get("IRIS_AI_BASE_URL")
    if base:
        s.ai.baseUrl = base
    mode = os.environ.get("IRIS_COMPUTE_MODE")
    if mode in ("auto", "cuda", "cpu"):
        s.compute.mode = mode  # type: ignore[assignment]
    mcp_on = os.environ.get("IRIS_MCP_ENABLED")
    if mcp_on:
        s.mcp.enabled = mcp_on.strip().lower() in ("1", "true", "yes", "on")
    mcp_w = os.environ.get("IRIS_MCP_ALLOW_WRITES")
    if mcp_w:
        s.mcp.allowWrites = mcp_w.strip().lower() in ("1", "true", "yes", "on")
    mcp_tok = os.environ.get("IRIS_MCP_TOKEN")
    if mcp_tok:
        s.mcp.token = mcp_tok
    auto = os.environ.get("IRIS_AUTO_ENRICH")
    if auto:
        # phase 2 of the ingest (app/enrich.py). Off = raw lines only, until the analyst asks per source.
        s.ingest.autoEnrich = auto.strip().lower() in ("1", "true", "yes", "on")
    return s


_LEGACY_PROVIDERS = {"anthropic": "openai", "openai-compatible": "openai", "openai_compatible": "openai", "compatible": "openai",
                     "azure": "openai", "ollama": "openai", "": "none"}


def migrate_provider(value: object) -> str:
    """Older builds persisted 'anthropic' / 'openai-compatible'; the only remote provider now is 'openai'
    (any OpenAI-compatible endpoint is reached through baseUrl)."""
    v = str(value or "").strip().lower()
    if v in ("none", "openai"):
        return v
    return _LEGACY_PROVIDERS.get(v, "none")


def migrate_settings_dict(data: dict[str, Any]) -> dict[str, Any]:
    ai = data.get("ai")
    if isinstance(ai, dict):
        old = str(ai.get("provider", "none") or "none")
        new = migrate_provider(old)
        if old.lower() == "anthropic":
            # Anthropic models/keys don't work against the OpenAI API: drop the model, keep the key masked out
            ai["model"] = ""
            ai["baseUrl"] = ""
        ai["provider"] = new
        if not ai.get("model"):
            ai["model"] = "gpt-4o-mini"
    return data


def load_settings() -> Settings:
    global _settings
    with _lock:
        if _settings is not None:
            return _settings
        _ensure_dirs()
        s = Settings()
        have_file = SETTINGS_PATH.exists()
        if have_file:
            try:
                data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
                s = Settings.model_validate(migrate_settings_dict(data))
            except Exception:
                s = Settings()
        force_env = os.environ.get("IRIS_ENV_OVERRIDES", "").lower() in ("1", "true", "yes")
        if not have_file or force_env:
            s = _apply_env(s)
        _settings = s
        if not have_file:
            try:  # materialize the file so the volume always carries the effective settings
                SETTINGS_PATH.write_text(json.dumps(s.model_dump(), indent=2), encoding="utf-8")
            except OSError:
                pass
        return _settings


def reset_settings() -> Settings:
    """Delete settings.json and reload defaults (env overrides still apply)."""
    global _settings
    with _lock:
        try:
            SETTINGS_PATH.unlink(missing_ok=True)
        except OSError:
            pass
        _settings = None
    return load_settings()


def get_settings() -> Settings:
    return load_settings()


def mask_key(key: str) -> str:
    if not key:
        return ""
    return "••••" + key[-4:]


def is_masked(value: str) -> bool:
    return value.startswith("••••") or value.startswith("****")


def public_settings() -> dict[str, Any]:
    s = get_settings()
    d = s.model_dump()
    d["ai"]["apiKey"] = mask_key(s.ai.apiKey)
    # The MCP token is a credential that grants tool access to the whole pool — masked exactly like the
    # API key, and PUT ignores a masked value so a round-trip of the settings form cannot erase it.
    d["mcp"]["token"] = mask_key(s.mcp.token)
    # Read-only posture, never persisted and ignored on PUT. It exists because the dangerous states here
    # are INVISIBLE ones: "no authentication", "MCP enabled but refusing", "TLS verification off for the
    # host every log excerpt is sent to". Each of those was found by a red team, not by the screen that
    # configures it. See app/security.py.
    from . import security
    d["security"] = security.security_posture()
    return d


class SettingsError(ValueError):
    """A rejected settings value. The router turns it into a 400 naming the field and the fix."""


# `https://host:3001/v1` is fine. A QUERY STRING is not, and that is not pedantry: ai/client.py appends
# `/chat/completions` to this value, so `http://127.0.0.1:8000/api/admin/clear-all?x=` becomes a POST to
# Iris's own wipe-everything endpoint with the appended path harmlessly parked in the query. Rejecting a
# query or fragment removes that primitive without blocking the LAN gateways analysts actually use — a
# private-IP blocklist would refuse this analyst's own `https://10.0.0.109:3001/v1` and be turned off.
def validate_base_url(value: str) -> str:
    from urllib.parse import urlsplit

    v = (value or "").strip()
    if not v:
        return v
    parts = urlsplit(v)
    if parts.scheme.lower() not in ("http", "https"):
        raise SettingsError(f"ai.baseUrl must be an http:// or https:// URL, not {parts.scheme or v!r}. "
                            f"Iris only speaks HTTP to an OpenAI-compatible endpoint.")
    if not parts.netloc:
        raise SettingsError("ai.baseUrl needs a host, e.g. https://api.openai.com/v1")
    if parts.query or parts.fragment:
        raise SettingsError("ai.baseUrl must not carry a query string or fragment — Iris appends the API "
                            "path to it, so anything after '?' or '#' silently changes which URL is "
                            "actually requested. Use just scheme://host[:port]/path.")
    return v


def update_settings(patch: dict[str, Any]) -> dict[str, Any]:
    """Merge a partial settings dict; masked/empty apiKey leaves the stored key intact."""
    global _settings
    s = get_settings()
    current = s.model_dump()
    for key, value in patch.items():
        # `ingest` MUST be in this tuple: a sub-dict that is not listed here is silently dropped, which is
        # exactly what happened to ingest.autoEnrich — PUT /api/settings returned 200 and the setting never
        # changed, so "nothing enriches on its own" could not actually be turned on.
        if key in ("compute", "ai", "mcp", "ingest") and isinstance(value, dict):
            sub = dict(current[key])
            for k2, v2 in value.items():
                if key == "ai" and k2 == "apiKey":
                    if not isinstance(v2, str) or not v2 or is_masked(v2):
                        continue
                if key == "mcp" and k2 == "token":
                    # masked = the UI echoing back what it was shown, so it is ignored. Unlike the API
                    # key, an EMPTY token is a deliberate "remove the token" (the UI has that button).
                    if not isinstance(v2, str) or is_masked(v2):
                        continue
                if key == "ai" and k2 == "provider":
                    v2 = migrate_provider(v2)
                if key == "ai" and k2 == "baseUrl" and isinstance(v2, str):
                    v2 = validate_base_url(v2)
                sub[k2] = v2
            current[key] = sub
        elif key in ("theme", "analyst"):
            current[key] = value
    new = Settings.model_validate(current)
    with _lock:
        _settings = new
        _ensure_dirs()
        SETTINGS_PATH.write_text(json.dumps(new.model_dump(), indent=2), encoding="utf-8")
    return public_settings()


def safe_os_error(exc: BaseException) -> str:
    """An OS error rendered for an API RESPONSE: the reason and the file's BASENAME, never its path.

    `str(OSError)` is `[Errno 2] No such file or directory: '/data/library/dns.csv'` — the absolute
    path, which on a native install carries the analyst's user name and the whole data-dir layout, out
    to any unauthenticated caller. The full error is printed to the server log, where the analyst can
    read it and an attacker cannot; what comes back is what actually helps: the reason and the name.
    """
    reason = getattr(exc, "strerror", None) or str(exc)
    name = getattr(exc, "filename", None)
    base = Path(str(name)).name if name else ""
    print(f"[iris] {type(exc).__name__}: {exc}")
    return f"{reason}: {base}" if base else str(reason)
