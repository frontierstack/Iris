"""AI-assisted field mapping suggestions for unknown delimited sources (falls back to the heuristic guess)."""
from __future__ import annotations

from typing import Any, Optional

import httpx

from ..config import get_settings
from ..parsers.delimited import DELIMS, guess_delimiter, guess_roles
from .client import AIError, LLMClient

CANONICAL = ["timestamp", "host", "user", "action", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "bytes", "packets",
             "status", "method", "path", "url", "message", "level", "pid", "program", "process", "event_id", "domain",
             "session", "duration", "interface", "rule", "policy", "zone", "direction", "user_agent", "referrer", "request_id"]
_DELIM_NAMES = {"|": "pipe", "\t": "tab", ",": "comma", ";": "semicolon", " ": "space"}

SYSTEM = (
    "You are the field-mapping assistant inside Iris, a log correlation workbench. You are shown sample rows of a delimited "
    "log file whose format is unknown. Decide the delimiter and name every column, in the order the columns appear.\n"
    "Naming rules, in priority order:\n"
    "1. If the column matches a name ALREADY IN USE in this case (listed below), reuse that exact name. Iris correlates "
    "events by shared field VALUES across files, so the same concept must carry the same name in every source — "
    "'src_ip' in one file and 'source_address' in another will not link up.\n"
    "2. Otherwise prefer a canonical name: " + ", ".join(CANONICAL) + ".\n"
    "3. Otherwise invent a short snake_case name that describes the value, not the vendor's label.\n"
    "Name a column for what it CONTAINS (an IPv4 in the 4th column is src_ip or dst_ip, not 'col4'). Never invent columns "
    "that are not in the rows, and never merge two columns into one name. Reply with JSON only: "
    '{"delimiter": "<single character>", "fields": ["name1","name2",...], "confidence": 0.0-1.0, "rationale": "<one or two sentences>"}'
)


def heuristic_guess(lines: list[str], delimiter: Optional[str] = None) -> tuple[list[str], Optional[str]]:
    lines = [l for l in lines if l.strip()]
    d = delimiter or guess_delimiter(lines)
    if not d:
        return [], None
    rows = [l.split(d) for l in lines[:200]]
    names = guess_roles(rows)
    # the delimited parser stores src/dst; the mapping vocabulary uses src_ip/dst_ip
    names = ["src_ip" if n == "src" else "dst_ip" if n == "dst" else n for n in names]
    return names, d


def _describe_delim(d: Optional[str]) -> str:
    if not d:
        return "unknown"
    return f"{_DELIM_NAMES.get(d, d)} ({d!r})"


async def suggest_mapping(lines: list[str], current_fields: Optional[list[str]] = None,
                          current_delimiter: Optional[str] = None, filename: str = "",
                          known_fields: Optional[list[str]] = None) -> dict[str, Any]:
    """Return {fields, delimiter, confidence, rationale, source}. Never raises: falls back to the heuristic guess."""
    sample = [l.rstrip("\r\n") for l in lines if l.strip()][:20]
    h_fields, h_delim = heuristic_guess(sample, current_delimiter)
    if current_fields:
        h_fields = list(current_fields)
    fallback = {"fields": h_fields, "delimiter": h_delim, "confidence": 0.5 if h_fields else 0.2, "source": "heuristic"}
    settings = get_settings()
    client = LLMClient.from_settings(settings.ai)
    if not client.configured:
        return {**fallback, "rationale": "AI provider not configured (settings > AI); showing the heuristic column-role guess."}
    if not sample:
        return {**fallback, "rationale": "Source has no sample lines to analyse."}
    user = (
        f"File name: {filename or 'unknown'}\n"
        f"Heuristic delimiter guess: {_describe_delim(h_delim)}\n"
        f"Heuristic field guess (in column order): {h_fields or '(none)'}\n"
        f"Sample rows ({len(sample)}):\n" + "\n".join(f"{i + 1}: {l[:400]}" for i, l in enumerate(sample))
    )
    try:
        obj = await client.complete_json(SYSTEM, user, max_tokens=600, temperature=0.0)
    except (AIError, httpx.HTTPError) as exc:
        return {**fallback, "rationale": f"AI suggestion unavailable ({exc}); showing the heuristic guess."}
    except Exception as exc:  # pragma: no cover - never 500 for a suggestion
        return {**fallback, "rationale": f"AI suggestion failed ({type(exc).__name__}); showing the heuristic guess."}
    fields = obj.get("fields")
    if not isinstance(fields, list) or not fields or not all(isinstance(f, str) and f.strip() for f in fields):
        return {**fallback, "rationale": "AI reply did not contain a usable field list; showing the heuristic guess."}
    fields = [_snap_to_known(_normalize_name(f), known_fields or []) for f in fields]
    delim = obj.get("delimiter")
    if isinstance(delim, str):
        delim = {"tab": "\t", "\\t": "\t", "comma": ",", "pipe": "|", "semicolon": ";", "space": " "}.get(delim.strip().lower(), delim)
        if len(delim) != 1 or (delim not in DELIMS and delim != " "):
            delim = h_delim
    else:
        delim = h_delim
    # sanity: the field count should match the sample's column count for the chosen delimiter
    if delim and sample:
        ncol = max(len(l.split(delim)) for l in sample)
        if len(fields) < ncol:
            fields += [f"field{i + 1}" for i in range(len(fields), ncol)]
        elif len(fields) > ncol:
            fields = fields[:ncol]
    seen: set[str] = set()
    uniq: list[str] = []
    for f in fields:
        while f in seen:
            f = f + "_"
        seen.add(f)
        uniq.append(f)
    try:
        conf = float(obj.get("confidence", 0.7))
    except (TypeError, ValueError):
        conf = 0.7
    conf = max(0.0, min(1.0, conf))
    rationale = str(obj.get("rationale") or "").strip()[:600] or f"Suggested by {client.model}."
    return {"fields": uniq, "delimiter": delim, "confidence": round(conf, 3), "rationale": rationale, "source": "ai"}


def _snap_to_known(name: str, known: list[str]) -> str:
    """Pull a near-miss onto a name the case already uses, so values correlate across sources.

    Only collapses obvious variants (separator/pluralisation noise) — never two genuinely different
    fields, which would silently merge unrelated values in the entity graph.
    """
    if not known or name in known:
        return name
    squash = lambda s: s.replace("_", "").replace(".", "").rstrip("s")  # noqa: E731
    target = squash(name)
    for k in known:
        if squash(k) == target:
            return k
    return name


def _normalize_name(name: str) -> str:
    n = name.strip().lower().replace(" ", "_").replace("-", "_")
    n = "".join(ch for ch in n if ch.isalnum() or ch in "_.")
    aliases = {"time": "timestamp", "ts": "timestamp", "datetime": "timestamp", "date": "timestamp", "hostname": "host",
               "username": "user", "source_ip": "src_ip", "sourceip": "src_ip", "destination_ip": "dst_ip", "destip": "dst_ip",
               "dest_ip": "dst_ip", "sport": "src_port", "dport": "dst_port", "protocol": "proto", "msg": "message",
               "severity": "level", "size": "bytes", "length": "bytes"}
    return aliases.get(n, n) or "field"
