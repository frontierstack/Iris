"""AI rule builder: natural-language description → draft regex Rule (heuristic fallback when AI is off/fails)."""
from __future__ import annotations

import random
import re
from typing import Any, Optional

import httpx

from ..config import get_settings
from ..models import Event, Rule, RuleFlags
from ..rules import RuleError, RuleTimeout, compile_pattern, find_matches
from .client import AIError, LLMClient

SEVERITIES = ("critical", "high", "medium", "low", "info")
_SEV_WORDS = {"critical": "critical", "crit": "critical", "severe": "critical", "high": "high", "urgent": "high",
              "medium": "medium", "moderate": "medium", "low": "low", "minor": "low", "info": "info", "informational": "info"}
_STOP = {"the", "a", "an", "and", "or", "of", "for", "to", "in", "on", "with", "any", "all", "when", "that", "this", "from",
         "by", "is", "are", "be", "as", "at", "it", "if", "than", "then", "into", "detect", "detection", "alert", "flag", "find",
         "match", "matches", "matching", "rule", "event", "events", "log", "logs", "line", "lines", "containing", "contains",
         "contain", "mention", "mentions", "where", "which", "who", "whose", "should", "would", "could", "every", "each",
         "severity", "level", "regex", "pattern", "raise", "fire", "trigger", "show", "me", "please", "create", "make", "build",
         "want", "need", "look", "looking", "see", "about", "over", "more", "less", "some", "not", "no", "yes", "was", "were",
         "has", "have", "had", "will", "can", "also", "like", "such", "via", "per", "within", "one", "two", "three",
         "field", "fields", "message", "messages", "text", "value", "values", "occurs", "occur", "occurrence"} | set(_SEV_WORDS)

SYSTEM = (
    "You are the detection-engineering assistant inside Iris, a log correlation workbench. Turn the analyst's description into ONE "
    "regular-expression detection rule using Python `re` syntax (no lookbehind of variable width, no PCRE-only features). "
    "The rule is evaluated per event: field 'any' matches the message OR the raw line OR any parsed field value; a specific field name "
    "(msg, raw, host, user, source, file, or a parsed field key such as http.status, src_ip, EventID, eventName) matches only that value. "
    "Prefer precise, low-false-positive patterns; escape literal dots and slashes; keep it under 400 characters. "
    "Reply with JSON only: {\"name\": \"<short title>\", \"description\": \"<one sentence>\", \"sev\": \"critical|high|medium|low|info\", "
    "\"pattern\": \"<regex>\", \"field\": \"any|<field name>\", \"flags\": {\"ignoreCase\": true|false}, "
    "\"sourceFilter\": \"<substring of the source family or file name, or empty>\", \"tags\": [\"...\"], \"rationale\": \"<why this pattern>\"}"
)


# ------------------------------------------------------------------ helpers
def _keywords(prompt: str) -> tuple[list[str], list[str]]:
    """(quoted phrases, significant bare words) from the prompt."""
    phrases = [m.group(1) or m.group(2) or m.group(3) for m in re.finditer(r'"([^"]+)"|\'([^\']+)\'|`([^`]+)`', prompt)]
    phrases = [p.strip() for p in phrases if p and p.strip()]
    rest = re.sub(r'"[^"]+"|\'[^\']+\'|`[^`]+`', " ", prompt)
    words: list[str] = []
    for w in re.findall(r"[A-Za-z0-9_][A-Za-z0-9_.:/\\-]{2,}", rest):
        lw = w.lower().strip(".:/-")
        if not lw or lw in _STOP or lw in words:
            continue
        words.append(lw)
    return phrases, words


def _sev_from(prompt: str, default: str = "medium") -> str:
    for w in re.findall(r"[A-Za-z]+", prompt.lower()):
        if w in _SEV_WORDS:
            return _SEV_WORDS[w]
    return default


def _title(prompt: str) -> str:
    t = re.sub(r"\s+", " ", prompt).strip().rstrip(".")
    return (t[:1].upper() + t[1:])[:60] or "Custom rule"


def _sample_lines(events: list[Event], prompt: str, n: int = 30) -> list[str]:
    """~n diverse raw lines from the case, preferring lines that contain prompt keywords, spread across sources."""
    if not events:
        return []
    phrases, words = _keywords(prompt)
    keys = [k.lower() for k in phrases + words]
    rnd = random.Random(7)
    pool = events if len(events) <= 5000 else rnd.sample(events, 5000)
    scored: list[tuple[int, str, str]] = []
    for e in pool:
        raw = e.raw or e.msg
        low = raw.lower()
        score = sum(1 for k in keys if k in low)
        scored.append((score, e.source, raw))
    scored.sort(key=lambda x: -x[0])
    out: list[str] = []
    seen: set[str] = set()
    per_source: dict[str, int] = {}
    # first pass: keyword hits, at most n/2 per source
    for score, src, raw in scored:
        if len(out) >= n:
            break
        if score == 0:
            break
        key = raw[:200]
        if key in seen or per_source.get(src, 0) >= max(3, n // 2):
            continue
        seen.add(key)
        per_source[src] = per_source.get(src, 0) + 1
        out.append(raw[:400])
    # second pass: round-robin across sources for diversity
    by_src: dict[str, list[str]] = {}
    for _, src, raw in scored:
        by_src.setdefault(src, []).append(raw)
    while len(out) < n and any(by_src.values()):
        for src in list(by_src):
            lst = by_src[src]
            while lst:
                raw = lst.pop(rnd.randrange(len(lst)))
                if raw[:200] not in seen:
                    seen.add(raw[:200])
                    out.append(raw[:400])
                    break
            if not lst:
                del by_src[src]
            if len(out) >= n:
                break
    return out


def _count_hits(events: list[Event], pattern: str, field: str, flags: RuleFlags, source_filter: str) -> Optional[int]:
    if not events:
        return None
    try:
        return len(find_matches(events, pattern, field, flags, source_filter))
    except (RuleError, RuleTimeout):
        return None


def _draft(name: str, description: str, sev: str, pattern: str, field: str, ignore_case: bool, source_filter: str,
           tags: list[str], created_by: str, hits: Optional[int]) -> Rule:
    return Rule(id="", name=name, description=description, sev=sev, enabled=True, builtin=False, kind="regex",  # type: ignore[arg-type]
                pattern=pattern, field=field or "any", flags=RuleFlags(ignoreCase=ignore_case, multiline=False),
                sourceFilter=source_filter or "", tags=tags, createdBy=created_by, createdAt="", updatedAt="", hits=hits)  # type: ignore[arg-type]


def heuristic_rule(prompt: str, events: list[Event]) -> tuple[Rule, str]:
    phrases, words = _keywords(prompt)
    terms = phrases or words[:8]
    if not terms:
        terms = [prompt.strip()[:40] or "TODO"]
    pattern = "|".join(re.escape(t) for t in terms)
    sev = _sev_from(prompt)
    hits = _count_hits(events, pattern, "any", RuleFlags(ignoreCase=True), "")
    rule = _draft(_title(prompt), f"Matches events mentioning {', '.join(terms[:5])}.", sev, pattern, "any", True, "",
                  ["custom"], "user", hits)
    src = "quoted phrases" if phrases else "significant keywords"
    return rule, f"Heuristic draft: case-insensitive alternation of {src} from your description ({len(terms)} term{'s' if len(terms) != 1 else ''}); refine before saving."


def _coerce(obj: dict[str, Any], prompt: str) -> tuple[str, str, str, str, str, bool, str, list[str], str]:
    name = str(obj.get("name") or "").strip()[:80] or _title(prompt)
    description = str(obj.get("description") or "").strip()[:400]
    sev = str(obj.get("sev") or obj.get("severity") or "").strip().lower()
    if sev not in SEVERITIES:
        sev = _sev_from(prompt)
    pattern = obj.get("pattern") or obj.get("regex") or ""
    if not isinstance(pattern, str):
        raise AIError("model reply had no string pattern")
    field = str(obj.get("field") or "any").strip() or "any"
    flags = obj.get("flags") if isinstance(obj.get("flags"), dict) else {}
    ic = flags.get("ignoreCase", True)
    ignore_case = bool(ic) if isinstance(ic, (bool, int)) else str(ic).lower() in ("true", "1", "yes")
    source_filter = obj.get("sourceFilter") or ""
    source_filter = str(source_filter).strip()[:100] if isinstance(source_filter, (str, int)) else ""
    tags = obj.get("tags") if isinstance(obj.get("tags"), list) else []
    tags = [str(t).strip()[:30] for t in tags if str(t).strip()][:8]
    rationale = str(obj.get("rationale") or "").strip()[:600]
    return name, description, sev, pattern, field, ignore_case, source_filter, tags, rationale


# ------------------------------------------------------------------ entry point
async def suggest_rule(prompt: str, examples: list[str], events: list[Event]) -> dict[str, Any]:
    """Return {rule, rationale, source}. Never raises: falls back to the heuristic draft (always HTTP 200)."""
    prompt = (prompt or "").strip()
    fb_rule, fb_rationale = heuristic_rule(prompt, events)
    settings = get_settings()
    client = LLMClient.from_settings(settings.ai)
    if not client.configured:
        return {"rule": fb_rule, "rationale": "AI provider not configured (settings > AI). " + fb_rationale, "source": "heuristic"}
    if not prompt:
        return {"rule": fb_rule, "rationale": "Empty description. " + fb_rationale, "source": "heuristic"}
    lines = [l.rstrip("\r\n") for l in (examples or []) if isinstance(l, str) and l.strip()][:30]
    sampled = False
    if not lines:
        lines = _sample_lines(events, prompt)
        sampled = True
    user = (
        f"Analyst description:\n{prompt}\n\n"
        + (f"Example log lines ({len(lines)}{', sampled from the active case' if sampled else ', supplied by the analyst'}):\n"
           + "\n".join(f"{i + 1}: {l[:400]}" for i, l in enumerate(lines)) if lines else "No example lines are available.")
    )
    last_error = ""
    best: Optional[dict[str, Any]] = None
    for attempt in range(2):
        try:
            obj = await client.complete_json(SYSTEM, user, max_tokens=700, temperature=0.0)
            name, description, sev, pattern, field, ignore_case, source_filter, tags, rationale = _coerce(obj, prompt)
            compile_pattern(pattern, RuleFlags(ignoreCase=ignore_case))
        except (AIError, httpx.HTTPError, RuleError) as exc:
            last_error = str(exc)
            if isinstance(exc, RuleError) and attempt == 0:
                user += f"\n\nYour previous pattern was rejected by Python's re module ({exc}). Return a corrected rule."
                continue
            break
        except Exception as exc:  # pragma: no cover - never 500 for a suggestion
            last_error = f"{type(exc).__name__}: {exc}"
            break
        hits = _count_hits(events, pattern, field, RuleFlags(ignoreCase=ignore_case), source_filter)
        rule = _draft(name, description, sev, pattern, field, ignore_case, source_filter, tags or ["ai"], "ai", hits)
        result = {"rule": rule, "rationale": (rationale or f"Suggested by {client.model}.")
                  + (f" ({hits} matching event{'s' if hits != 1 else ''} in the active case)" if hits is not None else ""), "source": "ai"}
        if hits == 0 and attempt == 0 and events:
            best = result
            user += (f"\n\nFeedback: the pattern {pattern!r} on field {field!r}"
                     + (f" with sourceFilter {source_filter!r}" if source_filter else "")
                     + " matched 0 of the case's events. Loosen it (or fix the field / drop the source filter) so it matches the "
                       "relevant example lines while staying specific, and return the corrected rule.")
            continue
        return result
    if best is not None:
        return best
    return {"rule": fb_rule, "rationale": f"AI suggestion unavailable ({last_error or 'no reply'}); " + fb_rationale, "source": "heuristic"}
