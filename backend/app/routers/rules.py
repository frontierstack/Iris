"""Detection rules: built-ins (metadata + condition params editable) + custom rules — a raw regex or a
list of typed (field, operator, value) conditions with optional threshold semantics — plus test + AI suggest."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..models import Rule, RuleInput, RuleTestInput, RuleTestResult
from ..rules import RULES_STORE, RuleError, test_rule
from ..store import STORE

router = APIRouter(prefix="/rules", tags=["rules"])


class SuggestBody(BaseModel):
    prompt: str
    examples: Optional[list[str]] = None


def _with_hits(rules: list[Rule]) -> list[Rule]:
    with STORE.lock:
        return RULES_STORE.with_hits(rules, STORE.events)


@router.get("", response_model=list[Rule])
def list_rules(includeRemoved: bool = False) -> list[Rule]:
    return _with_hits(RULES_STORE.all_rules(include_removed=includeRemoved))


@router.post("", response_model=Rule)
def create_rule(body: RuleInput) -> Rule:
    # a custom rule is EITHER a raw regex or a list of typed conditions — one of the two is required
    if not (body.pattern or "").strip() and not (body.conditions or []):
        raise HTTPException(400, "a custom rule needs either a pattern or at least one condition")
    try:
        r = RULES_STORE.create(body)
    except RuleError as exc:
        raise HTTPException(400, str(exc))
    STORE.reapply_rule(r.id)
    return _with_hits([RULES_STORE.get(r.id) or r])[0]


@router.post("/test", response_model=RuleTestResult)
def test_rule_endpoint(body: RuleTestInput) -> RuleTestResult:
    with STORE.lock:
        events = list(STORE.events)
    try:
        return RuleTestResult(**test_rule(events, body))
    except RuleError as exc:
        raise HTTPException(400, str(exc))


@router.post("/suggest")
async def suggest_rule(body: SuggestBody) -> dict:
    from ..ai.rules_suggest import suggest_rule as _suggest
    with STORE.lock:
        events = list(STORE.events)
    return await _suggest(body.prompt, body.examples or [], events)


@router.post("/clear")
def clear_rules(scope: str = "all") -> dict:
    """Empty the rule list. scope=all also takes the built-ins out; scope=custom keeps them.

    Built-ins are only removed from the catalogue, so POST /rules/restore-defaults brings them all back.
    Custom rules are deleted for good - the UI confirms before calling this.
    """
    if scope not in ("all", "custom"):
        raise HTTPException(400, "scope must be 'all' or 'custom'")
    removed = RULES_STORE.clear_all(scope)
    STORE.reapply_all_rules()
    return {"ok": True, **removed}


@router.post("/restore-defaults")
def restore_defaults() -> dict:
    """Put every built-in back and drop all overrides (regex edits, renames, severities). Custom rules stay."""
    restored = RULES_STORE.restore_defaults()
    STORE.reapply_all_rules()
    return {"ok": True, "restored": restored}


@router.put("/{rule_id}", response_model=Rule)
def update_rule(rule_id: str, body: RuleInput) -> Rule:
    if RULES_STORE.is_builtin(rule_id):
        # Metadata edit, plus the regex for the built-ins that match with one. The rest of the condition
        # (windows, thresholds, cross-event joins) stays in code, so field/flags/sourceFilter are ignored.
        try:
            r = RULES_STORE.update_builtin(rule_id, body)
        except RuleError as exc:
            raise HTTPException(400, str(exc))
        STORE.reapply_rule(rule_id)
        return _with_hits([RULES_STORE.get(rule_id) or r])[0]
    if not (body.pattern or "").strip() and not (body.conditions or []):
        raise HTTPException(400, "a custom rule needs either a pattern or at least one condition")
    try:
        r = RULES_STORE.update(rule_id, body)
    except KeyError:
        raise HTTPException(404, "rule not found")
    except RuleError as exc:
        raise HTTPException(400, str(exc))
    STORE.reapply_rule(rule_id)
    return _with_hits([RULES_STORE.get(rule_id) or r])[0]


@router.delete("/{rule_id}")
def delete_rule(rule_id: str) -> dict:
    # built-ins are removed from the catalogue (reversible via /restore); custom rules are deleted outright
    if RULES_STORE.is_builtin(rule_id):
        if not RULES_STORE.remove_builtin(rule_id):
            raise HTTPException(404, "rule not found")
    elif not RULES_STORE.delete(rule_id):
        raise HTTPException(404, "rule not found")
    STORE.reapply_rule(rule_id)
    return {"ok": True}


@router.post("/{rule_id}/restore", response_model=Rule)
def restore_rule(rule_id: str) -> Rule:
    """Put a removed built-in back and drop any metadata override. Custom rules have nothing to restore to."""
    try:
        r = RULES_STORE.restore_builtin(rule_id)
    except KeyError:
        raise HTTPException(404, "not a built-in rule")
    STORE.reapply_rule(rule_id)
    return _with_hits([RULES_STORE.get(rule_id) or r])[0]


@router.post("/{rule_id}/toggle", response_model=Rule)
def toggle_rule(rule_id: str) -> Rule:
    try:
        r = RULES_STORE.toggle(rule_id)
    except KeyError:
        raise HTTPException(404, "rule not found")
    STORE.reapply_rule(rule_id)
    return _with_hits([RULES_STORE.get(rule_id) or r])[0]
