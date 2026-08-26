"""The rules screen must not walk the pool, and it must not do it under the store lock.

`RulesStore.with_hits` counted detections per rule by iterating every event and every detection —
inside `with STORE.lock`, in `routers/rules._with_hits`, on every `GET /api/rules`. The Anomalies
screen polls that endpoint, so a workspace-sized pass ran inside the lock on a poll: at 11 M events
that is seconds during which every other request queues behind it. Every rule MUTATION paid it twice
more, because `reapply_rule` then counted `rule_id`'s hits over the pool and totalled every
detection over the pool, both on top of the catalogue pass that had just walked it.

The tally is version-keyed now (`Store.rule_hit_counts`), so it costs one pass per change and
nothing at all on the polls in between. The numbers themselves must not move — that is the first
test here, and it is the one that matters.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.rules import RULES_STORE
from app.store import STORE

LOG = b"".join(
    ("2026-08-26T00:%02d:%02dZ web1 sshd[42]: Failed password for root from 10.0.0.%d port 22 ssh2\n"
     % (i // 60 % 60, i % 60, i % 250)).encode() for i in range(600))


class _CountingList(list):
    def __init__(self, *a):
        super().__init__(*a)
        self.iterations = 0

    def __iter__(self):
        self.iterations += 1
        return super().__iter__()


@pytest.fixture()
def c():
    with TestClient(app) as client:
        yield client


@pytest.fixture()
def pool(c):
    STORE.clear_all()
    r = c.post("/api/library/upload", files=[("files", ("auth.log", LOG, "text/plain"))])
    assert r.status_code == 200, r.text
    return c


def _hits(client) -> dict[str, int]:
    r = client.get("/api/rules")
    assert r.status_code == 200, r.text
    return {x["id"]: x["hits"] for x in r.json() if x.get("hits")}


def test_the_hit_counts_are_what_a_walk_of_the_pool_would_say(pool) -> None:
    """The tally replaces a count; it must produce the same numbers."""
    reported = _hits(pool)
    walked: dict[str, int] = {}
    for e in STORE.events:
        for d in e.detections:
            walked[d.id] = walked.get(d.id, 0) + 1
    assert reported == {k: v for k, v in walked.items() if v}
    assert reported, "the fixture should fire at least one rule, or this proves nothing"


def test_polling_the_rules_screen_does_not_iterate_the_pool(pool) -> None:
    first = _hits(pool)                       # may walk once to fill the tally
    counting = _CountingList(STORE.events)
    STORE.events = counting
    try:
        for _ in range(3):
            assert _hits(pool) == first
        assert counting.iterations == 0, (
            f"{counting.iterations} pass(es) over the pool for a poll that changed nothing")
    finally:
        STORE.events = list(counting)


def test_a_rule_toggle_still_reports_the_right_hits(pool) -> None:
    """And the count has to react to the toggle in the SAME response, not one poll later."""
    fired = _hits(pool)
    rule_id = max(fired, key=fired.get)
    before = fired[rule_id]
    assert before > 0

    off = pool.post(f"/api/rules/{rule_id}/toggle")
    assert off.status_code == 200, off.text
    assert not off.json().get("hits"), "a disabled rule still reports its old hit count"
    assert rule_id not in _hits(pool)

    on = pool.post(f"/api/rules/{rule_id}/toggle")
    assert on.status_code == 200, on.text
    assert on.json()["hits"] == before
    assert _hits(pool)[rule_id] == before
    assert RULES_STORE.get(rule_id).enabled
