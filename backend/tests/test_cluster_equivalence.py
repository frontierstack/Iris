"""`Analyzer.clusters()` must group exactly what the original pairwise scan grouped.

The pairwise version compared every seed with every later seed inside a one-hour window. On a
detection-rich pool (318 k seeds in the profile run) that is ~10^10 comparisons and the timeline build
never finished. The replacement unions only consecutive pairs, which is provably the same connectivity
— this pins that claim on randomised pools rather than trusting the proof.
"""
from __future__ import annotations

import random

import numpy as np

from app.correlate import PHASES, _PHASE_OF, _UF, Analyzer
from app.models import Detection, Event

_RULE_IDS = [rid for _, _, _, ids in PHASES for rid in ids]


def _reference_groups(az: Analyzer) -> set[frozenset[str]]:
    """The original O(seeds^2) grouping, kept as the oracle."""
    events, ts, seeds = az.events, az.ts, az.seeds
    seed_pos = {i: k for k, i in enumerate(seeds)}
    uf = _UF(len(seeds))
    phase_of = {i: max(_PHASE_OF.get(d.id, 2) for d in events[i].detections) for i in seeds}
    by_phase: dict[int, list[int]] = {}
    for i in seeds:
        by_phase.setdefault(phase_of[i], []).append(i)
    for members in by_phase.values():
        members.sort(key=lambda i: ts[i])
        for ai in range(len(members)):
            a = members[ai]
            ea = set(events[a].entities) - az.generic
            for b in members[ai + 1:]:
                dt = ts[b] - ts[a]
                if dt > 3600:
                    break
                if dt <= 900 or (ea & set(events[b].entities)):
                    uf.union(seed_pos[a], seed_pos[b])
    groups: dict[int, set[str]] = {}
    for i in seeds:
        groups.setdefault(uf.find(seed_pos[i]), set()).add(events[i].id)
    return {frozenset(g) for g in groups.values()}


def _pool(seed: int, n: int = 400):
    rng = random.Random(seed)
    events: list[Event] = []
    t = 0.0
    stamps: list[float] = []
    for i in range(n):
        t += rng.choice([1, 30, 200, 800, 1200, 4000])   # straddles both the 900 s and 3600 s edges
        ents = [f"ip{rng.randrange(9)}", f"user{rng.randrange(7)}"]
        if rng.random() < 0.2:
            ents.append("shared-lb")                      # a candidate for the generic filter
        dets = ([Detection(name="d", id=rng.choice(_RULE_IDS), level="high")] if rng.random() < 0.7 else [])
        events.append(Event(id=f"e{i}", ts="2026-03-01T00:00:00Z", source="syslog", sourceId="s1",
                            file="f.log", host="h", user="u", msg=f"m{i}", sev="info", raw=f"m{i}",
                            fields={}, entities=ents, detections=dets))
        stamps.append(t)
    return events, np.asarray(stamps, dtype=np.float64)


def test_clusters_match_the_pairwise_reference():
    for seed in range(12):
        events, ts = _pool(seed)
        az = Analyzer(events, ts)
        got = {frozenset(c.eventIds) for c in az.clusters()}
        assert got == _reference_groups(az), f"seed {seed}"


def test_clusters_are_stable_and_ordered_by_start():
    events, ts = _pool(99)
    clusters = Analyzer(events, ts).clusters()
    assert [c.id for c in clusters] == [f"c{k}" for k in range(1, len(clusters) + 1)]
    assert [c.start for c in clusters] == sorted(c.start for c in clusters)


def test_clusters_is_empty_without_detections():
    events, ts = _pool(3)
    for e in events:
        e.detections = []
    assert Analyzer(events, ts).clusters() == []
