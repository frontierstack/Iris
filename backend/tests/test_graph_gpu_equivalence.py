"""The vectorised graph passes must give the SAME graph on numpy and on cupy.

What actually moved to the array backend, and what did not, measured with cProfile over 30 k realistic
events (see the report in the change that introduced this file):

  * ~75 % of the build is `extract()` — regexes and string slicing over Python `str`. That does not
    vectorise as written and is NOT on the GPU. It was made ~2x faster on the CPU instead (one-pass field
    bucketing, gated regexes, alternation regexes for the word lists, a leaner aggregation loop).
  * the graph-level passes — distinct-neighbour degree over the deduplicated edge list, and the node rank
    order — ARE pure integer array work, and they run through `compute.xp()`: cupy when a CUDA device is
    active, numpy otherwise.

`compute.xp()` returning numpy is the normal, supported configuration, so the numpy path is the
definition of correct here and the GPU path is checked against it. Both are checked against a plain
Python reference implementation, which is what the code used to do inline.
"""
from __future__ import annotations

import numpy as np
import pytest
from fastapi.testclient import TestClient

from app import graph as G
from app.main import app
from app.store import STORE
from tests.conftest import load_sample_case


@pytest.fixture(scope="module")
def gb():
    with TestClient(app) as c:
        load_sample_case(c)
        yield STORE.graph_v2("all")


def _reference_degrees(gb) -> dict[str, int]:
    """What the build used to keep inline: a set of neighbours per node, maintained per relation."""
    adj: dict[str, set[str]] = {}
    for s, t, _k in gb.edges:
        if s == t:
            continue
        adj.setdefault(s, set()).add(t)
        adj.setdefault(t, set()).add(s)
    return {k: len(v) for k, v in adj.items() if v}


def _reference_rank(gb) -> list[str]:
    deg = _reference_degrees(gb)

    def key(i: str):
        n = gb.nodes[i]
        d = deg.get(i, 0)
        return (0 if (n.detections and d) else 1,
                1 if n.type in ("port", "pid", "session") else 0,
                -n.detections, -d, -n.count)

    return sorted(gb.nodes, key=key)          # Python's sort is stable → ties keep insertion order


def test_degrees_match_the_python_reference(gb):
    assert gb._deg == _reference_degrees(gb)
    for i in list(gb.nodes)[:200]:
        assert gb.degree(i) == len(gb.adj.get(i, ()))


def test_rank_order_matches_the_python_reference(gb):
    assert gb.ranked_ids() == _reference_rank(gb)


def test_rank_order_is_total_so_it_cannot_depend_on_sort_stability():
    """Every tie is broken by the node's own position, so an unstable backend sort still agrees."""
    keys = [np.array([1, 1, 1, 1], dtype=np.int64) for _ in range(5)]
    assert list(G._lexsort_rank(*keys)) == [0, 1, 2, 3]


def _forced(monkeypatch, module):
    monkeypatch.setattr(G, "_xp", lambda: module)


def test_numpy_and_cupy_produce_identical_graphs(gb, monkeypatch):
    """Same builder, both backends, byte-identical node order and degrees."""
    cupy = pytest.importorskip("cupy", reason="no cupy in this environment — CPU-only install")
    try:
        if cupy.cuda.runtime.getDeviceCount() < 1:
            pytest.skip("cupy installed but no CUDA device")
    except Exception as exc:                                     # pragma: no cover - depends on the host
        pytest.skip(f"cupy present but unusable: {exc}")

    _forced(monkeypatch, np)
    cpu_deg = gb._degrees()
    gb._ranked = None
    cpu_rank = gb.ranked_ids()

    _forced(monkeypatch, cupy)
    gpu_deg = gb._degrees()
    gb._ranked = None
    gpu_rank = gb.ranked_ids()

    assert cpu_deg == gpu_deg
    assert cpu_rank == gpu_rank
    assert cpu_deg == _reference_degrees(gb)


def test_a_broken_gpu_backend_falls_back_to_numpy(gb, monkeypatch):
    """MANDATORY: every GPU import is guarded and a failure degrades to the numpy answer, never a 500."""
    class Exploding:
        def __getattr__(self, _name):
            raise RuntimeError("simulated CUDA runtime failure")

    monkeypatch.setattr(G, "_xp", lambda: Exploding())
    assert gb._degrees() == _reference_degrees(gb)
    gb._ranked = None
    assert gb.ranked_ids() == _reference_rank(gb)
