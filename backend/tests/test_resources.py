"""Worker pools are sized from what the PROCESS can use, not from one host's constant."""
from __future__ import annotations

from app import resources as R


def _res(logical, physical, usable=None, avail_mb=64_000, total_mb=64_000, quota=None, limit=None):
    return R.Resources(cpuLogical=logical, cpuPhysical=physical, cpuUsable=usable or logical, cpuQuota=quota,
                       memTotalMB=total_mb, memAvailableMB=avail_mb, memLimitMB=limit, container=quota is not None,
                       platform="test")


def test_the_measured_host_still_gets_six(monkeypatch) -> None:
    for v in ("IRIS_PARSE_WORKERS", "IRIS_GRAPH_WORKERS", "IRIS_ENRICH_WORKERS"):
        monkeypatch.delenv(v, raising=False)
    p = R.build_profile(_res(8, 4))
    assert (p.parseWorkers, p.graphWorkers) == (6, 6), "8 logical / 4 physical saturated at six — the rule must reproduce it"
    assert p.enrichWorkers == 3


def test_a_wide_machine_scales_up_to_the_ceiling(monkeypatch) -> None:
    for v in ("IRIS_PARSE_WORKERS", "IRIS_GRAPH_WORKERS", "IRIS_ENRICH_WORKERS"):
        monkeypatch.delenv(v, raising=False)
    p = R.build_profile(_res(100, 50, avail_mb=256_000, total_mb=256_000))
    assert p.parseWorkers == R.HARD_MAX_WORKERS and p.graphWorkers == R.HARD_MAX_WORKERS
    assert p.enrichWorkers == R.HARD_MAX_WORKERS // 2


def test_a_container_quota_beats_the_host_core_count(monkeypatch) -> None:
    monkeypatch.delenv("IRIS_PARSE_WORKERS", raising=False)
    p = R.build_profile(_res(64, 32, usable=4, quota=4.0))
    assert p.parseWorkers == 2, "a --cpus=4 container has two cores to spare, whatever the host has"


def test_memory_bounds_the_pool(monkeypatch) -> None:
    monkeypatch.delenv("IRIS_GRAPH_WORKERS", raising=False)
    p = R.build_profile(_res(32, 16, avail_mb=R.MEMORY_RESERVE_MB + 3 * R.GRAPH_WORKER_MB + 10))
    assert p.graphWorkers == 3
    assert p.parseWorkers == 1, "no room for a 512 MB worker beyond the reserve — but never zero"


def test_env_pins_are_honoured_and_reported(monkeypatch) -> None:
    monkeypatch.setenv("IRIS_PARSE_WORKERS", "1")
    monkeypatch.setenv("IRIS_GRAPH_WORKERS", "12")
    p = R.build_profile(_res(8, 4))
    assert p.parseWorkers == 1 and p.graphWorkers == 12
    assert p.pinned == {"IRIS_PARSE_WORKERS": 1, "IRIS_GRAPH_WORKERS": 12}
    assert any("pinned" in r for r in p.reasons)


def test_the_live_pools_read_the_profile(monkeypatch) -> None:
    from app.parsers.parallel import parallel_workers
    from app.graph_parts import workers
    from app.enrich import small_parallel_max
    monkeypatch.setenv("IRIS_PARSE_WORKERS", "7")
    monkeypatch.setenv("IRIS_GRAPH_WORKERS", "9")
    monkeypatch.setenv("IRIS_ENRICH_WORKERS", "5")
    R.profile(fresh=True)
    assert (parallel_workers(), workers(), small_parallel_max()) == (7, 9, 5)
    for v in ("IRIS_PARSE_WORKERS", "IRIS_GRAPH_WORKERS", "IRIS_ENRICH_WORKERS"):
        monkeypatch.delenv(v)
    R.profile(fresh=True)


def test_detect_never_raises_and_describe_is_ascii() -> None:
    r = R.detect()
    assert r.cpuUsable >= 1 and r.cpuLogical >= 1
    R.describe().encode("ascii")   # a cp1252 console (Windows local install) must not crash the lifespan
    d = R.as_dict(fresh=True)
    assert set(d) == {"machine", "profile"}
