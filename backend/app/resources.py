"""What this machine has, and how many workers Iris should run on it.

The old sizing was one constant, ``MAX_WORKERS = 6``, measured on ONE host (8 logical / 4 physical
cores): the parallel parse and the graph extraction both saturated at six workers there, because the
parent needs a core for the request thread and one for its own unpickle/merge share, and eight workers
plus the parent oversubscribed four physical cores. That number was right for that machine and wrong
for every other one — a 50-core box ran six workers and left forty-four idle.

So the sizing is DERIVED here, once, from three things that are actually measured:
- the cores this process may USE (the affinity mask, then a container CPU quota — a 64-core host with
  ``--cpus=4`` gives the container four cores, and ``os.cpu_count()`` still says 64);
- the memory the workers can have (cgroup limit inside a container, else free RAM), with a reserve for
  the parent, which holds the pool;
- the SMT ratio — on this host's 8-logical/4-physical the sweet spot was 6, i.e. 1.5x physical. Hyper-
  threads are not cores for pure-Python string work, so logical−2 overstates it on wide SMT parts.

``profile()`` is the single answer. ``parsers/parallel``, ``graph_parts`` and ``enrich`` read their
defaults from it; the ``IRIS_*_WORKERS`` env vars still pin any one of them. It is printed at startup,
served on ``GET /api/compute`` as ``resources`` (Settings → Compute shows it with the reasoning), and
``setup.*`` / ``start.*`` print the host's side of it so the two can be compared when the container is
given less than the machine has.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

# Ceiling for any pool. Past this the PARENT is the bottleneck — it unpickles every worker's result
# (~15 s per million events) and merges partials serially — so more workers only add memory.
HARD_MAX_WORKERS = 32
# Cores kept for the parent: the request thread and its own unpickle/merge share. Measured: with
# `cpu_count - 1` uvicorn fought the workers for the last core and lost (3-7 s /api/health stalls).
PARENT_CORES = 2
# Memory a worker of each kind needs on top of the parent, from measurement (see CLAUDE.md):
# parse workers hold one 4 MB chunk plus its Events; graph workers a 25 k-event chunk of packed rows.
PARSE_WORKER_MB = 512
GRAPH_WORKER_MB = 300
ENRICH_WORKER_MB = 768       # a whole small source (< IRIS_PARSE_MIN_MB) parsed in one worker
MEMORY_RESERVE_MB = 2048     # for the parent (the pool lives there) — never hand it to workers


@dataclass
class Resources:
    cpuLogical: int
    cpuPhysical: int
    cpuUsable: int           # affinity ∩ cgroup quota — what this process may actually run on
    cpuQuota: Optional[float]  # container CPU limit in cores, when one is set
    memTotalMB: int
    memAvailableMB: int
    memLimitMB: Optional[int]  # cgroup memory limit, when one is set (Docker --memory)
    container: bool
    platform: str


@dataclass
class Profile:
    parseWorkers: int
    graphWorkers: int
    enrichWorkers: int
    uploadLanes: int
    pinned: dict = field(default_factory=dict)   # env var -> value, for every value that was overridden
    reasons: list = field(default_factory=list)


_lock = threading.Lock()
_cache: dict = {"at": 0.0, "res": None, "prof": None}
_TTL = 30.0


# --------------------------------------------------------------------------- detection
def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _cgroup_cpu_quota() -> Optional[float]:
    """Cores a container is limited to (`--cpus`), else None. cgroup v2 then v1."""
    v2 = _read("/sys/fs/cgroup/cpu.max")
    if v2:
        parts = v2.split()
        if len(parts) == 2 and parts[0] != "max":
            try:
                return max(0.1, int(parts[0]) / int(parts[1]))
            except (ValueError, ZeroDivisionError):
                pass
    quota, period = _read("/sys/fs/cgroup/cpu/cpu.cfs_quota_us"), _read("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
    try:
        if quota and period and int(quota) > 0:
            return max(0.1, int(quota) / int(period))
    except ValueError:
        pass
    return None


def _cgroup_mem_limit_mb() -> Optional[int]:
    for p in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        raw = _read(p)
        if raw and raw != "max":
            try:
                n = int(raw)
            except ValueError:
                continue
            if 0 < n < (1 << 60):          # v1 reports a huge number for "no limit"
                return n // (1 << 20)
    return None


def _in_container() -> bool:
    if os.path.exists("/.dockerenv"):
        return True
    cg = _read("/proc/1/cgroup")
    return any(k in cg for k in ("docker", "containerd", "kubepods", "libpod"))


def _physical_cores(logical: int) -> int:
    try:
        import psutil
        n = psutil.cpu_count(logical=False)
        if n:
            return int(n)
    except Exception:
        pass
    return logical


def detect() -> Resources:
    logical = os.cpu_count() or 2
    usable = logical
    try:
        usable = len(os.sched_getaffinity(0))   # type: ignore[attr-defined]  (Linux)
    except (AttributeError, OSError):
        pass
    quota = _cgroup_cpu_quota()
    if quota is not None:
        usable = max(1, min(usable, int(quota + 0.5)))
    total_mb = avail_mb = 0
    try:
        import psutil
        vm = psutil.virtual_memory()
        total_mb, avail_mb = vm.total // (1 << 20), vm.available // (1 << 20)
    except Exception:
        pass
    limit_mb = _cgroup_mem_limit_mb()
    if limit_mb and (not total_mb or limit_mb < total_mb):
        # inside a memory-limited container psutil reports the HOST; the limit is what we may use
        used = _cgroup_mem_used_mb()
        total_mb = limit_mb
        avail_mb = max(0, limit_mb - used) if used is not None else min(avail_mb or limit_mb, limit_mb)
    return Resources(cpuLogical=logical, cpuPhysical=_physical_cores(logical), cpuUsable=max(1, usable),
                     cpuQuota=quota, memTotalMB=total_mb, memAvailableMB=avail_mb, memLimitMB=limit_mb,
                     container=_in_container(), platform=sys.platform)


def _cgroup_mem_used_mb() -> Optional[int]:
    for p in ("/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory/memory.usage_in_bytes"):
        raw = _read(p)
        if raw:
            try:
                return int(raw) // (1 << 20)
            except ValueError:
                continue
    return None


# --------------------------------------------------------------------------- the profile
def _env_int(name: str) -> Optional[int]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    try:
        return max(0, int(raw))
    except ValueError:
        return None


def cpu_workers(res: Resources) -> int:
    """Workers the CPU side supports: usable cores minus the parent's two, and no more than 1.5x the
    physical cores (SMT siblings are not cores for pure-Python string work — measured on 8/4: six)."""
    by_logical = res.cpuUsable - PARENT_CORES
    # a quota below the physical count is the real ceiling — scale the SMT rule to the usable share
    physical = min(res.cpuPhysical, res.cpuUsable)
    by_physical = max(physical, int(physical * 1.5 + 0.5))
    return max(1, min(HARD_MAX_WORKERS, by_logical, by_physical))


def memory_workers(res: Resources, per_worker_mb: int) -> int:
    if not res.memAvailableMB:
        return HARD_MAX_WORKERS
    room = (res.memAvailableMB - MEMORY_RESERVE_MB) // max(1, per_worker_mb)
    return max(1, min(HARD_MAX_WORKERS, int(room)))


def build_profile(res: Resources) -> Profile:
    cpu = cpu_workers(res)
    reasons: list[str] = []
    pinned: dict[str, int] = {}
    cores = f"{res.cpuUsable} usable of {res.cpuLogical} logical / {res.cpuPhysical} physical cores"
    if res.cpuQuota is not None:
        cores += f" (container CPU quota {res.cpuQuota:g})"
    reasons.append(f"{cores}; {PARENT_CORES} kept for the API process; SMT counted at 1.5x physical -> up to {cpu} workers")
    if res.memAvailableMB:
        reasons.append(f"{res.memAvailableMB:,} MB free of {res.memTotalMB:,} MB"
                       + (f" (container limit {res.memLimitMB:,} MB)" if res.memLimitMB else "")
                       + f"; {MEMORY_RESERVE_MB:,} MB reserved for the pool")

    def pick(env: str, per_mb: int, ceiling: int = HARD_MAX_WORKERS) -> int:
        pin = _env_int(env)
        if pin is not None:
            pinned[env] = pin
            return pin
        return max(1, min(ceiling, cpu, memory_workers(res, per_mb)))

    parse = pick("IRIS_PARSE_WORKERS", PARSE_WORKER_MB)
    graph = pick("IRIS_GRAPH_WORKERS", GRAPH_WORKER_MB)
    # phase 2 over many SMALL sources: a whole file per worker, so memory bounds it harder, and it
    # shares the machine with a parse that may be running its own pool — keep it to half
    enrich = pick("IRIS_ENRICH_WORKERS", ENRICH_WORKER_MB, ceiling=max(1, cpu // 2) if cpu > 3 else cpu)
    lanes = 2 if res.cpuUsable <= 2 else 4 if res.cpuUsable <= 8 else 6 if res.cpuUsable <= 16 else 8
    if pinned:
        reasons.append("pinned by environment: " + ", ".join(f"{k}={v}" for k, v in pinned.items()))
    return Profile(parseWorkers=parse, graphWorkers=graph, enrichWorkers=enrich, uploadLanes=lanes,
                   pinned=pinned, reasons=reasons)


def profile(fresh: bool = False) -> Profile:
    """The current sizing, memoised for 30 s — free memory moves, cores do not, and workers() is
    asked per chunkable file and per graph build."""
    with _lock:
        now = time.time()
        if fresh or _cache["prof"] is None or now - _cache["at"] > _TTL:
            res = detect()
            _cache.update(at=now, res=res, prof=build_profile(res))
        return _cache["prof"]


def resources(fresh: bool = False) -> Resources:
    profile(fresh)
    return _cache["res"]


def as_dict(fresh: bool = False) -> dict:
    p = profile(fresh)
    return {"machine": asdict(_cache["res"]), "profile": asdict(p)}


def describe() -> str:
    """One paragraph for the startup banner and the scripts."""
    r, p = resources(), profile()
    where = "container" if r.container else r.platform
    mem = f"{r.memAvailableMB / 1024:.1f} GB free of {r.memTotalMB / 1024:.1f} GB" if r.memTotalMB else "memory unknown"
    return (f"[iris] resources ({where}): {r.cpuUsable} usable cores ({r.cpuLogical} logical, {r.cpuPhysical} physical), "
            f"{mem} -> parse workers {p.parseWorkers}, graph workers {p.graphWorkers}, enrichment lanes {p.enrichWorkers}"
            + (" - pinned: " + ", ".join(f"{k}={v}" for k, v in p.pinned.items()) if p.pinned else ""))
