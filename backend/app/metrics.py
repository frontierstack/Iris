"""Live performance metrics: GPU utilisation / memory / temperature / power, process CPU + RSS,
and parse throughput. A background thread samples every SAMPLE_SECONDS into a ring buffer that
GET /api/compute/metrics serves to the Settings → Compute performance graphs.

GPU numbers come from pynvml when importable, else `nvidia-smi --query-gpu`; both are optional and
import-guarded — on CPU-only hosts the GPU fields are simply null.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Optional

SAMPLE_SECONDS = 2.0
HISTORY = 900  # 30 minutes at 2 s

_lock = threading.Lock()
_samples: deque[dict[str, Any]] = deque(maxlen=HISTORY)
_stop = threading.Event()
_thread: Optional[threading.Thread] = None

# parse throughput accounting — credited INCREMENTALLY, from the same per-source progress ticks the
# Sources page reads (jobs.ProgressTracker.advance), not once per finished file.
#
# Crediting at the end of each file made the chart a spike train and the number a lie: a 1.1 GB CSV
# takes minutes during which the rate reads 0 events/s, then one 2 s sample claims ten million. The
# analyst watching a big ingest sees "0 events/s" for the whole thing, which is exactly the "is it
# hung?" question two-phase ingest exists to answer. Per-source deltas are kept so the same source can
# be credited a thousand times without double counting, and the final call credits only the remainder.
_parsed_events = 0
_parsed_bytes = 0
_seen: dict[str, tuple[int, int]] = {}
_parsed_lock = threading.Lock()
_last_parsed_events = 0
_last_parsed_bytes = 0
_last_ts = time.monotonic()

# GPU source selection. Two failures live here and they are NOT the same failure, which is the whole
# point of keeping them apart:
#
#   * pynvml is not installed. A module cannot appear under a running process, so that is permanent
#     and it is right to stop trying (`_nvml_absent`).
#   * an NVML CALL failed — a driver reset, an XID, the device briefly off the bus, a container that
#     started before the driver did. That is TRANSIENT, and the old code latched it permanently:
#     one exception anywhere in the sample set `_nvml_ok = False` for the life of the process, after
#     which every 2 s tick fell through to `nvidia-smi`. Measured on this host, 38 ms per spawn
#     (Windows; WSL and the container are slower) — a process create every 2 s, forever, ~2 % of a
#     core, for a GPU that had recovered seconds after the blip. So a call failure backs off and is
#     RETRIED instead: 30 s, doubling to a 300 s ceiling, reset the moment a sample succeeds.
#
# The handle is dropped on failure so the retry re-runs nvmlInit() — that is what lets a driver
# that comes back be picked up rather than being queried through a dead handle.
#
# Nothing is ever cached across a failure. A failed sample reports NO gpus, never the last good
# numbers: a stale utilisation figure presented as live is a lie about the machine, and the analyst
# reads these charts to answer "is it using the GPU?".
NVML_RETRY_MIN = 30.0
NVML_RETRY_MAX = 300.0
SMI_RETRY_MIN = 30.0
SMI_RETRY_MAX = 300.0

_nvml: Any = None
_nvml_absent = False
_nvml_retry_at = 0.0
_nvml_backoff = 0.0
# The same backoff for the fallback, for the same reason at a higher cost: `nvidia-smi` missing or
# failing was re-probed (a shutil.which walk of PATH plus a spawn) on every 2 s tick.
_smi_retry_at = 0.0
_smi_backoff = 0.0
_proc: Any = None


def _backoff_next(current: float, lo: float, hi: float) -> float:
    return min(hi, max(lo, current * 2.0))


def record_parsed(events: int, nbytes: int) -> None:
    """Credit work that belongs to no tracked source (kept for callers that have no source id)."""
    global _parsed_events, _parsed_bytes
    with _parsed_lock:
        _parsed_events += max(0, events)
        _parsed_bytes += max(0, nbytes)


def record_progress(key: str, events: int, nbytes: int) -> None:
    """Credit the DELTA for one source since it was last seen. Safe to call from a parse loop.

    `events`/`nbytes` are the source's running TOTALS, which is what the progress tracker holds; only
    the growth is added. A total that goes backwards (a phase-2 re-parse of the same source starts at
    zero again) re-baselines rather than crediting a negative.
    """
    global _parsed_events, _parsed_bytes
    if not key:
        return
    with _parsed_lock:
        prev_e, prev_b = _seen.get(key, (0, 0))
        ev, by = max(0, int(events)), max(0, int(nbytes))
        if ev < prev_e or by < prev_b:
            prev_e, prev_b = 0, 0            # a new pass over the same source
        _parsed_events += ev - prev_e
        _parsed_bytes += by - prev_b
        _seen[key] = (ev, by)


def finish_progress(key: str, events: int, nbytes: int) -> None:
    """Credit whatever the ticks had not reached yet and forget the source.

    The final numbers are authoritative: progress ticks are published every N records, so the tail of
    a file — and every file too small to tick at all — is credited here.
    """
    global _parsed_events, _parsed_bytes
    with _parsed_lock:
        prev_e, prev_b = _seen.pop(key, (0, 0)) if key else (0, 0)
        _parsed_events += max(0, int(events) - prev_e)
        _parsed_bytes += max(0, int(nbytes) - prev_b)


def _nvml_gpus() -> Optional[list[dict[str, Any]]]:
    global _nvml, _nvml_absent, _nvml_retry_at, _nvml_backoff
    if _nvml_absent:
        return None
    if _nvml_retry_at and time.monotonic() < _nvml_retry_at:
        return None
    try:
        if _nvml is None:
            try:
                import pynvml  # type: ignore
            except Exception:
                _nvml_absent = True      # not installed; that cannot change under a running process
                return None
            pynvml.nvmlInit()            # CAN change: a driver that comes up later, a GPU attached
            _nvml = pynvml
        pynvml = _nvml
        out = []
        for i in range(pynvml.nvmlDeviceGetCount()):
            h = pynvml.nvmlDeviceGetHandleByIndex(i)
            util = pynvml.nvmlDeviceGetUtilizationRates(h)
            mem = pynvml.nvmlDeviceGetMemoryInfo(h)
            try:
                temp = int(pynvml.nvmlDeviceGetTemperature(h, pynvml.NVML_TEMPERATURE_GPU))
            except Exception:
                temp = None
            try:
                power = round(pynvml.nvmlDeviceGetPowerUsage(h) / 1000.0, 1)
            except Exception:
                power = None
            try:
                clock = int(pynvml.nvmlDeviceGetClockInfo(h, pynvml.NVML_CLOCK_SM))
            except Exception:
                clock = None
            name = pynvml.nvmlDeviceGetName(h)
            if isinstance(name, bytes):
                name = name.decode(errors="ignore")
            out.append({"index": i, "name": name, "util": int(util.gpu), "memUtil": int(util.memory),
                        "memUsedMB": int(mem.used // (1024 * 1024)), "memTotalMB": int(mem.total // (1024 * 1024)),
                        "tempC": temp, "powerW": power, "smClockMHz": clock})
        _nvml_retry_at, _nvml_backoff = 0.0, 0.0     # a good sample clears the whole backoff
        return out
    except Exception:
        # Transient by assumption, and the assumption is the cheap one to be wrong about: retrying a
        # genuinely dead NVML costs one call every 300 s, while latching a live one off costs a
        # subprocess every 2 s for the life of the container.
        _nvml = None                                  # re-init on the retry, do not reuse the handle
        _nvml_backoff = _backoff_next(_nvml_backoff, NVML_RETRY_MIN, NVML_RETRY_MAX)
        _nvml_retry_at = time.monotonic() + _nvml_backoff
        return None


def _smi_fail() -> None:
    global _smi_retry_at, _smi_backoff
    _smi_backoff = _backoff_next(_smi_backoff, SMI_RETRY_MIN, SMI_RETRY_MAX)
    _smi_retry_at = time.monotonic() + _smi_backoff


def _smi_gpus() -> Optional[list[dict[str, Any]]]:
    global _smi_retry_at, _smi_backoff
    if _smi_retry_at and time.monotonic() < _smi_retry_at:
        return None
    exe = shutil.which("nvidia-smi")
    if not exe:
        _smi_fail()
        return None
    try:
        proc = subprocess.run(
            [exe, "--query-gpu=index,name,utilization.gpu,utilization.memory,memory.used,memory.total,temperature.gpu,power.draw,clocks.sm",
             "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=4)
    except Exception:
        _smi_fail()
        return None
    if proc.returncode != 0:
        _smi_fail()
        return None
    # A working nvidia-smi is sampled at the full 2 s cadence deliberately: the spawn is the cost of
    # the only GPU reading available on this host, and coarsening it would put a stale number on a
    # live chart. Only FAILURE backs off.
    _smi_retry_at, _smi_backoff = 0.0, 0.0
    out = []
    for line in proc.stdout.splitlines():
        p = [x.strip() for x in line.split(",")]
        if len(p) < 9:
            continue

        def num(v: str) -> Optional[float]:
            try:
                return float(v)
            except ValueError:
                return None
        out.append({"index": int(num(p[0]) or 0), "name": p[1], "util": int(num(p[2]) or 0), "memUtil": int(num(p[3]) or 0),
                    "memUsedMB": int(num(p[4]) or 0), "memTotalMB": int(num(p[5]) or 0),
                    "tempC": (int(num(p[6])) if num(p[6]) is not None else None),
                    "powerW": num(p[7]), "smClockMHz": (int(num(p[8])) if num(p[8]) is not None else None)})
    return out


def _process() -> dict[str, Any]:
    global _proc
    try:
        import psutil  # type: ignore
        if _proc is None:
            _proc = psutil.Process(os.getpid())
            _proc.cpu_percent(None)  # prime
        cpu = _proc.cpu_percent(None)
        rss = _proc.memory_info().rss // (1024 * 1024)
        sys_cpu = psutil.cpu_percent(None)
        vm = psutil.virtual_memory()
        return {"cpuPct": round(cpu, 1), "rssMB": int(rss), "sysCpuPct": round(sys_cpu, 1),
                "sysMemPct": round(vm.percent, 1), "threads": _proc.num_threads()}
    except Exception:
        return {"cpuPct": None, "rssMB": None, "sysCpuPct": None, "sysMemPct": None, "threads": threading.active_count()}


def sample_once() -> dict[str, Any]:
    global _last_parsed_events, _last_parsed_bytes, _last_ts
    now = time.monotonic()
    with _parsed_lock:
        ev, by = _parsed_events, _parsed_bytes
    dt = max(1e-6, now - _last_ts)
    eps = (ev - _last_parsed_events) / dt
    bps = (by - _last_parsed_bytes) / dt
    _last_parsed_events, _last_parsed_bytes, _last_ts = ev, by, now

    gpus = _nvml_gpus()
    if gpus is None:
        gpus = _smi_gpus()
    from . import compute  # local import (compute imports nothing from here)
    st = compute.status()
    s = {
        "t": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "gpus": gpus or [],
        "active": st.active,
        "eventsPerSec": round(eps, 1),
        "bytesPerSec": int(bps),
        "totalParsedEvents": ev,
        **_process(),
    }
    with _lock:
        _samples.append(s)
    return s


def history(window: int = 300) -> dict[str, Any]:
    with _lock:
        items = list(_samples)[-max(1, min(window, HISTORY)):]
    return {"intervalSec": SAMPLE_SECONDS, "samples": items, "current": items[-1] if items else None}


def _loop() -> None:
    while not _stop.wait(SAMPLE_SECONDS):
        try:
            sample_once()
        except Exception:
            pass


def start_background() -> None:
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, name="metrics-sampler", daemon=True)
    _thread.start()


def stop_background() -> None:
    _stop.set()
