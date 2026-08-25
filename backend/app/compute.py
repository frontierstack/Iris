"""GPU / CUDA detection and array-backend selection.

All GPU dependencies are optional and import-guarded; the app runs with numpy only.
"""
from __future__ import annotations

import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

import numpy as np

from .config import get_settings
from .models import ComputeStatus, GPUInfo

REPROBE_SECONDS = 60


"""Sentinel a probe returns when the GPU library simply is not installed. That is the supported CPU
configuration (GPU deps live only in requirements-gpu.txt), so it must never surface as an error."""
_NOT_INSTALLED = "\x00not-installed"


class _State:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.available = False
        self.backend: str = "numpy"
        self.cuda_version: Optional[str] = None
        self.gpus: list[GPUInfo] = []
        self.error: Optional[str] = None
        self.no_gpu_libs = False  # nothing installed, as opposed to installed-but-broken
        self.last_check: datetime = datetime.now(timezone.utc)
        self.checking = False
        self.cupy: Any = None
        self.torch: Any = None
        self.thread: Optional[threading.Thread] = None
        self.stop = threading.Event()


_state = _State()


def _probe_cupy() -> tuple[bool, Optional[str], Any, Optional[str]]:
    try:
        import cupy  # type: ignore
    except ModuleNotFoundError:
        return False, None, None, _NOT_INSTALLED  # CPU install — the supported default, not a failure
    except Exception as exc:  # CUDA runtime failures at import (installed but unusable)
        return False, None, None, f"cupy: {type(exc).__name__}"
    try:
        n = cupy.cuda.runtime.getDeviceCount()
        if n <= 0:
            return False, None, None, "cupy: no CUDA devices"
        ver = cupy.cuda.runtime.runtimeGetVersion()
        cuda_version = f"{ver // 1000}.{(ver % 1000) // 10}"
        # Exercise the same JIT paths correlate.py uses (linspace/histogram/fancy indexing) so a
        # runtime without CUDA headers (NVRTC) is reported as unavailable instead of failing later.
        cupy.zeros(1).sum()
        cupy.linspace(0.0, 1.0, 4)
        cupy.histogram(cupy.arange(16, dtype=cupy.float64), bins=4, range=(0.0, 16.0))
        m = cupy.zeros((4, 4), dtype=cupy.float32)
        m[cupy.asarray([0, 1]), cupy.asarray([1, 2])] = 1.0
        (m.T @ m).sum()
        # The kernels the accelerated paths added: bincount (search.byte_histogram), the shift/mask
        # expansion and the float32 GEMM (correlate.cooccurrence), searchsorted + flatnonzero
        # (search._Engine.contains). Compiling these here costs milliseconds on a 16-element array and
        # keeps ~3 s of first-use NVRTC compilation out of the first index build.
        cupy.bincount(cupy.arange(16, dtype=cupy.int32), minlength=256)
        bits = (cupy.arange(16, dtype=cupy.uint64)[:, None] >> cupy.arange(4, dtype=cupy.uint64)) & cupy.uint64(1)
        (bits.astype(cupy.float32).T @ bits.astype(cupy.float32)).astype(cupy.int64).sum()
        cupy.searchsorted(cupy.arange(16, dtype=cupy.int64), cupy.arange(4, dtype=cupy.int64), side="right")
        cupy.flatnonzero(cupy.arange(16, dtype=cupy.uint8) == 3)
        return True, cuda_version, cupy, None
    except Exception as exc:
        return False, None, None, f"cupy: {exc}"


def _probe_torch() -> tuple[bool, Optional[str], Any, Optional[str]]:
    try:
        import torch  # type: ignore
    except ModuleNotFoundError:
        return False, None, None, _NOT_INSTALLED
    except Exception as exc:
        return False, None, None, f"torch: {type(exc).__name__}"
    try:
        if torch.cuda.is_available():
            return True, getattr(torch.version, "cuda", None), torch, None
        return False, None, None, "torch: cuda not available"
    except Exception as exc:
        return False, None, None, f"torch: {exc}"


def _gpus_pynvml() -> Optional[list[GPUInfo]]:
    try:
        import pynvml  # type: ignore
    except Exception:
        return None
    try:
        pynvml.nvmlInit()
        try:
            driver = pynvml.nvmlSystemGetDriverVersion()
            driver = driver.decode() if isinstance(driver, bytes) else str(driver)
            out: list[GPUInfo] = []
            for i in range(pynvml.nvmlDeviceGetCount()):
                h = pynvml.nvmlDeviceGetHandleByIndex(i)
                name = pynvml.nvmlDeviceGetName(h)
                name = name.decode() if isinstance(name, bytes) else str(name)
                mem = pynvml.nvmlDeviceGetMemoryInfo(h)
                out.append(GPUInfo(index=i, name=name, memoryTotalMB=int(mem.total // (1024 * 1024)),
                                   memoryUsedMB=int(mem.used // (1024 * 1024)), driver=driver))
            return out
        finally:
            try:
                pynvml.nvmlShutdown()
            except Exception:
                pass
    except Exception:
        return None


def _gpus_nvidia_smi() -> list[GPUInfo]:
    exe = shutil.which("nvidia-smi")
    if not exe:
        return []
    try:
        proc = subprocess.run(
            [exe, "--query-gpu=index,name,memory.total,memory.used,driver_version", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=8,
        )
    except Exception:
        return []
    if proc.returncode != 0:
        return []
    out: list[GPUInfo] = []
    for line in proc.stdout.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 5:
            continue
        try:
            out.append(GPUInfo(index=int(parts[0]), name=parts[1], memoryTotalMB=int(float(parts[2])),
                               memoryUsedMB=int(float(parts[3])), driver=parts[4]))
        except ValueError:
            continue
    return out


def probe() -> ComputeStatus:
    """Run a full probe (blocking) and update the shared state."""
    with _state.lock:
        _state.checking = True
    try:
        ok, cuda_version, mod, err = _probe_cupy()
        backend = "cupy" if ok else "numpy"
        cupy_mod, torch_mod = (mod, None) if ok else (None, None)
        errors: list[str] = []
        if not ok and err:
            errors.append(err)
        if not ok:
            ok2, cv2, mod2, err2 = _probe_torch()
            if ok2:
                ok, cuda_version, torch_mod, backend = True, cv2, mod2, "torch"
            elif err2:
                errors.append(err2)
        gpus = _gpus_pynvml()
        if gpus is None:
            gpus = _gpus_nvidia_smi()
        # every reason we fell back was "the library isn't there" → a plain CPU install, not a fault
        no_libs = bool(errors) and all(e == _NOT_INSTALLED for e in errors)
        real_errors = [e for e in errors if e != _NOT_INSTALLED]
        with _state.lock:
            _state.available = ok
            _state.backend = backend
            _state.cuda_version = cuda_version
            _state.gpus = gpus
            _state.cupy = cupy_mod
            _state.torch = torch_mod
            _state.no_gpu_libs = (not ok) and no_libs
            _state.error = None if ok else ("; ".join(real_errors) if real_errors else None)
            _state.last_check = datetime.now(timezone.utc)
    finally:
        with _state.lock:
            _state.checking = False
    return status()


_NO_LIBS_HINT = ("No GPU compute library is installed, so parsing and correlation run on the CPU (numpy). "
                 "This is the default CPU build — to enable CUDA, install backend/requirements-gpu.txt "
                 "or run the GPU image (docker-compose.gpu.yml).")


def status() -> ComputeStatus:
    mode = get_settings().compute.mode
    with _state.lock:
        available = _state.available
        error = _state.error
        no_libs = _state.no_gpu_libs
        note: Optional[str] = None
        if mode == "cpu":
            active = "cpu"
        elif mode == "cuda":
            active = "cuda" if available else "cpu"
            if not available:
                # the analyst explicitly asked for CUDA and did not get it — that IS an error, whatever the cause
                detail = error or (_NO_LIBS_HINT if no_libs else None)
                error = "CUDA requested but no usable GPU backend was found — running on CPU" + (f". {detail}" if detail else "")
        else:
            active = "cuda" if available else "cpu"
        if active == "cpu" and mode != "cuda" and no_libs and not error:
            note = _NO_LIBS_HINT
        backend = _state.backend if active == "cuda" else "numpy"
        try:
            from . import resources as _res
            res_block: Optional[dict] = _res.as_dict()
        except Exception:
            res_block = None
        return ComputeStatus(resources=res_block,
            available=available, active=active, mode=mode, gpus=list(_state.gpus),
            cudaVersion=_state.cuda_version, backend=backend,  # type: ignore[arg-type]
            lastCheck=_state.last_check.strftime("%Y-%m-%dT%H:%M:%SZ"), checking=_state.checking, error=error, note=note,
        )


def xp() -> Any:
    """Return the active array module: cupy when CUDA is active with the cupy backend, else numpy."""
    st = status()
    if st.active == "cuda" and st.backend == "cupy":
        with _state.lock:
            if _state.cupy is not None:
                return _state.cupy
    return np


def asnumpy(arr: Any) -> np.ndarray:
    """Convert an array from the active backend to numpy."""
    if isinstance(arr, np.ndarray):
        return arr
    get = getattr(arr, "get", None)
    if callable(get):
        return get()
    return np.asarray(arr)


# --------------------------------------------------------------------------- device budget
# Everything that wants to push a big array to the GPU asks HERE first, and does it in bounded chunks.
# The failure this exists to prevent is real: a 1.16 GB one-shot `cupy.asarray` could not allocate the
# pinned host staging buffer, warned, and fell back to a SYNCHRONOUS transfer that pinned the process at
# 100 % CPU for minutes. Deciding before transferring, and then transferring 64 MB at a time, means the
# staging allocation is never the thing that fails.

H2D_CHUNK = 64 << 20        # bytes per host→device copy


def device_memory() -> Optional[tuple[int, int]]:
    """(free, total) device bytes, or None when there is no queryable CUDA device."""
    ap = xp()
    if ap is np:
        return None
    try:
        free, total = ap.cuda.runtime.memGetInfo()
        return int(free), int(total)
    except Exception:
        return None


def gpu_budget_bytes(fraction: float = 0.5) -> int:
    """How many device bytes a caller may claim right now (0 = no GPU / unknown)."""
    mem = device_memory()
    if mem is None:
        return 0
    return int(mem[0] * fraction)


def gpu_fits(need: int, fraction: float = 0.5) -> tuple[bool, str]:
    """Can `need` bytes be claimed on the device? Returns (ok, reason-when-not)."""
    mem = device_memory()
    if mem is None:
        return False, "no CUDA device is active"
    free, _total = mem
    if need > free * fraction:
        return False, (f"it needs {need / 1e6:.0f} MB and only {free / 1e6:.0f} MB of device memory is free")
    return True, ""


def to_device(arr: np.ndarray, chunk: int = H2D_CHUNK) -> Any:
    """Copy a C-contiguous numpy array onto the active GPU backend in bounded chunks.

    Raises whatever the backend raises (the caller decides to fall back); never leaves a partial array
    reachable. Falls back to the plain path for backends without cupy's `.set()`.
    """
    ap = xp()
    if ap is np:
        return arr
    a = np.ascontiguousarray(arr)
    if a.nbytes <= chunk or a.ndim != 1:
        return ap.asarray(a)
    dev = ap.empty(a.shape, dtype=a.dtype)
    setter = getattr(dev, "set", None)
    if not callable(setter):  # pragma: no cover - non-cupy backend
        return ap.asarray(a)
    step = max(1, chunk // max(1, a.itemsize))
    for s in range(0, a.shape[0], step):
        dev[s:s + step].set(a[s:s + step])
    return dev


def _loop() -> None:
    while not _state.stop.wait(REPROBE_SECONDS):
        try:
            probe()
        except Exception as exc:  # pragma: no cover
            with _state.lock:
                _state.error = str(exc)
                _state.no_gpu_libs = False  # the probe itself failed — that is a real error, not a CPU install


def start_background(initial: bool = True) -> None:
    if _state.thread and _state.thread.is_alive():
        return
    _state.stop.clear()
    if initial:
        threading.Thread(target=probe, name="compute-initial-probe", daemon=True).start()
    _state.thread = threading.Thread(target=_loop, name="compute-reprobe", daemon=True)
    _state.thread.start()


def stop_background() -> None:
    _state.stop.set()
    time.sleep(0)
