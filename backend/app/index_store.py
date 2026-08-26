"""Persist the packed SEARCH INDEX so a restart does not re-pack the whole pool.

Measured on the analyst's workspace: 11,180,062 events, a 5.4 GB packed buffer, **164.7 s to build**.
It is a pure-Python loop (`packed += _doc(e)` per event) and it does not vectorise, so every restart
and every crash-restart cost that again — and until it lands, every search takes the scan path, which
measured 35-45 s per query on this pool. That is the "constantly pending with the spinner" the
analyst reported: not one slow query, a three-minute window after every start in which every query is
slow.

The pool that comes back after a restart is byte-identical (see `pool_store`), so the index built
from it is the same index. This writes it out and reads it back:

* **Raw arrays, not a pickle.** The payload is a small JSON header followed by `text`, `offsets`,
  `sev`, `source`, `ts` and the byte histogram, written with `ndarray.tofile` and read with
  `np.fromfile`. Nothing here can execute code on load, and neither side ever materialises a second
  copy of a 5.4 GB buffer the way `pickle.dumps` would.
* **Still HMAC-tagged**, streamed in blocks. Not because of code execution — because a corrupted or
  edited index does not fail loudly, it silently changes which events a query finds, and "the search
  missed it" is the failure this project exists to prevent. The tag costs ~5 s against a 165 s build.
* **The key is the pool's CONTENT plus the packing code** — `graph_store.signature()` (every source's
  id/file/count/range plus the total) and a digest of `search.py` + the parser/normalize sources, so a
  changed `_doc()` or a changed parser can never serve an index built by the old one.
* **Saved from the HOST arrays, before any device transfer**, so persisting never pulls 5.4 GB back
  off the GPU.

It is a cache: any mismatch, short read, bad tag or exception is a miss, and the index is rebuilt.
`IRIS_INDEX_CACHE=0` disables it, `clear-all` wipes `cache/`, and deleting the file is always safe.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any, Optional

import numpy as np

from . import config, sealed

INDEX_FORMAT = 1
_MAGIC = b"IRISIDX1"
_TAG = 32
_BLOCK = 8 << 20
_ARRAYS = ("text", "offsets", "sev", "source", "ts", "byte_counts")


def enabled() -> bool:
    return os.environ.get("IRIS_INDEX_CACHE", "1").strip().lower() not in ("0", "false", "no", "off")


def _dir() -> Path:
    return config.CACHE_DIR


def _path() -> Path:
    return _dir() / "search-index.iris"


_CODE_UNUSABLE: "Optional[str]" = None


def _unusable_code_digest(exc: BaseException) -> str:
    """A digest nothing on disk can ever match, memoised so one process agrees with itself."""
    global _CODE_UNUSABLE
    if _CODE_UNUSABLE is None:
        _CODE_UNUSABLE = "unusable-" + os.urandom(8).hex()
        _log(f"cannot hash the packing code ({type(exc).__name__}: {exc}); "
             f"the index cache is disabled for this process rather than risk serving "
             f"a buffer packed by different code")
    return _CODE_UNUSABLE


def _code_digest() -> str:
    """The code that decides what the packed buffer CONTAINS — not the code that searches it.

    This hashed the whole of `search.py`, so tuning a query path threw away a 5.4 GB index that only
    `_doc` and `build_index` determine, and the next restart paid a 3.5-minute rebuild during which
    every search fell back to the scan. The two functions below are the ones whose output is stored;
    everything else in that module reads the result.
    """
    import inspect

    from . import pool_store, search

    h = hashlib.sha256()
    try:
        for fn in (search._doc, search.build_index):
            h.update(inspect.getsource(fn).encode("utf-8"))
        h.update(str(search._SEP + search._FSEP + search._END).encode("utf-8"))
    except (OSError, TypeError, AttributeError) as exc:
        # The SAME bug `pool_store._unusable_digest` documents, one level up, and worse here: this
        # digest is what says WHICH `_doc()` packed the buffer, and the artefact is the 4.1 GB
        # search index. A CONSTANT is a value two different builds both produce, so an index packed
        # by a build that could not read its own sources is a HIT for any other build that also
        # cannot (a .pyc-only or frozen deploy fails `inspect.getsource` on every boot, so it writes
        # and reads under the same constant forever). The answer would then be a query resolved
        # against text packed by a different `_doc` — wrong rows, no error, a green `vector` badge.
        # A per-process token degrades this run instead: nothing on disk can match it, so the index
        # is rebuilt and re-saved rather than served wrongly.
        return _unusable_code_digest(exc)
    h.update(pool_store.pipeline_digest().encode("utf-8"))
    return h.hexdigest()[:16]


def signature(store: Any) -> str:
    """What the index was built FROM. Same string -> the same events in the same order."""
    from . import graph_store

    try:
        return f"{INDEX_FORMAT}:{_code_digest()}:{graph_store.signature(store, 'all')}"
    except Exception:                                   # noqa: BLE001 — no signature = no cache
        return ""


def _log(msg: str) -> None:
    print(f"[iris] search index cache: {msg}")


# --------------------------------------------------------------------------- save
def save(idx: Any, sig: str, arrays: dict[str, np.ndarray]) -> bool:
    """Write the host-side arrays of a freshly built index. `arrays` must hold every name in _ARRAYS."""
    if not enabled() or not sig:
        return False
    missing = [k for k in _ARRAYS if k not in arrays or arrays[k] is None]
    if missing:
        _log(f"not saving: {', '.join(missing)} missing from the build")
        return False
    t0 = time.perf_counter()
    path = _path()
    tmp = path.with_suffix(".tmp")
    try:
        header = {
            "format": INDEX_FORMAT, "sig": sig, "n": int(idx.n), "version": int(idx.version),
            "sources": list(idx.sources), "savedAt": time.time(),
            "arrays": [{"name": k, "dtype": arrays[k].dtype.str, "count": int(arrays[k].size)} for k in _ARRAYS],
        }
        blob = json.dumps(header).encode("utf-8")
        _dir().mkdir(parents=True, exist_ok=True)
        mac = hmac.new(sealed.key(), digestmod=hashlib.sha256)
        with open(tmp, "wb") as fh:
            fh.write(_MAGIC)
            fh.write(bytes(_TAG))                      # the tag lands here once the payload is known
            head = len(blob).to_bytes(8, "little")
            fh.write(head)
            mac.update(head)
            fh.write(blob)
            mac.update(blob)
            for k in _ARRAYS:
                a = np.ascontiguousarray(arrays[k])
                a.tofile(fh)                            # streams; never a 5.4 GB bytes() copy
                for off in range(0, a.nbytes, _BLOCK):  # tag it in blocks, from the same memory
                    mac.update(memoryview(a).cast("B")[off:off + _BLOCK])
            fh.flush()
            fh.seek(len(_MAGIC))
            fh.write(mac.digest())
        os.replace(tmp, path)
        _log(f"saved {path.stat().st_size >> 20} MB in {time.perf_counter() - t0:.1f}s")
        return True
    except Exception as exc:                            # noqa: BLE001 — a cache never breaks a build
        _log(f"save failed ({type(exc).__name__}: {exc}); the index stays in memory only")
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False


# --------------------------------------------------------------------------- load
def load(sig: str) -> Optional[dict[str, Any]]:
    """{'header', 'arrays', 'raw'} for the CURRENT pool, or None. Never raises.

    ONE pass, into preallocated buffers. Two things made the first version slow, and the measurements
    on the analyst's 5.66 GB index are why they are worth naming:

    * it verified the tag in a streaming pass and then read everything AGAIN to build the arrays —
      10.8 GB of I/O for a 5.4 GB index;
    * it read the packed buffer with one `fh.read(5.4 GB)`, a single enormous allocation on a process
      already holding an 11 M-event pool.

    Together: 166 s, against 43 s for the same bytes read in blocks (131 MB/s through the bind mount)
    — and sha256 over them costs nothing measurable on top, because it overlaps the read. So: read
    each array once into a preallocated `bytearray` with `readinto`, hashing each block as it lands,
    and check the tag before anything is RETURNED. Nothing here executes on load (raw arrays, not a
    pickle), so verifying at the end costs only the result being discarded if the check fails.

    The `text` buffer is kept as the `bytearray` itself: it has `.find` (the CPU search path) and
    `np.frombuffer` shares the same memory, so neither view costs a copy.
    """
    if not enabled() or not sig:
        return None
    path = _path()
    if not path.is_file():
        return None
    t0 = time.perf_counter()
    try:
        with open(path, "rb") as fh:
            if fh.read(len(_MAGIC)) != _MAGIC:
                return None
            tag = fh.read(_TAG)
            mac = hmac.new(sealed.key(), digestmod=hashlib.sha256)

            head = fh.read(8)
            mac.update(head)
            hlen = int.from_bytes(head, "little")
            if hlen <= 0 or hlen > (16 << 20):
                return None
            blob = fh.read(hlen)
            mac.update(blob)
            header = json.loads(blob.decode("utf-8"))
            if header.get("format") != INDEX_FORMAT or header.get("sig") != sig:
                return None

            arrays: dict[str, np.ndarray] = {}
            raw_text: Optional[bytearray] = None
            for spec in header.get("arrays") or []:
                name, count = str(spec["name"]), int(spec["count"])
                dtype = np.dtype(spec["dtype"])
                want = count * dtype.itemsize
                buf = bytearray(want)
                view = memoryview(buf)
                got = 0
                while got < want:
                    n = fh.readinto(view[got:min(got + _BLOCK, want)])
                    if not n:
                        _log("short read; rebuilding")
                        return None
                    mac.update(view[got:got + n])
                    got += n
                if name == "text":
                    raw_text = buf
                arrays[name] = np.frombuffer(buf, dtype=dtype)

            if fh.read(1):
                _log("trailing data; rebuilding")
                return None
            if not hmac.compare_digest(tag, mac.digest()):
                _log("the file was not written by this install; rebuilding")
                return None
            if any(k not in arrays for k in _ARRAYS):
                return None
        _log(f"loaded {int(header['n']):,} events in {time.perf_counter() - t0:.1f}s "
             f"(skipped a full re-pack)")
        return {"header": header, "arrays": arrays, "raw": raw_text}
    except Exception as exc:                            # noqa: BLE001 — corrupt cache = miss
        _log(f"unreadable ({type(exc).__name__}: {exc}); rebuilding")
        return None


def clear() -> None:
    try:
        _path().unlink(missing_ok=True)
    except OSError:
        pass
