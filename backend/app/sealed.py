"""HMAC-tagged blobs for the on-disk caches under `$IRIS_DATA_DIR/cache/`.

Both caches (the built entity graph, the parsed pool) are pickles in a bind-mounted directory, so
anyone who can drop a file there could hand `pickle.load` a payload of their choosing — arbitrary
code in the app process. Every cache file therefore carries an HMAC-SHA256 over its exact bytes
under a per-install random key; a missing, foreign or edited tag is a cache MISS, never a load and
never a crash.

The key lives next to the caches (`cache/graph.key`, 0600 where the OS allows it). Losing it costs
one rebuild — that is the whole blast radius, which is why generating a new one on the spot is the
right failure mode for an unreadable key file. `clear-all` wipes the tree, key included.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import threading
from typing import Optional

from . import config

_MAGIC = b"IRISSEAL"
_KEY_LOCK = threading.Lock()
_KEY: Optional[bytes] = None


def key() -> bytes:
    global _KEY
    with _KEY_LOCK:
        if _KEY is not None:
            return _KEY
        path = config.CACHE_DIR / "graph.key"
        try:
            data = path.read_bytes()
            if len(data) < 32:
                raise ValueError("short key")
        except (OSError, ValueError):
            data = os.urandom(32)
            try:
                config.CACHE_DIR.mkdir(parents=True, exist_ok=True)
                tmp = path.with_suffix(".tmp")
                tmp.write_bytes(data)
                try:
                    os.chmod(tmp, 0o600)
                except OSError:
                    pass          # Windows / bind mounts: best effort, the tag is the control
                os.replace(tmp, path)
            except OSError:
                pass              # unwritable cache dir: keep the in-process key, the cache just misses
        _KEY = data
        return _KEY


def reset_key() -> None:
    """Forget the cached key (after clear-all deleted the file, and in tests)."""
    global _KEY
    with _KEY_LOCK:
        _KEY = None


def seal(blob: bytes, magic: bytes = _MAGIC) -> bytes:
    return magic + hmac.new(key(), blob, hashlib.sha256).digest() + blob


def unseal(data: bytes, magic: bytes = _MAGIC) -> Optional[bytes]:
    """The payload bytes, or None if this file was not written by this install."""
    n = len(magic)
    if len(data) < n + 32 or not data.startswith(magic):
        return None
    tag, blob = data[n:n + 32], data[n + 32:]
    return blob if hmac.compare_digest(tag, hmac.new(key(), blob, hashlib.sha256).digest()) else None
