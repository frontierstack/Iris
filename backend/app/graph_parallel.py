"""Compatibility shim. The multi-process extraction moved to `graph_parts` (per source, with a
per-source partial cache); this name is kept so existing imports and the env vars keep working."""
from .graph_parts import (  # noqa: F401
    CHUNK_EVENTS, CHUNK_TIMEOUT, MAX_WORKERS, MIN_PARALLEL_EVENTS, GraphBuildCancelled, _Det, _Row,
    ProcessPoolExecutor, _reported, build, chunk_events, extract_chunk, groups_of, pack, workers,
    workers_by_memory,
)


def should_parallelise(n: int) -> bool:
    from .graph_parts import min_parallel_events
    return workers() >= 2 and n >= min_parallel_events()
