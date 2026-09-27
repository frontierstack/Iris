"""WHAT THE PROVIDER CAN RUN, and on which model — read from the provider, not guessed.

The analyst's gateway (Open-Source-Model-Manager over llama.cpp) exposes several loaded models, each
with its own number of inference slots, plus a pool alias (`auto`) that sends each request to
whichever member has a free slot. `GET {base}/models` says all of it:

    Qwen3.8-27B   slots 1   n_params 27.3 B   context 131,072
    Qwen3.6-14B   slots 2   n_params 13.8 B   context 131,072
    auto          slots 3   capacity.models = [both of the above]

Iris used to treat the configured model as ONE unit with a yes/no "does it run two requests at
once" verdict, and that cost quality twice over. Measured on that gateway with the model set to
`auto` (every request's `model` field read back from the stream):

* the LEAD landed on the 14B model on every turn, and so did the delegation PLANNER, although the
  27B model sat idle - the pool hands a request to whichever slot is free and the smaller model has
  more of them. The analyst chose `auto` to get more agents, not a weaker lead.
* the agents were spread blindly: which model an agent ran on was the pool's accident.

So the capacity is DISCOVERED and scheduled:

* the lead runs on the STRONGEST member of a pool alias (by parameter count, then context window).
  A concrete model the analyst named is never changed - that is a choice, not a pool.
* workers are placed on real models with free slots, strongest first, each placed only on a model
  whose context window holds a worker's prompt, optionally restricted to `settings.ai.workerModels`.
  Width = min(the analyst's agent setting, the free slots found).
* a provider that does not describe itself (OpenAI proper, most gateways) gets `None` everywhere,
  and every caller falls back to what it did before: the configured model and the timing probe.

Nothing here ever raises into a run: a provider that cannot be read is simply not described.
"""
from __future__ import annotations

import copy
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

#: How long a discovered pool is trusted. SHORT, because `free` moves with every request.
POOL_TTL = 20.0
#: ...and how long "this provider does not describe itself" is trusted, so a plain OpenAI endpoint
#: is not asked for its model list at every delegation.
MISS_TTL = 300.0
DISCOVERY_TIMEOUT = 6.0
#: Tokens a worker's request needs: ~4.6k of compact schemas, the worker prompt and task, and a
#: transcript `subagents._fit` holds under 56k characters. A model with a smaller window is skipped.
WORKER_MIN_CONTEXT = 24_000


@dataclass
class ModelCap:
    id: str
    slots: int = 0
    free: Optional[int] = None
    context: int = 0
    params: int = 0
    backend: str = ""

    @property
    def short(self) -> str:
        """The folder or file a gateway id names: `/models/Qwen3.8-27B-…-GGUF/x.gguf` -> `Qwen3.8-27B-…-GGUF`."""
        parts = [p for p in self.id.replace("\\", "/").split("/") if p]
        if len(parts) >= 2 and parts[-1].lower().endswith(".gguf"):
            return parts[-2]
        return parts[-1] if parts else self.id

    def available(self) -> int:
        return max(0, self.free if self.free is not None else self.slots)


@dataclass
class Pool:
    models: list[ModelCap] = field(default_factory=list)          # real, loaded models
    aliases: dict[str, list[str]] = field(default_factory=dict)   # alias id -> member ids
    llamacpp: bool = False                                        # the backend honours chat_template_kwargs

    def find(self, name: str) -> Optional[ModelCap]:
        n = (name or "").strip()
        if not n:
            return None
        for m in self.models:
            if m.id == n:
                return m
        low = n.lower()
        hits = [m for m in self.models if m.short.lower() == low] or \
               [m for m in self.models if low in m.id.lower()]
        return hits[0] if len(hits) == 1 else None

    def members(self, configured: str) -> list[ModelCap]:
        """The real models a configured name can run on: the alias's members, or the model itself."""
        if configured in self.aliases:
            out = [self.find(x) for x in self.aliases[configured]]
            return [m for m in out if m is not None]
        m = self.find(configured)
        return [m] if m else []

    def is_alias(self, configured: str) -> bool:
        return configured in self.aliases


def strength(m: ModelCap) -> tuple[int, int]:
    return (m.params, m.context)


def _int(v: Any) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def parse(data: Any) -> Optional[Pool]:
    """A `/models` answer -> Pool, or None when it says nothing about slots (an ordinary provider)."""
    rows = data.get("data") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        return None
    pool = Pool()
    described = False
    for r in rows:
        if not isinstance(r, dict) or not r.get("id"):
            continue
        cap = r.get("capacity") if isinstance(r.get("capacity"), dict) else {}
        meta = r.get("meta") if isinstance(r.get("meta"), dict) else {}
        members = cap.get("models")
        if isinstance(members, list) and members:
            pool.aliases[str(r["id"])] = [str(x) for x in members]
            described = True
            continue
        slots = _int(cap.get("slots")) or _int(r.get("max_concurrency")) or _int(meta.get("total_slots"))
        if slots:
            described = True
        free = cap.get("free")
        backend = str(cap.get("backend") or r.get("owned_by") or "")
        pool.llamacpp = pool.llamacpp or "llama" in backend.lower()
        pool.models.append(ModelCap(
            id=str(r["id"]), slots=slots, free=_int(free) if free is not None else None,
            context=_int(r.get("context_window")) or _int(meta.get("n_ctx")),
            params=_int(meta.get("n_params")), backend=backend))
    return pool if described and pool.models else None


_CACHE: dict[str, tuple[Optional[Pool], float]] = {}
_LOCK = threading.Lock()


def forget() -> None:
    with _LOCK:
        _CACHE.clear()


def _key(client: Any) -> str:
    return str(getattr(client, "resolved_base", None) or getattr(client, "base_url", "") or "").rstrip("/")


def cached(client: Any) -> Optional[Pool]:
    with _LOCK:
        hit = _CACHE.get(_key(client))
    if hit and time.monotonic() - hit[1] < (POOL_TTL if hit[0] else MISS_TTL):
        return hit[0]
    return None


async def discover(client: Any, *, fresh: bool = False) -> Optional[Pool]:
    """The provider's own description of its models and slots, or None. Never raises.

    Only a real `LLMClient` is asked (it has `candidate_bases` and `_headers`); a scripted test
    provider is not a gateway and has no model list to read.
    """
    if not callable(getattr(client, "_headers", None)) or not getattr(client, "configured", False):
        return None
    key = _key(client)
    if not key:
        return None
    with _LOCK:
        hit = _CACHE.get(key)
    if hit and not fresh and time.monotonic() - hit[1] < (POOL_TTL if hit[0] else MISS_TTL):
        return hit[0]
    pool: Optional[Pool] = None
    try:
        async with httpx.AsyncClient(timeout=DISCOVERY_TIMEOUT, verify=getattr(client, "verify", True)) as hc:
            r = await hc.get(f"{key}/models", headers=client._headers(False))
            if r.status_code < 400:
                pool = parse(r.json())
    except Exception:  # noqa: BLE001 — a provider that cannot be read is simply not described
        pool = None
    with _LOCK:
        _CACHE[key] = (pool, time.monotonic())
    return pool


def lead_model(pool: Optional[Pool], configured: str) -> Optional[str]:
    """The model the LEAD should run on: the strongest member of a pool alias, else None (keep it)."""
    if pool is None or not pool.is_alias(configured):
        return None
    members = pool.members(configured)
    if not members or not any(m.params for m in members):
        return None           # no way to tell which is stronger - leave the pool to route
    return max(members, key=strength).id


def worker_models(pool: Optional[Pool], configured: str, want: int, override: Optional[list[str]] = None,
                  min_context: int = WORKER_MIN_CONTEXT, free_only: bool = True) -> Optional[list[str]]:
    """One model id per worker SLOT, strongest model first, at most `want`; None when unknown.

    `configured` is what the analyst set (a pool alias or a model). `override` is
    `settings.ai.workerModels`: when it names models this provider has, only those are used.
    The list may be SHORTER than `want` - that is the free capacity, and the caller's width.
    `free_only=False` counts every slot, busy or not: "could this provider EVER run two agents".
    """
    if pool is None:
        return None
    cands: list[ModelCap] = []
    for name in override or []:
        m = pool.find(name)
        if m is not None and m not in cands:
            cands.append(m)
    if not cands:
        # a pool alias schedules across its own members; a concrete model the analyst named is the
        # LEAD's, and the workers may use every loaded model - that is the gateway's capacity
        cands = pool.members(configured) if pool.is_alias(configured) else list(pool.models)
    if not cands:
        return None
    fit = [m for m in cands if not m.context or m.context >= min_context]
    out: list[str] = []
    for m in sorted(fit, key=strength, reverse=True):
        out.extend([m.id] * (m.available() if free_only else max(0, m.slots)))
    return out[:max(0, want)]


def with_model(client: Any, model: str) -> Any:
    """A copy of `client` that sends `model`. Shallow on purpose: one base, one key, one TLS setting."""
    if not model or getattr(client, "model", None) == model:
        return client
    c = copy.copy(client)
    c.model = model
    return c


def short_name(model: str) -> str:
    return ModelCap(id=model or "").short


#: What a llama.cpp backend is asked for when a request should not reason at length. Measured on
#: the analyst's gateway: the same small prompt answered in 0.7 s with it and 2.3 s without, and
#: inside runs the 14B model's reasoning ran away on worker turns - 120 s cuts, 2.4-3.7 MB of
#: `reasoning_content` each, three of them in one delegation - and on the planner (120 s, no plan).
NO_THINKING = {"chat_template_kwargs": {"enable_thinking": False}}


def without_thinking(client: Any, pool: Optional[Pool]) -> Any:
    """A copy of `client` that asks the model not to think - only on a backend the provider itself
    reported as llama.cpp. Anything else is returned unchanged: an unknown key in the body is a 400
    on some providers, so it is only sent where the provider has said what it is."""
    if pool is None or not pool.llamacpp or not callable(getattr(client, "_headers", None)):
        return client
    c = copy.copy(client)
    c.extra_body = dict(NO_THINKING)
    return c
