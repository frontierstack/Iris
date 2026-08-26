"""LLM client over httpx (no SDKs): OpenAI chat-completions, streaming, with an optional baseUrl so any
OpenAI-compatible endpoint (Azure OpenAI gateways, vLLM, Ollama, LM Studio, OpenRouter...) works through the same provider."""
from __future__ import annotations

import re
import time
from typing import Any, AsyncIterator, Optional
from urllib.parse import urlsplit

import httpx
import orjson

from ..models import AISettings

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"

_VERSION_SEG = re.compile(r"^v\d+([a-z0-9._-]*)$", re.I)  # v1, v2, v1beta, v1alpha1 …


def normalize_base_url(raw: str) -> str:
    """Turn whatever the analyst pasted into a base that `/chat/completions` can be appended to.

    Providers advertise their endpoint inconsistently — "https://host", "https://host/v1",
    "https://host/v1/chat/completions" all mean the same thing to a human. Appending blindly gave
    "https://host/chat/completions", which most gateways answer with a bare 404, so normalise:
      • drop trailing slashes and a pasted "/chat/completions" suffix
      • leave Azure OpenAI deployment URLs alone (they use their own path + api-version)
      • append "/v1" when the path doesn't already end in a version segment
    """
    url = (raw or "").strip().rstrip("/")
    if not url:
        return DEFAULT_BASE_URL
    for suffix in ("/chat/completions", "/completions"):
        if url.lower().endswith(suffix):
            url = url[: -len(suffix)].rstrip("/")
            break
    if "/deployments/" in url.lower():  # Azure OpenAI — caller knows exactly what it wants
        return url
    # Look for a version segment anywhere in the PATH (not the host: "v2.example.com" is a hostname, not an API
    # version). Gemini's compat endpoint ends "/v1beta/openai", so checking only the last segment got it wrong.
    path = urlsplit(url if "//" in url else "//" + url).path
    if any(_VERSION_SEG.match(seg) for seg in path.split("/") if seg):
        return url
    return url + "/v1"


class AIError(Exception):
    pass


class ContextTooLong(AIError):
    """The provider refused the request because the TRANSCRIPT no longer fits the model's context window.

    Reported live as `openai HTTP 400 at .../v1/chat/completions (the response body is in the server log)`
    followed by the run dying. The analyst's gateway (llama.cpp, context shift enabled) refuses a
    PROMPT larger than n_ctx outright; context shift only helps with generated tokens. Iris's own
    compaction threshold (IRIS_AI_MAX_CONTEXT_TOKENS, an estimate) sat above the real window, so Iris
    never compacted and the provider said no. This is the signal the investigator compacts on: it is
    not a failure of the run, it is the moment to fold the transcript and carry on.

    `limit` / `requested` are the token counts when the body states them (OpenAI-style "maximum
    context length is 8192 tokens ... you requested 9021"), else 0. Only those two integers are taken
    from the body; see `_http_error` for why the body itself is never echoed.
    """

    def __init__(self, message: str, status: int = 400, limit: int = 0, requested: int = 0) -> None:
        super().__init__(message)
        self.status = status
        self.limit = limit
        self.requested = requested


class ProviderUnavailable(AIError):
    """A TRANSIENT provider failure: 5xx, 429, a timeout, a dropped connection. Worth retrying.

    The investigator retries these a bounded number of times with a backoff before failing the run;
    nothing of the turn has reached the transcript when they happen, so re-sending is safe. A 4xx
    that is not a context overflow is NOT one of these: a wrong key or URL will not fix itself.
    """

    def __init__(self, message: str, status: int = 0) -> None:
        super().__init__(message)
        self.status = status


class BadToolArguments(AIError):
    """The provider could not parse the ARGUMENTS the model wrote for a tool call.

    A subclass of AIError so every existing handler still catches it, and a distinct type so
    `stream_chat` can retry exactly this one case. It is not a capability problem and must never be
    reported as one.
    """


# ---------------------------------------------------------------- text-mode tool calls
# Not every model/gateway pairing does NATIVE tool calling. When `tools` never reaches the model — an
# older gateway that drops unknown body keys, a served template that has no tool grammar, a model whose
# chat template renders tools as documentation — the model still tries to act, and it writes the call out
# in whatever text syntax it was trained on. The analyst saw exactly that leak into a final report:
#
#   <tool_call><function=create_case><parameter=name>…</parameter></function></tool_call>
#
# with invented parameters (`severity`, `status`) that no Iris tool declares — the signature of a model
# guessing rather than being handed a schema. Printing that at an analyst is the worst of the options, so
# these forms are PARSED into real tool calls where possible and REPORTED where not; either way they are
# stripped out of prose before anything is shown or persisted.
_TC_BLOCK = re.compile(r"<tool_call>\s*(.*?)\s*(?:</tool_call>|\Z)", re.S | re.I)
_FN_BLOCK = re.compile(r"<function\s*=\s*([A-Za-z0-9_.-]+)\s*>(.*?)(?:</function>|\Z)", re.S | re.I)
_PARAM = re.compile(r"<parameter\s*=\s*([A-Za-z0-9_.-]+)\s*>(.*?)(?:</parameter>|\Z)", re.S | re.I)
# a bare <function=…> call with no <tool_call> wrapper, plus the older ```tool_call fenced form
_BARE_FN = re.compile(r"<function\s*=\s*[A-Za-z0-9_.-]+\s*>.*?(?:</function>|\Z)", re.S | re.I)
_FENCED = re.compile(r"```(?:tool_call|tool_code|function_call)\s*(.*?)```", re.S | re.I)


def _coerce(value: str) -> Any:
    """A <parameter> body is always text; recover the obvious JSON scalars so ints/bools survive."""
    s = value.strip()
    if s[:1] in "[{" or s in ("true", "false", "null") or re.fullmatch(r"-?\d+(\.\d+)?", s or "x"):
        try:
            return orjson.loads(s)
        except orjson.JSONDecodeError:
            return value
    return value


def _calls_from_fragment(frag: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for name, body in _FN_BLOCK.findall(frag):
        args = {k: _coerce(v) for k, v in _PARAM.findall(body)}
        out.append({"name": name, "arguments": args})
    if out:
        return out
    try:
        obj = orjson.loads(frag.strip())
    except (orjson.JSONDecodeError, TypeError, ValueError):
        return out
    for item in (obj if isinstance(obj, list) else [obj]):
        if isinstance(item, dict) and item.get("name"):
            args = item.get("arguments") if item.get("arguments") is not None else item.get("parameters")
            out.append({"name": str(item["name"]), "arguments": args if isinstance(args, dict) else {}})
    return out


def parse_text_tool_calls(text: str) -> tuple[str, list[dict[str, Any]]]:
    """(prose with the call syntax removed, assembled tool_calls). Never raises."""
    if not text or "<tool_call" not in text.lower() and "<function=" not in text.lower() \
            and "```tool_call" not in text.lower():
        return text or "", []
    found: list[dict[str, Any]] = []
    cleaned = text
    for rx in (_TC_BLOCK, _FENCED):
        for frag in rx.findall(cleaned):
            found.extend(_calls_from_fragment(frag))
        cleaned = rx.sub("", cleaned)
    if not found:
        for frag in _BARE_FN.findall(cleaned):
            found.extend(_calls_from_fragment(frag))
    cleaned = _BARE_FN.sub("", cleaned)
    calls = [{"id": f"text_call_{i}", "type": "function",
              "function": {"name": c["name"], "arguments": orjson.dumps(c.get("arguments") or {}).decode()}}
             for i, c in enumerate(found) if c.get("name")]
    return cleaned.strip(), calls


# Streaming deltas arrive a few characters at a time, so the markup above is half-written when it
# reaches the panel: the analyst watched `<tool_call><function=` type itself out before the parser could
# see a whole block. `_hold_split` is the fix — a delta is only released once it CANNOT be the beginning
# of a call marker. Anything from a real marker onward is held to the end of the turn, where the buffer
# goes through parse_text_tool_calls and only the cleaned prose is emitted. Never stream what you may
# have to retract.
_CALL_STARTS = ("<tool_call", "<function=", "```tool_call", "```tool_code", "```function_call")
_CALL_START_MAX = max(len(m) for m in _CALL_STARTS)


def _hold_split(buf: str) -> tuple[str, str]:
    """(prose safe to stream now, text to keep buffered)."""
    low = buf.lower()
    cut = min([i for i in (low.find(m) for m in _CALL_STARTS) if i != -1], default=-1)
    if cut != -1:
        return buf[:cut], buf[cut:]
    # No complete marker — hold back a tail that could still grow into one ("…the <func" ).
    for n in range(min(_CALL_START_MAX - 1, len(buf)), 0, -1):
        tail = low[-n:]
        if any(m.startswith(tail) for m in _CALL_STARTS):
            return buf[:-n], buf[-n:]
    return buf, ""


def has_tool_call_syntax(text: str) -> bool:
    """True when raw tool-call markup is still present — used to keep it out of a final report."""
    low = (text or "").lower()
    return "<tool_call" in low or "<function=" in low or "```tool_call" in low


def resolve_verify(verify_tls: bool = True, ca_bundle: str = "") -> Any:
    """httpx `verify` value: False when the user disabled verification, else a CA bundle path if one is
    configured / auto-discovered ($IRIS_CA_BUNDLE, <data dir>/ca.pem, <data dir>/ca.crt), else True (certifi).

    `ca_bundle` comes from SETTINGS, i.e. over the API, so it is confined to the data dir. Any absolute
    path was accepted before, which made an unauthenticated `PUT /api/settings` + one AI call into an
    existence oracle for arbitrary server paths (the failure differs for a missing file, an unreadable
    one and a file that is not a certificate). The env vars are NOT confined — they are set by whoever
    starts the process, who can already read the disk. Drop `ca.pem` in the data dir for the common case.
    """
    if not verify_tls:
        return False
    import os
    from pathlib import Path
    from .. import config
    env = [os.environ.get("IRIS_CA_BUNDLE", ""), os.environ.get("SSL_CERT_FILE", ""),
           os.environ.get("REQUESTS_CA_BUNDLE", "")]
    candidates = [_settings_ca_path(ca_bundle), *env, str(config.DATA_DIR / "ca.pem"), str(config.DATA_DIR / "ca.crt")]
    for c in candidates:
        if c and Path(c).is_file():
            return c
    return True


def _settings_ca_path(ca_bundle: str) -> str:
    """A settings-supplied CA bundle, resolved under DATA_DIR, or "" if it escapes (or cannot be resolved).

    A relative path is taken as relative to the data dir, which is what the Settings field means anyway.
    """
    from pathlib import Path
    from .. import config
    raw = (ca_bundle or "").strip()
    if not raw:
        return ""
    try:
        root = config.DATA_DIR.resolve()
        p = Path(raw)
        p = (root / p) if not p.is_absolute() else p
        p = p.resolve()
        if p == root or root not in p.parents:
            return ""
        return str(p)
    except (OSError, ValueError):
        return ""


class LLMClient:
    def __init__(self, provider: str, model: str = "", base_url: str = "", api_key: str = "", timeout: float = 120.0,
                 verify_tls: bool = True, ca_bundle: str = "") -> None:
        from ..config import migrate_provider  # local import: config imports models, keep the graph acyclic

        self.provider = migrate_provider(provider)
        self.model = model or DEFAULT_MODEL
        self.base_url = normalize_base_url(base_url)
        self.resolved_base: Optional[str] = None  # candidate that actually answered, cached after the first call
        self.api_key = api_key
        self.timeout = timeout
        # NO READ TIMEOUT on a generation. `timeout=120.0` set all four httpx timeouts, so a model that
        # thought for longer than that before its first token — an ordinary thing for a local gateway on
        # a large prompt, and the whole point of a deep investigation — had its answer cut off and
        # reported as a transport failure. Nothing about a slow REPLY is a fault to recover from: the
        # analyst has Stop, and a run has its own wall clock (settings.ai.maxSeconds, which they can
        # switch off). What stays bounded is everything that indicates a broken PEER rather than a
        # thinking one: connect, write, and acquiring a pool slot. A dead host still fails in seconds.
        self.http_timeout = httpx.Timeout(timeout, connect=15.0, write=30.0, pool=15.0, read=None)
        self.verify = resolve_verify(verify_tls, ca_bundle)

    @classmethod
    def from_settings(cls, s: AISettings) -> "LLMClient":
        return cls(s.provider, s.model, s.baseUrl, s.apiKey, verify_tls=s.verifyTls, ca_bundle=s.caBundle)

    @property
    def configured(self) -> bool:
        return self.provider == "openai"

    def _http_error(self, status: int, body: str, url: str, tried: Optional[list[str]] = None) -> str:
        """A 4xx from a gateway is usually a wrong URL or model — say which one we called, not just the code.

        THE UPSTREAM BODY IS NOT ECHOED. It used to be, ~300 bytes of it, and `POST /api/ai/test`
        returns this string in its 200 response — which turned a blind request-forgery into one that
        reads back whatever the chosen host replied with. The body is logged server-side, where the
        analyst can see it and an attacker cannot. What is kept is what actually helps configure the
        thing: the status, the URL Iris called, and the bases it tried.
        """
        print(f"[iris] ai: HTTP {status} from {url}: {body.strip()[:300]}")
        msg = f"openai HTTP {status} at {url} (the response body is in the server log)"
        if status == 404:
            msg += (f" — no chat endpoint there. Check the base URL points at the OpenAI-compatible root"
                    f" (Iris appends /chat/completions) and that the model '{self.model}' exists on this provider.")
            if tried and len(tried) > 1:
                msg += " Tried: " + ", ".join(tried) + "."
        elif status == 401:
            msg += " — the API key was rejected by this endpoint."
        return msg

    def candidate_bases(self) -> list[str]:
        """Bases to try, best guess first.

        Self-hosted gateways disagree about where the OpenAI-compatible API lives, and the path a user
        copies out of a web UI is often a *different* API on the same host (an admin/management route that
        answers 200 on /models but has no /chat/completions). Rather than dead-end on a 404, try the
        conventional alternatives on the same origin before giving up.
        """
        out: list[str] = []

        def add(u: str) -> None:
            u = u.rstrip("/")
            if u and u not in out:
                out.append(u)

        add(self.base_url)
        if "/deployments/" in self.base_url.lower():
            return out  # Azure: the caller's path is exact, never second-guess it
        parts = urlsplit(self.base_url)
        root = f"{parts.scheme}://{parts.netloc}"
        path = parts.path.rstrip("/")
        # the configured path with the version segment stripped back off (in case appending /v1 was wrong)
        unversioned = re.sub(r"/v\d+[a-z0-9._-]*$", "", path, flags=re.I)
        if unversioned != path:
            add(root + unversioned)
        add(root + "/v1")        # by far the most common layout
        add(root + "/api/v1")
        add(root + "/openai/v1")
        add(root)
        return out

    async def _probe_bases(self, client: "httpx.AsyncClient") -> Optional[str]:
        """GET {base}/models on each candidate; return the first that looks like a real model list."""
        for base in self.candidate_bases():
            try:
                r = await client.get(f"{base}/models", headers=self._headers(False), timeout=8.0)
            except httpx.HTTPError:
                continue
            if r.status_code < 400 and ("model" in r.text[:400].lower()):
                return base
        return None

    def _headers(self, stream: bool) -> dict[str, str]:
        h = {"Content-Type": "application/json", "Accept": "text/event-stream" if stream else "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def _body(self, system: str, user: str, temperature: float, stream: bool,
              json_mode: bool = False) -> dict[str, Any]:
        # NO `max_tokens` — see `_chat_body`. The model's budget is the model's to keep.
        body: dict[str, Any] = {"model": self.model, "stream": stream, "temperature": temperature,
                                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        return body

    def _chat_body(self, messages: list[dict[str, Any]], temperature: float, stream: bool,
                   tools: Optional[list[dict[str, Any]]] = None, tool_choice: str = "auto") -> dict[str, Any]:
        """Body for a MULTI-TURN chat with optional tools (the investigator loop).

        `messages` is the running transcript — system, user, assistant (possibly with tool_calls) and
        role='tool' results — exactly as the OpenAI chat-completions schema defines it, so any
        compatible gateway that supports function calling works unchanged.

        **Iris sends NO `max_tokens`, here or anywhere else**, on the analyst's instruction: no token
        limit in Iris at all, the backend model handles tokens. The reason is on the record — a cap
        Iris picks is a cap Iris cannot pick correctly. It was 1400, which cut `build_case_graph` off
        at char 3313 and `add_note` at char 2308 mid-argument, and the provider then refused the whole
        call as invalid JSON. Every gateway already enforces its own ceiling and knows its own context
        window; a second, smaller, blind limit in front of it can only truncate replies the model was
        going to finish. Never reintroduce it — not as a default, not as a setting.
        `ai/argrepair.py` stays as the salvage for a reply the PROVIDER truncates.
        """
        body: dict[str, Any] = {"model": self.model, "stream": stream,
                                "temperature": temperature, "messages": messages}
        if tools:
            body["tools"] = tools
            body["tool_choice"] = tool_choice
        return body

    # -------------------------------------------------------------- streaming
    async def stream(self, system: str, user: str, temperature: float = 0.2) -> AsyncIterator[str]:
        """Yield text deltas from a chat completion."""
        if not self.configured:
            raise AIError("AI provider is not configured (settings.ai.provider = none)")
        body = self._body(system, user, temperature, stream=True)
        # A 404 means "no chat endpoint here", not "request rejected" — walk the other conventional
        # layouts on this origin before failing, and remember whichever one answers.
        bases = [self.resolved_base] if self.resolved_base else self.candidate_bases()
        async with httpx.AsyncClient(timeout=self.http_timeout, verify=self.verify) as client:
            for i, cand in enumerate(bases):
                url = f"{cand}/chat/completions"
                async with client.stream("POST", url, headers=self._headers(True), content=orjson.dumps(body)) as resp:
                    if resp.status_code in (404, 405) and i < len(bases) - 1:
                        await resp.aread()
                        continue
                    if resp.status_code >= 400:
                        text = (await resp.aread()).decode(errors="replace")
                        raise AIError(self._http_error(resp.status_code, text, url, tried=bases))
                    self.resolved_base = cand
                    async for chunk in self._read_stream(resp):
                        yield chunk
                    return

    async def _read_stream(self, resp: "httpx.Response") -> AsyncIterator[str]:
        """Decode an SSE chat-completion response into text deltas."""
        ctype = resp.headers.get("content-type", "")
        if "text/event-stream" not in ctype and "stream" not in ctype:
            # non-streaming reply (some compatible servers ignore stream=true)
            data = orjson.loads(await resp.aread())
            yield _openai_text(data)
            return
        async for line in resp.aiter_lines():
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if payload == "[DONE]":
                break
            try:
                data = orjson.loads(payload)
            except orjson.JSONDecodeError:
                continue
            if isinstance(data, dict) and data.get("error"):
                err = data["error"]
                raise AIError(str(err.get("message", err) if isinstance(err, dict) else err))
            for choice in data.get("choices", []):
                delta = choice.get("delta") or {}
                text = delta.get("content")
                if text:
                    yield text

    # ------------------------------------------------------------ tool calling
    async def stream_chat(self, messages: list[dict[str, Any]], tools: Optional[list[dict[str, Any]]] = None,
                          temperature: float = 0.1,
                          tool_choice: str = "auto") -> AsyncIterator[dict[str, Any]]:
        """One turn — retried ONCE if the model wrote tool arguments the provider could not parse.

        That failure is a sampling accident, not a capability: the request was accepted, the model was
        called, and one argument blob came back malformed. Nothing has been yielded when it happens (the
        provider answers 4xx/5xx before any token reaches us), so re-sending is safe and the next sample
        is usually clean. Measured on the analyst's own gateway, which answered HTTP 500 "Failed to parse
        tool call arguments as JSON … column 315" mid-investigation and ended the run with a message
        telling them to change model.

        Exactly one retry, and it is taken at temperature 0: the retry exists to get a CLEANER sample
        of the same call, and sampling is what produced the unescaped quote. A model that cannot emit
        valid JSON for this call will not learn to on the third attempt, and a run that silently
        re-asks a provider forever is worse than a clear failure — past this the investigator loop
        takes over, tells the model its call never ran and asks for a smaller one (prompts.ARG_TOO_BIG).
        """
        try:
            async for item in self._stream_once(messages, tools, temperature, tool_choice):
                yield item
            return
        except BadToolArguments:
            pass
        async for item in self._stream_once(messages, tools, 0.0, tool_choice):
            yield item

    async def _stream_once(self, messages: list[dict[str, Any]], tools: Optional[list[dict[str, Any]]] = None,
                           temperature: float = 0.1,
                           tool_choice: str = "auto") -> AsyncIterator[dict[str, Any]]:
        """One turn of a tool-using conversation, streamed.

        Yields `{"type":"text","text":delta}` while the model writes prose and exactly one terminal
        `{"type":"message","message":{role,content,tool_calls},"finish":str}` carrying the assembled
        assistant message — which the caller appends to the transcript verbatim before executing the
        tool calls. Tool-call arguments arrive as a *string* split across deltas (that is how the wire
        format works); they are concatenated per `index` here and parsed by the caller, because a
        provider that returns malformed JSON must be reported as a tool error, not crash the run.
        """
        if not self.configured:
            raise AIError("AI provider is not configured (settings.ai.provider = none)")
        body = self._chat_body(messages, temperature, True, tools, tool_choice)
        bases = [self.resolved_base] if self.resolved_base else self.candidate_bases()
        try:
            async for item in self._stream_bases(body, bases, tools):
                yield item
        except httpx.HTTPError as exc:
            # ConnectError, ReadTimeout, RemoteProtocolError (the gateway closed the stream mid-reply),
            # ReadError: none of these is a fact about the transcript, so the caller may retry the turn.
            raise ProviderUnavailable(f"could not reach the AI provider ({type(exc).__name__}: {exc})") from exc

    async def _stream_bases(self, body: dict[str, Any], bases: list[str],
                            tools: Optional[list[dict[str, Any]]]) -> AsyncIterator[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=self.http_timeout, verify=self.verify) as client:
            for i, cand in enumerate(bases):
                url = f"{cand}/chat/completions"
                async with client.stream("POST", url, headers=self._headers(True), content=orjson.dumps(body)) as resp:
                    if resp.status_code in (404, 405) and i < len(bases) - 1:
                        await resp.aread()
                        continue
                    if resp.status_code >= 400:
                        text = (await resp.aread()).decode(errors="replace")
                        # Checked BEFORE _rejects_tools: this body contains "tool" and "invalid", so the
                        # capability check matches it and blames the model's tool-calling SUPPORT for
                        # what is really one malformed argument blob.
                        if tools and _model_wrote_bad_json(resp.status_code, text):
                            raise BadToolArguments(
                                f"the model produced tool-call arguments this endpoint could not parse as "
                                f"JSON ({url}, HTTP {resp.status_code}: {text.strip()[:200]}). This is NOT "
                                f"a missing capability — '{self.model}' IS calling tools and the provider "
                                f"is passing them through; the ARGUMENTS came back malformed, usually an "
                                f"unescaped quote or newline inside a long string. If it keeps happening, "
                                f"prefer a model with constrained/grammar-based tool output, or ask for "
                                f"less in one call.")
                        if _context_overflow(resp.status_code, text):
                            limit, requested = _context_numbers(text)
                            raise ContextTooLong(
                                f"the conversation no longer fits the model's context window - the provider "
                                f"refused the request (HTTP {resp.status_code} at {url}"
                                + (f", limit {limit:,} tokens" if limit else "")
                                + (f", requested {requested:,}" if requested else "") + ")",
                                status=resp.status_code, limit=limit, requested=requested)
                        if _transient_status(resp.status_code):
                            raise ProviderUnavailable(self._http_error(resp.status_code, text, url, tried=bases),
                                                      status=resp.status_code)
                        if tools and _rejects_tools(resp.status_code, text):
                            # Fail LOUDLY and specifically. Retrying without `tools` would produce a model
                            # that cannot act, narrating tool calls it never made — which is the failure
                            # this whole path exists to prevent.
                            raise AIError(
                                f"this endpoint rejected the tool definitions ({url}, HTTP {resp.status_code}: "
                                f"{text.strip()[:200]}). The Iris investigator needs a model that supports "
                                f"OpenAI-style tool calling — '{self.model}' on this provider does not. "
                                f"Choose a tool-calling model in Settings → AI assistant.")
                        raise AIError(self._http_error(resp.status_code, text, url, tried=bases))
                    self.resolved_base = cand
                    async for item in self._read_tool_stream(resp):
                        yield item
                    return

    async def _read_tool_stream(self, resp: "httpx.Response") -> AsyncIterator[dict[str, Any]]:
        ctype = resp.headers.get("content-type", "")
        if "text/event-stream" not in ctype and "stream" not in ctype:
            # some compatible servers ignore stream=true — take the whole message in one go
            data = orjson.loads(await resp.aread())
            choice = (data.get("choices") or [{}])[0]
            msg = choice.get("message") or {}
            text = msg.get("content") or ""
            if text:
                shown, _ = parse_text_tool_calls(text)
                if shown:
                    yield {"type": "text", "text": shown}
            yield {"type": "message", "message": _clean_assistant(msg),
                   "finish": choice.get("finish_reason") or ""}
            return
        content: list[str] = []
        calls: dict[int, dict[str, Any]] = {}
        held = ""
        finish = ""
        async for line in resp.aiter_lines():
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if payload == "[DONE]":
                break
            try:
                data = orjson.loads(payload)
            except orjson.JSONDecodeError:
                continue
            if isinstance(data, dict) and data.get("error"):
                err = data["error"]
                raise AIError(str(err.get("message", err) if isinstance(err, dict) else err))
            for choice in data.get("choices", []):
                if choice.get("finish_reason"):
                    finish = str(choice["finish_reason"])
                delta = choice.get("delta") or {}
                text = delta.get("content")
                if text:
                    content.append(text)
                    safe, held = _hold_split(held + text)
                    if safe:
                        yield {"type": "text", "text": safe}
                for tc in delta.get("tool_calls") or []:
                    idx = int(tc.get("index") or 0)
                    slot = calls.setdefault(idx, {"id": "", "type": "function", "function": {"name": "", "arguments": ""}})
                    if tc.get("id"):
                        slot["id"] = str(tc["id"])
                    fn = tc.get("function") or {}
                    if fn.get("name"):
                        slot["function"]["name"] = str(fn["name"])
                    if fn.get("arguments"):
                        slot["function"]["arguments"] += str(fn["arguments"])
        if held:
            # The turn ended with buffered text: emit only what survives markup stripping.
            tail, _ = parse_text_tool_calls(held)
            if tail:
                yield {"type": "text", "text": tail}
        msg: dict[str, Any] = {"role": "assistant", "content": "".join(content)}
        if calls:
            ordered = [calls[k] for k in sorted(calls)]
            for n, c in enumerate(ordered):
                if not c["id"]:
                    c["id"] = f"call_{n}"
            msg["tool_calls"] = ordered
        yield {"type": "message", "message": msg, "finish": finish}

    # ------------------------------------------------------------ non-stream
    async def complete(self, system: str, user: str, temperature: float = 0.2) -> str:
        parts: list[str] = []
        async for chunk in self.stream(system, user, temperature):
            parts.append(chunk)
        return "".join(parts)

    async def complete_json(self, system: str, user: str, temperature: float = 0.0) -> dict[str, Any]:
        """Single non-streaming request in JSON mode; falls back to a plain request if the server rejects response_format."""
        if not self.configured:
            raise AIError("AI provider is not configured (settings.ai.provider = none)")
        bases = [self.resolved_base] if self.resolved_base else self.candidate_bases()
        async with httpx.AsyncClient(timeout=self.http_timeout, verify=self.verify) as client:
            resp = None
            url = ""
            for i, cand in enumerate(bases):  # same endpoint walk as stream()
                url = f"{cand}/chat/completions"
                resp = await client.post(url, headers=self._headers(False),
                                         content=orjson.dumps(self._body(system, user, temperature, False, json_mode=True)))
                if resp.status_code in (404, 405) and i < len(bases) - 1:
                    continue
                self.resolved_base = cand
                break
            assert resp is not None
            if resp.status_code == 400 and b"response_format" in resp.content:
                resp = await client.post(url, headers=self._headers(False),
                                         content=orjson.dumps(self._body(system, user, temperature, False)))
            if resp.status_code >= 400:
                raise AIError(self._http_error(resp.status_code, resp.text, url, tried=bases))
            try:
                text = _openai_text(orjson.loads(resp.content))
            except orjson.JSONDecodeError:
                raise AIError("openai returned a non-JSON response")
        return parse_json_object(text)

    async def test(self) -> tuple[bool, str, Optional[int]]:
        if not self.configured:
            return False, "No provider selected", None
        t0 = time.perf_counter()
        try:
            text = await self.complete("You are a connectivity probe. Reply with the single word OK.", "ping",
                                       temperature=0.0)
        except AIError as exc:
            # Nothing served chat completions. Probe for a /models listing so we can name a base that
            # does respond, instead of leaving the analyst to guess the path.
            hint = ""
            try:
                async with httpx.AsyncClient(timeout=10.0, verify=self.verify) as probe:
                    found = await self._probe_bases(probe)
                if found and found != self.base_url:
                    hint = f" A model listing DOES answer at {found} — try that as the base URL."
            except httpx.HTTPError:
                pass
            return False, str(exc) + hint, None
        except httpx.ConnectError as exc:
            msg = str(exc)
            if "CERTIFICATE_VERIFY_FAILED" in msg or "certificate" in msg.lower():
                return False, ("TLS certificate verification failed (" + msg[:120] + "). A proxy/AV is likely re-signing HTTPS. "
                               "Fix: place its root CA as ca.pem in the Iris data dir (Docker: the iris-data volume, e.g. "
                               "`docker cp corp-root.pem iris:/data/ca.pem`) or set IRIS_CA_BUNDLE, then re-test. "
                               "As a last resort disable 'Verify TLS certificates' under Advanced."), None
            return False, f"connection error: {msg[:300]}", None
        except httpx.HTTPError as exc:
            return False, f"connection error: {exc}", None
        ms = int((time.perf_counter() - t0) * 1000)
        used = self.resolved_base or self.base_url
        # say which endpoint answered — it may not be the one that was typed in
        note = "" if used == self.base_url else f" (resolved to {used} — save this as the base URL)"
        return True, f"openai / {self.model} @ {used} responded: {text.strip()[:60] or '(empty)'}{note}", ms


def parse_json_object(text: str) -> dict[str, Any]:
    """Extract the first JSON object from a model reply (tolerates ```json fences and prose around it)."""
    s = text.strip()
    if s.startswith("```"):
        s = s.strip("`")
        if s.lower().startswith("json"):
            s = s[4:]
    start, end = s.find("{"), s.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise AIError("model reply contained no JSON object")
    try:
        obj = orjson.loads(s[start:end + 1])
    except orjson.JSONDecodeError as exc:
        raise AIError(f"model reply was not valid JSON: {exc}")
    if not isinstance(obj, dict):
        raise AIError("model reply was not a JSON object")
    return obj


_TOOLS_REJECTED = ("tool", "function")

# The provider parsed the request fine, called the model, and then FAILED TO PARSE WHAT THE MODEL WROTE:
#   HTTP 500 {"error":{"message":"Failed to parse tool call arguments as JSON: [json.exception.
#   parse_error.101] parse error at line 1, column 315: syntax error while parsing value …"}}
# That is a different fact from "this endpoint does not do tool calling", and reporting it as the latter
# sends the analyst to Settings to replace a model that is working. It is usually a sampling accident:
# one argument blob came back malformed (an unescaped quote or newline inside a long string is the
# common one) and the next sample is clean.
_ARG_PARSE_FAIL = (
    ("parse", "tool call argument"),
    ("parse error", "tool_call"),
    ("failed to parse", "arguments"),
)


_CTX_WORDS = ("context length", "context_length", "context window", "context size", "maximum context",
              "max context", "too many tokens", "prompt is too long", "prompt too long", "exceeds the available",
              "exceed the context", "exceeds the context", "reduce the length", "n_ctx", "input length",
              "tokens to process", "context shift", "request too large", "prompt_tokens")


def _context_overflow(status: int, body: str) -> bool:
    """Is this 4xx the provider saying the PROMPT does not fit its context window?

    OpenAI: 400 `context_length_exceeded` / "This model's maximum context length is N tokens".
    llama.cpp: 400 "the request exceeds the available context size. try increasing the context size or
    enable context shift". vLLM / Ollama / LM Studio say "input length", "prompt is too long",
    "context window". 413 is what a proxy in front of any of them says.
    """
    if status not in (400, 413, 422):
        return False
    low = (body or "").lower()
    return any(w in low for w in _CTX_WORDS)


_CTX_LIMIT_RE = re.compile(r"(?:maximum|max)[^.\d]{0,40}?(\d{3,7})\s*tokens", re.I)
_CTX_REQ_RE = re.compile(r"(?:requested|resulted in|your messages? (?:resulted in|contains?))\D{0,30}?(\d{3,8})\s*tokens", re.I)


def _context_numbers(body: str) -> tuple[int, int]:
    """(limit, requested) token counts from an overflow body, 0 when it does not state them."""
    def _n(rx: "re.Pattern[str]") -> int:
        m = rx.search(body or "")
        try:
            return int(m.group(1)) if m else 0
        except (TypeError, ValueError):
            return 0
    return _n(_CTX_LIMIT_RE), _n(_CTX_REQ_RE)


def _transient_status(status: int) -> bool:
    return status in (408, 425, 429, 500, 502, 503, 504)


def _model_wrote_bad_json(status: int, body: str) -> bool:
    if status < 400:
        return False
    low = (body or "").lower()
    return any(all(part in low for part in parts) for parts in _ARG_PARSE_FAIL)


def _rejects_tools(status: int, body: str) -> bool:
    """True when a 4xx is specifically about the `tools` / `tool_choice` body keys.

    A gateway that does not do tool calling answers either with a 400 naming the parameter or by
    ignoring it entirely (which is the case `absorb_text_calls` catches downstream). Both must be
    visible to the analyst; neither may be silently swallowed.
    """
    if status not in (400, 404, 422, 500, 501):
        return False
    low = (body or "").lower()
    if not any(t in low for t in _TOOLS_REJECTED):
        return False
    return any(w in low for w in ("not support", "unsupported", "unknown", "unrecognized", "unrecognised",
                                  "invalid", "not allowed", "no such", "unexpected"))


def absorb_text_calls(msg: dict[str, Any]) -> dict[str, Any]:
    """Turn a text-mode tool call into a real one, and never leave the markup in the prose.

    Applied by investigator.py to the assembled assistant message — one place, whatever client produced
    it. Only when the model produced NO native tool_calls: a provider that does tool calling properly is
    never second-guessed. `textToolCalls` marks the message so the investigator can say so in the
    transcript — a run silently working in text mode is a run that will surprise the analyst later.
    """
    if msg.get("tool_calls"):
        return msg
    content = msg.get("content") or ""
    if not has_tool_call_syntax(content):
        return msg
    cleaned, calls = parse_text_tool_calls(content)
    msg["content"] = cleaned
    if calls:
        msg["tool_calls"] = calls
        msg["textToolCalls"] = True
    else:
        msg["textToolCallsUnparsed"] = True
    return msg


def _clean_assistant(msg: dict[str, Any]) -> dict[str, Any]:
    """Keep only the fields the API accepts back on the next turn."""
    out: dict[str, Any] = {"role": "assistant", "content": msg.get("content") or ""}
    calls = msg.get("tool_calls")
    if isinstance(calls, list) and calls:
        out["tool_calls"] = [{"id": str(c.get("id") or f"call_{i}"), "type": "function",
                              "function": {"name": str((c.get("function") or {}).get("name") or ""),
                                           "arguments": str((c.get("function") or {}).get("arguments") or "")}}
                             for i, c in enumerate(calls)]
    return out


def _openai_text(data: dict) -> str:
    try:
        return data["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError):
        return ""
