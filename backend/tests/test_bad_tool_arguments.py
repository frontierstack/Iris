"""A provider that cannot parse the MODEL's tool arguments is not a provider without tool calling.

The analyst's gateway answered, mid-investigation:

    HTTP 500 {"error":{"code":500,"message":"Failed to parse tool call arguments as JSON:
    [json.exception.parse_error.101] parse error at line 1, column 315: syntax error while parsing
    value - invalid string: miss…"}}

and Iris reported: *"The Iris investigator needs a model that supports OpenAI-style tool calling —
'qwen3.8' on this provider does not."* That message is wrong and expensively wrong: the request was
accepted, the model DID call a tool, and the provider passed the definitions through. One argument blob
came back malformed — an unescaped quote or newline inside a long string is the usual cause — and the
advice sent the analyst off to replace a working model.

The body says "tool" and "invalid", which is exactly what the capability check looks for, so the new
check runs FIRST. And because the failure is a sampling accident with nothing yielded yet, the turn is
retried ONCE before it is reported.
"""
from __future__ import annotations

import asyncio

import pytest

from app.ai.client import AIError, BadToolArguments, LLMClient, _model_wrote_bad_json, _rejects_tools

BODY = ('{"error":{"code":500,"message":"Failed to parse tool call arguments as JSON: '
        '[json.exception.parse_error.101] parse error at line 1, column 315: syntax error while '
        'parsing value - invalid string: miss"}}')


def test_the_real_failure_is_recognised():
    assert _model_wrote_bad_json(500, BODY) is True
    # ...and it is exactly the body the capability check also matches, which is why order matters
    assert _rejects_tools(500, BODY) is True


@pytest.mark.parametrize("status,body", [
    (400, '{"error":{"message":"Unrecognized request argument supplied: tools"}}'),
    (400, '{"error":{"message":"tool_choice is not supported by this model"}}'),
])
def test_a_genuine_capability_refusal_is_not_mistaken_for_it(status, body):
    assert _model_wrote_bad_json(status, body) is False


def test_it_is_an_aierror_so_every_existing_handler_still_catches_it():
    assert issubclass(BadToolArguments, AIError)


class _Provider:
    """A gateway that fails to parse the model's arguments `fail_times` times, then succeeds."""

    def __init__(self, fail_times: int):
        self.fail_times = fail_times
        self.calls = 0

    async def stream(self, client, *_a, **_k):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise BadToolArguments("bad json")
        yield {"type": "message", "message": {"role": "assistant", "content": "done"}, "finish": "stop"}


def _drive(provider: _Provider) -> list[dict]:
    client = LLMClient("openai", "m", "http://x/v1", "k")
    client._stream_once = lambda *a, **k: provider.stream(client, *a, **k)   # type: ignore[assignment]

    async def go():
        return [x async for x in client.stream_chat([{"role": "user", "content": "hi"}], tools=[{}])]

    return asyncio.run(go())


def test_one_bad_sample_is_retried_and_the_turn_survives():
    p = _Provider(fail_times=1)
    out = _drive(p)
    assert p.calls == 2, "the turn must be re-sent once — nothing had been yielded"
    assert out[-1]["message"]["content"] == "done"


def test_it_gives_up_after_one_retry():
    """A model that cannot emit valid JSON will not learn to on the third attempt, and a run that
    silently re-asks forever is worse than a clear failure."""
    p = _Provider(fail_times=5)
    with pytest.raises(BadToolArguments):
        _drive(p)
    assert p.calls == 2


def test_a_clean_turn_is_not_retried():
    p = _Provider(fail_times=0)
    _drive(p)
    assert p.calls == 1
