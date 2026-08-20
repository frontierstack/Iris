"""Tool-call arguments a small model wrote badly must not cost the run its work.

Reported twice, from the analyst's own local gateway, mid-investigation:

    build_case_graph  refused — could not parse the arguments you sent
                      (unexpected end of data: line 1 column 3314 (char 3313))
    add_note          refused — … (unexpected end of data: line 1 column 2308 (char 2308))

Both are the same fact: the ARGUMENT TEXT RAN OUT OF TOKENS. `build_case_graph` may draw 40 links with
prose and citations and `add_note` writes a whole write-up, and the turn was capped at 1400 tokens —
about 3.3 kB once the model has also written prose. So the first fix is the budget, the second is the
mechanical repair here, and the third is telling the model its call never ran instead of ending a
27-call investigation on a sampling accident.
"""
from __future__ import annotations

import orjson

from app.ai.argrepair import repair_arguments
from app.ai.investigator import _bad_args_message, tool_turn_tokens


def test_valid_json_is_returned_untouched_and_reports_no_repair():
    obj, notes = repair_arguments('{"a": 1, "b": ["x"]}')
    assert obj == {"a": 1, "b": ["x"]}
    assert notes == []


def test_the_reported_failure_a_call_cut_off_mid_string():
    """The live shape: a links array truncated inside the last item's `why`."""
    good = [{"source": f"ip:10.0.0.{i}", "target": "host:web-1", "relation": "connected_to",
             "why": "seen in the proxy log", "citedEventIds": [f"e{i:x}"]} for i in range(3)]
    blob = orjson.dumps({"links": good}).decode()
    cut = blob[:blob.rindex(chr(125)+chr(44)+chr(123)) + 40]          # stops inside the FOURTH... i.e. mid-object
    obj, notes = repair_arguments(cut)
    assert obj is not None, "a truncated call must be salvageable"
    assert [l["source"] for l in obj["links"]] == ["ip:10.0.0.0", "ip:10.0.0.1"]
    assert any("CUT OFF" in n for n in notes), "dropping an item must always be reported"


def test_truncation_inside_a_top_level_note_keeps_the_complete_fields():
    obj, notes = repair_arguments('{"caseId": "3", "text": "## Findings\nthe host ')
    assert obj == {"caseId": "3"}
    assert any("CUT OFF" in n for n in notes)


def test_a_raw_newline_inside_a_string_is_escaped():
    obj, notes = repair_arguments('{"text": "line one\nline two"}')
    assert obj == {"text": "line one\nline two"}
    assert any("control character" in n for n in notes)


def test_an_unescaped_quote_inside_a_string_is_escaped_not_treated_as_the_end():
    obj, notes = repair_arguments('{"why": "the user said "no" and left", "n": 2}')
    assert obj == {"why": 'the user said "no" and left', "n": 2}
    assert any("unescaped quote" in n for n in notes)


def test_a_trailing_comma_is_dropped():
    obj, notes = repair_arguments('{"ids": ["e1", "e2",],}')
    assert obj == {"ids": ["e1", "e2"]}
    assert any("trailing comma" in n for n in notes)


def test_nothing_salvageable_is_refused_rather_than_guessed():
    assert repair_arguments("")[0] is None
    assert repair_arguments("I will now call build_case_graph.")[0] is None
    assert repair_arguments("[1, 2, 3]")[0] is None, "arguments must be an object"


def test_the_refusal_names_truncation_because_send_valid_json_is_unactionable():
    cut = _bad_args_message(ValueError("unexpected end of data: line 1 column 3314 (char 3313)"), "")
    assert "CUT OFF" in cut and "fewer items" in cut
    # a finish_reason of 'length' says the same thing even when the parser's wording does not
    assert "CUT OFF" in _bad_args_message(ValueError("nope"), "length")
    assert "Send valid JSON" in _bad_args_message(ValueError("invalid character"), "stop")


def test_the_turn_budget_is_big_enough_for_a_full_batch_of_links(monkeypatch):
    """1400 tokens is where the analyst's runs died; the default must clear a real call."""
    monkeypatch.delenv("IRIS_AI_MAX_TOOL_TOKENS", raising=False)
    assert tool_turn_tokens() >= 4096
    monkeypatch.setenv("IRIS_AI_MAX_TOOL_TOKENS", "8000")
    assert tool_turn_tokens() == 8000
    monkeypatch.setenv("IRIS_AI_MAX_TOOL_TOKENS", "not a number")
    assert tool_turn_tokens() == 4096


def test_a_cut_inside_a_nested_value_does_not_leave_a_half_link_behind():
    """Truncation two levels down must not promote a partial object into the array."""
    cut = ('{"links": [{"source": "ip:1.1.1.1", "target": "host:a", "relation": "ran"}, '
           '{"source": "ip:2.2.2.2", "meta": {"note": "half a sen')
    obj, notes = repair_arguments(cut)
    assert obj == {"links": [{"source": "ip:1.1.1.1", "target": "host:a", "relation": "ran"}]}
    assert any("CUT OFF" in n for n in notes)


def test_truncating_a_real_call_anywhere_never_raises_and_never_lies():
    """Every prefix of a valid call: repaired to a real object, or refused. Never an exception, and
    never a value the model did not finish writing."""
    call = {"caseId": "3", "text": "the host was reached from 45.83.140.22",
            "links": [{"source": f"ip:10.0.0.{i}", "target": "host:web-1", "relation": "connected_to",
                       "why": "proxy log", "citedEventIds": [f"e{i:x}"]} for i in range(4)],
            "confidence": 0.8}
    blob = orjson.dumps(call).decode()
    salvaged = 0
    for n in range(1, len(blob)):
        obj, notes = repair_arguments(blob[:n])
        if obj is None:
            continue
        salvaged += 1
        for link in obj.get("links", []):
            assert link in call["links"], "a repaired item must be one the model actually finished"
        if obj.get("text"):
            assert obj["text"] == call["text"]
        assert notes, "anything but a clean parse must be reported"
    assert salvaged > len(blob) // 2, "most prefixes of a real call should be salvageable"


# --------------------------------------------------------------- the loop, end to end
import asyncio                                                          # noqa: E402

import pytest                                                          # noqa: E402
from fastapi.testclient import TestClient                              # noqa: E402

from app.ai import investigator, runs as ai_runs                       # noqa: E402
from app.ai.client import BadToolArguments                             # noqa: E402
from app.main import app                                               # noqa: E402
from app.store import STORE                                            # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


class _Provider:
    """A model whose tool arguments reach the loop EXACTLY as the provider sent them.

    The FakeModel in test_ai_investigator.py serialises its arguments with json.dumps, which is the
    one thing that cannot happen here — the whole failure is a blob that is not valid JSON.
    """

    def __init__(self, turns):
        self.turns = list(turns)
        self.model = "local-model"
        self.configured = True
        self.max_tokens = 0
        self.seen: list[list[dict]] = []

    async def stream_chat(self, messages, tools=None, max_tokens=1400, temperature=0.1, tool_choice="auto"):
        self.seen.append([dict(m) for m in messages])
        self.max_tokens = max_tokens
        turn = self.turns.pop(0) if self.turns else {"text": "Done."}
        if turn.get("providerRefuses"):
            raise BadToolArguments("HTTP 500: Failed to parse tool call arguments as JSON: parse error "
                                   "at line 1, column 3326")
        msg = {"role": "assistant", "content": turn.get("text", "")}
        if turn.get("call") and tool_choice != "none":
            name, blob = turn["call"]
            msg["tool_calls"] = [{"id": "c1", "type": "function",
                                  "function": {"name": name, "arguments": blob}}]
        yield {"type": "message", "message": msg,
               "finish": turn.get("finish") or ("tool_calls" if msg.get("tool_calls") else "stop")}


def _drive(turns, objective="what happened?"):
    p = _Provider(turns)
    rid = ai_runs.new_id()

    async def go():
        return [ev async for ev in investigator.investigate(STORE, objective, rid, client=p)]

    return asyncio.run(go()), p


def test_a_truncated_call_is_repaired_run_and_declared(client):
    """The reported failure, end to end: the call runs instead of being refused — and the analyst is
    told, because a repaired write that lands nine of ten links must never look like ten."""
    evs, _ = _drive([
        {"call": ("search_events", '{"query": "failed login", "limit": 5, "sources": ["ngin'),
         "finish": "length"},
        {"text": "Nothing further."},
    ])
    calls = [e for e in evs if e["type"] == "tool_call"]
    assert calls and calls[0]["arguments"]["query"] == "failed login"
    assert "sources" not in calls[0]["arguments"], "an unfinished value must never be passed on"
    results = [e for e in evs if e["type"] == "tool_result"]
    assert results[0]["ok"] is True
    assert results[0]["data"].get("argumentsRepaired"), "the model must be told what it actually sent"
    warn = [e for e in evs if e["type"] == "warning"]
    assert any("repaired" in w["message"] for w in warn)


def test_arguments_that_cannot_be_salvaged_are_refused_with_actionable_advice(client):
    evs, _ = _drive([
        {"call": ("search_events", "I will search for failed logins"), "finish": "length"},
        {"text": "Nothing further."},
    ])
    res = [e for e in evs if e["type"] == "tool_result"]
    assert res and res[0]["ok"] is False
    assert "CUT OFF" in res[0]["data"]["error"] and "fewer items" in res[0]["data"]["error"]


def test_the_provider_refusing_the_arguments_does_not_end_the_investigation(client):
    """A 27-call investigation used to die here with `AIError`. The turn never happened, so the model
    is told that and asked for a smaller call."""
    evs, p = _drive([
        {"providerRefuses": True},
        {"text": "Here is the answer."},
    ])
    done = evs[-1]
    assert done["type"] == "done" and done["reason"] == "complete"
    assert any("could not parse the tool-call arguments" in w["message"]
               for w in evs if w["type"] == "warning")
    assert any("YOUR LAST TOOL CALL DID NOT RUN" in str(m.get("content"))
               for m in p.seen[-1]), "the model was never told its call had not run"


def test_the_run_still_fails_if_it_never_stops_happening(client):
    evs, p = _drive([{"providerRefuses": True} for _ in range(investigator.MAX_ARG_FAILURES + 2)])
    last = evs[-1]
    assert last["type"] == "error" and "parse" in last["message"].lower()


def test_the_loop_asks_for_more_tokens_than_the_budget_that_caused_this(client):
    _, p = _drive([{"text": "Done."}])
    assert p.max_tokens >= 4096, "1400 tokens is what cut build_case_graph off at 3.3 kB"
