"""Repairing tool-call arguments a small model wrote badly.

The analyst's local gateway produced this, repeatedly, mid-investigation:

    build_case_graph  refused — could not parse the arguments you sent
    (unexpected end of data: line 1 column 3314 (char 3313)). Send valid JSON.

and the same run also died on the provider's own version of it (HTTP 500 "Failed to parse tool call
arguments as JSON … column 3326"). Both numbers are the point: ~3.3 kB of argument text is roughly
where a 1400-token reply RUNS OUT. The arguments were not gibberish — they were CUT OFF mid-string,
because `build_case_graph` may draw up to 40 links and each carries prose and citations. The first
fix is therefore the token budget (see `investigator.tool_turn_tokens`); this module is the second,
because a model that writes JSON by sampling will still occasionally leave an unescaped quote or a
raw newline inside a long string.

What this does NOT do is guess at meaning. It performs exactly four mechanical repairs, each of which
either succeeds or leaves the call refused:

  * escape raw control characters (a literal newline/tab) inside a string;
  * escape a `"` that is clearly inside a string rather than ending it (the next non-space character
    is not one of `, : } ]`);
  * drop a trailing comma before a `}` / `]`;
  * for a TRUNCATED blob, discard the incomplete trailing element and close the open containers.

The last one loses data, so it is always reported. Every caller must surface the returned notes:
a repaired write that silently drew nine of the ten links the model meant is precisely the
silent-omission bug this project keeps fighting. `investigator` streams them as a `warning` (never
folded in the panel) and hands them back to the model in the tool result, so it can send the rest.
"""
from __future__ import annotations

from typing import Any, Optional

import orjson

# A repair is only attempted on blobs of a sane size; past this the input is not a truncated call,
# it is something else entirely and the refusal is the honest answer.
MAX_INPUT = 2_000_000

_ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t", "\b": "\\b", "\f": "\\f"}
_VALUE_END = ",:}]"


def repair_arguments(raw: str) -> tuple[Optional[dict[str, Any]], list[str]]:
    """(arguments, what was repaired). `None` when the blob cannot be salvaged.

    Never raises. An empty note list with a real object means the text parsed cleanly.
    """
    if not isinstance(raw, str) or not raw.strip() or len(raw) > MAX_INPUT:
        return (None, [])
    obj = _load(raw)
    if obj is not None:
        return (obj, [])
    notes: list[str] = []
    text = _strip_fence(raw)
    start = text.find("{")
    if start < 0:
        return (None, notes)
    if start > 0:
        notes.append("dropped text written before the JSON object")
    text = text[start:]
    fixed, fnotes = _rebuild(text)
    obj = _load(fixed)
    if obj is None:
        return (None, notes)
    return (obj, notes + fnotes)


def _load(text: str) -> Optional[dict[str, Any]]:
    try:
        obj = orjson.loads(text)
    except (orjson.JSONDecodeError, ValueError, TypeError):
        return None
    return obj if isinstance(obj, dict) else None


def _strip_fence(text: str) -> str:
    s = text.strip()
    if s.startswith("```"):
        s = s[3:]
        if s[:4].lower() == "json":
            s = s[4:]
        end = s.rfind("```")
        if end >= 0:
            s = s[:end]
    return s.strip()


def _drop_trailing_comma(out: list[str]) -> bool:
    i = len(out) - 1
    while i >= 0 and out[i].strip() == "":
        i -= 1
    if i >= 0 and out[i] == ",":
        del out[i:]
        return True
    return False


def _rebuild(s: str) -> tuple[str, list[str]]:
    """One pass, character by character, tracking string state and the open containers.

    `stack` holds `[closer, safe_len]` per open container: `safe_len` is the length of the output at
    the last point where that container held only COMPLETE elements — set when a `,` is seen at its
    own depth and when a child container closes. Truncating back to it is what makes dropping the
    incomplete trailing element exact rather than a guess at where the last value began.
    """
    out: list[str] = []
    stack: list[list[Any]] = []
    in_str = esc = False
    ctrl = quotes = commas = 0
    n = len(s)
    i = 0
    while i < n:
        ch = s[i]
        if in_str:
            if esc:
                out.append(ch)
                esc = False
            elif ch == "\\":
                out.append(ch)
                esc = True
            elif ch == '"':
                j = i + 1
                while j < n and s[j] in " \t\r\n":
                    j += 1
                if j >= n or s[j] in _VALUE_END:
                    in_str = False
                    out.append(ch)
                else:
                    # not the end of the value — the model wrote a bare quote inside its own string
                    out.append('\\"')
                    quotes += 1
            elif ch in _ESCAPES or ord(ch) < 0x20:
                out.append(_ESCAPES.get(ch) or "\\u%04x" % ord(ch))
                ctrl += 1
            else:
                out.append(ch)
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
        elif ch in "{[":
            out.append(ch)
            stack.append(["}" if ch == "{" else "]", len(out), len(out) - 1])
        elif ch in "}]":
            if _drop_trailing_comma(out):
                commas += 1
            out.append(ch)
            if stack:
                stack.pop()
            if stack:
                stack[-1][1] = len(out)
        elif ch == ",":
            if stack:
                stack[-1][1] = len(out)
            out.append(ch)
        else:
            out.append(ch)
        i += 1

    notes: list[str] = []
    if ctrl:
        notes.append(f"escaped {ctrl} raw control character(s) inside a string")
    if quotes:
        notes.append(f"escaped {quotes} unescaped quote(s) inside a string")
    if commas:
        notes.append(f"removed {commas} trailing comma(s)")
    if in_str or stack:
        # Unwinding, innermost first, and an OBJECT is not treated like an ARRAY:
        #   * an unclosed object that has a parent is DROPPED WHOLE. It is a record the model never
        #     finished — a link holding only its `source`, an ioc with no `value` — and a half-record
        #     promoted into the call is the silent-corruption case this whole module must not create.
        #   * an unclosed array keeps the elements that ARE complete and is closed. A shorter list is
        #     an honest partial, and the note says items were dropped.
        #   * the OUTERMOST container is always salvaged, whatever it is: dropping it means no call at
        #     all, and a missing required argument is refused by the tool's own schema check anyway.
        # A salvage that comes out empty (`{}` / `[]`) is then dropped from its parent for the same
        # reason as the first rule.
        while stack:
            closer, safe, opened = stack.pop()
            if closer == "}" and stack:
                del out[opened:]
                _drop_trailing_comma(out)
                continue
            del out[safe:]
            _drop_trailing_comma(out)
            out.append(closer)
            if not stack:
                break
            if len(out) - opened <= 2:          # the salvage is `{}` / `[]` — nothing survived in it
                del out[opened:]
                _drop_trailing_comma(out)
            else:
                stack[-1][1] = len(out)
        notes.append("the arguments were CUT OFF mid-value (the reply hit its token limit): the "
                     "incomplete trailing item was dropped and the JSON closed")
    return ("".join(out), notes)
