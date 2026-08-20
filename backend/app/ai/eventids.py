"""What an event id LOOKS like — one definition, because three places were guessing at it.

Ids are hexadecimal, not decimal (`store._append_events`: `f"e{n:x}"`), so a case event is `e1 … e79f`
and a library event is `l<8 hex source id><hex counter>`, e.g. `l6e2c94f91078ed`. Both
`ai/compaction.py` and `ai/continuation.py` matched `e\\d{1,9}` — decimal only — which silently missed
every id past `e9` that contains a letter. Those two modules use this to carry citations across a
context compaction and into a follow-up turn, so a pattern that misses ids does not fail loudly: it
drops the evidence behind a finding, and the citation validator then flags the model's own correct
claim as uncited.

Matching is not verification. Anything found here is checked against the live pool before it is ever
treated as a citation (`tools.verify_event_ids`), because a plausible-looking id is exactly what a
model invents.
"""
from __future__ import annotations

import re

# `e` + hex for a case event, `l` + hex for a library one. Bounded lengths so a long hex blob in a log
# line (a hash, a GUID fragment) cannot be mistaken for an id.
EVENT_ID = r"(?:e[0-9a-f]{1,10}|l[0-9a-f]{9,24})"

#: an id written in backticks — how the agent is told to cite, and the only form worth trusting first
BACKTICKED = re.compile(rf"`({EVENT_ID})`")
#: a bare id, for text that was never marked up (a compacted transcript, a tool result)
BARE = re.compile(rf"\b({EVENT_ID})\b")


def find(text: str, *, backticked_first: bool = True, cap: int = 200) -> list[str]:
    """Ids mentioned in `text`, in order, de-duplicated.

    `backticked_first` returns ONLY the backticked ones when there are any. In prose that is the
    deliberate citation, and falling straight through to bare tokens would let an ordinary hex-looking
    word ride along — harmless once verification runs, but the narrower answer is the honest one.
    """
    out: list[str] = []
    if backticked_first:
        for m in BACKTICKED.finditer(text or ""):
            if m.group(1) not in out:
                out.append(m.group(1))
            if len(out) >= cap:
                return out
        if out:
            return out
    for m in BARE.finditer(text or ""):
        if m.group(1) not in out:
            out.append(m.group(1))
        if len(out) >= cap:
            break
    return out
