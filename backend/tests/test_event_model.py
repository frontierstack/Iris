"""The pooled `Event` representation — the pool's memory ceiling, pinned.

`Event` stopped being a pydantic `BaseModel` because one instance per LOG LINE at ~1.9 kB was what made
the analyst's 1.07 GB `DNS_Logs.csv` unloadable. What replaced it only stays cheap while three things
hold, and each of them fails silently rather than loudly if it is undone, so each gets a test:

  * no `__dict__` (that is where the 8 x saving went);
  * the shared empty containers cannot be mutated in place — one event writing a field onto every other
    event in the pool is evidence fabrication, not a performance bug;
  * `msg` is derived from `raw` only where the two genuinely agree, and a parser-synthesised message
    (SQLite `summarise()`, EVTX, JSONL) survives verbatim.

Plus the boundary: a slotted object is not JSON-serializable and FastAPI will not encode it, so every
endpoint that returns events has to convert explicitly. That is checked against the real app.
"""
from __future__ import annotations

import pickle
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import EMPTY_FIELDS, EMPTY_LIST, Detection, Event, EventDetail, EventOut
from tests.conftest import drain_enrichment


def mk(**kw) -> Event:
    base = dict(id="e1", ts="2026-08-11T03:14:47Z", source="nginx.access", sourceId="s1", file="a.log",
                host="edge-lb-01", user="svc_deploy", msg="POST /api/v2/login 200", sev="critical",
                raw="45.83.140.22 svc_deploy 200")
    base.update(kw)
    return Event(**base)


# --------------------------------------------------------------------- representation
def test_an_event_has_no_instance_dict() -> None:
    """`__slots__` with no `__dict__` IS the saving. A stray class attribute or a base class without
    `__slots__` silently re-adds one and every event pays ~100 B plus its keys again."""
    e = mk()
    assert not hasattr(e, "__dict__")
    with pytest.raises(AttributeError):
        e.not_a_real_attribute = "x"  # type: ignore[attr-defined]
    assert "__dict__" not in Event.__slots__


def test_empty_events_share_one_container_each() -> None:
    """Three freshly allocated empty containers per event is ~176 B of nothing, at 1.2 M events."""
    a, b = mk(), mk(id="e2")
    assert a.fields is b.fields is EMPTY_FIELDS
    assert a.entities is b.entities is EMPTY_LIST
    assert a.detections is b.detections is EMPTY_LIST
    assert a.labels is b.labels is EMPTY_LIST


def test_the_shared_container_cannot_be_mutated_in_place() -> None:
    """The hazard the sharing creates, refused rather than absorbed: if this ever succeeds, one event's
    detection appears on every other event in the pool that has none."""
    a, b = mk(), mk(id="e2")
    with pytest.raises(TypeError):
        a.fields["burst.count"] = "9"
    with pytest.raises(TypeError):
        a.detections.append(Detection(name="x", id="SIGMA-AUTH-0111", level="high"))
    with pytest.raises(TypeError):
        a.entities.append("10.0.0.1")
    assert b.fields == {} and b.detections == [] and b.entities == []


def test_writing_a_field_copies_and_does_not_touch_the_next_event() -> None:
    a, b = mk(), mk(id="e2")
    a.set_field("burst.count", "9")
    a.set_field_default("direction", "outbound")
    a.set_field_default("burst.count", "1")          # must not overwrite
    a.add_detection(Detection(name="x", id="SIGMA-AUTH-0111", level="high"))
    assert a.fields == {"burst.count": "9", "direction": "outbound"}
    assert [d.id for d in a.detections] == ["SIGMA-AUTH-0111"]
    # the whole point: the OTHER event is untouched, and still shares the empties
    assert b.fields == {} and b.detections == []
    assert b.fields is EMPTY_FIELDS and b.detections is EMPTY_LIST


def test_the_detection_pass_can_clear_detections_back_to_the_shared_empty() -> None:
    """`run_rules` clears every event's detections on every pass. If that left a per-event `[]` behind,
    a single re-run would put 1.2 M empty lists back into the pool."""
    from app.models import EMPTY_LIST as SHARED

    a = mk()
    a.add_detection(Detection(name="x", id="SIGMA-AUTH-0111", level="high"))
    a.detections = SHARED
    assert a.detections is EMPTY_LIST


def test_msg_is_derived_from_raw_only_where_they_agree() -> None:
    """Line parsers set `msg = raw[:200]`; storing it twice is ~173 B an event of nothing. A parser
    that SYNTHESISES a message (SQLite summarise(), EVTX, JSONL) says something the raw line does not,
    and that must never be flattened to a prefix of the raw text."""
    line = "2024-03-11 08:14:22 client 10.44.18.203#51422 (telemetry.example.net): query: A"
    derived = Event(id="e1", raw=line, msg=line[:200])
    assert derived._msg is None                       # nothing stored
    assert derived.msg == line

    long = "x" * 500
    trimmed = Event(id="e2", raw=long, msg=long[:200])
    assert trimmed._msg is None and trimmed.msg == long[:200] and len(trimmed.msg) == 200

    synthesised = Event(id="e3", raw="1|14|13426745475080779|805306370",
                        msg="visit to https://example.net/login (auto_bookmark)")
    assert synthesised._msg is not None
    assert synthesised.msg == "visit to https://example.net/login (auto_bookmark)"

    # an explicitly EMPTY message is a real value, not "derive it"
    assert Event(id="e4", raw="something", msg="").msg == ""

    # and the setter round-trips both ways
    synthesised.msg = synthesised.raw[:200]
    assert synthesised._msg is None and synthesised.msg == synthesised.raw


def test_model_dump_hands_out_copies_not_pool_references() -> None:
    """A response that returned the shared empty dict would let a caller corrupt the pool through it."""
    e = mk()
    d = e.model_dump()
    assert d["fields"] == {} and d["entities"] == [] and d["detections"] == []
    d["fields"]["x"] = "1"          # a plain dict: writable, and disconnected
    d["entities"].append("y")
    assert e.fields is EMPTY_FIELDS and e.entities is EMPTY_LIST
    assert set(d) == {"id", "ts", "source", "sourceId", "file", "host", "user", "msg", "sev", "raw",
                      "fields", "entities", "detections", "baseline", "inCase", "labels"}


def test_model_copy_does_not_resurrect_a_dict() -> None:
    e = mk(msg="synthesised")
    c = e.model_copy(update={"ts": "2026-08-12T00:00:00Z"})
    assert not hasattr(c, "__dict__")
    assert c.ts == "2026-08-12T00:00:00Z" and c.id == e.id and c.msg == "synthesised"
    assert e.ts == "2026-08-11T03:14:47Z"
    assert c.model_copy(update={"msg": c.raw[:200]})._msg is None   # 'msg' goes through the property


def test_case_membership_is_not_pool_state() -> None:
    """`inCase`/`labels`/`baseline` are readable but not settable on a pooled event: they are boundary
    fields, and a slot for each was 24 B x every log line to hold False, [] and None. The stamp lands
    on the dict `Store.stamp_membership` returns instead."""
    e = mk()
    assert e.inCase is False and e.labels == [] and e.baseline is None
    for name, value in (("inCase", True), ("labels", ["pinned"]), ("baseline", "x")):
        with pytest.raises(AttributeError):
            setattr(e, name, value)
    assert e.model_dump()["inCase"] is False


def test_an_event_survives_a_pickle_round_trip_exactly() -> None:
    """`parsers/parallel.py` returns Events from ProcessPoolExecutor workers, so this is the wire
    format for every large parse."""
    e = mk(msg="synthesised", fields={"a": "b"}, entities=["10.0.0.1"],
           detections=[Detection(name="x", id="SIGMA-AUTH-0111", level="high")])
    back = pickle.loads(pickle.dumps(e))
    assert back.model_dump() == e.model_dump()
    assert not hasattr(back, "__dict__")
    empty = pickle.loads(pickle.dumps(mk()))
    assert empty.fields == {} and empty.detections == [] and empty.entities == []


# --------------------------------------------------------------------- the API boundary
@pytest.fixture(scope="module")
def client():
    """One real log, one case, one curated event — enough to make every event-bearing endpoint produce
    a real body, and deliberately lighter than the whole sample case: this module is about
    serialization, and a heavier fixture is a heavier footprint for whatever runs next."""
    with TestClient(app) as c:
        c.post("/api/cases", json={"name": "event model"})
        log = (Path(__file__).resolve().parent / "fixtures" / "sample_case" / "edge-lb-01_access.log").read_bytes()
        r = c.post("/api/sources", files=[("files", ("edge-lb-01_access.log", log, "text/plain"))])
        assert r.status_code == 200, r.text
        drain_enrichment()
        rows = c.get("/api/events", params={"limit": 5}).json()["rows"]
        assert rows, "the fixture log produced no events"
        c.post(f"/api/case-set/{rows[0]['id']}", json={"labels": ["pinned"], "note": "n"})
        yield c
        # Leave nothing behind: a module that loads evidence and walks away hands its case, its source
        # and its pool to whatever runs next (see TODO's "PASSES IN ISOLATION" note).
        c.post("/api/admin/clear-all", json={})


def test_every_event_bearing_endpoint_still_serializes(client) -> None:
    """A slotted object is not JSON-serializable and FastAPI will not encode it — so every one of these
    is an explicit conversion, and a missed one is a 500, not a subtly wrong field."""
    rows = client.get("/api/events", params={"limit": 5}).json()["rows"]
    assert rows and all(isinstance(r["fields"], dict) and isinstance(r["detections"], list) for r in rows)
    eid = rows[0]["id"]

    detail = client.get(f"/api/events/{eid}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["id"] == eid and "correlations" in detail.json()

    assert client.get("/api/events/fields").status_code == 200
    assert client.get("/api/timeline").status_code == 200

    rep = client.get("/api/report")
    assert rep.status_code == 200, rep.text
    assert isinstance(rep.json()["caseSet"], list)
    # the json export goes through orjson, which will not encode a pooled Event either
    assert client.get("/api/report", params={"format": "json"}).status_code == 200

    cs = client.get("/api/case-set")
    assert cs.status_code == 200, cs.text
    assert all("raw" in e for e in cs.json()["events"])

    an = client.get("/api/anomalies")
    assert an.status_code == 200, an.text
    rows_a = an.json()["anomalies"]
    # a real sample, not an empty list: Anomaly.sample holds Events and is exactly the field that would
    # 500 (or silently empty) if the boundary conversion were missing
    assert rows_a and any(a["sample"] and a["sample"][0]["raw"] for a in rows_a), rows_a

    rt = client.post("/api/rules/test", json={"pattern": "login", "field": "any"})
    assert rt.status_code == 200, rt.text
    assert isinstance(rt.json()["sample"], list)


def test_the_memory_estimate_is_measured_and_says_when_it_is_not(client) -> None:
    """`POOL_BYTES_PER_SOURCE_BYTE = 50` told the analyst a 1149 MB file needed 57.5 GB — wrong by
    2.3x, because a constant cannot know whether a byte of log becomes one field or ten. The ratio is
    measured on the pool that IS loaded, and the second element of the tuple says so, so the log line
    can never present a fallback as a measurement."""
    from app.store import STORE, POOL_BYTES_PER_SOURCE_BYTE, event_bytes

    ratio, measured = STORE.pool_bytes_per_source_byte()
    assert measured is True, "the sample case is loaded — there is something to measure"
    assert 1.0 < ratio < 200.0, ratio

    empty = type(STORE)()
    assert empty.pool_bytes_per_source_byte() == (float(POOL_BYTES_PER_SOURCE_BYTE), False)

    # and the per-event count reacts to what the event actually holds
    plain = Event(id="e1", raw="x" * 300)
    rich = Event(id="e2", raw="x" * 300, fields={"a": "y" * 300}, entities=["z" * 300])
    assert event_bytes(rich) > event_bytes(plain) + 500


def test_the_boundary_model_is_a_separate_pydantic_type(client) -> None:
    """`EventDetail` no longer subclasses the pooled event — it subclasses the boundary model, which is
    what keeps validation and JSON encoding off the 1.2 M-event hot path."""
    assert not issubclass(EventDetail, Event)
    assert issubclass(EventDetail, EventOut)
    e = mk()
    assert EventOut.model_validate(e).model_dump() == e.model_dump()
