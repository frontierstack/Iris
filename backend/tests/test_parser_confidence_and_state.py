"""Three follow-ons from `test_parser_misclassification.py`, all about telling the analyst the truth.

1. **A confidence floor must depend on the match ratio.** `syslog` was fixed; `nginx`, `k8s audit` and
   the per-line branch of `jsonl` had the identical shape — a floor (0.55 / 0.55 / 0.45) that plain text
   (max 0.5) could not beat, reached by ONE matching line in two hundred. The trial parse in
   `registry.fingerprint` demotes the parser afterwards, so the file is no longer misparsed — but the
   SCORE is what the Sources drawer shows, and "nginx combined, 0.552" for a file that is 0.5 % nginx is
   a false statement about the evidence. `cloudtrail` is the same bug in the EVTX form: it scored off
   keys found ANYWHERE in the sample, so a transcript quoting one record beat JSONL — and unlike the
   others there was no backstop, because that parser never emits `parse_error`.

2. **MAP is a QUEUE**, not a score band: it means "this file is waiting for a decision from you", and the
   only decision is a field mapping — anonymous columns named against the event schema. `PlaintextParser`
   tops out at 0.5 and READY starts at 0.9, so every plain text file sat there for ever (38 of the
   analyst's 680 staged files) asking for a mapping it has no columns for, holding the case posture's
   "Unmapped fields" open and feeding `POST /api/sources/mapping/auto`, which would have asked the model
   for column names and RE-PARSED each one as delimited.

3. **A demotion is a fact about the file.** When the trial rule rejects the winner, `Fingerprint.scores`
   alone says "EVTX scored 0.97 and lost", which reads as "something scored higher" — not "it won the
   ranking and was thrown out for producing nothing but parse errors". `Fingerprint.demoted` records it.
"""
from __future__ import annotations

import pytest

from app.parsers.base import BaseParser
from app.parsers.cloudtrail import CloudTrailParser
from app.parsers.delimited import DelimitedParser
from app.parsers.evtx import EvtxParser
from app.parsers.jsonl import JsonlParser
from app.parsers.k8s_audit import K8sAuditParser
from app.parsers.nginx import NginxParser
from app.parsers.plaintext import PlaintextParser
from app.parsers.registry import (
    READY_THRESHOLD,
    REVIEW_THRESHOLD,
    Fingerprint,
    all_parsers,
    fingerprint,
    sample_lines,
    state_for,
)
from app.parsers.syslog import SyslogParser
from tests.test_parser_misclassification import BROKEN_EVTX, DPKG

# ------------------------------------------------------------------ fixtures

NGINX = ('203.0.113.9 - - [11/Aug/2026:03:21:04 +0000] "GET /admin HTTP/1.1" 403 512 '
         '"-" "Mozilla/5.0"')
SYSLOG = "Aug 11 03:22:41 bastion-1 sshd[20418]: Accepted publickey for root from 10.22.4.19 port 44120 ssh2"
K8S = ('{"kind":"Event","apiVersion":"audit.k8s.io/v1","verb":"create","requestURI":"/api/v1/namespaces/'
       'default/pods","objectRef":{"resource":"pods","namespace":"default","name":"web-1"},'
       '"user":{"username":"system:serviceaccount:default:deployer"},'
       '"requestReceivedTimestamp":"2026-08-11T03:21:04.117Z"}')
JSONL = '{"ts":"2026-08-11T03:21:04Z","level":"info","msg":"worker started","host":"app-1"}'
CLOUDTRAIL = ('{"eventVersion":"1.09","eventTime":"2026-08-11T03:16:04Z","eventSource":"iam.amazonaws.com",'
              '"eventName":"CreateAccessKey","awsRegion":"us-east-1","sourceIPAddress":"45.83.140.22",'
              '"userIdentity":{"userName":"svc_deploy","type":"IAMUser"}}')

# Prose that no structured parser has any claim on: no delimiters from DELIMS, no JSON, no timestamps.
PROSE = ["the build step finished and the artifact was written to disk"] * 199

# Every parser whose sniff scores a per-LINE match ratio. Each pairs one real record of its format with
# the constant it now has to clear.
RATIO_PARSERS = [
    (SyslogParser, SYSLOG),
    (NginxParser, NGINX),
    (K8sAuditParser, K8S),
    (JsonlParser, JSONL),
]


def _minority(record: str) -> list[str]:
    """One record of a format, hidden in prose — 0.5 % of the sample."""
    return [record] + list(PROSE)


# ------------------------------------- 1. a floor that ignores the ratio is a lie

@pytest.mark.parametrize("cls,record", RATIO_PARSERS, ids=lambda v: getattr(v, "__name__", ""))
def test_one_matching_line_in_two_hundred_scores_zero(cls, record):
    """The old floors were 0.55 / 0.55 / 0.55 / 0.45 and plain text tops out at 0.5."""
    assert cls().sniff(_minority(record), "mystery.log") == 0.0


@pytest.mark.parametrize("cls,record", RATIO_PARSERS, ids=lambda v: getattr(v, "__name__", ""))
def test_a_real_file_of_that_format_is_untouched(cls, record):
    conf = cls().sniff([record] * 40, "evidence.log")
    assert conf >= REVIEW_THRESHOLD, conf


@pytest.mark.parametrize("cls,record", RATIO_PARSERS, ids=lambda v: getattr(v, "__name__", ""))
def test_a_majority_still_claims_the_file(cls, record):
    """The demand is a MAJORITY, not perfection: real logs carry continuation and junk lines."""
    mixed = [record] * 12 + ["    at com.example.Thing.run(Thing.java:41)"] * 8
    assert cls().sniff(mixed, "evidence.log") > 0.0


def test_a_mostly_prose_file_with_one_access_line_is_plain_text():
    data = "\n".join(_minority(NGINX)).encode()
    fp = fingerprint("mystery.log", data)
    assert isinstance(fp.parser, PlaintextParser), fp.scores
    assert fp.scores["nginx combined"] == 0.0


def test_cloudtrail_needs_a_document_not_a_mention():
    """The EVTX bug in CloudTrail's clothing: it scored off keys found anywhere in the sample, and no
    trial parse can catch it — CloudTrailParser never emits `parse_error`."""
    quoting = [
        '{"type":"assistant","message":{"role":"assistant","content":"a record looks like '
        + CLOUDTRAIL.replace('"', '\\"') + '"}}'
    ] + ['{"type":"user","message":{"role":"user","content":"step %d"}}' % i for i in range(40)]
    transcript = "\n".join(quoting).encode()
    assert CloudTrailParser().sniff(sample_lines(transcript), "agent.jsonl") == 0.0
    fp = fingerprint("agent-transcript.jsonl", transcript)
    assert isinstance(fp.parser, JsonlParser), fp.scores

    # ...and a real export, in either shape, is untouched
    lines = [CLOUDTRAIL] * 10
    assert CloudTrailParser().sniff(lines, "cloudtrail.json") >= 0.9
    doc = ('{"Records":[' + ",".join([CLOUDTRAIL] * 5) + "]}").encode()
    assert isinstance(fingerprint("cloudtrail_20260811.json", doc).parser, CloudTrailParser)


# ----------------------------------------- 2. MAP is a queue, not a score band

def test_plain_text_is_never_waiting_for_a_mapping():
    """It has no columns, so MAP asks a question the screen cannot even render: the mapping editor is
    driven by `Source.guessedFields`, which only the delimited parser fills in."""
    p = PlaintextParser()
    for conf in (0.05, 0.2, 0.35, 0.5):
        assert state_for(conf, p) == "READY", conf


def test_the_analysts_plain_text_files_come_out_ready():
    fp = fingerprint("dpkg.log", DPKG)
    assert isinstance(fp.parser, PlaintextParser), fp.scores
    assert fp.confidence < REVIEW_THRESHOLD      # the score is honest: it is the fallback
    assert fp.state == "READY"                   # ...and the state says the file is DONE


def test_a_parser_with_nothing_to_map_falls_to_review_not_map():
    """A low-confidence guess is still worth checking — but it is a question about the PARSER CHOICE,
    not a request for column names, so it belongs in REVIEW."""
    assert state_for(0.6, EvtxParser()) == "REVIEW"      # a `.evtx` name with no ElfFile magic
    assert state_for(0.0, SyslogParser()) == "REVIEW"
    assert state_for(0.95, EvtxParser()) == "READY"


def test_delimited_keeps_the_map_state_it_is_the_reason_for():
    d = DelimitedParser()
    assert d.mapping is None
    assert state_for(0.5, d) == "MAP"
    assert state_for(0.86, d) == "MAP"
    assert state_for(READY_THRESHOLD, d) == "READY"


def test_only_the_delimited_parser_declares_itself_mappable():
    mappable = sorted(p.name for p in all_parsers() if p.mappable)
    assert mappable == [DelimitedParser.name]
    fallback = sorted(p.name for p in all_parsers() if p.fallback)
    assert fallback == [PlaintextParser.name]
    assert BaseParser.mappable is False and BaseParser.fallback is False


@pytest.mark.parametrize("parser", all_parsers(), ids=lambda p: p.name)
def test_no_parser_can_be_queued_for_a_mapping_it_cannot_accept(parser):
    for conf in (0.0, 0.2, 0.5, 0.69, 0.7, 0.89, 0.9, 1.0):
        state = state_for(conf, parser)
        assert state in ("READY", "REVIEW", "MAP")
        if state == "MAP":
            assert parser.mappable, f"{parser.name} at {conf} asks for a mapping it has no columns for"


# ------------------------------------------------- 3. a demotion is on the record

def test_a_demoted_parser_is_named_with_its_error_ratio():
    fp = fingerprint("exported.xml", BROKEN_EVTX)
    assert isinstance(fp.parser, PlaintextParser), fp.scores
    assert [d.parser for d in fp.demoted] == ["Windows EVTX"]
    d = fp.demoted[0]
    assert d.confidence >= 0.9                       # it WON the ranking on this number
    assert d.errorRatio == 1.0                       # and could not read a single record
    assert d.confidence == fp.scores["Windows EVTX"]  # the two views agree


def test_a_clean_file_demotes_nothing():
    fp = fingerprint("bastion-1_syslog", ("\n".join([SYSLOG] * 20)).encode())
    assert isinstance(fp.parser, SyslogParser), fp.scores
    assert fp.demoted == []


def test_a_parser_that_never_claimed_the_file_is_not_reported_as_demoted():
    """dpkg.log is the sniff fix, not the trial fix: syslog now scores 0.0 and never enters the walk.
    Reporting it as "demoted" would invent a rejection that did not happen."""
    fp = fingerprint("dpkg.log", DPKG)
    assert fp.scores["syslog (RFC3164/5424)"] == 0.0
    assert fp.demoted == []


def test_demoted_defaults_to_empty_so_every_caller_keeps_working():
    fp = Fingerprint(parser=PlaintextParser(), confidence=0.2, state="READY", sample="", scores={})
    assert fp.demoted == []


# ---------------------------- 2b. the queue the MAP state actually feeds

@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c


def test_only_mappable_sources_reach_the_pending_mapping_queue(client):
    """`GET /api/sources/mapping/pending` is not just a display: `POST /mapping/auto` walks it, asks the
    model for column names for every entry and calls `remap_source`, which re-parses the file as
    DELIMITED. A JSONL source in REVIEW named its own fields already — remapping it would replace them
    with guessed column names."""
    # JSON lines with no timestamp key: sniffs ~0.8, so REVIEW — and nothing to map.
    notes = ("\n".join(['{"level":"info","msg":"worker %d started","host":"app-1"}' % i
                        for i in range(20)])).encode()
    pipe = b"2026-08-11T03:29:50Z|fw-edge-2|ALLOW|10.22.4.19:51993|45.83.140.22:8443|tcp|2297851\n" * 5
    a = client.post("/api/sources", files={"files": ("queue-notes.jsonl", notes, "text/plain")}).json()[0]
    b = client.post("/api/sources", files={"files": ("queue-fw.pipe.log", pipe, "text/plain")}).json()[0]
    try:
        assert a["state"] == "REVIEW" and a["parser"] == JsonlParser.name, a
        assert b["state"] == "MAP" and b["parser"] == DelimitedParser.name, b
        pending = client.get("/api/sources/mapping/pending").json()
        ids = {row["id"] for row in pending["sources"]}
        assert b["id"] in ids           # anonymous columns: a real question
        assert a["id"] not in ids       # named its own fields: nothing to ask
    finally:
        client.delete(f"/api/sources/{a['id']}")
        client.delete(f"/api/sources/{b['id']}")


def test_a_plain_text_source_is_not_in_the_mapping_queue(client):
    body = ("\n".join(["the build step finished and the artifact was written to disk"] * 30)).encode()
    src = client.post("/api/sources", files={"files": ("queue-prose.log", body, "text/plain")}).json()[0]
    try:
        assert src["parser"] == PlaintextParser.name and src["state"] == "READY", src
        ids = {row["id"] for row in client.get("/api/sources/mapping/pending").json()["sources"]}
        assert src["id"] not in ids
    finally:
        client.delete(f"/api/sources/{src['id']}")
