"""A parser must not claim a file it cannot read.

Both cases below were found on the analyst's real pool, not invented:

* `agent-a179e225a1e492cc0.jsonl` — a JSONL agent transcript that QUOTES Windows event XML in a message
  body. `EvtxParser.sniff` only asked whether "<Event" appeared anywhere in the sample, so the transcript
  scored 0.97, beat JSONL's 0.92, and every event of that source came back with `parse_error: xml`.
* `dpkg.log` — `2026-02-10 00:54:43 install base-passwd:amd64 <none> 3.6.3build1` reads as
  `<ts> <host> <program>:` to syslog's ISO pattern, so ~30 % of the lines matched. `SyslogParser.sniff`
  scored that 0.674 (its floor is 0.55 for ANY hit at all, and plain text tops out at 0.5) and the other
  70 % of the file became `parse_error: unmatched`.

The general rule that backs both of them up lives in `registry.fingerprint`: the winning candidate is
trialled on the sampled lines and loses the file if the MAJORITY of the records it produces carry a
`parse_error` field.
"""
from __future__ import annotations

from app.parsers.cloudtrail import CloudTrailParser
from app.parsers.evtx import EvtxParser
from app.parsers.jsonl import JsonlParser
from app.parsers.plaintext import PlaintextParser
from app.parsers.registry import TRIAL_ERROR_RATIO, fingerprint, sample_lines, trial_error_ratio
from app.parsers.syslog import SyslogParser

# ------------------------------------------------------------------ fixtures

EVTX_XML = (
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
    "<EventID>4624</EventID><Computer>WIN-FS01</Computer>"
    '<TimeCreated SystemTime="2026-08-11T03:21:04.117Z"/></System><EventData>'
    '<Data Name="TargetUserName">svc_deploy</Data><Data Name="LogonType">3</Data>'
    "</EventData></Event>"
)

# A chat/agent transcript: JSON lines, one of which quotes the event XML above inside a string.
AGENT_JSONL = "\n".join(
    [
        '{"ts":"2026-08-11T03:10:00Z","type":"user","message":{"role":"user","content":'
        '"Read app/parsers/evtx.py and explain it"}}',
        '{"ts":"2026-08-11T03:10:04Z","type":"assistant","message":{"role":"assistant","content":'
        '"The exported form looks like ' + EVTX_XML.replace('"', '\\"') + '"}}',
        '{"ts":"2026-08-11T03:10:09Z","type":"user","message":{"role":"user","content":'
        '"and <System> / <EventID> come from the System block"}}',
    ]
    + [
        '{"ts":"2026-08-11T03:1%d:00Z","type":"assistant","message":{"role":"assistant",'
        '"content":"step %d"}}' % (i % 10, i)
        for i in range(40)
    ]
).encode()

# Real dpkg.log shape: a timestamp, an action, a package with an :arch suffix, versions.
DPKG = "\n".join(
    [
        "2026-02-10 00:54:43 startup archives install",
        "2026-02-10 00:54:43 install base-passwd:amd64 <none> 3.6.3build1",
        "2026-02-10 00:54:43 status half-installed base-passwd:amd64 3.6.3build1",
        "2026-02-10 00:54:43 status unpacked base-passwd:amd64 3.6.3build1",
        "2026-02-10 00:54:43 configure base-passwd:amd64 3.6.3build1 3.6.3build1",
        "2026-02-10 00:54:43 status half-configured base-passwd:amd64 3.6.3build1",
        "2026-02-10 00:54:43 status installed base-passwd:amd64 3.6.3build1",
        "2026-02-10 00:55:02 install libssl3t64:amd64 <none> 3.0.13-0ubuntu3.5",
        "2026-02-10 00:55:02 status half-installed libssl3t64:amd64 3.0.13-0ubuntu3.5",
        "2026-02-10 00:55:03 status installed libssl3t64:amd64 3.0.13-0ubuntu3.5",
    ]
    * 6
).encode()

SYSLOG = "Aug 11 03:22:41 bastion-1 sshd[20418]: Accepted publickey for root from 10.22.4.19 port 44120 ssh2"

# Starts as markup and carries every EVTX marker, so the sniff is genuinely confident — but each record's
# XML is malformed (`<Data …>` closed by `</EventData>`), so the parser can only report parse_error.
BROKEN_EVTX = (
    "<?xml version='1.0' encoding='utf-8'?>\n<Events>\n"
    + "\n".join(
        [
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            "<EventID>4624</EventID><Computer>WIN-FS01</Computer></System>"
            '<EventData><Data Name="TargetUserName">svc_deploy</EventData></Event>'
        ]
        * 12
    )
).encode()


# ------------------------------------------------------- 1. the JSONL agent log

def test_agent_jsonl_is_not_windows_evtx():
    fp = fingerprint("agent-a179e225a1e492cc0.jsonl", AGENT_JSONL)
    assert isinstance(fp.parser, JsonlParser), fp.scores
    assert fp.state == "READY"


def test_evtx_sniff_needs_a_document_not_a_mention():
    p = EvtxParser()
    quoting = sample_lines(AGENT_JSONL)
    assert p.sniff(quoting, "agent.jsonl") == 0.0
    # a real export still scores exactly as before, prolog or no prolog
    assert p.sniff([EVTX_XML], "WIN-FS01_Security.xml") >= 0.9
    assert p.sniff(["<?xml version='1.0'?>", "<Events>", EVTX_XML, "</Events>"]) >= 0.9
    assert p.sniff([], "Security.evtx") == 0.6
    assert p.sniff([], "", b"ElfFile\x00") == 1.0


def test_agent_jsonl_events_carry_no_parse_error():
    fp = fingerprint("agent-a179e225a1e492cc0.jsonl", AGENT_JSONL)
    recs = list(fp.parser.parse_bytes(AGENT_JSONL))
    assert recs
    assert not [r for r in recs if "parse_error" in r.fields]


# ------------------------------------------------------------- 2. dpkg.log

def test_dpkg_log_is_not_syslog():
    fp = fingerprint("dpkg.log", DPKG)
    assert not isinstance(fp.parser, SyslogParser), fp.scores
    assert isinstance(fp.parser, PlaintextParser), fp.scores
    recs = list(fp.parser.parse_bytes(DPKG))
    assert recs
    assert not [r for r in recs if "parse_error" in r.fields]


def test_syslog_sniff_demands_a_majority():
    p = SyslogParser()
    dpkg_lines = sample_lines(DPKG)
    assert p.sniff(dpkg_lines, "dpkg.log") == 0.0
    # a real syslog file is untouched
    assert p.sniff([SYSLOG] * 20, "bastion-1_syslog") > 0.9
    # ...including one with a minority of continuation / junk lines
    mixed = [SYSLOG] * 14 + ["    at com.example.Thing.run(Thing.java:41)"] * 6
    assert p.sniff(mixed, "app_syslog") > 0.7


def test_syslog_file_with_a_few_odd_lines_is_still_syslog():
    """The demotion must not fire on a file the parser genuinely reads."""
    data = "\n".join([SYSLOG] * 18 + ["    continued stack frame", "    and another"]).encode()
    fp = fingerprint("bastion-1_syslog", data)
    assert isinstance(fp.parser, SyslogParser), fp.scores
    recs = list(fp.parser.parse_bytes(data))
    errs = [r for r in recs if "parse_error" in r.fields]
    assert 0 < len(errs) / len(recs) <= TRIAL_ERROR_RATIO


# ------------------------------- 3. the general rule: mostly parse_error loses

def test_parser_that_errors_on_most_records_loses_to_plaintext():
    """A confident sniff is not a licence to write parse_error onto every event of a source."""
    p = EvtxParser()
    lines = sample_lines(BROKEN_EVTX)
    assert p.sniff(lines, "exported.xml") >= 0.9            # it really does claim the file
    assert trial_error_ratio(p, lines) == 1.0               # and really cannot read a record of it
    fp = fingerprint("exported.xml", BROKEN_EVTX)
    assert isinstance(fp.parser, PlaintextParser), fp.scores
    assert fp.scores["Windows EVTX"] >= 0.9                 # the sniff scores are reported as sniffed


def test_trial_error_ratio_measures_the_sampled_records():
    lines = sample_lines(DPKG)
    ratio = trial_error_ratio(SyslogParser(), lines)
    assert ratio is not None and ratio > TRIAL_ERROR_RATIO
    assert trial_error_ratio(PlaintextParser(), lines) == 0.0


def test_trial_never_touches_the_parser_that_will_read_the_file():
    """The trial runs on a fresh instance: parse() warms up on the head and must not be pre-warmed."""
    p = SyslogParser()
    before = dict(p.__dict__)
    trial_error_ratio(p, sample_lines(DPKG))
    assert p.__dict__ == before


def test_a_silent_parser_is_not_a_failing_one():
    """A truncated whole-document format yields nothing from the sample. That is not evidence of failure
    and must not demote it — otherwise a big pretty-printed CloudTrail export falls to plain text."""
    truncated = (
        '{\n "Records": [\n'
        + "".join(
            '  {"eventVersion":"1.09","eventTime":"2026-08-11T03:16:0%dZ","eventSource":"iam.amazonaws.com",'
            '"eventName":"CreateAccessKey","awsRegion":"us-east-1","sourceIPAddress":"45.83.140.22",'
            '"userIdentity":{"userName":"svc_deploy","type":"IAMUser"}},\n' % (i % 10)
            for i in range(30)
        )
    ).encode()
    lines = sample_lines(truncated)
    assert trial_error_ratio(CloudTrailParser(), lines) is None
    fp = fingerprint("cloudtrail_20260811.json", truncated)
    assert isinstance(fp.parser, CloudTrailParser), fp.scores
