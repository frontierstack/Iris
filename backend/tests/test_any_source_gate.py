"""The any-source pre-gate must never reject a line the real pattern would match.

The gate is a NECESSARY-substring filter, not a sufficient one: it lets a line through and the real
regex decides. That direction is safe. The other direction is not — a string that matches
`_SECRET` / `_ENCODED_CMD` / `_RANSOM` but contains none of the listed literals is a detection that
silently never fires, on the one pass that reads every line in the workspace.

So this walks every ALTERNATIVE of every shipped pattern with a string that matches it, and asserts
the gate agrees. If someone edits a pattern and forgets the literal, this is what says so.
"""
from __future__ import annotations

import re

import pytest

from app import detect

SECRET_POSITIVES = [
    "AKIAIOSFODNN7EXAMPLE",
    "ASIA" + "B" * 16,
    "-----BEGIN RSA PRIVATE KEY-----",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1g",
    "password=hunter2hunter2",
    "passwd: correcthorsebattery",
    'pwd="s3cr3tvalue1"',
    "api_key=abcdef0123456789",
    "api-key: abcdef0123456789",
    "apikey=abcdef0123456789",
    "secret=abcdef0123456789",
    "token: abcdef0123456789",
    "client_secret=abcdef0123456789",
    "client-secret=abcdef0123456789",
    "xoxb-" + "1234567890ab",
    "ghp_" + "a" * 30,
    "gho_" + "a" * 30,
    "ghr_" + "a" * 30,
    "ghs_" + "a" * 30,
    "ghu_" + "a" * 30,
    "github_pat_" + "a" * 22,
    "sk_" + "live_" + "a" * 24,
    "hooks.slack.com/services/T0000AAAA/B1111BBBB/abcdefghij123456",
]

ENCODED_POSITIVES = [
    "powershell.exe -EncodedCommand " + "QQ" * 20,
    "powershell -enc " + "QQ" * 20,
    "FromBase64String(",
    "[Convert]::FromBase64String",
    "certutil.exe -decode payload.b64 out.exe",
    "base64 -d file | sh",
    "base64 --decode blob | bash",
    "echo " + "QUFB" * 12 + " | base64 -d",
]

RANSOM_POSITIVES = [
    "READ_ME.txt", "README.txt",
    "HOW_TO_DECRYPT.txt", "HOW TO DECRYPT.html",
    "DECRYPT-FILES.txt", "DECRYPT_INSTRUCTION.hta",
    "RECOVER-FILES.txt", "RECOVER_YOUR.txt",
    "RESTORE-FILES.txt", "RESTORE_FILES.html",
    "YOUR_FILES_ARE_ENCRYPTED.txt",
    "invoice.locky", "report.crypt", "db.cryptolocker", "notes.encrypted", "x.enc",
    "y.lockbit", "y.conti", "y.ryuk", "y.revil", "y.sodinokibi", "y.djvu",
    "y.wannacry", "y.wncry", "y.onion", "y.makop", "y.phobos", "y.cerber",
]

CASES = [(detect._SECRET, SECRET_POSITIVES),
         (detect._ENCODED_CMD, ENCODED_POSITIVES),
         (detect._RANSOM, RANSOM_POSITIVES)]


@pytest.mark.parametrize("rx,positives", CASES, ids=["secret", "encoded", "ransom"])
def test_every_alternative_survives_the_gate(rx, positives) -> None:
    gate = detect._literal_gate([detect._SECRET, detect._ENCODED_CMD, detect._RANSOM])
    assert gate is not None, "the shipped patterns must get a gate"
    for text in positives:
        line = f"2026-08-26T00:00:00Z host app: {text} trailing"
        assert rx.search(line), f"the fixture does not match the pattern it claims to: {text!r}"
        assert gate.search(line.lower()), f"the gate would drop a real detection: {text!r}"


def test_an_overridden_pattern_gets_no_gate() -> None:
    """A gate built from the SHIPPED literals says nothing about a regex the analyst wrote."""
    custom = re.compile(r"totally-different-\d+")
    assert detect._literal_gate([custom]) is None
    assert detect._literal_gate([detect._SECRET, custom]) is None
    assert detect._literal_gate([detect._SECRET]) is not None


def test_the_gate_rejects_ordinary_traffic() -> None:
    """Otherwise it is a correct filter that saves nothing, which is the whole point of it."""
    gate = detect._literal_gate([detect._SECRET, detect._ENCODED_CMD, detect._RANSOM])
    ordinary = [
        '10.0.0.5 - - "GET /api/v1/items/42?page=3&sort=desc HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        "2026-08-26T00:00:01Z web1 sshd[7]: Accepted publickey for alice from 10.0.0.9 port 22",
        "kernel: [12345.678] eth0: link up, 1000 Mbps, full duplex",
    ]
    for line in ordinary:
        assert not gate.search(line.lower()), line
