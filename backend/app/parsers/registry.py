"""Parser registry and file fingerprinting."""
from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from typing import Optional

from .base import BaseParser
from .cloudtrail import CloudTrailParser
from .csv import CsvParser
from .delimited import DelimitedParser
from .docx import DocxParser
from .eml import EmailParser
from .evtx import EvtxParser
from .image import ImageParser, image_magic
from .jsonl import JsonlParser
from .k8s_audit import K8sAuditParser
from .memdump import MemdumpParser, is_binary
from .nginx import NginxParser
from .pdf import PdfParser
from .plaintext import PlaintextParser
from .sqlitedb import JOURNAL_MAGIC, MAGIC as SQLITE_MAGIC, WAL_MAGIC, WAL_MAGIC_ALT, SqliteParser
from .syslog import SyslogParser
from .xlsx import XLS_MAGIC, XlsxParser

READY_THRESHOLD = 0.9
REVIEW_THRESHOLD = 0.7

# A sniff is a GUESS about the shape of a file; the trial parse below is the check on it. A parser that
# reports `parse_error` on the majority of the records it produces from the sample has not recognised the
# format — persisting that verdict writes a `parse_error` field onto every event of the source and hides
# the real content behind a parser that cannot read it. Measured on the analyst's pool: EVTX claimed a
# 400 KB JSONL agent transcript (4 records, 4 parse_error) and syslog claimed dpkg.log (141 of 200
# sampled records unmatched).
TRIAL_ERROR_RATIO = 0.5   # strictly MORE than half the sampled records must fail before a parser loses
TRIAL_MAX_RECORDS = 500   # one sampled line can expand into many records (a JSON array); bound the trial

# A -wal / -journal sibling uploaded on its own: routed to the SQLite parser purely so it can say what the
# file is instead of dumping strings out of it.
SQLITE_SIBLING_MAGIC = (WAL_MAGIC, WAL_MAGIC_ALT, JOURNAL_MAGIC)
SQLITE_SIBLINGS = ("-wal", "-shm", "-journal")


def all_parsers() -> list[BaseParser]:
    return [
        EvtxParser(),
        CloudTrailParser(),
        K8sAuditParser(),
        NginxParser(),
        SyslogParser(),
        JsonlParser(),
        CsvParser(),
        DelimitedParser(),
        PdfParser(),
        XlsxParser(),
        DocxParser(),
        EmailParser(),
        # SqliteParser is NOT here on purpose: it is selected by magic in binary_hint. Sniffing it by
        # extension would hand every non-SQLite ".db" to a parser that can only fail on it.
        ImageParser(),
        MemdumpParser(),
        PlaintextParser(),
    ]


def parser_by_name(name: str) -> Optional[BaseParser]:
    """A fresh parser instance for a stored parser NAME, or None if this build has no such parser.

    The pool cache (app/pool_store.py) restores a source without re-sniffing the file, so it has the
    name and needs the object back. None is the honest answer when the name is unknown — the caller
    re-parses rather than serving events that nothing in this build can explain or re-map.

    `delimited (mapped)` is deliberately NOT resolvable to its mapping here: the mapping itself lives
    on `Source.mapping` and is re-applied by `remap_source`, so a plain delimited parser is the right
    starting point and the wrong one would silently claim column names it does not have.
    """
    want = (name or "").strip()
    if not want:
        return None
    for p in all_parsers():
        if p.name == want:
            return p
    if want.startswith("delimited"):
        return DelimitedParser()
    if want == SqliteParser().name:     # selected by magic, so not in all_parsers()
        return SqliteParser()
    return None


OOXML_MARKER = b"[Content_Types].xml"


def is_ooxml(data: bytes) -> bool:
    """True for Office Open XML containers (xlsx/docx/pptx): a zip whose directory lists [Content_Types].xml."""
    if not data.startswith(b"PK\x03\x04"):
        return False
    if OOXML_MARKER in data[:4096]:
        return True
    return OOXML_MARKER in data[-65536:]  # central directory sits at the end


def binary_hint(filename: str, data: bytes) -> Optional[BaseParser]:
    """Fast path for binary containers: decide by magic bytes / extension before any text sniffing."""
    head = data[:64]
    lower = filename.lower()
    if head.startswith(b"%PDF") or lower.endswith(".pdf"):
        return PdfParser()
    if is_ooxml(data) or lower.endswith((".xlsx", ".xlsm", ".docx", ".docm")):
        if lower.endswith((".docx", ".docm")) or b"word/" in data[:4096]:
            return DocxParser()
        if lower.endswith((".xlsx", ".xlsm")) or b"xl/" in data[:4096]:
            return XlsxParser()
        return None  # other OOXML (pptx): fall through to strings
    if lower.endswith(".xls") and head.startswith(XLS_MAGIC):
        return XlsxParser()
    # SQLite is identified by its magic ONLY: a ".db" that is not a SQLite file (Thumbs.db, Berkeley DB…)
    # must still fall through to the strings parser rather than erroring out with a misleading message.
    # The exception is a SIBLING (-wal / -shm / -journal): copying a browser profile brings those along,
    # an empty one has no magic to recognise, and parsing it as "plain text" produced a source stuck in
    # MAP waiting for a field mapping. Claim it by name so the analyst gets the explanation instead.
    if head.startswith(SQLITE_MAGIC) or head.startswith(SQLITE_SIBLING_MAGIC) or lower.endswith(SQLITE_SIBLINGS):
        return SqliteParser(filename)
    # Outlook .msg is an OLE2 compound document — same magic as legacy .xls, so key off the extension.
    if lower.endswith((".msg", ".eml", ".mbox", ".mbx")):
        return EmailParser()
    if image_magic(head) or lower.endswith(ImageParser.extensions):
        return ImageParser()
    if head.startswith(b"ElfFile"):
        return EvtxParser()
    return None


def state_for(confidence: float, parser: BaseParser) -> str:
    """READY | REVIEW | MAP for a parsed source.

    MAP is a QUEUE: it means "this file is waiting for a decision from you", and the only decision the
    app can take is a field mapping — anonymous columns named against the event schema, driven by
    `Source.guessedFields`. So MAP is reserved for a parser that declares itself `mappable`.

    A parser with no columns to map cannot answer that question and must never sit in it. Below the
    READY threshold it drops to REVIEW ("we guessed at the format — check it"), which is a statement
    about the parser CHOICE, not a request for a mapping. And the fallback parser is not even a guess:
    plain text is what a file gets when nothing else claimed it, every line becomes a record and nothing
    can fail, so it is READY at any confidence.
    """
    if parser.mappable and getattr(parser, "mapping", None) is None:
        return "MAP" if confidence < READY_THRESHOLD else "READY"
    if parser.fallback:
        return "READY"
    if confidence >= READY_THRESHOLD:
        return "READY"
    if confidence >= REVIEW_THRESHOLD:
        return "REVIEW"
    return "MAP" if parser.mappable else "REVIEW"


@dataclass
class Demotion:
    """A parser that OUTSCORED the winner and lost the file on the trial parse below.

    Without this the Fingerprint reports the sniff scores and nothing else, so a source that fell all
    the way to plain text looks like a file nothing recognised — when in fact a parser recognised it,
    claimed it and could not read a record of it. That is the difference between "unknown format" and
    "EVTX claimed this file and produced 4 parse errors out of 4", and only the second one tells the
    analyst where to look.
    """

    parser: str        # the display name, as it appears in Fingerprint.scores
    confidence: float  # what it sniffed at — it WON the ranking on this number
    errorRatio: float  # fraction of the records it produced from the sample that carried a parse_error


@dataclass
class Fingerprint:
    parser: BaseParser
    confidence: float
    state: str
    sample: str
    scores: dict[str, float]
    # Highest-scoring first: every candidate that beat the winner and was rejected by the trial parse.
    demoted: list[Demotion] = dc_field(default_factory=list)


def sample_lines(data: bytes, n: int = 200) -> list[str]:
    head = data[: 256 * 1024]
    text = head.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if len(data) > len(head) and lines:
        lines = lines[:-1]  # drop possibly-truncated last line
    return lines[:n]


def trial_error_ratio(parser: BaseParser, lines: list[str]) -> Optional[float]:
    """Fraction of the records this parser produces from `lines` that carry a `parse_error` field.

    None means "no verdict": the parser produced nothing from the sample, which is what a truncated
    sample of a WHOLE-DOCUMENT format (a pretty-printed CloudTrail array, an mbox) legitimately looks
    like. Silence is not evidence of failure, so those are never demoted on this signal.

    The trial runs on a FRESH instance: `parse()` warms up on the head of the file (delimiter, header,
    column names) and the instance in the candidate list is the one that will be handed the real file.
    """
    try:
        probe = type(parser)()
    except Exception:
        return None
    total = 0
    errors = 0
    try:
        for pe in probe.parse(lines):
            total += 1
            if "parse_error" in pe.fields:
                errors += 1
            if total >= TRIAL_MAX_RECORDS:
                break
    except Exception:
        # A raise is judged on what it produced first, never as an automatic failure: a whole-document
        # parser can legitimately blow up on a sample that stops mid-document, and demoting on that would
        # move files that parse fine. Whatever records it DID emit are still a fair measurement.
        pass
    if not total:
        return None
    return errors / total


def fingerprint(filename: str, data: bytes) -> Fingerprint:
    hinted = binary_hint(filename, data)
    if hinted is not None:
        conf = float(hinted.sniff([], filename, data[:64])) or 0.9
        return Fingerprint(parser=hinted, confidence=round(conf, 3), state=state_for(conf, hinted),
                           sample=f"<{hinted.name}: {len(data):,} bytes>", scores={hinted.name: conf})
    if is_binary(data[:8192]):
        p = MemdumpParser()
        conf = float(p.sniff([], filename, data[:64]))
        return Fingerprint(parser=p, confidence=round(conf, 3), state=state_for(conf, p),
                           sample=f"<binary: {len(data):,} bytes>", scores={p.name: conf})
    lines = sample_lines(data)
    head = data[:64]
    scores: dict[str, float] = {}
    ranked: list[tuple[float, BaseParser]] = []
    for p in all_parsers():
        try:
            c = float(p.sniff(lines, filename, head))
        except Exception:
            c = 0.0
        scores[p.name] = c
        ranked.append((c, p))
    # sort() is stable, so parsers that tie keep all_parsers() order — that ordering IS the precedence
    # and the previous `c > best_conf` loop preserved it the same way.
    ranked.sort(key=lambda t: -t[0])

    best: Optional[BaseParser] = None
    best_conf = -1.0
    demoted: list[Demotion] = []
    for conf, p in ranked:
        if conf <= 0:
            break
        if p.fallback:
            best, best_conf = p, conf   # the fallback never "fails to parse": every line is a record
            break
        ratio = trial_error_ratio(p, lines)
        if ratio is not None and ratio > TRIAL_ERROR_RATIO:
            # It claimed the file and cannot read it — try the next candidate, and RECORD the rejection.
            # The scores dict alone cannot express this: it says EVTX scored 0.97 and lost, which reads
            # as "something scored higher", not "it won and was thrown out for producing only errors".
            demoted.append(Demotion(parser=p.name, confidence=round(conf, 3), errorRatio=round(ratio, 3)))
            continue
        best, best_conf = p, conf
        break
    if best is None:
        best, best_conf = PlaintextParser(), 0.2
    return Fingerprint(parser=best, confidence=round(best_conf, 3), state=state_for(best_conf, best),
                       sample="\n".join(lines[:8]), scores=scores, demoted=demoted)
