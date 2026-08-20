"""Parser protocol and shared helpers."""
from __future__ import annotations

import io

from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Iterator, Optional, Protocol, runtime_checkable


@dataclass
class ParsedEvent:
    """Output of a parser before normalization (severity/entities/UTC are added later)."""

    raw: str
    msg: str
    ts: Optional[datetime] = None
    ts_text: str = ""  # raw timestamp string if the parser did not parse it
    host: str = ""
    user: str = ""
    sev: Optional[str] = None
    fields: dict[str, str] = field(default_factory=dict)


@runtime_checkable
class Parser(Protocol):
    name: str  # display name, e.g. "nginx combined"
    family: str  # event source family, e.g. "nginx.access"

    def sniff(self, sample: list[str], filename: str = "", head: bytes = b"") -> float:
        """Return a confidence 0..1 that this parser handles the file."""
        ...

    def parse(self, lines: Iterable[str]) -> Iterator[ParsedEvent]:
        ...


class BaseParser:
    name = "base"
    family = "generic"
    binary = False  # True if parse_bytes must be used (EVTX)
    # True only when parse() is stateless once it has warmed up on the head of the file: every record
    # depends on its own line(s) and on the delimiter/header resolved from the first ~200 lines, never on
    # a record arbitrarily far back. That is exactly the condition parsers.parallel needs to hand a
    # byte-range chunk to another process (prefixed with the head) and get the same events out.
    # Leave it False for anything that accumulates across the file (jsonl's multi-line documents, eml,
    # and every binary/container parser).
    chunkable = False
    # The format quotes fields, so a record may legally span newlines. Chunk boundaries then also have to
    # land where the running count of double quotes is even.
    quoted = False
    # True when this parser has anonymous COLUMNS an analyst can name — i.e. when the MAP state is a
    # question they can actually answer. Everything else already names its own fields (syslog, nginx,
    # EVTX, JSONL…) or has no fields at all (plain text), and putting one of those in MAP asks for a
    # mapping the screen cannot even offer: the editor is driven by `Source.guessedFields`, which is
    # populated by the delimited parser and nothing else. See registry.state_for.
    mappable = False
    # True for the TERMINAL choice — the parser that gets the file when nothing else claimed it. Its
    # confidence measures how much structure it found, NOT doubt about the parser choice, so it must
    # never gate the state: a plain text log is finished, not awaiting a decision.
    fallback = False

    def sniff(self, sample: list[str], filename: str = "", head: bytes = b"") -> float:
        return 0.0

    def parse(self, lines: Iterable[str]) -> Iterator[ParsedEvent]:
        return iter(())

    def parse_bytes(self, data: bytes) -> Iterator[ParsedEvent]:
        text = data.decode("utf-8", errors="replace")
        return self.parse(text.splitlines())


def clean(s: object) -> str:
    if s is None:
        return ""
    return str(s).strip()


def flatten(obj: object, prefix: str = "", out: Optional[dict[str, str]] = None, depth: int = 0) -> dict[str, str]:
    """Flatten nested JSON into dotted keys with string values."""
    if out is None:
        out = {}
    if depth > 6:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            flatten(v, key, out, depth + 1)
    elif isinstance(obj, list):
        if all(not isinstance(x, (dict, list)) for x in obj):
            out[prefix] = ",".join(str(x) for x in obj)
        else:
            for i, v in enumerate(obj[:20]):
                flatten(v, f"{prefix}[{i}]", out, depth + 1)
    else:
        if prefix:
            out[prefix] = "" if obj is None else str(obj)
    return out


# ---------------------------------------------------------------- OOXML containers
# An .xlsx/.docx is a ZIP with a very particular layout. A file that is a zip but NOT that layout --
# a plain archive someone renamed, an OpenDocument .ods/.odt, a Numbers export -- reaches openpyxl or
# python-docx and dies with a message about the ZIP's internals:
#     KeyError: "There is no item named '[Content_Types].xml' in the archive"
# That names an implementation detail of a library the analyst did not choose, says nothing about
# which file failed or why, and reads like a bug in Iris. Identify the container instead and say what
# it actually is.
OOXML_PARTS = {
    "xl/workbook.xml": "Excel workbook",
    "word/document.xml": "Word document",
    "ppt/presentation.xml": "PowerPoint presentation",
}
_ODF_MIME = {
    "application/vnd.oasis.opendocument.spreadsheet": "OpenDocument spreadsheet (.ods)",
    "application/vnd.oasis.opendocument.text": "OpenDocument text (.odt)",
    "application/vnd.oasis.opendocument.presentation": "OpenDocument presentation (.odp)",
}


def describe_zip(data: bytes) -> tuple[str, str]:
    """What is this zip, really? -> (kind, human description).

    kind is one of: 'xlsx' | 'docx' | 'pptx' | 'odf' | 'zip' | 'notzip' | 'corrupt'.
    Used to turn a library's internal KeyError into a sentence naming the file's real type and the
    way forward. Never raises.
    """
    import zipfile
    if not data[:4].startswith(b"PK\x03\x04"):
        return "notzip", "not a ZIP container at all"
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = set(z.namelist())
            if "xl/workbook.xml" in names:
                return "xlsx", "Excel workbook"
            if "word/document.xml" in names:
                return "docx", "Word document"
            if "ppt/presentation.xml" in names:
                return "pptx", "PowerPoint presentation"
            if "mimetype" in names:
                try:
                    mime = z.read("mimetype").decode("ascii", "replace").strip()
                except Exception:
                    mime = ""
                return "odf", _ODF_MIME.get(mime, f"OpenDocument file ({mime or 'unknown type'})")
            n = len(names)
            return "zip", f"a plain ZIP archive ({n} entr{'y' if n == 1 else 'ies'})"
    except zipfile.BadZipFile:
        return "corrupt", "a damaged or truncated ZIP container"
    except Exception:
        return "corrupt", "an unreadable ZIP container"


def ooxml_error(data: bytes, expected: str, exc: BaseException) -> RuntimeError:
    """The message an analyst gets when an Office parser is handed something that is not that format."""
    kind, what = describe_zip(data)
    if kind == expected:
        # Right container, still unreadable: keep the library's reason, it is the informative part.
        return RuntimeError(f"this {what} could not be read: {exc}")
    noun = {"xlsx": "an Excel workbook", "docx": "a Word document"}.get(expected, f"a .{expected} file")
    if kind == "zip":
        return RuntimeError(
            f"this file is {what}, not {noun}. "
            f"Rename it to .zip and Iris will expand it and parse what is inside.")
    if kind == "notzip":
        return RuntimeError(
            f"this file is {what}, so it is not {noun} despite the .{expected} name. Give it the "
            f"extension its format actually uses and re-upload.")
    if kind == "corrupt":
        return RuntimeError(f"this file is {what} - the upload may be incomplete.")
    article = "an" if what[:1].lower() in "aeiou" else "a"
    return RuntimeError(
        f"this file is {article} {what}, not {noun}. Open it in its own application and "
        f"save/export it as .{expected}, then re-upload.")
