"""CSV / TSV parser with header-row auto-detection (csv.Sniffer + heuristics)."""
from __future__ import annotations

import csv as _csv
import io
import itertools
from typing import Iterable, Iterator, Optional

from .base import BaseParser, ParsedEvent
from .tabular import ColumnRoles, looks_like_header

_CANDIDATES = [",", "\t", ";", "|"]


def sniff_dialect(lines: list[str]) -> Optional[str]:
    """Return the most likely delimiter or None if the sample doesn't look tabular."""
    text = "\n".join(lines[:50])
    try:
        d = _csv.Sniffer().sniff(text, delimiters="".join(_CANDIDATES))
        delim = d.delimiter
    except _csv.Error:
        delim = None
    best, best_score = None, 0.0
    for cand in _CANDIDATES:
        counts = [l.count(cand) for l in lines if l.strip()]
        if not counts or max(counts) == 0:
            continue
        # consistency of column count across rows
        rows = list(_csv.reader(lines[:100], delimiter=cand))
        widths = [len(r) for r in rows if r]
        if not widths:
            continue
        common = max(set(widths), key=widths.count)
        if common < 2:
            continue
        score = widths.count(common) / len(widths) * (1 + min(common, 10) / 20)
        if cand == delim:
            score += 0.15
        if score > best_score:
            best, best_score = cand, score
    return best


class CsvParser(BaseParser):
    name = "CSV (header)"
    family = "delimited.csv"
    chunkable = True
    quoted = True      # a quoted cell may contain newlines — chunk boundaries must respect quote parity

    def __init__(self, delimiter: Optional[str] = None) -> None:
        self.delimiter = delimiter
        self.header: Optional[list[str]] = None
        self.guessed: list[str] = []
        self.mapping = None

    def sniff(self, sample: list[str], filename: str = "", head: bytes = b"") -> float:
        lines = [l for l in sample if l.strip()][:200]
        if len(lines) < 2:
            return 0.0
        if any(l.lstrip().startswith(("{", "<", "[")) for l in lines[:5]):
            return 0.0
        d = sniff_dialect(lines)
        if not d:
            return 0.0
        rows = list(_csv.reader(lines[:100], delimiter=d))
        if len(rows) < 2 or not looks_like_header(rows[0], rows[1]):
            return 0.0
        widths = [len(r) for r in rows if r]
        common = max(set(widths), key=widths.count)
        consistency = widths.count(common) / len(widths)
        roles = ColumnRoles(rows[0])
        known = sum(1 for r in (roles.ts, roles.host, roles.user, roles.msg, roles.level) if r is not None)
        conf = 0.55 + 0.25 * consistency + 0.05 * min(known, 3)
        lower = filename.lower()
        if lower.endswith((".csv", ".tsv")):
            conf += 0.05
        return round(min(0.95, conf), 3)

    def parse(self, lines: Iterable[str]) -> Iterator[ParsedEvent]:
        it = iter(lines)
        buffer: list[str] = []
        for line in it:
            if line.strip():
                buffer.append(line.rstrip("\r\n"))
            if len(buffer) >= 100:
                break
        if not buffer:
            return
        d = self.delimiter or sniff_dialect(buffer) or ","
        self.delimiter = d
        head_rows = list(_csv.reader(buffer[:2], delimiter=d))
        header = head_rows[0] if head_rows and looks_like_header(head_rows[0], head_rows[1] if len(head_rows) > 1 else None) else None
        if header is None:
            ncol = max(len(r) for r in head_rows) if head_rows else 1
            header = [f"col{i + 1}" for i in range(ncol)]
            start = 0
        else:
            header = [h.strip() or f"col{i + 1}" for i, h in enumerate(header)]
            start = 1
        self.header = header
        self.guessed = list(header)
        roles = ColumnRoles(header)

        def rows_from(chunk: Iterable[str]) -> Iterator[ParsedEvent]:
            # feed a csv.reader line by line so `raw` stays the physical line (multi-line quoted cells are rejoined)
            pending = ""
            for line in chunk:
                l = line.rstrip("\r\n")
                if not l.strip() and not pending:
                    continue
                pending = (pending + "\n" + l) if pending else l
                try:
                    cells = next(_csv.reader(io.StringIO(pending), delimiter=d))
                except (StopIteration, _csv.Error):
                    cells = None
                if cells is None or (pending.count('"') % 2 == 1 and len(pending) < 20000):
                    continue
                yield roles.event(pending, cells)
                pending = ""
            if pending:
                yield roles.event(pending, pending.split(d))

        # ONE pass over the sniff buffer AND the rest of the file. Two calls put an artificial
        # record boundary at line 100: `rows_from` ends by flushing whatever is still `pending`
        # as a record, so a quoted cell that straddles that line was emitted as a malformed
        # half-record and the second call then started mid-cell — every record after it in the
        # file misaligned by a line, in the SINGLE-worker path, with nothing reporting it.
        yield from rows_from(itertools.chain(buffer[start:], it))
