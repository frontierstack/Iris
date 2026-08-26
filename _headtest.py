import io

CR, LF = chr(13), chr(10)
p = 'backend/tests/test_parse_progress.py'
s = io.open(p, encoding='utf-8', newline='').read()
NL = CR + LF if (CR + LF) in s else LF


def n(t):
    return t.replace(LF, NL) if NL != LF else t


# Replace the add_file-based test (which only exercised phase 1) with one at the level the bug lives.
start = s.index(n('@pytest.mark.parametrize("workers", [2, 4])\ndef test_parallel_agrees_when_a_quoted_cell_straddles_the_head'))
s = s[:start]

NEWTEST = '''def test_the_warm_up_head_never_ends_inside_a_quoted_cell() -> None:
    """A CSV cell may contain a newline, so counting newlines alone can cut the head mid-cell.

    The first assertion is the one that keeps this honest: it proves the fixture really does trip the
    old behaviour, so a green result means the fix works rather than that nothing was exercised.
    """
    data = _csv_multiline(4000)
    old_end, _ = _head_slice_by_lines(data)
    new_end, lines = par._head_slice(data, True)
    assert data.count(b\'"\', 0, old_end) % 2 == 1, "the fixture no longer cuts inside a quoted cell"
    assert data.count(b\'"\', 0, new_end) % 2 == 0, "the head still ends on an open quote"
    assert new_end > old_end and lines >= par.HEAD_LINES


def _head_slice_by_lines(data: bytes):
    """The pre-fix head: newline counting only, quote parity ignored."""
    lines, pos = 0, 0
    limit = min(len(data), par.HEAD_MAX_BYTES)
    while pos < limit and lines < par.HEAD_LINES:
        nl = data.find(b"\\n", pos)
        if nl < 0:
            return None
        if data[pos:nl].strip():
            lines += 1
        pos = nl + 1
    return (pos, lines) if lines >= par.HEAD_LINES else None


def _chunked_records(data: bytes, head_slice) -> list[str]:
    """Every record the CHUNKED path yields, the way `_run_chunk` yields it: each worker parses
    `head + chunk` from a pristine parser and discards the records the head alone produced."""
    import copy

    from app.parsers.csv import CsvParser

    parser = CsvParser()
    head_end, _ = head_slice
    pristine = copy.deepcopy(parser)
    par._reset_parser(pristine)
    head_text = data[:head_end].decode("utf-8", errors="replace")
    head_parsed = list(parser.parse(head_text.splitlines()))
    skip = len(head_parsed)
    out = [pe.raw for pe in head_parsed]
    for s, e in par._chunk_ranges(data, head_end, par.chunk_bytes(), True):
        worker = copy.deepcopy(pristine)
        text = head_text + data[s:e].decode("utf-8", errors="replace")
        out.extend(pe.raw for i, pe in enumerate(worker.parse(text.splitlines())) if i >= skip)
    return out


def test_a_head_cut_mid_cell_loses_records_and_the_fix_stops_it(monkeypatch) -> None:
    """The chunked path must yield exactly what one worker over the whole file yields.

    With the head cut inside an open quote, that quote swallows the first line of every chunk: the
    head\'s dangling record and the chunk\'s first record merge into one, and discarding
    `head_records` of them discards a real line of evidence per chunk. Silently — the source still
    reads READY, just with fewer events.
    """
    monkeypatch.setenv("IRIS_PARSE_CHUNK_MB", "0.06")
    from app.parsers.csv import CsvParser

    data = _csv_multiline(4000)
    whole = [pe.raw for pe in CsvParser().parse(data.decode().splitlines())]

    broken = _chunked_records(data, _head_slice_by_lines(data))
    fixed = _chunked_records(data, par._head_slice(data, True))

    assert fixed == whole, "the quote-aware head must reproduce the single-worker records exactly"
    assert broken != whole, "the fixture did not actually exercise the old failure"
    assert len(broken) < len(whole), f"expected lost records, got {len(broken)} vs {len(whole)}"
'''

s = s + n(NEWTEST)
io.open(p, 'w', encoding='utf-8', newline='').write(s)
print('test replaced')
