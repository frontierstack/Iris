"""Phase 1 reads the file in chunks, and must produce EXACTLY what the whole buffer produced.

The reason it is chunked at all is memory: `raw_events` held the file three times over — the bytes, the
whole decoded `str`, and `splitlines()` as a list with every line its own object. Measured shapes from
the analyst's own corpus: a 639 MB binetflow export and a 1.9 GB capture, on a VM that segfaults under
exactly that allocation pressure. Nothing in phase 1 ever looks at more than one line at a time, so
none of it needed to exist.

But a chunked reader is where evidence quietly changes. Two failure modes, both silent:

  * a multi-byte character split across the boundary decodes to TWO replacement characters instead of
    one character, so the line the analyst reads is not the line in the file;
  * a CRLF split across the boundary becomes two line breaks, so one event becomes two — and every
    event id after it shifts, which moves every case-set citation in the file.

So these tests do not check that streaming "works". They check that streaming and the whole-buffer path
produce byte-identical events, with the chunk size turned down far enough to land a boundary inside
every awkward construct on purpose.
"""
from __future__ import annotations

import pytest

from app import enrich
from app.enrich import raw_events, raw_events_from_file


def _ids_and_raws(events):
    return [(e.id, e.ts, e.raw) for e in events]


def _both(tmp_path, blob: bytes, chunk: int, name: str = "s.log"):
    """The same bytes through both paths: one buffer, and a file read `chunk` bytes at a time."""
    path = tmp_path / name
    path.write_bytes(blob)
    whole = raw_events("s1", name, "syslog", blob, "", first_id=1)
    old = enrich.CHUNK_BYTES
    enrich.CHUNK_BYTES = chunk
    try:
        streamed = raw_events_from_file("s1", name, "syslog", path, "", first_id=1)
    finally:
        enrich.CHUNK_BYTES = old
    return whole, streamed


CASES = {
    "plain lines": b"alpha\nbravo\ncharlie\n",
    "no trailing newline": b"alpha\nbravo\ncharlie",
    "crlf": b"alpha\r\nbravo\r\ncharlie\r\n",
    "mixed crlf and lf": b"alpha\r\nbravo\ncharlie\r\n",
    "lone cr": b"alpha\rbravo\rcharlie\r",
    "blank lines": b"alpha\n\n\nbravo\n",
    "whitespace only lines": b"alpha\n   \n\t\nbravo\n",
    "empty": b"",
    "one line no break": b"single",
    "trailing cr only": b"alpha\nbravo\r",
    "multibyte": "alpha\nbrävo café ☃\nchar\U0001f600lie\n".encode("utf-8"),
    "invalid utf-8": b"alpha\n\xff\xfe bad bytes \x80\nbravo\n",
    "vertical tab and form feed": b"alpha\x0bbravo\x0ccharlie\n",
    "nel and line separator": "alpha\x85bravo charlie delta\n".encode("utf-8"),
    "very long line": b"x" * 5000 + b"\nshort\n",
    "no breaks at all": b"y" * 3000,
}


@pytest.mark.parametrize("name", sorted(CASES))
@pytest.mark.parametrize("chunk", [1, 2, 3, 5, 7, 8, 64, 4096])
def test_streaming_matches_the_whole_buffer(tmp_path, name: str, chunk: int) -> None:
    """Every chunk size lands a boundary somewhere different; all of them must agree with one buffer."""
    whole, streamed = _both(tmp_path, CASES[name], chunk)
    assert _ids_and_raws(streamed) == _ids_and_raws(whole), (
        f"{name!r} at chunk={chunk}: streaming produced different events")


def test_a_multibyte_character_split_across_the_boundary_stays_one_character(tmp_path) -> None:
    """The failure this is really guarding: a 3-byte snowman cut in half decodes to replacements."""
    blob = "a☃b\n".encode("utf-8")            # 61 e2 98 83 62 0a
    for chunk in (2, 3, 4):                        # boundaries inside the snowman
        whole, streamed = _both(tmp_path, blob, chunk)
        assert streamed[0].raw == "a☃b"
        assert _ids_and_raws(streamed) == _ids_and_raws(whole)


def test_a_crlf_split_across_the_boundary_is_one_line_break(tmp_path) -> None:
    """Two events where there should be one shifts every id after it — and every citation with them."""
    blob = b"alpha\r\nbravo\r\n"
    whole, streamed = _both(tmp_path, blob, 6)     # boundary falls exactly between CR and LF
    assert [e.raw for e in streamed] == ["alpha", "bravo"]
    assert _ids_and_raws(streamed) == _ids_and_raws(whole)


def test_event_ids_are_identical_across_the_two_paths(tmp_path) -> None:
    """Ids are load-bearing: case sets, notes and indicators cite them."""
    blob = b"".join(f"line {i}\n".encode() for i in range(500))
    whole, streamed = _both(tmp_path, blob, 37)
    assert [e.id for e in streamed] == [e.id for e in whole]
    assert [e.id for e in streamed][:3] == ["e1", "e2", "e3"]


def test_the_prefix_form_still_numbers_from_one(tmp_path) -> None:
    """Library sources use a per-source prefix; the streamed path must number them the same way."""
    path = tmp_path / "lib.log"
    path.write_bytes(b"a\nb\nc\n")
    enrich.CHUNK_BYTES, old = 2, enrich.CHUNK_BYTES
    try:
        evs = raw_events_from_file("s9", "lib.log", "syslog", path, "ls9", first_id=1)
    finally:
        enrich.CHUNK_BYTES = old
    assert [e.id for e in evs] == ["ls91", "ls92", "ls93"]


def test_progress_reaches_the_end_of_the_file(tmp_path) -> None:
    """The bar has to arrive: `total` comes from the file, not from a buffer nobody holds any more."""
    path = tmp_path / "big.log"
    blob = b"".join(f"2026-01-01T00:00:{i % 60:02d}Z line {i}\n".encode() for i in range(20_000))
    path.write_bytes(blob)
    seen: list[tuple[int, int]] = []
    enrich.CHUNK_BYTES, old = 8192, enrich.CHUNK_BYTES
    try:
        evs = raw_events_from_file("s2", "big.log", "syslog", path, "", first_id=1,
                                   progress=lambda done, n: seen.append((done, n)))
    finally:
        enrich.CHUNK_BYTES = old
    assert len(evs) == 20_000
    assert seen, "a streamed parse must still publish progress"
    assert [d for d, _ in seen] == sorted(d for d, _ in seen), "progress went backwards"
    assert max(d for d, _ in seen) <= len(blob)
    assert max(d for d, _ in seen) > len(blob) // 2, "progress never got past halfway"


def test_a_missing_file_is_an_ordinary_error(tmp_path) -> None:
    with pytest.raises(OSError):
        raw_events_from_file("s3", "gone.log", "syslog", tmp_path / "nope.log", "")


# ---------------------------------------------------------------- the helper's own contract
# `raw_events` skips blank lines, which HIDES a whole class of chunker bug from the tests above: a CRLF
# split across the boundary yields an extra EMPTY line, and the events come out identical anyway. That
# is luck, not correctness — `_iter_lines` is a general helper and its contract is the stronger one, so
# it is pinned against the thing it claims to reproduce: `bytes.decode(...).splitlines()`.
def _chunked(blob: bytes, size: int) -> list[str]:
    return list(enrich._iter_lines(blob[i:i + size] for i in range(0, len(blob), size) or [0]))


@pytest.mark.parametrize("name", sorted(CASES))
@pytest.mark.parametrize("chunk", [1, 2, 3, 5, 7, 8, 64, 4096])
def test_iter_lines_reproduces_splitlines_exactly(name: str, chunk: int) -> None:
    blob = CASES[name]
    expected = blob.decode("utf-8", "replace").splitlines()
    assert _chunked(blob, chunk) == expected, f"{name!r} at chunk={chunk}"


@pytest.mark.parametrize("chunk", [1, 2, 3, 4, 5, 6, 7])
def test_iter_lines_does_not_invent_a_blank_line_at_a_crlf_boundary(chunk: int) -> None:
    """The bug the event-level tests cannot see: CR and LF landing in different chunks reads as two
    breaks, so an empty line appears between them that is not in the file."""
    blob = b"alpha\r\nbravo\r\ncharlie"
    assert _chunked(blob, chunk) == ["alpha", "bravo", "charlie"]


@pytest.mark.parametrize("chunk", [1, 2, 3, 4])
def test_iter_lines_never_splits_a_multibyte_character(chunk: int) -> None:
    blob = "☃\U0001f600é\n".encode("utf-8")
    assert _chunked(blob, chunk) == ["☃\U0001f600é"]
    assert "�" not in "".join(_chunked(blob, chunk))
