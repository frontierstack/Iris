"""What encoding a text log is in, and turning it into the UTF-8 every parser reads.

Iris decodes text as UTF-8. Three real kinds of log are not, and each failed silently:

* **UTF-8 with a byte-order mark** — Excel's "CSV UTF-8" and most Windows tools write EF BB BF first.
  Decoded as plain UTF-8 the mark became U+FEFF glued to the first header, so the column read
  `\\ufefftimestamp`, the timestamp role was never found, and the whole CSV sat in MAP unparsed.
  This one needs no transcode: `utf-8-sig` is UTF-8 that drops a leading mark, so every decode site
  uses it (`DECODE`), which costs nothing and holds for a file of any size.
* **Windows-1252** — a CSV exported by Excel in a western locale, an older Windows tool. One accented
  byte is invalid UTF-8, the file failed the binary check, and the Binary-strings parser took it:
  events like `connexion r` with byte offsets for fields, and `café` unfindable.
* **UTF-16 without a byte-order mark** — the same failure, with a NUL between every character.

The last two are TRANSCODED to UTF-8 once, where a file is expanded (`archives.expand`), exactly as
a UTF-16 export with a BOM always was; the codec is recorded on the source (`#<codec>`) so every
re-read — phase 2, the raw viewer — applies the same transcode and sees the same text.

Detection is conservative, because the failure it must not create is mojibake: a UTF-8 file with a
stray bad byte decoded as Windows-1252 turns every `é` into `Ã©`. So Windows-1252 is chosen only when
the bytes are NOT mostly valid UTF-8, and only for text-like content (few control characters, a
western share of high bytes); UTF-16 only when the NULs fall on one parity and the decoded text is
mostly ASCII — which a packet capture or a database, full of NULs everywhere, never is.
"""
from __future__ import annotations

import codecs
import re

DECODE = "utf-8-sig"       # UTF-8, minus a leading byte-order mark: the decode every text reader uses

UTF8_BOM = b"\xef\xbb\xbf"
_UTF16_BOMS = (b"\xff\xfe", b"\xfe\xff")
# a complete, valid multi-byte UTF-8 sequence
_UTF8_MULTI = re.compile(rb"[\xc2-\xdf][\x80-\xbf]|[\xe0-\xef][\x80-\xbf]{2}|[\xf0-\xf4][\x80-\xbf]{3}")
_CONTROL = frozenset(range(0, 9)) | {0x0B, 0x0C} | frozenset(range(0x0E, 0x20)) | {0x7F}


def _latin1_fallback(err: UnicodeDecodeError) -> tuple[str, int]:
    # the five bytes Windows-1252 leaves undefined (0x81 0x8D 0x8F 0x90 0x9D) are read as Latin-1,
    # which is what Windows itself shows for them — never a replacement character
    return err.object[err.start:err.end].decode("latin-1"), err.end


codecs.register_error("iris-latin1", _latin1_fallback)


def _texty(text: str, ascii_share: float = 0.0) -> bool:
    """Few control characters, and (when asked) mostly ASCII — what a log looks like decoded."""
    if not text:
        return False
    ctrl = sum(1 for ch in text if ord(ch) in _CONTROL)
    if ctrl > len(text) * 0.01:
        return False
    if ascii_share and sum(1 for ch in text if ord(ch) < 0x80) < len(text) * ascii_share:
        return False
    return True


def sniff(data: bytes) -> str:
    """The codec to transcode `data` from, or '' when it is UTF-8 already (or not text at all).

    `data` is the file's opening bytes, or the whole file when it is in hand — the more bytes, the
    likelier a Windows-1252 file's first accented character is in them.
    """
    if not data:
        return ""
    if data.startswith(_UTF16_BOMS):
        text = data[2:4096 + 2].decode("utf-16-le" if data[:2] == b"\xff\xfe" else "utf-16-be", errors="replace")
        return "utf-16" if _texty(text) else ""
    if data.startswith(UTF8_BOM):
        return ""                                  # UTF-8; DECODE drops the mark
    head = data[:65536]
    if len(head) >= 64 and b"\x00" in head:
        even, odd = head[0::2], head[1::2]
        z_even, z_odd = even.count(0) / len(even), odd.count(0) / len(odd)
        cand = "utf-16-le" if z_odd > 0.4 and z_even < 0.05 else \
               "utf-16-be" if z_even > 0.4 and z_odd < 0.05 else ""
        if cand:
            text = head[: len(head) // 2 * 2].decode(cand, errors="replace")
            if ("\n" in text or "\r" in text) and _texty(text, ascii_share=0.9):
                return cand
        return ""                                  # NULs and not UTF-16: binary, not ours
    if b"\x00" in data:
        return ""
    try:
        data.decode("utf-8")
        return ""
    except UnicodeDecodeError as exc:
        if exc.start >= len(data) - 3:
            try:                                   # only a multi-byte character cut off at the end
                data[:exc.start].decode("utf-8")
                return ""
            except UnicodeDecodeError:
                pass
    # Not valid UTF-8. Mostly-valid UTF-8 with a few bad bytes stays UTF-8 (a replacement character
    # per bad byte is honest; `Ã©` for every good one would not be).
    sample = data[:1 << 20]
    good = len(_UTF8_MULTI.findall(sample))
    bad = sample.decode("utf-8", errors="replace").count("�")
    if good >= bad:
        return ""
    high = sum(1 for b in sample if b >= 0x80)
    if high > len(sample) * 0.3:
        return ""                                  # too many high bytes for western text: binary
    return "cp1252" if _texty(sample.decode("cp1252", errors="iris-latin1")) else ""


def transcode(data: bytes, codec: str) -> bytes:
    """`data` re-encoded as UTF-8 from `codec` (a value `sniff` returned)."""
    if codec == "cp1252":
        return data.decode("cp1252", errors="iris-latin1").encode("utf-8")
    return data.decode(codec, errors="replace").encode("utf-8")
