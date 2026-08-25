"""Archive expansion: turn an uploaded container into the log files inside it.

One entry point, `expand(filename, data)`, returns the members to ingest AND the problems worth telling the
analyst about (`Expanded.errors`). Errors are never swallowed: a password-protected archive, a member that
tried to escape the extraction root, or a bomb that tripped the caps all come back as a plain-English string
that the upload endpoints turn into an ERROR source, so the UI shows it instead of silently ingesting nothing.

Member names carry the provenance: `incident.zip!var/log/auth.log`, and for nesting
`outer.zip!inner.tar.gz!var/log/auth.log`. That string becomes Source.file / Event.file, so a line can always
be traced back to the archive it came from.

Guards:
  * zip-slip  - absolute paths, drive letters and any `..` component are refused, per member.
  * zip bomb  - total uncompressed bytes, per-member bytes and entry count are capped; tripping a cap stops
                the expansion and reports it rather than eating the machine's RAM.
  * nesting   - archives inside archives are expanded to MAX_DEPTH levels, then reported as too deep.

7z and RAR need optional third-party packages. The imports are guarded and their absence is reported as an
unsupported-format message; the app never depends on them.
"""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import re
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Optional

MAX_DEPTH = 3                            # outer archive = depth 0
MAX_ENTRIES = 5_000                      # members across the whole expansion
MAX_TOTAL_BYTES = 512 * 1024 * 1024      # uncompressed bytes across the whole expansion
MAX_MEMBER_BYTES = 256 * 1024 * 1024     # uncompressed bytes for one member

ZIP_MAGIC = b"PK\x03\x04"
GZIP_MAGIC = b"\x1f\x8b"
BZIP2_MAGIC = b"BZh"
XZ_MAGIC = b"\xfd7zXZ\x00"
SEVENZ_MAGIC = b"7z\xbc\xaf\x27\x1c"
RAR_MAGIC = b"Rar!\x1a\x07"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

TAR_EXTENSIONS = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tbz2", ".tar.xz", ".txz", ".tar.zst")
ARCHIVE_EXTENSIONS = (".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".zst") + TAR_EXTENSIONS

SEVENZ_MISSING = ("7-Zip archives need the optional 'py7zr' package (pip install py7zr). "
                  "Re-pack the evidence as .zip or .tar.gz to ingest it now.")
RAR_MISSING = ("RAR archives are not supported out of the box: extracting one needs the 'rarfile' package "
               "(pip install rarfile) AND an external unrar binary, whose licence is non-free, so Iris does "
               "not ship it. Install rarfile plus unrar (or the BSD-licensed bsdtar: apt install "
               "libarchive-tools) on the host, or re-pack the evidence as .zip, .7z or .tar.gz.")
ZSTD_MISSING = ("Zstandard archives need the optional 'zstandard' package (pip install zstandard). "
                "Re-compress the evidence as .gz or .xz to ingest it now.")

OOXML_MARKER = b"[Content_Types].xml"
# Documents: a zip whose parser wants the WHOLE file, never its entries.
DOCUMENT_EXTENSIONS = (".xlsx", ".xlsm", ".docx", ".docm", ".pptx", ".pptm", ".odt", ".ods", ".odp")
# Packages: also zips, also kept whole - but because their entries are code and metadata, not evidence.
# Expanding a .jar into the pool puts hundreds of .class files in front of the analyst.
PACKAGE_EXTENSIONS = (".epub", ".jar", ".apk", ".vsix", ".nupkg", ".whl")
OFFICE_EXTENSIONS = DOCUMENT_EXTENSIONS + PACKAGE_EXTENSIONS

# What `zip_kind` can answer. 'zip' = a plain archive; 'unknown' = the directory could not be read
# (a truncated sniff head, a damaged container), which is NOT the same as "not a document".
DOCUMENT_KINDS = ("xlsx", "docx", "pptx", "odf")

_TEXT_EXTENSIONS = (".log", ".txt", ".csv", ".tsv", ".json", ".jsonl", ".xml", ".evtx.xml")


def is_ooxml(data: bytes) -> bool:
    """True for Office Open XML containers (xlsx/docx/pptx): a zip whose directory lists [Content_Types].xml."""
    if not data.startswith(ZIP_MAGIC):
        return False
    if OOXML_MARKER in data[:4096]:
        return True
    return OOXML_MARKER in data[-65536:]  # central directory sits at the end


def zip_kind(data: bytes) -> str:
    """What a zip REALLY is, from its own directory: xlsx|docx|pptx|odf|zip|unknown.

    `[Content_Types].xml` says "some OOXML package", not "an Excel workbook" - a .vsix, a .nupkg and an
    .apk all carry it. Routing on that marker plus the extension is what handed openpyxl a container it
    could only fail on, with a message about the ZIP's internals. Ask the namelist instead.

    'unknown' means the question could not be answered here (the caller holds a 64 KB sniff head, or the
    container is damaged); it must never be read as "not a document".
    """
    return zip_kind_fh(io.BytesIO(data))


def zip_kind_fh(fh) -> str:
    """`zip_kind` for an open seekable file - the central directory is at the END, so this needs the file."""
    try:
        fh.seek(0)
        if fh.read(4) != ZIP_MAGIC:
            return "unknown"
        fh.seek(0)
        with zipfile.ZipFile(fh) as z:
            names = set(z.namelist())
            if "xl/workbook.xml" in names or "xl/workbook.bin" in names:
                return "xlsx"
            if "word/document.xml" in names:
                return "docx"
            if "ppt/presentation.xml" in names:
                return "pptx"
            if "mimetype" in names:
                try:
                    if z.read("mimetype").startswith(b"application/vnd.oasis.opendocument"):
                        return "odf"
                except Exception:
                    return "unknown"
            return "zip"
    except Exception:
        return "unknown"


def is_document(name: str, data: bytes) -> bool:
    """True when this file is an Office/ODF DOCUMENT and must be handed to its parser whole.

    Detected from the container, never from the extension alone: a plain .zip full of logs that someone
    named `report.xlsx` is a zip, and the useful outcome is to EXPAND it and parse what is inside -
    not to fail the file (and, before this, the whole upload it arrived in) with "rename it to .zip".
    """
    lower = name.lower()
    if not data[:4].startswith(ZIP_MAGIC):
        # Not a zip at all. Claimed by name so the Office parser can explain the mismatch by name;
        # nothing here can expand it either way.
        return lower.endswith(DOCUMENT_EXTENSIONS)
    kind = zip_kind(data)
    if kind in DOCUMENT_KINDS:
        return True
    if kind == "unknown":  # unreadable directory: trust the name rather than shredding a real document
        return lower.endswith(DOCUMENT_EXTENSIONS) or is_ooxml(data)
    return False


@dataclass
class Expanded:
    """Members to ingest plus every problem worth showing the analyst."""

    members: list[tuple[str, bytes]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # `expand_path` only: this file is NOT a container and its single member IS the file on disk, so
    # `members` is empty and the caller should read (or stream) the path itself. It exists so that
    # deciding "this 1.9 GB capture is not an archive" costs a 64 KB read instead of 1.9 GB — which is
    # the whole point of having a path-based entry point at all.
    passthrough: bool = False
    # `expand`/`expand_path`: the single member IS the file, but its BYTES are not — a UTF-16 text export
    # was transcoded to UTF-8 in memory. Anything that re-reads the file (phase 2, a remap, the raw
    # viewer) must re-apply the transcode, or it reads the raw UTF-16 as UTF-8 and every line comes
    # back full of NULs while the source still reports `enriched`. See `TRANSCODE_MEMBER`.
    transcoded: bool = False

    @property
    def ok(self) -> bool:
        return not self.errors


# The pseudo member name `read_member` accepts for "the whole file, transcoded from UTF-16". Recorded
# as `<file>!<marker>` in `Store.source_member` so the re-read path is the same as for an archive member.
TRANSCODE_MEMBER = "#utf-16"


class _Budget:
    """Shared caps for one expansion (including everything nested inside it)."""

    def __init__(self) -> None:
        self.entries = 0
        self.total = 0
        self.tripped = ""

    def take(self, size: int) -> bool:
        if self.tripped:
            return False
        if self.entries >= MAX_ENTRIES:
            self.tripped = (f"archive stopped after {MAX_ENTRIES:,} files - it holds more entries than Iris will "
                            "expand in one upload (possible zip bomb). Extract it yourself and upload the files "
                            "you need.")
            return False
        if self.total + size > MAX_TOTAL_BYTES:
            self.tripped = (f"archive stopped at the {MAX_TOTAL_BYTES // (1024 * 1024)} MB uncompressed limit "
                            "(possible zip bomb). Extract it yourself and upload the files you need.")
            return False
        self.entries += 1
        self.total += size
        return True


def safe_member_name(name: str) -> Optional[str]:
    """Normalize an archive member path, or None if it tries to escape the extraction root (zip-slip).

    Rejected: absolute POSIX paths, Windows drive letters, UNC paths, and any `..` component. Iris never
    writes members to their archive-relative path, but a traversal attempt is evidence in its own right and
    must be reported rather than quietly flattened.
    """
    raw = str(name or "").replace("\\", "/").strip()
    if not raw:
        return None
    if raw.startswith("/") or raw.startswith("//"):
        return None
    if re.match(r"^[A-Za-z]:", raw):
        return None
    parts = [p for p in PurePosixPath(raw).parts if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return None
    return "/".join(parts) or None


def _join(outer: str, inner: str) -> str:
    return f"{outer}!{inner}"


def _looks_like_archive(name: str, data: bytes) -> bool:
    lower = name.lower()
    if lower.endswith(PACKAGE_EXTENSIONS) or is_document(name, data):
        return False
    if lower.endswith(ARCHIVE_EXTENSIONS):
        return True
    return bool(data[:8].startswith((ZIP_MAGIC, GZIP_MAGIC, BZIP2_MAGIC, XZ_MAGIC, SEVENZ_MAGIC, RAR_MAGIC))
                or _is_tar(data))


def _is_tar(data: bytes) -> bool:
    return len(data) > 262 and data[257:262] == b"ustar"


def _strip_compression_suffix(name: str) -> str:
    lower = name.lower()
    for suffix in (".gz", ".bz2", ".xz", ".zst", ".z"):
        if lower.endswith(suffix):
            return name[: -len(suffix)]
    return name


def expand(filename: str, data: bytes) -> Expanded:
    """Expand an uploaded file. Non-archives come back as the single member they are."""
    out = Expanded()
    budget = _Budget()
    _expand_into(out, budget, filename, data, depth=0)
    if budget.tripped:
        out.errors.append(f"{filename}: {budget.tripped}")
    return out


# How much of a container is read to decide WHAT it is. Every sniff here looks at a magic number, an
# extension or the tar header at offset 257 — none of them needs more than a few hundred bytes.
SNIFF_BYTES = 64 * 1024


def expand_path(filename: str, path) -> Expanded:
    """`expand`, reading the container from DISK instead of from a copy of it in memory.

    The 3.35 GB packet-capture bundle is what this exists for. `expand(filename, data)` needs the whole
    container as one `bytes` before it can look at the first member — so staging that archive meant 3.6
    GB of RAM on top of the members it produced, on a VM that segfaults under exactly that pressure.

    zip and tar are the two containers that can be READ member at a time from an open file, and they are
    also the two that arrive big, so those open the path directly and never hold more than one member.
    Everything else falls back to `expand()` over the file's bytes, deliberately: the single-file
    compressors (gz/bz2/xz/zst) decompress into memory whatever we do, 7z and RAR are third-party
    readers with their own file handling, and a NON-container is about to be parsed from this same path
    anyway. All of them are already bounded by MAX_MEMBER_BYTES; the outer container was not.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(SNIFF_BYTES)
    except OSError as exc:
        out = Expanded()
        out.errors.append(f"{filename}: could not be read ({type(exc).__name__}: {exc}).")
        return out

    lower = filename.lower()
    # An Office/OOXML package is a zip that is a DOCUMENT — its parser wants the whole file, not its
    # entries. Which it is lives in the central directory at the END of the file, which a 64 KB head
    # does not contain, so the question is asked of the open file rather than of the sniff head.
    is_zip = head.startswith(ZIP_MAGIC) or lower.endswith(".zip")
    if is_zip and not lower.endswith(PACKAGE_EXTENSIONS):
        out, budget = Expanded(), _Budget()
        try:
            with open(path, "rb") as fh:
                kind = zip_kind_fh(fh)
                if kind in DOCUMENT_KINDS or (kind == "unknown" and lower.endswith(DOCUMENT_EXTENSIONS)):
                    # A real document: its parser reads it from this same path, so never load it here.
                    return Expanded(passthrough=True)
                fh.seek(0)
                _expand_zip(out, budget, filename, None, 0, fileobj=fh)
        except OSError as exc:
            out.errors.append(f"{filename}: could not be read ({type(exc).__name__}: {exc}).")
        if budget.tripped:
            out.errors.append(f"{filename}: {budget.tripped}")
        return out

    if _is_tar(head) or lower.endswith(TAR_EXTENSIONS) or _compressed_tar(head):
        out, budget = Expanded(), _Budget()
        opened = False
        try:
            with open(path, "rb") as fh:
                opened = _expand_tar(out, budget, filename, None, 0, fileobj=fh)
        except OSError as exc:
            out.errors.append(f"{filename}: could not be read ({type(exc).__name__}: {exc}).")
            return out
        if opened:
            if budget.tripped:
                out.errors.append(f"{filename}: {budget.tripped}")
            return out
        # not actually a tar after all — fall through and let the byte path decide

    # The formats that still need the whole file in memory. Each one either decompresses into RAM
    # regardless (gz/bz2/xz/zst), is handled by a third-party reader with its own file handling
    # (7z/rar), or rewrites the bytes before anything else sees them (a UTF-16 text export). All are
    # bounded by MAX_MEMBER_BYTES once expanded; none of them is the multi-gigabyte case.
    if (head.startswith((GZIP_MAGIC, BZIP2_MAGIC, XZ_MAGIC, ZSTD_MAGIC, SEVENZ_MAGIC, RAR_MAGIC))
            or lower.endswith((".gz", ".bz2", ".xz", ".lzma", ".zst", ".7z", ".rar"))
            or (head[:2] in (b"\xff\xfe", b"\xfe\xff") and lower.endswith(_TEXT_EXTENSIONS))):
        try:
            return expand(filename, _read_all(path))
        except OSError as exc:
            out = Expanded()
            out.errors.append(f"{filename}: could not be read ({type(exc).__name__}: {exc.strerror or exc}).")
            return out

    # Not a container. Say so instead of reading it: the caller has the path and is about to parse
    # from it anyway, and this is the branch every large log takes.
    return Expanded(passthrough=True)


def _read_all(path) -> bytes:
    with open(path, "rb") as fh:      # an unreadable file is the CALLER's error to report, by name
        return fh.read()


def _bytes_of(data: Optional[bytes], fileobj) -> bytes:
    """The container's own bytes, loaded only on the branch that actually keeps them as a member."""
    if data is not None:
        return data
    if fileobj is None:
        return b""
    try:
        fileobj.seek(0)
        return fileobj.read()
    except Exception:
        return b""


def read_member(path, member: str) -> bytes:
    """The bytes of ONE member of a staged container, read from disk.

    `member` is the provenance path Iris already puts on the source — `bundle.zip!var/log/auth.log`, and
    for nesting `outer.zip!inner.tar!var/log/auth.log`. The first segment names the container itself and
    is dropped; what follows is walked one level at a time.

    This is what makes a staged archive's members honest. `Store.source_paths[sid]` for such a member is
    the CONTAINER, so anything that re-read "the source's file" got the archive: phase 2 replaced a
    perfectly parsed syslog member with lines of decoded zip binary and reported the source `enriched`.
    Reading the member back is also the bounded thing to do — MAX_MEMBER_BYTES, not the archive's size.
    """
    parts = member.split("!")
    if len(parts) < 2:
        raise ValueError(f"{member!r} does not name a member inside a container")
    if parts[-1] == TRANSCODE_MEMBER:
        # a UTF-16 text export, transcoded at ingest: hand back the SAME bytes the parsers first saw
        with open(path, "rb") as fh:
            return fh.read().decode("utf-16").encode("utf-8")
    blob: Optional[bytes] = None
    for i, want in enumerate(parts[1:]):
        if i == 0:
            with open(path, "rb") as fh:
                blob = _read_one(fh, want)
        else:
            blob = _read_one(io.BytesIO(blob or b""), want)
        if blob is None:
            raise KeyError(f"{member!r}: {want!r} is not in the container")
    return blob or b""


def _read_one(fh, want: str) -> Optional[bytes]:
    """One member out of an open zip, tar, or single-file compressor, by its (sanitised) inner path.

    A .gz/.bz2/.xz/.zst that is NOT a tar has exactly one payload, and that payload is the member —
    `_expand_single` names it after the file minus its suffix. This used to be unreachable: only zip
    and tar were walked, so a `auth.log.gz` staged into the library parsed fine in phase 1 and then
    failed phase 2 with "'auth.log' does not name a member inside a container" — every compressed
    log, every time, on the path uploads now take by default.
    """
    head = fh.read(SNIFF_BYTES)
    fh.seek(0)
    if head.startswith(ZIP_MAGIC):
        with zipfile.ZipFile(fh) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if safe_member_name(info.filename) == want:
                    return zf.read(info)
        return None
    if head.startswith((GZIP_MAGIC, BZIP2_MAGIC, XZ_MAGIC, ZSTD_MAGIC)):
        try:
            if head.startswith(ZSTD_MAGIC):
                raise tarfile.ReadError("zstd")       # tarfile cannot open zstd; the payload path handles it
            with tarfile.open(fileobj=fh, mode="r:*") as tf:
                return _read_tar_member(tf, want)
        except tarfile.ReadError:
            fh.seek(0)
            blob = _decompress_single(fh.read())
            # the payload may itself be a container (a zipped log inside a .gz): keep walking
            if blob.startswith(ZIP_MAGIC) or _is_tar(blob):
                return _read_one(io.BytesIO(blob), want)
            return blob
    with tarfile.open(fileobj=fh, mode="r:*") as tf:
        return _read_tar_member(tf, want)


def _read_tar_member(tf, want: str) -> Optional[bytes]:
    while True:
        m = tf.next()
        if m is None:
            return None
        if not m.isfile() or safe_member_name(m.name) != want:
            continue
        got = tf.extractfile(m)
        return got.read() if got is not None else b""


def _decompress_single(data: bytes) -> bytes:
    if data.startswith(GZIP_MAGIC):
        return gzip.decompress(data)
    if data.startswith(BZIP2_MAGIC):
        return bz2.decompress(data)
    if data.startswith(XZ_MAGIC):
        return lzma.decompress(data)
    import zstandard  # guarded at expansion time; a stream that expanded once has the module
    return zstandard.ZstdDecompressor().decompress(data, max_output_size=MAX_MEMBER_BYTES)


# ------------------------------------------------------------------------ internals
def _emit(out: Expanded, budget: _Budget, name: str, blob: bytes, depth: int) -> None:
    """Add a member, recursing when it is itself an archive."""
    if len(blob) > MAX_MEMBER_BYTES:
        out.errors.append(f"{name}: member is larger than the "
                          f"{MAX_MEMBER_BYTES // (1024 * 1024)} MB per-file limit and was skipped.")
        return
    if not budget.take(len(blob)):
        return
    if depth < MAX_DEPTH and _looks_like_archive(name, blob):
        before = len(out.members)
        _expand_into(out, budget, name, blob, depth + 1)
        if len(out.members) != before or budget.tripped:
            return
        # nothing came out of it (empty container) - keep the bytes so the analyst still sees the file
    elif depth >= MAX_DEPTH and _looks_like_archive(name, blob):
        out.errors.append(f"{name}: nested archives deeper than {MAX_DEPTH} levels are not expanded; "
                          "the container was kept as-is.")
    out.members.append((name, blob))


def _expand_into(out: Expanded, budget: _Budget, filename: str, data: bytes, depth: int) -> None:
    lower = filename.lower()

    # Office documents and packages are zips, but they are not evidence CONTAINERS - keep them whole and
    # hand them to their parser. Anything else that merely looks like one (a plain zip named .xlsx, an
    # OOXML package that is not a document) falls through and is expanded like the archive it is.
    if lower.endswith(PACKAGE_EXTENSIONS) or is_document(filename, data):
        out.members.append((filename, data))
        return

    if data.startswith(SEVENZ_MAGIC) or lower.endswith(".7z"):
        _expand_7z(out, budget, filename, data, depth)
        return
    if data.startswith(RAR_MAGIC) or lower.endswith(".rar"):
        _expand_rar(out, budget, filename, data, depth)
        return
    if data.startswith(ZIP_MAGIC) or lower.endswith(".zip"):
        _expand_zip(out, budget, filename, data, depth)
        return

    # tarballs, including the compressed flavours tarfile opens transparently
    if _is_tar(data) or lower.endswith(TAR_EXTENSIONS) or _compressed_tar(data):
        if _expand_tar(out, budget, filename, data, depth):
            return

    if data.startswith(GZIP_MAGIC) or lower.endswith(".gz"):
        _expand_single(out, budget, filename, data, depth, gzip.decompress, "gzip")
        return
    if data.startswith(BZIP2_MAGIC) or lower.endswith(".bz2"):
        _expand_single(out, budget, filename, data, depth, bz2.decompress, "bzip2")
        return
    if data.startswith(XZ_MAGIC) or lower.endswith((".xz", ".lzma")):
        _expand_single(out, budget, filename, data, depth, lzma.decompress, "xz")
        return
    if data.startswith(ZSTD_MAGIC) or lower.endswith(".zst"):
        _expand_zstd(out, budget, filename, data, depth)
        return

    if depth == 0 and data[:2] in (b"\xff\xfe", b"\xfe\xff") and lower.endswith(_TEXT_EXTENSIONS):
        try:  # UTF-16 text export (PowerShell Out-File default): transcode so text parsers can read it
            out.members.append((filename, data.decode("utf-16").encode("utf-8")))
            out.transcoded = True
            return
        except UnicodeDecodeError:
            pass

    out.members.append((filename, data))


def _compressed_tar(data: bytes) -> bool:
    """A .gz/.bz2/.xz stream whose first block is a tar header (named e.g. `logs.gz` by accident)."""
    if not data[:8].startswith((GZIP_MAGIC, BZIP2_MAGIC, XZ_MAGIC)):
        return False
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            return tf.next() is not None
    except Exception:
        return False


def _expand_single(out: Expanded, budget: _Budget, filename: str, data: bytes, depth: int,
                   decompress, label: str) -> None:
    """One-file compressors (gz/bz2/xz): the payload keeps the outer name minus the suffix."""
    try:
        blob = decompress(data)
    except Exception as exc:
        out.errors.append(f"{filename}: {label} stream could not be decompressed ({type(exc).__name__}: {exc}).")
        out.members.append((filename, data))
        return
    inner = _strip_compression_suffix(filename)
    if inner == filename:
        inner = f"{filename}.out"
    name = inner if depth == 0 else _join(filename, PurePosixPath(inner).name)
    _emit(out, budget, name, blob, depth)


def _expand_zip(out: Expanded, budget: _Budget, filename: str, data: Optional[bytes], depth: int,
                fileobj=None) -> None:
    """`data` may be None when `fileobj` is an open file: a 3.35 GB zip must never be read into RAM
    whole just to list what is inside it. The only branch that still needs the bytes is the one that
    keeps an unreadable container as its own member, and it loads them there."""
    try:
        zf = zipfile.ZipFile(fileobj if fileobj is not None else io.BytesIO(data or b""))
    except zipfile.BadZipFile as exc:
        out.errors.append(f"{filename}: not a readable zip archive ({exc}).")
        out.members.append((filename, _bytes_of(data, fileobj)))
        return
    encrypted: list[str] = []
    traversal: list[str] = []
    with zf:
        for info in zf.infolist():
            if budget.tripped:
                break
            if info.is_dir():
                continue
            safe = safe_member_name(info.filename)
            if safe is None:
                traversal.append(info.filename)
                continue
            if info.flag_bits & 0x1:
                encrypted.append(safe)
                continue
            if info.file_size > MAX_MEMBER_BYTES:
                out.errors.append(f"{_join(filename, safe)}: member is larger than the "
                                  f"{MAX_MEMBER_BYTES // (1024 * 1024)} MB per-file limit and was skipped.")
                continue
            if PurePosixPath(safe).name.startswith("."):
                continue  # __MACOSX / dotfile noise
            try:
                blob = zf.read(info)
            except RuntimeError as exc:
                if "encrypted" in str(exc).lower():
                    encrypted.append(safe)
                else:
                    out.errors.append(f"{_join(filename, safe)}: could not be extracted ({exc}).")
                continue
            except Exception as exc:
                out.errors.append(f"{_join(filename, safe)}: could not be extracted "
                                  f"({type(exc).__name__}: {exc}).")
                continue
            if not blob:
                continue
            _emit(out, budget, _join(filename, safe), blob, depth)
    if encrypted:
        out.errors.append(
            f"{filename} is password protected (encrypted zip): {len(encrypted)} file(s) were NOT ingested "
            f"- {', '.join(encrypted[:5])}{' ...' if len(encrypted) > 5 else ''}. "
            "Iris cannot decrypt archives; extract it with the password and upload the contents."
        )
    if traversal:
        out.errors.append(
            f"{filename}: {len(traversal)} member(s) use a path that escapes the archive root and were "
            f"refused - {', '.join(traversal[:3])}. This is a path-traversal (zip-slip) attempt."
        )


def _expand_tar(out: Expanded, budget: _Budget, filename: str, data: Optional[bytes], depth: int,
                fileobj=None) -> bool:
    try:
        tf = tarfile.open(fileobj=(fileobj if fileobj is not None else io.BytesIO(data or b"")), mode="r:*")
    except Exception as exc:
        out.errors.append(f"{filename}: not a readable tar archive ({type(exc).__name__}: {exc}).")
        return False
    traversal: list[str] = []
    with tf:
        while True:
            if budget.tripped:
                break
            try:
                member = tf.next()
            except Exception as exc:
                out.errors.append(f"{filename}: tar stream ended early ({type(exc).__name__}: {exc}).")
                break
            if member is None:
                break
            if not member.isfile():
                continue  # directories, symlinks and devices are never materialised
            safe = safe_member_name(member.name)
            if safe is None:
                traversal.append(member.name)
                continue
            if member.size > MAX_MEMBER_BYTES:
                out.errors.append(f"{_join(filename, safe)}: member is larger than the "
                                  f"{MAX_MEMBER_BYTES // (1024 * 1024)} MB per-file limit and was skipped.")
                continue
            if PurePosixPath(safe).name.startswith("."):
                continue
            try:
                fh = tf.extractfile(member)
                blob = fh.read() if fh is not None else b""
            except Exception as exc:
                out.errors.append(f"{_join(filename, safe)}: could not be extracted "
                                  f"({type(exc).__name__}: {exc}).")
                continue
            if not blob:
                continue
            _emit(out, budget, _join(filename, safe), blob, depth)
    if traversal:
        out.errors.append(
            f"{filename}: {len(traversal)} member(s) use a path that escapes the archive root and were "
            f"refused - {', '.join(traversal[:3])}. This is a path-traversal (tar-slip) attempt."
        )
    return True


def _expand_7z(out: Expanded, budget: _Budget, filename: str, data: bytes, depth: int) -> None:
    try:
        import py7zr
    except Exception:
        out.errors.append(f"{filename}: {SEVENZ_MISSING}")
        out.members.append((filename, data))
        return
    try:
        archive = py7zr.SevenZipFile(io.BytesIO(data))
    except Exception as exc:
        text = f"{type(exc).__name__}: {exc}"
        if "password" in text.lower() or "encrypt" in text.lower():
            out.errors.append(f"{filename} is password protected (encrypted 7-Zip archive) and was NOT "
                              "ingested. Extract it with the password and upload the contents.")
        else:
            out.errors.append(f"{filename}: not a readable 7-Zip archive ({text}).")
        out.members.append((filename, data))
        return
    traversal: list[str] = []
    with archive:
        try:
            if archive.needs_password():
                out.errors.append(f"{filename} is password protected (encrypted 7-Zip archive) and was NOT "
                                  "ingested. Extract it with the password and upload the contents.")
                out.members.append((filename, data))
                return
            entries = _sevenz_entries(archive)
        except Exception as exc:
            out.errors.append(f"{filename}: 7-Zip archive could not be read "
                              f"({type(exc).__name__}: {exc}).")
            out.members.append((filename, data))
            return

        # Plan first, decompress second: the member list carries the uncompressed sizes, so an over-sized
        # member or a bomb is refused BEFORE its bytes are ever expanded into RAM.
        planned: list[tuple[str, str]] = []  # (archive name, safe name)
        running = budget.total
        overflow = 0
        for inner, size in entries:
            safe = safe_member_name(inner)
            if safe is None:
                traversal.append(str(inner))
                continue
            if size > MAX_MEMBER_BYTES:
                out.errors.append(f"{_join(filename, safe)}: member is larger than the "
                                  f"{MAX_MEMBER_BYTES // (1024 * 1024)} MB per-file limit and was skipped.")
                continue
            if PurePosixPath(safe).name.startswith("."):
                continue
            if running + size > MAX_TOTAL_BYTES:
                overflow = max(overflow, size)
                continue
            planned.append((inner, safe))
            running += size

        contents: dict[str, bytes] = {}
        if planned:
            try:
                contents = _sevenz_read(archive, [inner for inner, _ in planned])
            except Exception as exc:
                out.errors.append(f"{filename}: 7-Zip archive could not be read "
                                  f"({type(exc).__name__}: {exc}).")
                out.members.append((filename, data))
                return
        for inner, safe in planned:
            if budget.tripped:
                break
            blob = contents.get(inner) or b""
            if not blob:
                continue
            _emit(out, budget, _join(filename, safe), blob, depth)
        if overflow and not budget.tripped:
            budget.take(overflow)  # trips the cap so the analyst is told the archive was cut short
    if traversal:
        out.errors.append(f"{filename}: {len(traversal)} member(s) escape the archive root and were refused "
                          f"- {', '.join(traversal[:3])}.")


def _sevenz_entries(archive) -> list[tuple[str, int]]:
    """[(member name, uncompressed size)] for the files in a 7z archive (directories excluded)."""
    out: list[tuple[str, int]] = []
    for info in archive.list() or []:
        if getattr(info, "is_directory", False):
            continue
        name = str(getattr(info, "filename", "") or "")
        if not name:
            continue
        out.append((name, int(getattr(info, "uncompressed", 0) or 0)))
    return out


def _sevenz_read(archive, names: list[str]) -> dict[str, bytes]:
    """Decompress the named members to bytes across BOTH py7zr generations.

    py7zr 1.0 deleted `read()`/`readall()` in favour of `extract(factory=...)` with a `WriterFactory`
    (py7zr.io.BytesIOFactory). Supporting only the old call silently returned zero members on a modern
    install, so both are handled and the archive is rewound between attempts.
    """
    if hasattr(archive, "readall") or hasattr(archive, "read"):
        try:
            reader = getattr(archive, "read", None)
            contents = reader(targets=names) if reader is not None else archive.readall()
            out: dict[str, bytes] = {}
            for name, buf in (contents or {}).items():
                try:
                    buf.seek(0)
                except Exception:
                    pass
                out[str(name)] = buf.read() or b""
            if out:
                return out
        except Exception:
            pass
        try:
            archive.reset()
        except Exception:
            pass
    from py7zr.io import BytesIOFactory  # py7zr >= 1.0

    factory = BytesIOFactory(MAX_MEMBER_BYTES)
    archive.extract(targets=list(names), factory=factory)
    out = {}
    for name in names:
        try:
            buf = factory.get(name)
        except Exception:
            continue
        try:
            buf.seek(0)
            out[name] = buf.read() or b""
        except Exception:
            continue
    return out


def _expand_rar(out: Expanded, budget: _Budget, filename: str, data: bytes, depth: int) -> None:
    try:
        import rarfile
    except Exception:
        out.errors.append(f"{filename}: {RAR_MISSING}")
        out.members.append((filename, data))
        return
    try:
        rf = rarfile.RarFile(io.BytesIO(data))
    except Exception as exc:
        out.errors.append(f"{filename}: not a readable RAR archive ({type(exc).__name__}: {exc}).")
        out.members.append((filename, data))
        return
    with rf:
        try:
            if rf.needs_password():
                out.errors.append(f"{filename} is password protected (encrypted RAR archive) and was NOT "
                                  "ingested. Extract it with the password and upload the contents.")
                out.members.append((filename, data))
                return
            infos = rf.infolist()
        except Exception as exc:
            out.errors.append(f"{filename}: RAR archive could not be read ({type(exc).__name__}: {exc}).")
            out.members.append((filename, data))
            return
        traversal: list[str] = []
        for info in infos:
            if budget.tripped:
                break
            if getattr(info, "isdir", lambda: False)():
                continue
            safe = safe_member_name(info.filename)
            if safe is None:
                traversal.append(info.filename)
                continue
            if getattr(info, "needs_password", False):
                out.errors.append(f"{_join(filename, safe)} is password protected and was NOT ingested.")
                continue
            try:
                blob = rf.read(info)
            except Exception as exc:
                text = f"{type(exc).__name__}: {exc}"
                if "password" in text.lower():
                    out.errors.append(f"{filename} is password protected (encrypted RAR archive) and was "
                                      "NOT ingested.")
                else:
                    out.errors.append(f"{_join(filename, safe)}: could not be extracted ({text}).")
                continue
            if not blob or PurePosixPath(safe).name.startswith("."):
                continue
            _emit(out, budget, _join(filename, safe), blob, depth)
    if traversal:
        out.errors.append(f"{filename}: {len(traversal)} member(s) escape the archive root and were refused "
                          f"- {', '.join(traversal[:3])}.")


def _expand_zstd(out: Expanded, budget: _Budget, filename: str, data: bytes, depth: int) -> None:
    try:
        import zstandard
    except Exception:
        out.errors.append(f"{filename}: {ZSTD_MISSING}")
        out.members.append((filename, data))
        return
    try:
        blob = zstandard.ZstdDecompressor().decompress(data, max_output_size=MAX_MEMBER_BYTES)
    except Exception as exc:
        out.errors.append(f"{filename}: zstd stream could not be decompressed "
                          f"({type(exc).__name__}: {exc}).")
        out.members.append((filename, data))
        return
    inner = _strip_compression_suffix(filename)
    name = inner if depth == 0 else _join(filename, PurePosixPath(inner).name)
    _emit(out, budget, name, blob, depth)
