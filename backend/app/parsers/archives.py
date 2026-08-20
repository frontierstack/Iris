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
OFFICE_EXTENSIONS = (".xlsx", ".xlsm", ".docx", ".docm", ".pptx", ".pptm", ".odt", ".ods", ".odp", ".epub", ".jar",
                     ".apk", ".vsix", ".nupkg", ".whl")

_TEXT_EXTENSIONS = (".log", ".txt", ".csv", ".tsv", ".json", ".jsonl", ".xml", ".evtx.xml")


def is_ooxml(data: bytes) -> bool:
    """True for Office Open XML containers (xlsx/docx/pptx): a zip whose directory lists [Content_Types].xml."""
    if not data.startswith(ZIP_MAGIC):
        return False
    if OOXML_MARKER in data[:4096]:
        return True
    return OOXML_MARKER in data[-65536:]  # central directory sits at the end


@dataclass
class Expanded:
    """Members to ingest plus every problem worth showing the analyst."""

    members: list[tuple[str, bytes]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


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
    if lower.endswith(OFFICE_EXTENSIONS) or is_ooxml(data):
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

    # Office documents / other OOXML packages are zips, but they are DOCUMENTS - hand them to their parser.
    if lower.endswith(OFFICE_EXTENSIONS) or is_ooxml(data):
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


def _expand_zip(out: Expanded, budget: _Budget, filename: str, data: bytes, depth: int) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        out.errors.append(f"{filename}: not a readable zip archive ({exc}).")
        out.members.append((filename, data))
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


def _expand_tar(out: Expanded, budget: _Budget, filename: str, data: bytes, depth: int) -> bool:
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
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
