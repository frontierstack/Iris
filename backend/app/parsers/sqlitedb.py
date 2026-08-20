"""SQLite database parser.

Evidence databases (browser history, chat apps, EDR/agent caches, application logs) are read STRICTLY
read-only: the bytes are written to a temp file and opened through a `file:...?mode=ro&immutable=1` URI,
so sqlite never creates a -wal/-shm sibling, never rolls a journal back and never mutates the evidence.

Every user table is enumerated, timestamp-ish and message/host/user columns are discovered by name AND by
value shape, and each row becomes one event with the table name in `fields["table"]`.

READABILITY IS THE WHOLE POINT, and a normalised database defeats a naive row dump. Brave/Chrome history
is the case that proved it: `visits` rows came out as `id=1 url=14 visit_time=13426745475080779
transition=805306370 …` — every interesting value is a FOREIGN KEY into another table, so the analyst got
integers where they needed URLs. Three things fix that, all generic:

* `Resolver` follows references, declared or not. Chrome declares NO foreign keys, so a column is matched
  to a table by name as well (`visits.url` -> `urls`, `visited_links.link_url_id` -> `urls`,
  `segment_usage.segment_id` -> `segments`), and the referenced row is rendered by its own label column
  (url / title / name / path / …). Lookups are single indexed reads behind a bounded cache.
* the message is SYNTHESISED from the informative columns — resolved references and real text — instead
  of concatenating every column, which is how a download row came out as the message "0".
* a few well-documented enums are decoded (Chrome page transitions), because `transition=805306370` is
  not evidence anyone can read.

Module is named `sqlitedb` on purpose: a top-level `sqlite.py` is harmless today but a package module named
after a stdlib-adjacent name is a trap waiting to happen.
"""
from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Iterator, Optional

from ..normalize import parse_ts
from .base import BaseParser, ParsedEvent, clean
from .tabular import HOST_NAMES, MSG_NAMES, TS_NAMES, USER_NAMES, _norm

UTC = timezone.utc

MAGIC = b"SQLite format 3\x00"
# Standalone journal / WAL siblings: useful to recognise so the analyst gets a real explanation instead of
# a screenful of extracted strings.
WAL_MAGIC = b"\x37\x7f\x06\x82"
WAL_MAGIC_ALT = b"\x37\x7f\x06\x83"
JOURNAL_MAGIC = b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7"

EXTENSIONS = (".sqlite", ".sqlite3", ".db", ".db3", ".sqlitedb", ".s3db")
# Siblings of a live database. Copying a browser profile takes these along, and they were being ingested
# as "plain text" (an empty -wal became a MAP source waiting for a field mapping) or as binary strings.
# They are not evidence on their own — they are a fragment of the database next to them — so they are
# claimed here and REFUSED with the sentence that says what to do instead.
SIBLING_SUFFIXES = ("-wal", "-shm", "-journal")

MAX_ROWS_PER_TABLE = 50_000
MAX_TOTAL_ROWS = 250_000
FETCH_SIZE = 500
MAX_VALUE_LEN = 512
MAX_BLOB_PREVIEW = 96
SAMPLE_ROWS = 60           # rows sampled per table when guessing column roles
MAX_REF_CACHE = 200_000    # resolved foreign keys held in memory (a bounded dict, not a leak)
MAX_LABEL_LEN = 200
MSG_PARTS = 8              # informative columns folded into one event message

# Columns worth showing as the label of a REFERENCED row, best first. `url` beats `title` because an
# analyst pivots on the URL; the title comes along as a parenthetical.
LABEL_NAMES = ("url", "name", "title", "path", "target_path", "value", "term", "email", "address",
               "username", "user", "handle", "filename", "file", "message", "text", "query", "host")
# Purely numeric values are noise (ids, flags, scores) UNLESS the column name says the number is the
# point. Without this every row drags along `hidden=0 typed_count=0 annotation_flags=0`.
NUMERIC_KEEP = ("count", "bytes", "size", "len", "duration", "port", "status", "code", "state", "level",
                "pid", "score", "total", "errno", "attempts", "version")
# Columns that are never worth reading: surrogate keys and internal bookkeeping.
NOISE_COLS = ("rowid", "guid", "uuid", "cache_guid", "etag", "hash", "checksum", "sync_id")

# Chrome/Brave/Edge page transitions. The low byte is the core type; the high bits are qualifiers.
# Documented in components/history — `transition=805306370` means "link, chain start, chain end".
CHROME_TRANSITION_CORE = {
    0: "link", 1: "typed", 2: "auto_bookmark", 3: "auto_subframe", 4: "manual_subframe", 5: "generated",
    6: "start_page", 7: "form_submit", 8: "reload", 9: "keyword", 10: "keyword_generated",
}
CHROME_TRANSITION_QUALIFIERS = (
    (0x00800000, "forward_back"), (0x01000000, "from_address_bar"), (0x02000000, "home_page"),
    (0x04000000, "from_api"), (0x10000000, "chain_start"), (0x20000000, "chain_end"),
    (0x40000000, "client_redirect"), (0x80000000, "server_redirect"),
)


def decode_chrome_transition(v: Any) -> str:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return ""
    if n < 0:
        return ""
    core = CHROME_TRANSITION_CORE.get(n & 0xFF)
    if core is None:
        return ""
    quals = [name for bit, name in CHROME_TRANSITION_QUALIFIERS if n & bit]
    return core + ("+" + "+".join(quals) if quals else "")


# (table, column) -> decoder. Deliberately keyed on BOTH: a bare column name called `state` means
# something different in every schema, and guessing wrong would put a confident wrong word in evidence.
ENUM_DECODERS: dict[tuple[str, str], Any] = {
    ("visits", "transition"): decode_chrome_transition,
    ("moz_historyvisits", "visit_type"): lambda v: {1: "link", 2: "typed", 3: "bookmark", 4: "embed",
                                                    5: "redirect_permanent", 6: "redirect_temporary",
                                                    7: "download", 8: "framed_link",
                                                    9: "reload"}.get(int(v), "") if str(v).lstrip("-").isdigit() else "",
}

_MIN_YEAR = datetime(1990, 1, 1, tzinfo=UTC)
_MAX_YEAR = datetime(2100, 1, 1, tzinfo=UTC)
_EPOCH_1601 = datetime(1601, 1, 1, tzinfo=UTC)
_EPOCH_0001 = datetime(1, 1, 1, tzinfo=UTC)

# The WAL caveat is a real evidence problem, not a nag: Iris opens the database `immutable=1`, which
# tells sqlite to ignore any -wal. Rows committed to the WAL but not yet checkpointed into the main file
# are therefore NOT read - on a live browser profile that is the most recent activity, which is usually
# the part being investigated.
WAL_HINT = ("this is a SQLite write-ahead log (-wal) sibling, not a database. Upload the main "
            ".db/.sqlite file - Iris reads it read-only. Note that a -wal is never replayed: anything "
            "committed to it but not yet checkpointed into the main file will be missing, so take a "
            "checkpointed copy of the database if the newest records matter.")

ENCRYPTED_HINT = (
    "this file is not a readable SQLite database - it is encrypted (SQLCipher / WxSQLite) or the header is "
    "corrupt. Iris cannot decrypt it; supply a decrypted export."
)


# --------------------------------------------------------------------------- timestamp heuristics
def ts_from_number(v: float) -> Optional[datetime]:
    """Decode the numeric timestamp encodings that actually turn up in evidence databases."""
    try:
        n = float(v)
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return None
    try:
        if 2_400_000.0 <= n <= 2_600_000.0:                     # Julian day (sqlite's own julianday())
            return datetime.fromtimestamp((n - 2_440_587.5) * 86400.0, UTC)
        if 1e8 <= n < 4e9:                                      # unix seconds
            return datetime.fromtimestamp(n, UTC)
        if 1e11 <= n < 4e12:                                    # unix milliseconds
            return datetime.fromtimestamp(n / 1e3, UTC)
        if 1e14 <= n < 5e15:                                    # unix microseconds
            return datetime.fromtimestamp(n / 1e6, UTC)
        if 1.0e16 <= n < 2.0e16:                                # WebKit/Chrome: microseconds since 1601
            return _EPOCH_1601 + timedelta(microseconds=n)
        if 6.2e17 <= n < 6.7e17:                                # .NET ticks: 100 ns since year 1
            return _EPOCH_0001 + timedelta(microseconds=n / 10.0)
        if 1e17 <= n < 4e18:                                    # unix nanoseconds
            return datetime.fromtimestamp(n / 1e9, UTC)
    except (OverflowError, OSError, ValueError):
        return None
    return None


def ts_from_value(v: Any) -> Optional[datetime]:
    """Best-effort timestamp for one cell (number in any common epoch, or an ISO-ish string)."""
    if v is None or isinstance(v, (bytes, bytearray, memoryview)):
        return None
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        dt = ts_from_number(v)
    else:
        text = str(v).strip()
        if not text:
            return None
        if re.fullmatch(r"[-+]?\d+(\.\d+)?", text):
            dt = ts_from_number(float(text))
        else:
            dt = parse_ts(text)
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    dt = dt.astimezone(UTC)
    return dt if _MIN_YEAR <= dt <= _MAX_YEAR else None


# --------------------------------------------------------------------------- value rendering
def render(v: Any) -> str:
    """A safe, printable rendering of a cell. BLOBs never leak binary into the event text."""
    if v is None:
        return ""
    if isinstance(v, (bytes, bytearray, memoryview)):
        b = bytes(v)
        digest = hashlib.sha256(b).hexdigest()[:16]
        try:
            text = b.decode("utf-8")
        except UnicodeDecodeError:
            text = ""
        if text and text.isprintable():
            return f"{text[:MAX_BLOB_PREVIEW]} <blob {len(b)} bytes sha256:{digest}>"
        return f"<blob {len(b)} bytes sha256:{digest}>"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    if isinstance(v, datetime):
        return v.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if v.tzinfo else v.strftime("%Y-%m-%dT%H:%M:%SZ")
    s = clean(v)
    return s[:MAX_VALUE_LEN]


def _name_rank(col: str, names: tuple[str, ...]) -> int:
    """0 = exact name match, 1 = contains one of the names, 2 = no match."""
    n = _norm(col)
    if n in names:
        return 0
    if any(cand in n for cand in names if len(cand) > 3):
        return 1
    return 2


def _pick_by_name(columns: list[str], names: tuple[str, ...]) -> Optional[int]:
    best: Optional[int] = None
    best_rank = 2
    for i, c in enumerate(columns):
        r = _name_rank(c, names)
        if r < best_rank:
            best, best_rank = i, r
    return best


class Resolver:
    """Turns a foreign key into the thing it points at.

    Declared `FOREIGN KEY`s are used when they exist, but the databases analysts actually hand over
    mostly do not declare any — Chrome's history schema declares none at all — so a column is also
    matched to a table BY NAME (`url` / `url_id` / `link_url_id` -> `urls`). A plan is worked out once
    per (table, column) and every resolved value is cached, so following a key is one indexed read.

    It refuses to guess when it would be misleading: the reference must be an integer, the target table
    must exist, and it must have a column worth showing. Otherwise the raw number is left alone — an
    unresolved id is honest, a wrong one is not.
    """

    def __init__(self, conn: sqlite3.Connection, tables: list[str], decode: Any) -> None:
        self.conn = conn
        self.decode = decode
        self.by_lower = {t.lower(): t for t in tables}
        self.plans: dict[tuple[str, str], Optional[tuple[str, str, str, str]]] = {}
        self.cache: dict[tuple[str, int], str] = {}
        self._cols: dict[str, list[tuple[str, str, int]]] = {}

    # ---------------------------------------------------------------- schema
    def columns(self, table: str) -> list[tuple[str, str, int]]:
        """[(name, declared type, is primary key)] — cached; one PRAGMA per table."""
        if table not in self._cols:
            quoted = '"' + table.replace('"', '""') + '"'
            try:
                info = self.conn.execute(f"PRAGMA table_info({quoted})").fetchall()
            except sqlite3.DatabaseError:
                info = []
            out = []
            for r in info:
                name = self.decode(r[1])
                ctype = self.decode(r[2])
                out.append((name if isinstance(name, str) else str(name),
                            (ctype if isinstance(ctype, str) else str(ctype or "")).upper(), int(r[5] or 0)))
            self._cols[table] = out
        return self._cols[table]

    def _declared(self, table: str) -> dict[str, tuple[str, str]]:
        quoted = '"' + table.replace('"', '""') + '"'
        try:
            rows = self.conn.execute(f"PRAGMA foreign_key_list({quoted})").fetchall()
        except sqlite3.DatabaseError:
            return {}
        out: dict[str, tuple[str, str]] = {}
        for r in rows:
            ref_t, frm, to = self.decode(r[2]), self.decode(r[3]), self.decode(r[4])
            if isinstance(ref_t, str) and isinstance(frm, str):
                out[frm.lower()] = (ref_t, to if isinstance(to, str) and to else "")
        return out

    @staticmethod
    def _candidates(col: str) -> list[str]:
        """Table names a column called `col` might be pointing at, most likely first."""
        base = col.lower().strip()
        for suffix in ("_id", "id"):
            if base.endswith(suffix) and len(base) > len(suffix):
                base = base[: -len(suffix)].rstrip("_")
                break
        if not base:
            return []
        names = [base, base + "s", base + "es"]
        if "_" in base:                       # link_url_id -> url -> urls
            tail = base.rsplit("_", 1)[-1]
            names += [tail, tail + "s", tail + "es"]
        return names

    def _label_col(self, table: str, key_col: str) -> tuple[str, str]:
        """(primary label column, optional secondary) for a referenced table."""
        cols = self.columns(table)
        lower = {c[0].lower(): c[0] for c in cols}
        primary = ""
        for want in LABEL_NAMES:
            if want in lower and lower[want].lower() != key_col.lower():
                primary = lower[want]
                break
        if not primary:
            for name, ctype, pk in cols:
                if pk or name.lower() == key_col.lower() or name.lower() in NOISE_COLS:
                    continue
                if any(t in ctype for t in ("CHAR", "TEXT", "CLOB")):
                    primary = name
                    break
        if not primary:
            return "", ""
        secondary = ""
        if primary.lower() != "title" and "title" in lower:
            secondary = lower["title"]
        elif primary.lower() != "name" and "name" in lower:
            secondary = lower["name"]
        return primary, secondary

    def plan(self, table: str, column: str, declared: dict[str, tuple[str, str]]) -> Optional[tuple[str, str, str, str]]:
        """(ref table, key column, label column, secondary label) or None when it must not be guessed."""
        key = (table.lower(), column.lower())
        if key in self.plans:
            return self.plans[key]
        ref_table = ""
        ref_key = ""
        dec = declared.get(column.lower())
        if dec:
            ref_table = self.by_lower.get(dec[0].lower(), "")
            ref_key = dec[1]
        if not ref_table:
            for cand in self._candidates(column):
                hit = self.by_lower.get(cand)
                if hit and hit.lower() != table.lower():
                    ref_table = hit
                    break
        result: Optional[tuple[str, str, str, str]] = None
        if ref_table:
            if not ref_key:
                pk = [c[0] for c in self.columns(ref_table) if c[2]]
                ref_key = pk[0] if len(pk) == 1 else "rowid"
            label, second = self._label_col(ref_table, ref_key)
            if label:
                result = (ref_table, ref_key, label, second)
        self.plans[key] = result
        return result

    # ---------------------------------------------------------------- lookup
    def lookup(self, plan: tuple[str, str, str, str], value: Any) -> str:
        try:
            n = int(value)
        except (TypeError, ValueError):
            return ""
        if n <= 0:                      # 0 / -1 are Chrome's "no reference", not row 0
            return ""
        ref_table, ref_key, label, second = plan
        ck = (ref_table + "|" + label, n)
        hit = self.cache.get(ck)
        if hit is not None:
            return hit
        qt = '"' + ref_table.replace('"', '""') + '"'
        ql = '"' + label.replace('"', '""') + '"'
        qk = "rowid" if ref_key == "rowid" else '"' + ref_key.replace('"', '""') + '"'
        cols = ql + (', "' + second.replace('"', '""') + '"' if second else "")
        try:
            row = self.conn.execute(f"SELECT {cols} FROM {qt} WHERE {qk} = ? LIMIT 1", (n,)).fetchone()
        except sqlite3.DatabaseError:
            self.plans[(ref_table.lower(), label.lower())] = None
            return ""
        text = ""
        if row:
            main = render(self.decode(row[0]))[:MAX_LABEL_LEN]
            extra = render(self.decode(row[1]))[:80] if second and len(row) > 1 else ""
            if main and extra and extra != main:
                text = f"{main} ({extra})"
            else:
                text = main
        if len(self.cache) < MAX_REF_CACHE:
            self.cache[ck] = text
        return text


class TableRoles:
    """Which column of a table is the timestamp / message / host / user, from names AND sampled values."""

    def __init__(self, columns: list[str], sample: list[tuple[Any, ...]]) -> None:
        self.columns = columns
        self.ts = self._pick_ts(columns, sample)
        self.msg = _pick_by_name(columns, MSG_NAMES)
        self.host = _pick_by_name(columns, HOST_NAMES)
        self.user = _pick_by_name(columns, USER_NAMES)
        if self.msg is None:
            self.msg = self._widest_text(columns, sample)

    @staticmethod
    def _pick_ts(columns: list[str], sample: list[tuple[Any, ...]]) -> Optional[int]:
        candidates: list[tuple[int, int, int]] = []  # (name_rank, -hits, index)
        for i, col in enumerate(columns):
            vals = [row[i] for row in sample if i < len(row) and row[i] not in (None, "")]
            if not vals:
                continue
            hits = sum(1 for v in vals[:SAMPLE_ROWS] if ts_from_value(v) is not None)
            if hits and hits >= 0.6 * len(vals[:SAMPLE_ROWS]):
                candidates.append((_name_rank(col, TS_NAMES), -hits, i))
        if not candidates:
            return None
        candidates.sort()
        return candidates[0][2]

    @staticmethod
    def _widest_text(columns: list[str], sample: list[tuple[Any, ...]]) -> Optional[int]:
        best: Optional[int] = None
        best_len = 12  # below this it is an id/flag, not a message
        for i in range(len(columns)):
            vals = [row[i] for row in sample if i < len(row) and isinstance(row[i], str)]
            if not vals:
                continue
            avg = sum(len(v) for v in vals) / len(vals)
            if avg > best_len:
                best, best_len = i, avg
        return best


def _informative(col: str, text: str, resolved: bool) -> bool:
    """Is this cell worth putting in the one-line message?

    A row dump reads as noise because most columns are surrogate keys and zero flags. A resolved
    reference always earns its place; plain text earns it by having letters; a bare number only earns
    it when the column name says the number is the point (bytes, count, duration, status...).
    """
    if not text:
        return False
    low = col.lower()
    if resolved:
        return True
    if low in NOISE_COLS or low.endswith("_guid"):
        return False
    if text in ("0", "-1", "0.0"):
        return False
    if any(ch.isalpha() for ch in text):
        return len(text) > 1 or low not in ("id",)
    return any(k in low for k in NUMERIC_KEEP)


def summarise(table: str, columns: list[str], rendered: list[str], resolved: dict[int, str],
              msg_idx: Optional[int], ts_idx: Optional[int]) -> str:
    """One readable line for a row: the message column first if there is one, then whatever else says
    something. `downloads` used to come out as the single character "0" — the widest-text guess picked a
    flag column and nothing else was shown."""
    parts: list[str] = []
    lead = ""
    if msg_idx is not None and msg_idx < len(rendered):
        text = resolved.get(msg_idx) or rendered[msg_idx]
        if _informative(columns[msg_idx], text, msg_idx in resolved):
            lead = text
    for i, col in enumerate(columns):
        if i >= len(rendered) or i == msg_idx or i == ts_idx:
            continue
        text = resolved.get(i) or rendered[i]
        if not _informative(col, text, i in resolved):
            continue
        parts.append(f"{col}={text}")
        if len(parts) >= MSG_PARTS:
            break
    body = " ".join(x for x in ([lead] + parts) if x)
    return f"{table}: {body}".strip() if body else f"{table}: (empty row)"


class SqliteParser(BaseParser):
    name = "SQLite database"
    family = "db.sqlite"
    binary = True
    extensions = EXTENSIONS

    def __init__(self, filename: str = "") -> None:
        # A zero-byte -wal has no magic bytes at all, so the only thing that identifies it is its NAME.
        # registry.binary_hint passes it in; parse_bytes falls back to this when called without one.
        self.filename = filename

    def sniff(self, sample: list[str], filename: str = "", head: bytes = b"") -> float:
        if head.startswith(MAGIC):
            return 1.0
        lower = filename.lower()
        if lower.endswith(SIBLING_SUFFIXES) or head.startswith((WAL_MAGIC, WAL_MAGIC_ALT, JOURNAL_MAGIC)):
            return 1.0        # claim it so the refusal below is what the analyst reads
        if lower.endswith(EXTENSIONS):
            return 0.75
        return 0.0

    def parse(self, lines: Iterable[str]) -> Iterator[ParsedEvent]:
        return iter(())

    def parse_bytes(self, data: bytes, filename: str = "") -> Iterator[ParsedEvent]:
        low = (filename or getattr(self, "filename", "") or "").lower()
        if data.startswith((WAL_MAGIC, WAL_MAGIC_ALT)) or low.endswith("-wal"):
            raise RuntimeError(WAL_HINT)
        if data.startswith(JOURNAL_MAGIC) or low.endswith("-journal"):
            raise RuntimeError("this is a SQLite rollback journal (-journal) sibling, not a database. "
                               "Upload the main .db/.sqlite file instead - it is read on its own.")
        if low.endswith("-shm"):
            raise RuntimeError("this is a SQLite shared-memory index (-shm) sibling, not a database. It "
                               "holds no records at all. Upload the main .db/.sqlite file instead.")
        if not data.startswith(MAGIC):
            raise RuntimeError(f"not a SQLite database: {ENCRYPTED_HINT}")
        fd, tmp = tempfile.mkstemp(prefix="iris-sqlite-", suffix=".db")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            yield from self._read(tmp)
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    # ---------------------------------------------------------------- reading
    def _read(self, path: str) -> Iterator[ParsedEvent]:
        uri = "file:" + path.replace("?", "%3f").replace("#", "%23") + "?mode=ro&immutable=1"
        try:
            conn = sqlite3.connect(uri, uri=True, timeout=5.0)
        except sqlite3.Error as exc:
            raise RuntimeError(f"could not open the SQLite database read-only: {exc}")
        conn.text_factory = bytes  # decode ourselves: evidence rows are frequently not valid UTF-8
        try:
            tables = self._tables(conn)
            if not tables:
                raise RuntimeError("the SQLite database contains no user tables")
            resolver = Resolver(conn, tables, self._decode)
            emitted = 0
            for table in tables:
                if emitted >= MAX_TOTAL_ROWS:
                    break
                for ev in self._table_rows(conn, table, MAX_TOTAL_ROWS - emitted, resolver):
                    emitted += 1
                    yield ev
        finally:
            conn.close()

    @staticmethod
    def _decode(v: Any) -> Any:
        """text_factory=bytes gives us raw bytes for TEXT columns; recover str where it really is text."""
        if isinstance(v, bytes):
            try:
                return v.decode("utf-8")
            except UnicodeDecodeError:
                return v
        return v

    def _tables(self, conn: sqlite3.Connection) -> list[str]:
        try:
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        except sqlite3.DatabaseError as exc:
            if "not a database" in str(exc).lower():
                raise RuntimeError(ENCRYPTED_HINT)
            raise RuntimeError(f"the SQLite database could not be read (corrupt?): {exc}")
        out: list[str] = []
        for (raw,) in rows:
            name = self._decode(raw)
            if isinstance(name, str) and name:
                out.append(name)
        return sorted(out)

    def _table_rows(self, conn: sqlite3.Connection, table: str, budget: int,
                    resolver: Optional["Resolver"] = None) -> Iterator[ParsedEvent]:
        quoted = '"' + table.replace('"', '""') + '"'
        try:
            info = conn.execute(f"PRAGMA table_info({quoted})").fetchall()
        except sqlite3.DatabaseError:
            return
        columns = [self._decode(r[1]) for r in info]
        columns = [c if isinstance(c, str) else str(c) for c in columns]
        if not columns:
            return
        limit = min(budget, MAX_ROWS_PER_TABLE)
        if limit <= 0:
            return
        try:
            cur = conn.execute(f"SELECT * FROM {quoted} LIMIT {int(limit)}")
        except sqlite3.DatabaseError:
            return  # one unreadable table must not abort the rest of the database
        cur.arraysize = FETCH_SIZE
        try:
            sample = [tuple(self._decode(v) for v in row) for row in cur.fetchmany(SAMPLE_ROWS)]
        except sqlite3.DatabaseError:
            return
        roles = TableRoles(columns, sample)
        row_no = 0
        # Which columns point at another table, worked out once for the table rather than per row.
        declared = resolver._declared(table) if resolver is not None else {}
        ref_plans: dict[int, tuple[str, str, str, str]] = {}
        if resolver is not None:
            for i, col in enumerate(columns):
                if i == roles.ts:
                    continue
                plan = resolver.plan(table, col, declared)
                if plan is not None:
                    ref_plans[i] = plan
        enums = {i: ENUM_DECODERS[(table.lower(), col.lower())] for i, col in enumerate(columns)
                 if (table.lower(), col.lower()) in ENUM_DECODERS}

        def emit(row: tuple[Any, ...], n: int) -> Optional[ParsedEvent]:
            fields: dict[str, str] = {"table": table, "row": str(n)}
            rendered: list[str] = []
            resolved: dict[int, str] = {}
            for i, col in enumerate(columns):
                if i >= len(row):
                    break
                text = render(row[i])
                rendered.append(text)
                if text:
                    fields.setdefault(col, text)
                # A foreign key is only useful once it is followed: `url=14` is not evidence.
                if i in ref_plans and resolver is not None and text:
                    label = resolver.lookup(ref_plans[i], row[i])
                    if label:
                        resolved[i] = label
                        fields[col] = label
                        fields.setdefault(f"{col}_id", text)
                elif i in enums and text:
                    decoded = enums[i](row[i])
                    if decoded:
                        resolved[i] = decoded
                        fields[col] = decoded
                        fields.setdefault(f"{col}_raw", text)
            ts = ts_from_value(row[roles.ts]) if roles.ts is not None and roles.ts < len(row) else None
            if ts is None:  # the named column lost its shape on this row - try any other cell
                for i, v in enumerate(row):
                    if i == roles.ts:
                        continue
                    ts = ts_from_value(v)
                    if ts is not None:
                        break
            msg = summarise(table, columns, rendered, resolved, roles.msg, roles.ts)
            raw = f"[{table}] " + " | ".join(
                f"{c}=" + (f"{resolved[i]} (#{rendered[i]})" if i in resolved and resolved[i] != rendered[i]
                           else rendered[i])
                for i, c in enumerate(columns) if i < len(rendered))
            if not any(rendered):
                return None
            return ParsedEvent(
                raw=raw[:4000], msg=(msg or raw)[:300], ts=ts,
                ts_text=rendered[roles.ts] if roles.ts is not None and roles.ts < len(rendered) else "",
                host=(resolved.get(roles.host) or rendered[roles.host])
                if roles.host is not None and roles.host < len(rendered) else "",
                user=(resolved.get(roles.user) or rendered[roles.user])
                if roles.user is not None and roles.user < len(rendered) else "",
                fields=fields,
            )

        for row in sample:
            row_no += 1
            ev = emit(row, row_no)
            if ev is not None:
                yield ev
        while True:
            try:
                chunk = cur.fetchmany(FETCH_SIZE)
            except sqlite3.DatabaseError:
                return
            if not chunk:
                return
            for raw_row in chunk:
                row_no += 1
                ev = emit(tuple(self._decode(v) for v in raw_row), row_no)
                if ev is not None:
                    yield ev
