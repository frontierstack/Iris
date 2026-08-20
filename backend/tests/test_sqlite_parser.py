"""SQLite parser: table enumeration, timestamp-column discovery, BLOB safety, error surfacing."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.parsers.registry import fingerprint
from app.parsers.sqlitedb import MAGIC, SqliteParser, ts_from_number

UTC = timezone.utc


def _build(path) -> bytes:
    conn = sqlite3.connect(str(path))
    conn.executescript(
        """
        CREATE TABLE auth_log (id INTEGER PRIMARY KEY, ts INTEGER, hostname TEXT, username TEXT, message TEXT);
        CREATE TABLE downloads (id INTEGER PRIMARY KEY, start_time INTEGER, url TEXT, payload BLOB);
        CREATE TABLE empty_table (a TEXT);
        """
    )
    conn.executemany(
        "INSERT INTO auth_log (ts, hostname, username, message) VALUES (?,?,?,?)",
        [
            (1786000000, "web-1", "alice", "Accepted password for alice from 45.83.140.22"),
            (1786000060, "web-2", "bob", "Failed password for bob from 45.83.140.22"),
        ],
    )
    conn.executemany(
        "INSERT INTO downloads (start_time, url, payload) VALUES (?,?,?)",
        [
            # WebKit/Chrome microseconds since 1601 — 2026-08-11T03:14:47Z
            (13396396487000000, "http://malware.example.com/payload.exe", b"\x00\x01\x02binary\xff"),
        ],
    )
    conn.commit()
    conn.close()
    return path.read_bytes()


def test_magic_detection_and_fingerprint(tmp_path):
    data = _build(tmp_path / "evidence.sqlite")
    assert data.startswith(MAGIC)
    fp = fingerprint("evidence.sqlite", data)
    assert isinstance(fp.parser, SqliteParser)
    assert fp.state == "READY" and fp.confidence >= 0.9
    # magic wins even when the file has a misleading extension
    assert isinstance(fingerprint("history", data).parser, SqliteParser)


def test_rows_become_events_with_table_context(tmp_path):
    data = _build(tmp_path / "evidence.sqlite")
    evs = list(SqliteParser().parse_bytes(data))
    tables = {e.fields["table"] for e in evs}
    assert {"auth_log", "downloads"} <= tables
    assert "empty_table" not in tables  # no rows, no events

    auth = [e for e in evs if e.fields["table"] == "auth_log"]
    assert len(auth) == 2
    assert auth[0].host == "web-1" and auth[0].user == "alice"
    assert "Accepted password" in auth[0].msg
    assert auth[0].ts == datetime(2026, 8, 6, 7, 6, 40, tzinfo=UTC)  # unix seconds decoded
    assert auth[0].fields["row"] == "1"


# --------------------------------------------------------------------- readability
# A normalised database defeats a naive row dump, and Brave/Chrome history is the case that proved it:
# `visits` rows read `url=14 transition=805306370` — every value the analyst wants is a foreign key or
# an enum. These tests pin the three fixes: follow references (declared or not), decode the enums that
# are actually documented, and synthesise a message from the columns that say something.
def _browser_history(path) -> bytes:
    """Chrome's history schema in miniature — and, like the real thing, it declares NO foreign keys."""
    conn = sqlite3.connect(str(path))
    conn.executescript(
        """
        CREATE TABLE urls (id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR,
                           visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER);
        CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER,
                             transition INTEGER, segment_id INTEGER, visit_duration INTEGER);
        CREATE TABLE keyword_search_terms (keyword_id INTEGER, url_id INTEGER, term LONGVARCHAR);
        CREATE TABLE downloads (id INTEGER PRIMARY KEY, guid VARCHAR, target_path LONGVARCHAR,
                                start_time INTEGER, received_bytes INTEGER, state INTEGER, opened INTEGER);
        """
    )
    conn.execute("INSERT INTO urls VALUES (14,'https://evil.example/pay','Payment portal',3,1,13426745475080779,0)")
    conn.execute("INSERT INTO urls VALUES (42,'https://intranet.corp/hr','HR - Corp',9,0,13426745478715612,0)")
    # transition 805306368 = link | chain_start | chain_end
    conn.execute("INSERT INTO visits VALUES (1,14,13426745475080779,0,805306368,0,3637357)")
    conn.execute("INSERT INTO visits VALUES (2,42,13426745478715612,1,805306369,0,1819017)")
    conn.execute("INSERT INTO keyword_search_terms VALUES (2,14,'how to disable edr')")
    conn.execute("INSERT INTO downloads VALUES (1,'b4cd-1','C:/Users/Tay/Desktop/tool.exe',13426973303620387,317973,1,0)")
    conn.commit()
    conn.close()
    return path.read_bytes()


def _by_table(evs):
    out = {}
    for e in evs:
        out.setdefault(e.fields["table"], []).append(e)
    return out


def test_foreign_keys_are_followed_even_when_the_schema_declares_none(tmp_path):
    evs = _by_table(list(SqliteParser().parse_bytes(_browser_history(tmp_path / "History"))))
    visit = evs["visits"][0]
    # `visits.url` is an INTEGER pointing at `urls.id`. Chrome declares no FK, so the link is found by
    # name; without it the analyst is told the page visited was "14".
    assert "https://evil.example/pay" in visit.msg
    assert visit.fields["url"] == "https://evil.example/pay (Payment portal)"
    assert visit.fields["url_id"] == "14"           # the raw key is kept, not thrown away
    assert "(#14)" in visit.raw                     # and the raw line shows both
    # a column whose name only ENDS with the table name resolves too (url_id -> urls)
    term = evs["keyword_search_terms"][0]
    assert "how to disable edr" in term.msg and "https://evil.example/pay" in term.fields["url_id"]


def test_a_reference_is_left_alone_when_it_cannot_be_resolved_honestly(tmp_path):
    """An unresolved id is honest; a guessed one is not. `from_visit` points at `visits`, which has no
    label column worth showing, so the number stays a number."""
    evs = _by_table(list(SqliteParser().parse_bytes(_browser_history(tmp_path / "History"))))
    second = evs["visits"][1]
    assert second.fields["from_visit"] == "1"
    assert "from_visit_id" not in second.fields


def test_chrome_page_transitions_are_decoded(tmp_path):
    evs = _by_table(list(SqliteParser().parse_bytes(_browser_history(tmp_path / "History"))))
    first, second = evs["visits"][0], evs["visits"][1]
    assert first.fields["transition"] == "link+chain_start+chain_end"
    assert first.fields["transition_raw"] == "805306368"
    assert second.fields["transition"].startswith("typed")     # low byte 1
    assert "transition=link+chain_start+chain_end" in first.msg


def test_the_message_is_synthesised_from_informative_columns(tmp_path):
    """A downloads row used to come out as the message "0" — the widest-text guess picked a flag column
    and nothing else was shown. Now the path and the byte count are in the line, and the zero flags are
    not."""
    evs = _by_table(list(SqliteParser().parse_bytes(_browser_history(tmp_path / "History"))))
    dl = evs["downloads"][0].msg
    assert dl.startswith("downloads:")
    assert "tool.exe" in dl and "received_bytes=317973" in dl
    assert "opened=0" not in dl                      # a zero flag is noise
    assert "guid" not in dl                          # so is a surrogate key
    url_row = evs["urls"][0].msg
    assert "Payment portal" in url_row and "https://evil.example/pay" in url_row
    assert "hidden=0" not in url_row


def test_resolution_does_not_explode_the_row_count_or_the_time(tmp_path):
    """The resolver must add lookups, not events: one row in, one event out, cached per referenced id."""
    data = _browser_history(tmp_path / "History")
    evs = list(SqliteParser().parse_bytes(data))
    assert len(evs) == 2 + 2 + 1 + 1                 # urls, visits, search term, download
    assert len({(e.fields["table"], e.fields["row"]) for e in evs}) == len(evs)


def test_webkit_timestamp_and_blob_rendering(tmp_path):
    data = _build(tmp_path / "evidence.sqlite")
    evs = [e for e in SqliteParser().parse_bytes(data) if e.fields["table"] == "downloads"]
    assert len(evs) == 1
    ev = evs[0]
    assert ev.ts == datetime(2025, 7, 7, 21, 14, 47, tzinfo=UTC)  # WebKit µs since 1601
    assert "<blob 10 bytes sha256:" in ev.fields["payload"]
    assert "\x00" not in ev.raw and "\xff" not in ev.raw  # no binary garbage leaks into the event


def test_numeric_timestamp_encodings():
    assert ts_from_number(1786000000).year == 2026            # unix seconds
    assert ts_from_number(1786000000_000).year == 2026        # milliseconds
    assert ts_from_number(1786000000_000000).year == 2026     # microseconds
    assert ts_from_number(1786000000_000000000).year == 2026  # nanoseconds
    assert ts_from_number(13396396487000000).year == 2025     # WebKit / Chrome µs since 1601
    assert ts_from_number(638600000000000000).year == 2024    # .NET ticks (100 ns since year 1)
    assert ts_from_number(2461263.6353).year == 2026          # Julian day
    assert ts_from_number(0) is None and ts_from_number(42) is None


def test_database_is_opened_read_only(tmp_path):
    """Parsing must not mutate the evidence, nor leave a -wal/-shm sibling next to it."""
    path = tmp_path / "evidence.sqlite"
    data = _build(path)
    before = path.read_bytes()
    mtime = path.stat().st_mtime_ns
    list(SqliteParser().parse_bytes(data))
    assert path.read_bytes() == before
    assert path.stat().st_mtime_ns == mtime
    assert sorted(p.name for p in tmp_path.iterdir()) == ["evidence.sqlite"]


def test_encrypted_or_corrupt_database_reports_clearly():
    fake = MAGIC + b"\x00" * 200 + b"garbage" * 50
    with pytest.raises(RuntimeError) as exc:
        list(SqliteParser().parse_bytes(fake))
    assert "encrypted" in str(exc.value).lower() or "corrupt" in str(exc.value).lower()

    with pytest.raises(RuntimeError) as exc2:
        list(SqliteParser().parse_bytes(b"SQLCipher-encrypted-nonsense" * 20))
    assert "not a SQLite database" in str(exc2.value)


def test_sqlite_siblings_are_claimed_by_NAME_and_refused(tmp_path):
    """Copying a browser profile brings -wal / -shm / -journal along.

    They were being ingested as evidence: an EMPTY -wal has no magic bytes, so it sniffed as "plain text"
    and sat in MAP waiting for a field mapping, and a -shm became a Binary-strings source of zero events.
    Neither is a database — each is a fragment of the one next to it — so the parser claims them by name
    and refuses with the sentence that says what to upload instead.
    """
    from app.parsers.registry import fingerprint

    for name, data in [("places.sqlite-wal", b""),           # empty: the NAME is the only evidence
                       ("places.sqlite-shm", bytes(64)),
                       ("history.db-journal", b"")]:
        fp = fingerprint(name, data)
        assert isinstance(fp.parser, SqliteParser), name
        with pytest.raises(RuntimeError) as exc:
            list(fp.parser.parse_bytes(data))
        msg = str(exc.value).lower()
        assert "sibling" in msg and ("upload the main" in msg)

    # and the -wal refusal states the forensic caveat: an immutable open never replays it
    fp = fingerprint("places.sqlite-wal", b"")
    with pytest.raises(RuntimeError) as exc:
        list(fp.parser.parse_bytes(b""))
    assert "checkpoint" in str(exc.value).lower()


def test_a_real_database_still_wins_over_the_name_rules(tmp_path):
    """The sibling rule keys off suffixes; a real .sqlite must be unaffected by it."""
    from app.parsers.registry import fingerprint
    data = _browser_history(tmp_path / "History")
    fp = fingerprint("History", data)
    assert isinstance(fp.parser, SqliteParser)
    assert len(list(fp.parser.parse_bytes(data))) > 0


def test_wal_sibling_explained_not_dumped():
    wal = b"\x37\x7f\x06\x82" + b"\x00" * 100
    with pytest.raises(RuntimeError) as exc:
        list(SqliteParser().parse_bytes(wal))
    assert "write-ahead log" in str(exc.value)
    assert isinstance(fingerprint("evidence.sqlite-wal", wal).parser, SqliteParser)


def test_large_table_is_capped(tmp_path, monkeypatch):
    from app.parsers import sqlitedb

    monkeypatch.setattr(sqlitedb, "MAX_ROWS_PER_TABLE", 10)
    path = tmp_path / "big.sqlite"
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE t (ts INTEGER, message TEXT)")
    conn.executemany("INSERT INTO t VALUES (?,?)", [(1786000000 + i, f"line {i}") for i in range(500)])
    conn.commit()
    conn.close()
    evs = list(SqliteParser().parse_bytes(path.read_bytes()))
    assert len(evs) == 10


@pytest.fixture()
def c():
    with TestClient(app) as client:
        yield client


def test_ingested_end_to_end(c, tmp_path):
    """Through the API: a SQLite upload becomes real, searchable events."""
    data = _build(tmp_path / "evidence.sqlite")
    r = c.post("/api/sources", files=[("files", ("evidence.sqlite", data, "application/octet-stream"))])
    assert r.status_code == 200, r.text
    sources = r.json()
    assert sources and sources[0]["parser"] == "SQLite database"
    assert sources[0]["state"] == "READY"
    assert sources[0]["events"] == 3
    # scope the search to THIS source: the store may already hold other cases' events
    rows = c.get("/api/events", params={"q": "alice", "sources": sources[0]["id"], "limit": 100}).json()["rows"]
    assert rows and any("Accepted password" in e["msg"] for e in rows)
    assert all(e["fields"]["table"] in ("auth_log", "downloads") for e in rows)
