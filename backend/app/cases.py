"""Multi-case registry: $IRIS_DATA_DIR/cases/<CASE-0001>/{case.json, uploads/} + cases/index.json = {"active": id}.

The in-memory STORE always holds exactly one case (the active one); the others live on disk and are summarised
from their case.json (event_count / per-source events are persisted by Store.save_meta so nothing needs re-parsing).
"""
from __future__ import annotations

import errno
import json
import logging
import os
import shutil
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from . import config
from .models import CaseDetail, CaseNote, CaseSnapshot, CaseSummary, NoteRef, SourceBrief
from .normalize import to_iso
from .store import STORE, _load_notes

log = logging.getLogger("iris.cases")

_lock = threading.RLock()
# ONE definition, in config, because config's path helpers now refuse anything that does not match it —
# two copies of "what a case id looks like" would mean a route validating one shape against a
# filesystem guard enforcing another.
_ID_RE = config.CASE_ID_RE
UTC = timezone.utc

# How long a delete keeps retrying the rename into the trash. See _to_trash: on Windows a directory
# cannot be renamed while ANY file inside it is open, and the handles that collide here are held for
# microseconds, so a short retry turns a failed delete into a normal one.
TRASH_MOVE_RETRY_SECONDS = 5.0


# ------------------------------------------------------------------ registry helpers
def _read_index() -> dict[str, Any]:
    try:
        data = json.loads(config.CASES_INDEX.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_index(active: str, seq: Optional[int] = None) -> None:
    """Persist the active case and the id high-water mark (`seq`), preserving whichever isn't given."""
    try:
        cur = _read_index()
        if seq is None:
            try:
                seq = int(cur.get("seq") or 0)
            except (TypeError, ValueError):
                seq = 0
        config.CASES_DIR.mkdir(parents=True, exist_ok=True)
        tmp = config.CASES_INDEX.with_suffix(".tmp")
        tmp.write_text(json.dumps({"active": active, "seq": seq}, indent=1), encoding="utf-8")
        tmp.replace(config.CASES_INDEX)
    except OSError:
        pass


def case_ids() -> list[str]:
    """Case ids present on disk (sorted)."""
    try:
        return sorted(p.name for p in config.CASES_DIR.iterdir() if p.is_dir() and _ID_RE.match(p.name))
    except OSError:
        return []


def next_id() -> str:
    """Allocate a NEVER-REUSED case id.

    Ids used to be the lowest free number, so deleting your only case immediately recreated
    "CASE-0001" — the Cases page looked completely unchanged and the delete read as broken, even
    though the case and its uploads really were gone. A high-water mark in index.json keeps ids
    monotonic so a delete is always visible.
    """
    used = {int(_ID_RE.match(i).group(1)) for i in case_ids()}  # type: ignore[union-attr]
    try:
        high = int(_read_index().get("seq") or 0)
    except (TypeError, ValueError):
        high = 0
    n = max([high, *used], default=0) + 1
    cid = f"CASE-{n:04d}"
    _write_index(str(_read_index().get("active") or cid), seq=n)
    return cid


def _read_meta(case_id: str) -> dict[str, Any]:
    try:
        data = json.loads(config.case_path(case_id).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_meta(case_id: str, meta: dict[str, Any]) -> None:
    path = config.case_path(case_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(meta, indent=1), encoding="utf-8")
    tmp.replace(path)


def _size_bytes(case_id: str) -> int:
    total = 0
    try:
        for f in config.upload_dir(case_id).iterdir():
            if f.is_file():
                try:
                    total += f.stat().st_size
                except OSError:
                    pass
    except OSError:
        pass
    return total


def _iso(value: Any, fallback: Optional[datetime] = None) -> str:
    if isinstance(value, str) and value:
        try:
            return to_iso(datetime.fromisoformat(value))
        except ValueError:
            return value
    return to_iso(fallback or datetime.now(UTC))


# ------------------------------------------------------------------ startup / migration
def migrate_legacy() -> Optional[str]:
    """Move a legacy single-case layout ($IRIS_DATA_DIR/case.json + uploads/) into cases/CASE-0001. Returns the id."""
    legacy_case, legacy_up = config.LEGACY_CASE_PATH, config.LEGACY_UPLOAD_DIR
    have_case = legacy_case.is_file()
    have_uploads = legacy_up.is_dir() and any(legacy_up.iterdir())
    if not have_case and not have_uploads:
        return None
    meta = {}
    if have_case:
        try:
            meta = json.loads(legacy_case.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            meta = {}
    cid = meta.get("case_id") if _ID_RE.match(str(meta.get("case_id", ""))) else None
    if not cid or cid in case_ids():
        cid = "CASE-0001" if "CASE-0001" not in case_ids() else next_id()
    target = config.case_dir(cid)
    target.mkdir(parents=True, exist_ok=True)
    new_up = config.upload_dir(cid)
    if have_uploads:
        if new_up.exists():
            for f in legacy_up.iterdir():
                try:
                    shutil.move(str(f), str(new_up / f.name))
                except OSError:
                    pass
            shutil.rmtree(legacy_up, ignore_errors=True)
        else:
            shutil.move(str(legacy_up), str(new_up))
    # rewrite upload paths inside the meta so restore() finds them at the new location
    meta["case_id"] = cid
    for src in meta.get("sources", []) or []:
        p = Path(str(src.get("path") or ""))
        if p.name:
            src["path"] = str(new_up / p.name)
    _write_meta(cid, meta)
    try:
        legacy_case.unlink(missing_ok=True)
    except OSError:
        pass
    return cid


def startup() -> str:
    """Migrate legacy files, pick the active case (index.json → most recent → new), and rebuild the
    workspace pool: the active case's sources AND every case-less file staged in the library.

    Analysis does not require a case, so this returns a usable workspace even when `case_ids()` is empty —
    the library pool is restored either way.
    """
    with _lock:
        config.CASES_DIR.mkdir(parents=True, exist_ok=True)
        migrated = migrate_legacy()
        ids = case_ids()
        active = str(_read_index().get("active") or "")
        if migrated and (active not in ids or not active):
            active = migrated
        if active not in ids:
            if not ids:  # fresh install / everything deleted — stay empty until something is created
                _go_pending(next_id())
                STORE.load_library()  # analysis needs no case: the pool loads either way
                return STORE.case_id
            active = ids[-1]
        config.case_dir(active).mkdir(parents=True, exist_ok=True)
        with STORE.lock:
            # restore() and restore_library() both APPEND, so the store must be empty first — otherwise
            # calling startup() a second time (re-init, or a data-dir switch) doubles every event. This is
            # the ONE place that clears the library pool as well (keep_library defaults to False).
            STORE._clear_memory(delete_files=False)
            STORE.case_id = active
            STORE.pending = False
        _write_index(active)
        STORE.restore(active)
        with STORE._detect_lock:
            STORE._run_detections()
        STORE.bump()
        # After the case, so a staged file the case was attached from is skipped rather than parsed twice.
        # A large library loads in a thread: this runs inside the FastAPI lifespan, so it must not block
        # the API from coming up (a 589 MB library kept /api/health unreachable for minutes).
        STORE.load_library()
        return active


def _go_pending(cid: str) -> None:
    """Point the store at a reserved-but-unwritten case id: no case in memory, absent from disk.

    keep_library: files staged with no case belong to no case, so deleting the last case must leave them
    (and their events) exactly where they are — that is the whole point of a case-less pool.
    """
    with STORE.lock:
        STORE._clear_memory(delete_files=False, keep_library=True)
        STORE.case_id = cid
        STORE.name = "Untitled case"
        STORE.analyst = config.get_settings().analyst
        STORE.created_at = datetime.now(UTC)
        STORE.pending = True
        STORE.version += 1
        STORE._analysis = None
    _write_index(cid)


# ------------------------------------------------------------------ summaries
def _case_set_count(meta: dict[str, Any]) -> int:
    """Case-set size from persisted metadata, tolerating the pre-case-set `pinned` list."""
    cs = meta.get("case_set")
    if isinstance(cs, list):
        return len(cs)
    return len(meta.get("pinned") or [])


def _n(v: object) -> int:
    """How many entries a case.json list holds — 0 for a key that is missing or the wrong shape."""
    return len(v) if isinstance(v, list) else 0


def summary(case_id: str) -> CaseSummary:
    active = case_id == STORE.case_id
    if active:
        with STORE.lock:
            # the CASE's own sources/events — the library pool belongs to no case and must not inflate it
            src_ok = STORE.case_source_ids()
            return CaseSummary(id=case_id, name=STORE.name, analyst=STORE.analyst, createdAt=to_iso(STORE.created_at),
                               updatedAt=to_iso(datetime.now(UTC)), sources=len(src_ok),
                               events=sum(STORE.sources[s].events for s in src_ok),
                               caseSet=len(STORE.case_set), noteCount=len(STORE.notes),
                               iocCount=len(STORE.manual_iocs), graphLinkCount=len(STORE.graph_links),
                               active=True, sizeBytes=_size_bytes(case_id))
    meta = _read_meta(case_id)
    sources = meta.get("sources") or []
    events = meta.get("event_count")
    if not isinstance(events, int):
        events = sum(int(s.get("events", 0) or 0) for s in sources if isinstance(s, dict))
    created = _iso(meta.get("created_at"))
    return CaseSummary(id=case_id, name=str(meta.get("name") or "Untitled case"), analyst=str(meta.get("analyst") or ""),
                       createdAt=created, updatedAt=_iso(meta.get("updated_at"), datetime.fromisoformat(created.replace("Z", "+00:00"))),
                       sources=len(sources), events=int(events), caseSet=_case_set_count(meta),
                       noteCount=_n(meta.get("notes")), iocCount=_n(meta.get("manual_iocs")),
                       graphLinkCount=_n(meta.get("graph_links")), active=False,
                       sizeBytes=_size_bytes(case_id))


def _detachable(sid: str) -> bool:
    """True when this case source came from the library and its staged copy is still there, i.e. it can
    be taken back out of the case without destroying anything (Store.detach_case_source)."""
    name = STORE.source_library.get(sid) or ""
    return bool(name) and (config.LIBRARY_DIR / name).is_file()


def detail(case_id: str) -> CaseDetail:
    """Case detail. For the ACTIVE case everything is live; for others it comes from the persisted snapshot."""
    # A pending id has nothing on disk and is absent from /api/cases, so it must 404 here too - the
    # active-case short circuit below would otherwise serve a full detail page for a case that does not
    # exist, which is what made a deleted case look like it was still around.
    if STORE.pending and case_id == STORE.case_id:
        raise KeyError(case_id)
    base = summary(case_id)
    if case_id == STORE.case_id:
        with STORE.lock:
            srcs = [STORE.sources[s] for s in STORE.case_source_ids()]
            notes = STORE.notes
        return CaseDetail(**base.model_dump(), notes=list(notes), snapshot=STORE.snapshot(),
                          sourceList=[SourceBrief(id=s.id, file=s.file, parser=s.parser, events=s.events,
                                                  size=s.size, state=s.state, fromLibrary=_detachable(s.id))
                                      for s in srcs])
    if case_id not in case_ids():
        raise KeyError(case_id)
    meta = _read_meta(case_id)
    snap = None
    raw_snap = meta.get("snapshot")
    if isinstance(raw_snap, dict):
        try:
            snap = CaseSnapshot.model_validate(raw_snap)
        except Exception:
            snap = None
    briefs = []
    for s in meta.get("sources") or []:
        if isinstance(s, dict):
            staged = str(s.get("library") or "")
            briefs.append(SourceBrief(id=str(s.get("id") or ""), file=str(s.get("file") or ""),
                                      parser=str(s.get("parser") or ""), events=int(s.get("events") or 0),
                                      size=int(s.get("size") or 0), state="READY",
                                      fromLibrary=bool(staged) and (config.LIBRARY_DIR / staged).is_file()))
    return CaseDetail(**base.model_dump(), notes=_load_notes(meta.get("notes")), snapshot=snap, sourceList=briefs)


def list_cases() -> list[CaseSummary]:
    """Cases that exist on disk. A PENDING case (id reserved, nothing written) is deliberately absent —
    after deleting the last case the list is empty rather than showing a blank case nobody created."""
    with _lock:
        ids = case_ids()
        if STORE.case_id not in ids and not STORE.pending:
            ids.append(STORE.case_id)
        return [summary(i) for i in sorted(ids)]


# ------------------------------------------------------------------ mutations
def create_case(name: str, analyst: Optional[str] = None) -> CaseSummary:
    """Create a new empty case AND activate it."""
    with _lock:
        cid = next_id()
        now = datetime.now(UTC)
        _write_meta(cid, {"case_id": cid, "name": name.strip() or "Untitled case",
                          "analyst": (analyst or "").strip() or config.get_settings().analyst,
                          "created_at": now.isoformat(), "updated_at": now.isoformat(), "case_set": [], "notes": [], "event_count": 0, "sources": []})
        config.upload_dir(cid).mkdir(parents=True, exist_ok=True)
        activate(cid)
        return summary(cid)


def activate(case_id: str) -> None:
    with _lock:
        if case_id not in case_ids():
            raise KeyError(case_id)
        STORE.activate(case_id)
        _write_index(case_id)


def patch_case(case_id: str, name: Optional[str], analyst: Optional[str]) -> CaseSummary:
    with _lock:
        if case_id == STORE.case_id:
            with STORE.lock:
                if name is not None and name.strip():
                    STORE.name = name.strip()
                if analyst is not None and analyst.strip():
                    STORE.analyst = analyst.strip()
                STORE._materialise()  # naming a pending case is enough to make it real
            STORE.save_meta()
            return summary(case_id)
        if case_id not in case_ids():
            raise KeyError(case_id)
        meta = _read_meta(case_id)
        if name is not None and name.strip():
            meta["name"] = name.strip()
        if analyst is not None and analyst.strip():
            meta["analyst"] = analyst.strip()
        meta["updated_at"] = datetime.now(UTC).isoformat()
        meta.setdefault("case_id", case_id)
        _write_meta(case_id, meta)
        return summary(case_id)


# ------------------------------------------------------------------ notes
def _notes_of(case_id: str) -> list[CaseNote]:
    if case_id == STORE.case_id:
        with STORE.lock:
            return list(STORE.notes)
    return _load_notes(_read_meta(case_id).get("notes"))


def _write_notes(case_id: str, notes: list[CaseNote]) -> None:
    """Persist notes for either the active case (in memory + case.json) or an on-disk one."""
    if case_id == STORE.case_id:
        with STORE.lock:
            STORE.notes = notes
        STORE.save_meta()
        return
    if case_id not in case_ids():
        raise KeyError(case_id)
    meta = _read_meta(case_id)
    meta["notes"] = [n.model_dump() for n in notes]
    meta["updated_at"] = datetime.now(UTC).isoformat()
    meta.setdefault("case_id", case_id)
    _write_meta(case_id, meta)


def list_notes(case_id: str) -> list[CaseNote]:
    # same reasoning as detail(): a pending id is not a case, so it must not answer for one
    if STORE.pending and case_id == STORE.case_id:
        raise KeyError(case_id)
    if case_id != STORE.case_id and case_id not in case_ids():
        raise KeyError(case_id)
    return _notes_of(case_id)


def add_note(case_id: str, text: str, refs: Optional[list[NoteRef]] = None, author: str = "") -> CaseNote:
    with _lock:
        notes = list_notes(case_id)
        used = {n.id for n in notes}
        n = 1
        while f"n{n}" in used:
            n += 1
        note = CaseNote(id=f"n{n}", text=text, author=author or config.get_settings().analyst,
                        createdAt=to_iso(datetime.now(UTC)), refs=list(refs or []))
        notes.append(note)
        _write_notes(case_id, notes)
        return note


def update_note(case_id: str, note_id: str, text: Optional[str], refs: Optional[list[NoteRef]]) -> CaseNote:
    with _lock:
        notes = list_notes(case_id)
        for i, n in enumerate(notes):
            if n.id == note_id:
                notes[i] = n.model_copy(update={
                    "text": n.text if text is None else text,
                    "refs": n.refs if refs is None else list(refs),
                    "updatedAt": to_iso(datetime.now(UTC)),
                })
                _write_notes(case_id, notes)
                return notes[i]
        raise KeyError(note_id)


def restore_note(case_id: str, note: CaseNote) -> CaseNote:
    """Put a deleted note back, id, author and timestamps intact.

    add_note() allocates the lowest free `n<k>`, which after a delete is usually — but not always — the
    id that was removed. Undo has to return the case file to exactly what it was, so the note is
    re-inserted verbatim; only a genuine id collision falls back to a fresh id."""
    with _lock:
        notes = list_notes(case_id)
        if any(n.id == note.id for n in notes):
            return add_note(case_id, note.text, note.refs, note.author)
        notes.append(note)
        notes.sort(key=lambda n: (n.createdAt, n.id))
        _write_notes(case_id, notes)
        return note


def delete_note(case_id: str, note_id: str) -> None:
    with _lock:
        notes = list_notes(case_id)
        kept = [n for n in notes if n.id != note_id]
        if len(kept) == len(notes):
            raise KeyError(note_id)
        _write_notes(case_id, kept)


def _trash_name(case_id: str) -> str:
    return f"{case_id}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"


def _release_library_copies(case_id: str, moved_to: Path) -> None:
    """A deleted case takes its ATTACHED files out of the workspace with it.

    Attaching a staged library file to a case copies the bytes into `cases/<id>/uploads/` and leaves
    the staged copy in `library/` (Store.attach_library_source — the in-memory `source_library` link
    is what stopped `restore_library` re-adding it). Deleting the case moved the uploads to the trash
    and cleared those sources from memory, and then the very next `load_library()` (activating the
    replacement case) — or the next restart — found the staged copy with no case claiming it and
    parsed it straight back into the pool as a library source. Reported as *"when deleting a case,
    associated Anomalies detections / graph detections etc do not clear"*: the detections were on
    events that had come back through the side door.

    So the staged copy is removed here, ONLY when the trash entry holds the bytes (the copy into the
    case's uploads can fall back to the staged path on an OSError, in which case the staged file is
    the only copy and stays). The trash entry is the file's home now: a restore re-parses the case's
    uploads, and a later detach re-stages it (`Store._stage_into_library`). Files that were never
    attached to this case are not touched — the library is case-less on purpose.
    """
    try:
        meta = _read_meta_from(moved_to / _latest_trash_entry_for(case_id)) if moved_to else {}
    except Exception:  # noqa: BLE001 — a delete must not fail on its own bookkeeping
        meta = {}
    names: list[str] = []
    for src in meta.get("sources") or []:
        name = str((src or {}).get("library") or "")
        if name and name not in names:
            names.append(name)
    if not names:
        return
    from .routers.library import _update_library_index, invalidate_library_cache
    entry_dir = moved_to / _latest_trash_entry_for(case_id)
    released: list[str] = []
    for name in names:
        kept = entry_dir / "uploads" / name
        staged = config.LIBRARY_DIR / name
        if not kept.is_file() or not staged.is_file():
            continue
        try:
            staged.unlink()
            released.append(name)
        except OSError as exc:
            log.warning("delete %s: could not release library copy of %s: %s", case_id, name, exc)
    if released:
        _update_library_index(lambda idx: any(idx.pop(n, None) is not None for n in list(released)))
        invalidate_library_cache()
        log.info("delete %s: released %d library cop%s that the case had attached: %s", case_id,
                 len(released), "y" if len(released) == 1 else "ies", ", ".join(released))


def _latest_trash_entry_for(case_id: str) -> str:
    entries = sorted(p.name for p in config.TRASH_DIR.iterdir()
                     if p.is_dir() and p.name.startswith(f"{case_id}-")) if config.TRASH_DIR.exists() else []
    return entries[-1] if entries else ""


def _read_meta_from(case_dir: Path) -> dict[str, Any]:
    p = case_dir / "case.json"
    if not p.is_file():
        return {}
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def _to_trash(case_id: str) -> bool:
    """Move cases/<id> into the trash. True when the case folder is really gone from cases/.

    This used to be one `shutil.move` with `except OSError: rmtree(case_dir)`, and both halves were
    wrong on Windows:

    * **A directory cannot be renamed while any file inside it is open**, and legitimate background
      work holds such a handle for a moment on exactly this folder — phase-2 enrichment reads a case
      upload (`Store.enrich_source`), and every `Store.bump()` writes `cases/<id>/case.tmp` through
      `save_meta()`, which the enrichment worker does once per source it finishes, library sources
      included. So a delete raced a handle it had no reason to care about.
    * `shutil.move` answers a failed rename with copytree + rmtree. The copy lands, the rmtree hits
      the same open file and raises — leaving the case BOTH copied into the trash and still in
      `cases/`, i.e. a delete the Cases page shows as a no-op. The old handler's `rmtree` then could
      not remove it either. Worse, when the copy is the half that fails, that `rmtree` is an
      unrecoverable loss of the only copy of the uploads — the exact thing the trash exists to stop.

    So: retry the ATOMIC rename (it either moves the whole case or changes nothing) for a moment,
    because those handles are released in milliseconds. Only if that is still impossible — a large
    file genuinely mid-parse, or a trash on another device — copy the evidence across FIRST and
    remove the original afterwards, in that order, always.
    """
    src = config.case_dir(case_id)
    dest = config.TRASH_DIR / _trash_name(case_id)
    try:
        config.TRASH_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        log.error("case %s: no trash directory (%s) — leaving the case on disk rather than destroying it",
                  case_id, exc)
        return False

    deadline = time.monotonic() + TRASH_MOVE_RETRY_SECONDS
    last: Optional[OSError] = None
    while True:
        try:
            os.replace(src, dest)
            return True
        except FileNotFoundError:
            return not src.exists()  # already gone; nothing to do
        except OSError as exc:
            last = exc
            # A cross-device trash can never be renamed into, however long we wait.
            if exc.errno == errno.EXDEV or getattr(exc, "winerror", None) == 17:
                break
            if time.monotonic() >= deadline:
                break
            time.sleep(0.02)

    try:
        shutil.copytree(src, dest, dirs_exist_ok=True)
    except OSError as exc:
        # shutil.Error carries the per-file failures of a PARTIAL copy. The original is intact, so
        # the half-copy is only noise — and a half-copy listed as a recoverable case is a lie about
        # what can be recovered.
        shutil.rmtree(dest, ignore_errors=True)
        log.error("case %s could not be moved to the trash (%s) nor copied into it (%s) — leaving it "
                  "in cases/ rather than destroying its uploads", case_id, last, exc)
        return False
    shutil.rmtree(src, ignore_errors=True)
    if src.exists():
        log.warning("case %s was copied to the trash but cases/%s is still on disk (%s) — it will keep "
                    "appearing as a case until whatever holds it lets go", case_id, case_id, last)
        return False
    return True


def _prune_trash() -> None:
    """Keep only the most recent config.TRASH_KEEP entries. Trashed cases hold whole uploads, so this
    is what stops the safety net from growing without bound."""
    try:
        entries = sorted((p for p in config.TRASH_DIR.iterdir() if p.is_dir()),
                         key=lambda p: p.name, reverse=True)
    except OSError:
        return
    for old in entries[config.TRASH_KEEP:]:
        shutil.rmtree(old, ignore_errors=True)


def list_trash() -> list[dict]:
    """Deleted cases still recoverable, newest first."""
    out: list[dict] = []
    try:
        entries = sorted((p for p in config.TRASH_DIR.iterdir() if p.is_dir()), key=lambda p: p.name, reverse=True)
    except OSError:
        return out
    for p in entries:
        cid, _, stamp = p.name.rpartition("-")
        meta: dict = {}
        try:
            meta = json.loads((p / "case.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        size = 0
        uploads = 0
        try:
            for f in (p / "uploads").iterdir():
                if f.is_file():
                    uploads += 1
                    size += f.stat().st_size
        except OSError:
            pass
        out.append({"entry": p.name, "caseId": cid or p.name, "name": str(meta.get("name") or "Untitled case"),
                    "deletedAt": stamp, "events": int(meta.get("event_count") or 0),
                    "sources": uploads, "sizeBytes": size,
                    # A curation-only case has no uploads and no events of its own, so without these a
                    # deleted investigation reads as "0 events · 0 files · 0 B" — an empty row for a case
                    # that holds the entire write-up. See CaseSummary.notes.
                    "caseSet": _case_set_count(meta), "noteCount": _n(meta.get("notes")),
                    "iocCount": _n(meta.get("manual_iocs")), "graphLinkCount": _n(meta.get("graph_links"))})
    return out


def restore_trash(entry: str) -> str:
    """Put a trashed case back. Returns the case id it was restored as.

    If the original id has since been reused, the case comes back under a fresh id rather than
    overwriting whatever now holds that id.
    """
    src = config.TRASH_DIR / Path(entry).name
    if src.resolve().parent != config.TRASH_DIR.resolve() or not src.is_dir():
        raise KeyError(entry)
    cid = src.name.rpartition("-")[0] or src.name
    with _lock:
        if cid in case_ids() or not _ID_RE.match(cid):
            cid = next_id()
        shutil.move(str(src), str(config.case_dir(cid)))
        meta = _read_meta(cid)
        meta["case_id"] = cid
        # paths inside case.json may point at the old folder; Store.restore resolves by basename
        _write_meta(cid, meta)
    return cid


def _wait_for_store_lock_and_clear(timeout: float = 20.0) -> bool:
    """Drop the active case from memory so its uploads can be renamed. Bounded, never forever.

    Only reached when the trash move failed, which on Windows means something still holds a file in
    `cases/<id>/uploads/`. Waiting for the store lock is acceptable HERE because the alternative is a
    delete that cannot happen at all — but it is bounded, because a delete that hangs is the bug this
    whole path exists to fix.
    """
    if not STORE.lock.acquire(timeout=timeout):
        log.warning("delete: the store was busy for %.0fs, clearing the case without the lock", timeout)
        STORE._clear_memory(delete_files=False, keep_library=True)
        return False
    try:
        STORE._clear_memory(delete_files=False, keep_library=True)
    finally:
        STORE.lock.release()
    return True


# How long a delete will wait for the replacement case to load before handing back and letting it
# finish in the background. Long enough for an ordinary case, far too short to hold up a delete.
ACTIVATE_AFTER_DELETE_WAIT = 3.0


def _activate_quietly(case_id: str) -> None:
    """Load a case in the background after a delete handed the active slot to it.

    Failure here must not resurrect the deleted case or leave the store pointing at nothing: the
    index already names this case, so the worst outcome is an empty active case that the next
    activate/restore fills in.
    """
    try:
        with STORE.lock:
            still_ours = STORE.case_id == case_id and not STORE.pending
        if not still_ours:
            # Something newer already claimed the active slot — a create, an activate, another
            # delete. Restoring now would clear the pool under whatever is using it and put back a
            # case nobody asked for. Abandon: the current owner has already loaded what it needs.
            return
        STORE.activate(case_id, save_current=False, force=True)
    except Exception:  # noqa: BLE001
        log.exception("case %s could not be activated after a delete", case_id)


def delete_case(case_id: str) -> None:
    """Move a case to the trash. If it was active: activate the most recently updated remaining case,
    or hold a pending id when nothing is left.

    The folder is MOVED, not removed: it holds the only copy of its uploads, so a delete used to be an
    unrecoverable loss of evidence. config.TRASH_KEEP entries are retained; see restore_trash.
    """
    with _lock:
        if case_id not in case_ids():
            raise KeyError(case_id)
        was_active = case_id == STORE.case_id
        # The TRASH MOVE first, and the in-memory clear only if that move needs it.
        #
        # It used to clear memory first, which meant taking `STORE.lock` on the request path — and
        # that lock is held, briefly but constantly, by whatever background work is running. Measured
        # on an 11.1 M-event workspace mid-load: **101 s to delete a case with no sources at all**,
        # every second of it spent queueing for a lock the delete did not need. The clear exists for a
        # Windows reason (a directory cannot be renamed while a file inside it is open, and the parse
        # holds such a handle), so it is still done — but only when the rename actually fails, which
        # for a case whose uploads nothing is reading is never.
        moved = _to_trash(case_id)
        if not moved and was_active:
            _wait_for_store_lock_and_clear()
            moved = _to_trash(case_id)
        if moved:
            _prune_trash()
            _release_library_copies(case_id, moved_to=config.TRASH_DIR)
        if not was_active:
            return
        remaining = case_ids()
        if remaining:
            def _updated(cid: str) -> str:
                return _iso(_read_meta(cid).get("updated_at"), datetime.fromtimestamp(0, UTC))
            target = max(remaining, key=lambda c: (_updated(c), c))
            # The index moves NOW, so the delete is done as far as every screen is concerned. The
            # RESTORE of the replacement case re-parses its uploads, which on a real case is seconds
            # to minutes — and making the analyst wait for an unrelated case to load before their
            # delete returns is how "I cannot delete this case" starts. Same rule as deleting a
            # source: it is a click, not a job.
            _write_index(target)
            # Two field assignments; if the store is busy they are not worth queueing for, because the
            # background activation sets them under the lock when it gets there and the INDEX on disk
            # already names the target (which is what survives a restart).
            quick = STORE.lock.acquire(timeout=0.5)
            if quick:
                try:
                    STORE.case_id = target
                    STORE.pending = False
                finally:
                    STORE.lock.release()
            else:
                log.info("delete: store busy, the active case moves to %s in the background", target)
            t = threading.Thread(target=_activate_quietly, args=(target,), name="iris-case-activate",
                                 daemon=True)
            t.start()
            # A short join, not a fire-and-forget: a small case comes back in milliseconds and callers
            # (and tests) reasonably expect it to be THERE when the delete returns. A big one blows
            # through this and finishes behind the response — which is the case that made a delete
            # look impossible.
            # Wait for it only if the store was free a moment ago: on an idle workspace a small case
            # is back in milliseconds and callers reasonably expect it. If the store is busy, the
            # activation is queued behind the same lock, so waiting for it is waiting for nothing.
            if quick:
                t.join(timeout=ACTIVATE_AFTER_DELETE_WAIT)
        else:
            # Nothing left: do NOT invent a replacement case. Reserve an id and hold it pending, so the
            # Cases page is genuinely empty until the analyst creates one or ingests something.
            _go_pending(next_id())
