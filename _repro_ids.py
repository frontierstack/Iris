"""Does phase 2 re-point event ids at other lines? Throwaway data dir, never the live one."""
import os
import shutil
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="iris-repro-ids-")
os.environ["IRIS_DATA_DIR"] = TMP
os.environ["IRIS_AUTO_ENRICH"] = "0"        # drive phase 2 by hand so the two phases are observable
sys.path.insert(0, "backend")

from app import config                       # noqa: E402
from app.store import STORE                  # noqa: E402

assert str(config.DATA_DIR) == TMP

# A syslog-shaped log whose RECORD order is not its chronological order — the ordinary case for any
# merged or multi-host log, and for any stack trace (a continuation line has no timestamp at all).
LOG = (b"2026-05-01T10:00:03Z host1 sshd[1]: THIRD line, latest time\n"
       b"2026-05-01T10:00:01Z host1 sshd[2]: FIRST line, earliest time\n"
       b"2026-05-01T10:00:02Z host1 sshd[3]: SECOND line, middle time\n")

srcs = STORE.add_file("out-of-order.log", LOG, origin="library")
sid = srcs[0].id
print(f"source {sid}  enrich={srcs[0].enrich}")

print("\nPHASE 1 - what each id points at (pool order):")
before = {}
for e in STORE.events:
    if e.sourceId == sid:
        before[e.id] = e.raw.strip()
        print(f"   {e.id:<16} ts={e.ts:<22} {e.raw.strip()[:46]}")

STORE.enrich_source(sid)

print("\nPHASE 2 - what each id points at NOW:")
moved = []
for e in STORE.events:
    if e.sourceId == sid:
        was = before.get(e.id)
        flag = ""
        if was is not None and was != e.raw.strip():
            flag = "   <-- SAME ID, DIFFERENT LINE"
            moved.append((e.id, was, e.raw.strip()))
        print(f"   {e.id:<16} ts={e.ts:<22} {e.raw.strip()[:46]}{flag}")

print()
if moved:
    print(f"REPRODUCED: {len(moved)} id(s) now point at a different log line.")
    for i, was, now in moved:
        print(f"   {i}: was {was[:44]!r}")
        print(f"   {' ' * len(i)}  now {now[:44]!r}")
else:
    print("not reproduced: every id still points at the line it did after phase 1")

shutil.rmtree(TMP, ignore_errors=True)
