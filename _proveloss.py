"""Did the old (newline-only) head actually LOSE evidence, or just cut oddly? Throwaway data dir."""
import os
import shutil
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="iris-headloss-")
os.environ["IRIS_DATA_DIR"] = TMP
os.environ["IRIS_PARSE_MIN_MB"] = "0.05"
os.environ["IRIS_PARSE_CHUNK_MB"] = "0.06"
sys.path.insert(0, "backend")

from app import config                        # noqa: E402
from app.parsers import parallel as par       # noqa: E402
from app.store import Store                   # noqa: E402

assert str(config.DATA_DIR) == TMP


def csv_multiline(rows: int) -> bytes:
    out = [b"timestamp,host,message\n"]
    for i in range(rows):
        out.append(('2026-03-01T00:00:%02d,h%d,"first part\nsecond part %d"\n'
                    % (i % 60, i % 3, i)).encode())
    return b"".join(out)


DATA = csv_multiline(4000)
HEAD_LINES, HEAD_MAX = par.HEAD_LINES, par.HEAD_MAX_BYTES
FIXED = par._head_slice


def old_head_slice(data, quoted=False):
    """The pre-fix implementation: newline counting only, quote parity ignored."""
    lines, pos = 0, 0
    limit = min(len(data), HEAD_MAX)
    while pos < limit and lines < HEAD_LINES:
        nl = data.find(b"\n", pos)
        if nl < 0:
            return None
        if data[pos:nl].strip():
            lines += 1
        pos = nl + 1
    return (pos, lines) if lines >= HEAD_LINES else None


def digest(nworkers: int, head_impl, tag: str):
    os.environ["IRIS_PARSE_WORKERS"] = str(nworkers)
    par._head_slice = head_impl
    st = Store()
    st.pending = False
    p = os.path.join(TMP, f"{tag}.csv")
    with open(p, "wb") as fh:
        fh.write(DATA)
    import pathlib
    with st.bulk_load():
        st.add_file("multiline.csv", DATA, background_ok=False, sid="cccc3333", path=pathlib.Path(p))
    print(f"   [{tag}] parser={st.sources['cccc3333'].parser!r} quoted={getattr(st.source_parsers['cccc3333'], 'quoted', None)}")
    return [(e.id, e.raw) for e in st.events]


serial = digest(1, FIXED, "serial")
old_par = digest(4, old_head_slice, "old")
new_par = digest(4, FIXED, "new")
par._head_slice = FIXED

print(f"records, single worker           : {len(serial):>6}")
print(f"records, 4 workers OLD head slice: {len(old_par):>6}   {'LOST ' + str(len(serial) - len(old_par)) if len(old_par) != len(serial) else 'same'}")
print(f"records, 4 workers NEW head slice: {len(new_par):>6}   {'differs!' if new_par != serial else 'identical to serial'}")
if len(old_par) != len(serial) or old_par != serial:
    bad = [i for i, (a, b) in enumerate(zip(serial, old_par)) if a != b]
    print(f"\nold path first divergence at record {bad[0] if bad else 'n/a'}")
    if bad:
        i = bad[0]
        print(f"   serial: {serial[i][1][:70]!r}")
        print(f"   old   : {old_par[i][1][:70]!r}")
shutil.rmtree(TMP, ignore_errors=True)
