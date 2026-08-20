"""The multi-process graph extraction must produce EXACTLY the serial graph.

Not "the same totals" — the same structure, node by node and relation by relation, including the
things that are invisible in a summary but decide what the analyst sees:

* dict INSERTION ORDER of `nodes` and `edges`, because the node ranking's final tie-break is the
  node's position in that dict and `node_detail`'s neighbour list is sorted on a non-total key;
* `srcs` / `files` key order, because `Counter.most_common(4)` breaks ties by iteration order and
  those tallies are rendered as the node's "Sources" fact;
* the per-node event-index buffers — the first-200 `events` array AND the most-recent-200 ring
  including its write cursor, which is what `recent()` (node detail's timeline) unwraps;
* the first-20 `eventIds` per edge, `first`/`last`, the severity roll-up and the `why` tally.

Plus the operational contract: a pool that will not start falls back to the serial build instead of
failing, `IRIS_GRAPH_WORKERS=1` turns the path off, and a build kicked off the way the app really does
it — from the `derived.AsyncCache` daemon thread — completes rather than deadlocking.
"""
from __future__ import annotations

import random
import threading
import time

import pytest

from app import graph, graph_parallel
from app.derived import AsyncCache
from app.models import Detection, Event

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

# Small chunks so a few thousand events still exercise many chunks, many workers and a full 200-entry
# head + a wrapped 200-entry ring on the busy nodes.
CHUNK = 250


# --------------------------------------------------------------------------- corpus
_IPS = [f"{a}.{b}.{c}.{d}" for a, b, c, d in
        [(203, 0, 113, 7), (198, 51, 100, 22), (10, 4, 2, 9), (172, 16, 5, 40), (8, 8, 4, 4), (91, 213, 50, 3)]]
_USERS = ["root", "svc_deploy", "alice", "DOMAIN\\bob", "carol", "admin"]
_HOSTS = ["edge-lb-01", "bastion-1", "WIN-FS01", "db-03"]
_FILES = ["/var/log/auth.log", "C:\\Windows\\Temp\\p.exe", "/etc/shadow", "/home/alice/keys.txt"]
_PROCS = ["sshd", "cmd.exe", "powershell.exe", "python3", "curl"]
_DOMS = ["login.example.com", "cdn.evil.xyz", "api.corp.net"]
_SEV = ["info", "low", "medium", "high", "critical"]
_DETS = [Detection(name="Brute force", id="SIGMA-AUTH-0111", level="high"),
         Detection(name="Odd exec", id="SIGMA-WIN-0140", level="medium")]


def make_corpus(n: int, seed: int = 11) -> list[Event]:
    """A randomised mixed corpus: nginx, sshd, cloudtrail, windows, firewall, k8s shapes."""
    r = random.Random(seed)
    out: list[Event] = []
    for i in range(n):
        ip, user, host = r.choice(_IPS), r.choice(_USERS), r.choice(_HOSTS)
        pid = str(r.randrange(1, 40000))
        ts = f"2026-08-11T{r.randrange(24):02d}:{r.randrange(60):02d}:{r.randrange(60):02d}Z"
        kind = r.randrange(6)
        if kind == 0:
            dom, st = r.choice(_DOMS), r.choice(["200", "401", "403", "500"])
            raw = f'{ip} - {user} "GET https://{dom}/login HTTP/1.1" {st} {r.randrange(100, 9999)} "sqlmap/1.7"'
            fields = {"src_ip": ip, "remote_user": user, "status": st, "url": f"https://{dom}/login"}
            src, fil = "nginx", "edge_access.log"
        elif kind == 1:
            raw = (f"Aug 11 00:00:00 {host} sshd[{pid}]: "
                   f"{r.choice(['Failed password for', 'Accepted publickey for', 'Invalid user'])} "
                   f"{user} from {ip} port {r.randrange(1024, 65000)} ssh2")
            fields = {"host": host, "process": "sshd", "pid": pid, "src_ip": ip, "user": user}
            src, fil = "syslog", "bastion_syslog"
        elif kind == 2:
            raw = (f'{{"eventName":"{r.choice(["ConsoleLogin", "AssumeRole", "DeleteObject"])}",'
                   f'"userIdentity":{{"arn":"arn:aws:iam::447119089082:user/{user}"}},'
                   f'"sourceIPAddress":"{ip}","errorCode":"AccessDenied"}}')
            fields = {"eventName": "ConsoleLogin", "userIdentity.arn": f"arn:aws:iam::447119089082:user/{user}",
                      "sourceIPAddress": ip, "accessKeyId": f"AKIA{r.randrange(10**11):011d}X"}
            src, fil = "cloudtrail", "cloudtrail.json"
        elif kind == 3:
            proc, f = r.choice(_PROCS), r.choice(_FILES)
            raw = (f"<Event><EventID>4688</EventID><Computer>{host}</Computer><TargetUserName>{user}"
                   f"</TargetUserName><NewProcessName>C:\\Windows\\System32\\{proc}</NewProcessName>"
                   f"<NewProcessId>{pid}</NewProcessId><ObjectName>{f}</ObjectName></Event>")
            fields = {"EventID": "4688", "Computer": host, "TargetUserName": user, "ObjectName": f,
                      "NewProcessName": f"C:\\Windows\\System32\\{proc}", "NewProcessId": pid,
                      "ParentProcessName": "explorer.exe"}
            src, fil = "evtx", "WIN-FS01_Security.evtx.xml"
        elif kind == 4:
            dst, port = r.choice(_IPS), str(r.choice([22, 443, 3389, 4444]))
            raw = f"fw action={r.choice(['allow', 'deny', 'drop'])} src={ip} dst={dst} dport={port} proto=tcp"
            fields = {"action": "deny", "src": ip, "dst": dst, "dport": port}
            src, fil = "firewall", "fw.pipe.log"
        else:
            raw = (f'{{"verb":"delete","user":{{"username":"{user}"}},"objectRef":{{"name":"pod-{r.randrange(99):02d}"}},'
                   f'"sourceIPs":["{ip}"],"responseStatus":{{"code":403}}}}')
            fields = {"verb": "delete", "user.username": user, "objectRef.name": f"pod-{r.randrange(99):02d}",
                      "sourceIPs": ip, "svc": "kube-apiserver", "status": "403"}
            src, fil = "k8s_audit", "k8s_audit.jsonl"
        out.append(Event(id=f"e{i + 1}", ts=ts, source=src, sourceId="s1", file=fil, host=host, user=user,
                         msg=raw[:200], sev=r.choice(_SEV), raw=raw, fields=fields, entities=[],
                         detections=[r.choice(_DETS)] if r.random() < 0.12 else []))
    return out


# --------------------------------------------------------------------------- comparison
def assert_same_graph(a: graph.GraphBuilder, b: graph.GraphBuilder) -> None:
    assert list(a.nodes) == list(b.nodes), "node ids or their insertion order differ"
    for i in a.nodes:
        x, y = a.nodes[i], b.nodes[i]
        for attr in ("type", "value", "label", "count", "first", "last", "sev", "detections", "ti"):
            assert getattr(x, attr) == getattr(y, attr), f"node {i}.{attr}"
        assert list(x.events) == list(y.events), f"node {i}.events"
        assert list(x.tail) == list(y.tail), f"node {i}.tail"
        assert x.recent() == y.recent(), f"node {i}.recent()"
        assert list(x.srcs.items()) == list(y.srcs.items()), f"node {i}.srcs"
        assert list(x.files.items()) == list(y.files.items()), f"node {i}.files"
    assert list(a.edges) == list(b.edges), "edge keys or their insertion order differ"
    for k in a.edges:
        x, y = a.edges[k], b.edges[k]
        for attr in ("source", "target", "relation", "count", "first", "last", "sev", "events"):
            assert getattr(x, attr) == getattr(y, attr), f"edge {k}.{attr}"
        assert list(x.outcomes.items()) == list(y.outcomes.items()), f"edge {k}.outcomes"
        assert list(x.why.items()) == list(y.why.items()), f"edge {k}.why"
    assert a.ranked_ids() == b.ranked_ids()
    assert a._deg == b._deg
    for scope in ({}, {"limit": 2000}, {"limit": 40, "min_count": 3}):
        na, ea, sa = a.select(**scope)
        nb, eb, sb = b.select(**scope)
        assert [n.model_dump() for n in na] == [n.model_dump() for n in nb]
        assert [e.model_dump() for e in ea] == [e.model_dump() for e in eb]
        assert sa == sb
    for i in a.ranked_ids()[:12]:
        assert a.node_detail(i) == b.node_detail(i)


@pytest.fixture()
def small_chunks(monkeypatch):
    monkeypatch.setenv("IRIS_GRAPH_CHUNK", str(CHUNK))
    monkeypatch.setenv("IRIS_GRAPH_PARALLEL_MIN", "0")
    graph_parallel._reported.clear()


# --------------------------------------------------------------------------- tests
@pytest.mark.parametrize("n", [1200, 4000])
def test_parallel_graph_is_byte_identical(small_chunks, n):
    """The whole point. A randomised corpus, many chunks, compared node by node and edge by edge."""
    evs = make_corpus(n, seed=n)
    serial = graph.GraphBuilder(evs, parallel=False)
    par = graph.GraphBuilder(evs, parallel=True)
    assert par._used_parallel is True, "the parallel path did not actually run"
    assert_same_graph(serial, par)


def test_event_index_buffers_wrap_identically(small_chunks):
    """A node seen far more than 400 times exercises the ring: head, wrapped tail and write cursor."""
    evs = make_corpus(6000, seed=3)
    serial = graph.GraphBuilder(evs, parallel=False)
    par = graph.GraphBuilder(evs, parallel=True)
    busy = [i for i, n in serial.nodes.items() if n.count > 400]
    assert busy, "corpus did not produce a node past the ring boundary"
    for i in busy:
        assert serial.nodes[i].ti == par.nodes[i].ti
        assert list(serial.nodes[i].tail) == list(par.nodes[i].tail)
    assert_same_graph(serial, par)


def test_workers_one_disables_the_path(monkeypatch):
    monkeypatch.setenv("IRIS_GRAPH_WORKERS", "1")
    assert graph_parallel.workers() == 1
    assert graph_parallel.should_parallelise(10_000_000) is False
    gb = graph.GraphBuilder(make_corpus(300), parallel=None)
    assert gb._used_parallel is False
    assert gb.nodes


def test_pool_failure_falls_back_to_serial(small_chunks, monkeypatch, capsys):
    """A sandbox that forbids subprocesses must still produce a correct graph, and say why once."""
    def boom(*a, **k):
        raise OSError("subprocesses are not permitted here")

    monkeypatch.setattr(graph_parallel, "ProcessPoolExecutor", boom)
    evs = make_corpus(1200, seed=5)
    par = graph.GraphBuilder(evs, parallel=True)
    assert par._used_parallel is False
    assert_same_graph(graph.GraphBuilder(evs, parallel=False), par)
    assert "parallel extraction unavailable" in capsys.readouterr().err


def test_worker_death_falls_back_to_serial(small_chunks, monkeypatch):
    """A worker killed by the OOM killer surfaces as BrokenProcessPool on the result. That is a
    fallback to the in-process build, never a broken or partial graph."""
    from concurrent.futures.process import BrokenProcessPool

    class DeadFuture:
        def cancel(self): return False
        def result(self, timeout=None): raise BrokenProcessPool("a worker process died abruptly")

    class DeadPool:
        def __init__(self, *a, **k): pass
        def submit(self, *a, **k): return DeadFuture()
        def shutdown(self, *a, **k): pass

    monkeypatch.setattr(graph_parallel, "ProcessPoolExecutor", DeadPool)
    evs = make_corpus(1200, seed=6)
    par = graph.GraphBuilder(evs, parallel=True)
    assert par._used_parallel is False
    assert_same_graph(graph.GraphBuilder(evs, parallel=False), par)


def test_chunk_timeout_falls_back_to_serial(small_chunks, monkeypatch):
    """A wedged worker must not hang the build thread forever."""
    from concurrent.futures import TimeoutError as FTimeout

    class StuckFuture:
        def cancel(self): return True
        def result(self, timeout=None): raise FTimeout()

    class StuckPool:
        def __init__(self, *a, **k): pass
        def submit(self, *a, **k): return StuckFuture()
        def shutdown(self, *a, **k): pass

    monkeypatch.setattr(graph_parallel, "ProcessPoolExecutor", StuckPool)
    evs = make_corpus(1200, seed=7)
    par = graph.GraphBuilder(evs, parallel=True)
    assert par._used_parallel is False
    assert_same_graph(graph.GraphBuilder(evs, parallel=False), par)


def test_cancellation_stops_the_build(small_chunks):
    """A store bump mid-build must tear the workers down, not leave them burning CPU."""
    evs = make_corpus(4000, seed=8)
    calls = {"n": 0}

    def cancelled() -> bool:
        calls["n"] += 1
        return calls["n"] > 2

    with pytest.raises(graph_parallel.GraphBuildCancelled):
        graph.GraphBuilder(evs, parallel=True, cancelled=cancelled)


def test_build_from_a_background_thread_completes(small_chunks):
    """The REAL code path: `derived.AsyncCache` builds on a daemon thread, and that thread is what
    starts the workers. `spawn` is what makes that safe — a `fork` here could inherit a lock held by
    another thread and hang forever, which is why this test exists at all."""
    evs = make_corpus(2500, seed=9)
    cache = AsyncCache("test-graph", sync_limit=0)
    holder = threading.Lock()
    stop = threading.Event()

    gb = None

    def churn() -> None:
        # a second thread contending on a lock and allocating throughout the build — the shape that
        # makes fork() deadlock and spawn() not care
        while not stop.is_set():
            with holder:
                _ = [object() for _ in range(200)]

    noise = threading.Thread(target=churn, daemon=True)
    noise.start()
    try:
        assert cache.ready("all", "k1", len(evs), lambda: graph.GraphBuilder(evs, parallel=True)) is None
        assert cache.status("all", "k1")["state"] == "building"
        for _ in range(600):
            gb = cache.peek("all", "k1")
            if gb is not None:
                break
            time.sleep(0.1)
        assert gb is not None, "background build never finished (deadlock?)"
    finally:
        stop.set()
        noise.join(timeout=5)
    assert gb._used_parallel is True
    assert_same_graph(graph.GraphBuilder(evs, parallel=False), gb)
    assert cache.status("all", "k1")["state"] == "ready"
    assert cache._inflight == {}


def test_a_failed_run_leaves_the_callers_dicts_untouched(small_chunks, monkeypatch):
    """`build()` must not half-write `nodes`/`edges`: whatever went wrong, the serial path that runs
    next has to start from a clean slate or the graph would double-count."""
    class Done:
        def __init__(self, v): self.v = v
        def cancel(self): return False
        def result(self, timeout=None): return self.v

    class Boom:
        def cancel(self): return False
        def result(self, timeout=None): raise MemoryError("worker ran out of memory")

    class HalfPool:
        """First chunk succeeds, the next one dies — the case where a naive merge would leave the
        caller holding half a graph and the serial rebuild would then double every count."""
        def __init__(self, *a, **k): pass
        def submit(self, fn, rows, base): return Done(fn(rows, base)) if base == 0 else Boom()
        def shutdown(self, *a, **k): pass

    monkeypatch.setattr(graph_parallel, "ProcessPoolExecutor", HalfPool)
    nodes: dict = {}
    edges: dict = {}
    assert graph_parallel.build(make_corpus(1200, seed=4), nodes, edges) is False
    assert nodes == {} and edges == {}


def test_the_row_shim_covers_every_event_attribute_extraction_reads():
    """The workers do not get `Event`s — they get `graph_parallel._Row`, rebuilt from the packed
    columns. If someone teaches `extract()` or `aggregate()` to read one more Event attribute and does
    not add it to the pack, the workers silently see `AttributeError` (a fallback, so the graph stays
    correct but the speedup quietly disappears) or, worse, a stale value. Grep for it, the same way
    test_rule_params.py greps run_rules for its param readers."""
    import inspect
    import re as _re

    src = inspect.getsource(graph.extract) + inspect.getsource(graph.aggregate)
    read = {m for m in _re.findall(r"\be\.([A-Za-z_]+)", src)}
    missing = read - set(graph_parallel._Row.__slots__)
    assert not missing, f"extract()/aggregate() read Event attributes the worker row does not carry: {missing}"
    packed = _re.findall(r"\be\.([A-Za-z_]+)", inspect.getsource(graph_parallel.pack))
    assert read <= set(packed), f"attributes read but not packed: {read - set(packed)}"


def test_a_cancelled_background_build_does_not_wedge_the_cache():
    """A build that is cancelled must release `AsyncCache._inflight` and drop the status, or the slot
    is stuck reporting `building` forever and the Graph screen polls a build that will never publish —
    the shape of the total graph outage this cache has already caused once."""
    evs = make_corpus(800, seed=12)
    cache = AsyncCache("test-cancel", sync_limit=0)

    def build():
        return graph.GraphBuilder(evs, parallel=False, cancelled=lambda: True)

    assert cache.ready("all", "k1", len(evs), build) is None
    for _ in range(200):
        if "all" not in cache._inflight:
            break
        time.sleep(0.05)
    assert cache._inflight == {}, "the single-flight guard survived a cancelled build"
    assert cache.status("all", "k1")["state"] == "idle"
    # and the very next request starts a fresh build rather than being locked out
    assert cache.ready("all", "k2", len(evs), lambda: graph.GraphBuilder(evs, parallel=False)) is None
    for _ in range(200):
        if cache.peek("all", "k2") is not None:
            break
        time.sleep(0.05)
    assert cache.peek("all", "k2") is not None


def test_the_serial_build_is_cancellable_too(small_chunks, monkeypatch):
    """`IRIS_GRAPH_WORKERS=1` (and every fallback) still has to stop when its key goes stale — a 290 s
    in-process extraction for a result nothing can read is the same waste as six workers doing it."""
    monkeypatch.setenv("IRIS_GRAPH_WORKERS", "1")
    with pytest.raises(graph.BuildCancelled):
        graph.GraphBuilder(make_corpus(40_000, seed=13), parallel=None, cancelled=lambda: True)
