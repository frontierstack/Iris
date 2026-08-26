"""Correlation: clusters, per-event correlations, entity graph, baselines.

Vectorized parts (time bucketing / burst ratios, entity co-occurrence matrix) use the active
array backend from app.compute.xp() (cupy when CUDA is active, numpy otherwise).
"""
from __future__ import annotations

import heapq
import os
import re
from array import array
from collections import Counter, defaultdict
from typing import Any, Callable, Iterable, Iterator, Optional

import numpy as np

from .compute import asnumpy, gpu_fits, to_device, xp
from .derived import AsyncCache, DEFAULT_SYNC_LIMIT
from .models import Cluster, Correlation, Edge, Entity, EntityLink, Event, SEV_ORDER, max_sev
from .normalize import entity_kind, is_public_ip

# kill-chain phases used to split the seed events into explainable clusters
PHASES: list[tuple[str, str, str, tuple[str, ...]]] = [
    ("recon", "Credential stuffing burst", "FREQUENCY",
     ("SIGMA-WEB-0042", "SIGMA-LNX-0045", "SIGMA-WIN-0140", "SIGMA-NET-0027", "SIGMA-WEB-0050", "SIGMA-WEB-0058",
      "SIGMA-APP-0061", "SIGMA-WEB-0063", "SIGMA-K8S-0025")),
    ("access", "Successful auth, then persistence", "ENTITY LINK",
     ("SIGMA-AUTH-0111", "SIGMA-AUTH-0203", "SIGMA-AWS-0007", "SIGMA-AWS-0031", "SIGMA-AWS-0052", "SIGMA-AWS-0060",
      "SIGMA-AWS-0071", "SIGMA-WIN-0120", "SIGMA-LNX-0050", "SIGMA-WIN-0150")),
    ("lateral", "Lateral movement", "ENTITY LINK",
     ("SIGMA-NET-0019", "SIGMA-WIN-0088", "SIGMA-WIN-0091", "SIGMA-LNX-0012", "SIGMA-K8S-0004", "SIGMA-WIN-0133",
      "SIGMA-LNX-0041", "SIGMA-K8S-0011", "SIGMA-K8S-0017")),
    ("egress", "Collection and egress", "ANOMALY",
     ("SIGMA-APP-0055", "SIGMA-NET-0022", "SIGMA-LNX-0030", "SIGMA-AWS-0044", "SIGMA-WIN-0104")),
]
_PHASE_OF: dict[str, int] = {rid: i for i, (_, _, _, ids) in enumerate(PHASES) for rid in ids}
_GENERIC_SHARE = 0.5  # entities present in >50% of events are not used as links (e.g. the load balancer host)
GRAPH_MAX_ENTITIES = 48
_TEMPLATE_RE = re.compile(r"\d+|\b[0-9a-f]{6,}\b")


def fmt_span(seconds: float) -> str:
    seconds = max(0, int(round(seconds)))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m:02d}m"
    if m:
        return f"{m}m {s:02d}s"
    return f"{s}s"


def fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} TB"


def clock(iso: str) -> str:
    return iso[11:19] if len(iso) >= 19 else iso


_EMPTY_I = np.zeros(0, dtype=np.int32)


def _ints(idx: array) -> np.ndarray:
    """An `array('i')` event-index list as an int32 numpy view — no copy, no per-element Python int."""
    return np.frombuffer(idx, dtype=np.int32) if len(idx) else _EMPTY_I


def _dedup(it: Iterable[int]) -> Iterator[int]:
    """Drop repeats from an ASCENDING run — an event that fired two of the rules being asked about
    appears in both per-rule lists and must still be considered once, in its own position."""
    prev = -1
    for j in it:
        if j != prev:
            yield j
            prev = j


# Rows per chunk of the co-occurrence product. Kept under 2**24 so the float32 accumulation used on the
# GPU is EXACT for the integer counts it holds (a column can contribute at most one per row), which is
# what makes the CUDA and numpy answers bit-identical rather than merely close.
_CO_CHUNK = 1 << 20
_co_note = ""


def _note_co(reason: str) -> None:
    global _co_note
    if reason != _co_note:
        _co_note = reason
        print(f"[iris] entity co-occurrence staying on CPU (numpy): {reason}")


def _cooccurrence_np(masks: np.ndarray, ncols: int) -> np.ndarray:
    shifts = np.arange(ncols, dtype=np.uint64)
    one = np.uint64(1)
    co = np.zeros((ncols, ncols), dtype=np.int64)
    for s in range(0, masks.shape[0], 100_000):
        blk = masks[s:s + 100_000]
        a = ((blk[:, None] >> shifts) & one).astype(np.int32)
        co += (a.T @ a).astype(np.int64)
    return co


def cooccurrence(masks: np.ndarray, ncols: int) -> np.ndarray:
    """`ncols x ncols` counts of how often each pair of top entities appears in the same event.

    One uint64 bitmask per event (8 bytes) is expanded to a 0/1 membership block and multiplied by its
    own transpose in chunks. That is a dense GEMM over a million rows — genuinely GPU work — and the
    input is 8 bytes an event, so the transfer is a rounding error next to the arithmetic.

    Both paths compute exact integer counts, so the CUDA and numpy results are identical, not merely
    close; `test_gpu_equivalence.py` asserts it.
    """
    if masks.shape[0] == 0 or ncols == 0:
        return np.zeros((ncols, ncols), dtype=np.int64)
    ap = xp()
    if ap is not np:
        need = int(masks.nbytes) + _CO_CHUNK * ncols * 4 * 2 + ncols * ncols * 8
        ok, why = gpu_fits(need)
        if not ok:
            _note_co(why)
        else:
            try:
                dev = to_device(masks)
                shifts = ap.arange(ncols, dtype=ap.uint64)
                one = ap.uint64(1)
                co = ap.zeros((ncols, ncols), dtype=ap.int64)
                for s in range(0, int(dev.shape[0]), _CO_CHUNK):
                    blk = dev[s:s + _CO_CHUNK]
                    a = ((blk[:, None] >> shifts) & one).astype(ap.float32)
                    co += (a.T @ a).astype(ap.int64)
                out = asnumpy(co).astype(np.int64)
                del dev, co
                return out
            except Exception as exc:
                _note_co(f"the GPU path failed ({type(exc).__name__}: {exc})")
    return _cooccurrence_np(masks, ncols)


class _UF:
    def __init__(self, n: int) -> None:
        self.p = list(range(n))

    def find(self, a: int) -> int:
        while self.p[a] != a:
            self.p[a] = self.p[self.p[a]]
            a = self.p[a]
        return a

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


class Analyzer:
    """Holds the event list / timestamp array and produces every correlation artefact."""

    def __init__(self, events: list[Event], ts: np.ndarray,
                 progress: Optional[Callable[[int], None]] = None) -> None:
        self.events = events
        self.ts = ts
        self.n = len(events)
        # ONE pass over the pool for everything that needs one. This used to be three separate walks
        # (entities, templates, seeds) plus a fourth in stats() and a full scan per burst_ratio /
        # baseline_for call; at 1.2 M events each walk is seconds.
        # entity_index / source_index hold array('i') rather than list[int]: same API for everything that
        # reads them (len, slice, iterate, set()) at 4 bytes an entry instead of a 28-byte int object.
        self.entity_index: dict[str, array] = defaultdict(lambda: array("i"))
        self.source_index: dict[str, array] = defaultdict(lambda: array("i"))
        # Seed indices per DETECTION id, ascending. `correlations_for` answers "what else fired the
        # same rule?" and used to do it by walking EVERY seed in the pool and building a transient set
        # of that event's detection ids — O(all seeds) with an allocation each, on the event-detail
        # request thread, for a page that is supposed to be a dictionary lookup. Measured on this
        # machine at 150,000 seeds: 75-80 ms of that one scan per open, and 240 ms for the whole call
        # once a broadly-firing rule gave it a hundred thousand candidates to insert and sort.
        # It is filled here because this pass is ALREADY reading `e.detections`, so it is free; it is
        # array('i') for the same reason the two indexes above are — 4 bytes an entry rather than a
        # 28-byte int object — and it holds one entry per (seed, detection), not per event.
        self.seeds_by_rule: dict[str, array] = defaultdict(lambda: array("i"))
        self.templates: Counter = Counter()
        self.seeds: list[int] = []
        self._egress = 0
        for i, e in enumerate(events):
            if progress is not None and not i % 20_000:
                progress(i)
            for x in e.entities:
                self.entity_index[x].append(i)
            self.source_index[e.sourceId].append(i)
            self.templates[(e.sourceId, _TEMPLATE_RE.sub("#", e.msg)[:80])] += 1
            if e.detections and e.ts:
                # A cluster is a statement about WHEN things happened, so an event with no parsed
                # timestamp cannot seed one — its epoch is +inf (unknown, see store.ts_key) and it would
                # poison every span it touched. It keeps its detections and is still searchable; it just
                # does not claim a position in a sequence. Enriching the source is what gives it one.
                self.seeds.append(i)
                egress = False
                for d in e.detections:
                    # `i` only ever grows, so comparing the last entry is a COMPLETE dedupe. It is
                    # here because nothing stops a rule tagging one event twice (`add_detection`
                    # appends), and a repeated index would spend one of the bounded candidate slots
                    # in `_same_detection` on an event that is already in the list.
                    idx = self.seeds_by_rule[d.id]
                    if not idx or idx[-1] != i:
                        idx.append(i)
                    if d.id == "SIGMA-NET-0022":
                        egress = True
                if egress and e.fields.get("bytes", "").isdigit():
                    self._egress += int(e.fields["bytes"])
        # Indices of the events that actually carry a time, for the handful of places that need the
        # pool's overall span. `ts` is sorted with the unstamped ones last, so this is a prefix.
        self.n_stamped = int(np.count_nonzero(np.isfinite(ts))) if self.n else 0
        self.generic = {k for k, v in self.entity_index.items() if self.n > 20 and len(v) > _GENERIC_SHARE * self.n}
        self.seed_set = set(self.seeds)
        self._ratio_cache: dict[int, Optional[float]] = {}
        # `i in seed_set` once per entity occurrence is millions of dict probes in graph(); as a bool
        # array the same question is one gather per entity.
        self.seed_mask = np.zeros(self.n, dtype=bool)
        if self.seeds:
            self.seed_mask[np.asarray(self.seeds, dtype=np.int64)] = True

    # ------------------------------------------------------------ bursts
    def burst_ratio(self, anchor: int) -> Optional[float]:
        """Anchor's per-minute rate vs the median non-empty minute for the same source (histogram on xp)."""
        if anchor in self._ratio_cache:
            return self._ratio_cache[anchor]
        sid = self.events[anchor].sourceId
        idx = self.source_index.get(sid, array("i"))
        result: Optional[float] = None
        if len(idx) >= 30:
            ap = xp()
            sub = self.ts[idx]
            sub = sub[np.isfinite(sub)]        # unstamped events have no per-minute rate
            if len(sub) < 30:
                self._ratio_cache[anchor] = None
                return None
            lo, hi = float(sub.min()), float(sub.max())
            bins = max(2, int((hi - lo) // 60) + 1)
            hist, _ = ap.histogram(ap.asarray(sub), bins=bins, range=(lo, lo + bins * 60))
            hist = asnumpy(hist).astype(np.float64)
            nonzero = hist[hist > 0]
            if len(nonzero) >= 3:
                baseline = float(np.median(nonzero))
                peak = float(hist[min(int((self.ts[anchor] - lo) // 60), bins - 1)])
                result = peak / baseline if baseline > 0 else None
        self._ratio_cache[anchor] = result
        return result

    # ---------------------------------------------------------- clusters
    def clusters(self) -> list[Cluster]:
        events, ts, seeds = self.events, self.ts, self.seeds
        if not seeds:
            return []
        seed_pos = {i: k for k, i in enumerate(seeds)}
        uf = _UF(len(seeds))
        phase_of: dict[int, int] = {}
        for i in seeds:
            phase_of[i] = max(_PHASE_OF.get(d.id, 2) for d in events[i].detections)
        by_phase: dict[int, list[int]] = defaultdict(list)
        for i in seeds:
            by_phase[phase_of[i]].append(i)
        # Connectivity, not the full pair list. This was every seed against every later seed inside a
        # one-hour window: with 300 k dense seeds that is ~10^10 comparisons and /api/timeline simply
        # never came back. Union-find only needs a SPANNING set of edges, and both original edge kinds
        # collapse to consecutive pairs:
        #   * time (dt <= 900): the members are sorted, so if a and b are within 900 s every member
        #     between them is too — the consecutive chain already unions the whole run.
        #   * shared entity (dt <= 3600): same argument along the subsequence of members carrying that
        #     entity, so only each entity's previous occurrence has to be considered.
        # Identical components, O(seeds x entities-per-seed) instead of quadratic; pinned by
        # test_gpu_equivalence-style comparison against the original in test_cluster_equivalence.
        for members in by_phase.values():
            members.sort(key=lambda i: ts[i])
            prev_with: dict[str, int] = {}
            for k, b in enumerate(members):
                if k and ts[b] - ts[members[k - 1]] <= 900:
                    uf.union(seed_pos[members[k - 1]], seed_pos[b])
                for x in events[b].entities:
                    if x in self.generic:
                        continue
                    a = prev_with.get(x)
                    if a is not None and ts[b] - ts[a] <= 3600:
                        uf.union(seed_pos[a], seed_pos[b])
                    prev_with[x] = b
        groups: dict[int, list[int]] = defaultdict(list)
        for i in seeds:
            groups[uf.find(seed_pos[i])].append(i)
        out: list[Cluster] = []
        for k, g in enumerate(sorted(groups.values(), key=lambda g: min(ts[i] for i in g)), 1):
            g.sort(key=lambda i: ts[i])
            ph = Counter(phase_of[i] for i in g).most_common(1)[0][0]
            _, title, tag, _ = PHASES[ph]
            evs = [events[i] for i in g]
            sev = "info"
            sources: list[str] = []
            count = 0
            for e in evs:
                sev = max_sev(sev, e.sev)
                if e.source not in sources:
                    sources.append(e.source)
                bc = e.fields.get("burst.count", "")
                count += int(bc) if bc.isdigit() else 1
            if tag == "FREQUENCY" and len(sources) >= 2:
                tag = "ENTITY LINK"
            out.append(Cluster(id=f"c{k}", title=title, start=evs[0].ts, end=evs[-1].ts, span=fmt_span(ts[g[-1]] - ts[g[0]]),
                               tag=tag, sev=sev, count=count, sources=sources, why=self._why(evs, g, tag),  # type: ignore[arg-type]
                               eventIds=[e.id for e in evs]))
        return out

    def _why(self, evs: list[Event], idx: list[int], tag: str) -> str:
        ts = self.ts
        ent_counter: Counter = Counter()
        for e in evs:
            for x in e.entities:
                if x not in self.generic:
                    ent_counter[x] += 1
        shared = [x for x, c in ent_counter.most_common(3) if c >= 2] if len(evs) > 1 else []
        span = fmt_span(ts[idx[-1]] - ts[idx[0]])
        parts: list[str] = []
        if tag == "FREQUENCY":
            a = evs[0]
            bc = a.fields.get("burst.count", "")
            ratio = self.burst_ratio(idx[0])
            if bc:
                parts.append(f"{bc} events matching '{a.detections[0].name}' against one target from "
                             f"{a.fields.get('src_ip') or a.host} in {a.fields.get('burst.window', span)}"
                             + (f", {ratio:,.0f}× the per-minute baseline for this source" if ratio and ratio > 2 else "") + ".")
            else:
                parts.append(f"{len(evs)} detection(s) in {span}" + (f", {ratio:,.0f}× baseline rate" if ratio and ratio > 2 else "") + ".")
            parts.append("Grouped by time proximity" + (f" and shared {shared[0]}" if shared else "") + ".")
        else:
            steps = [f"{clock(e.ts)} {(e.detections[0].name if e.detections else e.msg).lower()} ({e.source})" for e in evs[:6]]
            parts.append("Sequence: " + "; ".join(steps) + ("; …" if len(evs) > 6 else "") + ".")
            if shared:
                parts.append(f"Linked by shared entit{'y' if len(shared) == 1 else 'ies'} {', '.join(shared)} across "
                             f"{len({e.source for e in evs})} source(s) within {span}.")
            else:
                parts.append(f"Linked by time proximity within {span}.")
            if tag == "ANOMALY":
                vol = [e for e in evs if any(d.id in ("SIGMA-NET-0022", "SIGMA-APP-0055") for d in e.detections)]
                if vol:
                    parts.append("Volume anomaly: " + "; ".join(e.msg for e in vol[:2]) + ".")
        return " ".join(parts)

    # ------------------------------------------------------------- graph
    def graph(self) -> tuple[list[Entity], list[Edge], dict[str, Entity]]:
        events, ts = self.events, self.ts
        score: Counter = Counter()
        for name, idx in self.entity_index.items():
            det = int(self.seed_mask[_ints(idx)].sum()) if len(idx) < 50000 else 0
            s = det * 1000 + min(len(idx), 999)
            if re.fullmatch(r"[\w.-]+\[\d+\]", name):  # process[pid] nodes are too granular for the graph
                s -= 100000
            score[name] = s
        top = [name for name, s in score.most_common(GRAPH_MAX_ENTITIES) if s > 0]
        if not top:
            return [], [], {}
        pos = {name: k for k, name in enumerate(top)}
        ncols = len(top)
        # Co-occurrence over at most GRAPH_MAX_ENTITIES (48) columns. The dense n x 48 float32 membership
        # matrix this used to build is 234 MB at 1.2 M events (and a second copy for the transpose), for a
        # 48x48 answer. One uint64 bitmask per event holds the same information in 8 bytes, and the
        # product is accumulated in row chunks so peak extra memory is a few MB whatever the pool size.
        masks = np.zeros(self.n, dtype=np.uint64)
        for i, e in enumerate(events):
            m = 0
            for x in e.entities:
                j = pos.get(x)
                if j is not None:
                    m |= 1 << j
            if m:
                masks[i] = m
        masks = masks[masks != 0]
        co = cooccurrence(masks, ncols)
        edges: list[Edge] = []
        for a in range(len(top)):
            for b in range(a + 1, len(top)):
                shared = int(co[a, b])
                if shared > 0:
                    edges.append(Edge(a=top[a], b=top[b], weight=round(1.0 + min(2.0, float(np.log10(shared + 1))), 2)))
        edges.sort(key=lambda e: -e.weight)
        edges = edges[:200]
        entities: list[Entity] = []
        emap: dict[str, Entity] = {}
        for name in top:
            idx = self.entity_index[name]
            first_i = min(idx, key=lambda i: ts[i])
            last_i = max(idx, key=lambda i: ts[i])
            kind = self._kind(name, idx)
            facts: list[tuple[str, str]] = [("Kind", kind), ("Events", f"{len(idx):,}"),
                                            ("First seen in case", clock(events[first_i].ts)), ("Last seen", clock(events[last_i].ts))]
            srcs = Counter(events[i].source for i in idx[:5000])
            facts.append(("Sources", " · ".join(s for s, _ in srcs.most_common(4))))
            dets = Counter(d.name for i in idx if i in self.seed_set for d in events[i].detections)
            if dets:
                facts.append(("Detections", "; ".join(f"{k} ({v})" for k, v in dets.most_common(3))))
            facts.extend(self._kind_facts(name, kind, idx))
            j = pos[name]
            link_rows = sorted(((int(co[j, k]), top[k]) for k in range(len(top)) if k != j and co[j, k] > 0), reverse=True)
            links = [EntityLink(name=other, shared=shared, via=self._via(name, other)) for shared, other in link_rows[:8]]
            ent = Entity(name=name, kind=kind, first=events[first_i].ts, count=len(idx), facts=facts, links=links)
            entities.append(ent)
            emap[name] = ent
        return entities, edges, emap

    def _kind(self, name: str, idx: list[int]) -> str:
        sample = [self.events[i] for i in idx[:200]]
        hint = ""
        if any(e.host == name for e in sample):
            fam = Counter(e.source for e in sample if e.host == name).most_common(1)[0][0]
            hint = {"windows.evtx": "Host · Windows", "syslog": "Host · Linux", "nginx.access": "Host · load balancer",
                    "aws.cloudtrail": "AWS region", "k8s.audit": "Cluster", "app.jsonl": "Service",
                    "firewall.edge": "Host · firewall"}.get(fam, "Host")
        elif any(e.user == name for e in sample):
            fams = {e.source for e in sample if e.user == name}
            if "aws.cloudtrail" in fams:
                hint = "IAM principal · service account" if name.startswith(("svc_", "svc-")) else "IAM principal"
            elif name in ("root", "administrator", "admin"):
                hint = "OS account"
            elif name.startswith(("svc_", "svc-", "ci-")):
                hint = "Service account"
            else:
                hint = "Account"
        elif any(e.fields.get("pod", "").startswith(name) for e in sample):
            hint = "Pod" if re.search(r"-[a-f0-9]{4,10}$", name) else "Service · k8s deployment"
        return entity_kind(name, hint)

    def _kind_facts(self, name: str, kind: str, idx: list[int]) -> list[tuple[str, str]]:
        sample = [self.events[i] for i in idx[:5000]]
        facts: list[tuple[str, str]] = []
        if kind.startswith("IPv4"):
            facts.append(("Scope", "external / public" if is_public_ip(name) else "internal / private"))
            users = Counter(e.user for e in sample if e.user)
            if users:
                facts.append(("Accounts seen", ", ".join(u for u, _ in users.most_common(3))))
            hosts = Counter(e.host for e in sample if e.host and e.host != name)
            if hosts:
                facts.append(("Hosts touched", ", ".join(h for h, _ in hosts.most_common(3))))
            out = sum(int(e.fields["bytes"]) for e in sample if e.fields.get("dst") == name and e.fields.get("bytes", "").isdigit())
            if out:
                facts.append(("Bytes received", fmt_bytes(out)))
            if any(d.id == "SIGMA-WEB-0042" for e in sample for d in e.detections):
                facts.append(("Reputation", "source of a credential-stuffing burst in this case"))
        elif "principal" in kind or "account" in kind.lower():
            ips = Counter(x for e in sample for x in e.entities if is_public_ip(x))
            if ips:
                facts.append(("External IPs", ", ".join(i for i, _ in ips.most_common(3))))
            hosts = Counter(e.host for e in sample if e.host)
            if hosts:
                facts.append(("Hosts", ", ".join(h for h, _ in hosts.most_common(4))))
            if any(e.fields.get("MFAUsed", "").lower() == "no" for e in sample):
                facts.append(("MFA", "not used"))
            privs = sorted({p for e in sample for p in e.fields.get("PrivilegeList", "").split() if p})
            if privs:
                facts.append(("Privilege", ", ".join(privs[:4])))
            keys = [e.fields["accessKeyId"] for e in sample if e.fields.get("accessKeyId")]
            if keys:
                facts.append(("Access keys created", ", ".join(k[:4] + "…" + k[-4:] for k in keys[:3])))
        elif kind == "AWS access key":
            facts.append(("Persistence", "long-lived credential"))
        else:
            users = Counter(e.user for e in sample if e.user)
            if users:
                facts.append(("Accounts", ", ".join(u for u, _ in users.most_common(4))))
            sev = Counter(e.sev for e in sample)
            facts.append(("Severity mix", ", ".join(f"{k} {v}" for k, v in sev.most_common(3))))
        return facts

    def _via(self, a: str, b: str) -> str:
        # Both index arrays are already ascending and unique (an entity is listed once per event), so the
        # shared events are an intersect1d rather than two Python sets built from millions of ints.
        common = np.intersect1d(_ints(self.entity_index[a]), _ints(self.entity_index[b]), assume_unique=True)
        shared = sorted((int(i) for i in common), key=lambda i: -SEV_ORDER.get(self.events[i].sev, 0))[:50]
        if not shared:
            return "co-occur"
        dets = Counter(d.name for i in shared for d in self.events[i].detections)
        if dets:
            return dets.most_common(1)[0][0].lower()
        fams = Counter(self.events[i].source for i in shared)
        return f"co-occur in {fams.most_common(1)[0][0]}"

    # ------------------------------------------------------ correlations
    def _same_detection(self, cands: dict[int, list[str]], i: int, det_ids: set[str], limit: int) -> None:
        """Append "same detection" to the candidates that earn it, without walking the pool.

        There are two groups and they are different problems:

        * A `j` the entity and time passes have ALREADY put in `cands` only needs the reason appended
          IN PLACE, so its position in the dict — which is what the final stable sort uses to break a
          tie — does not move. Both of those passes are already bounded (5,000 per entity, 2,000 in
          the window), so this loop is bounded too.
        * Every OTHER matching seed can be reached through this one reason and no other, so `rank`
          scores it `(-4, -sev, |dt|)` — the first element CONSTANT, because a seed always has
          detections. At most `limit` of them can survive `sorted(cands, key=rank)[:limit]`, so only
          the `limit` smallest by that exact tail are inserted, in ascending index order. That is the
          order the old full pass inserted them in, so a tie is broken exactly as it was before.

        The old code asked the same question from the other end — `for j in self.seeds`, building a set
        of every seed's detection ids and intersecting — which is the whole pool's worth of seeds and
        one allocation each, per event opened. `seeds_by_rule` is that question's index.
        """
        events, ts, seed_mask = self.events, self.ts, self.seed_mask
        for j in list(cands):
            if j != i and seed_mask[j] and any(d.id in det_ids for d in events[j].detections):
                cands[j].append("same detection")
        if len(det_ids) == 1:
            merged: Iterable[int] = self.seeds_by_rule.get(next(iter(det_ids)), ())
        else:
            merged = _dedup(heapq.merge(*(self.seeds_by_rule.get(r, ()) for r in sorted(det_ids))))
        ti = ts[i]
        best = heapq.nsmallest(limit, ((-SEV_ORDER.get(events[j].sev, 0), abs(ts[j] - ti), j)
                                       for j in merged if j != i and j not in cands))
        for j in sorted(k[2] for k in best):
            cands[j].append("same detection")

    def correlations_for(self, i: int, limit: int = 7) -> list[Correlation]:
        events, ts = self.events, self.ts
        e = events[i]
        cands: dict[int, list[str]] = defaultdict(list)
        for x in e.entities:
            if x in self.generic:
                continue
            for j in self.entity_index.get(x, [])[:5000]:
                if j != i:
                    cands[j].append(f"shares {x}")
        if np.isfinite(ts[i]):
            lo = int(np.searchsorted(ts, ts[i] - 90, side="left"))
            hi = int(np.searchsorted(ts, ts[i] + 90, side="right"))
        else:
            lo = hi = i   # no timestamp, no "happened around the same time" — only shared entities

        for j in range(lo, min(hi, lo + 2000)):
            if j != i:
                cands[j].append(f"within {int(abs(ts[j] - ts[i]))}s")
        det_ids = {d.id for d in e.detections}
        if det_ids:
            self._same_detection(cands, i, det_ids, limit)

        def rank(j: int) -> tuple:
            reasons = cands[j]
            shares = sum(1 for r in reasons if r.startswith("shares"))
            same = 1 if any(r.startswith("same") for r in reasons) else 0
            has_det = 1 if events[j].detections else 0
            return (-(shares * 2 + has_det * 3 + same), -SEV_ORDER.get(events[j].sev, 0), abs(ts[j] - ts[i]))

        out: list[Correlation] = []
        for j in sorted(cands, key=rank)[:limit]:
            reasons = sorted(set(cands[j]), key=lambda r: (0 if r.startswith("shares") else 1 if r.startswith("within") else 2))
            o = events[j]
            out.append(Correlation(id=o.id, ts=o.ts, msg=o.msg, sev=o.sev, reason=", ".join(reasons[:3])))
        return out

    def baseline_for(self, i: int) -> str:
        e = self.events[i]
        same = self.templates.get((e.sourceId, _TEMPLATE_RE.sub("#", e.msg)[:80]), 1)
        src_idx = self.source_index.get(e.sourceId, array("i"))
        stamped = [j for j in (src_idx[0], src_idx[-1]) if np.isfinite(self.ts[j])] if len(src_idx) > 1 else []
        span_h = max((self.ts[src_idx[-1]] - self.ts[src_idx[0]]) / 3600.0, 1 / 60) if len(stamped) == 2 else 1 / 60
        who = e.host or e.source
        if same == 1:
            base = f"{who}: this message template appears once in {e.file} — no in-file baseline."
        else:
            base = f"{who}: {same:,} similar events in {e.file} (~{same / span_h:,.1f}/hour over {fmt_span(span_h * 3600)})."
        if e.fields.get("burst.count"):
            ratio = self.burst_ratio(i)
            if ratio and ratio > 1.5:
                base += f" This window is {ratio:,.0f}× the per-minute median for the source."
        return base

    # -------------------------------------------------------------- stats
    def stats(self, clusters: list[Cluster], entities: list[Entity]) -> dict[str, Any]:
        if self.seeds:
            window = fmt_span(max(self.ts[i] for i in self.seeds) - min(self.ts[i] for i in self.seeds))
        elif self.n_stamped > 1:
            window = fmt_span(float(self.ts[self.n_stamped - 1] - self.ts[0]))
        else:
            window = "0s"
        egress = self._egress  # tallied in the single build pass, not re-scanned per request
        return {"window": window, "clusters": len(clusters), "entities": len(entities), "egress": fmt_bytes(egress) if egress else "0 B"}


def analyze(events: list[Event], ts: np.ndarray,
            progress: Optional[Callable[[int], None]] = None) -> dict[str, Any]:
    if not events:
        return {"analyzer": None, "clusters": [], "entities": [], "entity_map": {}, "edges": [],
                "stats": {"window": "0s", "clusters": 0, "entities": 0, "egress": "0 B"}}
    az = Analyzer(events, ts, progress=progress)
    clusters = az.clusters()
    entities, edges, emap = az.graph()
    return {"analyzer": az, "clusters": clusters, "entities": entities, "entity_map": emap, "edges": edges,
            "stats": az.stats(clusters, entities)}


# ============================================================================= cache
def _sync_limit() -> int:
    try:
        return int(os.environ.get("IRIS_ANALYSIS_SYNC_MAX", DEFAULT_SYNC_LIMIT))
    except ValueError:
        return DEFAULT_SYNC_LIMIT


# One analysis per scope, keyed on the store version. GET /api/timeline reads it through
# `Store.analysis_ready` and never builds it on the request thread at pool scale.
ANALYSIS_CACHE = AsyncCache("analysis", sync_limit=_sync_limit())
