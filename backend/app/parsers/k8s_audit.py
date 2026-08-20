"""Kubernetes audit log parser (JSON lines, audit.k8s.io/v1 Event)."""
from __future__ import annotations

from typing import Iterable, Iterator

import orjson

from ..normalize import parse_ts
from .base import BaseParser, ParsedEvent, flatten

# A kube-apiserver audit log is one audit Event per line, so the audit keys are on essentially every
# line. The floor below is 0.55 and plain text tops out at 0.5, so a single JSON line carrying "verb"
# anywhere in a 200-line sample used to outscore the fallback and claim the file — and every other line
# would come back as `parse_error: json`. Demand a majority. Same constant, same reasoning, as
# syslog.MIN_MATCH_RATIO and nginx.MIN_MATCH_RATIO.
MIN_MATCH_RATIO = 0.5


class K8sAuditParser(BaseParser):
    name = "k8s audit v1"
    family = "k8s.audit"

    def sniff(self, sample: list[str], filename: str = "", head: bytes = b"") -> float:
        lines = [l for l in sample if l.strip()][:200]
        if not lines:
            return 0.0
        hits = 0
        strong = 0
        for l in lines:
            if not l.lstrip().startswith("{"):
                continue
            if '"objectRef"' in l or '"requestURI"' in l or '"verb"' in l:
                hits += 1
                if "audit.k8s.io" in l or ('"objectRef"' in l and '"verb"' in l):
                    strong += 1
        ratio = hits / len(lines)
        if ratio < MIN_MATCH_RATIO:
            return 0.0
        conf = 0.55 + 0.35 * ratio + (0.1 * strong / len(lines))
        return round(min(1.0, conf), 3)

    def parse(self, lines: Iterable[str]) -> Iterator[ParsedEvent]:
        for line in lines:
            s = line.strip()
            if not s:
                continue
            try:
                obj = orjson.loads(s)
            except orjson.JSONDecodeError:
                yield ParsedEvent(raw=s, msg=s[:200], fields={"parse_error": "json"})
                continue
            if not isinstance(obj, dict):
                continue
            fields = flatten(obj)
            ref = obj.get("objectRef") or {}
            user = ""
            u = obj.get("user") or {}
            if isinstance(u, dict):
                user = str(u.get("username", ""))
                fields["user"] = user
            verb = str(obj.get("verb", ""))
            resource = str(ref.get("resource", "")) if isinstance(ref, dict) else ""
            sub = str(ref.get("subresource", "")) if isinstance(ref, dict) else ""
            ns = str(ref.get("namespace", "")) if isinstance(ref, dict) else ""
            name = str(ref.get("name", "")) if isinstance(ref, dict) else ""
            res_full = f"{resource}/{sub}" if sub else resource
            fields["verb"] = verb
            fields["resource"] = res_full
            fields["namespace"] = ns
            if resource == "pods" and name:
                fields["pod"] = name
            uri = str(obj.get("requestURI", ""))
            code = ""
            rs = obj.get("responseStatus")
            if isinstance(rs, dict):
                code = str(rs.get("code", ""))
                fields["responseStatus"] = code
            fields["stage"] = str(obj.get("stage", ""))
            ips = obj.get("sourceIPs")
            if isinstance(ips, list) and ips:
                fields["src_ip"] = str(ips[0])
            sev = None
            if sub == "exec":
                cmd = ""
                if "command=" in uri:
                    cmd = uri.split("command=", 1)[1].split("&", 1)[0]
                fields["command"] = cmd
                msg = f"pods/exec into {name}" + (f" — {cmd}" if cmd else "")
                sev = "high"
            elif resource == "deployments" and verb == "patch":
                msg = f"deployments/{name} patched"
                body = obj.get("requestObject")
                if isinstance(body, dict):
                    spec = body.get("spec") or {}
                    if isinstance(spec, dict) and "replicas" in spec:
                        msg = f"deployments/{name} scaled → {spec['replicas']}"
                        fields["replicas"] = str(spec["replicas"])
            elif resource == "secrets" and verb in ("get", "list"):
                msg = f"secrets {verb} in {ns or 'cluster'}" + (f" — {name}" if name else "")
                sev = "medium" if verb == "list" else "low"
            elif code and code.startswith("4"):
                msg = f"{verb} {res_full} {name} → {code}".strip()
                sev = "medium" if code == "403" else "low"
            else:
                msg = f"{verb} {res_full}" + (f" {name}" if name else "") + (f" in {ns}" if ns else "")
            host = fields.get("annotations.cluster") or fields.get("cluster") or "k8s"
            ts_text = str(obj.get("requestReceivedTimestamp") or obj.get("stageTimestamp") or obj.get("timestamp") or "")
            yield ParsedEvent(raw=s, msg=msg, ts=parse_ts(ts_text), ts_text=ts_text, host=host, user=user, sev=sev, fields=fields)
