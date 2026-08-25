"""Generic JSON-lines parser: infers timestamp / level / message / host / user keys."""
from __future__ import annotations

from typing import Iterable, Iterator, Optional

import orjson

from ..normalize import parse_ts
from .base import BaseParser, ParsedEvent, flatten

TS_KEYS = ("ts", "timestamp", "@timestamp", "time", "eventTime", "datetime", "date", "t", "created_at", "logged_at", "asctime",
           "epoch", "epoch_ms", "epochMillis", "epoch_millis", "unix_time", "unixtime", "unixTime", "timestamp_ms", "ts_ms",
           "time_ms", "_time", "time_t", "event_time")
LEVEL_KEYS = ("level", "severity", "lvl", "loglevel", "log.level", "priority", "sev")
MSG_KEYS = ("msg", "message", "event", "text", "log", "description", "summary", "action")
HOST_KEYS = ("host", "hostname", "svc", "service", "app", "application", "server", "node", "container", "source")
USER_KEYS = ("user", "username", "actor", "user_id", "principal", "account", "uid", "user.name", "email")


LIST_KEYS = ("Records", "records", "events", "Events", "items", "logs", "data", "results", "hits", "entries", "rows", "value", "messages")

# Per-LINE branch only (a pretty-printed document is one record and has no per-line ratio to measure).
# A JSON-lines file is JSON on every line; a text log that happens to carry a couple of JSON blobs is
# not. The floor below is 0.45, so a handful of JSON lines used to beat a plain text file with no
# timestamps (0.2) and every non-JSON line became `parse_error: json`. Demand a majority — the same
# constant, and the same reasoning, as syslog/nginx/k8s_audit.MIN_MATCH_RATIO.
MIN_MATCH_RATIO = 0.5


def _unwrap(obj: object) -> list:
    """A JSON array, or an object holding a top-level list (Records/events/items/logs/data...) -> list of records."""
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        for k in LIST_KEYS:
            v = obj.get(k)
            if isinstance(v, list) and v and all(isinstance(x, dict) for x in v[:20]):
                return v
        # single list-valued key of dicts
        lists = [v for v in obj.values() if isinstance(v, list) and v and all(isinstance(x, dict) for x in v[:20])]
        if len(lists) == 1:
            return lists[0]
        return [obj]
    return []


def _iter_json_documents(lines: Iterable[str]) -> Iterator[tuple[object, str]]:
    """Yield (parsed, raw) for JSON lines; consecutive non-JSON lines are buffered as one pretty-printed document."""
    buf: list[str] = []
    for line in lines:
        s = line.strip()
        if not s:
            continue
        if not buf and s[0] in "{[" and s[-1] in "}]":
            try:
                yield orjson.loads(s), s
                continue
            except orjson.JSONDecodeError:
                pass
        buf.append(line)
    if buf:
        text = "\n".join(buf)
        try:
            yield orjson.loads(text), text
        except orjson.JSONDecodeError:
            for l in buf:
                if l.strip():
                    yield None, l.strip()


class JsonlParser(BaseParser):
    name = "JSON lines (inferred)"
    family = "app.jsonl"

    def sniff(self, sample: list[str], filename: str = "", head: bytes = b"") -> float:
        lines = [l for l in sample if l.strip()][:200]
        if not lines:
            return 0.0
        first = lines[0].lstrip()
        if first.startswith("[") or (first.startswith("{") and not first.rstrip().endswith("}")):
            # pretty-printed / array JSON document: sniff by structure of the whole sample
            text = "\n".join(lines)
            try:
                obj = orjson.loads(text)
                recs = _unwrap(obj)
                if recs and all(isinstance(r, dict) for r in recs[:20]):
                    with_ts = sum(1 for r in recs[:50] if any(k in r for k in TS_KEYS))
                    return round(min(0.9, 0.7 + 0.2 * with_ts / min(len(recs), 50)), 3)
                return 0.4 if isinstance(obj, (dict, list)) else 0.0
            except orjson.JSONDecodeError:
                pass
            # sample truncated: structural hint only
            if first.startswith("[") and "{" in text[:2000]:
                return 0.75
            if first.startswith("{") and any(f'"{k}"' in text[:2000] for k in LIST_KEYS):
                return 0.72
            return 0.0
        ok = 0
        with_ts = 0
        for l in lines:
            s = l.strip()
            if not (s.startswith("{") and s.endswith("}")):
                continue
            try:
                obj = orjson.loads(s)
            except orjson.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                ok += 1
                if any(k in obj for k in TS_KEYS):
                    with_ts += 1
        ratio = ok / len(lines)
        if ratio < MIN_MATCH_RATIO:
            return 0.0
        conf = 0.45 + 0.35 * ratio + 0.12 * (with_ts / max(ok, 1))
        return round(min(0.92, conf), 3)

    @staticmethod
    def _pick(obj: dict, keys: tuple[str, ...]) -> tuple[Optional[str], str]:
        for k in keys:
            if k in obj and obj[k] not in (None, ""):
                v = obj[k]
                if isinstance(v, (dict, list)):
                    continue
                return k, str(v)
        return None, ""

    def parse(self, lines: Iterable[str]) -> Iterator[ParsedEvent]:
        for doc, raw in _iter_json_documents(lines):
            if doc is None:
                yield ParsedEvent(raw=raw, msg=raw[:200], fields={"parse_error": "json"})
                continue
            recs = _unwrap(doc)
            if len(recs) == 1 and recs[0] is doc:
                yield self._one(doc, raw)
                continue
            for rec in recs:
                if isinstance(rec, dict):
                    yield self._one(rec, orjson.dumps(rec).decode())
                else:
                    r = orjson.dumps(rec).decode()
                    yield ParsedEvent(raw=r, msg=r[:200])

    def _one(self, obj: dict, s: str) -> ParsedEvent:
        if True:
            fields = flatten(obj)
            _, ts_text = self._pick(obj, TS_KEYS)
            _, level = self._pick(obj, LEVEL_KEYS)
            _, msg = self._pick(obj, MSG_KEYS)
            _, host = self._pick(obj, HOST_KEYS)
            _, user = self._pick(obj, USER_KEYS)
            if level:
                fields["level"] = level
            if not msg:
                msg = s[:200]
            else:
                # enrich message with a few notable scalar fields
                extras = []
                for k in ("rows", "dest", "path", "status", "duration_ms", "error", "reason", "count", "bytes"):
                    if k in obj and not isinstance(obj[k], (dict, list)):
                        v = obj[k]
                        if k == "rows" and isinstance(v, int):
                            v = f"{v:,}"
                        extras.append(f"{k}={v}")
                if extras:
                    msg = f"{msg} — " + " ".join(extras)
            return ParsedEvent(raw=s, msg=msg[:300], ts=parse_ts(ts_text) if ts_text else None, ts_text=ts_text,
                               host=host, user=user, sev=None, fields=fields)
