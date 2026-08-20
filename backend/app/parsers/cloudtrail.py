"""AWS CloudTrail parser (JSON {"Records":[...]} or JSON lines)."""
from __future__ import annotations

from typing import Any, Iterable, Iterator

import orjson

from ..normalize import parse_ts
from .base import BaseParser, ParsedEvent, flatten

_SENSITIVE = {
    "ConsoleLogin", "CreateAccessKey", "DeleteTrail", "StopLogging", "UpdateTrail", "PutBucketPolicy",
    "CreateUser", "AttachUserPolicy", "PutUserPolicy", "AssumeRole", "GetSecretValue", "CreateLoginProfile",
    "DeleteAccessKey", "AuthorizeSecurityGroupIngress", "DisableKey", "ScheduleKeyDeletion",
}


def _iter_records(lines: Iterable[str]) -> Iterator[tuple[dict[str, Any], str]]:
    buf: list[str] = []
    for line in lines:
        s = line.strip()
        if not s:
            continue
        if s.startswith("{") and s.endswith("}") and not buf:
            try:
                obj = orjson.loads(s)
            except orjson.JSONDecodeError:
                buf.append(line)
                continue
            if isinstance(obj, dict) and isinstance(obj.get("Records"), list):
                for rec in obj["Records"]:
                    if isinstance(rec, dict):
                        yield rec, orjson.dumps(rec).decode()
            elif isinstance(obj, dict):
                yield obj, s
            continue
        buf.append(line)
    if buf:
        text = "\n".join(buf)
        try:
            obj = orjson.loads(text)
        except orjson.JSONDecodeError:
            return
        recs = obj.get("Records") if isinstance(obj, dict) else obj
        if isinstance(recs, list):
            for rec in recs:
                if isinstance(rec, dict):
                    yield rec, orjson.dumps(rec).decode()
        elif isinstance(obj, dict):
            yield obj, text


class CloudTrailParser(BaseParser):
    name = "AWS CloudTrail"
    family = "aws.cloudtrail"

    def sniff(self, sample: list[str], filename: str = "", head: bytes = b"") -> float:
        lines = sample[:200]
        text = "\n".join(lines)
        if '"eventSource"' not in text and '"eventName"' not in text:
            return 0.0
        # A CloudTrail file is a JSON DOCUMENT. Merely MENTIONING the AWS keys is not evidence of that —
        # this scores off distinct keys found anywhere in the sample, so a chat transcript or a ticket
        # export that QUOTES one record scores 1.0 and outranks JSONL. That is the same mistake EvtxParser
        # made with "<Event", and unlike syslog/nginx there is no backstop: this parser never emits
        # `parse_error`, so registry's trial parse can never demote it. Require the sample to actually
        # START as JSON, which every real CloudTrail export does ({"Records":[…]} or one object per line).
        first = next((l.lstrip("﻿ \t") for l in lines if l.strip()), "")
        if not first.startswith(("{", "[")):
            return 0.0
        score = 0.0
        for key in ('"eventVersion"', '"eventTime"', '"eventSource"', '"eventName"', '"awsRegion"', '"userIdentity"', '"sourceIPAddress"'):
            if key in text:
                score += 1
        conf = 0.5 + 0.5 * (score / 7)
        if '"Records"' in text:
            conf = min(1.0, conf + 0.05)
        return round(min(1.0, conf), 3)

    def parse(self, lines: Iterable[str]) -> Iterator[ParsedEvent]:
        for rec, raw in _iter_records(lines):
            fields = flatten(rec)
            name = str(rec.get("eventName", ""))
            ident = rec.get("userIdentity") or {}
            user = ""
            if isinstance(ident, dict):
                user = str(ident.get("userName") or "")
                if not user:
                    sess = ident.get("sessionContext", {}).get("sessionIssuer", {}) if isinstance(ident.get("sessionContext"), dict) else {}
                    user = str(sess.get("userName") or ident.get("arn", "").split("/")[-1] or ident.get("type") or "")
                fields["userIdentity.userName"] = user
            region = str(rec.get("awsRegion", ""))
            fields["region"] = region
            fields["eventName"] = name
            ip = str(rec.get("sourceIPAddress", ""))
            fields["sourceIPAddress"] = ip
            err = rec.get("errorCode")
            add = rec.get("additionalEventData") or {}
            resp = rec.get("responseElements") or {}
            mfa = add.get("MFAUsed") if isinstance(add, dict) else None
            if mfa is not None:
                fields["MFAUsed"] = str(mfa)
            fields["errorCode"] = str(err or "—")
            sev = None
            msg = name
            if name == "ConsoleLogin":
                result = resp.get("ConsoleLogin", "Success") if isinstance(resp, dict) else "Success"
                fields["result"] = str(result)
                msg = f"ConsoleLogin {result}" + (" — MFA not used" if str(mfa).lower() == "no" else "")
            elif name == "CreateAccessKey":
                key = ""
                if isinstance(resp, dict):
                    key = str((resp.get("accessKey") or {}).get("accessKeyId", ""))
                fields["accessKeyId"] = key
                fields["result"] = "Denied" if err else "Success"
                target = ""
                if isinstance(rec.get("requestParameters"), dict):
                    target = str(rec["requestParameters"].get("userName", ""))
                fields["target.user"] = target or user
                short = f"{key[:4]}…{key[-4:]}" if len(key) > 8 else key
                msg = f"CreateAccessKey — new long-lived key {short}" if not err else f"CreateAccessKey attempted — {err}"
            elif err:
                fields["result"] = "Denied" if "Denied" in str(err) else str(err)
                msg = f"{name} attempted — {err}"
                sev = "medium"
            else:
                fields["result"] = "Success"
                if isinstance(rec.get("requestParameters"), dict):
                    rp = rec["requestParameters"]
                    detail = rp.get("bucketName") or rp.get("userName") or rp.get("name") or rp.get("roleArn") or rp.get("instanceId") or ""
                    if detail:
                        msg = f"{name} {detail}"
            if name in _SENSITIVE and sev is None:
                sev = "medium"
            yield ParsedEvent(raw=raw, msg=msg, ts=parse_ts(str(rec.get("eventTime", ""))), ts_text=str(rec.get("eventTime", "")),
                              host=region, user=user, sev=sev, fields=fields)
