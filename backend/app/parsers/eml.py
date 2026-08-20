"""E-mail parser: RFC 822 `.eml`, Unix `.mbox` archives and (optionally) Outlook `.msg`.

Named `eml` rather than `email` on purpose - a module called `email.py` inside this package would be
importable as `app.parsers.email`, which is harmless, but any future `import email` written without
`from __future__ import absolute_import` habits (or a tool that adds the package dir to sys.path) would
shadow the stdlib module this file depends on. Not worth the risk.

Each message becomes ONE event: Date -> ts, Subject -> msg, sender -> user, and the security-relevant
parts (originating IPs from Received, SPF/DKIM/DMARC from Authentication-Results, body URLs, attachment
names + SHA-256) land in fields so entity extraction and the IOC panel pick them up.
"""
from __future__ import annotations

import email
import email.policy
import hashlib
import re
from email.header import decode_header, make_header
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime
from typing import Iterable, Iterator, Optional

from ..normalize import IPV4_RE, is_public_ip
from .base import BaseParser, ParsedEvent
from .memdump import URL_RE

EXTENSIONS = (".eml", ".mbox", ".msg", ".mbx", ".email")
OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

MSG_MISSING = ("Outlook .msg files need the optional 'extract_msg' package (pip install extract-msg). "
               "Export the mail as .eml from Outlook for an alternative.")

MAX_MESSAGES = 50_000
MAX_BODY = 4000
MAX_URLS = 25
MAX_ATTACHMENTS = 50

_FROM_LINE = re.compile(rb"(?m)^From \S+.*$")
_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc|compauth)\s*=\s*([A-Za-z]+)", re.I)
_RECEIVED_IP = re.compile(r"\[?\b((?:\d{1,3}\.){3}\d{1,3})\b\]?")
_RECEIVED_FROM = re.compile(r"^\s*from\s+([A-Za-z0-9._-]+)", re.I)

# extensions that are worth flagging on an inbound mail
RISKY_ATTACHMENTS = (".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".wsf",
                     ".hta", ".lnk", ".ps1", ".jar", ".iso", ".img", ".vhd", ".msi", ".dll", ".docm", ".xlsm",
                     ".pptm", ".chm", ".reg")


def msg_available() -> bool:
    try:
        import extract_msg  # noqa: F401
        return True
    except Exception:
        return False


def _hdr(m: Message, name: str) -> str:
    """A decoded header value that never raises on malformed RFC 2047 encoding."""
    try:
        raw = m.get(name)
    except Exception:
        return ""
    if raw is None:
        return ""
    if not isinstance(raw, str):
        raw = str(raw)
    try:
        value = str(make_header(decode_header(raw)))
    except Exception:
        value = raw
    return " ".join(value.split())


def _addr_list(m: Message, name: str) -> list[str]:
    try:
        values = m.get_all(name) or []
    except Exception:
        return []
    out: list[str] = []
    for _disp, addr in getaddresses([str(v) for v in values]):
        addr = addr.strip().strip("<>")
        if addr and addr not in out:
            out.append(addr)
    return out


def _domain(addr: str) -> str:
    _, _, dom = addr.partition("@")
    return dom.strip().lower()


def _body_text(m: Message) -> tuple[str, list[tuple[str, int, str]]]:
    """(text body, [(filename, size, sha256)]). Handles multipart, quoted-printable and base64."""
    body_parts: list[str] = []
    attachments: list[tuple[str, int, str]] = []
    try:
        walker = m.walk() if m.is_multipart() else [m]
    except Exception:
        walker = [m]
    for part in walker:
        try:
            if part.is_multipart():
                continue
            ctype = (part.get_content_type() or "").lower()
            disp = (part.get_content_disposition() or "").lower()
            filename = part.get_filename()
            if filename:
                try:
                    filename = str(make_header(decode_header(filename)))
                except Exception:
                    pass
            payload = part.get_payload(decode=True)
        except Exception:
            continue
        if payload is None:
            continue
        if filename or disp == "attachment":
            if len(attachments) < MAX_ATTACHMENTS:
                attachments.append((str(filename or "(unnamed)"), len(payload),
                                    hashlib.sha256(payload).hexdigest()))
            continue
        if ctype.startswith("text/") and len(" ".join(body_parts)) < MAX_BODY:
            charset = part.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="replace")
            except (LookupError, UnicodeDecodeError):
                text = payload.decode("utf-8", errors="replace")
            if ctype == "text/html":
                text = re.sub(r"<[^>]+>", " ", text)
            body_parts.append(text)
    return " ".join(" ".join(body_parts).split())[:MAX_BODY], attachments


def _received_chain(m: Message) -> tuple[list[str], str]:
    """(public IPs seen in Received headers, originating host). Received headers are prepended, so the
    LAST one is the first hop - that is the one that names the actual originator."""
    try:
        received = [str(v) for v in (m.get_all("Received") or [])]
    except Exception:
        received = []
    ips: list[str] = []
    for line in reversed(received):
        for ip in _RECEIVED_IP.findall(line):
            if IPV4_RE.fullmatch(ip) and is_public_ip(ip) and ip not in ips:
                ips.append(ip)
    host = ""
    if received:
        mo = _RECEIVED_FROM.match(" ".join(received[-1].split()))
        if mo:
            host = mo.group(1)
    return ips, host


def _auth_results(m: Message) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        lines = [str(v) for v in (m.get_all("Authentication-Results") or [])]
        lines += [str(v) for v in (m.get_all("ARC-Authentication-Results") or [])]
    except Exception:
        lines = []
    for line in lines:
        for key, value in _AUTH_RE.findall(line):
            out.setdefault(key.lower(), value.lower())
    spf = _hdr(m, "Received-SPF")
    if spf and "spf" not in out:
        out["spf"] = spf.split()[0].lower()
    return out


def message_event(m: Message, extra: Optional[dict[str, str]] = None) -> ParsedEvent:
    """Normalize one parsed message into an event. Never raises on malformed input."""
    fields: dict[str, str] = dict(extra or {})
    subject = _hdr(m, "Subject")
    senders = _addr_list(m, "From")
    to = _addr_list(m, "To")
    cc = _addr_list(m, "Cc")
    bcc = _addr_list(m, "Bcc")
    reply_to = _addr_list(m, "Reply-To")
    sender = senders[0] if senders else ""

    ts = None
    date_text = _hdr(m, "Date")
    if date_text:
        try:
            ts = parsedate_to_datetime(date_text)
        except (TypeError, ValueError, IndexError):
            ts = None

    body, attachments = _body_text(m)
    ips, origin_host = _received_chain(m)
    auth = _auth_results(m)

    urls: list[str] = []
    for u in URL_RE.findall(f"{subject} {body}"):
        u = u.rstrip(").,;'\"")
        if u not in urls:
            urls.append(u)
        if len(urls) >= MAX_URLS:
            break

    if subject:
        fields["subject"] = subject
    if sender:
        fields["from"] = sender
        fields["email"] = sender
        dom = _domain(sender)
        if dom:
            fields["from_domain"] = dom
            fields["domain"] = dom
    for key, values in (("to", to), ("cc", cc), ("bcc", bcc), ("reply_to", reply_to)):
        if values:
            fields[key] = ", ".join(values[:20])
    if reply_to and sender and _domain(reply_to[0]) != _domain(sender):
        fields["reply_to_mismatch"] = "yes"
    for name, key in (("Message-ID", "message_id"), ("In-Reply-To", "in_reply_to"), ("Return-Path", "return_path"),
                      ("X-Mailer", "x_mailer"), ("User-Agent", "user_agent"), ("X-Originating-IP", "x_originating_ip"),
                      ("List-Id", "list_id"), ("Content-Type", "content_type")):
        v = _hdr(m, name)
        if v:
            fields[key] = v[:300]
    if date_text:
        fields["date"] = date_text
    if ips:
        fields["received_ips"] = ", ".join(ips[:10])
        fields["src_ip"] = ips[0]
    if origin_host:
        fields["origin_host"] = origin_host
    for key in ("spf", "dkim", "dmarc", "compauth"):
        if key in auth:
            fields[key] = auth[key]
    if urls:
        fields["url"] = ", ".join(urls)
        fields["url_count"] = str(len(urls))
    risky: list[str] = []
    if attachments:
        fields["attachments"] = ", ".join(f"{n} ({s} bytes)" for n, s, _ in attachments)
        fields["attachment_names"] = ", ".join(n for n, _, _ in attachments)
        fields["attachment_hashes"] = ", ".join(f"{n}=sha256:{h}" for n, _, h in attachments)
        fields["attachment_count"] = str(len(attachments))
        risky = [n for n, _, _ in attachments if n.lower().endswith(RISKY_ATTACHMENTS)]
        if risky:
            fields["risky_attachment"] = ", ".join(risky)
    if body:
        fields["body"] = body[:1000]

    sev = None
    auth_failed = [k for k in ("spf", "dkim", "dmarc") if auth.get(k) in ("fail", "softfail", "permerror")]
    if risky:
        sev = "high"
    elif auth_failed:
        fields["auth_failed"] = ", ".join(auth_failed)
        sev = "medium"

    header_lines = []
    for name in ("Date", "From", "To", "Cc", "Subject", "Message-ID", "Return-Path"):
        v = _hdr(m, name)
        if v:
            header_lines.append(f"{name}: {v}")
    raw = "\n".join(header_lines)
    if ips:
        raw += "\nReceived-IPs: " + ", ".join(ips[:10])
    if body:
        raw += "\n\n" + body[:2000]

    return ParsedEvent(raw=raw[:6000], msg=(subject or (body[:200] if body else "(no subject)"))[:300],
                       ts=ts, ts_text=date_text, host=origin_host, user=sender, sev=sev, fields=fields)


class EmailParser(BaseParser):
    name = "E-mail message"
    family = "mail.message"
    binary = True
    extensions = EXTENSIONS

    def sniff(self, sample: list[str], filename: str = "", head: bytes = b"") -> float:
        lower = filename.lower()
        if lower.endswith((".eml", ".msg", ".mbox", ".mbx")):
            return 1.0
        # a raw RFC 822 stream: header block with the headers that actually matter
        head_lines = [l for l in sample[:60]]
        if not head_lines:
            return 0.0
        joined = "\n".join(head_lines[:40])
        strong = sum(1 for h in ("Message-ID:", "Received:", "MIME-Version:", "Content-Type:", "Return-Path:",
                                 "Authentication-Results:")
                     if re.search(rf"(?mi)^{re.escape(h)}", joined))
        has_from = bool(re.search(r"(?mi)^From:\s*\S", joined))
        has_subject = bool(re.search(r"(?mi)^Subject:", joined))
        if head_lines[0].startswith("From ") and strong >= 1:
            return 0.95  # mbox separator line
        if has_from and has_subject and strong >= 2:
            return 0.92
        if has_from and strong >= 3:
            return 0.8
        return 0.0

    def parse(self, lines: Iterable[str]) -> Iterator[ParsedEvent]:
        yield from self.parse_bytes("\n".join(lines).encode("utf-8", errors="replace"))

    def parse_bytes(self, data: bytes) -> Iterator[ParsedEvent]:
        if data.startswith(OLE2_MAGIC):
            yield from self._parse_msg(data)
            return
        # Only an mbox starts with a From_ separator line. Gating on that keeps a body line that happens
        # to begin with "From " from splitting a single .eml into pieces.
        if data.lstrip(b"\r\n").startswith(b"From "):
            for i, chunk in enumerate(split_mbox(data)[:MAX_MESSAGES], 1):
                m = _safe_parse(chunk)
                if m is None:
                    continue
                yield message_event(m, {"mbox_index": str(i)})
            return
        m = _safe_parse(data)
        if m is None:
            raise RuntimeError("the file could not be parsed as an e-mail message")
        yield message_event(m)

    def _parse_msg(self, data: bytes) -> Iterator[ParsedEvent]:
        try:
            import extract_msg
        except Exception:
            raise RuntimeError(MSG_MISSING)
        import io

        try:
            msg = extract_msg.openMsg(io.BytesIO(data))
        except Exception as exc:
            raise RuntimeError(f"the Outlook .msg file could not be read: {exc}")
        try:
            # extract_msg can hand back the original transport headers; when it can, reuse the whole
            # RFC 822 pipeline so .msg and .eml produce identical fields. The headers alone carry no MIME
            # parts, though, so the body and the attachments have to be lifted off the .msg object and
            # merged in - without that a phishing .msg lost its payload names and hashes entirely.
            headers = getattr(msg, "header", None)
            if isinstance(headers, Message):
                extra = _msg_extras(msg)
                ev = message_event(headers, extra)
                body = extra.get("body", "")
                if body and body[:200] not in ev.raw:
                    ev.raw = (ev.raw + "\n\n" + body)[:6000]
                # message_event only saw the (attachment-less) headers, so it may have settled on the
                # medium it gives an SPF/DKIM failure. A risky attachment outranks that.
                if extra.get("risky_attachment") and ev.sev not in ("critical", "high"):
                    ev.sev = "high"
                if not ev.msg or ev.msg == "(no subject)":
                    ev.msg = (str(getattr(msg, "subject", "") or "") or body[:200] or "(no subject)")[:300]
                _merge_urls(ev.fields, extra)
                yield ev
                return
            # No transport headers in the file (a draft, or a .msg Outlook composed locally).
            fields = _msg_extras(msg)
            subject = str(getattr(msg, "subject", "") or "")
            sender = str(getattr(msg, "sender", "") or "")
            to = str(getattr(msg, "to", "") or "")
            body = fields.get("body", "")
            if subject:
                fields["subject"] = subject
            if sender:
                fields["from"] = sender
                fields["email"] = sender
            if to:
                fields["to"] = to
            ts = None
            date = getattr(msg, "date", None)
            if date is not None:
                try:
                    ts = date if hasattr(date, "tzinfo") else parsedate_to_datetime(str(date))
                except Exception:
                    ts = None
            raw = f"Subject: {subject}\nFrom: {sender}\nTo: {to}\n\n{body[:2000]}"
            yield ParsedEvent(raw=raw[:6000], msg=(subject or body[:200] or "(no subject)")[:300], ts=ts,
                              user=sender, sev="high" if fields.get("risky_attachment") else None,
                              fields=fields)
        finally:
            try:
                msg.close()
            except Exception:
                pass


def _merge_urls(fields: dict[str, str], extra: dict[str, str]) -> None:
    """message_event recomputes `url` from the (header-only) MIME body, which would drop the URLs found
    in the .msg body stream. Union both lists instead of letting either win."""
    seen: list[str] = []
    for source in (fields.get("url", ""), extra.get("url", "")):
        for u in source.split(", "):
            u = u.strip()
            if u and u not in seen:
                seen.append(u)
    if seen:
        fields["url"] = ", ".join(seen[:MAX_URLS])
        fields["url_count"] = str(len(seen[:MAX_URLS]))


def _msg_extras(msg: object) -> dict[str, str]:
    """Body + attachment facts lifted off an extract_msg object, keyed exactly like the RFC 822 path.

    Outlook keeps the body and the attachments in their own OLE streams, so they are invisible to the
    transport-header Message the .msg also carries. Attachment names and SHA-256s are the whole point of
    ingesting a phishing mail, so they are merged in rather than left to the (empty) MIME walk.
    """
    fields: dict[str, str] = {"msg_format": "outlook"}
    body = ""
    for attr in ("body", "htmlBody", "rtfBody"):
        try:
            value = getattr(msg, attr, None)
        except Exception:
            continue
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        if isinstance(value, str) and value.strip():
            body = value
            if attr == "htmlBody":
                body = re.sub(r"<[^>]+>", " ", body)
            break
    body = " ".join(body.split())[:MAX_BODY]
    if body:
        fields["body"] = body[:1000]

    entries: list[tuple[str, int, str]] = []
    try:
        attachments = list(getattr(msg, "attachments", None) or [])
    except Exception:
        attachments = []
    for att in attachments[:MAX_ATTACHMENTS]:
        name = ""
        for attr in ("longFilename", "shortFilename", "name"):
            value = getattr(att, attr, None)
            if isinstance(value, str) and value.strip():
                name = value.strip()
                break
        try:
            blob = getattr(att, "data", None)
        except Exception:
            blob = None
        if isinstance(blob, str):
            blob = blob.encode("utf-8", errors="replace")
        if not isinstance(blob, (bytes, bytearray)):
            blob = None  # embedded .msg / unreadable stream: keep the name, skip the hash
        entries.append((name or "(unnamed)", len(blob) if blob is not None else 0,
                        hashlib.sha256(blob).hexdigest() if blob else ""))
    if entries:
        fields["attachments"] = ", ".join(f"{n} ({s} bytes)" for n, s, _ in entries)
        fields["attachment_names"] = ", ".join(n for n, _, _ in entries)
        hashes = [f"{n}=sha256:{h}" for n, _, h in entries if h]
        if hashes:
            fields["attachment_hashes"] = ", ".join(hashes)
        fields["attachment_count"] = str(len(entries))
        risky = [n for n, _, _ in entries if n.lower().endswith(RISKY_ATTACHMENTS)]
        if risky:
            fields["risky_attachment"] = ", ".join(risky)

    urls: list[str] = []
    for u in URL_RE.findall(body):
        u = u.rstrip(").,;'\"")
        if u not in urls:
            urls.append(u)
        if len(urls) >= MAX_URLS:
            break
    if urls:
        fields["url"] = ", ".join(urls)
        fields["url_count"] = str(len(urls))
    return fields


def _safe_parse(data: bytes) -> Optional[Message]:
    for policy in (email.policy.compat32,):
        try:
            return email.message_from_bytes(data, policy=policy)
        except Exception:
            continue
    return None


def split_mbox(data: bytes) -> list[bytes]:
    """Split an mbox into per-message byte chunks. A single .eml comes back as one chunk."""
    starts = [m.start() for m in _FROM_LINE.finditer(data)
              if m.start() == 0 or data[m.start() - 1:m.start()] == b"\n"]
    if not starts or starts[0] != 0:
        # tolerate leading blank lines / a preamble before the first From_ line
        if not starts:
            return [data]
    chunks: list[bytes] = []
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(data)
        body = data[start:end]
        nl = body.find(b"\n")
        if nl != -1:
            body = body[nl + 1:]
        body = _unescape_from(body).strip(b"\r\n")
        if body:
            chunks.append(body)
    return chunks or [data]


def _unescape_from(body: bytes) -> bytes:
    """mbox escapes body lines beginning with 'From ' as '>From '."""
    return re.sub(rb"(?m)^>(>*From )", rb"\1", body)
