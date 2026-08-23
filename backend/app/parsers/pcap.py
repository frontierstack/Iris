"""Packet capture parser: classic libpcap (.pcap/.cap) and pcapng (.pcapng), one event per packet.

Standard library only, on purpose. scapy is ~30 MB of import for a decoder we need a narrow slice of,
dpkt is unmaintained on the protocols analysts actually ask about (TLS SNI), and a capture is the one
evidence format most likely to arrive on a machine that installed nothing optional. Everything below
is header arithmetic over a memoryview.

What an event is: ONE PACKET, with the five-tuple in fields so `src_ip:10.0.0.5` and
`dst_port:445` work like any other source, plus the application-layer facts that answer the questions
a capture is opened for — which name was resolved (DNS), which host was requested (HTTP), which
server was reached through TLS (the ClientHello SNI, which is the only readable identity in an
encrypted flow).

Bounded by construction: every packet is decoded inside try/except and a malformed one becomes an
event carrying `parse_error` rather than ending the file — a truncated capture is normal evidence
(the analyst stopped tcpdump), and dropping the packets before the truncation would be silent loss.
"""
from __future__ import annotations

import struct
from datetime import datetime, timezone
from typing import Iterable, Iterator, Optional

from .base import BaseParser, ParsedEvent

# NOT ".pcap.gz" and friends: a compressed capture is an ARCHIVE, and claiming it here would hand
# gzip bytes to a decoder that can only report the magic is wrong. The archive handler expands it
# and the member arrives back here as a plain .pcap.
EXTENSIONS = (".pcap", ".pcapng", ".cap", ".ntar")

# ------------------------------------------------------------------ file magics
PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"        # microsecond, little-endian
PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"        # microsecond, big-endian
PCAP_MAGIC_NS_LE = b"\x4d\x3c\xb2\xa1"     # nanosecond, little-endian
PCAP_MAGIC_NS_BE = b"\xa1\xb2\x3c\x4d"     # nanosecond, big-endian
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"         # Section Header Block type

MAGICS = (PCAP_MAGIC_LE, PCAP_MAGIC_BE, PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE, PCAPNG_MAGIC)

# pcapng block types
_SHB = 0x0A0D0D0A
_IDB = 0x00000001
_PB = 0x00000002       # obsolete Packet Block
_SPB = 0x00000003      # Simple Packet Block
_EPB = 0x00000006      # Enhanced Packet Block

# DLT / LINKTYPE values we decode. Anything else still produces an event — with its link type named,
# because "Iris does not decode LINKTYPE_IEEE802_11 yet" and "this capture is empty" are different facts.
DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW_BSD = 12
DLT_RAW_ALT = 14
DLT_PPP = 9
DLT_LOOP = 108
DLT_LINUX_SLL = 113
DLT_RAW = 101
DLT_IPV4 = 228
DLT_IPV6 = 229
DLT_LINUX_SLL2 = 276

LINK_NAMES = {
    DLT_NULL: "null/loopback", DLT_EN10MB: "ethernet", DLT_PPP: "ppp", DLT_RAW_BSD: "raw ip",
    DLT_RAW_ALT: "raw ip", DLT_RAW: "raw ip", DLT_LOOP: "openbsd loopback", DLT_LINUX_SLL: "linux cooked",
    DLT_LINUX_SLL2: "linux cooked v2", DLT_IPV4: "raw ipv4", DLT_IPV6: "raw ipv6",
    105: "ieee802.11", 127: "ieee802.11 radiotap", 143: "dvb-ci", 195: "ieee802.15.4",
    204: "ppp with direction", 239: "netlink", 249: "usb linux",
}

IP_PROTOS = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6",
             89: "OSPF", 103: "PIM", 132: "SCTP"}

# IPv6 extension headers that are skippable in the (len, next) form. 44 (fragment) is fixed-size 8.
_V6_EXT_SKIP = {0, 43, 60, 51}

TCP_FLAG_NAMES = ((0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
                  (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR"))

ICMP_TYPES = {0: "echo-reply", 3: "dest-unreachable", 5: "redirect", 8: "echo-request",
              11: "ttl-exceeded", 13: "timestamp", 30: "traceroute"}
ICMP6_TYPES = {1: "dest-unreachable", 2: "packet-too-big", 3: "ttl-exceeded", 128: "echo-request",
               129: "echo-reply", 133: "router-solicit", 134: "router-advert", 135: "neighbor-solicit",
               136: "neighbor-advert"}

DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
             33: "SRV", 35: "NAPTR", 43: "DS", 46: "RRSIG", 48: "DNSKEY", 65: "HTTPS", 255: "ANY"}
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"TRACE ",
                b"CONNECT ", b"PROPFIND ")

DNS_PORTS = (53, 5353, 5355)
HTTP_PORTS = (80, 8080, 8000, 8888, 3128)
TLS_PORTS = (443, 8443, 993, 995, 465, 587, 990, 4443)

MAX_DNS_ANSWERS = 4        # a response can hold dozens; the first few are what identifies the flow
MAX_NAME_LEN = 253         # a DNS name cannot legally be longer, and a pointer loop must not grow one


class PcapError(Exception):
    """The file is not a capture we can read. Carries the sentence shown to the analyst."""


# ------------------------------------------------------------------ small helpers
def _ipv4(b: memoryview, off: int) -> str:
    return f"{b[off]}.{b[off + 1]}.{b[off + 2]}.{b[off + 3]}"


def _ipv6(b: bytes) -> str:
    """RFC 5952 text form, without importing ipaddress per packet."""
    groups = [f"{(b[i] << 8) | b[i + 1]:x}" for i in range(0, 16, 2)]
    best_i = best_n = cur_i = cur_n = -1
    for i, g in enumerate(groups + ["x"]):
        if g == "0":
            if cur_i < 0:
                cur_i, cur_n = i, 0
            cur_n += 1
        else:
            if cur_n > best_n:
                best_i, best_n = cur_i, cur_n
            cur_i, cur_n = -1, 0
    if best_n < 2:
        return ":".join(groups)
    return ":".join(groups[:best_i]) + "::" + ":".join(groups[best_i + best_n:])


def _mac(b: memoryview, off: int) -> str:
    return ":".join(f"{b[off + i]:02x}" for i in range(6))


def _tcp_flags(bits: int) -> str:
    return ",".join(name for mask, name in TCP_FLAG_NAMES if bits & mask)


def _ts(seconds: float) -> Optional[datetime]:
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


# ------------------------------------------------------------------ DNS
def _dns_name(buf: memoryview, off: int, end: int) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name. Returns (name, offset after the name in the record).

    Compression pointers can legally point backwards anywhere in the message, and a malicious or
    corrupt capture can make them point at each other. `hops` bounds that: a name is at most 253
    bytes, so a capture that needs more than a handful of jumps is not a name we should be following.
    """
    labels: list[str] = []
    hops = 0
    cur = off
    after = -1
    total = 0
    while cur < end:
        n = buf[cur]
        if n == 0:
            cur += 1
            break
        if n & 0xC0 == 0xC0:                       # pointer
            if cur + 1 >= end:
                break
            nxt = ((n & 0x3F) << 8) | buf[cur + 1]
            if after < 0:
                after = cur + 2
            hops += 1
            if hops > 8 or nxt >= end or nxt >= cur:   # only ever jump BACKWARDS: no loops possible
                break
            cur = nxt
            continue
        if cur + 1 + n > end:
            break
        total += n + 1
        if total > MAX_NAME_LEN:
            break
        labels.append(bytes(buf[cur + 1: cur + 1 + n]).decode("utf-8", "replace"))
        cur += 1 + n
    return (".".join(labels), after if after >= 0 else cur)


def _dns(payload: memoryview, fields: dict[str, str]) -> str:
    """Fill fields from a DNS message and return a one-line summary ('' if it is not DNS)."""
    n = len(payload)
    if n < 12:
        return ""
    tid, flags, qd, an = struct.unpack_from("!HHHH", payload, 0)
    is_resp = bool(flags & 0x8000)
    rcode = flags & 0x0F
    if qd == 0 and an == 0:
        return ""
    off = 12
    qname = ""
    qtype = 0
    if qd:
        qname, off = _dns_name(payload, off, n)
        if off + 4 > n:
            return ""
        qtype, _qclass = struct.unpack_from("!HH", payload, off)
        off += 4
    fields["dns_id"] = str(tid)
    fields["dns_qr"] = "response" if is_resp else "query"
    if qname:
        fields["dns_query"] = qname
        fields["dns_qtype"] = DNS_TYPES.get(qtype, str(qtype))
    answers: list[str] = []
    if is_resp:
        fields["dns_rcode"] = DNS_RCODES.get(rcode, str(rcode))
        for _ in range(min(an, MAX_DNS_ANSWERS)):
            if off + 10 > n:
                break
            _name, off = _dns_name(payload, off, n)
            if off + 10 > n:
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack_from("!HHIH", payload, off)
            off += 10
            if off + rdlen > n:
                break
            rdata = payload[off: off + rdlen]
            if rtype == 1 and rdlen == 4:
                answers.append(_ipv4(rdata, 0))
            elif rtype == 28 and rdlen == 16:
                answers.append(_ipv6(bytes(rdata)))
            elif rtype in (5, 2, 12):
                answers.append(_dns_name(payload, off, n)[0])
            off += rdlen
        if answers:
            fields["dns_answers"] = ",".join(answers)
    if not qname and not answers:
        return ""
    head = "DNS response" if is_resp else "DNS query"
    parts = [head, qname or "?"]
    if qtype:
        parts.append(DNS_TYPES.get(qtype, str(qtype)))
    if is_resp:
        if rcode:
            parts.append(DNS_RCODES.get(rcode, str(rcode)))
        elif answers:
            parts.append("-> " + " ".join(answers))
    return " ".join(parts)


# ------------------------------------------------------------------ HTTP
def _http(payload: memoryview, fields: dict[str, str]) -> str:
    data = bytes(payload[:2048])
    if data.startswith(b"HTTP/"):
        line = data.split(b"\r\n", 1)[0][:200].decode("latin-1", "replace")
        bits = line.split(" ", 2)
        if len(bits) >= 2 and bits[1].isdigit():
            fields["http_status"] = bits[1]
        fields["http_response"] = line
        return f"HTTP {line}"
    if not data.startswith(HTTP_METHODS):
        return ""
    head, _, rest = data.partition(b"\r\n")
    line = head[:400].decode("latin-1", "replace")
    bits = line.split(" ")
    if len(bits) < 2:
        return ""
    fields["http_method"] = bits[0]
    fields["http_path"] = bits[1][:1000]
    host = ua = ""
    for raw_line in rest.split(b"\r\n")[:40]:
        low = raw_line[:5].lower()
        if low.startswith(b"host:"):
            host = raw_line[5:].strip()[:255].decode("latin-1", "replace")
        elif raw_line[:11].lower().startswith(b"user-agent:"):
            ua = raw_line[11:].strip()[:400].decode("latin-1", "replace")
    if host:
        fields["http_host"] = host
        fields["url"] = f"http://{host}{bits[1][:1000]}"
    if ua:
        fields["user_agent"] = ua
    return f"HTTP {bits[0]} {host}{bits[1]}" if host else f"HTTP {line}"


# ------------------------------------------------------------------ TLS
def _tls(payload: memoryview, fields: dict[str, str]) -> str:
    """ClientHello SNI (and the handshake type otherwise). The SNI is the only readable identity in
    an encrypted flow, which is exactly why a capture is opened."""
    n = len(payload)
    if n < 6 or payload[0] != 0x16 or payload[1] != 0x03:
        return ""
    fields["tls_record"] = "handshake"
    hs_type = payload[5]
    if hs_type == 0x02:
        fields["tls_handshake"] = "server_hello"
        return "TLS server hello"
    if hs_type != 0x01:
        fields["tls_handshake"] = f"type-{hs_type}"
        return "TLS handshake"
    fields["tls_handshake"] = "client_hello"
    try:
        off = 9                                   # record(5) + handshake header(4)
        if off + 34 > n:
            return "TLS client hello"
        ver = struct.unpack_from("!H", payload, off)[0]
        fields["tls_version"] = {0x0301: "1.0", 0x0302: "1.1", 0x0303: "1.2", 0x0304: "1.3"}.get(ver, hex(ver))
        off += 34                                 # version(2) + random(32)
        off += 1 + payload[off]                   # session id
        if off + 2 > n:
            return "TLS client hello"
        off += 2 + struct.unpack_from("!H", payload, off)[0]   # cipher suites
        if off >= n:
            return "TLS client hello"
        off += 1 + payload[off]                   # compression methods
        if off + 2 > n:
            return "TLS client hello"
        ext_end = min(n, off + 2 + struct.unpack_from("!H", payload, off)[0])
        off += 2
        while off + 4 <= ext_end:
            etype, elen = struct.unpack_from("!HH", payload, off)
            off += 4
            if off + elen > ext_end:
                break
            if etype == 0x0000 and elen >= 5:     # server_name
                # list length(2), type(1), name length(2), name
                nlen = struct.unpack_from("!H", payload, off + 3)[0]
                if off + 5 + nlen <= ext_end:
                    sni = bytes(payload[off + 5: off + 5 + nlen]).decode("utf-8", "replace")
                    if sni:
                        fields["tls_sni"] = sni
                        fields["domain"] = sni
                        return f"TLS client hello {sni}"
            off += elen
    except (struct.error, IndexError):
        pass
    return "TLS client hello"


# ------------------------------------------------------------------ link / network decode
def _link(data: memoryview, linktype: int, fields: dict[str, str]) -> tuple[int, int]:
    """Strip the link layer. Returns (offset of the network header, ethertype-ish protocol).

    The protocol is an ethertype (0x0800 / 0x86dd / 0x0806), or -1 when there is nothing to decode.
    """
    n = len(data)
    if linktype == DLT_EN10MB:
        if n < 14:
            return (n, -1)
        fields["src_mac"] = _mac(data, 6)
        fields["dst_mac"] = _mac(data, 0)
        etype = (data[12] << 8) | data[13]
        off = 14
        hops = 0
        while etype in (0x8100, 0x88A8, 0x9100) and off + 4 <= n and hops < 3:   # VLAN tags
            fields["vlan"] = str(((data[off] << 8) | data[off + 1]) & 0x0FFF)
            etype = (data[off + 2] << 8) | data[off + 3]
            off += 4
            hops += 1
        return (off, etype)
    if linktype in (DLT_NULL, DLT_LOOP):
        if n < 4:
            return (n, -1)
        fam = struct.unpack_from("<I" if linktype == DLT_NULL else ">I", data, 0)[0]
        if fam > 0xFFFF:                          # written in the other byte order
            fam = struct.unpack_from(">I" if linktype == DLT_NULL else "<I", data, 0)[0]
        return (4, 0x0800 if fam == 2 else (0x86DD if fam in (24, 28, 30) else -1))
    if linktype == DLT_LINUX_SLL:
        if n < 16:
            return (n, -1)
        return (16, (data[14] << 8) | data[15])
    if linktype == DLT_LINUX_SLL2:
        if n < 20:
            return (n, -1)
        return (20, (data[0] << 8) | data[1])
    if linktype in (DLT_RAW, DLT_RAW_BSD, DLT_RAW_ALT, DLT_IPV4, DLT_IPV6):
        if n < 1:
            return (n, -1)
        ver = data[0] >> 4
        return (0, 0x0800 if ver == 4 else (0x86DD if ver == 6 else -1))
    return (0, -1)


def _ports_and_payload(data: memoryview, off: int, proto: int, fields: dict[str, str]) -> tuple[str, int, int, memoryview]:
    """Transport header -> (extra summary text, sport, dport, payload)."""
    n = len(data)
    empty = data[n:n]
    if proto == 6:                                # TCP
        if off + 20 > n:
            return ("", 0, 0, empty)
        sport, dport, seq, ack = struct.unpack_from("!HHII", data, off)
        doff = (data[off + 12] >> 4) * 4
        flags = data[off + 13]
        win = struct.unpack_from("!H", data, off + 14)[0]
        fields["tcp_flags"] = _tcp_flags(flags)
        fields["tcp_seq"] = str(seq)
        if flags & 0x10:
            fields["tcp_ack"] = str(ack)
        fields["tcp_window"] = str(win)
        body = data[off + doff: n] if off + doff <= n else empty
        return (f"[{fields['tcp_flags'] or '-'}]", sport, dport, body)
    if proto == 17:                               # UDP
        if off + 8 > n:
            return ("", 0, 0, empty)
        sport, dport, ulen = struct.unpack_from("!HHH", data, off)
        end = min(n, off + max(8, ulen))
        return ("", sport, dport, data[off + 8: end])
    if proto in (1, 58):                          # ICMP / ICMPv6
        if off + 2 > n:
            return ("", 0, 0, empty)
        itype, icode = data[off], data[off + 1]
        names = ICMP_TYPES if proto == 1 else ICMP6_TYPES
        label = names.get(itype, f"type-{itype}")
        fields["icmp_type"] = str(itype)
        fields["icmp_code"] = str(icode)
        return (label, 0, 0, empty)
    return ("", 0, 0, empty)


def _app_layer(sport: int, dport: int, payload: memoryview, fields: dict[str, str]) -> str:
    if not payload:
        return ""
    if sport in DNS_PORTS or dport in DNS_PORTS:
        return _dns(payload, fields)
    if sport in TLS_PORTS or dport in TLS_PORTS:
        return _tls(payload, fields)
    if sport in HTTP_PORTS or dport in HTTP_PORTS:
        return _http(payload, fields)
    # An unusual port is exactly where a decode is worth trying rather than assuming: the sniff is
    # cheap (one byte for TLS, a method token for HTTP) and it is the case an analyst cares about.
    if payload[0] == 0x16 and len(payload) > 5 and payload[1] == 0x03:
        return _tls(payload, fields)
    if bytes(payload[:9]).startswith(HTTP_METHODS):
        return _http(payload, fields)
    return ""


def _decode(data: memoryview, linktype: int, fields: dict[str, str]) -> str:
    """Fill `fields` from one packet's bytes and return the human summary."""
    off, etype = _link(data, linktype, fields)
    n = len(data)
    if etype == 0x0806:                           # ARP
        fields["protocol"] = "ARP"
        if off + 28 <= n:
            op = struct.unpack_from("!H", data, off + 6)[0]
            spa, tpa = _ipv4(data, off + 14), _ipv4(data, off + 24)
            fields["src_ip"], fields["dst_ip"] = spa, tpa
            fields["arp_op"] = "request" if op == 1 else ("reply" if op == 2 else str(op))
            return (f"ARP who-has {tpa} tell {spa}" if op == 1 else f"ARP {spa} is-at {_mac(data, off + 8)}")
        return "ARP"
    if etype == 0x0800:                           # IPv4
        if off + 20 > n:
            fields["protocol"] = "IPv4"
            return "IPv4 (truncated header)"
        ihl = (data[off] & 0x0F) * 4
        total_len = struct.unpack_from("!H", data, off + 2)[0]
        frag = struct.unpack_from("!H", data, off + 6)[0]
        proto = data[off + 9]
        src, dst = _ipv4(data, off + 12), _ipv4(data, off + 16)
        fields["ip_version"] = "4"
        fields["src_ip"], fields["dst_ip"] = src, dst
        fields["ttl"] = str(data[off + 8])
        fields["ip_len"] = str(total_len)
        name = IP_PROTOS.get(proto, f"ip-proto-{proto}")
        fields["protocol"] = name
        if frag & 0x1FFF:                         # a non-first fragment has no transport header
            fields["ip_fragment"] = str((frag & 0x1FFF) * 8)
            return f"{name} {src} > {dst} (fragment offset {(frag & 0x1FFF) * 8})"
        extra, sport, dport, payload = _ports_and_payload(data, off + ihl, proto, fields)
        return _summarise(name, src, dst, sport, dport, extra, payload, fields)
    if etype == 0x86DD:                           # IPv6
        if off + 40 > n:
            fields["protocol"] = "IPv6"
            return "IPv6 (truncated header)"
        plen = struct.unpack_from("!H", data, off + 4)[0]
        nxt = data[off + 6]
        src, dst = _ipv6(bytes(data[off + 8: off + 24])), _ipv6(bytes(data[off + 24: off + 40]))
        fields["ip_version"] = "6"
        fields["src_ip"], fields["dst_ip"] = src, dst
        fields["ttl"] = str(data[off + 7])
        fields["ip_len"] = str(plen)
        cur = off + 40
        hops = 0
        while nxt in _V6_EXT_SKIP and cur + 2 <= n and hops < 8:
            length = (data[cur + 1] + 1) * 8
            nxt = data[cur]
            cur += length
            hops += 1
        if nxt == 44 and cur + 8 <= n:            # fragment header: no ports past the first fragment
            nxt = data[cur]
            cur += 8
        name = IP_PROTOS.get(nxt, f"ip-proto-{nxt}")
        fields["protocol"] = name
        extra, sport, dport, payload = _ports_and_payload(data, cur, nxt, fields)
        return _summarise(name, src, dst, sport, dport, extra, payload, fields)
    link_name = LINK_NAMES.get(linktype, f"linktype-{linktype}")
    if etype >= 0:
        fields["ethertype"] = f"0x{etype:04x}"
        fields["protocol"] = f"ethertype-0x{etype:04x}"
        return f"{link_name} frame, ethertype 0x{etype:04x} (not decoded)"
    fields["protocol"] = link_name
    return f"{link_name} frame ({n} bytes, not decoded)"


def _summarise(proto: str, src: str, dst: str, sport: int, dport: int, extra: str,
               payload: memoryview, fields: dict[str, str]) -> str:
    if sport:
        fields["src_port"] = str(sport)
    if dport:
        fields["dst_port"] = str(dport)
    app = _app_layer(sport, dport, payload, fields) if payload else ""
    left = f"{src}:{sport}" if sport else src
    right = f"{dst}:{dport}" if dport else dst
    parts = [proto, left, ">", right]
    if extra:
        parts.append(extra)
    if payload is not None and len(payload):
        # In fields as well as in the message: a rule about cleartext protocols has to tell a bare SYN
        # from a packet actually carrying credentials, and "len=" inside a sentence is not a field.
        fields["payload_len"] = str(len(payload))
        parts.append(f"len={len(payload)}")
    if app:
        parts.append("·")
        parts.append(app)
    return " ".join(parts)


# ------------------------------------------------------------------ container readers
def _iter_pcap(data: bytes) -> Iterator[tuple[float, int, memoryview, int]]:
    """(timestamp, linktype, packet bytes, original length) from a classic libpcap file."""
    magic = data[:4]
    if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
        endian = "<"
    elif magic in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE):
        endian = ">"
    else:
        raise PcapError("not a libpcap file")
    nanos = magic in (PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE)
    if len(data) < 24:
        raise PcapError("the file header is truncated — this capture holds no complete packets")
    linktype = struct.unpack_from(endian + "I", data, 20)[0] & 0x0FFFFFFF
    rec = struct.Struct(endian + "IIII")
    mv = memoryview(data)
    off = 24
    total = len(data)
    div = 1e9 if nanos else 1e6
    while off + 16 <= total:
        ts_sec, ts_frac, incl, orig = rec.unpack_from(data, off)
        off += 16
        if incl > total - off:
            incl = total - off                    # truncated final packet: keep what is there
            if incl <= 0:
                break
            yield (ts_sec + ts_frac / div, linktype, mv[off: off + incl], orig)
            break
        yield (ts_sec + ts_frac / div, linktype, mv[off: off + incl], orig)
        off += incl


def _pcapng_options(body: memoryview, off: int, endian: str) -> dict[int, bytes]:
    out: dict[int, bytes] = {}
    n = len(body)
    hdr = struct.Struct(endian + "HH")
    while off + 4 <= n:
        code, length = hdr.unpack_from(body, off)
        off += 4
        if code == 0 or off + length > n:
            break
        out[code] = bytes(body[off: off + length])
        off += (length + 3) & ~3
    return out


def _iter_pcapng(data: bytes) -> Iterator[tuple[float, int, memoryview, int]]:
    mv = memoryview(data)
    total = len(data)
    off = 0
    endian = "<"
    ifaces: list[tuple[int, float]] = []          # (linktype, timestamp resolution divisor)
    saw_shb = False
    while off + 12 <= total:
        if off + 8 > total:
            break
        # Every block starts with its type and total length, both in the SECTION's byte order. A new
        # section can flip that order mid-file (concatenated captures do exactly this).
        btype = struct.unpack_from(endian + "I", data, off)[0]
        if btype == _SHB or struct.unpack_from(">I", data, off)[0] == _SHB:
            if off + 12 > total:
                break
            bom = data[off + 8: off + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else (">" if bom == b"\x1a\x2b\x3c\x4d" else endian)
            btype = _SHB
            saw_shb = True
            ifaces = []
        blen = struct.unpack_from(endian + "I", data, off + 4)[0]
        if blen < 12 or off + blen > total:
            if not saw_shb:
                raise PcapError("not a pcapng file")
            break                                  # truncated tail: stop, keep everything before it
        body = mv[off + 8: off + blen - 4]
        if btype == _IDB and len(body) >= 8:
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            opts = _pcapng_options(body, 8, endian)
            div = 1e6
            res = opts.get(9)
            if res:
                r = res[0]
                div = float(2 ** (r & 0x7F)) if r & 0x80 else float(10 ** (r & 0x7F))
            ifaces.append((linktype, div))
        elif btype == _EPB and len(body) >= 20:
            iface, ts_hi, ts_lo, caplen, origlen = struct.unpack_from(endian + "IIIII", body, 0)
            link, div = ifaces[iface] if iface < len(ifaces) else (DLT_EN10MB, 1e6)
            pkt = body[20: 20 + min(caplen, len(body) - 20)]
            yield ((((ts_hi << 32) | ts_lo) / div), link, pkt, origlen)
        elif btype == _SPB and len(body) >= 4:
            origlen = struct.unpack_from(endian + "I", body, 0)[0]
            link, _div = ifaces[0] if ifaces else (DLT_EN10MB, 1e6)
            yield (0.0, link, body[4: 4 + min(origlen, len(body) - 4)], origlen)
        elif btype == _PB and len(body) >= 20:
            iface, _drops, ts_hi, ts_lo, caplen, origlen = struct.unpack_from(endian + "HHIIII", body, 0)
            link, div = ifaces[iface] if iface < len(ifaces) else (DLT_EN10MB, 1e6)
            yield ((((ts_hi << 32) | ts_lo) / div), link, body[20: 20 + min(caplen, len(body) - 20)], origlen)
        off += blen
    if not saw_shb:
        raise PcapError("not a pcapng file")


def looks_like_capture(head: bytes) -> bool:
    return head[:4] in MAGICS


# ------------------------------------------------------------------ the parser
class PcapParser(BaseParser):
    """One event per packet. Binary: there is no raw text phase (see Store._raw_first_ok)."""

    name = "packet capture"
    family = "network.pcap"
    binary = True
    extensions = EXTENSIONS

    def sniff(self, sample: list[str], filename: str = "", head: bytes = b"") -> float:
        if looks_like_capture(head):
            return 1.0
        if filename.lower().endswith(EXTENSIONS):
            return 0.6
        return 0.0

    def parse(self, lines: Iterable[str]) -> Iterator[ParsedEvent]:
        # A capture has no text form. Reaching here means something fed us decoded lines, which for a
        # binary container is always a routing mistake — say so rather than emitting nothing.
        yield ParsedEvent(raw="", msg="a packet capture must be read as bytes, not as text lines",
                          fields={"parse_error": "not-text"})

    def parse_bytes(self, data: bytes) -> Iterator[ParsedEvent]:
        head = data[:4]
        try:
            if head == PCAPNG_MAGIC:
                packets = _iter_pcapng(data)
            elif head in MAGICS:
                packets = _iter_pcap(data)
            else:
                yield ParsedEvent(
                    raw="", fields={"parse_error": "not-a-capture"},
                    msg=("this file is named like a packet capture but does not start with a libpcap or "
                         "pcapng magic number, so there is nothing to decode. If it came out of a tool "
                         "that wraps captures (a .zip, a .gz), upload that container and Iris will expand it."))
                return
        except PcapError as exc:
            yield ParsedEvent(raw="", msg=f"packet capture unreadable: {exc}", fields={"parse_error": "container"})
            return
        yield from self._events(packets)

    def _events(self, packets: Iterator[tuple[float, int, memoryview, int]]) -> Iterator[ParsedEvent]:
        frame = 0
        for ts_epoch, linktype, pkt, origlen in packets:
            frame += 1
            fields: dict[str, str] = {"frame": str(frame), "cap_len": str(len(pkt)),
                                      "frame_len": str(origlen or len(pkt)),
                                      "link_type": LINK_NAMES.get(linktype, str(linktype))}
            try:
                summary = _decode(pkt, linktype, fields)
            except (struct.error, IndexError, ValueError, UnicodeError) as exc:
                # One malformed packet must not end the capture: a truncated tail is normal evidence.
                fields["parse_error"] = type(exc).__name__
                summary = f"undecodable packet ({len(pkt)} bytes captured)"
            ts = _ts(ts_epoch) if ts_epoch else None
            when = ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" if ts else ""
            raw = f"{when} #{frame} {summary}".strip()
            # `host` is deliberately EMPTY: it means the machine that WROTE the log line, and a capture
            # has no such host — the source IP is a party to the packet, not its author. It is in
            # fields (and therefore in the entity graph) where it belongs.
            yield ParsedEvent(raw=raw, msg=summary, ts=ts, fields=fields)
