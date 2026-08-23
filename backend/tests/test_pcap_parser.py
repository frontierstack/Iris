"""Packet capture parsing: pcap + pcapng, the five-tuple, and the application-layer facts.

Captures are synthesised here byte by byte rather than committed as fixtures: a .pcap in the repo is
opaque to review, and the point of these tests is that the header arithmetic is right — which is only
legible when the bytes are built next to the assertion.
"""
from __future__ import annotations

import struct

import pytest

from app.parsers.pcap import PcapParser
from app.parsers.registry import binary_hint, fingerprint, parser_by_name


# --------------------------------------------------------------------- builders
def eth(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66", etype=0x0800) -> bytes:
    mac = lambda s: bytes(int(x, 16) for x in s.split(":"))
    return mac(dst) + mac(src) + struct.pack("!H", etype)


def ipv4(payload: bytes, proto: int, src="10.0.0.5", dst="93.184.216.34", ttl=64) -> bytes:
    ip = lambda s: bytes(int(x) for x in s.split("."))
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, total, 0x1234, 0, ttl, proto, 0) + ip(src) + ip(dst)
    return hdr + payload


def ipv6(payload: bytes, nxt: int, src=b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x01",
         dst=b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x02") -> bytes:
    return struct.pack("!IHBB", 0x60000000, len(payload), nxt, 64) + src + dst + payload


def tcp(payload: bytes, sport=52344, dport=443, flags=0x18) -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, 1000, 2000, 0x50, flags, 8192, 0, 0) + payload


def udp(payload: bytes, sport=51000, dport=53) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def pcap_file(packets: list[bytes], linktype=1, ts=1_700_000_000) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for i, p in enumerate(packets):
        out += struct.pack("<IIII", ts + i, 500_000, len(p), len(p)) + p
    return out


def pcapng_file(packets: list[bytes], linktype=1, ts_us=1_700_000_000_000_000) -> bytes:
    def block(btype: int, body: bytes) -> bytes:
        pad = (-len(body)) % 4
        total = 12 + len(body) + pad
        return struct.pack("<II", btype, total) + body + b"\x00" * pad + struct.pack("<I", total)

    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(0x00000001, struct.pack("<HHI", linktype, 0, 65535))
    for p in packets:
        body = struct.pack("<IIIII", 0, ts_us >> 32, ts_us & 0xFFFFFFFF, len(p), len(p)) + p
        out += block(0x00000006, body)
    return out


def dns_query(name="example.com", qtype=1) -> bytes:
    q = b"".join(bytes([len(lbl)]) + lbl.encode() for lbl in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)


def dns_response(name="example.com", ip="93.184.216.34") -> bytes:
    q = b"".join(bytes([len(lbl)]) + lbl.encode() for lbl in name.split(".")) + b"\x00"
    head = struct.pack("!HHHHHH", 0xABCD, 0x8180, 1, 1, 0, 0) + q + struct.pack("!HH", 1, 1)
    rdata = bytes(int(x) for x in ip.split("."))
    return head + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + rdata


def client_hello(sni="malicious.example.net") -> bytes:
    host = sni.encode()
    ext = struct.pack("!HHHBH", 0x0000, len(host) + 5, len(host) + 3, 0, len(host)) + host
    body = (struct.pack("!H", 0x0303) + b"\x11" * 32 + b"\x00"           # version, random, no session id
            + struct.pack("!H", 2) + b"\x13\x01"                          # cipher suites
            + b"\x01\x00"                                                 # compression
            + struct.pack("!H", len(ext)) + ext)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def events(data: bytes) -> list:
    return list(PcapParser().parse_bytes(data))


# --------------------------------------------------------------------- routing
def test_a_capture_is_routed_by_its_magic_not_its_name():
    cap = pcap_file([eth() + ipv4(tcp(b""), 6)])
    assert isinstance(binary_hint("evidence.bin", cap), PcapParser)
    assert isinstance(binary_hint("capture.pcapng", pcapng_file([eth() + ipv4(tcp(b""), 6)])), PcapParser)
    fp = fingerprint("evidence.bin", cap)
    assert fp.parser.name == "packet capture"
    assert fp.state == "READY"


def test_the_parser_survives_the_pool_cache_round_trip():
    # pool_store restores a source by parser NAME without re-sniffing the file.
    p = parser_by_name("packet capture")
    assert p is not None and isinstance(p, PcapParser)


def test_a_file_named_pcap_that_is_not_one_says_so_instead_of_dumping_strings():
    p = binary_hint("bogus.pcap", b"this is just text, honest\n" * 10)
    assert isinstance(p, PcapParser)
    out = events(b"this is just text, honest\n" * 10)
    assert len(out) == 1
    assert out[0].fields["parse_error"] == "not-a-capture"
    assert "magic" in out[0].msg


# --------------------------------------------------------------------- decoding
def test_one_packet_becomes_one_event_with_the_five_tuple():
    out = events(pcap_file([eth() + ipv4(tcp(b"", flags=0x02), 6)]))
    assert len(out) == 1
    f = out[0].fields
    assert (f["src_ip"], f["dst_ip"]) == ("10.0.0.5", "93.184.216.34")
    assert (f["src_port"], f["dst_port"]) == ("52344", "443")
    assert f["protocol"] == "TCP"
    assert f["tcp_flags"] == "SYN"
    assert f["ttl"] == "64"
    assert out[0].ts is not None and out[0].ts.year == 2023
    assert "10.0.0.5:52344" in out[0].raw


def test_pcapng_reads_the_same_packets_as_pcap():
    pkt = eth() + ipv4(tcp(b"", flags=0x02), 6)
    a = events(pcap_file([pkt]))[0]
    b = events(pcapng_file([pkt]))[0]
    assert a.fields["src_ip"] == b.fields["src_ip"]
    assert a.fields["tcp_flags"] == b.fields["tcp_flags"]
    assert a.msg == b.msg
    assert b.ts is not None


def test_a_big_endian_capture_reads_identically():
    pkt = eth() + ipv4(tcp(b""), 6)
    le = pcap_file([pkt])
    be = struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + struct.pack(">IIII", 1_700_000_000, 500_000, len(pkt), len(pkt)) + pkt
    assert events(be)[0].fields == events(le)[0].fields


def test_ipv6_and_icmp_are_decoded():
    out = events(pcap_file([eth(etype=0x86DD) + ipv6(tcp(b"", dport=80), 6)]))
    f = out[0].fields
    assert f["ip_version"] == "6"
    assert f["src_ip"] == "2001:db8::1"
    assert f["dst_port"] == "80"
    icmp = events(pcap_file([eth() + ipv4(b"\x08\x00\x00\x00", 1)]))[0]
    assert icmp.fields["protocol"] == "ICMP"
    assert "echo-request" in icmp.msg


def test_arp_names_both_parties():
    body = (struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + bytes(range(6)) + bytes([10, 0, 0, 5])
            + b"\x00" * 6 + bytes([10, 0, 0, 1]))
    out = events(pcap_file([eth(etype=0x0806) + body]))[0]
    assert out.fields["src_ip"] == "10.0.0.5" and out.fields["dst_ip"] == "10.0.0.1"
    assert "who-has 10.0.0.1" in out.msg


def test_vlan_tags_are_stripped_and_recorded():
    frame = eth(etype=0x8100) + struct.pack("!HH", 0x0064, 0x0800) + ipv4(tcp(b""), 6)
    f = events(pcap_file([frame]))[0].fields
    assert f["vlan"] == "100"
    assert f["src_ip"] == "10.0.0.5"


def test_linux_cooked_capture_still_reaches_the_ip_header():
    sll = struct.pack("!HHH", 0, 1, 6) + b"\x00" * 8 + struct.pack("!H", 0x0800)
    f = events(pcap_file([sll + ipv4(udp(dns_query()), 17)], linktype=113))[0].fields
    assert f["src_ip"] == "10.0.0.5"
    assert f["dns_query"] == "example.com"


# --------------------------------------------------------------------- application layer
def test_dns_question_and_answers_are_extracted():
    q = events(pcap_file([eth() + ipv4(udp(dns_query("evil.example.org", 28)), 17)]))[0]
    assert q.fields["dns_query"] == "evil.example.org"
    assert q.fields["dns_qtype"] == "AAAA"
    assert q.fields["dns_qr"] == "query"

    r = events(pcap_file([eth() + ipv4(udp(dns_response(), sport=53, dport=51000), 17)]))[0]
    assert r.fields["dns_query"] == "example.com"
    assert r.fields["dns_answers"] == "93.184.216.34"
    assert r.fields["dns_rcode"] == "NOERROR"
    assert "93.184.216.34" in r.msg


def test_http_request_carries_host_method_and_url():
    req = b"GET /admin/config.php HTTP/1.1\r\nHost: intranet.corp\r\nUser-Agent: sqlmap/1.7\r\n\r\n"
    f = events(pcap_file([eth() + ipv4(tcp(req, dport=80), 6)]))[0].fields
    assert f["http_method"] == "GET"
    assert f["http_host"] == "intranet.corp"
    assert f["url"] == "http://intranet.corp/admin/config.php"
    assert f["user_agent"] == "sqlmap/1.7"


def test_tls_client_hello_yields_the_sni():
    out = events(pcap_file([eth() + ipv4(tcp(client_hello()), 6)]))[0]
    assert out.fields["tls_sni"] == "malicious.example.net"
    assert out.fields["domain"] == "malicious.example.net"
    assert out.fields["tls_version"] == "1.2"
    assert "malicious.example.net" in out.msg


def test_an_encrypted_flow_on_a_nonstandard_port_is_still_recognised():
    out = events(pcap_file([eth() + ipv4(tcp(client_hello("c2.example.io"), dport=4444), 6)]))[0]
    assert out.fields["tls_sni"] == "c2.example.io"


# --------------------------------------------------------------------- robustness
def test_a_truncated_capture_keeps_every_packet_before_the_cut():
    good = pcap_file([eth() + ipv4(tcp(b""), 6)] * 3)
    out = events(good[:-20])          # cut into the middle of the last packet
    assert len(out) == 3              # the partial packet is kept, not silently dropped
    assert out[-1].fields.get("src_ip") == "10.0.0.5" or "parse_error" in out[-1].fields


def test_a_malformed_packet_does_not_end_the_file():
    packets = [eth() + ipv4(tcp(b""), 6), eth() + b"\x45", eth() + ipv4(tcp(b""), 6)]
    out = events(pcap_file(packets))
    assert len(out) == 3
    assert out[1].fields["protocol"] == "IPv4"        # named, not dropped
    assert out[2].fields["src_ip"] == "10.0.0.5"


def test_a_dns_pointer_loop_cannot_hang_the_parse():
    # A name whose compression pointer points at itself: the decoder must refuse to follow it.
    bad = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack("!HH", 1, 1)
    out = events(pcap_file([eth() + ipv4(udp(bad), 17)]))
    assert len(out) == 1              # returned at all: no loop


def test_an_undecoded_link_type_says_so_rather_than_looking_empty():
    out = events(pcap_file([b"\x00" * 40], linktype=105))[0]
    assert "ieee802.11" in out.msg
    assert "not decoded" in out.msg


@pytest.mark.parametrize("n", [1, 5, 50])
def test_every_packet_produces_exactly_one_event(n):
    assert len(events(pcap_file([eth() + ipv4(tcp(b""), 6)] * n))) == n
