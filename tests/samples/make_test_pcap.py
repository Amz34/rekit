#!/usr/bin/env python3
"""Build a small deterministic test PCAP (DNS + HTTP) with the standard library only.

No scapy, no dpkt: frames are assembled with `struct` and written to a classic
libpcap file, so the fixture regenerates on any machine with plain CPython.

    python3 make_test_pcap.py [out.pcap]
"""
from __future__ import annotations

import socket
import struct
import sys

CLIENT, GATEWAY, SERVER = "10.0.0.5", "10.0.0.1", "93.184.216.34"
CMAC = bytes.fromhex("020000000005")
GMAC = bytes.fromhex("020000000001")
SMAC = bytes.fromhex("0200000093e1")


def eth(dst: bytes, src: bytes, ethertype: int, payload: bytes) -> bytes:
    return dst + src + struct.pack("!H", ethertype) + payload


def _csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int) -> bytes:
    hdr = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    hdr = hdr[:10] + struct.pack("!H", _csum(hdr)) + hdr[12:]
    return hdr + payload


def _l4_csum(src: str, dst: str, proto: int, seg: bytes) -> int:
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, proto, len(seg))
    return _csum(pseudo + seg)


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    chk = _l4_csum(src, dst, 17, seg)
    return seg[:6] + struct.pack("!H", chk or 0xFFFF) + seg[8:]


def tcp(src: str, dst: str, sport: int, dport: int, flags: int, seq: int,
        ack: int, payload: bytes = b"") -> bytes:
    # data offset (5 x 32-bit words) lives in the high nibble of byte 12
    offset_flags = ((5 << 12) | flags) & 0xFFFF
    seg = struct.pack("!HHIIHHHH", sport, dport, seq, ack, offset_flags, 8192, 0, 0) + payload
    chk = _l4_csum(src, dst, 6, seg)
    return seg[:16] + struct.pack("!H", chk) + seg[18:]


def _qname(name: str) -> bytes:
    return b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"


def dns_query(ident: int, name: str) -> bytes:
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + _qname(name) + struct.pack("!HH", 1, 1)


def dns_response(ident: int, name: str, addr: str) -> bytes:
    body = _qname(name) + struct.pack("!HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton(addr)
    return struct.pack("!HHHHHH", ident, 0x8180, 1, 1, 0, 0) + body + answer


def tls_client_hello(sni: str) -> bytes:
    """A minimal but structurally valid TLS 1.2 ClientHello carrying SNI."""
    ext_sni = struct.pack("!HH", 0, len(sni) + 5) + struct.pack("!HBH", len(sni) + 3, 0, len(sni)) + sni.encode()
    body = (b"\x03\x03" + bytes(range(32))                      # version + random
            + b"\x00"                                            # empty session id
            + struct.pack("!H", 2) + b"\x00\x2f"                 # cipher TLS_RSA_WITH_AES_128_CBC_SHA
            + b"\x01\x00"                                        # compression: null
            + struct.pack("!H", len(ext_sni)) + ext_sni)         # extensions
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def frames() -> list[bytes]:
    http_get = (b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
                b"User-Agent: rekit-test\r\n\r\n")
    http_ok = (b"HTTP/1.1 200 OK\r\nServer: nginx\r\n"
               b"Content-Type: text/html\r\n\r\nok")
    # sequence numbers are kept consistent so tshark reassembles both streams
    get_seq, ok_seq = 101, 501
    get_end, ok_end = get_seq + len(http_get), ok_seq + len(http_ok)
    tls_hello = tls_client_hello("example.com")
    return [
        eth(GMAC, CMAC, 0x0800, ipv4(CLIENT, GATEWAY, 17, udp(CLIENT, GATEWAY, 41234, 53, dns_query(1, "example.com")), 1)),
        eth(CMAC, GMAC, 0x0800, ipv4(GATEWAY, CLIENT, 17, udp(GATEWAY, CLIENT, 53, 41234, dns_response(1, "example.com", SERVER)), 2)),
        eth(SMAC, CMAC, 0x0800, ipv4(CLIENT, SERVER, 6, tcp(CLIENT, SERVER, 41235, 80, 0x02, get_seq - 1, 0), 3)),
        eth(CMAC, SMAC, 0x0800, ipv4(SERVER, CLIENT, 6, tcp(SERVER, CLIENT, 80, 41235, 0x12, ok_seq - 1, get_seq), 4)),
        eth(SMAC, CMAC, 0x0800, ipv4(CLIENT, SERVER, 6, tcp(CLIENT, SERVER, 41235, 80, 0x18, get_seq, ok_seq, http_get), 5)),
        eth(CMAC, SMAC, 0x0800, ipv4(SERVER, CLIENT, 6, tcp(SERVER, CLIENT, 80, 41235, 0x18, ok_seq, get_end, http_ok), 6)),
        eth(SMAC, CMAC, 0x0800, ipv4(CLIENT, SERVER, 6, tcp(CLIENT, SERVER, 41236, 443, 0x18, 700, 1, tls_hello), 7)),
    ]


def write_pcap(path: str, packets: list[bytes]) -> None:
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, pkt in enumerate(packets):
            fh.write(struct.pack("<IIII", 1750000000 + i, i * 1000, len(pkt), len(pkt)))
            fh.write(pkt)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "test.pcap"
    pkts = frames()
    write_pcap(out, pkts)
    print(f"wrote {out}: {len(pkts)} packets")
