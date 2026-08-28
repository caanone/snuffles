#!/usr/bin/env python3
"""
make-corpus.py — build /opt/gen/corpus.pcap for the snuffles load-test rig.

Produces ~20k Ethernet frames spanning many protocols so that tcpreplay
(replay.sh) drives a realistic protocol mix through the bridge and snuffles'
dissector sees DNS/HTTP/TLS/DHCP/mDNS/NTP/QUIC/ICMP/ICMPv6/IPv6-ext-headers/
ARP/802.1Q/IPv4-fragments/SCTP.

L2 is ALWAYS unicast gen-MAC -> sink-MAC (even for frames whose L3 is normally
broadcast/multicast, e.g. DHCP/mDNS/ARP) so the SUT bridge FORWARDS the frame
to the sink port and never floods it out every port. The L3/L4 content is the
real protocol so the dissector still classifies it correctly.

Sizes span 60..1514 bytes on the wire (frames below 60 are padded with a
trailing Ethernet pad; larger sizes come from genuine L4 payloads plus, where
needed, a trailing pad). Nothing exceeds 1514 (standard-MTU corpus).

Usage:
  make-corpus.py [OUT] [--count N] [--gen-mac M] [--sink-mac M]
Defaults: OUT=/opt/gen/corpus.pcap  N=20000
          gen-mac=02:53:4e:46:01:01  sink-mac=02:53:4e:46:00:05
"""
import argparse
import os
import random
import struct
import sys
import time

# Keep scapy quiet and fast.
os.environ.setdefault("SCAPY_USE_PCAPDNET", "0")
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import (  # noqa: E402
    Ether, Dot1Q, ARP, IP, IPv6, TCP, UDP, ICMP, Raw,
    DNS, DNSQR, DNSRR, BOOTP, DHCP, fragment,
)
from scapy.layers.inet6 import (  # noqa: E402
    ICMPv6EchoRequest, ICMPv6EchoReply,
    IPv6ExtHdrHopByHop, IPv6ExtHdrFragment,
)
from scapy.layers.ntp import NTP  # noqa: E402
from scapy.layers.sctp import (  # noqa: E402
    SCTP, SCTPChunkInit, SCTPChunkInitAck, SCTPChunkParamStateCookie,
)

WIRE_MAX = 1514
WIRE_MIN = 60

RND = random.Random(0xC0FFEE)  # deterministic corpus


# ---------------------------------------------------------------------------
# frame finalisation: high-level pkt -> raw bytes, padded to a target size.
# Padding is appended AFTER scapy has computed the real IP/UDP/TCP lengths and
# checksums, so the pad falls outside the IP total-length and is pure Ethernet
# padding (dissectors still parse L3/L4 correctly and see the frame length).
# ---------------------------------------------------------------------------
def finalize(pkt, target=None):
    raw = bytes(pkt)
    if target is None:
        target = len(raw)
    if target < WIRE_MIN:
        target = WIRE_MIN
    if target > WIRE_MAX:
        target = WIRE_MAX
    if len(raw) > WIRE_MAX:
        # should not happen: builders keep base frames small; never truncate
        # into a header, just accept the natural (already <=1514) size.
        return raw
    if len(raw) < target:
        raw = raw + bytes(target - len(raw))
    return raw


def l2(dst, src):
    return Ether(dst=dst, src=src)


# ---------------------------------------------------------------------------
# hand-crafted TLS ClientHello (record + handshake) with an SNI extension.
# ---------------------------------------------------------------------------
def tls_client_hello_bytes(sni, extra_pad=0):
    rnd = bytes(RND.randrange(256) for _ in range(32))
    sid = b""
    suites = struct.pack(
        ">6H",
        0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0x009C,
    )
    comp = b"\x01\x00"  # len 1, null compression
    host = sni.encode()
    sni_list = b"\x00" + struct.pack(">H", len(host)) + host  # type host_name
    sni_ext_body = struct.pack(">H", len(sni_list)) + sni_list
    ext_sni = b"\x00\x00" + struct.pack(">H", len(sni_ext_body)) + sni_ext_body
    # supported_versions ext (TLS1.3+1.2)
    ext_vers = b"\x00\x2b" + b"\x00\x05" + b"\x04\x03\x04\x03\x03"
    exts = ext_sni + ext_vers
    if extra_pad > 0:
        # RFC 7685 client-hello padding extension (type 21)
        exts += b"\x00\x15" + struct.pack(">H", extra_pad) + bytes(extra_pad)
    body = (
        b"\x03\x03"                      # client version TLS1.2
        + rnd
        + struct.pack("B", len(sid)) + sid
        + struct.pack(">H", len(suites)) + suites
        + comp
        + struct.pack(">H", len(exts)) + exts
    )
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body  # type client_hello
    rec = b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs  # handshake, TLS1.0
    return rec


# ---------------------------------------------------------------------------
# hand-crafted QUIC v1 Initial (long header).
# ---------------------------------------------------------------------------
def quic_initial_bytes(payload_len=200):
    dcid = bytes(RND.randrange(256) for _ in range(8))
    scid = bytes(RND.randrange(256) for _ in range(8))
    first = 0xC0 | 0x03            # long header, fixed bit, type Initial, pnlen 4
    version = struct.pack(">I", 0x00000001)
    token_len = b"\x00"            # varint 0
    pn = struct.pack(">I", RND.randrange(1 << 16))
    payload = bytes(RND.randrange(256) for _ in range(payload_len))
    length_field = len(pn) + len(payload)
    # varint (2-byte form, 0x40 prefix) covers up to 16383
    length_varint = struct.pack(">H", 0x4000 | (length_field & 0x3FFF))
    return (
        struct.pack("B", first)
        + version
        + struct.pack("B", len(dcid)) + dcid
        + struct.pack("B", len(scid)) + scid
        + token_len
        + length_varint
        + pn
        + payload
    )


# ---------------------------------------------------------------------------
# per-protocol builders. Each returns a list of finalized raw frames.
# `size` is a requested wire size hint used to spread the distribution.
# ---------------------------------------------------------------------------
def b_dns_a(gm, sm, size):
    q = RND.choice(["example.com", "api.snuffles.test", "cdn.assets.example",
                    "www.debian.org", "mail.erkanbircan.com"])
    cid = RND.randrange(1 << 16)
    sport = RND.randrange(1024, 65535)
    qry = (l2(sm, gm) / IP(src="10.77.0.11", dst="10.77.0.53")
           / UDP(sport=sport, dport=53)
           / DNS(id=cid, rd=1, qd=DNSQR(qname=q, qtype="A")))
    ans = (l2(gm, sm) / IP(src="10.77.0.53", dst="10.77.0.11")
           / UDP(sport=53, dport=sport)
           / DNS(id=cid, qr=1, rd=1, ra=1,
                 qd=DNSQR(qname=q, qtype="A"),
                 an=DNSRR(rrname=q, type="A", ttl=300,
                          rdata="10.77.0.%d" % RND.randrange(2, 250))))
    return [finalize(qry, max(WIRE_MIN, size)), finalize(ans, size)]


def b_dns_aaaa(gm, sm, size):
    q = "ipv6." + RND.choice(["example.com", "svc.internal", "node.cluster"])
    cid = RND.randrange(1 << 16)
    sport = RND.randrange(1024, 65535)
    qry = (l2(sm, gm) / IP(src="10.77.0.12", dst="10.77.0.53")
           / UDP(sport=sport, dport=53)
           / DNS(id=cid, rd=1, qd=DNSQR(qname=q, qtype="AAAA")))
    ans = (l2(gm, sm) / IP(src="10.77.0.53", dst="10.77.0.12")
           / UDP(sport=53, dport=sport)
           / DNS(id=cid, qr=1, rd=1, ra=1,
                 qd=DNSQR(qname=q, qtype="AAAA"),
                 an=DNSRR(rrname=q, type="AAAA", ttl=120,
                          rdata="2001:db8::%x" % RND.randrange(1, 0xffff))))
    return [finalize(qry, WIRE_MIN), finalize(ans, size)]


def b_dns_txt(gm, sm, size):
    q = "_dmarc." + RND.choice(["example.com", "mail.test"])
    cid = RND.randrange(1 << 16)
    sport = RND.randrange(1024, 65535)
    txt = "v=spf1 include:_spf.%s ~all " % q + "x" * max(0, (size // 4))
    txt = txt[:255]
    qry = (l2(sm, gm) / IP(src="10.77.0.13", dst="10.77.0.53")
           / UDP(sport=sport, dport=53)
           / DNS(id=cid, rd=1, qd=DNSQR(qname=q, qtype="TXT")))
    ans = (l2(gm, sm) / IP(src="10.77.0.53", dst="10.77.0.13")
           / UDP(sport=53, dport=sport)
           / DNS(id=cid, qr=1, rd=1, ra=1,
                 qd=DNSQR(qname=q, qtype="TXT"),
                 an=DNSRR(rrname=q, type="TXT", ttl=60, rdata=txt)))
    return [finalize(qry, WIRE_MIN), finalize(ans, size)]


def b_http(gm, sm, size):
    host = RND.choice(["example.com", "10.77.0.5", "assets.test"])
    path = RND.choice(["/", "/index.html", "/api/v1/status", "/big"])
    sport = RND.randrange(1024, 65535)
    seq = RND.randrange(1 << 30)
    req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: snuffles-loadtest/1.0\r\n"
           "Accept: */*\r\nConnection: keep-alive\r\n\r\n" % (path, host))
    get = (l2(sm, gm) / IP(src="10.77.0.11", dst="10.77.0.5")
           / TCP(sport=sport, dport=80, flags="PA", seq=seq, ack=1)
           / Raw(load=req.encode()))
    body_len = max(0, size - 160)  # leave room for eth/ip/tcp + resp headers
    body = ("X" * body_len)
    resp = ("HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/plain\r\n"
            "Content-Length: %d\r\nConnection: keep-alive\r\n\r\n%s"
            % (len(body), body))
    ok = (l2(gm, sm) / IP(src="10.77.0.5", dst="10.77.0.11")
          / TCP(sport=80, dport=sport, flags="PA", seq=1, ack=seq + len(req))
          / Raw(load=resp.encode()))
    return [finalize(get, WIRE_MIN), finalize(ok, size)]


def b_tls(gm, sm, size):
    sni = RND.choice(["www.example.com", "api.snuffles.test",
                      "secure.bank.test", "cdn.jsdelivr.net"])
    sport = RND.randrange(1024, 65535)
    pad = max(0, min(size - 170, 1200))  # room for eth/ip/tcp + record/hs hdrs
    ch = tls_client_hello_bytes(sni, extra_pad=pad)
    pkt = (l2(sm, gm) / IP(src="10.77.0.12", dst="10.77.0.5")
           / TCP(sport=sport, dport=443, flags="PA",
                 seq=RND.randrange(1 << 30), ack=1)
           / Raw(load=ch))
    return [finalize(pkt, WIRE_MIN)]


def b_dhcp(gm, sm, size):
    xid = RND.randrange(1 << 32)
    chaddr = bytes(RND.randrange(256) for _ in range(6))
    disc = (l2(sm, gm) / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(op=1, xid=xid, chaddr=chaddr)
            / DHCP(options=[("message-type", "discover"),
                            ("param_req_list", [1, 3, 6, 15]), "end"]))
    offer = (l2(gm, sm) / IP(src="10.77.0.1", dst="10.77.0.99")
             / UDP(sport=67, dport=68)
             / BOOTP(op=2, xid=xid, yiaddr="10.77.0.99", siaddr="10.77.0.1",
                     chaddr=chaddr)
             / DHCP(options=[("message-type", "offer"),
                             ("server_id", "10.77.0.1"),
                             ("lease_time", 86400),
                             ("subnet_mask", "255.255.0.0"), "end"]))
    return [finalize(disc, size), finalize(offer, size)]


def b_mdns(gm, sm, size):
    q = RND.choice(["_services._dns-sd._udp.local", "_http._tcp.local",
                    "snuffles.local", "printer.local"])
    pkt = (l2(sm, gm) / IP(src="10.77.0.14", dst="224.0.0.251")
           / UDP(sport=5353, dport=5353)
           / DNS(rd=0, qd=DNSQR(qname=q, qtype="PTR")))
    return [finalize(pkt, WIRE_MIN)]


def b_ntp(gm, sm, size):
    sport = RND.randrange(1024, 65535)
    req = (l2(sm, gm) / IP(src="10.77.0.11", dst="10.77.0.123")
           / UDP(sport=sport, dport=123) / NTP(version=4, mode=3))
    resp = (l2(gm, sm) / IP(src="10.77.0.123", dst="10.77.0.11")
            / UDP(sport=123, dport=sport)
            / NTP(version=4, mode=4, stratum=2))
    return [finalize(req, WIRE_MIN), finalize(resp, WIRE_MIN)]


def b_quic(gm, sm, size):
    sport = RND.randrange(1024, 65535)
    pl = max(64, min(size - 80, 1200))
    pkt = (l2(sm, gm) / IP(src="10.77.0.13", dst="10.77.0.5")
           / UDP(sport=sport, dport=443)
           / Raw(load=quic_initial_bytes(pl)))
    return [finalize(pkt, WIRE_MIN)]


def b_icmp(gm, sm, size):
    ident = RND.randrange(1 << 16)
    data = bytes((i & 0xff) for i in range(max(0, size - 42)))
    echo = (l2(sm, gm) / IP(src="10.77.0.11", dst="10.77.0.5")
            / ICMP(type=8, id=ident, seq=1) / Raw(load=data))
    rep = (l2(gm, sm) / IP(src="10.77.0.5", dst="10.77.0.11")
           / ICMP(type=0, id=ident, seq=1) / Raw(load=data))
    return [finalize(echo, size), finalize(rep, size)]


def b_icmpv6(gm, sm, size):
    ident = RND.randrange(1 << 16)
    data = bytes((i & 0xff) for i in range(max(0, size - 62)))
    echo = (l2(sm, gm) / IPv6(src="fd77::11", dst="fd77::5")
            / ICMPv6EchoRequest(id=ident, seq=1, data=data))
    rep = (l2(gm, sm) / IPv6(src="fd77::5", dst="fd77::11")
           / ICMPv6EchoReply(id=ident, seq=1, data=data))
    return [finalize(echo, size), finalize(rep, size)]


def b_ipv6_hbh_tcp(gm, sm, size):
    sport = RND.randrange(1024, 65535)
    pl = max(0, size - 90)
    pkt = (l2(sm, gm) / IPv6(src="fd77::12", dst="fd77::5")
           / IPv6ExtHdrHopByHop()
           / TCP(sport=sport, dport=80, flags="PA",
                 seq=RND.randrange(1 << 30), ack=1)
           / Raw(load=b"H" * pl))
    return [finalize(pkt, WIRE_MIN)]


def b_ipv6_frag_udp(gm, sm, size):
    sport = RND.randrange(1024, 65535)
    pl = max(0, size - 96)
    pkt = (l2(sm, gm) / IPv6(src="fd77::13", dst="fd77::5")
           / IPv6ExtHdrFragment(offset=0, m=1, id=RND.randrange(1 << 32))
           / UDP(sport=sport, dport=9) / Raw(load=b"F" * pl))
    return [finalize(pkt, WIRE_MIN)]


def b_arp(gm, sm, size):
    who = (l2(sm, gm) / ARP(op=1, hwsrc=gm, psrc="10.77.0.11",
                            hwdst="00:00:00:00:00:00", pdst="10.77.0.5"))
    reply = (l2(gm, sm) / ARP(op=2, hwsrc=sm, psrc="10.77.0.5",
                              hwdst=gm, pdst="10.77.0.11"))
    return [finalize(who, WIRE_MIN), finalize(reply, WIRE_MIN)]


def b_dot1q(gm, sm, size):
    vlan = RND.choice([10, 20, 100, 4094])
    sport = RND.randrange(1024, 65535)
    pl = max(0, size - 50)
    pkt = (l2(sm, gm) / Dot1Q(vlan=vlan, prio=RND.randrange(8))
           / IP(src="10.77.0.11", dst="10.77.0.5")
           / UDP(sport=sport, dport=9) / Raw(load=b"V" * pl))
    return [finalize(pkt, WIRE_MIN)]


def b_ipv4_frags(gm, sm, size):
    # one large datagram split into fragments -> several fragment frames
    idn = RND.randrange(1 << 16)
    sport = RND.randrange(1024, 65535)
    total = RND.choice([1600, 2400, 3200, 4000])
    full = (IP(src="10.77.0.11", dst="10.77.0.5", id=idn)
            / UDP(sport=sport, dport=9) / Raw(load=b"G" * total))
    out = []
    for f in fragment(full, fragsize=1400):
        out.append(finalize(l2(sm, gm) / f, None))
    return out


def b_sctp(gm, sm, size):
    sport = RND.randrange(1024, 65535)
    init = (l2(sm, gm) / IP(src="10.77.0.11", dst="10.77.0.5")
            / SCTP(sport=sport, dport=132)
            / SCTPChunkInit(init_tag=RND.randrange(1 << 32), a_rwnd=106496,
                            n_out_streams=10, n_in_streams=65535,
                            init_tsn=RND.randrange(1 << 32)))
    cookie = SCTPChunkParamStateCookie(
        cookie=bytes(RND.randrange(256) for _ in range(32)))
    ack = (l2(gm, sm) / IP(src="10.77.0.5", dst="10.77.0.11")
           / SCTP(sport=132, dport=sport)
           / SCTPChunkInitAck(init_tag=RND.randrange(1 << 32), a_rwnd=106496,
                              n_out_streams=10, n_in_streams=10,
                              init_tsn=RND.randrange(1 << 32),
                              params=[cookie]))
    return [finalize(init, WIRE_MIN), finalize(ack, size)]


def b_tcp_syn(gm, sm, size):
    sport = RND.randrange(1024, 65535)
    syn = (l2(sm, gm) / IP(src="10.77.0.11", dst="10.77.0.5")
           / TCP(sport=sport, dport=RND.choice([80, 443, 22, 8080]),
                 flags="S", seq=RND.randrange(1 << 30),
                 options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (0, 0)),
                          ("NOP", None), ("WScale", 7)]))
    return [finalize(syn, WIRE_MIN)]


BUILDERS = [
    b_dns_a, b_dns_aaaa, b_dns_txt, b_http, b_tls, b_dhcp, b_mdns, b_ntp,
    b_quic, b_icmp, b_icmpv6, b_ipv6_hbh_tcp, b_ipv6_frag_udp, b_arp,
    b_dot1q, b_ipv4_frags, b_sctp, b_tcp_syn,
]


def write_pcap(path, frames):
    with open(path, "wb") as f:
        # pcap global header: magic little-endian, v2.4, snaplen 65535, DLT 1
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        t0 = int(time.time())
        usec = 0
        for b in frames:
            f.write(struct.pack("<IIII", t0, usec, len(b), len(b)))
            f.write(b)
            usec += 37
            if usec >= 1000000:
                usec = 0
                t0 += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out", nargs="?", default="/opt/gen/corpus.pcap")
    ap.add_argument("--count", type=int, default=20000)
    ap.add_argument("--gen-mac", default="02:53:4e:46:01:01")
    ap.add_argument("--sink-mac", default="02:53:4e:46:00:05")
    args = ap.parse_args()

    gm, sm = args.gen_mac, args.sink_mac
    frames = []
    i = 0
    # a size ladder that repeats across 60..1514 so the corpus spans sizes
    ladder = [60, 74, 90, 128, 200, 300, 450, 600, 800, 1000, 1200, 1400, 1514]
    while len(frames) < args.count:
        builder = BUILDERS[i % len(BUILDERS)]
        size = ladder[(i // len(BUILDERS)) % len(ladder)]
        try:
            frames.extend(builder(gm, sm, size))
        except Exception as e:  # noqa: BLE001
            sys.stderr.write("builder %s failed: %s\n" % (builder.__name__, e))
            raise
        i += 1
    frames = frames[:args.count]
    write_pcap(args.out, frames)
    total_bytes = sum(len(b) for b in frames)
    sys.stderr.write(
        "wrote %d frames, %d bytes to %s (avg %.0f B)\n"
        % (len(frames), total_bytes, args.out, total_bytes / len(frames)))


if __name__ == "__main__":
    main()
