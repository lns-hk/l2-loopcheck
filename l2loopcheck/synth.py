"""Synthetic capture builder used by the tests and by the demo command.

All addresses are documentation / private ranges and locally administered MACs.
Scenarios model the situations the verdicts must tell apart.
"""

from __future__ import annotations

import io
import random
import struct
from typing import Callable

from .pcapio import PcapWriter

BCAST = b"\xff" * 6
T0 = 1_700_000_000.0


def mac(n: int) -> bytes:
    return bytes([0x02, 0x00, 0x5E, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])


def ip(a: int, b: int, c: int, d: int) -> bytes:
    return bytes([a, b, c, d])


def eth(dst: bytes, src: bytes, etype: int, payload: bytes, vlan: int | None = None) -> bytes:
    tag = struct.pack("!HH", 0x8100, vlan) if vlan is not None else b""
    frame = dst + src + tag + struct.pack("!H", etype) + payload
    return frame.ljust(60 + len(tag), b"\0")


def llc_frame(dst: bytes, src: bytes, llc_payload: bytes, vlan: int | None = None) -> bytes:
    tag = struct.pack("!HH", 0x8100, vlan) if vlan is not None else b""
    return (dst + src + tag + struct.pack("!H", len(llc_payload)) + llc_payload).ljust(60 + len(tag), b"\0")


def arp(src: bytes, spa: bytes, tpa: bytes, op: int = 1, tha: bytes = b"\0" * 6, vlan=None, dst=BCAST) -> bytes:
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + src + spa + tha + tpa
    return eth(dst, src, 0x0806, body, vlan)


def ipv4_udp(dst_mac: bytes, src_mac: bytes, src_ip: bytes, dst_ip: bytes, sport: int, dport: int,
             payload: bytes, ttl: int = 64, ident: int = 0, vlan=None) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), ident, 0, ttl, 17, 0, src_ip, dst_ip)
    return eth(dst_mac, src_mac, 0x0800, hdr + udp, vlan)


def ipv4_tcp(dst_mac: bytes, src_mac: bytes, src_ip: bytes, dst_ip: bytes, seq: int, vlan=None) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", 443, 50000, seq, 0, 0x50, 0x18, 1024, 0, 0) + b"x" * 40
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), seq & 0xFFFF, 0, 64, 6, 0, src_ip, dst_ip)
    return eth(dst_mac, src_mac, 0x0800, hdr + tcp, vlan)


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def mdns_query(src_mac: bytes, src_ip: bytes, name: str, qtype: int = 33, ident: int = 0, vlan=None) -> bytes:
    msg = struct.pack("!HHHHHH", ident, 0, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", qtype, 1)
    return ipv4_udp(bytes.fromhex("01005e0000fb"), src_mac, src_ip, ip(224, 0, 0, 251), 5353, 5353, msg,
                    ttl=255, vlan=vlan)


def bpdu(bridge: bytes, root: bytes, root_prio=32768, bridge_prio=32768, cost=0, port=0x8001,
         flags=0x3C, version=2, region: str | None = None, revision=0, digest=b"\x11" * 16) -> bytes:
    btype = 0x02 if version >= 2 else 0x00
    body = struct.pack("!HBBB", 0, version, btype, flags)
    body += struct.pack("!H", root_prio) + root + struct.pack("!I", cost)
    body += struct.pack("!H", bridge_prio) + bridge + struct.pack("!H", port)
    body += struct.pack("!HHHH", 0, 20 * 256, 2 * 256, 15 * 256)
    if version >= 2:
        body += b"\x00"  # version 1 length
    if version == 3:
        cfg = b"\x00" + (region or "").encode().ljust(32, b"\0") + struct.pack("!H", revision) + digest
        rest = cfg + struct.pack("!I", 0) + struct.pack("!H", bridge_prio) + bridge + b"\x14"
        body += struct.pack("!H", len(rest)) + rest
    return llc_frame(bytes.fromhex("0180c2000000"), bridge, b"\x42\x42\x03" + body)


def lldp(src: bytes, system_name: str, port: str, mgmt: bytes) -> bytes:
    def tlv(t, v):
        return struct.pack("!H", (t << 9) | len(v)) + v
    body = tlv(1, b"\x04" + src) + tlv(2, b"\x05" + port.encode()) + tlv(3, b"\x00\x78")
    body += tlv(5, system_name.encode()) + tlv(4, b"uplink " + port.encode())
    body += tlv(8, b"\x05\x01" + mgmt + b"\x02\x00\x00\x00\x01\x00") + tlv(0, b"")
    return eth(bytes.fromhex("0180c200000e"), src, 0x88CC, body)


def cdp(src: bytes, device: str, port: str, platform: str) -> bytes:
    def tlv(t, v):
        return struct.pack("!HH", t, 4 + len(v)) + v
    body = b"\x02\xb4\x00\x00" + tlv(1, device.encode()) + tlv(3, port.encode()) + tlv(6, platform.encode())
    body += tlv(0x0A, struct.pack("!H", 20))
    return llc_frame(bytes.fromhex("01000ccccccc"), src, b"\xaa\xaa\x03\x00\x00\x0c\x20\x00" + body)


# ----------------------------------------------------------------- scenarios
Frames = list[tuple[float, bytes]]


def _background(rng: random.Random, duration: float, hosts: int = 12, vlan=None, stp=True,
                me: bytes = mac(0xFFFE)) -> Frames:
    out: Frames = []
    root = mac(0x100)
    for i in range(hosts):
        hm, hip = mac(0x1000 + i), ip(192, 0, 2, 10 + i)
        t = rng.uniform(0, 3)
        while t < duration:
            kind = rng.random()
            if kind < 0.4:
                out.append((t, arp(hm, hip, ip(192, 0, 2, rng.randint(1, 254)), vlan=vlan)))
            elif kind < 0.8:
                out.append((t, mdns_query(hm, hip, f"_svc{i % 4}._tcp.local", qtype=12,
                                          ident=rng.randint(0, 65535), vlan=vlan)))
            else:
                out.append((t, ipv4_tcp(me, hm, hip, ip(192, 0, 2, 250), rng.randint(0, 1 << 30), vlan=vlan)))
            t += rng.uniform(0.5, 4.0)
    if stp:
        t = 0.3
        while t < duration:
            out.append((t, bpdu(mac(0x101), root, root_prio=4096, cost=20000)))
            t += 2.0
    t = 1.0
    while t < duration:
        out.append((t, lldp(mac(0x101), "SW-ACCESS-1", "Gi1/0/12", ip(192, 0, 2, 2))))
        t += 30.0
    return out


def scenario_healthy(seed: int = 1, duration: float = 120.0) -> Frames:
    return _background(random.Random(seed), duration)


def scenario_loop(seed: int = 2, duration: float = 60.0, start: float = 20.0, period: float = 280e-6,
                  copies: int = 40) -> Frames:
    """A loop with no spanning tree: every flooded frame after ``start`` circulates."""
    rng = random.Random(seed)
    base = _background(rng, duration, stp=False)
    out: Frames = []
    for t, fr in base:
        out.append((t, fr))
        flooded = fr[0] & 1
        if t >= start and flooded:
            for k in range(1, copies + 1):
                out.append((t + k * period * rng.uniform(0.97, 1.03), fr))
    return out


def scenario_chatty_host(seed: int = 3, duration: float = 60.0, pps: int = 1500) -> Frames:
    """One device floods identical mDNS queries; no loop, STP healthy."""
    rng = random.Random(seed)
    out = _background(rng, duration)
    hm, hip = mac(0x2000), ip(198, 51, 100, 84)
    q = mdns_query(hm, hip, "Cast-8341._googlecast._tcp.local")
    step = 1.0 / pps
    t = 5.0
    while t < duration:
        out.append((t, q))
        t += step * rng.uniform(0.8, 1.2)
    return out


def scenario_stp_unstable(seed: int = 4, duration: float = 120.0) -> Frames:
    rng = random.Random(seed)
    out = _background(rng, duration, stp=False)
    root_a, root_b = mac(0x100), mac(0x200)
    t, n = 0.3, 0
    while t < duration:
        root = root_a if t < duration / 2 else root_b
        tc = 0x3D if int(t) % 12 < 2 else 0x3C
        out.append((t, bpdu(mac(0x101), root, root_prio=4096, cost=20000, flags=tc)))
        t += 2.0
        n += 1
    return out


def scenario_span_duplication(seed: int = 5, duration: float = 60.0) -> Frames:
    rng = random.Random(seed)
    base = _background(rng, duration, hosts=20)
    out: Frames = []
    for t, fr in base:
        out.append((t, fr))
        out.append((t + 20e-6, fr))
    return out


def scenario_cross_vlan(seed: int = 6, duration: float = 60.0) -> Frames:
    rng = random.Random(seed)
    out = _background(rng, duration, vlan=10)
    extra = []
    for t, fr in out:
        if fr[0] & 1 and fr[12:14] == b"\x81\x00" and rng.random() < 0.5:
            extra.append((t + 150e-6, fr[:14] + struct.pack("!H", 20) + fr[16:]))
    return out + extra


def scenario_duplicate_ip(seed: int = 7, duration: float = 60.0) -> Frames:
    rng = random.Random(seed)
    out = _background(rng, duration)
    a, b = mac(0x3001), mac(0x3002)
    for k in range(10):
        out.append((5.0 + k * 5, arp(a, ip(192, 0, 2, 77), ip(192, 0, 2, 1))))
        out.append((7.0 + k * 5, arp(b, ip(192, 0, 2, 77), ip(192, 0, 2, 1))))
    return out


def scenario_split_tree(seed: int = 8, duration: float = 90.0) -> Frames:
    rng = random.Random(seed)
    out = _background(rng, duration, stp=False)
    t = 0.3
    while t < duration:
        out.append((t, bpdu(mac(0x101), mac(0x100), root_prio=4096, cost=20000)))
        out.append((t + 0.5, bpdu(mac(0x201), mac(0x200), root_prio=32768, cost=0)))
        t += 2.0
    return out


def scenario_mst_regions(seed: int = 9, duration: float = 60.0) -> Frames:
    rng = random.Random(seed)
    out = _background(rng, duration, stp=False)
    t = 0.3
    while t < duration:
        out.append((t, bpdu(mac(0x101), mac(0x100), version=3, region="CAMPUS", revision=1)))
        out.append((t + 0.4, bpdu(mac(0x102), mac(0x100), version=3, region="CAMPUS", revision=2,
                                  digest=b"\x22" * 16)))
        t += 2.0
    return out


def scenario_short(seed: int = 10) -> Frames:
    return _background(random.Random(seed), 3.0, hosts=3)


SCENARIOS: dict[str, Callable[[], Frames]] = {
    "healthy": scenario_healthy,
    "loop": scenario_loop,
    "chatty-host": scenario_chatty_host,
    "stp-unstable": scenario_stp_unstable,
    "span-duplication": scenario_span_duplication,
    "cross-vlan": scenario_cross_vlan,
    "duplicate-ip": scenario_duplicate_ip,
    "split-tree": scenario_split_tree,
    "mst-regions": scenario_mst_regions,
    "short": scenario_short,
}


def to_pcap_bytes(frames: Frames, t0: float = T0) -> bytes:
    buf = io.BytesIO()
    w = PcapWriter(buf)
    for t, fr in sorted(frames, key=lambda x: x[0]):
        w.write(t0 + t, fr)
    return buf.getvalue()


def write_pcap(path: str, frames: Frames, t0: float = T0) -> None:
    with open(path, "wb") as f:
        f.write(to_pcap_bytes(frames, t0))
