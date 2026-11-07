"""Header-level frame decoding (stdlib only).

Only the fields the detectors need are decoded. Application payloads are never
kept; the only application-layer data extracted are mDNS/NBNS/LLMNR names and
LLDP/CDP identity strings, which identify devices in the report.

References: IEEE 802.1Q-2022 (VLAN tags, BPDUs clause 14), IEEE 802.1AB (LLDP),
Cisco CDP and PVST+ (SSTP) formats, RFC 826 (ARP), RFC 6762 (mDNS),
RFC 1002 (NBNS).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from .pcapio import LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2

ETH_VLAN_TPIDS = (0x8100, 0x88A8, 0x9100, 0x9200)
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_LLDP = 0x88CC
ETHERTYPE_PROBE = 0x88B5  # IEEE 802 local experimental ethertype 1

BROADCAST = b"\xff" * 6
STP_DST = bytes.fromhex("0180c2000000")
PVST_DST = bytes.fromhex("01000ccccccd")
CDP_DST = bytes.fromhex("01000ccccccc")
LLDP_DSTS = {bytes.fromhex(x) for x in ("0180c200000e", "0180c2000003", "0180c2000000")}

PROBE_MAGIC = b"L2LC"

# Well-known UDP ports used by chatty discovery / building protocols.
UDP_LABELS = {
    67: "DHCP", 68: "DHCP", 137: "NBNS", 138: "NetBIOS-DGM", 1900: "SSDP",
    5353: "mDNS", 5355: "LLMNR", 3702: "WS-Discovery", 47808: "BACnet",
    123: "NTP", 161: "SNMP", 514: "Syslog", 9: "WoL", 7: "WoL",
}


def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def ip4_str(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def is_virtual_router_mac(mac: bytes) -> bool:
    """VRRP / HSRP / GLBP virtual MACs legitimately share IPs."""
    return (
        mac[:5] == b"\x00\x00\x5e\x00\x01"  # VRRPv4
        or mac[:5] == b"\x00\x00\x5e\x00\x02"  # VRRPv6
        or mac[:5] == b"\x00\x00\x0c\x07\xac"  # HSRPv1
        or mac[:4] == b"\x00\x00\x0c\x9f"  # HSRPv2
        or mac[:4] == b"\x00\x07\xb4\x00"  # GLBP
    )


@dataclass(slots=True)
class Bpdu:
    kind: str  # "STP", "RSTP", "MSTP", "TCN", "PVST+" (with version suffix)
    version: int
    flags: int = 0
    root_prio: int = 0
    root_mac: bytes = b""
    root_cost: int = 0
    bridge_prio: int = 0
    bridge_mac: bytes = b""
    port_id: int = 0
    msg_age: float = 0.0
    max_age: float = 0.0
    hello: float = 0.0
    fwd_delay: float = 0.0
    vlan: Optional[int] = None  # PVST+ VLAN
    mst_region: Optional[str] = None
    mst_revision: Optional[int] = None
    mst_digest: Optional[str] = None

    @property
    def tc(self) -> bool:
        return bool(self.flags & 0x01) or self.kind == "TCN"

    @property
    def root_id(self) -> str:
        return f"{self.root_prio}/{mac_str(self.root_mac)}"

    @property
    def bridge_id(self) -> str:
        return f"{self.bridge_prio}/{mac_str(self.bridge_mac)}"


@dataclass(slots=True)
class Neighbour:
    protocol: str  # "LLDP" or "CDP"
    chassis: str = ""
    port: str = ""
    system_name: str = ""
    system_desc: str = ""
    port_desc: str = ""
    platform: str = ""
    mgmt_ip: str = ""
    native_vlan: Optional[int] = None


@dataclass(slots=True)
class Frame:
    src: bytes
    dst: bytes
    vlans: tuple = ()
    ethertype: int = 0
    proto: str = "Other"  # classification label for statistics
    core: bytes = b""  # frame bytes without VLAN tags, used for duplicate detection
    bcast: bool = False
    mcast: bool = False
    ip_src: Optional[bytes] = None
    ip_dst: Optional[bytes] = None
    ip_ttl: Optional[int] = None
    ip6_src: Optional[bytes] = None
    arp: Optional[tuple] = None  # (op, sha, spa, tha, tpa)
    bpdu: Optional[Bpdu] = None
    neighbour: Optional[Neighbour] = None
    name: Optional[str] = None  # mDNS/NBNS/LLMNR query or record name
    probe: Optional[tuple] = None  # (nonce_hex, seq)
    outgoing: Optional[bool] = None  # known only for Linux cooked captures
    extras: dict = field(default_factory=dict)


def decode(data: bytes, linktype: int) -> Optional[Frame]:
    """Decode one captured frame. Returns None if it cannot be parsed."""
    try:
        if linktype == LINKTYPE_ETHERNET:
            return _decode_ethernet(data)
        if linktype == LINKTYPE_LINUX_SLL:
            return _decode_sll(data)
        if linktype == LINKTYPE_LINUX_SLL2:
            return _decode_sll2(data)
    except (struct.error, IndexError, ValueError):
        return None
    return None


def _decode_ethernet(data: bytes) -> Optional[Frame]:
    if len(data) < 14:
        return None
    dst, src = data[0:6], data[6:12]
    off = 12
    vlans = []
    etype = struct.unpack("!H", data[off : off + 2])[0]
    while etype in ETH_VLAN_TPIDS and off + 6 <= len(data):
        tci = struct.unpack("!H", data[off + 2 : off + 4])[0]
        vlans.append(tci & 0x0FFF)
        off += 4
        etype = struct.unpack("!H", data[off : off + 2])[0]
    payload_off = off + 2
    core = data[:12] + data[off:] if vlans else data
    f = Frame(src=src, dst=dst, vlans=tuple(vlans), ethertype=etype, core=core)
    f.bcast = dst == BROADCAST
    f.mcast = bool(dst[0] & 1) and not f.bcast
    _decode_payload(f, data, payload_off, etype)
    return f


def _decode_sll(data: bytes) -> Optional[Frame]:
    # pkttype(2) hatype(2) halen(2) addr(8) protocol(2)
    if len(data) < 16:
        return None
    pkttype, _hatype, halen = struct.unpack("!HHH", data[0:6])
    src = data[6 : 6 + min(halen, 6)].ljust(6, b"\0")
    etype = struct.unpack("!H", data[14:16])[0]
    return _sll_common(data, pkttype, src, etype, 16)


def _decode_sll2(data: bytes) -> Optional[Frame]:
    # protocol(2) reserved(2) ifindex(4) hatype(2) pkttype(1) halen(1) addr(8)
    if len(data) < 20:
        return None
    etype = struct.unpack("!H", data[0:2])[0]
    pkttype, halen = data[10], data[11]
    src = data[12 : 12 + min(halen, 6)].ljust(6, b"\0")
    return _sll_common(data, pkttype, src, etype, 20)


def _sll_common(data: bytes, pkttype: int, src: bytes, etype: int, off: int) -> Frame:
    dst = BROADCAST if pkttype == 1 else (b"\x01\x00\x00\x00\x00\x00" if pkttype == 2 else b"\x00" * 6)
    f = Frame(src=src, dst=dst, ethertype=etype, core=src + data[off - 2 :])
    f.bcast = pkttype == 1
    f.mcast = pkttype == 2
    f.outgoing = pkttype == 4
    if etype == 0x0004:  # 802.2 LLC frames (STP, CDP) carried without a MAC header
        _decode_llc(f, data, off)
        return f
    _decode_payload(f, data, off, etype)
    return f


def _decode_payload(f: Frame, data: bytes, off: int, etype: int) -> None:
    if etype <= 1500:  # 802.3 length field: LLC follows
        _decode_llc(f, data, off)
        return
    if etype == ETHERTYPE_ARP:
        f.proto = "ARP"
        if len(data) >= off + 28:
            op = struct.unpack("!H", data[off + 6 : off + 8])[0]
            f.arp = (op, data[off + 8 : off + 14], data[off + 14 : off + 18],
                     data[off + 18 : off + 24], data[off + 24 : off + 28])
        return
    if etype == ETHERTYPE_IPV4:
        _decode_ipv4(f, data, off)
        return
    if etype == ETHERTYPE_IPV6:
        _decode_ipv6(f, data, off)
        return
    if etype == ETHERTYPE_LLDP:
        f.proto = "LLDP"
        f.neighbour = _decode_lldp(data[off:])
        return
    if etype == ETHERTYPE_PROBE:
        f.proto = "l2-loopcheck probe"
        body = data[off:]
        if body[:4] == PROBE_MAGIC and len(body) >= 15:
            f.probe = (body[5:13].hex(), struct.unpack("!H", body[13:15])[0])
        return
    f.proto = {
        0x8809: "LACP/Slow", 0x888E: "802.1X", 0x88E3: "MRP", 0x8892: "PROFINET",
        0x88F7: "PTP", 0x8899: "Realtek RRCP", 0x9000: "Loopback (CTP)",
        0x88B5: "Experimental", 0x88B6: "Experimental", 0x8100: "VLAN",
    }.get(etype, f"EtherType 0x{etype:04x}")


def _decode_llc(f: Frame, data: bytes, off: int) -> None:
    if len(data) < off + 3:
        f.proto = "LLC"
        return
    dsap, ssap, ctrl = data[off], data[off + 1], data[off + 2]
    if dsap == 0x42 and ssap == 0x42 and ctrl == 0x03:
        f.proto = "STP"
        f.bpdu = _decode_bpdu(data[off + 3 :])
        return
    if dsap == 0xAA and ssap == 0xAA and len(data) >= off + 8:
        oui = data[off + 3 : off + 6]
        pid = struct.unpack("!H", data[off + 6 : off + 8])[0]
        body = data[off + 8 :]
        if oui == b"\x00\x00\x0c" and pid == 0x010B:
            f.proto = "STP"
            b = _decode_bpdu(body)
            if b:
                b.kind = "PVST+ " + b.kind
                b.vlan = _pvst_vlan(body)
            f.bpdu = b
            return
        if oui == b"\x00\x00\x0c" and pid == 0x2000:
            f.proto = "CDP"
            f.neighbour = _decode_cdp(body)
            return
        if oui == b"\x00\x00\x0c" and pid == 0x2004:
            f.proto = "DTP"
            return
        if oui == b"\x00\x00\x0c" and pid == 0x2003:
            f.proto = "VTP"
            return
        f.proto = f"SNAP {oui.hex()}/{pid:04x}"
        return
    f.proto = "LLC"


def _decode_bpdu(b: bytes) -> Optional[Bpdu]:
    if len(b) < 4:
        return None
    proto_id, version, btype = struct.unpack("!HBB", b[:4])
    if proto_id != 0:
        return None
    if btype == 0x80:
        return Bpdu(kind="TCN", version=version)
    if len(b) < 35:
        return None
    flags = b[4]
    root_prio, root_mac = struct.unpack("!H", b[5:7])[0], b[7:13]
    cost = struct.unpack("!I", b[13:17])[0]
    br_prio, br_mac = struct.unpack("!H", b[17:19])[0], b[19:25]
    port_id = struct.unpack("!H", b[25:27])[0]
    times = [x / 256 for x in struct.unpack("!HHHH", b[27:35])]
    kind = {0: "STP", 2: "RSTP", 3: "MSTP"}.get(version, f"STPv{version}")
    bp = Bpdu(kind=kind, version=version, flags=flags, root_prio=root_prio, root_mac=root_mac,
              root_cost=cost, bridge_prio=br_prio, bridge_mac=br_mac, port_id=port_id,
              msg_age=times[0], max_age=times[1], hello=times[2], fwd_delay=times[3])
    if version == 3 and len(b) >= 38 + 51:
        cfg = b[38 : 38 + 51]
        bp.mst_region = cfg[1:33].rstrip(b"\0").decode("utf-8", "replace")
        bp.mst_revision = struct.unpack("!H", cfg[33:35])[0]
        bp.mst_digest = cfg[35:51].hex()
    return bp


def _pvst_vlan(body: bytes) -> Optional[int]:
    # PVST+ appends a TLV (type 0, len 2, vlan) after the 36-byte BPDU.
    for off in (36, 37, 38):
        if len(body) >= off + 6:
            t, ln, v = struct.unpack("!HHH", body[off : off + 6])
            if t == 0 and ln == 2:
                return v
    return None


def _clean(b: bytes) -> str:
    return b.decode("utf-8", "replace").strip("\0").strip()


def _decode_lldp(b: bytes) -> Neighbour:
    n = Neighbour(protocol="LLDP")
    off = 0
    while off + 2 <= len(b):
        hdr = struct.unpack("!H", b[off : off + 2])[0]
        t, ln = hdr >> 9, hdr & 0x1FF
        val = b[off + 2 : off + 2 + ln]
        off += 2 + ln
        if t == 0:
            break
        if t == 1 and val:
            n.chassis = mac_str(val[1:7]) if val[0] == 4 and len(val) >= 7 else _clean(val[1:])
        elif t == 2 and val:
            n.port = mac_str(val[1:7]) if val[0] == 3 and len(val) >= 7 else _clean(val[1:])
        elif t == 4:
            n.port_desc = _clean(val)
        elif t == 5:
            n.system_name = _clean(val)
        elif t == 6:
            n.system_desc = _clean(val)[:200]
        elif t == 8 and len(val) >= 6 and val[1] == 1 and val[0] >= 5:
            n.mgmt_ip = ip4_str(val[2:6])
    return n


def _decode_cdp(b: bytes) -> Neighbour:
    n = Neighbour(protocol="CDP")
    off = 4  # version, ttl, checksum
    while off + 4 <= len(b):
        t, ln = struct.unpack("!HH", b[off : off + 4])
        if ln < 4:
            break
        val = b[off + 4 : off + ln]
        off += ln
        if t == 0x0001:
            n.system_name = _clean(val)
        elif t == 0x0003:
            n.port = _clean(val)
        elif t == 0x0005:
            n.system_desc = _clean(val)[:200]
        elif t == 0x0006:
            n.platform = _clean(val)
        elif t == 0x000A and len(val) >= 2:
            n.native_vlan = struct.unpack("!H", val[:2])[0]
        elif t == 0x0002 and len(val) >= 13 and val[4] == 1 and val[6] == 0xCC:
            n.mgmt_ip = ip4_str(val[9:13])
    n.chassis = n.system_name
    return n


def _decode_ipv4(f: Frame, data: bytes, off: int) -> None:
    f.proto = "IPv4"
    if len(data) < off + 20:
        return
    ihl = (data[off] & 0x0F) * 4
    f.ip_ttl = data[off + 8]
    proto = data[off + 9]
    f.ip_src, f.ip_dst = data[off + 12 : off + 16], data[off + 16 : off + 20]
    l4 = off + ihl
    if proto == 17 and len(data) >= l4 + 8:
        sport, dport = struct.unpack("!HH", data[l4 : l4 + 4])
        label = UDP_LABELS.get(dport) or UDP_LABELS.get(sport)
        f.proto = label or ("UDP broadcast" if f.bcast else "UDP")
        _maybe_name(f, data[l4 + 8 :], label)
    elif proto == 1:
        f.proto = "ICMP"
    elif proto == 2:
        f.proto = "IGMP"
    elif proto == 6:
        f.proto = "TCP"
    elif proto == 112:
        f.proto = "VRRP"
    elif proto == 89:
        f.proto = "OSPF"


def _decode_ipv6(f: Frame, data: bytes, off: int) -> None:
    f.proto = "IPv6"
    if len(data) < off + 40:
        return
    nh = data[off + 6]
    f.ip_ttl = data[off + 7]  # hop limit
    f.ip6_src = data[off + 8 : off + 24]
    l4 = off + 40
    if nh == 58 and len(data) > l4:
        t = data[l4]
        f.proto = {133: "ICMPv6 RS", 134: "ICMPv6 RA", 135: "ICMPv6 NS", 136: "ICMPv6 NA",
                   143: "MLDv2", 130: "MLD"}.get(t, "ICMPv6")
    elif nh == 17 and len(data) >= l4 + 8:
        sport, dport = struct.unpack("!HH", data[l4 : l4 + 4])
        label = UDP_LABELS.get(dport) or UDP_LABELS.get(sport)
        f.proto = (label + " (v6)") if label else "UDP (v6)"
        _maybe_name(f, data[l4 + 8 :], label)
    elif nh == 0:
        f.proto = "IPv6 hop-by-hop (MLD)"


def _maybe_name(f: Frame, payload: bytes, label: Optional[str]) -> None:
    if label in ("mDNS", "LLMNR", "NBNS") and len(payload) > 12:
        try:
            qd, an = struct.unpack("!HH", payload[4:8])
            if qd or an:
                name = _dns_name(payload, 12)
                if label == "NBNS":
                    name = _nbns_decode(name)
                f.name = name[:120] if name else None
        except (IndexError, struct.error, UnicodeDecodeError):
            pass


def _dns_name(msg: bytes, off: int, depth: int = 0) -> str:
    labels = []
    while off < len(msg) and depth < 10:
        ln = msg[off]
        if ln == 0:
            break
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack("!H", msg[off : off + 2])[0] & 0x3FFF
            labels.append(_dns_name(msg, ptr, depth + 1))
            break
        labels.append(msg[off + 1 : off + 1 + ln].decode("utf-8", "replace"))
        off += 1 + ln
    return ".".join(x for x in labels if x)


def _nbns_decode(name: str) -> str:
    first = name.split(".")[0]
    if len(first) != 32:
        return name
    try:
        raw = bytes(((ord(first[i]) - 65) << 4) | (ord(first[i + 1]) - 65) for i in range(0, 32, 2))
    except ValueError:
        return name
    return f"{raw[:15].decode('ascii', 'replace').rstrip()}<{raw[15]:02x}>"
