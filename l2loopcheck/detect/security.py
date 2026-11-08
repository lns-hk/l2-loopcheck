"""Passive security checks: what the capture reveals about this network's exposure.

Nothing here sends a frame. Everything comes from frames already captured.

Privacy rule: payloads are only inspected in memory to classify a frame. No
password, SNMP community string, HTTP header value or file content is stored or
reported; a finding says *that* a default community or a clear-text login was
seen, never what it was.

All per-key tables are bounded so a capture of many hours cannot exhaust memory.
Thresholds are initial values, documented in docs/DETECTION.md, and need
calibrating against field captures.
"""

from __future__ import annotations

import ipaddress
import struct
from collections import Counter, deque
from typing import Optional

from ..decode import Frame, _dns_name, ip4_str, is_virtual_router_mac, mac_str

MAX_KEYS = 20000
MAX_SMALL = 64

CLEAR_TCP = {21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP", 512: "rexec", 513: "rlogin", 514: "rsh",
             5900: "VNC", 5901: "VNC"}
HTTP_PORTS = {80, 8000, 8080}
OT_TCP = {102: "S7comm / ISO-TSAP", 502: "Modbus/TCP", 789: "Red Lion Crimson", 1883: "MQTT without TLS",
          1911: "Niagara Fox", 2404: "IEC 60870-5-104", 5007: "Mitsubishi MELSEC", 9600: "OMRON FINS",
          20000: "DNP3", 44818: "EtherNet/IP"}
OT_UDP = {2222: "EtherNet/IP I/O", 3671: "KNXnet/IP", 9600: "OMRON FINS", 20000: "DNP3", 44818: "EtherNet/IP",
          47808: "BACnet/IP"}
OT_ETHERTYPES = {0x8892: "PROFINET", 0x88A4: "EtherCAT", 0x88B8: "IEC 61850 GOOSE", 0x88BA: "IEC 61850 SV"}
LOGIN_PREFIXES = (b"USER ", b"PASS ", b"LOGIN ", b"AUTH ")
TLS_NAMES = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1"}

SCAN_WINDOW_S = 60.0
SCAN_PORTS = 100  # distinct ports on one target from one source
SWEEP_HOSTS = 64  # distinct targets from one source
MAC_FLOOD_WINDOW_S = 10.0
MAC_FLOOD_NEW = 1000
DHCP_STARVE_CLIENTS = 50
ARP_REPLY_BURST_PER_S = 20
ARP_MANY_IPS = 16
DNS_LONG_LABEL = 45
DNS_TUNNEL_QUERIES = 20


def _ip6_str(b: bytes) -> str:
    return str(ipaddress.IPv6Address(b))


def _vlan(f: Frame):
    return f.vlans[-1] if f.vlans else None


def _vlan_key(v) -> str:
    return "untagged" if v is None else str(v)


def _add(s: set, value, limit: int = MAX_SMALL) -> None:
    if len(s) < limit:
        s.add(value)


class _WindowCounter:
    """Distinct values per key inside a sliding window; remembers each key's peak."""

    def __init__(self, window: float) -> None:
        self.window = window
        self.items: dict = {}
        self.peak: dict = {}

    def add(self, key, value, ts: float, index: int) -> None:
        if key not in self.items and len(self.items) >= MAX_KEYS:
            return
        q = self.items.setdefault(key, deque())
        q.append((ts, value))
        while q and ts - q[0][0] > self.window:
            q.popleft()
        if len(q) >= 8:  # no point counting until it could matter
            n = len({v for _t, v in q})
            if n > self.peak.get(key, (0, 0))[0]:
                self.peak[key] = (n, index)


class SecurityDetector:
    def __init__(self) -> None:
        self.frames = 0
        self.tagged = 0
        self.multi_tagged = 0
        self.multi_tag_first: Optional[int] = None
        self.vlans: Counter = Counter()
        self.unicast_dsts: Counter = Counter()
        self.unicast = 0
        self.services: dict[tuple, dict] = {}
        self.layer2: dict[str, dict] = {}
        self.snmp: dict[tuple, dict] = {}
        self.http_basic: dict[str, dict] = {}
        self.tls_old: dict[tuple, dict] = {}
        self.smb1: dict[str, dict] = {}
        self.dhcp_servers: dict[tuple, dict] = {}
        self.dhcp_clients = _WindowCounter(60.0)
        self.gateways: Counter = Counter()
        self.dhcp_routers: set = set()
        self.ra: dict[tuple, dict] = {}
        self.dhcp6: dict[tuple, dict] = {}
        self.redirects: dict[str, dict] = {}
        self.fhrp: dict[tuple, dict] = {}
        self.routing: dict[tuple, dict] = {}
        self.name_proto: dict[str, dict] = {}
        self.wpad = {"count": 0, "first_frame": None}
        self.mac_seen: set = set()
        self.mac_new_window: deque = deque()
        self.mac_flood_peak = (0, None)
        self.arp_claims: dict[bytes, set] = {}
        self.arp_reply_seconds: dict = {}
        self.arp_reply_peak: dict = {}
        self.arp_sweep = _WindowCounter(SCAN_WINDOW_S)
        self.port_scan = _WindowCounter(SCAN_WINDOW_S)
        self.host_sweep = _WindowCounter(SCAN_WINDOW_S)
        self.dns_long: dict[str, dict] = {}
        self.dot1x = 0
        self.hosts: dict[bytes, dict] = {}

    # ---------------------------------------------------------------- feed
    def feed(self, f: Frame, index: int, ts: float) -> None:
        self.frames += 1
        vlan = _vlan(f)
        self.vlans[_vlan_key(vlan)] += 1
        if f.vlans:
            self.tagged += 1
            if len(f.vlans) >= 2:
                self.multi_tagged += 1
                if self.multi_tag_first is None:
                    self.multi_tag_first = index
        if not f.bcast and not f.mcast and len(self.unicast_dsts) < MAX_KEYS:
            self.unicast += 1
            self.unicast_dsts[f.dst] += 1
        self._host(f, index, vlan)
        self._mac_flood(f, ts, index)
        if f.arp:
            self._arp(f, ts, index)
        off = 8 if f.outgoing is not None else 14
        body = f.core[off:]
        if f.ethertype == 0x0800:
            self._ipv4(f, body, vlan, ts, index)
        elif f.ethertype == 0x86DD:
            self._ipv6(f, body, vlan, ts, index)
        elif f.ethertype == 0x888E:
            self.dot1x += 1
        elif f.ethertype in OT_ETHERTYPES:
            self._service(OT_ETHERTYPES[f.ethertype], "ot", mac_str(f.src), None, None, index, vlan)
        elif f.ethertype <= 1500:
            self._llc(f, body, index)
        if f.name:
            self._name(f, index)

    def _host(self, f: Frame, index: int, vlan) -> None:
        h = self.hosts.get(f.src)
        if h is None:
            if len(self.hosts) >= MAX_KEYS:
                return
            h = self.hosts[f.src] = {"mac": mac_str(f.src), "ips": set(), "names": set(), "vlans": set(),
                                     "frames": 0, "first_frame": index, "protocols": Counter(), "roles": set(),
                                     "local_admin": bool(f.src[0] & 2)}
        h["frames"] += 1
        _add(h["vlans"], _vlan_key(vlan))
        h["protocols"][f.proto or "other"] += 1
        if f.ip_src and any(f.ip_src):
            _add(h["ips"], ip4_str(f.ip_src), 12)
        if f.ip6_src and any(f.ip6_src):
            _add(h["ips"], _ip6_str(f.ip6_src), 12)
        if f.name:
            _add(h["names"], f.name.rstrip("."), 8)

    def _mac_flood(self, f: Frame, ts: float, index: int) -> None:
        if f.src in self.mac_seen or len(self.mac_seen) >= 200000:
            return
        self.mac_seen.add(f.src)
        w = self.mac_new_window
        w.append(ts)
        while w and ts - w[0] > MAC_FLOOD_WINDOW_S:
            w.popleft()
        if len(w) > self.mac_flood_peak[0]:
            self.mac_flood_peak = (len(w), index)

    def _arp(self, f: Frame, ts: float, index: int) -> None:
        op, sha, spa, _tha, tpa = f.arp
        if any(spa) and not is_virtual_router_mac(sha):
            s = self.arp_claims.setdefault(sha, set()) if len(self.arp_claims) < MAX_KEYS or sha in self.arp_claims else None
            if s is not None:
                _add(s, spa, 256)
        if op == 1:
            if spa != tpa and any(spa):
                self.arp_sweep.add(sha, tpa, ts, index)
            self.gateways[tpa] += 1
        elif op == 2:
            key = (sha, int(ts))
            n = self.arp_reply_seconds.get(key, 0) + 1
            if len(self.arp_reply_seconds) > MAX_KEYS:
                self.arp_reply_seconds.clear()
            self.arp_reply_seconds[key] = n
            if n > self.arp_reply_peak.get(sha, (0, 0))[0]:
                self.arp_reply_peak[sha] = (n, index)

    def _llc(self, f: Frame, body: bytes, index: int) -> None:
        if body[:3] != b"\xaa\xaa\x03" or len(body) < 8:
            return
        pid = struct.unpack("!H", body[6:8])[0]
        name = {0x2004: "DTP", 0x2003: "VTP", 0x0104: "PAgP", 0x0111: "UDLD"}.get(pid)
        if name and body[3:6] == b"\x00\x00\x0c":
            e = self.layer2.setdefault(name, {"frames": 0, "first_frame": index, "senders": set()})
            e["frames"] += 1
            _add(e["senders"], mac_str(f.src))

    def _name(self, f: Frame, index: int) -> None:
        if f.proto and f.proto.split(" ")[0] in ("LLMNR", "NBNS"):
            e = self.name_proto.setdefault(f.proto.split(" ")[0], {"frames": 0, "first_frame": index, "senders": set()})
            e["frames"] += 1
            _add(e["senders"], mac_str(f.src))
        if f.name.lower().startswith("wpad"):
            self.wpad["count"] += 1
            self.wpad["first_frame"] = self.wpad["first_frame"] or index

    # ------------------------------------------------------------------ IP
    def _ipv4(self, f: Frame, b: bytes, vlan, ts: float, index: int) -> None:
        if len(b) < 20 or b[0] >> 4 != 4:
            return
        ihl = (b[0] & 0x0F) * 4
        frag = struct.unpack("!H", b[6:8])[0] & 0x1FFF
        if frag or len(b) < ihl:
            return
        proto, src, dst, l4 = b[9], ip4_str(b[12:16]), ip4_str(b[16:20]), b[ihl:]
        self._transport(f, proto, src, dst, l4, vlan, ts, index)
        if proto == 1 and l4[:1] == b"\x05":
            self._redirect(src, index)
        elif proto == 112 and len(l4) >= 6:
            self._fhrp("VRRP", src, f, vlan, index, auth="none" if (l4[0] >> 4 == 3 or l4[4] == 0) else "clear-text")
        elif proto == 89 and len(l4) >= 16:
            at = struct.unpack("!H", l4[14:16])[0]
            self._routing("OSPF", src, vlan, index, {0: "none", 1: "clear-text", 2: "cryptographic"}.get(at, "unknown"))
        elif proto == 88:
            self._routing("EIGRP", src, vlan, index, "unknown")
        elif proto == 103:
            self._routing("PIM", src, vlan, index, "unknown")

    def _ipv6(self, f: Frame, b: bytes, vlan, ts: float, index: int) -> None:
        if len(b) < 40 or b[0] >> 4 != 6:
            return
        nh, src, dst, l4 = b[6], _ip6_str(b[8:24]), _ip6_str(b[24:40]), b[40:]
        if nh == 58 and l4:
            if l4[0] == 134:
                self._ra(src, f, vlan, index, l4)
            elif l4[0] == 137:
                self._redirect(src, index)
            return
        self._transport(f, nh, src, dst, l4, vlan, ts, index)

    def _redirect(self, src: str, index: int) -> None:
        e = self.redirects.setdefault(src, {"frames": 0, "first_frame": index})
        e["frames"] += 1

    def _ra(self, src: str, f: Frame, vlan, index: int, l4: bytes) -> None:
        lifetime = struct.unpack("!H", l4[6:8])[0] if len(l4) >= 8 else 0
        key = (_vlan_key(vlan), f.src)
        if key not in self.ra and len(self.ra) >= MAX_KEYS:
            return
        e = self.ra.setdefault(key, {"ip": src, "mac": mac_str(f.src), "vlan": _vlan_key(vlan), "frames": 0,
                                     "first_frame": index, "router_lifetime": lifetime})
        e["frames"] += 1
        self._role(f.src, "IPv6 router")

    def _role(self, mac: bytes, role: str) -> None:
        if mac in self.hosts:
            self.hosts[mac]["roles"].add(role)

    def _fhrp(self, kind: str, src: str, f: Frame, vlan, index: int, auth: str) -> None:
        key = (kind, src)
        if key not in self.fhrp and len(self.fhrp) >= MAX_KEYS:
            return
        e = self.fhrp.setdefault(key, {"protocol": kind, "ip": src, "vlan": _vlan_key(vlan), "frames": 0,
                                       "first_frame": index, "auth": auth})
        e["frames"] += 1

    def _routing(self, kind: str, src: str, vlan, index: int, auth: str) -> None:
        key = (kind, src)
        if key not in self.routing and len(self.routing) >= MAX_KEYS:
            return
        e = self.routing.setdefault(key, {"protocol": kind, "ip": src, "vlan": _vlan_key(vlan), "frames": 0,
                                          "first_frame": index, "auth": auth})
        e["frames"] += 1

    def _service(self, name: str, kind: str, server: str, port, client, index: int, vlan, answered: bool = False) -> dict:
        key = (name, server, port)
        if key not in self.services:
            if len(self.services) >= MAX_KEYS:
                return {}
            self.services[key] = {"service": name, "kind": kind, "server": server, "port": port, "clients": set(),
                                  "frames": 0, "first_frame": index, "vlan": _vlan_key(vlan), "answered": False,
                                  "login_seen": False}
        e = self.services[key]
        e["frames"] += 1
        e["answered"] = e["answered"] or answered
        if client:
            _add(e["clients"], client, 32)
        return e

    def _transport(self, f: Frame, proto: int, src: str, dst: str, l4: bytes, vlan, ts: float, index: int) -> None:
        if proto == 6 and len(l4) >= 20:
            self._tcp(f, src, dst, l4, vlan, ts, index)
        elif proto == 17 and len(l4) >= 8:
            self._udp(f, src, dst, l4, vlan, ts, index)

    def _tcp(self, f: Frame, src: str, dst: str, l4: bytes, vlan, ts: float, index: int) -> None:
        sport, dport = struct.unpack("!HH", l4[:4])
        flags = l4[13]
        data = l4[(l4[12] >> 4) * 4:]
        attempt = flags & 0x12 == 0x02  # SYN without ACK: says nothing about whether the service exists
        if attempt:
            self.port_scan.add((src, dst), dport, ts, index)
            self.host_sweep.add((src, dport), dst, ts, index)
        if flags & 0x04:  # RST: the port is closed
            return
        for table, kind in ((CLEAR_TCP, "clear"), (OT_TCP, "ot")):
            if dport in table and not attempt:
                e = self._service(table[dport], kind, dst, dport, src, index, vlan)
                if kind == "clear" and e and data.upper().startswith(LOGIN_PREFIXES):
                    e["login_seen"] = True
            elif sport in table:
                self._service(table[sport], kind, src, sport, None, index, vlan, answered=True)
        if dport in HTTP_PORTS and not attempt:
            self._service("HTTP", "web", dst, dport, src, index, vlan)
            if b"\r\nauthorization: basic " in data[:4096].lower():
                e = self.http_basic.setdefault(dst, {"server": dst, "frames": 0, "first_frame": index})
                e["frames"] += 1
        elif sport in HTTP_PORTS:
            self._service("HTTP", "web", src, sport, None, index, vlan, answered=True)
        if 139 in (sport, dport) or 445 in (sport, dport):
            if data[4:8] == b"\xffSMB" and len(self.smb1) < MAX_KEYS:
                server = dst if dport in (139, 445) else src
                e = self.smb1.setdefault(server, {"server": server, "frames": 0, "first_frame": index})
                e["frames"] += 1
        if len(data) >= 11 and data[0] == 0x16 and data[5] == 0x02 and data[1] == 3:
            version = struct.unpack("!H", data[9:11])[0]
            if version in TLS_NAMES and len(self.tls_old) < MAX_KEYS:
                e = self.tls_old.setdefault((src, sport), {"server": src, "port": sport, "version": TLS_NAMES[version],
                                                           "frames": 0, "first_frame": index})
                e["frames"] += 1

    def _udp(self, f: Frame, src: str, dst: str, l4: bytes, vlan, ts: float, index: int) -> None:
        sport, dport = struct.unpack("!HH", l4[:4])
        data = l4[8:]
        if dport == 69:
            self._service("TFTP", "clear", dst, 69, src, index, vlan)
        elif dport == 514 or sport == 514:
            if dport == 514:
                self._service("Syslog over UDP", "clear", dst, 514, src, index, vlan)
        if dport in OT_UDP:
            self._service(OT_UDP[dport], "ot", dst, dport, src, index, vlan)
        elif sport in OT_UDP:
            self._service(OT_UDP[sport], "ot", src, sport, None, index, vlan, answered=True)
        if dport in (161, 162) or sport == 161:
            self._snmp(src, dst, sport, dport, data, vlan, index)
        if (sport == 67 or dport == 67) and len(data) >= 240:
            self._dhcp(f, src, data, vlan, ts, index)
        if sport == 547 and dport == 546 and data[:1] in (b"\x02", b"\x07"):
            key = (_vlan_key(vlan), f.src)
            if key in self.dhcp6 or len(self.dhcp6) < MAX_KEYS:
                e = self.dhcp6.setdefault(key, {"ip": src, "mac": mac_str(f.src), "vlan": _vlan_key(vlan), "frames": 0,
                                                "first_frame": index})
                e["frames"] += 1
                self._role(f.src, "DHCPv6 server")
        if dport in (1985, 2029):
            auth = "none"
            if dport == 1985 and len(data) >= 20:
                auth = "default" if data[12:20].rstrip(b"\0") == b"cisco" else "clear-text"
            elif dport == 2029:
                auth = "unknown"
            self._fhrp("HSRP", src, f, vlan, index, auth)
        elif dport == 3222:
            self._fhrp("GLBP", src, f, vlan, index, "unknown")
        elif dport == 520:
            self._routing("RIP", src, vlan, index, "unknown")
        if dport == 53 and len(data) > 12:
            self._dns(data, index)

    def _snmp(self, src: str, dst: str, sport: int, dport: int, data: bytes, vlan, index: int) -> None:
        # SEQUENCE { INTEGER version, OCTET STRING community, ...}; short-form lengths only are enough here.
        try:
            i = 2 if data[1] < 0x80 else 2 + (data[1] & 0x7F)
            if data[0] != 0x30 or data[i] != 0x02 or data[i + 1] != 1:
                return
            version = data[i + 2]
            if version not in (0, 1):
                return
            j = i + 3
            community = b""
            if data[j] == 0x04 and data[j + 1] < 0x80:
                community = bytes(data[j + 2 : j + 2 + data[j + 1]])
        except IndexError:
            return
        agent = src if sport == 161 else dst
        key = (agent, version)
        if key not in self.snmp and len(self.snmp) >= MAX_KEYS:
            return
        e = self.snmp.setdefault(key, {"agent": agent, "version": "v1" if version == 0 else "v2c", "frames": 0,
                                       "first_frame": index, "default_community": False, "vlan": _vlan_key(vlan)})
        e["frames"] += 1
        e["default_community"] = e["default_community"] or community.lower() in (b"public", b"private")

    def _dhcp(self, f: Frame, src: str, d: bytes, vlan, ts: float, index: int) -> None:
        if d[236:240] != b"\x63\x82\x53\x63":
            return
        opts = _options(d[240:])
        mtype = opts.get(53, b"\0")[0]
        chaddr = d[28:34]
        if mtype == 1:
            self.dhcp_clients.add(_vlan_key(vlan), chaddr, ts, index)
        if 12 in opts and chaddr in self.hosts:
            _add(self.hosts[chaddr]["names"], opts[12].decode("ascii", "replace")[:64].rstrip("\0"), 8)
        if mtype in (2, 5, 6):
            sid = ip4_str(opts[54][:4]) if len(opts.get(54, b"")) >= 4 else src
            key = (_vlan_key(vlan), sid)
            if key in self.dhcp_servers or len(self.dhcp_servers) < MAX_KEYS:
                e = self.dhcp_servers.setdefault(key, {"server": sid, "mac": mac_str(f.src), "vlan": _vlan_key(vlan),
                                                       "offers": 0, "acks": 0, "naks": 0, "first_frame": index,
                                                       "router": None, "dns": None})
                e[{2: "offers", 5: "acks", 6: "naks"}[mtype]] += 1
                if len(opts.get(3, b"")) >= 4:
                    e["router"] = ip4_str(opts[3][:4])
                    _add(self.dhcp_routers, opts[3][:4])
                if len(opts.get(6, b"")) >= 4:
                    e["dns"] = ip4_str(opts[6][:4])
                self._role(f.src, "DHCP server")

    def _dns(self, data: bytes, index: int) -> None:
        if data[2] & 0x80:
            return
        try:
            name = _dns_name(data, 12)
        except (IndexError, ValueError, UnicodeDecodeError, struct.error):
            return
        parts = name.rstrip(".").split(".")
        if len(parts) >= 3 and max(len(p) for p in parts[:-2]) >= DNS_LONG_LABEL:
            dom = ".".join(parts[-2:])
            if dom in self.dns_long or len(self.dns_long) < MAX_KEYS:
                e = self.dns_long.setdefault(dom, {"domain": dom, "queries": 0, "first_frame": index})
                e["queries"] += 1

    # ------------------------------------------------------------- summary
    def observed_vantage(self) -> str:
        """Best guess from traffic: 'span' sees unicast between other hosts; 'trunk' sees several VLANs tagged."""
        busy = [n for n in self.unicast_dsts.values() if n >= 20]
        top = max(self.unicast_dsts.values(), default=0)
        if len(busy) >= 4 and self.unicast and top / self.unicast < 0.8:
            return "span"
        tagged_vlans = [k for k in self.vlans if k != "untagged"]
        if self.frames and self.tagged / self.frames >= 0.02 and tagged_vlans:
            return "trunk"
        return "access"

    def summary(self) -> dict:
        def listing(d):
            out = []
            for v in d.values():
                v = dict(v)
                for k in ("clients", "senders"):
                    if k in v:
                        v[k] = sorted(v[k])
                out.append(v)
            return sorted(out, key=lambda e: e.get("first_frame") or 0)

        hosts = []
        for h in sorted(self.hosts.values(), key=lambda x: -x["frames"]):
            hosts.append({**h, "ips": sorted(h["ips"]), "names": sorted(h["names"]), "vlans": sorted(h["vlans"]),
                          "roles": sorted(h["roles"]), "protocols": [p for p, _n in h["protocols"].most_common(4)]})
        layer2 = {k: {**v, "senders": sorted(v["senders"])} for k, v in self.layer2.items()}
        many_ips = [{"mac": mac_str(m), "ips": len(s)} for m, s in self.arp_claims.items() if len(s) >= ARP_MANY_IPS]
        gateways = sorted(ip4_str(k) for k in self.dhcp_routers) or [
            ip4_str(k) for k, _n in self.gateways.most_common(1) if any(k)]

        def peaks(counter, limit, label):
            out = []
            for key, (n, idx) in counter.peak.items():
                if n >= limit:
                    out.append(label(key, n, idx))
            return sorted(out, key=lambda e: -e["count"])[:20]

        return {
            "frames": self.frames, "observed_vantage": self.observed_vantage(),
            "tagged_frames": self.tagged, "vlans": dict(self.vlans),
            "multi_tagged": {"frames": self.multi_tagged, "first_frame": self.multi_tag_first},
            "services": listing(self.services), "layer2_protocols": layer2,
            "snmp": listing(self.snmp), "http_basic": listing(self.http_basic), "tls_old": listing(self.tls_old),
            "smb1": listing(self.smb1), "dhcp_servers": listing(self.dhcp_servers),
            "dhcp_starvation": peaks(self.dhcp_clients, DHCP_STARVE_CLIENTS,
                                     lambda k, n, i: {"vlan": k, "count": n, "first_frame": i}),
            "router_advertisers": listing(self.ra), "dhcpv6_servers": listing(self.dhcp6),
            "redirects": [{"source": k, **v} for k, v in self.redirects.items()],
            "fhrp": listing(self.fhrp), "routing": listing(self.routing),
            "name_protocols": {k: {**v, "senders": sorted(v["senders"])} for k, v in self.name_proto.items()},
            "wpad": self.wpad, "dot1x_frames": self.dot1x,
            "gateways": gateways, "arp_many_ips": many_ips,
            "arp_reply_bursts": sorted(({"mac": mac_str(m), "count": n, "first_frame": i}
                                        for m, (n, i) in self.arp_reply_peak.items() if n >= ARP_REPLY_BURST_PER_S),
                                       key=lambda e: -e["count"])[:20],
            "arp_sweeps": peaks(self.arp_sweep, SWEEP_HOSTS,
                                lambda k, n, i: {"mac": mac_str(k), "count": n, "first_frame": i}),
            "port_scans": peaks(self.port_scan, SCAN_PORTS,
                                lambda k, n, i: {"source": k[0], "target": k[1], "count": n, "first_frame": i}),
            "host_sweeps": peaks(self.host_sweep, SWEEP_HOSTS,
                                 lambda k, n, i: {"source": k[0], "port": k[1], "count": n, "first_frame": i}),
            "mac_flood": {"new_macs_peak": self.mac_flood_peak[0], "first_frame": self.mac_flood_peak[1],
                          "window_s": MAC_FLOOD_WINDOW_S, "suspected": self.mac_flood_peak[0] >= MAC_FLOOD_NEW},
            "distinct_macs": len(self.mac_seen),
            "dns_long_names": sorted((e for e in self.dns_long.values() if e["queries"] >= DNS_TUNNEL_QUERIES),
                                     key=lambda e: -e["queries"])[:10],
            "hosts": hosts[:500], "hosts_total": len(self.hosts),
        }


def _options(b: bytes) -> dict:
    out, i = {}, 0
    while i < len(b):
        code = b[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        if i + 1 >= len(b):
            break
        n = b[i + 1]
        out.setdefault(code, bytes(b[i + 2 : i + 2 + n]))
        i += 2 + n
    return out


# ---------------------------------------------------------------- findings
def _f(sev, code, title, observed, hypothesis=None, recommendation=None, frames=None, confidence="observed"):
    return {"severity": sev, "code": code, "title": title, "observed": observed, "hypothesis": hypothesis,
            "recommendation": recommendation, "frames": [x for x in (frames or []) if x], "category": "security",
            "confidence": confidence}


def _names(items, key, limit=6) -> str:
    vals = [str(i[key]) for i in items]
    return ", ".join(vals[:limit]) + (f" and {len(vals) - limit} more" if len(vals) > limit else "")


def _svc(e: dict) -> str:
    return f"{e['server']}" + (f":{e['port']}" if e.get("port") else "")


def _by_vlan(items: list) -> dict:
    out: dict = {}
    for i in items:
        out.setdefault(i["vlan"], []).append(i)
    return out


def security_findings(s: dict, duplicate_ips: list, neighbours: list, stp: dict, vantage: str,
                      declared: Optional[str] = None) -> list:
    out = []
    # ---- Active-attack indicators
    for d in duplicate_ips:
        if d["ip"] in s.get("gateways", []):
            out.append(_f("critical", "gateway-spoof", f"Default gateway {d['ip']} is claimed by more than one device",
                          f"{d['ip']} was announced by {_names(d['macs'], 'mac')}.",
                          "ARP spoofing (a man-in-the-middle position) or a misconfigured device answering for the gateway.",
                          "Check both MACs on the switch immediately. Enable Dynamic ARP Inspection with DHCP snooping.",
                          [m["first_frame"] for m in d["macs"]], "inferred"))
    for e in s["arp_reply_bursts"][:3]:
        out.append(_f("high", "arp-reply-burst", f"Burst of ARP replies from {e['mac']}",
                      f"{e['count']} ARP replies in one second.",
                      "ARP poisoning tools send replies continuously; a misbehaving device can look the same.",
                      "Identify the device and enable Dynamic ARP Inspection.", [e["first_frame"]], "inferred"))
    for e in s["arp_many_ips"][:3]:
        out.append(_f("warning", "arp-many-ips", f"{e['mac']} claims {e['ips']} IP addresses",
                      f"This MAC was the ARP sender for {e['ips']} different IPv4 addresses.",
                      "Proxy ARP on a router or firewall is the usual cause; spoofing is the other.",
                      "Confirm this device is a router or firewall.", confidence="inferred"))
    m = s["mac_flood"]
    if m["suspected"]:
        out.append(_f("high", "mac-flood", "Possible MAC flooding",
                      f"{m['new_macs_peak']} new source MACs appeared within {m['window_s']:.0f} s.",
                      "A CAM-table overflow attack, or a loop or test tool generating random sources.",
                      "Enable port security or MAC limits on access ports.", [m["first_frame"]], "inferred"))
    for vlan, servers in _by_vlan(s["dhcp_servers"]).items():
        if len(servers) >= 2:
            out.append(_f("high", "rogue-dhcp", f"More than one DHCP server answering in VLAN {vlan}",
                          f"Servers: {_names(servers, 'server')}.",
                          "One may be rogue, handing out a wrong gateway or DNS server. Redundant DHCP is the benign explanation.",
                          "Confirm each server is authorised, and enable DHCP snooping.",
                          [x["first_frame"] for x in servers], "inferred"))
    for e in s["dhcp_starvation"][:3]:
        out.append(_f("high", "dhcp-starvation", f"DHCP starvation pattern in VLAN {e['vlan']}",
                      f"{e['count']} different client MACs sent DHCP Discover within 60 s.",
                      "An attacker exhausting the pool, or many devices booting after a power event.",
                      "Enable DHCP snooping with a rate limit.", [e["first_frame"]], "inferred"))
    for vlan, routers in _by_vlan(s["router_advertisers"]).items():
        if len(routers) >= 2:
            out.append(_f("high", "rogue-ra", f"More than one IPv6 router advertising in VLAN {vlan}",
                          f"Router Advertisements from {_names(routers, 'mac')}.",
                          "A rogue RA can redirect IPv6 traffic, even on a network believed to be IPv4-only.",
                          "Confirm each router, and enable RA Guard on access ports.",
                          [x["first_frame"] for x in routers], "inferred"))
    if len(s["dhcpv6_servers"]) >= 1:
        out.append(_f("warning", "dhcpv6-server", "DHCPv6 server answering on this segment",
                      f"From {_names(s['dhcpv6_servers'], 'mac')}.",
                      "Expected only if IPv6 is deployed. Otherwise this is the pattern of an IPv6 takeover tool.",
                      "Confirm the server is authorised, and enable DHCPv6 Guard.",
                      [x["first_frame"] for x in s["dhcpv6_servers"]], "inferred"))
    if s["redirects"]:
        out.append(_f("warning", "icmp-redirect", "ICMP redirects seen",
                      f"From {_names(s['redirects'], 'source')}.",
                      "Redirects can steer traffic through an attacker. Some routers send them legitimately.",
                      "Disable ICMP redirects on routers and hosts where not needed.",
                      [x["first_frame"] for x in s["redirects"]], "inferred"))
    for e in s["port_scans"][:3]:
        out.append(_f("high", "port-scan", f"{e['source']} scanned ports on {e['target']}",
                      f"{e['count']} different TCP ports within 60 s.",
                      "A port scan: an authorised scanner, or reconnaissance.",
                      "Identify the source and confirm whether the scan was authorised.", [e["first_frame"]], "inferred"))
    for e in s["host_sweeps"][:3]:
        out.append(_f("high", "host-sweep", f"{e['source']} probed TCP port {e['port']} across many hosts",
                      f"{e['count']} different targets within 60 s.",
                      "A scanner, or a worm spreading.",
                      "Identify the source and confirm whether this was authorised.", [e["first_frame"]], "inferred"))
    for e in s["arp_sweeps"][:3]:
        out.append(_f("warning", "arp-sweep", f"{e['mac']} ARP-swept the subnet",
                      f"ARP requests for {e['count']} different addresses within 60 s.",
                      "Network discovery. Monitoring systems and routers do this too.",
                      "Confirm what this device is.", [e["first_frame"]], "inferred"))
    for e in s["dns_long_names"]:
        out.append(_f("warning", "dns-tunnel", f"Unusually long DNS names under {e['domain']}",
                      f"{e['queries']} queries with labels of {DNS_LONG_LABEL}+ characters.",
                      "A DNS tunnel can carry data this way. Some security and CDN products do too.",
                      "Check which host is making these queries.", [e["first_frame"]], "inferred"))

    # ---- Layer-2 hardening
    dtp = s["layer2_protocols"].get("DTP")
    if dtp:
        out.append(_f("high", "dtp-enabled", "This port speaks DTP (trunk negotiation)",
                      f"{dtp['frames']} DTP frames from {', '.join(dtp['senders'][:3])}.",
                      "A device on this port may be able to negotiate a trunk and reach every VLAN (VLAN hopping).",
                      "Set access ports to 'switchport mode access' and 'switchport nonegotiate'.", [dtp["first_frame"]]))
    if s["multi_tagged"]["frames"]:
        out.append(_f("warning", "double-tagged", "Double-tagged frames seen",
                      f"{s['multi_tagged']['frames']} frames carried two or more VLAN tags.",
                      "Normal on a QinQ provider link. On an enterprise port it is the signature of VLAN hopping.",
                      "Confirm QinQ is expected here, and do not use VLAN 1 as a native VLAN.",
                      [s["multi_tagged"]["first_frame"]], "inferred"))
    tagged_vlans = sorted(k for k in s["vlans"] if k != "untagged")
    if declared == "access" and tagged_vlans:
        out.append(_f("high", "access-sees-vlans", "An access port is receiving tagged VLAN traffic",
                      f"VLANs seen: {', '.join(tagged_vlans[:12])}.",
                      "This port was described as an access port but behaves as a trunk, exposing other VLANs.",
                      "Confirm the port configuration. Access ports should carry one untagged VLAN."))
    elif s["observed_vantage"] == "trunk" and declared not in ("span", "trunk"):
        out.append(_f("warning", "trunk-port", "This port carries several VLANs",
                      f"VLANs seen: {', '.join(tagged_vlans[:12])}.",
                      "A device plugged in here can read every one of those VLANs.",
                      "If this is not an uplink, restrict it to a single access VLAN."))
    if stp.get("seen") and vantage == "access":
        out.append(_f("low", "bpdu-at-edge", "Spanning-tree BPDUs reach this access port",
                      f"{stp['bpdus']} BPDUs received.",
                      "Normal, but the port's protection against a device sending BPDUs cannot be seen from here.",
                      "Enable BPDU guard on edge ports and root guard towards access switches.", confidence="inferred"))
    if neighbours:
        leaky = [n for n in neighbours if n.get("mgmt_ip") or n.get("platform")]
        if leaky:
            n = leaky[0]
            out.append(_f("low", "neighbour-leak", "Switch details are broadcast to this port",
                          f"LLDP/CDP reveals {len(leaky)} device(s), e.g. {n['system_name'] or n['chassis']}"
                          + (f", management IP {n['mgmt_ip']}" if n.get("mgmt_ip") else "")
                          + (f", platform {n['platform']}" if n.get("platform") else "") + ".",
                          "Anyone plugged in here learns the device model and management address.",
                          "Disable CDP/LLDP on user-facing ports where the features are not needed.",
                          [n["first_frame"]]))
    for key, label, weak in (("fhrp", "gateway redundancy", "takeover of the default gateway"),
                             ("routing", "routing", "route injection")):
        exposed = [e for e in s[key] if e["auth"] in ("none", "default", "clear-text")]
        if exposed:
            kinds = sorted({e["protocol"] for e in exposed})
            default = any(e["auth"] == "default" for e in exposed)
            out.append(_f("high" if default else "warning", f"{key}-exposed",
                          f"{'/'.join(kinds)} {label} traffic reaches this port without strong authentication",
                          f"Speakers: {_names(exposed, 'ip')}. Authentication: "
                          f"{', '.join(sorted({e['auth'] for e in exposed}))}.",
                          f"A device on this port could attempt {weak}.",
                          "Use cryptographic authentication and do not expose these protocols on user ports.",
                          [e["first_frame"] for e in exposed[:5]], "inferred"))
    llmnr = [k for k in ("LLMNR", "NBNS") if k in s["name_protocols"]]
    if llmnr:
        senders = sorted({m for k in llmnr for m in s["name_protocols"][k]["senders"]})
        out.append(_f("warning", "name-poisoning", f"{' and '.join(llmnr)} in use",
                      f"{len(senders)} device(s) send these name lookups.",
                      "An attacker can answer these to capture Windows credentials.",
                      "Disable LLMNR and NetBIOS over TCP/IP by policy.",
                      [s["name_protocols"][k]["first_frame"] for k in llmnr]))
    if s["wpad"]["count"]:
        out.append(_f("warning", "wpad", "WPAD proxy discovery lookups seen",
                      f"{s['wpad']['count']} lookups for a WPAD name.",
                      "An attacker who answers can become the web proxy for that host.",
                      "Disable automatic proxy discovery, or define WPAD explicitly in DNS.", [s["wpad"]["first_frame"]]))

    # ---- Exposed services
    clear = [e for e in s["services"] if e["kind"] == "clear" and e["service"] != "Syslog over UDP"]
    logins = [e for e in clear if e["login_seen"]]
    if logins:
        out.append(_f("critical", "cleartext-login", "Logins sent in clear text",
                      f"Clear-text login commands seen to: {', '.join(e['service'] + ' ' + _svc(e) for e in logins[:6])}. "
                      "The credentials themselves were not stored.",
                      "Anyone able to see this traffic can read the password.",
                      "Change those passwords and move to SSH, SFTP or TLS.", [e["first_frame"] for e in logins[:5]]))
    other = [e for e in clear if not e["login_seen"]]
    if other:
        out.append(_f("high", "cleartext-service", "Clear-text management or file services in use",
                      "; ".join(f"{e['service']} {_svc(e)}" for e in other[:8]) + (" and more" if len(other) > 8 else "") + ".",
                      None, "Replace with SSH, SFTP, or TLS-protected versions, or restrict access.",
                      [e["first_frame"] for e in other[:5]]))
    if s["http_basic"]:
        out.append(_f("critical", "http-basic", "Passwords sent over plain HTTP",
                      f"HTTP Basic authentication to {_names(s['http_basic'], 'server')}. Header values were not stored.",
                      "Basic authentication is only encoded, so the password is readable.",
                      "Move this service to HTTPS and change the password.",
                      [e["first_frame"] for e in s["http_basic"][:5]]))
    defaults = [e for e in s["snmp"] if e["default_community"]]
    if defaults:
        out.append(_f("high", "snmp-default", "SNMP uses a default community string",
                      f"Agents: {_names(defaults, 'agent')}.",
                      "Default communities allow anyone to read device configuration, and sometimes change it.",
                      "Change the community strings now and move to SNMPv3.", [e["first_frame"] for e in defaults[:5]]))
    plain = [e for e in s["snmp"] if not e["default_community"]]
    if plain:
        out.append(_f("warning", "snmp-v12", "SNMP v1/v2c in use",
                      f"Agents: {_names(plain, 'agent')}.", "The community string travels in clear text.",
                      "Move to SNMPv3 with authentication and privacy.", [e["first_frame"] for e in plain[:5]]))
    if s["smb1"]:
        out.append(_f("high", "smb1", "SMBv1 in use",
                      f"Hosts: {_names(s['smb1'], 'server')}.", "SMBv1 is obsolete and has wormable vulnerabilities.",
                      "Disable SMBv1 and update the devices that need it.", [e["first_frame"] for e in s["smb1"][:5]]))
    if s["tls_old"]:
        out.append(_f("warning", "tls-old", "Obsolete TLS or SSL versions negotiated",
                      "; ".join(f"{e['version']} on {e['server']}:{e['port']}" for e in s["tls_old"][:8]) + ".",
                      None, "Require TLS 1.2 or newer.", [e["first_frame"] for e in s["tls_old"][:5]]))
    ot = [e for e in s["services"] if e["kind"] == "ot"]
    if ot:
        kinds = sorted({e["service"] for e in ot})
        out.append(_f("warning", "ot-exposed", "Unauthenticated building or industrial protocols on this segment",
                      f"{', '.join(kinds)}: {len(ot)} endpoint(s), e.g. "
                      + ", ".join(_svc(e) for e in ot[:5]) + ".",
                      "These protocols generally have no authentication; a device here may read or write controllers.",
                      "Separate OT from IT networks and restrict access to these endpoints.",
                      [e["first_frame"] for e in ot[:5]]))
    web = [e for e in s["services"] if e["kind"] == "web" and e["answered"]]
    if web:
        out.append(_f("info", "http-plain", "Unencrypted web interfaces in use",
                      f"{_names(web, 'server')}.", None, "Use HTTPS for device management.",
                      [e["first_frame"] for e in web[:5]]))
    return out


def coverage(s: dict, vantage: str, packets: int) -> list:
    """Which checks this capture could actually answer, so that silence is not read as a clean bill of health."""
    if not packets:
        return [{"check": "All checks", "status": "not_performed", "reason": "No frames were captured."}]
    full = vantage in ("span",)
    flooded = "Works from any port: this traffic is flooded."
    unicast_reason = ("Seen from a mirror port." if full else
                      "Limited: an access port only sees this computer's own unicast traffic. Mirror the switch "
                      "uplink (SPAN) to check other hosts.")
    rows = [
        ("ARP spoofing and duplicate IPs", "performed", flooded),
        ("Rogue DHCP and starvation", "performed", "DHCP offers are often broadcast or unicast to the client; a rogue "
                                                   "offer to another host can be missed from an access port."),
        ("Rogue IPv6 Router Advertisements", "performed", flooded),
        ("Spanning-tree stability and attacks", "performed", flooded),
        ("LLMNR, NBT-NS and WPAD", "performed", flooded),
        ("Trunk negotiation (DTP), VLAN exposure", "performed" if vantage != "span" else "limited",
         "Depends on the port itself." if vantage != "span" else "A mirror port does not show its own trunk negotiation."),
        ("Clear-text logins and services", "performed" if full else "limited", unicast_reason),
        ("SNMP communities and SMBv1", "performed" if full else "limited", unicast_reason),
        ("TLS versions", "performed" if full else "limited", unicast_reason),
        ("Port scans between other hosts", "performed" if full else "limited", unicast_reason),
        ("Building and industrial protocols", "performed" if full else "limited", unicast_reason),
    ]
    rows.append(("802.1X port authentication", "performed" if s.get("dot1x_frames") else "limited",
                 "802.1X traffic seen." if s.get("dot1x_frames") else
                 "No 802.1X frames seen; the port may be open, or authentication finished before the capture started."))
    return [{"check": c, "status": st, "reason": why} for c, st, why in rows]
