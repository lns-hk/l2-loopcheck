"""Broadcast / multicast composition, top talkers, storm-control clipping,
duplicate IP addresses and LLDP/CDP neighbours."""

from __future__ import annotations

from ..decode import Frame, Neighbour, ip4_str, is_virtual_router_mac, mac_str


class TrafficDetector:
    def __init__(self) -> None:
        self.total = 0
        self.bcast = 0
        self.mcast = 0
        self.by_proto: dict[str, dict] = {}
        self.talkers: dict[bytes, dict] = {}
        self.vlans: dict[int, int] = {}
        self.subnets: dict[str, set] = {}  # vlan label -> /16 prefixes seen in ARP

    def feed(self, f: Frame, index: int, is_copy: bool = False) -> None:
        self.total += 1
        if f.vlans:
            v = f.vlans[-1]
            self.vlans[v] = self.vlans.get(v, 0) + 1
        if not (f.bcast or f.mcast):
            return
        if f.bcast:
            self.bcast += 1
        else:
            self.mcast += 1
        p = self.by_proto.setdefault(f.proto, {"proto": f.proto, "frames": 0, "bcast": 0, "mcast": 0})
        p["frames"] += 1
        p["bcast" if f.bcast else "mcast"] += 1
        t = self.talkers.get(f.src)
        if t is None:
            t = self.talkers[f.src] = {"mac": mac_str(f.src), "frames": 0, "ips": set(), "protos": {},
                                       "names": set(), "first_frame": index, "copies": 0}
        t["frames"] += 1
        if is_copy:
            t["copies"] += 1
        t["protos"][f.proto] = t["protos"].get(f.proto, 0) + 1
        if f.ip_src and f.ip_src != b"\0\0\0\0" and len(t["ips"]) < 8:
            t["ips"].add(ip4_str(f.ip_src))
        if f.arp and f.arp[2] != b"\0\0\0\0" and len(t["ips"]) < 8:
            t["ips"].add(ip4_str(f.arp[2]))
        if f.name and len(t["names"]) < 5:
            t["names"].add(f.name)
        if f.arp:
            key = f"VLAN {f.vlans[-1]}" if f.vlans else "untagged"
            spa = f.arp[2]
            if spa != b"\0\0\0\0":
                self.subnets.setdefault(key, set()).add(f"{spa[0]}.{spa[1]}.0.0/16")

    def summary(self, duration: float) -> dict:
        flooded = self.bcast + self.mcast
        talkers = sorted(self.talkers.values(), key=lambda t: -t["frames"])[:15]
        out_talkers = []
        for t in talkers:
            out_talkers.append({
                "mac": t["mac"], "frames": t["frames"],
                "share": round(t["frames"] / flooded, 4) if flooded else 0.0,
                "pps": round(t["frames"] / duration, 1) if duration > 0 else 0.0,
                "ips": sorted(t["ips"]), "names": sorted(t["names"]),
                "top_protocols": sorted(t["protos"].items(), key=lambda kv: -kv[1])[:3],
                "first_frame": t["first_frame"],
                "copy_share": round(t["copies"] / t["frames"], 4) if t["frames"] else 0.0,
            })
        protos = sorted(self.by_proto.values(), key=lambda p: -p["frames"])
        for p in protos:
            p["pps"] = round(p["frames"] / duration, 1) if duration > 0 else 0.0
            p["share"] = round(p["frames"] / flooded, 4) if flooded else 0.0
        return {
            "frames": self.total,
            "broadcast": self.bcast,
            "multicast": self.mcast,
            "flooded_pps": round(flooded / duration, 1) if duration > 0 else 0.0,
            "by_protocol": protos[:20],
            "top_talkers": out_talkers,
            "vlans": dict(sorted(self.vlans.items())),
            "subnets_by_vlan": {k: sorted(v) for k, v in self.subnets.items()},
        }


def storm_control_clipping(series: list[dict], key: str = "flooded") -> dict:
    """Detect the saw-tooth pattern left by storm control.

    Storm control drops flooded traffic once a port exceeds its threshold, so a
    capture shows flooded rate climbing to a plateau, collapsing to near zero,
    then climbing again. Two or more such cliffs are reported as a hypothesis.
    """
    cliffs = []
    for i in range(1, len(series)):
        prev, cur = series[i - 1][key], series[i][key]
        if prev >= 500 and cur <= prev * 0.05:
            cliffs.append({"t": series[i]["t"], "before_pps": prev, "after_pps": cur})
    plateau = max((s[key] for s in series), default=0)
    return {"cliffs": cliffs[:20], "cliff_count": len(cliffs), "peak_pps": plateau,
            "suspected": len(cliffs) >= 2}


class DuplicateIpDetector:
    """IPv4 address conflicts from ARP (RFC 5227 semantics).

    An address is in conflict when two different hardware addresses claim it as
    sender protocol address. ARP probes (sender IP 0.0.0.0) are ignored, and
    VRRP/HSRP/GLBP virtual MACs are excluded because sharing is their purpose.
    """

    def __init__(self) -> None:
        self.claims: dict[bytes, dict[bytes, dict]] = {}

    def feed(self, f: Frame, index: int, ts: float) -> None:
        if not f.arp:
            return
        _op, sha, spa, _tha, _tpa = f.arp
        if spa[0] in (0, 127) or (spa[0] == 169 and spa[1] == 254) or is_virtual_router_mac(sha):
            return
        m = self.claims.setdefault(spa, {})
        c = m.get(sha)
        if c is None:
            m[sha] = {"mac": mac_str(sha), "count": 1, "first_frame": index, "first_ts": ts}
        else:
            c["count"] += 1

    def summary(self) -> list[dict]:
        out = []
        for ip, macs in self.claims.items():
            if len(macs) >= 2:
                out.append({"ip": ip4_str(ip), "macs": sorted(macs.values(), key=lambda c: c["first_frame"])})
        return sorted(out, key=lambda d: d["ip"])


class NeighbourCollector:
    def __init__(self) -> None:
        self.items: dict[tuple, dict] = {}

    def feed(self, n: Neighbour, index: int, src: bytes, vlans: tuple) -> None:
        key = (n.protocol, n.chassis, n.port)
        d = self.items.get(key)
        if d is None:
            self.items[key] = {
                "protocol": n.protocol, "system_name": n.system_name, "chassis": n.chassis,
                "port": n.port, "port_desc": n.port_desc, "platform": n.platform,
                "system_desc": n.system_desc, "mgmt_ip": n.mgmt_ip, "native_vlan": n.native_vlan,
                "src_mac": mac_str(src), "vlan": vlans[-1] if vlans else None,
                "count": 1, "first_frame": index,
            }
        else:
            d["count"] += 1

    def summary(self) -> list[dict]:
        return sorted(self.items.values(), key=lambda d: d["first_frame"])
