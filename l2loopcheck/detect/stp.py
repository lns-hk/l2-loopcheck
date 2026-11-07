"""Spanning-tree analysis: STP, RSTP, MSTP and Cisco PVST+.

Findings produced:
* which root bridge(s) are announced, per PVST+ VLAN or for the CIST;
* root changes over time (re-elections);
* topology-change activity (TC flag rising edges and TCN BPDUs);
* several roots claimed at the same time (the tree is split, often by a device
  that drops BPDUs, such as some unmanaged switches);
* mixed protocol versions and more than one MST region configuration;
* no BPDUs at all, which on a network with redundant links means nothing
  stops a loop.
"""

from __future__ import annotations

from ..decode import Bpdu, mac_str

SPLIT_WINDOW = 10.0  # seconds: distinct roots announced within this window = split


class StpDetector:
    def __init__(self) -> None:
        self.bpdus = 0
        self.kinds: dict[str, int] = {}
        self.senders: dict[str, dict] = {}
        self.roots: dict[str, dict] = {}  # key -> root_id -> info
        self.root_timeline: dict[str, list] = {}  # key -> [(ts, root_id, frame)]
        self.tc_events: list[dict] = []
        self.tcn_count = 0
        self.regions: dict[tuple, dict] = {}
        self._tc_state: dict[tuple, bool] = {}
        self.first_ts = None
        self.last_ts = None

    def feed(self, ts: float, index: int, b: Bpdu, src: bytes, vlans: tuple) -> None:
        self.bpdus += 1
        self.first_ts = ts if self.first_ts is None else self.first_ts
        self.last_ts = ts
        self.kinds[b.kind] = self.kinds.get(b.kind, 0) + 1
        sender = mac_str(src)
        s = self.senders.setdefault(sender, {"mac": sender, "count": 0, "kinds": set(), "bridge_id": None,
                                             "root_cost": None, "first_frame": index})
        s["count"] += 1
        s["kinds"].add(b.kind)
        if b.kind == "TCN":
            self.tcn_count += 1
            self.tc_events.append({"ts": ts, "frame": index, "sender": sender, "kind": "TCN"})
            return
        s["bridge_id"] = b.bridge_id
        s["root_cost"] = b.root_cost
        key = f"VLAN {b.vlan}" if b.vlan is not None else (f"VLAN {vlans[-1]}" if vlans and b.kind.startswith("PVST") else "CIST")
        info = self.roots.setdefault(key, {}).setdefault(b.root_id, {
            "root_id": b.root_id, "first_ts": ts, "last_ts": ts, "count": 0, "first_frame": index,
            "announced_by": set(),
        })
        info["last_ts"] = ts
        info["count"] += 1
        info["announced_by"].add(b.bridge_id)
        tl = self.root_timeline.setdefault(key, [])
        if not tl or tl[-1][1] != b.root_id:
            tl.append((ts, b.root_id, index))
        tc_key = (sender, b.port_id, key)
        prev = self._tc_state.get(tc_key, False)
        if b.tc and not prev:
            self.tc_events.append({"ts": ts, "frame": index, "sender": sender, "kind": "TC", "bridge_id": b.bridge_id})
        self._tc_state[tc_key] = b.tc
        if b.mst_region is not None:
            rk = (b.mst_region, b.mst_revision, b.mst_digest)
            r = self.regions.setdefault(rk, {"name": b.mst_region, "revision": b.mst_revision,
                                             "digest": b.mst_digest, "bridges": set(), "first_frame": index})
            r["bridges"].add(b.bridge_id)

    def summary(self, duration: float) -> dict:
        roots_out = {}
        root_changes = 0
        split = []
        for key, rmap in self.roots.items():
            roots_out[key] = sorted(
                ({**v, "announced_by": sorted(v["announced_by"])} for v in rmap.values()),
                key=lambda v: -v["count"])
            tl = self.root_timeline.get(key, [])
            changes = [
                {"ts": tl[i][0], "from": tl[i - 1][1], "to": tl[i][1], "frame": tl[i][2]}
                for i in range(1, len(tl))
            ]
            # Alternating announcements of two roots in a short window = split tree,
            # not a re-election; count only changes where the old root stops appearing.
            overlapping = _overlapping_roots(list(rmap.values()))
            if overlapping:
                split.append({"scope": key, "roots": overlapping})
            else:
                root_changes += len(changes)
        tc_rate = (len(self.tc_events) / duration * 60) if duration > 0 else 0.0
        senders = sorted(
            ({**v, "kinds": sorted(v["kinds"])} for v in self.senders.values()), key=lambda v: -v["count"])
        return {
            "bpdus": self.bpdus,
            "seen": self.bpdus > 0,
            "kinds": self.kinds,
            "mixed_versions": len({k.replace("PVST+ ", "") for k in self.kinds if k != "TCN"}) > 1,
            "roots": roots_out,
            "root_changes": root_changes,
            "split_trees": split,
            "tc_events": len(self.tc_events),
            "tc_per_minute": round(tc_rate, 2),
            "tc_examples": self.tc_events[:20],
            "tcn_bpdus": self.tcn_count,
            "senders": senders[:20],
            "mst_regions": [{**r, "bridges": sorted(r["bridges"])} for r in self.regions.values()],
        }


def _overlapping_roots(infos: list[dict]) -> list[str]:
    """Roots whose announcement periods overlap by more than SPLIT_WINDOW."""
    if len(infos) < 2:
        return []
    out = set()
    for i, a in enumerate(infos):
        for b in infos[i + 1:]:
            overlap = min(a["last_ts"], b["last_ts"]) - max(a["first_ts"], b["first_ts"])
            if overlap > SPLIT_WINDOW and a["count"] >= 3 and b["count"] >= 3:
                out.update((a["root_id"], b["root_id"]))
    return sorted(out)
