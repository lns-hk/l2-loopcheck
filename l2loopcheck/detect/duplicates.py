"""Duplicate / replayed frame detection.

A frame circulating in a Layer-2 loop reappears byte-for-byte (VLAN tags
aside) at a short, roughly constant interval: the time it takes to travel once
round the loop. Several facts follow and are used here:

* Copies arrive within milliseconds. Legitimate protocol retries (ARP after
  ~1 s, mDNS probes 250 ms apart) are slower, so only copies within
  ``WINDOW`` seconds count.
* A loop circulates *every* flooded frame, so frames from many unrelated
  sources repeat with the *same* period. One chatty host cannot produce that.
  This "common period" across distinct sources is the loop fingerprint.
* A SPAN session mirroring both directions of a link produces exactly two
  copies of every frame, including ordinary unicast TCP, microseconds apart.
  That artefact is detected and reported instead of being called a loop.
* The IP TTL is not used as primary evidence: many flooded protocols (mDNS,
  link-local) always use TTL 255, so an unchanged TTL proves little.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from statistics import median
from typing import Optional

from ..decode import Frame, mac_str

WINDOW = 0.2  # seconds: max gap between copies to count as a replay
PRUNE_EVERY = 2000  # frames between table pruning passes
SPAN_GAP = 0.0001  # 100 µs: copies this close are typical of SPAN mirroring
MIN_SOURCES_FOR_LOOP = 3  # distinct sources sharing a period
PERIOD_BIN = 1.25  # log-scale bin width for period clustering


@dataclass(slots=True)
class _Entry:
    first_ts: float
    last_ts: float
    first_index: int
    src: bytes
    proto: str
    name: Optional[str]
    bcast_or_mcast: bool
    unicast_l4: bool
    count: int = 1
    gaps: list = field(default_factory=list)
    vlans: set = field(default_factory=set)
    indices: list = field(default_factory=list)


@dataclass
class DuplicateGroup:
    src: str
    proto: str
    name: Optional[str]
    copies: int
    median_gap: float
    vlans: list
    first_index: int
    example_indices: list
    first_ts: float
    flooded: bool


class DuplicateDetector:
    def __init__(self) -> None:
        self.table: dict[bytes, _Entry] = {}
        self.groups: list[DuplicateGroup] = []
        self.copies_total = 0
        self.frames_total = 0
        self.unicast_l4_total = 0
        self.unicast_l4_copies = 0
        self._since_prune = 0
        self._max_groups = 50000

    def feed(self, ts: float, index: int, f: Frame) -> bool:
        """Process a frame; return True if it is a short-interval copy."""
        self.frames_total += 1
        unicast_l4 = not (f.bcast or f.mcast) and f.proto in ("TCP", "UDP")
        if unicast_l4:
            self.unicast_l4_total += 1
        key = f.core
        e = self.table.get(key)
        is_copy = False
        if e is not None and ts - e.last_ts <= WINDOW:
            gap = ts - e.last_ts
            e.count += 1
            if len(e.gaps) < 64:
                e.gaps.append(gap)
            if len(e.indices) < 5:
                e.indices.append(index)
            e.vlans.add(f.vlans[-1] if f.vlans else None)
            e.last_ts = ts
            self.copies_total += 1
            if unicast_l4:
                self.unicast_l4_copies += 1
            is_copy = True
        else:
            if e is not None:
                self._close(e)
            self.table[key] = _Entry(
                first_ts=ts, last_ts=ts, first_index=index, src=f.src, proto=f.proto,
                name=f.name, bcast_or_mcast=f.bcast or f.mcast, unicast_l4=unicast_l4,
                vlans={f.vlans[-1] if f.vlans else None}, indices=[index],
            )
        self._since_prune += 1
        if self._since_prune >= PRUNE_EVERY:
            self._prune(ts)
        return is_copy

    def _close(self, e: _Entry) -> None:
        if e.count >= 2 and len(self.groups) < self._max_groups:
            self.groups.append(DuplicateGroup(
                src=mac_str(e.src), proto=e.proto, name=e.name, copies=e.count,
                median_gap=median(e.gaps) if e.gaps else 0.0,
                vlans=sorted(v for v in e.vlans if v is not None),
                first_index=e.first_index, example_indices=list(e.indices),
                first_ts=e.first_ts, flooded=e.bcast_or_mcast,
            ))

    def _prune(self, now: float) -> None:
        self._since_prune = 0
        stale = [k for k, e in self.table.items() if now - e.last_ts > WINDOW]
        for k in stale:
            self._close(self.table.pop(k))

    def finish(self) -> dict:
        for e in self.table.values():
            self._close(e)
        self.table.clear()
        return self.summary()

    # ------------------------------------------------------------ analysis
    def summary(self) -> dict:
        groups = self.groups
        multi = [g for g in groups if g.copies >= 3]
        pairs = [g for g in groups if g.copies == 2]
        tight_pairs = [g for g in pairs if g.median_gap <= SPAN_GAP]

        # SPAN artefact: ordinary unicast TCP/UDP duplicated, mostly as tight pairs.
        span_suspected = False
        if self.unicast_l4_total >= 50:
            ratio = self.unicast_l4_copies / self.unicast_l4_total
            span_suspected = ratio > 0.3 and len(tight_pairs) > 2 * max(1, len(multi))

        common = _common_period(multi)
        cross_vlan = [g for g in groups if len(g.vlans) >= 2]
        sources = {}
        for g in multi:
            s = sources.setdefault(g.src, {"src": g.src, "groups": 0, "copies": 0, "protos": set(), "names": set()})
            s["groups"] += 1
            s["copies"] += g.copies
            s["protos"].add(g.proto)
            if g.name:
                s["names"].add(g.name)
        top_sources = sorted(sources.values(), key=lambda s: -s["copies"])[:10]
        for s in top_sources:
            s["protos"] = sorted(s["protos"])
            s["names"] = sorted(s["names"])[:5]
        examples = sorted(multi, key=lambda g: -g.copies)[:10]
        return {
            "frames": self.frames_total,
            "copies": self.copies_total,
            "copy_ratio": (self.copies_total / self.frames_total) if self.frames_total else 0.0,
            "groups_repeated_3plus": len(multi),
            "groups_pairs": len(pairs),
            "span_artefact_suspected": span_suspected,
            "unicast_l4_copy_ratio": (self.unicast_l4_copies / self.unicast_l4_total) if self.unicast_l4_total else 0.0,
            "common_period": common,
            "cross_vlan": [_group_dict(g) for g in sorted(cross_vlan, key=lambda g: -g.copies)[:10]],
            "cross_vlan_count": len(cross_vlan),
            "top_sources": top_sources,
            "examples": [_group_dict(g) for g in examples],
        }


def _group_dict(g: DuplicateGroup) -> dict:
    return {
        "src": g.src, "proto": g.proto, "name": g.name, "copies": g.copies,
        "median_gap_us": round(g.median_gap * 1e6, 1), "vlans": g.vlans,
        "first_frame": g.first_index, "example_frames": g.example_indices,
        "first_ts": g.first_ts,
    }


def _common_period(groups: list[DuplicateGroup]) -> Optional[dict]:
    """Find a repetition period shared by frames from several distinct sources."""
    bins: dict[int, list[DuplicateGroup]] = {}
    for g in groups:
        if g.median_gap <= 0:
            continue
        b = round(math.log(g.median_gap) / math.log(PERIOD_BIN))
        bins.setdefault(b, []).append(g)
    best = None
    for b in bins:
        members = bins.get(b - 1, []) + bins[b] + bins.get(b + 1, [])
        srcs = {g.src for g in members}
        protos = {g.proto for g in members}
        score = (len(srcs), len(members))
        if best is None or score > best[0]:
            best = (score, members, srcs, protos)
    if best is None:
        return None
    (_n_src, _n), members, srcs, protos = best
    return {
        "period_us": round(median(g.median_gap for g in members) * 1e6, 1),
        "distinct_sources": len(srcs),
        "groups": len(members),
        "protocols": sorted(protos),
        "sources": sorted(srcs)[:10],
        "example_frames": sorted(g.first_index for g in members)[:10],
        "loop_fingerprint": len(srcs) >= MIN_SOURCES_FOR_LOOP,
    }
