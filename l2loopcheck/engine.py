"""Analysis engine: feeds frames to every detector and keeps a per-second timeline.

The same engine serves offline files and live captures: ``feed`` is called once
per frame, ``snapshot`` gives the latest per-second figures for the live view,
and ``finish`` returns the full, JSON-serialisable result.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Iterable, Optional

from . import __version__
from .decode import decode
from .detect.duplicates import DuplicateDetector
from .detect.stp import StpDetector
from .detect.traffic import DuplicateIpDetector, NeighbourCollector, TrafficDetector, storm_control_clipping
from .pcapio import CaptureStats, Packet
from .verdict import judge


@dataclass
class Mark:
    ts: float
    label: str


@dataclass
class ProbeRecord:
    nonce: str
    sent: list = field(default_factory=list)  # [(seq, ts)]
    seen: dict = field(default_factory=dict)  # seq -> [ (ts, frame) ]
    platform: str = ""
    interface: str = ""
    sees_own_tx: Optional[bool] = None  # whether the capture shows our own transmitted frames


class Analyzer:
    def __init__(self, source: str = "", interface: str = "") -> None:
        self.source = source
        self.interface = interface
        self.dups = DuplicateDetector()
        self.stp = StpDetector()
        self.traffic = TrafficDetector()
        self.dupip = DuplicateIpDetector()
        self.neigh = NeighbourCollector()
        self.first_ts: Optional[float] = None
        self.last_ts: Optional[float] = None
        self.packets = 0
        self.undecoded = 0
        self.snap_truncated = 0
        self.outgoing_skipped = 0
        self.linktypes: set = set()
        self.seconds: dict[int, dict] = {}
        self.marks: list[Mark] = []
        self.probes: dict[str, ProbeRecord] = {}
        self.capture_stats = CaptureStats()
        self.capture_truncated = False
        self.capture_drops: Optional[int] = None  # from the live capture process
        self.capture_tool = ""

    # ---------------------------------------------------------------- input
    def feed(self, pkt: Packet) -> None:
        self.packets += 1
        self.linktypes.add(pkt.linktype)
        ts = pkt.ts
        if self.first_ts is None:
            self.first_ts = ts
        self.last_ts = ts
        if len(pkt.data) < pkt.wire_len:
            self.snap_truncated += 1
        sec = self.seconds.get(int(ts))
        if sec is None:
            sec = self.seconds[int(ts)] = {"t": int(ts), "total": 0, "bcast": 0, "mcast": 0, "copies": 0,
                                           "arp": 0, "tc": 0, "bpdu": 0}
        sec["total"] += 1
        f = decode(pkt.data, pkt.linktype)
        if f is None:
            self.undecoded += 1
            return
        if f.outgoing:
            # Linux cooked captures label our own transmitted frames; they are
            # only relevant to the probe.
            self.outgoing_skipped += 1
            if f.probe:
                self._probe_seen(f.probe, ts, pkt.index, own=True)
            return
        if f.bcast:
            sec["bcast"] += 1
        elif f.mcast:
            sec["mcast"] += 1
        if f.proto == "ARP":
            sec["arp"] += 1
        if self.dups.feed(ts, pkt.index, f):
            sec["copies"] += 1
        self.traffic.feed(f, pkt.index)
        if f.bpdu:
            sec["bpdu"] += 1
            n_tc = len(self.stp.tc_events)
            self.stp.feed(ts, pkt.index, f.bpdu, f.src, f.vlans)
            sec["tc"] += len(self.stp.tc_events) - n_tc
        if f.arp:
            self.dupip.feed(f, pkt.index, ts)
        if f.neighbour:
            self.neigh.feed(f.neighbour, pkt.index, f.src, f.vlans)
        if f.probe:
            self._probe_seen(f.probe, ts, pkt.index, own=False)

    def feed_all(self, packets: Iterable[Packet]) -> None:
        for p in packets:
            self.feed(p)

    def add_mark(self, label: str, ts: Optional[float] = None) -> Mark:
        m = Mark(ts if ts is not None else (self.last_ts or time.time()), label.strip() or "mark")
        self.marks.append(m)
        return m

    # ---------------------------------------------------------------- probe
    def register_probe(self, rec: ProbeRecord) -> None:
        self.probes[rec.nonce] = rec

    def _probe_seen(self, probe: tuple, ts: float, index: int, own: bool) -> None:
        nonce, seq = probe
        rec = self.probes.get(nonce)
        if rec is None:  # a probe from another run or another l2-loopcheck user
            rec = self.probes.setdefault(nonce, ProbeRecord(nonce=nonce))
        if own:
            rec.sees_own_tx = True
            return
        rec.seen.setdefault(seq, []).append((ts, index))

    def probe_returned(self, nonce: str) -> bool:
        rec = self.probes.get(nonce)
        return bool(rec and _probe_result(rec)["loop_confirmed"])

    # --------------------------------------------------------------- output
    def series(self) -> list[dict]:
        if not self.seconds:
            return []
        lo, hi = min(self.seconds), max(self.seconds)
        empty = {"total": 0, "bcast": 0, "mcast": 0, "copies": 0, "arp": 0, "tc": 0, "bpdu": 0}
        out = []
        for t in range(lo, hi + 1):
            s = self.seconds.get(t) or {"t": t, **empty}
            out.append({**s, "flooded": s["bcast"] + s["mcast"]})
        return out

    def snapshot(self) -> dict:
        """Figures for the live view: the last complete second plus totals."""
        if not self.seconds:
            return {"t": None, "total": 0, "flooded": 0, "copies": 0, "tc": 0, "packets": 0}
        keys = sorted(self.seconds)
        last = self.seconds[keys[-2]] if len(keys) >= 2 else self.seconds[keys[-1]]
        return {
            "t": last["t"], "total": last["total"], "flooded": last["bcast"] + last["mcast"],
            "copies": last["copies"], "tc": last["tc"], "arp": last["arp"], "packets": self.packets,
            "copies_total": self.dups.copies_total, "tc_total": len(self.stp.tc_events),
            "duration": (self.last_ts - self.first_ts) if self.first_ts else 0.0,
        }

    def finish(self) -> dict:
        duration = (self.last_ts - self.first_ts) if self.first_ts is not None else 0.0
        series = self.series()
        dup = self.dups.finish()
        result = {
            "tool": {"name": "l2-loopcheck", "version": __version__},
            "capture": {
                "source": self.source,
                "interface": self.interface,
                "tool": self.capture_tool,
                "start": self.first_ts,
                "end": self.last_ts,
                "duration_s": round(duration, 3),
                "packets": self.packets,
                "undecoded": self.undecoded,
                "snaplen_truncated": self.snap_truncated,
                "own_tx_skipped": self.outgoing_skipped,
                "file_truncated": self.capture_truncated,
                "drops": self._drops(),
                "linktypes": sorted(self.linktypes),
            },
            "duplicates": dup,
            "traffic": self.traffic.summary(duration),
            "storm_control": storm_control_clipping(series),
            "stp": self.stp.summary(duration),
            "duplicate_ips": self.dupip.summary(),
            "neighbours": self.neigh.summary(),
            "probes": [_probe_result(r) for r in self.probes.values()],
            "marks": [{"ts": m.ts, "label": m.label} for m in self.marks],
            "timeline": series,
        }
        result["verdict"] = judge(result)
        return result

    def _drops(self) -> Optional[int]:
        vals = [v for v in (self.capture_drops, self.capture_stats.if_drop, self.capture_stats.os_drop) if v is not None]
        return sum(vals) if vals else None


def _probe_result(r: ProbeRecord) -> dict:
    """Decide whether probe frames came back.

    Captures on some platforms include our own transmitted frame once. So a
    loop is confirmed when any probe frame is seen at least twice, or when the
    capture is known not to include our own transmissions (Linux cooked
    capture marks them) and the frame is seen once.
    """
    returns = {seq: len(v) for seq, v in r.seen.items()}
    max_seen = max(returns.values(), default=0)
    if r.sees_own_tx:
        confirmed = max_seen >= 1
    else:
        confirmed = max_seen >= 2
    return {
        "nonce": r.nonce, "sent": len(r.sent), "platform": r.platform, "interface": r.interface,
        "sent_at": [ts for _seq, ts in r.sent], "copies_by_seq": returns,
        "loop_confirmed": confirmed,
        "first_return_frame": min((i for v in r.seen.values() for _t, i in v), default=None),
        "ambiguous": (not confirmed) and max_seen == 1,
    }


def analyze_packets(packets: Iterable[Packet], source: str = "", stats: Optional[CaptureStats] = None) -> dict:
    a = Analyzer(source=source)
    a.feed_all(packets)
    if stats:
        a.capture_stats = stats
    return a.finish()
