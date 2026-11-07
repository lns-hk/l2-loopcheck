"""A live session: capture + engine + ring-buffer evidence + marks + probe.

Shared by the CLI (``live_cli``) and the GUI. All methods are thread-safe; the
capture thread feeds frames while the UI thread reads snapshots.

Each session writes a run folder::

    runs/20261108-153000/
        capture-00001.pcap ...   ring buffer of raw frames (oldest deleted first,
                                 segments around marks are kept)
        marks.json
        result.json
        report.html
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Callable, Optional

from .capture import CaptureProcess
from .engine import Analyzer
from .pcapio import Packet, PcapWriter


class RingWriter:
    def __init__(self, folder: str, max_total_bytes: int, linktype: int = 1) -> None:
        self.folder = folder
        self.max_total = max_total_bytes
        self.segment_size = max(10 * 1024 * 1024, max_total_bytes // 20)
        self.linktype = linktype
        self.segments: list[dict] = []  # {"path", "bytes", "first_ts", "last_ts", "locked"}
        self._f = None
        self._w: Optional[PcapWriter] = None
        self.deleted = 0

    def _open(self, ts: float) -> None:
        n = len(self.segments) + self.deleted + 1
        path = os.path.join(self.folder, f"capture-{n:05d}.pcap")
        self._f = open(path, "wb")
        self._w = PcapWriter(self._f, self.linktype)
        self.segments.append({"path": path, "bytes": 24, "first_ts": ts, "last_ts": ts, "locked": False})

    def write(self, pkt: Packet) -> None:
        if self._w is None:
            self.linktype = pkt.linktype
            self._open(pkt.ts)
        elif pkt.linktype != self.linktype:
            return  # mixed link types cannot share a classic pcap file; rare (multi-interface pcapng)
        self._w.write(pkt.ts, pkt.data, pkt.wire_len)
        seg = self.segments[-1]
        seg["bytes"] = self._w.bytes_written
        seg["last_ts"] = pkt.ts
        if seg["bytes"] >= self.segment_size:
            self._f.close()
            self._open(pkt.ts)
            self._enforce()

    def lock_around(self, ts: float) -> None:
        """Keep the segment containing ``ts`` and its neighbours."""
        for i, seg in enumerate(self.segments):
            if seg["first_ts"] <= ts <= seg["last_ts"] or i == len(self.segments) - 1:
                for j in (i - 1, i, i + 1):
                    if 0 <= j < len(self.segments):
                        self.segments[j]["locked"] = True
                self._pending_lock_next = True
                break

    def _enforce(self) -> None:
        if getattr(self, "_pending_lock_next", False):
            self.segments[-1]["locked"] = True
            self._pending_lock_next = False
        total = sum(s["bytes"] for s in self.segments)
        for seg in list(self.segments[:-1]):
            if total <= self.max_total:
                break
            if seg["locked"]:
                continue
            try:
                os.remove(seg["path"])
            except OSError:
                pass
            total -= seg["bytes"]
            self.segments.remove(seg)
            self.deleted += 1

    def close(self) -> None:
        if self._f:
            self._f.flush()
            self._f.close()
            self._f = None

    def files(self) -> list[str]:
        return [os.path.basename(s["path"]) for s in self.segments]


class LiveSession:
    def __init__(self, interface: str, backend: str = "auto", run_dir: Optional[str] = None,
                 max_total_mb: int = 2048, on_end: Callable[[Optional[str]], None] = lambda e: None,
                 save_frames: bool = True) -> None:
        self.interface = interface
        self.run_dir = run_dir or os.path.join(os.getcwd(), "runs", time.strftime("%Y%m%d-%H%M%S"))
        os.makedirs(self.run_dir, exist_ok=True)
        self.analyzer = Analyzer(source="live", interface=interface)
        self.ring = RingWriter(self.run_dir, max_total_mb * 1024 * 1024) if save_frames else None
        self.lock = threading.Lock()
        self.error: Optional[str] = None
        self.ended = threading.Event()
        self._user_on_end = on_end
        self.cap = CaptureProcess(interface, backend, on_packet=self._on_packet, on_end=self._on_end)
        self.analyzer.capture_tool = f"{self.cap.backend} ({self.cap.exe})"
        self.started_at = None
        self.result: Optional[dict] = None
        self.probe_log: list[str] = []

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        self.started_at = time.time()
        self.cap.start()

    def _on_packet(self, pkt: Packet) -> None:
        with self.lock:
            self.analyzer.feed(pkt)
            if self.ring:
                self.ring.write(pkt)

    def _on_end(self, err: Optional[str]) -> None:
        self.error = err
        self.ended.set()
        self._user_on_end(err)

    def stop(self, branding: Optional[dict] = None) -> dict:
        self.cap.stop()
        with self.lock:
            if self.ring:
                self.ring.close()
            self.analyzer.capture_drops = self.cap.drops
            if self.cap.reader:
                self.analyzer.capture_stats = self.cap.reader.stats
            r = self.analyzer.finish()
            r["capture"]["saved_files"] = self.ring.files() if self.ring else []
            r["capture"]["run_dir"] = self.run_dir
            r["capture"]["tool_messages"] = self.cap.stderr_lines[-10:]
            self.result = r
        self._write_outputs(r, branding)
        return r

    def _write_outputs(self, r: dict, branding: Optional[dict]) -> None:
        from .cli import write_outputs

        write_outputs(r, os.path.join(self.run_dir, "result.json"),
                      os.path.join(self.run_dir, "report.html"), branding)

    # ------------------------------------------------------------ live data
    def snapshot(self) -> dict:
        with self.lock:
            s = self.analyzer.snapshot()
            s["elapsed"] = time.time() - self.started_at if self.started_at else 0.0
            s["saved_mb"] = round(sum(x["bytes"] for x in self.ring.segments) / 1e6, 1) if self.ring else 0.0
            return s

    def series(self, last_n: int = 300) -> list[dict]:
        with self.lock:
            return self.analyzer.series()[-last_n:]

    def add_mark(self, label: str) -> dict:
        with self.lock:
            m = self.analyzer.add_mark(label, ts=time.time())
            if self.ring:
                self.ring.lock_around(m.ts)
            marks = [{"ts": x.ts, "label": x.label} for x in self.analyzer.marks]
        with open(os.path.join(self.run_dir, "marks.json"), "w", encoding="utf-8") as f:
            json.dump(marks, f, indent=2)
        return {"ts": m.ts, "label": m.label}

    def marks(self) -> list[dict]:
        with self.lock:
            return [{"ts": x.ts, "label": x.label} for x in self.analyzer.marks]

    # ---------------------------------------------------------------- probe
    def run_probe(self, log: Callable[[str], None] = print) -> dict:
        """Send the capped probe burst. The caller must have obtained consent."""
        from .probe import run_probe

        def returned(nonce: str) -> bool:
            with self.lock:
                return self.analyzer.probe_returned(nonce)

        def register(rec) -> None:
            with self.lock:
                self.analyzer.register_probe(rec)
                self.analyzer.add_mark(f"Probe {rec.nonce} sent", ts=time.time())

        def _log(msg: str) -> None:
            self.probe_log.append(msg)
            log(msg)

        return run_probe(self.interface, register=register, returned=returned, log=_log)
