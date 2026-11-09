"""Live capture through dumpcap (Wireshark) or tcpdump.

The capture tool writes a pcap/pcapng stream to stdout; we parse it with our own
reader, feed the engine, and save frames into a size-capped ring of pcap files.
Wireshark is never bundled: if no tool is found, ``CaptureToolMissing`` carries
the download hint shown to the user.

Platform notes
* macOS: Wireshark's installer adds ChmodBPF so dumpcap runs without root.
  tcpdump needs root.
* Linux: dumpcap without root needs the user in the ``wireshark`` group (or
  capabilities on dumpcap). tcpdump needs root.
* Windows: dumpcap from Wireshark with Npcap. Interface names look like
  ``\\Device\\NPF_{GUID}``.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import threading
from typing import Callable, Optional

from . import winproc
from .pcapio import CaptureReader, Packet

WIRESHARK_URL = "https://www.wireshark.org/download.html"


class CaptureToolMissing(RuntimeError):
    pass


def _candidates(tool: str) -> list[str]:
    """Where Wireshark's command-line tools (dumpcap, tshark) usually live."""
    c = []
    w = shutil.which(tool)
    if w:
        c.append(w)
    if sys.platform == "darwin":
        c.append(f"/Applications/Wireshark.app/Contents/MacOS/{tool}")
    elif os.name == "nt":
        for base in (os.environ.get("ProgramFiles", r"C:\Program Files"),
                     os.environ.get("ProgramW6432", r"C:\Program Files"),
                     os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")):
            c.append(os.path.join(base, "Wireshark", f"{tool}.exe"))
    else:
        c += [f"/usr/bin/{tool}", f"/usr/sbin/{tool}"]
    return c


def _candidates_dumpcap() -> list[str]:
    return _candidates("dumpcap")


def find_dumpcap() -> Optional[str]:
    return next((p for p in _candidates("dumpcap") if p and os.path.isfile(p)), None)


def find_tshark() -> Optional[str]:
    return next((p for p in _candidates("tshark") if p and os.path.isfile(p)), None)


def find_tcpdump() -> Optional[str]:
    if os.name == "nt":
        return None
    return shutil.which("tcpdump") or next(
        (p for p in ("/usr/sbin/tcpdump", "/usr/bin/tcpdump") if os.path.isfile(p)), None)


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def choose_backend(preference: str = "auto") -> tuple[str, str]:
    """Return (backend_name, executable). Auto prefers dumpcap (no root needed)."""
    d, t = find_dumpcap(), find_tcpdump()
    if preference in ("auto", "dumpcap") and d:
        return "dumpcap", d
    if preference in ("auto", "tcpdump") and t:
        return "tcpdump", t
    if preference == "dumpcap":
        raise CaptureToolMissing(f"dumpcap not found. Install Wireshark: {WIRESHARK_URL}")
    if preference == "tcpdump":
        raise CaptureToolMissing("tcpdump not found.")
    raise CaptureToolMissing(f"No capture tool found. Install Wireshark (includes dumpcap): {WIRESHARK_URL}")


# "1. \Device\NPF_{GUID} (Ethernet)"  dumpcap on Windows; description = adapter friendly name
# "4. etwdump (Event Tracing for Windows (ETW) reader)"   extcap, nested parentheses
# "1. en0 (Wi-Fi)"                    dumpcap on macOS
# "1.en0 [Up, Running, Wireless]"     tcpdump: no space after the dot, flags in brackets
_IFACE_RE = re.compile(r"^\s*\d+\.\s*(\S+)(?:\s+\((.*?)\))?(?:\s+\[[^\]]*\])?\s*$")


def parse_interfaces(text: str) -> list[tuple[str, str]]:
    """Parse ``dumpcap -D`` / ``tcpdump -D`` output into (name, description)."""
    out = []
    for line in text.splitlines():
        m = _IFACE_RE.match(line)
        if m:
            out.append((m.group(1), m.group(2) or ""))
    return out


def list_interfaces(preference: str = "auto") -> list[tuple[str, str]]:
    name, exe = choose_backend(preference)
    proc = subprocess.run([exe, "-D"], capture_output=True, text=True, encoding="utf-8",
                          errors="replace", stdin=subprocess.DEVNULL, timeout=30,
                          **winproc.hidden_kwargs())
    if proc.returncode != 0 and not proc.stdout:
        raise RuntimeError((proc.stderr or "").strip() or f"{name} -D failed")
    return parse_interfaces(proc.stdout)


def resolve_interface(name: str, interfaces: list[tuple[str, str]]) -> str:
    """Map a friendly name (``Ethernet``) or ``dumpcap -D`` index (``3``) to the device name.

    Device names (``\\Device\\NPF_{...}``, ``en7``) and unknown names are returned unchanged.
    """
    names = [n for n, _ in interfaces]
    if name in names:
        return name
    if name.isdigit() and 1 <= int(name) <= len(interfaces):
        return interfaces[int(name) - 1][0]
    matches = [n for n, d in interfaces if d.strip().lower() == name.strip().lower()]
    return matches[0] if len(matches) == 1 else name


def capture_command(backend: str, exe: str, interface: str) -> list[str]:
    if backend == "dumpcap":
        # -q: no packet count on stderr; -w -: pcapng to stdout (includes ISB drop stats at the end)
        return [exe, "-i", interface, "-q", "-w", "-"]
    cmd = [exe, "-i", interface, "-U", "-s", "0", "-w", "-"]
    if not is_root():
        cmd = ["sudo", "--"] + cmd  # CLI only; the GUI requires dumpcap or root
    return cmd


_DROP_PATTERNS = (
    re.compile(r"dropped on interface[^:]*:\s*\d+/(\d+)"),  # dumpcap
    re.compile(r"(\d+) packets? dropped by kernel"),  # tcpdump
)


class CaptureProcess:
    """Run the capture tool and call ``on_packet`` for every frame (in a thread)."""

    def __init__(self, interface: str, preference: str = "auto",
                 on_packet: Callable[[Packet], None] = lambda p: None,
                 on_end: Callable[[Optional[str]], None] = lambda err: None) -> None:
        self.interface = interface
        self.backend, self.exe = choose_backend(preference)
        self.on_packet = on_packet
        self.on_end = on_end
        self.proc: Optional[subprocess.Popen] = None
        self.reader: Optional[CaptureReader] = None
        self.stderr_lines: list[str] = []
        self.drops: Optional[int] = None
        self._threads: list[threading.Thread] = []
        self._stopping = False

    def start(self) -> None:
        cmd = capture_command(self.backend, self.exe, self.interface)
        # Windows: own process group (and a hidden console for the GUI) so stop() can
        # send CTRL_BREAK and dumpcap finishes cleanly instead of being killed.
        self.proc = winproc.popen_stoppable(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            stdin=subprocess.DEVNULL if self.backend == "dumpcap" else None)
        t1 = threading.Thread(target=self._read, daemon=True, name="capture-reader")
        t2 = threading.Thread(target=self._read_stderr, daemon=True, name="capture-stderr")
        self._threads = [t1, t2]
        t1.start()
        t2.start()

    def _read(self) -> None:
        err = None
        try:
            self.reader = CaptureReader(self.proc.stdout)
            for pkt in self.reader:
                self.on_packet(pkt)
        except Exception as e:  # noqa: BLE001 - report any reader failure to the UI
            if not self._stopping:
                err = f"{type(e).__name__}: {e}"
        rc = self.proc.wait()
        if err is None and rc not in (0, None) and not self._stopping:
            err = self._stderr_text() or f"{self.backend} exited with code {rc}"
        self.on_end(err)

    def _read_stderr(self) -> None:
        for raw in self.proc.stderr:
            line = raw.decode("utf-8", "replace").replace("\r", "").strip()  # dumpcap redraws its counter with \r
            if line:
                self.stderr_lines.append(line)
                for pat in _DROP_PATTERNS:
                    m = pat.search(line)
                    if m:
                        self.drops = (self.drops or 0) + int(m.group(1))

    def _stderr_text(self) -> str:
        return "\n".join(self.stderr_lines[-10:])

    def stop(self, timeout: float = 5.0) -> None:
        self._stopping = True
        if self.proc and self.proc.poll() is None:
            if not (os.name == "nt" and winproc.send_ctrl_break(self.proc)):
                self.proc.terminate()
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        for t in self._threads:
            t.join(timeout=timeout)
        if self.proc and not any(t.is_alive() for t in self._threads):
            for pipe in (self.proc.stdout, self.proc.stderr):
                if pipe:
                    pipe.close()
