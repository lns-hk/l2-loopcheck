"""Active loop probe (opt-in).

Design (agreed safety rules, not configurable):
* Broadcast destination so the frame is flooded into any loop.
* Source = the interface's own MAC, so port-security (one MAC per port) is
  not triggered. Never a random MAC.
* EtherType 0x88B5 (IEEE 802 local experimental) + payload ``L2LC`` magic,
  version, 8-byte random nonce and sequence number.
* Never an STP multicast destination, so BPDU guard is not triggered.
* At most ``MAX_FRAMES`` frames, one per ``INTERVAL`` seconds; stop as soon as
  one comes back. These limits are constants on purpose.

Platform senders (all stdlib): Linux ``AF_PACKET``, macOS ``/dev/bpf``,
Windows ``ctypes`` + Npcap ``wpcap.dll``. Each module exposes::

    get_mac(interface: str) -> bytes            # 6 bytes
    open_sender(interface: str) -> Sender       # object with send(frame: bytes) and close()
"""

from __future__ import annotations

import os
import secrets
import struct
import sys
import time
from typing import Callable

from ..decode import ETHERTYPE_PROBE, PROBE_MAGIC
from ..engine import ProbeRecord

MAX_FRAMES = 3
INTERVAL = 1.0
WAIT_AFTER_LAST = 1.5
PROBE_VERSION = 1


class ProbeUnavailable(RuntimeError):
    pass


def build_frame(src_mac: bytes, nonce: bytes, seq: int) -> bytes:
    assert len(src_mac) == 6 and len(nonce) == 8
    payload = PROBE_MAGIC + bytes([PROBE_VERSION]) + nonce + struct.pack("!Hd", seq, time.time())
    payload += b"l2-loopcheck loop test frame; see github.com/lns-hk/l2-loopcheck"
    frame = b"\xff" * 6 + src_mac + struct.pack("!H", ETHERTYPE_PROBE) + payload
    return frame.ljust(60, b"\0")


def platform_module():
    if sys.platform.startswith("linux"):
        from . import linux as m
    elif sys.platform == "darwin":
        from . import macos as m
    elif os.name == "nt":
        from . import windows as m
    else:
        raise ProbeUnavailable(f"probe not supported on {sys.platform}")
    return m


def run_probe(interface: str, register: Callable[[ProbeRecord], None], returned: Callable[[str], bool],
              log: Callable[[str], None] = print, sender=None, src_mac: bytes | None = None,
              sleep: Callable[[float], None] = time.sleep) -> dict:
    """Send up to MAX_FRAMES probe frames and report whether any came back.

    ``register`` must be called before sending so the engine recognises the
    returning frames; ``returned(nonce)`` asks the engine.
    """
    m = None
    if sender is None or src_mac is None:
        m = platform_module()
        src_mac = src_mac or m.get_mac(interface)
        sender = sender or m.open_sender(interface)
    nonce = secrets.token_bytes(8)
    rec = ProbeRecord(nonce=nonce.hex(), platform=sys.platform, interface=interface)
    register(rec)
    result = {"nonce": rec.nonce, "sent": 0, "loop_confirmed": False}
    try:
        for seq in range(MAX_FRAMES):
            sender.send(build_frame(src_mac, nonce, seq))
            rec.sent.append((seq, time.time()))
            result["sent"] += 1
            log(f"Probe frame {seq + 1}/{MAX_FRAMES} sent")
            sleep(INTERVAL if seq < MAX_FRAMES - 1 else WAIT_AFTER_LAST)
            if returned(rec.nonce):
                result["loop_confirmed"] = True
                log("Probe frame came back: loop confirmed. Stopped sending.")
                break
        else:
            log("No probe frame came back.")
    finally:
        sender.close()
    return result
