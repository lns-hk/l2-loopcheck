"""macOS probe sender: write a raw frame to a BPF device.

Works without root when Wireshark's ChmodBPF is installed (it gives the
``access_bpf`` group read/write access to /dev/bpf*).
"""

from __future__ import annotations

import fcntl
import os
import re
import struct
import subprocess

# _IOW('B', 108, struct ifreq) with sizeof(struct ifreq) == 32
BIOCSETIF = 0x8020426C
# _IOW('B', 117, u_int): keep our source MAC instead of the kernel filling it in
BIOCSHDRCMPLT = 0x80044275


def get_mac(interface: str) -> bytes:
    out = subprocess.run(["/sbin/ifconfig", interface], capture_output=True, text=True, check=True).stdout
    m = re.search(r"\bether\s+([0-9a-f:]{17})", out)
    if not m:
        raise ValueError(f"no Ethernet address for {interface}")
    return bytes.fromhex(m.group(1).replace(":", ""))


class _Sender:
    def __init__(self, interface: str) -> None:
        self.fd = -1
        last = None
        for i in range(256):
            try:
                self.fd = os.open(f"/dev/bpf{i}", os.O_RDWR)
                break
            except FileNotFoundError:
                break
            except OSError as e:  # EBUSY: in use; EACCES: no permission
                last = e
                continue
        if self.fd < 0:
            from . import ProbeUnavailable

            raise ProbeUnavailable("Cannot open /dev/bpf for writing. Install Wireshark (ChmodBPF) "
                                   f"or run as root. ({last})")
        ifreq = struct.pack("16s16x", interface.encode())
        fcntl.ioctl(self.fd, BIOCSETIF, ifreq)
        fcntl.ioctl(self.fd, BIOCSHDRCMPLT, struct.pack("I", 1))

    def send(self, frame: bytes) -> None:
        os.write(self.fd, frame)

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def open_sender(interface: str) -> _Sender:
    return _Sender(interface)
