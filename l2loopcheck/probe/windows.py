"""Windows probe sender: ctypes + Npcap ``wpcap.dll`` (``pcap_sendpacket``).

STATUS: to be implemented and tested on Windows (see docs/WINDOWS.md).

Contract (same as linux.py / macos.py):
    get_mac(interface) -> bytes      interface is the dumpcap/Npcap name, e.g. \\Device\\NPF_{GUID}
    open_sender(interface) -> object with send(frame: bytes) and close()

Npcap installs wpcap.dll in %SystemRoot%\\System32\\Npcap; that directory must
be added with os.add_dll_directory before loading. Raise
probe.ProbeUnavailable with a clear message when Npcap is missing.
"""

from __future__ import annotations


def get_mac(interface: str) -> bytes:
    from . import ProbeUnavailable

    raise ProbeUnavailable("Windows probe not implemented yet")


def open_sender(interface: str):
    from . import ProbeUnavailable

    raise ProbeUnavailable("Windows probe not implemented yet")
