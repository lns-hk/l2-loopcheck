"""Windows probe sender: ctypes + Npcap ``wpcap.dll`` (``pcap_sendpacket``).

Contract (same as linux.py / macos.py):
    get_mac(interface) -> bytes      interface is the dumpcap/Npcap name, e.g. \\Device\\NPF_{GUID}
    open_sender(interface) -> object with send(frame: bytes) and close()

* MAC lookup uses the IP Helper API (``ConvertInterfaceGuidToLuid`` +
  ``GetIfEntry2``) on the GUID in the NPF name, so it works without Npcap.
* Sending uses Npcap's ``wpcap.dll`` from ``%SystemRoot%\\System32\\Npcap``
  (falls back to a WinPcap-compatible ``wpcap.dll`` on the DLL search path).
  ``ProbeUnavailable`` explains what to install when it is missing.
* The sender only accepts l2-loopcheck probe frames (broadcast destination,
  EtherType 0x88B5 + magic) as a second line of defence; the rate and count limits live in
  ``probe/__init__.py`` and are not configurable.

Stdlib only.
"""

from __future__ import annotations

import ctypes
import os
import re
import uuid
from ctypes import wintypes

from ..decode import ETHERTYPE_PROBE, PROBE_MAGIC

NPCAP_URL = "https://npcap.com/"
PCAP_ERRBUF_SIZE = 256
PCAP_CHAR_ENC_UTF_8 = 1

_GUID_RE = re.compile(r"\{([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}\s*$")


def _unavailable(msg: str):
    from . import ProbeUnavailable

    return ProbeUnavailable(msg)


def interface_guid(interface: str) -> str:
    """``\\Device\\NPF_{GUID}`` or ``{GUID}`` -> ``GUID`` (upper case)."""
    m = _GUID_RE.search(interface.strip())
    if not m:
        raise _unavailable(f"'{interface}' is not a network adapter (expected \\Device\\NPF_{{GUID}}); "
                           "the probe cannot use loopback or extcap interfaces")
    return m.group(1).upper()


# ------------------------------------------------------------------ IP Helper

class _GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16), ("Data3", ctypes.c_uint16),
                ("Data4", ctypes.c_ubyte * 8)]

    @classmethod
    def from_str(cls, s: str) -> "_GUID":
        return cls.from_buffer_copy(uuid.UUID(s).bytes_le)


IF_MAX_STRING_SIZE = 256
IF_MAX_PHYS_ADDRESS_LENGTH = 32
IF_OPER_STATUS_UP = 1


class MIB_IF_ROW2(ctypes.Structure):  # netioapi.h; sizeof == 1352 on x86 and x64
    _fields_ = [
        ("InterfaceLuid", ctypes.c_uint64),
        ("InterfaceIndex", ctypes.c_uint32),
        ("InterfaceGuid", _GUID),
        ("Alias", ctypes.c_wchar * (IF_MAX_STRING_SIZE + 1)),
        ("Description", ctypes.c_wchar * (IF_MAX_STRING_SIZE + 1)),
        ("PhysicalAddressLength", ctypes.c_uint32),
        ("PhysicalAddress", ctypes.c_ubyte * IF_MAX_PHYS_ADDRESS_LENGTH),
        ("PermanentPhysicalAddress", ctypes.c_ubyte * IF_MAX_PHYS_ADDRESS_LENGTH),
        ("Mtu", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
        ("TunnelType", ctypes.c_int),
        ("MediaType", ctypes.c_int),
        ("PhysicalMediumType", ctypes.c_int),
        ("AccessType", ctypes.c_int),
        ("DirectionType", ctypes.c_int),
        ("InterfaceAndOperStatusFlags", ctypes.c_ubyte),
        ("OperStatus", ctypes.c_int),
        ("AdminStatus", ctypes.c_int),
        ("MediaConnectState", ctypes.c_int),
        ("NetworkGuid", _GUID),
        ("ConnectionType", ctypes.c_int),
        ("TransmitLinkSpeed", ctypes.c_uint64),
        ("ReceiveLinkSpeed", ctypes.c_uint64),
        ("_counters", ctypes.c_uint64 * 18),  # In*/Out* octet and packet counters, OutQLen
    ]


def adapter_info(interface: str) -> dict:
    """Friendly name, description, MAC and link state of the adapter behind an NPF name."""
    guid = _GUID.from_str(interface_guid(interface))
    iphlp = ctypes.WinDLL("iphlpapi")
    iphlp.ConvertInterfaceGuidToLuid.argtypes = [ctypes.POINTER(_GUID), ctypes.POINTER(ctypes.c_uint64)]
    iphlp.ConvertInterfaceGuidToLuid.restype = wintypes.DWORD
    iphlp.GetIfEntry2.argtypes = [ctypes.POINTER(MIB_IF_ROW2)]
    iphlp.GetIfEntry2.restype = wintypes.DWORD
    luid = ctypes.c_uint64()
    rc = iphlp.ConvertInterfaceGuidToLuid(ctypes.byref(guid), ctypes.byref(luid))
    if rc:
        raise _unavailable(f"No network adapter with GUID {{{interface_guid(interface)}}} (error {rc})")
    row = MIB_IF_ROW2()
    row.InterfaceLuid = luid.value
    rc = iphlp.GetIfEntry2(ctypes.byref(row))
    if rc:
        raise _unavailable(f"Cannot read adapter {{{interface_guid(interface)}}} (GetIfEntry2 error {rc})")
    n = row.PhysicalAddressLength
    return {"alias": row.Alias, "description": row.Description,
            "mac": bytes(row.PhysicalAddress[:n]), "up": row.OperStatus == IF_OPER_STATUS_UP}


def get_mac(interface: str) -> bytes:
    mac = adapter_info(interface)["mac"]
    if len(mac) != 6:
        raise _unavailable(f"{interface} has no Ethernet MAC address (not an Ethernet or Wi-Fi adapter)")
    return mac


# ---------------------------------------------------------------------- Npcap

_wpcap = None
_dll_dirs = []  # keep add_dll_directory handles alive


def _load_wpcap():
    global _wpcap
    if _wpcap is not None:
        return _wpcap
    npcap_dir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap")
    errors = []
    lib = None
    if os.path.isfile(os.path.join(npcap_dir, "wpcap.dll")):
        try:
            _dll_dirs.append(os.add_dll_directory(npcap_dir))  # Packet.dll lives next to wpcap.dll
            lib = ctypes.CDLL(os.path.join(npcap_dir, "wpcap.dll"))
        except OSError as e:
            errors.append(str(e))
    if lib is None:
        try:
            lib = ctypes.CDLL("wpcap.dll")  # Npcap in WinPcap-compatible mode, or WinPcap
        except OSError as e:
            errors.append(str(e))
    if lib is None:
        raise _unavailable("Npcap is not installed, so the probe cannot send frames. Install Wireshark "
                           f"(it includes Npcap) or Npcap from {NPCAP_URL}."
                           + (f" ({'; '.join(errors)})" if errors else ""))
    lib.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
    lib.pcap_open_live.restype = ctypes.c_void_p
    lib.pcap_sendpacket.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
    lib.pcap_sendpacket.restype = ctypes.c_int
    lib.pcap_geterr.argtypes = [ctypes.c_void_p]
    lib.pcap_geterr.restype = ctypes.c_char_p
    lib.pcap_close.argtypes = [ctypes.c_void_p]
    lib.pcap_close.restype = None
    lib.pcap_lib_version.argtypes = []
    lib.pcap_lib_version.restype = ctypes.c_char_p
    if hasattr(lib, "pcap_init"):  # libpcap >= 1.10 / Npcap >= 1.0: UTF-8 names and messages
        lib.pcap_init.argtypes = [ctypes.c_uint, ctypes.c_char_p]
        lib.pcap_init.restype = ctypes.c_int
        lib.pcap_init(PCAP_CHAR_ENC_UTF_8, ctypes.create_string_buffer(PCAP_ERRBUF_SIZE))
    _wpcap = lib
    return lib


def npcap_version() -> str:
    """e.g. 'Npcap version 1.79, based on libpcap version 1.10.4'; raises ProbeUnavailable if missing."""
    return _load_wpcap().pcap_lib_version().decode("utf-8", "replace")


def _is_probe_frame(frame: bytes) -> bool:
    return (14 + len(PROBE_MAGIC) <= len(frame) <= 1514
            and frame[:6] == b"\xff" * 6  # broadcast only: never an STP/LLDP multicast address
            and int.from_bytes(frame[12:14], "big") == ETHERTYPE_PROBE
            and frame[14:14 + len(PROBE_MAGIC)] == PROBE_MAGIC)


class _Sender:
    def __init__(self, interface: str, lib) -> None:
        self.interface = interface
        self.lib = lib
        errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
        # snaplen 64, not promiscuous, 100 ms timeout: this handle only sends.
        self.handle = lib.pcap_open_live(interface.encode("utf-8"), 64, 0, 100, errbuf)
        if not self.handle:
            msg = errbuf.value.decode("utf-8", "replace") or "unknown error"
            hint = (" If Npcap was installed with 'Restrict Npcap driver's access to Administrators only', "
                    "run l2-loopcheck as Administrator.") if "access" in msg.lower() or "denied" in msg.lower() else ""
            raise _unavailable(f"Npcap cannot open {interface}: {msg}.{hint}")

    def send(self, frame: bytes) -> None:
        if not _is_probe_frame(frame):
            raise ValueError("the Windows sender only sends l2-loopcheck probe frames")
        if self.handle is None:
            raise OSError("sender is closed")
        if self.lib.pcap_sendpacket(self.handle, frame, len(frame)) != 0:
            err = self.lib.pcap_geterr(self.handle) or b"unknown error"
            raise OSError(f"pcap_sendpacket failed on {self.interface}: {err.decode('utf-8', 'replace')}")

    def close(self) -> None:
        if self.handle is not None:
            self.lib.pcap_close(self.handle)
            self.handle = None


def open_sender(interface: str) -> _Sender:
    guid = interface_guid(interface)  # rejects loopback / extcap names early
    if not interface.startswith("\\Device\\"):
        interface = f"\\Device\\NPF_{{{guid}}}"
    return _Sender(interface, _load_wpcap())
