"""Streaming pcap / pcapng reader and a small pcap writer (stdlib only).

Reader yields ``Packet`` objects one at a time so multi-GB captures and live
pipes from dumpcap/tcpdump can be processed without loading them into memory.

References: libpcap file format (tcpdump.org/manpages/pcap-savefile.5.txt) and
the pcapng IETF draft (draft-ietf-opsawg-pcapng).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator, Optional

# Link-layer types we decode (tcpdump.org/linktypes.html).
LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276

PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_BOM = 0x1A2B3C4D


class CaptureFormatError(ValueError):
    """Raised when a file is not a readable pcap/pcapng capture."""


@dataclass(slots=True)
class Packet:
    ts: float  # seconds since epoch
    data: bytes  # captured bytes
    wire_len: int  # original length on the wire
    linktype: int
    index: int  # 1-based frame number, matches Wireshark's "No." column
    interface: int = 0


@dataclass(slots=True)
class CaptureStats:
    """Interface statistics from pcapng ISB blocks (if present)."""

    if_drop: Optional[int] = None  # dropped by the interface/driver
    os_drop: Optional[int] = None  # dropped by the OS / capture buffer
    if_recv: Optional[int] = None


def _read_exact(f: BinaryIO, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = f.read(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


class CaptureReader:
    """Iterate packets from a pcap or pcapng stream.

    ``stats`` is filled from pcapng Interface Statistics Blocks as they are
    read. ``truncated`` is set when the stream ends mid-record.
    """

    def __init__(self, f: BinaryIO):
        self.f = f
        self.stats = CaptureStats()
        self.truncated = False
        self.format = ""
        self.linktypes: list[int] = []
        head = _read_exact(f, 4)
        if len(head) < 4:
            raise CaptureFormatError("file is empty or too short")
        self._head = head

    # ------------------------------------------------------------------ pcap
    def _iter_pcap(self, head: bytes) -> Iterator[Packet]:
        magic_le = struct.unpack("<I", head)[0]
        magic_be = struct.unpack(">I", head)[0]
        if magic_le in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
            endian, magic = "<", magic_le
        else:
            endian, magic = ">", magic_be
        nano = magic == PCAP_MAGIC_NS
        rest = _read_exact(self.f, 20)
        if len(rest) < 20:
            raise CaptureFormatError("truncated pcap header")
        _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack(endian + "HHiIII", rest)
        linktype &= 0x0FFFFFFF
        self.format = "pcap"
        self.linktypes = [linktype]
        div = 1e9 if nano else 1e6
        rec = struct.Struct(endian + "IIII")
        idx = 0
        while True:
            hdr = _read_exact(self.f, 16)
            if not hdr:
                return
            if len(hdr) < 16:
                self.truncated = True
                return
            sec, frac, incl, orig = rec.unpack(hdr)
            if incl > 0x4000000:  # 64 MiB: corrupt
                raise CaptureFormatError(f"implausible record length {incl}")
            data = _read_exact(self.f, incl)
            if len(data) < incl:
                self.truncated = True
                return
            idx += 1
            yield Packet(sec + frac / div, data, orig, linktype, idx)

    # ---------------------------------------------------------------- pcapng
    def _iter_pcapng(self) -> Iterator[Packet]:
        self.format = "pcapng"
        endian = "<"
        ifaces: list[tuple[int, float]] = []  # (linktype, ticks per second)
        idx = 0
        first = True
        while True:
            if first:
                btype_raw = self._head
                first = False
            else:
                btype_raw = _read_exact(self.f, 4)
                if not btype_raw:
                    return
                if len(btype_raw) < 4:
                    self.truncated = True
                    return
            len_raw = _read_exact(self.f, 4)
            if len(len_raw) < 4:
                self.truncated = True
                return
            btype_le = struct.unpack("<I", btype_raw)[0]
            if btype_le == PCAPNG_SHB:
                bom = _read_exact(self.f, 4)
                if len(bom) < 4:
                    self.truncated = True
                    return
                endian = "<" if struct.unpack("<I", bom)[0] == PCAPNG_BOM else ">"
                if struct.unpack(endian + "I", bom)[0] != PCAPNG_BOM:
                    raise CaptureFormatError("bad pcapng byte-order magic")
                blen = struct.unpack(endian + "I", len_raw)[0]
                body = _read_exact(self.f, blen - 12)
                if len(body) < blen - 12:
                    self.truncated = True
                    return
                ifaces = []  # new section resets interfaces
                continue
            btype = struct.unpack(endian + "I", btype_raw)[0]
            blen = struct.unpack(endian + "I", len_raw)[0]
            if blen < 12 or blen > 0x4000000:
                raise CaptureFormatError(f"implausible pcapng block length {blen}")
            body = _read_exact(self.f, blen - 8)
            if len(body) < blen - 8:
                self.truncated = True
                return
            body = body[:-4]  # drop trailing length copy
            if btype == 1:  # Interface Description Block
                linktype, _res, _snap = struct.unpack(endian + "HHI", body[:8])
                tsres = 1e6
                for code, val in _iter_options(body[8:], endian):
                    if code == 9 and val:  # if_tsresol
                        r = val[0]
                        tsres = float(2 ** (r & 0x7F)) if r & 0x80 else float(10 ** r)
                ifaces.append((linktype, tsres))
                self.linktypes.append(linktype)
            elif btype == 6:  # Enhanced Packet Block
                if_id, ts_hi, ts_lo, cap, orig = struct.unpack(endian + "IIIII", body[:20])
                data = body[20 : 20 + cap]
                if if_id >= len(ifaces):
                    raise CaptureFormatError("packet references unknown interface")
                linktype, tsres = ifaces[if_id]
                idx += 1
                yield Packet(((ts_hi << 32) | ts_lo) / tsres, data, orig, linktype, idx, if_id)
            elif btype == 3:  # Simple Packet Block
                if not ifaces:
                    raise CaptureFormatError("simple packet before interface block")
                orig = struct.unpack(endian + "I", body[:4])[0]
                data = body[4 : 4 + orig]
                idx += 1
                yield Packet(0.0, data, orig, ifaces[0][0], idx)
            elif btype == 5:  # Interface Statistics Block
                for code, val in _iter_options(body[12:], endian):
                    if len(val) == 8:
                        n = struct.unpack(endian + "Q", val)[0]
                        if code == 4:
                            self.stats.if_recv = n
                        elif code == 5:
                            self.stats.if_drop = (self.stats.if_drop or 0) + n
                        elif code == 7:
                            self.stats.os_drop = (self.stats.os_drop or 0) + n
            # other block types (NRB, DSB, custom) are skipped

    def __iter__(self) -> Iterator[Packet]:
        le = struct.unpack("<I", self._head)[0]
        be = struct.unpack(">I", self._head)[0]
        if le == PCAPNG_SHB:
            return self._iter_pcapng()
        if le in (PCAP_MAGIC_US, PCAP_MAGIC_NS) or be in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
            return self._iter_pcap(self._head)
        raise CaptureFormatError("not a pcap or pcapng file")


def _iter_options(buf: bytes, endian: str) -> Iterator[tuple[int, bytes]]:
    off = 0
    while off + 4 <= len(buf):
        code, length = struct.unpack(endian + "HH", buf[off : off + 4])
        if code == 0:
            return
        val = buf[off + 4 : off + 4 + length]
        yield code, val
        off += 4 + ((length + 3) & ~3)


def read_packets(path: str) -> Iterator[Packet]:
    """Convenience: iterate packets of a file on disk."""
    with open(path, "rb") as f:
        yield from CaptureReader(f)


class PcapWriter:
    """Minimal classic-pcap writer (microsecond timestamps)."""

    def __init__(self, f: BinaryIO, linktype: int = LINKTYPE_ETHERNET, snaplen: int = 262144):
        self.f = f
        self.bytes_written = 24
        f.write(struct.pack("<IHHiIII", PCAP_MAGIC_US, 2, 4, 0, 0, snaplen, linktype))

    def write(self, ts: float, data: bytes, wire_len: Optional[int] = None) -> None:
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        if usec >= 1_000_000:
            sec, usec = sec + 1, usec - 1_000_000
        self.f.write(struct.pack("<IIII", sec, usec, len(data), wire_len or len(data)))
        self.f.write(data)
        self.bytes_written += 16 + len(data)
