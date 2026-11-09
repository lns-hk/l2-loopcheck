import io
import struct
import subprocess
import tempfile
import unittest
import os

from l2loopcheck.capture import find_tshark
from l2loopcheck.pcapio import CaptureFormatError, CaptureReader
from l2loopcheck.synth import SCENARIOS, to_pcap_bytes


def pcapng_bytes(frames, tsresol=6):
    def block(t, body):
        body += b"\0" * ((4 - len(body) % 4) % 4)
        n = 12 + len(body)
        return struct.pack("<II", t, n) + body + struct.pack("<I", n)
    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    opt = struct.pack("<HHB3x", 9, 1, tsresol) + struct.pack("<HH", 0, 0)
    out += block(1, struct.pack("<HHI", 1, 0, 0) + opt)
    for t, fr in frames:
        ticks = int(t * 10**tsresol)
        out += block(6, struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(fr), len(fr)) + fr)
    isb_opts = struct.pack("<HHQ", 5, 8, 7) + struct.pack("<HH", 0, 0)
    out += block(5, struct.pack("<III", 0, 0, 0) + isb_opts)
    return out


class PcapIO(unittest.TestCase):
    def test_pcap_roundtrip(self):
        frames = SCENARIOS["healthy"]()
        pk = list(CaptureReader(io.BytesIO(to_pcap_bytes(frames))))
        self.assertEqual(len(pk), len(frames))
        self.assertEqual([p.index for p in pk[:3]], [1, 2, 3])

    def test_pcapng_and_isb(self):
        frames = [(1_700_000_000.0 + i * 0.001, b"\xff" * 6 + b"\x02" * 6 + b"\x08\x06" + b"\0" * 46) for i in range(10)]
        for res in (6, 9):
            r = CaptureReader(io.BytesIO(pcapng_bytes(frames, res)))
            pk = list(r)
            self.assertEqual(len(pk), 10)
            self.assertAlmostEqual(pk[1].ts - pk[0].ts, 0.001, places=6)
            self.assertEqual(r.stats.if_drop, 7)

    def test_truncated_file(self):
        data = to_pcap_bytes(SCENARIOS["short"]())
        r = CaptureReader(io.BytesIO(data[:-5]))
        list(r)
        self.assertTrue(r.truncated)

    def test_not_a_capture(self):
        with self.assertRaises(CaptureFormatError):
            list(CaptureReader(io.BytesIO(b"hello world, not a capture")))

    @unittest.skipUnless(find_tshark(), "tshark not installed")
    def test_tshark_oracle(self):
        """Independent check: tshark must count the same frames, broadcasts and BPDUs."""
        tshark = find_tshark()
        from l2loopcheck.cli import analyze_file
        with tempfile.TemporaryDirectory() as d:
            for name in ("stp-unstable", "loop", "cross-vlan"):
                p = os.path.join(d, name + ".pcap")
                with open(p, "wb") as f:
                    f.write(to_pcap_bytes(SCENARIOS[name]()))
                r = analyze_file(p)

                def count(flt):
                    out = subprocess.run([tshark, "-r", p, "-Y", flt, "-T", "fields", "-e", "frame.number"],
                                         capture_output=True, text=True, check=True).stdout
                    return len(out.split())
                self.assertEqual(r["capture"]["packets"], count("frame"))
                self.assertEqual(r["traffic"]["broadcast"], count("eth.dst == ff:ff:ff:ff:ff:ff"))
                self.assertEqual(r["stp"]["bpdus"], count("stp"))
                self.assertEqual(sum(p["frames"] for p in r["traffic"]["by_protocol"] if p["proto"] == "ARP"),
                                 count("arp"))


if __name__ == "__main__":
    unittest.main()
