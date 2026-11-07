import os
import tempfile
import unittest

from l2loopcheck.engine import Analyzer
from l2loopcheck.live import RingWriter
from l2loopcheck.pcapio import Packet
from l2loopcheck.probe import MAX_FRAMES, build_frame, run_probe


class FakeSender:
    """Loops each sent frame back into the analyzer ``copies`` times."""

    def __init__(self, analyzer, copies):
        self.a, self.copies, self.sent, self.closed, self.n = analyzer, copies, [], False, 0

    def send(self, frame):
        self.sent.append(frame)
        for k in range(self.copies):
            self.n += 1
            self.a.feed(Packet(1000.0 + len(self.sent) + k * 0.0003, frame, len(frame), 1, self.n))

    def close(self):
        self.closed = True


class Probe(unittest.TestCase):
    def _run(self, copies):
        a = Analyzer()
        snd = FakeSender(a, copies)
        res = run_probe("test0", register=a.register_probe, returned=a.probe_returned, log=lambda m: None,
                        sender=snd, src_mac=b"\x02\0\0\0\0\x01", sleep=lambda s: None)
        return a, snd, res

    def test_loop_confirmed_and_stops(self):
        a, snd, res = self._run(copies=5)
        self.assertTrue(res["loop_confirmed"])
        self.assertEqual(len(snd.sent), 1)  # stopped after the first return
        self.assertTrue(snd.closed)
        self.assertEqual(a.finish()["verdict"]["label"], "Loop likely")

    def test_own_echo_only_is_not_a_loop(self):
        a, snd, res = self._run(copies=1)
        self.assertFalse(res["loop_confirmed"])
        self.assertEqual(len(snd.sent), MAX_FRAMES)

    def test_cap_is_constant(self):
        self.assertEqual(MAX_FRAMES, 3)
        f = build_frame(b"\x02\0\0\0\0\x01", b"\x01" * 8, 0)
        self.assertEqual(f[:6], b"\xff" * 6)
        self.assertEqual(f[12:14], b"\x88\xb5")
        self.assertNotEqual(f[:6], bytes.fromhex("0180c2000000"))


class Ring(unittest.TestCase):
    def test_ring_limits_and_locks(self):
        with tempfile.TemporaryDirectory() as d:
            w = RingWriter(d, max_total_bytes=30 * 1024 * 1024)
            w.segment_size = 1024 * 1024
            frame = b"\xff" * 6 + b"\x02" * 6 + b"\x08\x06" + b"\0" * 1000
            for i in range(80000):
                w.write(Packet(1000 + i * 0.001, frame, len(frame), 1, i + 1))
                if i == 2000:
                    w.lock_around(1000 + i * 0.001)
            w.close()
            total = sum(os.path.getsize(os.path.join(d, f)) for f in os.listdir(d))
            self.assertLessEqual(total, 32 * 1024 * 1024)
            self.assertIn("capture-00002.pcap", os.listdir(d))  # locked around the mark
            self.assertGreater(w.deleted, 0)


if __name__ == "__main__":
    unittest.main()
