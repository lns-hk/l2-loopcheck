"""End-to-end: each synthetic scenario must produce the expected verdict."""

import unittest

from l2loopcheck.engine import Analyzer
from l2loopcheck.pcapio import CaptureReader
from l2loopcheck.synth import SCENARIOS, to_pcap_bytes
import io

EXPECTED = {
    "healthy": ("Healthy", set()),
    "loop": ("Loop likely", {"common-period", "no-bpdu"}),
    "chatty-host": ("Storm without clear loop", {"top-talker", "flood-rate"}),
    "stp-unstable": ("STP unstable", {"tc-storm", "root-change"}),
    "span-duplication": ("Inconclusive", {"span-duplication"}),
    "cross-vlan": ("Loop likely", {"cross-vlan"}),
    "duplicate-ip": ("Healthy", {"duplicate-ip"}),
    "split-tree": ("STP unstable", {"split-tree"}),
    "mst-regions": ("STP unstable", {"mst-regions"}),
    "short": ("Inconclusive", set()),
}


def run(name):
    a = Analyzer(source=name)
    a.feed_all(CaptureReader(io.BytesIO(to_pcap_bytes(SCENARIOS[name]()))))
    return a.finish()


class ScenarioVerdicts(unittest.TestCase):
    def test_all_scenarios(self):
        for name, (label, codes) in EXPECTED.items():
            with self.subTest(scenario=name):
                r = run(name)
                got = {f["code"] for f in r["verdict"]["findings"]}
                self.assertEqual(r["verdict"]["label"], label, got)
                self.assertTrue(codes <= got, f"missing {codes - got}")

    def test_chatty_host_is_not_called_a_loop(self):
        r = run("chatty-host")
        cp = r["duplicates"]["common_period"]
        self.assertFalse(cp and cp["loop_fingerprint"])

    def test_loop_period_is_measured(self):
        r = run("loop")
        cp = r["duplicates"]["common_period"]
        self.assertTrue(cp["loop_fingerprint"])
        self.assertAlmostEqual(cp["period_us"], 280, delta=30)
        self.assertGreaterEqual(cp["distinct_sources"], 3)

    def test_findings_cite_frames(self):
        r = run("loop")
        f = next(f for f in r["verdict"]["findings"] if f["code"] == "common-period")
        self.assertTrue(f["frames"])
        self.assertIsNotNone(f["hypothesis"])

    def test_timeline_continuous(self):
        r = run("healthy")
        ts = [s["t"] for s in r["timeline"]]
        self.assertEqual(ts, list(range(ts[0], ts[-1] + 1)))


if __name__ == "__main__":
    unittest.main()
