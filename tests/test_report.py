import io
import unittest

from l2loopcheck.engine import Analyzer
from l2loopcheck.pcapio import CaptureReader
from l2loopcheck.report.html import render_html
from l2loopcheck.synth import SCENARIOS, to_pcap_bytes


class Report(unittest.TestCase):
    def test_renders_every_scenario_self_contained(self):
        for name, fn in SCENARIOS.items():
            with self.subTest(scenario=name):
                a = Analyzer(source=name)
                a.feed_all(CaptureReader(io.BytesIO(to_pcap_bytes(fn()))))
                a.add_mark("unplugged <uplink> & retest", ts=a.first_ts + 1)
                html = render_html(a.finish(), {"company": "Example Co", "site": "Level 3"})
                self.assertIn(a.finish()["verdict"]["label"], html)
                self.assertNotIn("<uplink>", html)  # escaped
                self.assertNotIn("http://", html.split("github.com")[0])
                self.assertNotIn("<script src", html)
                self.assertNotIn("<link ", html)


if __name__ == "__main__":
    unittest.main()
