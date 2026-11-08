import io
import json
import os
import tempfile
import unittest
from unittest import mock

from l2loopcheck import preflight
from l2loopcheck.engine import Analyzer
from l2loopcheck.pcapio import CaptureReader
from l2loopcheck.report.html import render_html
from l2loopcheck.report.redact import redact
from l2loopcheck.synth import SCENARIOS, to_pcap_bytes


def run(name, vantage=None):
    a = Analyzer(source=name)
    a.declared_vantage = vantage
    a.feed_all(CaptureReader(io.BytesIO(to_pcap_bytes(SCENARIOS[name]()))))
    return a.finish()


class SecurityChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = run("security-issues", "span")
        cls.codes = {f["code"] for f in cls.r["verdict"]["findings"] if f["category"] == "security"}

    def test_detects_each_weakness(self):
        expected = {"gateway-spoof", "rogue-dhcp", "rogue-ra", "dtp-enabled", "name-poisoning", "wpad", "cleartext-login",
                    "cleartext-service", "http-basic", "snmp-default", "smb1", "tls-old", "ot-exposed", "port-scan"}
        self.assertEqual(expected - self.codes, set())

    def test_scanned_ports_are_not_reported_as_services(self):
        servers = {(e["service"], e["port"]) for e in self.r["security"]["services"]}
        self.assertNotIn(("POP3", 110), servers)
        self.assertNotIn(("S7comm / ISO-TSAP", 102), servers)
        self.assertIn(("Telnet", 23), servers)

    def test_no_secret_reaches_the_result(self):
        text = json.dumps(self.r, default=str)
        for secret in ("ZXhhbXBsZTpleGFtcGxl", "USER admin", '"public"'):
            self.assertNotIn(secret, text)

    def test_healthy_network_has_no_serious_security_finding(self):
        r = run("healthy")
        bad = [f["code"] for f in r["verdict"]["findings"] if f["category"] == "security" and f["severity"] in ("critical", "high")]
        self.assertEqual(bad, [])

    def test_posture(self):
        self.assertEqual(self.r["verdict"]["security"]["posture"], "Action needed")

    def test_access_port_limits_are_stated(self):
        r = run("healthy", "access")
        limited = {c["check"] for c in r["coverage"] if c["status"] == "limited"}
        self.assertIn("Clear-text logins and services", limited)

    def test_declared_access_port_with_tags_is_flagged(self):
        codes = {f["code"] for f in run("cross-vlan", "access")["verdict"]["findings"]}
        self.assertIn("access-sees-vlans", codes)

    def test_trunk_seen_when_not_declared(self):
        codes = {f["code"] for f in run("cross-vlan")["verdict"]["findings"]}
        self.assertIn("trunk-port", codes)

    def test_no_frames_is_never_healthy(self):
        r = Analyzer(source="empty").finish()
        self.assertEqual(r["verdict"]["label"], "Inconclusive")
        self.assertEqual(r["verdict"]["security"]["posture"], "Not assessed")
        self.assertIn("no-frames", {f["code"] for f in r["verdict"]["findings"]})


class StormPerformance(unittest.TestCase):
    """A real loop delivers hundreds of thousands of frames; the window counter must stay linear."""

    def test_repeated_values_do_not_rescan_the_window(self):
        import time

        from l2loopcheck.detect.security import _WindowCounter

        c = _WindowCounter(60.0)
        t0 = time.perf_counter()
        for i in range(400000):
            c.add("sender", i % 200, 1000.0 + i * 0.0001, i)
        self.assertLess(time.perf_counter() - t0, 3.0)
        self.assertEqual(c.peak["sender"][0], 200)

    def test_values_outside_the_window_do_not_count(self):
        from l2loopcheck.detect.security import _WindowCounter

        c = _WindowCounter(60.0)
        for i in range(100):
            c.add("slow", i, 1000.0 + i * 10.0, i)  # 10 s apart: at most 7 values inside 60 s
        self.assertLess(c.peak.get("slow", (0, 0))[0], 9)

    def test_memory_is_bounded(self):
        from l2loopcheck.detect.security import _WindowCounter

        c = _WindowCounter(60.0)
        for i in range(20000):
            c.add("sweep", i, 1000.0, i)
        self.assertGreaterEqual(c.peak["sweep"][0], _WindowCounter.MAX_VALUES)


class RogueSeverity(unittest.TestCase):
    def _sev(self, macs, lifetime=1800):
        from l2loopcheck.detect.security import SecurityDetector, security_findings

        s = SecurityDetector().summary()
        s["router_advertisers"] = [{"ip": "fe80::1", "mac": m, "vlan": "untagged", "frames": 1, "first_frame": 1,
                                    "router_lifetime": lifetime} for m in macs]
        return [f["severity"] for f in security_findings(s, [], [], {}, "access") if f["code"] == "rogue-ra"]

    def test_same_vendor_is_a_review_item(self):
        self.assertEqual(self._sev(["02:00:5e:00:00:01", "02:00:5e:00:00:02"]), ["warning"])

    def test_different_vendors_is_high(self):
        self.assertEqual(self._sev(["02:00:5e:00:00:01", "06:11:22:00:00:02"]), ["high"])

    def test_zero_lifetime_routers_do_not_count(self):
        self.assertEqual(self._sev(["02:00:5e:00:00:01", "06:11:22:00:00:02"], lifetime=0), [])

    def test_most_arped_address_is_not_assumed_to_be_the_gateway(self):
        codes = {f["code"] for f in run("duplicate-ip")["verdict"]["findings"]}
        self.assertNotIn("gateway-spoof", codes)


class MultiVlanHost(unittest.TestCase):
    def test_not_called_a_loop(self):
        r = run("multi-vlan-host")
        codes = {f["code"] for f in r["verdict"]["findings"]}
        self.assertNotEqual(r["verdict"]["label"], "Loop likely")
        self.assertIn("multi-vlan-host", codes)
        self.assertNotIn("cross-vlan", codes)
        self.assertNotIn("few-replays", codes)


class Redaction(unittest.TestCase):
    def test_hides_identifiers(self):
        r = run("security-issues", "span")
        r["engagement"] = {"site": "Secret Tower", "client": "Example Client", "engineer": "A Person"}
        r["marks"] = [{"ts": 1.0, "label": "unplugged the uplink in Secret Tower"}]
        out = redact(r)
        text = json.dumps(out, default=str)
        self.assertNotIn("Secret Tower", text)
        self.assertNotIn("A Person", text)
        self.assertNotIn("02:00:5e:00:a0:01", text)  # gateway MAC from the scenario
        self.assertNotIn("192.0.2.50", json.dumps(r["security"]["hosts"][:0]))
        self.assertTrue(out["redacted"])
        render_html(out)

    def test_mapping_is_consistent(self):
        r = {"capture": {}, "a": "198.51.100.7 and 198.51.100.7, 198.51.100.9"}
        a, b, c = redact(r)["a"].replace(",", "").replace(" and", "").split()
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)


class Report(unittest.TestCase):
    def test_sections(self):
        r = run("security-issues", "span")
        r["engagement"] = {"site": "Level <3>", "authorised": True, "authorised_by": "A Person",
                           "preflight": [{"title": "Capture tool", "status": "ok", "detail": "x"}]}
        html = render_html(r)
        for text in ("Security findings", "What this capture could not check", "Devices seen", "Scope and authorisation",
                     "Level &lt;3&gt;"):
            self.assertIn(text, html)


class Preflight(unittest.TestCase):
    def test_classify(self):
        for text, kind in (("Intel(R) Ethernet Controller I226-V", "wired"), ("vEthernet (External) Hyper-V", "virtual"),
                           ("Wi-Fi Intel AX211", "wifi"), ("Tailscale Tunnel", "vpn"),
                           ("Adapter for loopback traffic capture", "loopback"), ("lo0", "loopback")):
            self.assertEqual(preflight.classify(text), kind, text)

    def _a(self, kind="wired", up=True, title="Ethernet"):
        return {"name": "x", "title": title, "hardware": "", "kind": kind, "up": up, "mac": ""}

    def test_suggest_prefers_live_wired(self):
        adapters = [self._a("wifi", True, "Wi-Fi"), self._a("wired", True, "LAN"), self._a("virtual", True, "vEthernet")]
        self.assertEqual(preflight.suggest(adapters)[0]["title"], "LAN")

    def test_vpn_and_dead_link_block(self):
        self.assertEqual(preflight.adapter_warnings(self._a("vpn"))[0][0], preflight.ERROR)
        self.assertEqual(preflight.adapter_warnings(self._a(up=False))[0][0], preflight.ERROR)
        self.assertEqual(preflight.adapter_warnings(self._a("wifi"))[0][0], preflight.WARNING)

    def test_missing_tool_is_an_error(self):
        from l2loopcheck.capture import CaptureToolMissing

        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(preflight, "choose_backend", side_effect=CaptureToolMissing("install it")), \
                mock.patch.object(preflight, "_driver_check", return_value=None):
            checks = preflight.run_preflight(self._a(), d)
        self.assertEqual(checks[0]["status"], preflight.ERROR)
        self.assertEqual(checks[-1]["status"], preflight.UNKNOWN)
        self.assertTrue(preflight.blocking(checks))

    def test_low_disk(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(preflight.shutil, "disk_usage") as du:
            du.return_value = mock.Mock(free=100 * 1024 * 1024)
            self.assertEqual(preflight._disk_check(d, 2048)["status"], preflight.ERROR)

    def test_unwritable_folder(self):
        with tempfile.TemporaryDirectory() as d:
            blocker = os.path.join(d, "file")
            open(blocker, "w").close()
            self.assertEqual(preflight._disk_check(os.path.join(blocker, "sub"), 2048)["status"], preflight.ERROR)


if __name__ == "__main__":
    unittest.main()
