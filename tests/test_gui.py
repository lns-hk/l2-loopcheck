"""GUI flow, offscreen. Skipped when PySide6 is not installed (CI's stdlib job)."""

import io
import os
import tempfile
import threading
import time
import unittest
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
try:
    from PySide6.QtWidgets import QApplication, QMessageBox
except ImportError:
    QApplication = None

SHOTS = os.environ.get("L2LC_GUI_SHOTS")
ADAPTERS = [
    {"name": "wired0", "title": "Ethernet 2", "hardware": "USB 10/100/1000 LAN", "kind": "wired", "up": True, "mac": ""},
    {"name": "wifi0", "title": "Wi-Fi", "hardware": "", "kind": "wifi", "up": True, "mac": ""},
    {"name": "vpn0", "title": "Example VPN", "hardware": "", "kind": "vpn", "up": True, "mac": ""},
]
CHECKS = [{"id": "tool", "title": "Capture tool", "status": "ok", "detail": "Dumpcap 4.6"},
          {"id": "test", "title": "Test capture", "status": "ok", "detail": "120 frames received in 3 seconds."}]


def analysed(name="security-issues", vantage="span"):
    from l2loopcheck.engine import Analyzer
    from l2loopcheck.pcapio import CaptureReader
    from l2loopcheck.synth import SCENARIOS, to_pcap_bytes

    a = Analyzer(source=name)
    a.declared_vantage = vantage
    a.feed_all(CaptureReader(io.BytesIO(to_pcap_bytes(SCENARIOS[name]()))))
    return a.finish()


class FakeSession:
    instances = []

    def __init__(self, interface, backend, run_dir, max_mb, vantage=None, engagement=None):
        self.interface, self.run_dir, self.vantage, self.engagement = interface, run_dir, vantage, engagement
        self.ended, self.error, self._marks, self.stopped = threading.Event(), None, [], False
        os.makedirs(run_dir, exist_ok=True)
        FakeSession.instances.append(self)

    def start(self):
        pass

    def snapshot(self):
        return {"copies": 0, "flooded": 12, "total": 240, "tc_total": 1, "saved_mb": 3.0, "packets": 900, "elapsed": 5.0}

    def series(self, n=300):
        return [{"t": i, "flooded": 10 + i % 5, "copies": 0} for i in range(60)]

    def marks(self):
        return self._marks

    def add_mark(self, text):
        m = {"ts": time.time(), "label": text}
        self._marks.append(m)
        return m

    def stop(self, branding=None):
        from l2loopcheck.cli import write_outputs

        self.stopped = True
        r = analysed()
        r["engagement"] = self.engagement
        write_outputs(r, os.path.join(self.run_dir, "result.json"), os.path.join(self.run_dir, "report.html"))
        return r


@unittest.skipIf(QApplication is None, "PySide6 not installed")
class GuiFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from l2loopcheck.gui import theme

        cls.app = QApplication.instance() or QApplication([])
        cls.app.setStyle("Fusion")
        cls.app.setStyleSheet(theme.stylesheet())

    def setUp(self):
        from l2loopcheck.gui import app, common, wizard

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.wizard_mod = wizard
        patches = [mock.patch.object(common, "SETTINGS_PATH", os.path.join(self.tmp.name, "s.json")),
                   mock.patch.object(wizard, "save_settings", lambda s: None),
                   mock.patch.object(wizard.pf, "discover_adapters", return_value=ADAPTERS),
                   mock.patch.object(wizard.pf, "run_preflight", return_value=CHECKS),
                   mock.patch.object(wizard, "LiveSession", FakeSession),
                   mock.patch.object(wizard.Wizard, "ask", lambda *_a: True),
                   mock.patch.object(wizard.RunningPage, "ask", lambda *_a: True, create=True)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        FakeSession.instances.clear()
        self.win = app.MainWindow()
        self.win.settings["runs_dir"] = self.tmp.name
        self.win.show()
        self.addCleanup(self.win.close)

    def pump(self, until, seconds=8):
        end = time.time() + seconds
        while time.time() < end:
            self.app.processEvents()
            if until():
                return
            time.sleep(0.01)
        self.fail("timed out waiting for the GUI")

    def shot(self, name):
        self.app.processEvents()
        if SHOTS:
            self.win.grab().save(os.path.join(SHOTS, f"{name}.png"))

    def _to_plan(self):
        self.win.start_wizard()
        w = self.win.wizard
        self.assertFalse(w.next_btn.isEnabled())
        w.site.fields["site"].setText("Level 3 comms room")
        w.site.fields["engineer"].setText("A. Engineer")
        self.assertFalse(w.next_btn.isEnabled(), "authorisation is required")
        w.site.auth.setChecked(True)
        self.assertTrue(w.next_btn.isEnabled())
        self.shot("1-site")
        w.next()
        self.pump(lambda: w.network.adapters)
        self.assertEqual(w.network.selected()["title"], "Ethernet 2")
        self.assertFalse(w.next_btn.isEnabled(), "adapter must be confirmed")
        w.network.confirm.setChecked(True)
        self.assertTrue(w.next_btn.isEnabled())
        self.shot("2-network")
        w.next()
        self.pump(lambda: w.pre.checks)
        self.assertTrue(w.next_btn.isEnabled())
        self.shot("3-preflight")
        w.next()
        self.shot("4-plan")
        return w

    def test_full_run_ends_on_results_with_a_report(self):
        w = self._to_plan()
        w.next()
        s = FakeSession.instances[0]
        self.assertEqual(s.engagement["site"], "Level 3 comms room")
        self.assertTrue(s.engagement["authorised"])
        self.assertEqual(len(s.engagement["preflight"]), 2)
        w.running.mark.setText("unplugged 2/F uplink")
        w.running.add_mark()
        self.assertEqual(s.marks()[0]["label"], "unplugged 2/F uplink")
        w.running.tick()
        self.shot("5-running")
        w.running.request_stop()
        self.pump(lambda: self.win.stack.currentWidget() is self.win.results)
        self.assertTrue(s.stopped)
        self.assertTrue(self.win.results.open_btn.isEnabled())
        self.assertGreater(self.win.results.table.rowCount(), 5)
        self.assertTrue(os.path.isfile(os.path.join(s.run_dir, "report.html")))
        self.shot("6-results")

    def test_vpn_adapter_is_refused(self):
        self.win.start_wizard()
        w = self.win.wizard
        w.go(1)
        self.pump(lambda: w.network.adapters)
        w.network.combo.setCurrentIndex(2)
        w.network.confirm.setChecked(True)
        self.assertFalse(w.next_btn.isEnabled())
        self.assertTrue(w.network.warn.isVisible())
        self.shot("2-network-vpn")

    def test_preflight_error_blocks(self):
        with mock.patch.object(self.wizard_mod.pf, "run_preflight",
                               return_value=[{"id": "x", "title": "Capture tool", "status": "error", "detail": "missing"}]):
            self.win.start_wizard()
            w = self.win.wizard
            w.go(2)
            self.pump(lambda: w.pre.checks)
            self.assertFalse(w.next_btn.isEnabled())
            self.shot("3-preflight-error")

    def test_preflight_warning_needs_acknowledgement(self):
        with mock.patch.object(self.wizard_mod.pf, "run_preflight",
                               return_value=[{"id": "x", "title": "Test capture", "status": "warning", "detail": "quiet"}]):
            self.win.start_wizard()
            w = self.win.wizard
            w.go(2)
            self.pump(lambda: w.pre.checks)
            self.assertFalse(w.next_btn.isEnabled())
            w.pre.accept.setChecked(True)
            self.assertTrue(w.next_btn.isEnabled())

    def test_capture_stops_at_planned_time(self):
        w = self._to_plan()
        w.next()
        w.running.seconds = 1
        w.running.started = time.time() - 5
        w.running.tick()
        self.pump(lambda: self.win.stack.currentWidget() is self.win.results)

    def test_dead_capture_tool_still_produces_results(self):
        w = self._to_plan()
        w.next()
        s = FakeSession.instances[0]
        s.error = "dumpcap exited with code 2"
        s.ended.set()
        w.running.tick()
        self.pump(lambda: self.win.stack.currentWidget() is self.win.results)

    def test_no_frames_shows_failure_banner(self):
        from l2loopcheck.engine import Analyzer

        r = Analyzer(source="x").finish()
        self.win.show_result(r, self.tmp.name)
        self.assertTrue(self.win.results.banner.isVisible())
        self.shot("6-results-empty")

    def test_markup_in_a_finding_is_not_interpreted(self):
        r = analysed()
        r["verdict"]["findings"][0]["title"] = "<img src=x>"
        self.win.show_result(r, self.tmp.name)
        self.assertIn("<img src=x>", self.win.results.detail.toPlainText())  # shown literally, not parsed


if __name__ == "__main__":
    unittest.main()
