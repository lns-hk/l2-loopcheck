"""Windows capture support: dumpcap -D parsing, graceful stop, live run folder.

The parsing tests run on every platform. Process tests run on Windows only and
use a fake dumpcap (a Python child) so they need neither Wireshark nor Npcap.
"""

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock

from l2loopcheck import capture, winproc

# Sample `dumpcap -D` output from Wireshark 4.x on Windows 11 with Npcap
# (GUIDs made up; CRLF line endings as dumpcap writes them).
DUMPCAP_D_WINDOWS = (
    "1. \\Device\\NPF_{3F2A1B0C-5D6E-4F70-8A9B-0C1D2E3F4A5B} (Ethernet)\r\n"
    "2. \\Device\\NPF_{7C8D9E0F-1A2B-4C3D-9E4F-5A6B7C8D9E0F} (Wi-Fi)\r\n"
    "3. \\Device\\NPF_{0A1B2C3D-4E5F-4061-8273-8495A6B7C8D9} (Local Area Connection* 10)\r\n"
    "4. \\Device\\NPF_{11223344-5566-4778-899A-ABBCCDDEEFF0} (Ethernet 2)\r\n"
    "5. \\Device\\NPF_Loopback (Adapter for loopback traffic capture)\r\n"
    "6. etwdump (Event Tracing for Windows (ETW) reader)\r\n"
    "7. ciscodump (Cisco remote capture)\r\n"
    "8. randpkt (Random packet generator)\r\n"
    "9. sshdump.exe (SSH remote capture)\r\n"
)

ETH = "\\Device\\NPF_{3F2A1B0C-5D6E-4F70-8A9B-0C1D2E3F4A5B}"
ETH2 = "\\Device\\NPF_{11223344-5566-4778-899A-ABBCCDDEEFF0}"


class InterfaceParsing(unittest.TestCase):
    def test_windows_dumpcap(self):
        ifs = capture.parse_interfaces(DUMPCAP_D_WINDOWS)
        self.assertEqual(len(ifs), 9)
        self.assertEqual(ifs[0], (ETH, "Ethernet"))
        self.assertEqual(ifs[1][1], "Wi-Fi")
        self.assertEqual(ifs[2][1], "Local Area Connection* 10")
        self.assertEqual(ifs[4], ("\\Device\\NPF_Loopback", "Adapter for loopback traffic capture"))
        self.assertEqual(ifs[5], ("etwdump", "Event Tracing for Windows (ETW) reader"))

    def test_macos_and_tcpdump(self):
        text = ("1. en0 (Wi-Fi)\n2. lo0 (Loopback)\n3. bridge0\n"
                "1.eth0 [Up, Running, Connected]\n"
                "5.any (Pseudo-device that captures on all interfaces) [Up, Running]\n")
        self.assertEqual(capture.parse_interfaces(text), [
            ("en0", "Wi-Fi"), ("lo0", "Loopback"), ("bridge0", ""), ("eth0", ""),
            ("any", "Pseudo-device that captures on all interfaces")])

    def test_ignores_noise(self):
        text = "Capturing is not possible\r\n\r\n1. \\Device\\NPF_{AB} (Ethernet)\r\n"
        self.assertEqual(capture.parse_interfaces(text), [("\\Device\\NPF_{AB}", "Ethernet")])

    def test_resolve_interface(self):
        ifs = capture.parse_interfaces(DUMPCAP_D_WINDOWS)
        r = capture.resolve_interface
        self.assertEqual(r("Ethernet", ifs), ETH)
        self.assertEqual(r("ethernet 2", ifs), ETH2)
        self.assertEqual(r("1", ifs), ETH)
        self.assertEqual(r(ETH2, ifs), ETH2)
        self.assertEqual(r("en7", ifs), "en7")  # unknown: passed through to dumpcap
        self.assertEqual(r("42", ifs), "42")

    def test_tool_candidates_windows(self):
        with mock.patch.object(capture.os, "name", "nt"), \
                mock.patch.object(capture.sys, "platform", "win32"), \
                mock.patch.object(capture.shutil, "which", return_value=None), \
                mock.patch.dict(os.environ, {"ProgramFiles": r"C:\Program Files"}):
            c = capture._candidates("tshark")
        self.assertIn(os.path.join(r"C:\Program Files", "Wireshark", "tshark.exe"), c)


# A stand-in for dumpcap: streams a pcap to stdout, and on CTRL_BREAK prints
# dumpcap's drop statistics line and exits 0, as dumpcap does.
FAKE_DUMPCAP = textwrap.dedent(r'''
    import signal, sys, time
    sys.path.insert(0, sys.argv[1])
    from l2loopcheck.synth import SCENARIOS, to_pcap_bytes
    stop = []
    signal.signal(signal.SIGBREAK, lambda *a: stop.append(1))
    out = sys.stdout.buffer
    out.write(to_pcap_bytes(SCENARIOS["short"]()))
    out.flush()
    t0 = time.time()
    while not stop and time.time() - t0 < 20:
        time.sleep(0.02)
    sys.stderr.write("Packets received/dropped on interface 'fake': 10/3 (pcap:3/dumpcap:0) (76.9%)\n")
    sys.stderr.write("graceful\n" if stop else "timeout\n")
    sys.exit(0 if stop else 5)
''')


@unittest.skipUnless(os.name == "nt", "Windows only")
class WindowsProcess(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.fake = os.path.join(self.tmp.name, "fake_dumpcap.py")
        with open(self.fake, "w", encoding="utf-8") as f:
            f.write(FAKE_DUMPCAP)
        from l2loopcheck.synth import SCENARIOS
        self.n_frames = len(SCENARIOS["short"]())
        self.root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def tearDown(self):
        self.tmp.cleanup()

    def _patches(self):
        cmd = [sys.executable, self.fake, self.root]
        return (mock.patch.object(capture, "choose_backend", return_value=("dumpcap", sys.executable)),
                mock.patch.object(capture, "capture_command", return_value=cmd))

    def test_graceful_stop_shared_console(self):
        if not winproc.has_console():
            self.skipTest("test process has no console")
        p1, p2 = self._patches()
        with p1, p2:
            cp = capture.CaptureProcess("fake")
            got = []
            cp.on_packet = got.append
            cp.start()
            deadline = time.time() + 10
            while len(got) < self.n_frames and time.time() < deadline:
                time.sleep(0.05)
            cp.stop()
        self.assertEqual(len(got), self.n_frames)
        self.assertEqual(cp.proc.returncode, 0, cp.stderr_lines)
        self.assertIn("graceful", cp.stderr_lines)
        self.assertEqual(cp.drops, 3)

    def test_graceful_stop_hidden_console(self):
        """GUI case: a parent without a console gives the child a hidden console and still stops it cleanly."""
        script = textwrap.dedent(r'''
            import subprocess, sys, time
            sys.path.insert(0, sys.argv[1])
            from l2loopcheck import winproc
            assert not winproc.has_console()
            p = winproc.popen_stoppable([sys.executable, sys.argv[2], sys.argv[1]],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
            p.stdout.read(24)  # pcap header: child is running
            ok = winproc.send_ctrl_break(p)
            out, err = p.communicate(timeout=15)
            print(ok, p.returncode, err.decode().split()[-1])
        ''')
        parent = os.path.join(self.tmp.name, "parent.py")
        with open(parent, "w", encoding="utf-8") as f:
            f.write(script)
        DETACHED_PROCESS = 0x00000008
        # The venv python.exe is a launcher stub that would give the real interpreter a new
        # console; the base interpreter stays console-less, like a windowed (GUI) exe.
        exe = getattr(sys, "_base_executable", sys.executable)
        r = subprocess.run([exe, parent, self.root, self.fake], capture_output=True, text=True,
                           timeout=60, creationflags=DETACHED_PROCESS, stdin=subprocess.DEVNULL)
        self.assertEqual(r.stdout.split(), ["True", "0", "graceful"], r.stderr)

    def test_live_session_run_folder(self):
        if not winproc.has_console():
            self.skipTest("test process has no console")
        from l2loopcheck.live import LiveSession

        run_dir = os.path.join(self.tmp.name, "runs", "20261108-120000")
        p1, p2 = self._patches()
        with p1, p2:
            s = LiveSession("fake", run_dir=run_dir)
            s.start()
            deadline = time.time() + 10
            while s.snapshot()["packets"] < self.n_frames and time.time() < deadline and not s.ended.is_set():
                time.sleep(0.05)
            s.add_mark("unplugged uplink")
            r = s.stop()
        files = sorted(os.listdir(run_dir))
        self.assertIn("capture-00001.pcap", files)
        self.assertIn("result.json", files)
        self.assertIn("marks.json", files)
        self.assertIn("report.html", files)
        with open(os.path.join(run_dir, "result.json"), encoding="utf-8") as f:
            saved = json.load(f)
        self.assertEqual(saved["capture"]["packets"], self.n_frames)
        self.assertEqual(r["capture"]["drops"], 3)
        self.assertIsNone(s.error)


if __name__ == "__main__":
    unittest.main()
