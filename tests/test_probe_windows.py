"""Windows probe sender: MAC lookup and Npcap open/close.

No test sends a frame on a real network. Sending is exercised only against a
fake wpcap library object.
"""

import json
import os
import subprocess
import unittest

NPF = "\\Device\\NPF_"


def _net_adapters() -> list[dict]:
    """Get-NetAdapter as the independent reference for name and MAC."""
    cmd = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
           "@(Get-NetAdapter | Select-Object Name,InterfaceGuid,MacAddress,Status) | ConvertTo-Json")
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                             capture_output=True, timeout=60, stdin=subprocess.DEVNULL).stdout
        data = json.loads(out.decode("utf-8-sig") or "[]")
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return []
    return data if isinstance(data, list) else [data]


@unittest.skipUnless(os.name == "nt", "Windows only")
class WindowsProbe(unittest.TestCase):
    def setUp(self):
        from l2loopcheck.probe import ProbeUnavailable, windows

        self.w = windows
        self.Unavailable = ProbeUnavailable

    def test_interface_guid(self):
        g = "3F2A1B0C-5D6E-4F70-8A9B-0C1D2E3F4A5B"
        self.assertEqual(self.w.interface_guid(NPF + "{" + g.lower() + "}"), g)
        self.assertEqual(self.w.interface_guid("{" + g + "}"), g)
        for bad in (NPF + "Loopback", "etwdump", "Ethernet", ""):
            with self.assertRaises(self.Unavailable):
                self.w.interface_guid(bad)

    def test_mac_matches_get_netadapter(self):
        adapters = [a for a in _net_adapters() if a.get("MacAddress")]
        if not adapters:
            self.skipTest("Get-NetAdapter not available")
        for a in adapters:
            info = self.w.adapter_info(NPF + a["InterfaceGuid"])
            self.assertEqual(info["alias"], a["Name"])
            self.assertEqual(info["mac"].hex(), a["MacAddress"].replace("-", "").lower())
            self.assertEqual(self.w.get_mac(NPF + a["InterfaceGuid"]), info["mac"])

    def test_unknown_adapter(self):
        with self.assertRaises(self.Unavailable):
            self.w.get_mac(NPF + "{00000000-0000-4000-8000-000000000000}")

    def test_open_close_real_npcap(self):
        """Open and close a real Npcap handle (no frame is sent). Without Npcap: a clear error."""
        up = [a for a in _net_adapters() if a.get("Status") == "Up" and a.get("MacAddress")]
        if not up:
            self.skipTest("no adapter is up")
        name = NPF + up[0]["InterfaceGuid"]
        try:
            self.w.npcap_version()
        except self.Unavailable as e:
            self.assertIn("Npcap", str(e))
            with self.assertRaises(self.Unavailable):
                self.w.open_sender(name)
            return
        s = self.w.open_sender(name)
        self.assertIsNotNone(s.handle)
        s.close()
        self.assertIsNone(s.handle)
        s.close()  # idempotent


class FakeWpcap:
    def __init__(self, open_ok=True, send_rc=0):
        self.open_ok, self.send_rc = open_ok, send_rc
        self.sent, self.closed, self.opened = [], 0, []

    def pcap_open_live(self, dev, snaplen, promisc, to_ms, errbuf):
        self.opened.append((dev, snaplen, promisc))
        if not self.open_ok:
            errbuf.value = b"Error opening adapter: Access is denied.  (5)"
            return None
        return 0x1234

    def pcap_sendpacket(self, h, buf, n):
        self.sent.append(bytes(buf[:n]))
        return self.send_rc

    def pcap_geterr(self, h):
        return b"send error (22)"

    def pcap_close(self, h):
        self.closed += 1


@unittest.skipUnless(os.name == "nt", "Windows only")
class WindowsSenderLogic(unittest.TestCase):
    def setUp(self):
        from l2loopcheck.probe import ProbeUnavailable, build_frame, windows

        self.w, self.Unavailable = windows, ProbeUnavailable
        self.frame = build_frame(b"\x02\x00\x5e\x00\x53\x01", b"\x01" * 8, 0)
        self.dev = NPF + "{3F2A1B0C-5D6E-4F70-8A9B-0C1D2E3F4A5B}"

    def test_send_probe_frame(self):
        lib = FakeWpcap()
        s = self.w._Sender(self.dev, lib)
        self.assertEqual(lib.opened, [(self.dev.encode(), 64, 0)])  # not promiscuous
        s.send(self.frame)
        self.assertEqual(lib.sent, [self.frame])
        s.close()
        s.close()
        self.assertEqual(lib.closed, 1)
        with self.assertRaises(OSError):
            s.send(self.frame)

    def test_only_probe_frames(self):
        s = self.w._Sender(self.dev, FakeWpcap())
        stp = b"\x01\x80\xc2\x00\x00\x00" + self.frame[6:]
        not_probe = self.frame[:12] + b"\x08\x06" + self.frame[14:]
        for bad in (stp, not_probe, self.frame[:16], self.frame + b"\0" * 1500):
            with self.assertRaises(ValueError):
                s.send(bad)
        self.assertTrue(self.w._is_probe_frame(self.frame))

    def test_open_denied_hint(self):
        with self.assertRaises(self.Unavailable) as cm:
            self.w._Sender(self.dev, FakeWpcap(open_ok=False))
        self.assertIn("Administrator", str(cm.exception))

    def test_send_error(self):
        s = self.w._Sender(self.dev, FakeWpcap(send_rc=-1))
        with self.assertRaises(OSError):
            s.send(self.frame)


if __name__ == "__main__":
    unittest.main()
