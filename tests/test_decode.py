import random
import unittest

from l2loopcheck import synth as s
from l2loopcheck.decode import decode


class Decode(unittest.TestCase):
    def test_rstp_bpdu(self):
        f = decode(s.bpdu(s.mac(1), s.mac(2), root_prio=4096, cost=19, flags=0x3D), 1)
        b = f.bpdu
        self.assertEqual(b.kind, "RSTP")
        self.assertEqual(b.root_prio, 4096)
        self.assertEqual(b.root_cost, 19)
        self.assertTrue(b.tc)
        self.assertEqual(b.root_mac, s.mac(2))

    def test_mstp_region(self):
        f = decode(s.bpdu(s.mac(1), s.mac(2), version=3, region="CAMPUS", revision=7), 1)
        self.assertEqual(f.bpdu.kind, "MSTP")
        self.assertEqual(f.bpdu.mst_region, "CAMPUS")
        self.assertEqual(f.bpdu.mst_revision, 7)

    def test_lldp(self):
        f = decode(s.lldp(s.mac(5), "SW-1", "Gi1/0/3", s.ip(192, 0, 2, 2)), 1)
        self.assertEqual(f.neighbour.system_name, "SW-1")
        self.assertEqual(f.neighbour.port, "Gi1/0/3")
        self.assertEqual(f.neighbour.mgmt_ip, "192.0.2.2")

    def test_cdp(self):
        f = decode(s.cdp(s.mac(5), "core-sw", "GigabitEthernet0/1", "WS-C2960"), 1)
        self.assertEqual(f.proto, "CDP")
        self.assertEqual(f.neighbour.system_name, "core-sw")
        self.assertEqual(f.neighbour.native_vlan, 20)

    def test_mdns_name_and_vlan_core(self):
        f = decode(s.mdns_query(s.mac(3), s.ip(192, 0, 2, 3), "printer._ipp._tcp.local", vlan=30), 1)
        self.assertEqual(f.vlans, (30,))
        self.assertEqual(f.proto, "mDNS")
        self.assertEqual(f.name, "printer._ipp._tcp.local")
        g = decode(s.mdns_query(s.mac(3), s.ip(192, 0, 2, 3), "printer._ipp._tcp.local", vlan=40), 1)
        self.assertEqual(f.core, g.core)  # VLAN tag excluded from duplicate key

    def test_arp(self):
        f = decode(s.arp(s.mac(9), s.ip(192, 0, 2, 9), s.ip(192, 0, 2, 1)), 1)
        self.assertEqual(f.arp[2], s.ip(192, 0, 2, 9))
        self.assertTrue(f.bcast)

    def test_garbage_never_raises(self):
        rng = random.Random(0)
        for _ in range(5000):
            data = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 120)))
            for lt in (1, 113, 276):
                decode(data, lt)
        # truncated versions of real frames
        frames = [s.bpdu(s.mac(1), s.mac(2), version=3, region="X"), s.lldp(s.mac(5), "a", "b", b"\1\2\3\4"),
                  s.cdp(s.mac(5), "c", "d", "e"), s.mdns_query(s.mac(1), b"\1\2\3\4", "a.b.local")]
        for fr in frames:
            for n in range(len(fr)):
                decode(fr[:n], 1)


if __name__ == "__main__":
    unittest.main()
