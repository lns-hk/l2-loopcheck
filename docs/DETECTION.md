# Detection spec

What each detector looks for, the thresholds it uses, what can fool it, and
what a single capture point cannot see. Thresholds are **initial values**; they
are to be calibrated against the lab captures (see `docs/LAB.md`).

## Vantage point

A laptop on an access port sees only flooded traffic (broadcast, multicast,
unknown unicast) plus traffic addressed to itself. On a SPAN/mirror port it
sees whatever the session mirrors. The report always states this limit.

## 1. Repeated frames and the loop fingerprint (`detect/duplicates.py`)

* Key: the whole frame without 802.1Q/QinQ tags, so a frame looping between
  VLANs is still recognised.
* A *copy* is the same key seen again within **200 ms** of the previous copy.
  Slower repeats (ARP retries ~1 s, mDNS probes 250 ms) are not counted.
* **Common period (loop fingerprint):** for every frame repeated 3+ times the
  median gap between copies is taken; gaps are clustered on a log scale
  (bins of x1.25). If frames from **≥3 distinct source MACs** share one
  period, and copies are **≥5 %** of all frames, the verdict is *Loop likely
  (high)*. One chatty host cannot make other hosts' frames repeat in step.
* Cross-VLAN: the same frame seen with two VLAN IDs → *Loop likely (medium)*.
* **SPAN artefact:** if >30 % of ordinary unicast TCP/UDP frames appear twice
  within 100 µs, the capture setup is duplicating frames; the verdict becomes
  *Inconclusive* unless other evidence is strong.
* Not used as primary evidence: unchanged IP TTL. mDNS and other link-local
  protocols always use TTL 255.

False positives to keep in mind: capture tools that write each frame twice,
NIC teaming that floods to both members, wireless bridges that re-flood.

## 2. Flooded traffic composition (`detect/traffic.py`)

* Per-protocol counts of broadcast/multicast (ARP, mDNS, SSDP, NBNS, LLMNR,
  DHCP, BACnet/IP, WS-Discovery, ICMPv6 ND, STP, LLDP, CDP, ...).
* Top talkers by source MAC with IPs and mDNS/NBNS names.
* *Storm without clear loop* when flooded traffic averages **≥1000 frames/s**,
  or one source sends **≥50 %** of flooded frames at **≥200/s**, without loop
  evidence.
* Storm-control saw-tooth: flooded rate falls from **≥500/s** to **≤5 %** of
  that in the next second, **≥2** times.

## 3. Spanning tree (`detect/stp.py`)

Parses STP, RSTP, MSTP (incl. MST configuration identifier) and Cisco PVST+.

* No BPDUs for the whole capture → warning (nothing blocks a redundant link).
* Topology changes: TC flag rising edges per bridge/port, plus TCN BPDUs.
  **≥3 events and ≥2/min** → *STP unstable*.
* Root changed during the capture → *STP unstable*.
* Two roots announced over the same period (>10 s overlap) → split tree.
* More than one MST configuration (name, revision, digest) → region mismatch.

## 4. Duplicate IPv4 addresses (RFC 5227)

Two different MACs using the same sender IP in ARP. ARP probes (0.0.0.0),
link-local and VRRP/HSRP/GLBP virtual MACs are ignored.

## 5. LLDP / CDP

Switch name, port, management IP and native VLAN: tells the reader where the
capture was taken.

## 6. Active probe

See `l2loopcheck/probe/__init__.py`. Up to 3 broadcast frames (EtherType
0x88B5, own MAC, random nonce), 1 per second, stop at the first return. A loop
is confirmed when a probe frame is captured twice (captures may include our own
transmission once), or once when the capture marks our own transmissions
(Linux cooked capture).

## Verdict order

Loop likely > STP unstable > Storm without clear loop > Inconclusive > Healthy.
*Inconclusive* is used when nothing positive was found but the capture is too
short (<10 s or <200 frames), lost ≥20 % of frames, or is distorted by SPAN
duplication.

## Security checks (`detect/security.py`)

All passive. Payloads are inspected in memory only to classify a frame; credentials, community strings and payloads are
never stored. Severity is a category, and there is no overall score. `observed` findings are facts in the capture;
`inferred` findings need checking on site.

| Finding | Trigger (initial threshold) | Severity |
|---|---|---|
| `gateway-spoof` | A gateway named by DHCP is claimed by two MACs. Most-ARPed addresses are not assumed to be gateways | Critical |
| `arp-reply-burst`, `arp-many-ips`, `arp-sweep` | 20 ARP replies/s; one MAC claims 16 IPs; 64 targets in 60 s | High, Medium, Medium |
| `mac-flood` | 1000 new source MACs in 10 s | High |
| `rogue-dhcp`, `rogue-ra` | Two servers or default routers in a VLAN. Same OUI (mesh or redundant pair): Medium. RA with lifetime 0 is ignored | High or Medium |
| `dhcp-starvation`, `dhcpv6-server`, `icmp-redirect` | 50 client MACs in 60 s; any DHCPv6 server; any redirect | High, Medium, Medium |
| `dtp-enabled`, `access-sees-vlans`, `trunk-port`, `double-tagged` | DTP seen; tags on a declared access port; tagged VLANs; 2+ tags | High, High, Medium, Medium |
| `fhrp-exposed`, `routing-exposed` | HSRP/VRRP/GLBP or OSPF/EIGRP/RIP/PIM without strong authentication | Medium, High with the default HSRP string |
| `name-poisoning`, `wpad` | LLMNR, NBT-NS or WPAD lookups | Medium |
| `cleartext-login`, `http-basic` | Login commands or HTTP Basic in clear text | Critical |
| `cleartext-service`, `snmp-default`, `smb1` | Telnet, FTP and similar with traffic beyond a bare SYN; default community; SMBv1 | High |
| `snmp-v12`, `tls-old`, `ot-exposed` | SNMP v1/v2c; negotiated TLS 1.1 or older; BACnet, Modbus, S7 and similar | Medium |
| `port-scan`, `host-sweep` | 100 ports on one host, or 64 hosts on one port, in 60 s | High |
| `dns-tunnel` | 20 queries with 45+ character labels under one domain | Medium |

A bare SYN never counts as a service being in use, so a port scan does not list every scanned port as exposed. Findings
from unicast traffic are limited on an access port, and the report's coverage table says so. One device repeating a frame
into several VLANs is reported as a multi-VLAN host and does not count towards a loop.
