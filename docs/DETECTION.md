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
