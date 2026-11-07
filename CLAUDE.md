# l2-loopcheck — project brief

Owner: Lierre Wong (GitHub `lns-hk`), independent IT / OT consultant in Hong Kong.

**Goal:** an open-source Layer-2 loop / broadcast-storm health-check tool. Typical case: an engineer plugs a laptop
into an access or SPAN port on a shared, undocumented building or office network with intermittent outages, captures
traffic, and needs evidence of a loop, a storm or STP instability, then a report for the client. It will be
published on github.com/lns-hk and listed on https://lns.hk/toybox/ as a portfolio piece.

**Working mode — important:** this project is developed in conversation with the owner. Before writing code, discuss
scope, priorities and design choices with the user and agree on a plan. Propose, don't assume. Build in small steps the
user can review. Do not create the GitHub repo or push until the user says so.

## Starting ideas (to discuss, not a fixed spec)
- Passive analysis of pcap/pcapng (Ethernet, 802.1Q/QinQ, Linux cooked): broadcast/multicast rate over time,
  duplicate-frame (replay) detection, TTL unchanged across copies, STP/RSTP/MSTP/PVST+ roots and topology changes,
  ARP storms and duplicate IPs, LLDP/CDP neighbour context.
- Optional active probe (Linux, root, opt-in, strictly rate-capped): send tagged test frames and count returns.
- Findings + an overall verdict ("Loop likely" / "Storm without clear loop" / "STP unstable" / "Healthy") with
  recommendations (loop protection, BPDU guard, storm control, unmanaged switches, ring protocol config).
- Outputs: terminal summary, JSON, self-contained HTML report with a timeline chart.
- Python 3.10+, ideally stdlib-only at runtime; tests with synthetic pcaps. MIT licence.

## Rules
- Never mention any employer, client, building or customer. Use documentation/private ranges and locally
  administered MACs in samples.
- Git commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
