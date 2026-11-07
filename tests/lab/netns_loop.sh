#!/usr/bin/env bash
# Build a real Layer-2 loop with Linux network namespaces and bridges (STP off),
# capture it live with l2-loopcheck, and check the verdict. Needs root.
#
#   host(ns h1) --- br1 ===== br2 --- probe point (ns cap)
#                    \\_______//      two links between br1 and br2 = loop
set -euo pipefail
cleanup() {
  for ns in h1 h2 cap sw; do ip netns del $ns 2>/dev/null || true; done
}
trap cleanup EXIT
cleanup
ip netns add sw; ip netns add h1; ip netns add h2; ip netns add cap
ip -n sw link add br1 type bridge stp_state 0
ip -n sw link add br2 type bridge stp_state 0
ip -n sw link set br1 up; ip -n sw link set br2 up
# two parallel links between the bridges -> loop
for i in 1 2; do
  ip -n sw link add l$i-a type veth peer name l$i-b
  ip -n sw link set l$i-a master br1; ip -n sw link set l$i-b master br2
  ip -n sw link set l$i-a up; ip -n sw link set l$i-b up
done
attach() { # ns bridge ifname
  ip link add $3 type veth peer name $3-sw
  ip link set $3 netns $1; ip link set $3-sw netns sw
  ip -n sw link set $3-sw master $2; ip -n sw link set $3-sw up
  ip -n $1 link set $3 up; ip -n $1 link set lo up
}
attach h1 br1 eh1; attach h2 br2 eh2; attach cap br2 ecap
ip -n h1 addr add 192.0.2.1/24 dev eh1
ip -n h2 addr add 192.0.2.2/24 dev eh2
# rate-limit the loop so the runner survives: tc on one link
ip netns exec sw tc qdisc add dev l1-a root tbf rate 20mbit burst 32kbit latency 50ms
ip netns exec sw tc qdisc add dev l2-a root tbf rate 20mbit burst 32kbit latency 50ms
OUT=$(mktemp -d)
ip netns exec cap timeout 25 tcpdump -i ecap -U -s 0 -w "$OUT/loop.pcap" 2>/dev/null &
sleep 2
# a few broadcasts from two hosts start the storm
ip netns exec h1 arping -c 3 -I eh1 192.0.2.99 >/dev/null 2>&1 || ip netns exec h1 ping -b -c 3 192.0.2.255 >/dev/null 2>&1 || true
ip netns exec h2 ping -c 3 -W 1 192.0.2.1 >/dev/null 2>&1 || true
sleep 15
# break the loop and let the capture end
ip -n sw link set l2-a down
wait || true
python3 -m l2loopcheck analyze "$OUT/loop.pcap" --json "$OUT/result.json"
python3 - "$OUT/result.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
v = r["verdict"]["label"]
print("verdict:", v, "| copy ratio:", round(r["duplicates"]["copy_ratio"], 3))
assert v == "Loop likely", v
PY
