#!/usr/bin/env bash
# Build a real Layer-2 loop with Linux network namespaces and bridges (STP off),
# capture it live with l2-loopcheck, and check the verdict. Needs root.
#
#   host(ns h1) --- br1 ===== br2 --- probe point (ns cap)
#                    \\_______//      two links between br1 and br2 = loop
set -euo pipefail
cleanup() {
  for ns in h1 h2 h3 h4 h5 cap sw; do ip netns del $ns 2>/dev/null || true; done
}
trap cleanup EXIT
cleanup
ip netns add sw; ip netns add cap
for n in 1 2 3 4 5; do ip netns add h$n; done
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
attach cap br2 ecap
for n in 1 2 3 4 5; do
  br=br1; [ $((n % 2)) -eq 0 ] && br=br2
  attach h$n $br eh$n
  ip -n h$n addr add 192.0.2.$n/24 dev eh$n
done
# rate-limit the loop so the runner survives: tc on one link
ip netns exec sw tc qdisc add dev l1-a root tbf rate 20mbit burst 32kbit latency 50ms
ip netns exec sw tc qdisc add dev l2-a root tbf rate 20mbit burst 32kbit latency 50ms
OUT=$(mktemp -d)
ip netns exec cap timeout 25 tcpdump -i ecap -U -s 0 -w "$OUT/loop.pcap" 2>/dev/null &
sleep 2
# every host ARPs for a missing address once per second: their broadcasts circulate
for n in 1 2 3 4 5; do
  ip netns exec h$n sh -c "for i in \$(seq 12); do ping -c1 -W1 192.0.2.$((100 + n)) >/dev/null 2>&1; sleep 1; done" &
done
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
