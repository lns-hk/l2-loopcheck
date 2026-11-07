# l2-loopcheck

Layer-2 loop and broadcast-storm health check. Plug a laptop into an access or
SPAN port, capture, and get evidence of a loop, a storm or spanning-tree
instability, plus a report you can hand to the client.

> Status: early development (v0.1 dev). Not yet released.

## What it finds

* **Loops**: frames from many unrelated devices repeating with one common
  period (the loop's round-trip time), frames appearing in two VLANs, and an
  optional probe that sends up to 3 test frames and watches for them to return.
* **Storms without a loop**: broadcast/multicast rate by protocol and the
  devices sending most of it; the saw-tooth left by storm control.
* **Spanning-tree problems**: no BPDUs at all, frequent topology changes, root
  changes, two roots at once, MST region mismatches (STP/RSTP/MSTP/PVST+).
* **Duplicate IP addresses**, and LLDP/CDP to show which switch port you are on.

Verdicts: *Loop likely*, *STP unstable*, *Storm without clear loop*,
*Inconclusive*, *Healthy*. Every finding separates what was observed (with
frame numbers you can check in Wireshark) from the hypothesis.

## Install

* macOS: see [docs/INSTALL-MACOS.md](docs/INSTALL-MACOS.md)
* Windows: see [docs/INSTALL-WINDOWS.md](docs/INSTALL-WINDOWS.md)
* From source (any OS, Python 3.10+): `pip install .` for the CLI,
  `pip install ".[gui]"` for the GUI, then `l2loopcheck gui`.

## Quick start (command line)

```sh
python -m l2loopcheck analyze capture.pcapng --html report.html
python -m l2loopcheck interfaces
python -m l2loopcheck live -i en7          # Ctrl-C or 'q' to stop
python -m l2loopcheck demo loop            # write a synthetic loop capture
```

Live capture uses Wireshark's `dumpcap` (recommended: no admin rights needed)
or `tcpdump`. Wireshark is not bundled; install it from wireshark.org.

The analysis engine and CLI use only the Python standard library (3.10+). The
GUI uses Dear PyGui.

See [docs/DETECTION.md](docs/DETECTION.md) for how each detector works.

## Testing

`python -m unittest discover -s tests -t .` runs the unit tests against
synthetic captures (and cross-checks counts with tshark when installed).
`sudo bash tests/lab/netns_loop.sh` builds a real loop between Linux bridges,
captures it live and checks the verdict; CI runs it on every push.

## Licence

MIT
