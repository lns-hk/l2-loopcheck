# Windows work package

Owner: the Windows agent on Lierre-PC. Everything else is shared code; keep
changes to shared modules minimal and covered by tests on all platforms.

## Goals

1. **Live capture via dumpcap** (`l2loopcheck/capture.py`): verify
   `find_dumpcap()` paths, `list_interfaces()` parsing of `dumpcap -D` output
   (`\Device\NPF_{GUID} (Ethernet)`), streaming `dumpcap -w -` on Windows
   (binary stdout, no console window), clean stop (terminate) and drop stats.
2. **Probe sender** (`l2loopcheck/probe/windows.py`): implement `get_mac()`
   and `open_sender()` with stdlib `ctypes` and Npcap's `wpcap.dll`
   (`pcap_open_live` + `pcap_sendpacket`, `os.add_dll_directory` for
   `%SystemRoot%\System32\Npcap`). MAC lookup: `GetAdaptersAddresses` via
   ctypes or `getmac /v /fo csv` matched on the NPF GUID. Raise
   `ProbeUnavailable` with a clear message when Npcap is missing.
   Safety rules in `probe/__init__.py` are fixed; do not change them.
3. **GUI on Windows** (`l2loopcheck/gui/`, Dear PyGui): run, fix
   Windows-specific issues (fonts, DPI, paths).
4. **Packaging**: PyInstaller one-folder build producing
   `l2-loopcheck-windows.zip` with `l2loopcheck-gui.exe` and `l2loopcheck.exe`;
   script in `packaging/windows/build.ps1`. Unsigned in v1; add
   `docs/INSTALL-WINDOWS.md` with SmartScreen "More info → Run anyway" steps
   and the Wireshark/Npcap prerequisite.
5. **Tests**: full `python -m unittest discover -s tests -t .` passes on
   Windows; add Windows-only tests (skip elsewhere) for interface parsing and
   the probe sender (send to a loopback-free check: open/close only, unless
   Lierre approves a real send).

## Rules

* Never send probe frames on a real network without Lierre's explicit OK.
* No client, employer or building names anywhere. Use documentation ranges.
* Work on branch `windows`; open a PR to `main`. Commits end with
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
