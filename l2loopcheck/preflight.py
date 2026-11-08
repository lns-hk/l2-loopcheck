"""Adapter discovery and pre-flight checks, run before any capture starts.

Nothing here sends a frame. The last check opens the adapter for three seconds
to prove that capture actually works, because that is the only way to catch
permission problems, a dead link or a silent port before the engineer walks
away from the laptop.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Optional

from . import winproc
from .capture import CaptureToolMissing, choose_backend, list_interfaces

OK, WARNING, ERROR, UNKNOWN = "ok", "warning", "error", "unknown"
MIN_FREE_MB = 500
TEST_CAPTURE_S = 3

_VIRTUAL = re.compile(r"hyper-v|vethernet|virtual|vmware|virtualbox|vbox|docker|wsl|bridge\d|utun|awdl|llw|"
                      r"anpi|gif\d|stf\d|ap\d$", re.I)
_VPN = re.compile(r"vpn|wireguard|tailscale|zerotier|tap-|tun\d|tunnel|meta$|fortinet|anyconnect|openvpn", re.I)
_WIFI = re.compile(r"wi-?fi|wlan|wireless|802\.11|airport", re.I)
_HIDE = re.compile(r"wan miniport|wi-fi direct|bluetooth|kernel debug|teredo|isatap|6to4|ip-https", re.I)
KIND_LABEL = {"wired": "Wired", "wifi": "Wi-Fi", "virtual": "Virtual", "vpn": "VPN", "loopback": "Loopback",
              "other": "Other"}


def classify(text: str) -> str:
    """Adapter kind from its name and description."""
    t = text.lower()
    if "loopback" in t or re.fullmatch(r"lo\d*", t.strip()):
        return "loopback"
    if _VPN.search(t):
        return "vpn"
    if _VIRTUAL.search(t):
        return "virtual"
    if _WIFI.search(t):
        return "wifi"
    return "wired"


def _windows_details(name: str) -> dict:
    from .probe import ProbeUnavailable
    from .probe.windows import adapter_info

    try:
        info = adapter_info(name)
    except (ProbeUnavailable, OSError, ValueError):
        return {}
    return {"up": info["up"], "mac": info["mac"].hex(":") if len(info["mac"]) == 6 else "",
            "hardware": info["description"], "alias": info["alias"]}


def _macos_ports() -> dict:
    try:
        out = subprocess.run(["networksetup", "-listallhardwareports"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    ports, port = {}, ""
    for line in out.splitlines():
        if line.startswith("Hardware Port:"):
            port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:"):
            ports[line.split(":", 1)[1].strip()] = port
    return ports


def _posix_details(name: str) -> dict:
    path = f"/sys/class/net/{name}"
    if os.path.isdir(path):
        try:
            with open(f"{path}/operstate", encoding="ascii") as f:
                state = f.read().strip()
            with open(f"{path}/address", encoding="ascii") as f:
                mac = f.read().strip()
        except OSError:
            return {}
        return {"up": state in ("up", "unknown"), "mac": mac, "wifi": os.path.isdir(f"{path}/wireless")}
    try:
        out = subprocess.run(["ifconfig", name], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    m = re.search(r"ether ([0-9a-f:]{17})", out)
    return {"up": "status: active" in out or ("UP" in out and "status:" not in out), "mac": m.group(1) if m else ""}


def discover_adapters(preference: str = "auto") -> list[dict]:
    """Adapters from the capture tool, classified, best first. Extcap pseudo-interfaces are left out."""
    mac_ports = _macos_ports() if sys.platform == "darwin" else {}
    out = []
    for name, desc in list_interfaces(preference):
        if os.name == "nt" and not name.startswith("\\Device\\"):
            continue
        if re.match(r"(ciscodump|randpkt|sshdump|udpdump|wifidump|etwdump|any$|nflog|nfqueue|dbus|bluetooth|usbmon)", name):
            continue
        details = _windows_details(name) if os.name == "nt" else _posix_details(name)
        hardware = details.get("hardware") or mac_ports.get(name) or ""
        text = f"{name} {desc} {hardware}"
        if _HIDE.search(text):
            continue
        kind = classify(text)
        if details.get("wifi"):
            kind = "wifi"
        title = desc or details.get("alias") or name
        out.append({"name": name, "title": title, "hardware": hardware, "kind": kind, "up": details.get("up"),
                    "mac": details.get("mac", "")})
    rank = {"wired": 0, "wifi": 1, "other": 2, "virtual": 3, "vpn": 4, "loopback": 5}
    out.sort(key=lambda a: (0 if a["up"] else 1, rank[a["kind"]], a["title"].lower()))
    return out


def adapter_label(a: dict) -> str:
    state = {True: "connected", False: "no link", None: "link unknown"}[a["up"]]
    extra = f"{a['hardware']}, " if a["hardware"] and a["hardware"] != a["title"] else ""
    return f"{a['title']}  ({extra}{KIND_LABEL[a['kind']]}, {state})"


def suggest(adapters: list[dict]) -> tuple[Optional[dict], list[str]]:
    """The adapter to propose, and the reasons shown to the engineer."""
    if not adapters:
        return None, ["No capture adapters were found."]
    pick = next((a for a in adapters if a["kind"] == "wired" and a["up"]), None)
    reasons = []
    if pick:
        reasons.append(f"Suggested {pick['title']}: a physical wired adapter with a live link.")
    else:
        pick = adapters[0]
        reasons.append("No wired adapter with a live link was found. Plug in the cable and press Refresh.")
    for a in adapters:
        if a is pick:
            continue
        if a["kind"] != "wired":
            reasons.append(f"Not suggested: {a['title']} ({KIND_LABEL[a['kind']]}).")
        elif not a["up"]:
            reasons.append(f"Not suggested: {a['title']} has no link.")
    return pick, reasons[:6]


def adapter_warnings(a: dict) -> list[tuple[str, str]]:
    """(status, message) about this adapter being the wrong place to capture."""
    out = []
    if a["kind"] == "loopback":
        out.append((ERROR, "This is the computer's internal loopback. It never sees the network."))
    elif a["kind"] == "vpn":
        out.append((ERROR, "This is a VPN or tunnel. It does not see the switch or any Layer-2 traffic."))
    elif a["kind"] == "virtual":
        out.append((WARNING, "This is a virtual adapter. It shows what the host or virtual switch passes to it, not "
                             "the raw switch port. Pick the physical adapter instead, if it is listed."))
    elif a["kind"] == "wifi":
        out.append((WARNING, "This is Wi-Fi. Wi-Fi hides most Layer-2 traffic and spanning tree, so a loop can go "
                             "unseen. Use a wired adapter on the switch."))
    if a["up"] is False:
        out.append((ERROR, "This adapter has no link. Check the cable and the switch port."))
    return out


def _check(cid: str, title: str, status: str, detail: str) -> dict:
    return {"id": cid, "title": title, "status": status, "detail": detail}


def _tool_check(preference: str) -> tuple[dict, Optional[tuple[str, str]]]:
    try:
        backend, exe = choose_backend(preference)
    except CaptureToolMissing as e:
        return _check("tool", "Capture tool", ERROR, str(e)), None
    version = ""
    try:
        p = subprocess.run([exe, "-v"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15,
                           stdin=subprocess.DEVNULL, **winproc.hidden_kwargs())
        version = (p.stdout or p.stderr).strip().splitlines()[0] if (p.stdout or p.stderr).strip() else ""
    except (OSError, subprocess.SubprocessError):
        pass
    return _check("tool", "Capture tool", OK, version or f"{backend} found at {exe}."), (backend, exe)


def _driver_check() -> Optional[dict]:
    title = "Capture driver"
    if os.name == "nt":
        path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap", "wpcap.dll")
        if not os.path.isfile(path):
            return _check("driver", title, ERROR, "Npcap is not installed. Install it from https://npcap.com/ .")
        try:
            out = subprocess.run(["sc", "query", "npcap"], capture_output=True, text=True, errors="replace", timeout=15,
                                 stdin=subprocess.DEVNULL, **winproc.hidden_kwargs()).stdout
        except (OSError, subprocess.SubprocessError):
            return _check("driver", title, UNKNOWN, "Could not query the Npcap service.")
        if "RUNNING" not in out:
            return _check("driver", title, ERROR, "The Npcap driver is installed but not running. Restart Windows, "
                                                  "or reinstall Npcap.")
        return _check("driver", title, OK, "Npcap is installed and running.")
    if sys.platform == "darwin":
        if not os.access("/dev/bpf0", os.R_OK):
            return _check("driver", title, ERROR, "This user cannot read /dev/bpf. Install ChmodBPF from the Wireshark "
                                                  "package, then log out and in again.")
        return _check("driver", title, OK, "BPF devices are readable.")
    return None


def _disk_check(folder: str, max_total_mb: int) -> dict:
    title = "Space for the capture"
    try:
        os.makedirs(folder, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=folder):
            pass
        free = shutil.disk_usage(folder).free // (1024 * 1024)
    except OSError as e:
        return _check("disk", title, ERROR, f"Cannot write to {folder}: {e}")
    if free < MIN_FREE_MB:
        return _check("disk", title, ERROR, f"Only {free} MB free in {folder}; at least {MIN_FREE_MB} MB is needed.")
    if free < max_total_mb:
        return _check("disk", title, WARNING, f"{free} MB free, less than the {max_total_mb} MB capture limit. "
                                              "Old capture files will be removed sooner.")
    return _check("disk", title, OK, f"{free:,} MB free in {folder}.")


def _test_capture(backend: str, exe: str, a: dict, seconds: int = TEST_CAPTURE_S) -> dict:
    title = "Test capture"
    if backend != "dumpcap":
        return _check("test", title, UNKNOWN, "Only checked with dumpcap.")
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "t.pcapng")
        try:
            p = subprocess.run([exe, "-i", a["name"], "-a", f"duration:{seconds}", "-q", "-w", target],
                               capture_output=True, encoding="utf-8", errors="replace", timeout=seconds + 25,
                               stdin=subprocess.DEVNULL, **winproc.hidden_kwargs())
        except subprocess.TimeoutExpired:
            return _check("test", title, ERROR, "The capture tool did not finish. Another program may be holding the adapter.")
        except OSError as e:
            return _check("test", title, ERROR, str(e))
    if p.returncode != 0:
        msg = " ".join(line.strip() for line in p.stderr.splitlines() if line.strip())[:300]
        return _check("test", title, ERROR, f"The adapter could not be opened: {msg or 'unknown error'}")
    m = re.search(r"Packets captured:\s*(\d+)", p.stderr.replace("\r", "\n"))
    n = int(m.group(1)) if m else None
    if n == 0:
        return _check("test", title, WARNING, f"No frames arrived in {seconds} seconds. Check the cable and the port. "
                                              "A very quiet port can also look like this.")
    if n is None:
        return _check("test", title, UNKNOWN, "The test capture ran, but it did not report a frame count.")
    return _check("test", title, OK, f"{n:,} frames received in {seconds} seconds.")


def run_preflight(adapter: Optional[dict], folder: str, preference: str = "auto", max_total_mb: int = 2048) -> list[dict]:
    tool, found = _tool_check(preference)
    checks = [tool]
    driver = _driver_check()
    if driver:
        checks.append(driver)
    checks.append(_disk_check(folder, max_total_mb))
    if adapter is None:
        checks.append(_check("adapter", "Network adapter", ERROR, "No adapter was selected."))
        return checks
    warnings = adapter_warnings(adapter)
    worst = ERROR if any(s == ERROR for s, _m in warnings) else WARNING if warnings else OK
    checks.append(_check("adapter", "Network adapter", worst,
                         " ".join(m for _s, m in warnings) or f"{adapter['title']} is a wired adapter with a live link."))
    blocked = any(c["status"] == ERROR for c in checks)
    if found and not blocked:
        checks.append(_test_capture(found[0], found[1], adapter))
    else:
        checks.append(_check("test", "Test capture", UNKNOWN, "Skipped until the problems above are fixed."))
    return checks


def blocking(checks: list[dict]) -> list[dict]:
    return [c for c in checks if c["status"] == ERROR]
