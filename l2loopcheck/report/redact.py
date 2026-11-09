"""Make a result safe to share: pseudonymise MACs, IPs, host names and site details.

The mapping is consistent within one result, so "host A talks to host B" still
reads correctly, and is one-way: it is not stored anywhere.
"""

from __future__ import annotations

import copy
import ipaddress
import re

_MAC = re.compile(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", re.I)
_IP4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IP6 = re.compile(r"(?<![0-9a-f:.])(?:[0-9a-f]{1,4}:){1,7}:?(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?(?![0-9a-f:])", re.I)
_DEVICE = re.compile(r"\\Device\\NPF_\{[0-9A-Fa-f-]+\}")
_BRIDGE = re.compile(r"\b[0-9a-f]{1,4}[.:/](?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b", re.I)
SITE_KEYS = ("site", "client", "engineer", "org", "company", "case_ref", "authorised_by")
PATH_KEYS = ("run_dir", "saved_files", "tool", "tool_messages", "source", "interface")


class _Mapper:
    def __init__(self) -> None:
        self.mac: dict = {}
        self.ip: dict = {}
        self.names: dict = {}

    def _mac(self, m: re.Match) -> str:
        n = self.mac.setdefault(m.group(0).lower(), len(self.mac) + 1)
        return f"02:00:00:00:{(n >> 8) & 255:02x}:{n & 255:02x}"

    def _ip4(self, m: re.Match) -> str:
        v = m.group(0)
        try:
            addr = ipaddress.IPv4Address(v)
        except ValueError:
            return v
        if addr.is_multicast or v in ("0.0.0.0", "255.255.255.255"):
            return v
        n = self.ip.setdefault(v, len(self.ip) + 1)
        return f"192.0.2.{n % 254 + 1}" if n <= 254 else f"198.51.100.{n % 254 + 1}"

    def _ip6(self, m: re.Match) -> str:
        v = m.group(0)
        try:
            addr = ipaddress.IPv6Address(v)
        except ValueError:
            return v
        if addr.is_multicast or v == "::":
            return v
        n = self.ip.setdefault(addr.exploded, len(self.ip) + 1)
        return f"2001:db8::{n:x}"

    def text(self, s: str) -> str:
        s = _DEVICE.sub("adapter", s)
        for name, alias in self.names.items():
            s = re.sub(re.escape(name), alias, s, flags=re.I)
        s = _MAC.sub(self._mac, s)
        s = _IP6.sub(self._ip6, s)
        return _IP4.sub(self._ip4, s)

    def walk(self, x):
        if isinstance(x, str):
            return self.text(x)
        if isinstance(x, list):
            return [self.walk(v) for v in x]
        if isinstance(x, dict):
            return {k: self.walk(v) for k, v in x.items()}
        return x


def _collect_names(r: dict) -> set:
    names = set()
    sec = r.get("security") or {}
    for h in sec.get("hosts", []):
        names.update(h.get("names", []))
    for t in r.get("traffic", {}).get("top_talkers", []):
        names.update(t.get("names", []))
    for n in r.get("neighbours", []):
        names.update(x for x in (n.get("system_name"), n.get("chassis"), n.get("platform")) if x)
    for e in r.get("duplicates", {}).get("examples", []):
        if e.get("name"):
            names.add(e["name"])
    return {n for n in names if len(n) >= 3}


def redact(result: dict) -> dict:
    r = copy.deepcopy(result)
    m = _Mapper()
    for i, name in enumerate(sorted(_collect_names(r), key=len, reverse=True), 1):
        m.names[name] = f"device-{i}"
    eng = r.get("engagement") or {}
    for k in SITE_KEYS:
        if eng.get(k):
            eng[k] = "(redacted)"
    eng.pop("logo_path", None)
    eng.pop("authorisation_text", None)
    cap = r.get("capture", {})
    for k in PATH_KEYS:
        if cap.get(k):
            cap[k] = [] if isinstance(cap[k], list) else "(redacted)"
    for mark in r.get("marks", []):
        mark["label"] = "(redacted note)"
    out = m.walk(r)
    out["redacted"] = True
    return out
