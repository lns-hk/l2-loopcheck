"""Linux probe sender: AF_PACKET raw socket (needs root or CAP_NET_RAW)."""

from __future__ import annotations

import socket


def get_mac(interface: str) -> bytes:
    with open(f"/sys/class/net/{interface}/address", encoding="ascii") as f:
        return bytes.fromhex(f.read().strip().replace(":", ""))


class _Sender:
    def __init__(self, interface: str) -> None:
        self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.s.bind((interface, 0))

    def send(self, frame: bytes) -> None:
        self.s.send(frame)

    def close(self) -> None:
        self.s.close()


def open_sender(interface: str) -> _Sender:
    try:
        return _Sender(interface)
    except PermissionError as e:
        from . import ProbeUnavailable

        raise ProbeUnavailable("Sending a probe needs root or CAP_NET_RAW "
                               "(e.g. sudo setcap cap_net_raw+ep $(readlink -f $(which python3)))") from e
