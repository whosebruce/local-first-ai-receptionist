"""Test network guard: fails any test that attempts a non-loopback connection.

Activated by RECEPTIONIST_TEST_NETGUARD=1 (scripts/verify.sh sets it). This is
a belt-and-braces proof that the deterministic suite can never contact a real
person, transport, model endpoint, or SaaS: every socket connect to anything
except 127.0.0.0/8, ::1, or an AF_UNIX path raises immediately.
"""
from __future__ import annotations

import ipaddress
import socket

_installed = False
_original_connect = socket.socket.connect


class NetworkGuardViolation(AssertionError):
    pass


def _is_loopback(address) -> bool:
    if isinstance(address, (str, bytes)):  # AF_UNIX
        return True
    host = address[0]
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _guarded_connect(self, address):
    if not _is_loopback(address):
        raise NetworkGuardViolation(
            f"test attempted a non-loopback connection to {address!r}")
    return _original_connect(self, address)


def install() -> None:
    global _installed
    if _installed:
        return
    socket.socket.connect = _guarded_connect
    _installed = True
