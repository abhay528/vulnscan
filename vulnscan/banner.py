"""Banner grabbing and service/version fingerprinting."""

from __future__ import annotations

import re
import socket

# (compiled regex, product name). The first capture group is the version.
_FINGERPRINTS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"OpenSSH[_/ ]?([\d.]+)", re.I), "OpenSSH"),
    (re.compile(r"Apache/([\d.]+)", re.I), "Apache"),
    (re.compile(r"nginx/([\d.]+)", re.I), "nginx"),
    (re.compile(r"vsftpd ([\d.]+)", re.I), "vsftpd"),
    (re.compile(r"ProFTPD ([\d.]+)", re.I), "ProFTPD"),
    (re.compile(r"Pure-FTPd", re.I), "Pure-FTPd"),
    (re.compile(r"Microsoft-IIS/([\d.]+)", re.I), "IIS"),
    (re.compile(r"MySQL[ _-]?([\d.]+)", re.I), "MySQL"),
    (re.compile(r"MariaDB[ _-]?([\d.]+)", re.I), "MariaDB"),
    (re.compile(r"Exim ([\d.]+)", re.I), "Exim"),
    (re.compile(r"Postfix", re.I), "Postfix"),
    (re.compile(r"Redis[ _-]?server[ _-]?v?=?([\d.]+)", re.I), "Redis"),
]

# Payloads that nudge certain services into sending a useful banner.
_PROBES: dict[int, bytes] = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
    6379: b"INFO\r\n",
}


def grab_banner(sock: socket.socket, port: int) -> str:
    """Read a banner from an already-connected socket.

    The socket is expected to have a timeout set by the caller.
    Returns a stripped banner string (may be empty).
    """
    banner = ""
    try:
        probe = _PROBES.get(port)
        if probe:
            sock.sendall(probe)
        data = sock.recv(2048)
        banner = data.decode(errors="ignore").strip()
    except (OSError, socket.timeout):
        banner = ""
    return banner


def fingerprint(banner: str) -> tuple[str, str]:
    """Extract (product, version) from a banner string.

    Returns empty strings when nothing is recognised.
    """
    if not banner:
        return "", ""
    for pattern, product in _FINGERPRINTS:
        match = pattern.search(banner)
        if match:
            version = match.group(1) if match.groups() else ""
            return product, version
    return "", ""
