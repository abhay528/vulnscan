"""Concurrent TCP port scanner."""

from __future__ import annotations

import datetime
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, Optional

from .banner import fingerprint, grab_banner
from .constants import COMMON_PORTS, WEAK_SERVICES
from .models import Finding, PortResult, ScanResult, Severity
from .vulndb import VulnDB


class Scanner:
    """Scan a host for open ports and assess each service."""

    def __init__(
        self,
        timeout: float = 1.0,
        workers: int = 100,
        vulndb: Optional[VulnDB] = None,
    ) -> None:
        self.timeout = timeout
        self.workers = max(1, workers)
        self.vulndb = vulndb or VulnDB.load_default()

    # -- low level -----------------------------------------------------

    def _scan_one(self, host: str, port: int) -> Optional[PortResult]:
        """Return a PortResult if the port is open, else None."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            if sock.connect_ex((host, port)) != 0:
                return None  # closed or filtered
            banner = grab_banner(sock, port)

        service = COMMON_PORTS.get(port, "Unknown")
        product, version = fingerprint(banner)
        result = PortResult(
            port=port,
            service=service,
            banner=banner,
            product=product,
            version=version,
        )
        self._assess(result)
        return result

    def _assess(self, result: PortResult) -> None:
        """Attach findings for weak services and outdated versions."""
        weak = WEAK_SERVICES.get(result.port)
        if weak:
            severity, note = weak
            result.findings.append(
                Finding(
                    title=f"Weak/insecure service: {result.service}",
                    severity=Severity.from_name(severity),
                    description=note,
                )
            )
        if result.product:
            result.findings.extend(
                self.vulndb.check(result.product, result.version)
            )

    # -- public API ----------------------------------------------------

    def scan(self, host: str, ports: Iterable[int]) -> ScanResult:
        """Scan ``host`` across ``ports`` concurrently."""
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror as exc:
            raise ValueError(f"Could not resolve host: {host}") from exc

        started = datetime.datetime.now()
        open_ports: list[PortResult] = []
        port_list = list(ports)

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {
                pool.submit(self._scan_one, ip, port): port for port in port_list
            }
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    open_ports.append(result)

        open_ports.sort(key=lambda r: r.port)
        finished = datetime.datetime.now()
        return ScanResult(
            target=host,
            ip=ip,
            started_at=started.isoformat(timespec="seconds"),
            finished_at=finished.isoformat(timespec="seconds"),
            ports=open_ports,
        )


def parse_ports(spec: Optional[str]) -> list[int]:
    """Parse a port spec such as '22,80,443' or '1-1024' or '20-25,80'.

    When ``spec`` is falsy, the common-ports list is returned.
    """
    if not spec:
        return sorted(COMMON_PORTS)
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo_s, hi_s = chunk.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(chunk))
    valid = {p for p in ports if 0 < p <= 65535}
    if not valid:
        raise ValueError(f"No valid ports in spec: {spec!r}")
    return sorted(valid)
