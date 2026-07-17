"""Data models used across the scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Ordered severity levels (higher = worse)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        return cls[name.strip().upper()]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


@dataclass
class Finding:
    """A single security issue discovered on a port."""

    title: str
    severity: Severity
    description: str = ""
    reference: str = ""  # e.g. a CVE id or advisory

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity.name,
            "description": self.description,
            "reference": self.reference,
        }


@dataclass
class PortResult:
    """The outcome of scanning a single port."""

    port: int
    service: str = "Unknown"
    banner: str = ""
    product: str = ""
    version: str = ""
    findings: list[Finding] = field(default_factory=list)

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "service": self.service,
            "banner": self.banner,
            "product": self.product,
            "version": self.version,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ScanResult:
    """The complete result of a scan against one target."""

    target: str
    ip: str
    started_at: str
    finished_at: str
    ports: list[PortResult] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return sum(len(p.findings) for p in self.ports)

    def severity_counts(self) -> dict[str, int]:
        counts = {s.name: 0 for s in Severity if s is not Severity.INFO}
        for port in self.ports:
            for finding in port.findings:
                counts[finding.severity.name] += 1
        return counts

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "ip": self.ip,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "open_ports": len(self.ports),
            "total_findings": self.total_findings,
            "severity_counts": self.severity_counts(),
            "ports": [p.to_dict() for p in self.ports],
        }
