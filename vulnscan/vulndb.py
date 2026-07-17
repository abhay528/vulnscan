"""Signature database and version comparison."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from .models import Finding, Severity

_DEFAULT_DB = Path(__file__).parent / "data" / "vuln_signatures.json"


def parse_version(value: str) -> tuple[int, ...]:
    """Turn a version string like '7.4p1' into a comparable tuple (7, 4)."""
    parts: list[int] = []
    for token in re.split(r"[._\-+]", value.strip()):
        match = re.match(r"\d+", token)
        if not match:
            break
        parts.append(int(match.group()))
    return tuple(parts)


def version_le(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    """Return True if version tuple ``a`` <= ``b`` (zero-padded)."""
    length = max(len(a), len(b))
    a_pad = list(a) + [0] * (length - len(a))
    b_pad = list(b) + [0] * (length - len(b))
    return a_pad <= b_pad


class VulnDB:
    """A small collection of version-based vulnerability signatures."""

    def __init__(self, signatures: list[dict]) -> None:
        self.signatures = signatures

    @classmethod
    def load_default(cls) -> "VulnDB":
        return cls.load(_DEFAULT_DB)

    @classmethod
    def load(cls, path: Path | str) -> "VulnDB":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(data.get("signatures", []))

    def check(self, product: str, version: str) -> list[Finding]:
        """Return findings for a detected product/version."""
        findings: list[Finding] = []
        if not version:
            return findings
        detected = parse_version(version)
        if not detected:
            return findings
        for sig in self.signatures:
            if sig["product"].lower() != product.lower():
                continue
            max_vuln = parse_version(str(sig["max_vulnerable"]))
            exact = sig.get("exact")
            if exact is not None:
                if version.startswith(str(exact)):
                    findings.append(self._finding(sig, product, version))
                continue
            if version_le(detected, max_vuln):
                findings.append(self._finding(sig, product, version))
        return findings

    @staticmethod
    def _finding(sig: dict, product: str, version: str) -> Finding:
        return Finding(
            title=f"Outdated {product} {version}",
            severity=Severity.from_name(sig.get("severity", "MEDIUM")),
            description=sig.get("description", ""),
            reference=sig.get("cve", ""),
        )
