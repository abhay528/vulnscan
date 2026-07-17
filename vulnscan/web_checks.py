"""Optional HTTP security-header checks for web applications.

Uses only the Python standard library (urllib) so there is no hard
dependency on ``requests``.
"""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request

from .constants import SECURITY_HEADERS
from .models import Finding, Severity


def check_security_headers(url: str, timeout: float = 5.0) -> list[Finding]:
    """Return a Finding for each missing HTTP security header."""
    findings: list[Finding] = []
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "vulnscan/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            present = {k.lower() for k in resp.headers.keys()}
    except (urllib.error.URLError, ValueError, OSError) as exc:
        return [
            Finding(
                title="Web header check failed",
                severity=Severity.INFO,
                description=f"Could not fetch {url}: {exc}",
            )
        ]
    for header, why in SECURITY_HEADERS.items():
        if header.lower() not in present:
            findings.append(
                Finding(
                    title=f"Missing security header: {header}",
                    severity=Severity.LOW,
                    description=why,
                )
            )
    return findings
