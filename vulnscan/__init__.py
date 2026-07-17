"""vulnscan - a simple, educational network vulnerability scanner.

Scans a target host for open ports, fingerprints running services via
banner grabbing, flags weak/insecure services and outdated software
versions, and generates a report in text, JSON, or HTML format.

EDUCATIONAL USE ONLY. Only scan hosts you own or are explicitly
authorised to test.
"""

__version__ = "1.0.0"
__author__ = "Jual Coco"
__license__ = "MIT"

from .models import Finding, PortResult, ScanResult, Severity
from .scanner import Scanner
from .vulndb import VulnDB

__all__ = [
    "Finding",
    "PortResult",
    "ScanResult",
    "Severity",
    "Scanner",
    "VulnDB",
    "__version__",
]
