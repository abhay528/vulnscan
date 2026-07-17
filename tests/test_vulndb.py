"""Unit tests for version parsing and the signature database."""

from vulnscan.models import Severity
from vulnscan.vulndb import VulnDB, parse_version, version_le


def test_parse_version_basic():
    assert parse_version("7.4") == (7, 4)
    assert parse_version("7.4p1") == (7, 4)
    assert parse_version("2.3.4") == (2, 3, 4)
    assert parse_version("") == ()


def test_version_le_padding():
    assert version_le((7, 4), (7, 9)) is True
    assert version_le((8, 0), (7, 9)) is False
    assert version_le((2, 4), (2, 4, 0)) is True


def test_outdated_openssh_flagged():
    db = VulnDB.load_default()
    findings = db.check("OpenSSH", "6.6")
    assert findings, "OpenSSH 6.6 should be flagged"
    assert findings[0].severity == Severity.HIGH


def test_current_openssh_not_flagged():
    db = VulnDB.load_default()
    assert db.check("OpenSSH", "9.6") == []


def test_vsftpd_backdoor_critical():
    db = VulnDB.load_default()
    findings = db.check("vsftpd", "2.3.4")
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_unknown_product_returns_empty():
    db = VulnDB.load_default()
    assert db.check("TotallyMadeUp", "1.0") == []
