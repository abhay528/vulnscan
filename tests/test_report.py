"""Tests for :mod:`vulnscan.report`.

The report module was missing from an earlier release while ``cli.py``
already imported it, which broke every invocation of the tool. These tests
exist so that regression cannot happen silently again.
"""

from __future__ import annotations

import json

from vulnscan import report
from vulnscan.models import Finding, PortResult, ScanResult, Severity


def make_result() -> ScanResult:
    """A small scan covering several severities and an unaffected port."""
    redis = PortResult(
        port=6379,
        service="Redis",
        banner="-ERR unknown command",
        product="Redis",
        version="2.8.4",
        findings=[
            Finding(
                title="Unauthenticated Redis instance",
                severity=Severity.HIGH,
                description="Redis is unauthenticated by default; never expose it.",
                reference="https://redis.io/docs/management/security/",
            )
        ],
    )
    http = PortResult(
        port=80,
        service="HTTP",
        findings=[
            Finding(
                title="Cleartext HTTP",
                severity=Severity.LOW,
                description="HTTP has no transport encryption; prefer HTTPS.",
            )
        ],
    )
    ssh = PortResult(port=22, service="SSH", product="OpenSSH", version="9.6p1")
    return ScanResult(
        target="example.test",
        ip="203.0.113.7",
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:03Z",
        ports=[ssh, http, redis],
    )


def test_formats_tuple_matches_cli_choices():
    assert report.FORMATS == ("text", "json", "html")


def test_reported_severities_exclude_info_and_are_worst_first():
    assert report._REPORTED_SEVERITIES == ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def test_render_defaults_to_text():
    assert report.render(make_result()) == report.render_text(make_result())


def test_render_text_includes_target_and_counts():
    output = report.render_text(make_result())
    assert "example.test" in output
    assert "203.0.113.7" in output
    assert "HIGH     : 1" in output
    assert "LOW      : 1" in output
    assert "Unauthenticated Redis instance" in output


def test_render_text_is_worst_first():
    output = report.render_text(make_result())
    # Redis (HIGH) must be reported before HTTP (LOW) and SSH (no findings).
    assert output.index("Port 6379/tcp") < output.index("Port 80/tcp")
    assert output.index("Port 80/tcp") < output.index("Port 22/tcp")


def test_render_text_has_no_ansi_escapes():
    # The CLI can write this straight to a file via -o.
    assert "\033" not in report.render_text(make_result())


def test_render_text_collapses_multiline_banner():
    result = make_result()
    result.ports[2].banner = "line one\r\nline two"
    output = report.render_text(result)
    assert "Banner  : line one line two" in output


def test_render_json_round_trips():
    payload = json.loads(report.render_json(make_result()))
    assert payload["target"] == "example.test"
    assert payload["open_ports"] == 3
    assert payload["total_findings"] == 2
    assert payload["severity_counts"]["HIGH"] == 1
    assert {p["port"] for p in payload["ports"]} == {22, 80, 6379}


def test_render_html_is_document():
    output = report.render_html(make_result())
    assert output.startswith("<!DOCTYPE html>")
    assert output.rstrip().endswith("</html>")
    assert "example.test" in output


def test_render_html_escapes_hostile_banner():
    """A remote host controls its banner; it must never become markup."""
    result = make_result()
    result.ports[0].banner = "<script>alert('xss')</script>"
    result.ports[0].product = "<img src=x onerror=alert(1)>"
    output = report.render_html(result)
    assert "<script>alert" not in output
    assert "<img src=x" not in output
    assert "&lt;script&gt;" in output


def test_render_html_does_not_link_unsafe_reference_scheme():
    result = make_result()
    result.ports[2].findings[0].reference = "javascript:alert(1)"
    output = report.render_html(result)
    assert 'href="javascript:' not in output


def test_render_html_links_http_reference():
    output = report.render_html(make_result())
    assert 'href="https://redis.io/docs/management/security/"' in output


def test_render_handles_empty_scan():
    empty = ScanResult(
        target="example.test",
        ip="203.0.113.7",
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
    )
    assert empty.total_findings == 0
    text = report.render_text(empty)
    assert "No open ports found" in text
    assert json.loads(report.render_json(empty))["open_ports"] == 0
    assert "No open ports found" in report.render_html(empty)


def test_render_rejects_unknown_format():
    try:
        report.render(make_result(), "pdf")
    except ValueError as exc:
        assert "pdf" in str(exc)
    else:  # pragma: no cover - only runs on regression
        raise AssertionError("expected ValueError for an unsupported format")


def test_render_normalises_format_string():
    assert report.render(make_result(), "  JSON ") == report.render_json(make_result())
