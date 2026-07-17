"""Generate illustrative sample reports (used for the repo examples/).

Builds a realistic ScanResult in-memory so the sample output demonstrates
findings without needing a real vulnerable host to scan.
"""

from vulnscan.models import Finding, PortResult, ScanResult, Severity
from vulnscan import report

result = ScanResult(
    target="scanme.example.org",
    ip="203.0.113.10",
    started_at="2026-07-17T14:20:00",
    finished_at="2026-07-17T14:20:07",
    ports=[
        PortResult(
            port=21, service="FTP", banner="220 (vsFTPd 2.3.4)",
            product="vsftpd", version="2.3.4",
            findings=[
                Finding("Weak/insecure service: FTP", Severity.MEDIUM,
                        "FTP often allows anonymous or plaintext logins."),
                Finding("Outdated vsftpd 2.3.4", Severity.CRITICAL,
                        "vsftpd 2.3.4 shipped with a malicious backdoor.",
                        "CVE-2011-2523"),
            ],
        ),
        PortResult(
            port=22, service="SSH", banner="SSH-2.0-OpenSSH_6.6.1p1",
            product="OpenSSH", version="6.6",
            findings=[
                Finding("Outdated OpenSSH 6.6", Severity.HIGH,
                        "OpenSSH before 8.0 has several known vulnerabilities.",
                        "multiple"),
            ],
        ),
        PortResult(
            port=80, service="HTTP", banner="HTTP/1.1 200 OK",
            findings=[
                Finding("Weak/insecure service: HTTP", Severity.LOW,
                        "HTTP has no transport encryption; prefer HTTPS."),
            ],
        ),
        PortResult(port=443, service="HTTPS", banner="HTTP/1.1 200 OK"),
    ],
)

with open("examples/sample_report.html", "w", encoding="utf-8") as fh:
    fh.write(report.to_html(result))
with open("examples/sample_report.json", "w", encoding="utf-8") as fh:
    fh.write(report.to_json(result))
with open("examples/sample_report.txt", "w", encoding="utf-8") as fh:
    fh.write(report.to_text(result))
print(report.to_text(result))
