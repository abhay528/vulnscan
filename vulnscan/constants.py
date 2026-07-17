"""Static reference data: common ports and known weak services."""

from __future__ import annotations

# Well-known TCP ports mapped to their typical service name.
COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

# Services that are insecure or risky by design (weak configuration),
# mapped to (severity, explanation).
WEAK_SERVICES: dict[int, tuple[str, str]] = {
    21: ("MEDIUM", "FTP often allows anonymous or plaintext logins."),
    23: ("HIGH", "Telnet transmits credentials in clear text; use SSH."),
    80: ("LOW", "HTTP has no transport encryption; prefer HTTPS."),
    111: ("MEDIUM", "RPCbind can leak service info and enable NFS attacks."),
    139: ("MEDIUM", "Legacy NetBIOS session service; often abused."),
    445: ("HIGH", "Exposed SMB is a frequent ransomware/worm vector."),
    3389: ("HIGH", "Internet-exposed RDP is a top brute-force target."),
    5900: ("HIGH", "VNC often runs with weak or no authentication."),
    6379: ("HIGH", "Redis is unauthenticated by default; never expose it."),
    9200: ("HIGH", "Elasticsearch has no auth by default; data exposure risk."),
    27017: ("HIGH", "MongoDB historically shipped with no authentication."),
}

# HTTP response headers that should be present on a well-configured site.
SECURITY_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "Enforces HTTPS (HSTS).",
    "Content-Security-Policy": "Mitigates XSS and data injection.",
    "X-Frame-Options": "Protects against clickjacking.",
    "X-Content-Type-Options": "Stops MIME-type sniffing.",
    "Referrer-Policy": "Controls referrer information leakage.",
    "Permissions-Policy": "Restricts powerful browser features.",
}
