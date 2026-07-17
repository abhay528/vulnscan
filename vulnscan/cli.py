"""Command-line interface for vulnscan."""

from __future__ import annotations

import argparse
import sys

from . import __version__, report
from .scanner import Scanner, parse_ports
from .web_checks import check_security_headers

BANNER = r"""
                 _
 __   ___   _| |_ __  ___  ___ __ _ _ __
 \ \ / / | | | | '_ \/ __|/ __/ _` | '_ \
  \ V /| |_| | | | | \__ \ (_| (_| | | | |
   \_/  \__,_|_|_| |_|___/\___\__,_|_| |_|   v{version}
"""

DISCLAIMER = (
    "Only scan systems you own or are explicitly authorised to test. "
    "Unauthorised scanning may be illegal."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description="A simple educational network vulnerability scanner.",
        epilog=DISCLAIMER,
    )
    parser.add_argument("host", help="Target host or IP (e.g. 127.0.0.1)")
    parser.add_argument(
        "-p", "--ports",
        help="Ports to scan, e.g. '22,80,443' or '1-1024' (default: common ports)",
    )
    parser.add_argument(
        "-f", "--format", choices=["text", "json", "html"], default="text",
        help="Report format (default: text)",
    )
    parser.add_argument("-o", "--output", help="Write the report to this file")
    parser.add_argument(
        "-t", "--timeout", type=float, default=1.0,
        help="Per-port connection timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=100,
        help="Number of concurrent worker threads (default: 100)",
    )
    parser.add_argument(
        "--web", metavar="URL",
        help="Also check HTTP security headers for this URL",
    )
    parser.add_argument("--no-banner", action="store_true", help="Hide the ASCII banner")
    parser.add_argument("--version", action="version", version=f"vulnscan {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.no_banner:
        print(BANNER.format(version=__version__), file=sys.stderr)
    print(f"[!] {DISCLAIMER}\n", file=sys.stderr)

    scanner = Scanner(timeout=args.timeout, workers=args.workers)
    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))

    print(f"[*] Scanning {args.host} across {len(ports)} ports...", file=sys.stderr)
    try:
        result = scanner.scan(args.host, ports)
    except ValueError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 2

    if args.web:
        web_findings = check_security_headers(args.web)
        if result.ports:
            result.ports[0].findings.extend(web_findings)

    rendered = report.render(result, args.format)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered)
        print(f"[*] Report written to {args.output}", file=sys.stderr)
    else:
        print(rendered)

    # Exit code reflects the worst severity found (useful in CI pipelines).
    return 1 if result.total_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
