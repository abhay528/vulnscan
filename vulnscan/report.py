"""Render :class:`~vulnscan.models.ScanResult` objects as reports.

Three formats are supported, matching the ``--format`` choices in
:mod:`vulnscan.cli`:

``text``
    Plain ASCII, safe to redirect to a file or pipe into ``grep``.
``json``
    Machine-readable, suitable for CI pipelines and diffing between runs.
``html``
    A self-contained page with no external assets or network requests.

Design notes
------------
* The text report deliberately contains **no ANSI escape sequences**. The
  CLI may write the rendered string straight to a file via ``-o``, and
  colour codes would corrupt it.
* The HTML report escapes every piece of target-controlled data. Service
  banners, product names and version strings come from a remote host and
  must never be trusted; a hostile banner containing ``<script>`` would
  otherwise execute in the operator's browser when the report is opened.
"""

from __future__ import annotations

import html
import json
import textwrap

from .models import PortResult, ScanResult, Severity

__all__ = ["FORMATS", "render", "render_html", "render_json", "render_text"]

#: Report formats this module can produce, in the CLI's declared order.
FORMATS: tuple[str, ...] = ("text", "json", "html")

#: Severity levels shown in summaries, worst first. ``INFO`` is excluded to
#: match :meth:`ScanResult.severity_counts`.
_REPORTED_SEVERITIES: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

#: Badge colours for the HTML report.
_SEVERITY_HEX: dict[str, str] = {
    "CRITICAL": "#7f1d1d",
    "HIGH": "#b91c1c",
    "MEDIUM": "#b45309",
    "LOW": "#1d4ed8",
    "INFO": "#4b5563",
}

_RULE = "=" * 62
_THIN = "-" * 62


def _sorted_ports(result: ScanResult) -> list[PortResult]:
    """Return ports worst-first, then by ascending port number.

    An operator skimming a report should hit the most dangerous finding
    first rather than whatever happened to have the lowest port number.
    """
    return sorted(result.ports, key=lambda p: (-int(p.max_severity), p.port))


def render(result: ScanResult, fmt: str = "text") -> str:
    """Render ``result`` in the requested format.

    Args:
        result: The completed scan to render.
        fmt: One of :data:`FORMATS`. Case and surrounding whitespace are
            ignored.

    Returns:
        The rendered report as a string.

    Raises:
        ValueError: If ``fmt`` is not a supported format.
    """
    key = (fmt or "text").strip().lower()
    try:
        renderer = _RENDERERS[key]
    except KeyError:
        supported = ", ".join(FORMATS)
        raise ValueError(
            f"Unknown report format {fmt!r}. Supported formats: {supported}."
        ) from None
    return renderer(result)


# --------------------------------------------------------------------------- #
# text
# --------------------------------------------------------------------------- #
def render_text(result: ScanResult) -> str:
    """Render a plain-ASCII report suitable for terminals and files."""
    counts = result.severity_counts()
    lines: list[str] = [
        _RULE,
        " vulnscan report",
        _RULE,
        f" Target      : {result.target} ({result.ip})",
        f" Started     : {result.started_at}",
        f" Finished    : {result.finished_at}",
        f" Open ports  : {len(result.ports)}",
        f" Findings    : {result.total_findings}",
        _THIN,
        " Severity summary",
    ]
    for name in _REPORTED_SEVERITIES:
        lines.append(f"   {name:<9}: {counts.get(name, 0)}")
    lines.append(_THIN)
    lines.append("")

    if not result.ports:
        lines.append(" No open ports found in the scanned range.")
        lines.append("")
        return "\n".join(lines)

    for port in _sorted_ports(result):
        lines.append(
            f"[{port.max_severity.name}] Port {port.port}/tcp - {port.service}"
        )
        if port.product or port.version:
            product = " ".join(part for part in (port.product, port.version) if part)
            lines.append(f"  Product : {product}")
        if port.banner:
            lines.append(f"  Banner  : {_one_line(port.banner)}")

        if not port.findings:
            lines.append("  Findings: none")
            lines.append("")
            continue

        lines.append("  Findings:")
        worst_first = sorted(port.findings, key=lambda f: -int(f.severity))
        for finding in worst_first:
            lines.append(f"    - [{finding.severity.name}] {finding.title}")
            if finding.description:
                lines.append(
                    textwrap.fill(
                        finding.description,
                        width=62,
                        initial_indent="      ",
                        subsequent_indent="      ",
                    )
                )
            if finding.reference:
                lines.append(f"      Reference: {finding.reference}")
        lines.append("")

    if not result.total_findings:
        lines.append(" No issues detected on the scanned ports.")
        lines.append("")

    return "\n".join(lines)


def _one_line(value: str, limit: int = 100) -> str:
    """Collapse a banner to a single truncated line.

    Banners routinely contain CRLF sequences; left alone they would break
    the alignment of the report and could forge fake report lines.
    """
    collapsed = " ".join(value.split())
    if len(collapsed) > limit:
        return collapsed[: limit - 3] + "..."
    return collapsed


# --------------------------------------------------------------------------- #
# json
# --------------------------------------------------------------------------- #
def render_json(result: ScanResult) -> str:
    """Render the scan as indented JSON with a trailing newline."""
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n"


# --------------------------------------------------------------------------- #
# html
# --------------------------------------------------------------------------- #
_CSS = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 40px 24px 64px;
  background: #0b0f19;
  color: #e5e7eb;
  font: 15px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto,
    Helvetica, Arial, sans-serif;
}
.wrap { max-width: 900px; margin: 0 auto; }
h1 { font-size: 22px; margin: 0 0 4px; letter-spacing: -0.3px; }
.sub { color: #9ca3af; font-size: 13px; margin: 0 0 28px; }
.meta {
  width: 100%;
  border-collapse: collapse;
  margin: 0 0 28px;
  font-size: 14px;
}
.meta th, .meta td {
  text-align: left;
  padding: 8px 10px;
  border-bottom: 1px solid #1f2937;
  vertical-align: top;
}
.meta th { color: #9ca3af; font-weight: 600; width: 160px; }
.counts { display: flex; flex-wrap: wrap; gap: 8px; margin: 0 0 32px; }
.badge {
  display: inline-block;
  padding: 4px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.4px;
  color: #fff;
}
.port {
  border: 1px solid #1f2937;
  border-radius: 10px;
  padding: 18px 20px;
  margin: 0 0 16px;
  background: #111827;
}
.port h2 {
  font-size: 16px;
  margin: 0 0 10px;
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.kv { color: #9ca3af; font-size: 13px; margin: 2px 0; }
.kv code {
  color: #d1d5db;
  background: #0b0f19;
  padding: 1px 5px;
  border-radius: 4px;
  font-size: 12px;
  word-break: break-all;
}
ul.findings { list-style: none; margin: 14px 0 0; padding: 0; }
ul.findings li {
  border-left: 3px solid #374151;
  padding: 8px 0 8px 14px;
  margin: 0 0 12px;
}
.f-title { font-weight: 600; }
.f-desc { color: #9ca3af; font-size: 13.5px; margin: 4px 0 0; }
.f-ref { font-size: 12.5px; margin: 4px 0 0; }
.f-ref a { color: #93c5fd; }
.clean { color: #6ee7b7; }
footer { color: #6b7280; font-size: 12px; margin-top: 36px; }
"""


def render_html(result: ScanResult) -> str:
    """Render a self-contained HTML report.

    All target-supplied values are HTML-escaped. A remote host controls its
    own banner text, so treating it as markup would turn this report into
    a stored-XSS delivery mechanism against the person running the scan.
    """
    esc = html.escape
    counts = result.severity_counts()

    parts: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8" />',
        '<meta name="viewport" content="width=device-width, initial-scale=1" />',
        f"<title>vulnscan report - {esc(result.target)}</title>",
        f"<style>{_CSS}</style>",
        "</head>",
        "<body>",
        '<div class="wrap">',
        "<h1>vulnscan report</h1>",
        f'<p class="sub">{esc(result.target)} ({esc(result.ip)})</p>',
        '<table class="meta">',
        f"<tr><th>Target</th><td>{esc(result.target)}</td></tr>",
        f"<tr><th>Resolved IP</th><td>{esc(result.ip)}</td></tr>",
        f"<tr><th>Started</th><td>{esc(result.started_at)}</td></tr>",
        f"<tr><th>Finished</th><td>{esc(result.finished_at)}</td></tr>",
        f"<tr><th>Open ports</th><td>{len(result.ports)}</td></tr>",
        f"<tr><th>Total findings</th><td>{result.total_findings}</td></tr>",
        "</table>",
        '<div class="counts">',
    ]

    for name in _REPORTED_SEVERITIES:
        colour = _SEVERITY_HEX[name]
        parts.append(
            f'<span class="badge" style="background:{colour}">'
            f"{name} {counts.get(name, 0)}</span>"
        )
    parts.append("</div>")

    if not result.ports:
        parts.append(
            '<p class="clean">No open ports found in the scanned range.</p>'
        )
    else:
        for port in _sorted_ports(result):
            sev = port.max_severity.name
            colour = _SEVERITY_HEX[sev]
            parts.append('<section class="port">')
            parts.append(
                "<h2>"
                f'<span class="badge" style="background:{colour}">{sev}</span>'
                f"Port {port.port}/tcp"
                f"<span style=\"color:#9ca3af;font-weight:400\">"
                f"{esc(port.service)}</span>"
                "</h2>"
            )
            if port.product or port.version:
                product = " ".join(
                    part for part in (port.product, port.version) if part
                )
                parts.append(f'<p class="kv">Product: {esc(product)}</p>')
            if port.banner:
                parts.append(
                    f'<p class="kv">Banner: <code>'
                    f"{esc(_one_line(port.banner, 200))}</code></p>"
                )

            if not port.findings:
                parts.append('<p class="kv clean">No findings on this port.</p>')
            else:
                parts.append('<ul class="findings">')
                worst_first = sorted(port.findings, key=lambda f: -int(f.severity))
                for finding in worst_first:
                    f_colour = _SEVERITY_HEX[finding.severity.name]
                    parts.append(
                        f'<li style="border-left-color:{f_colour}">'
                        f'<span class="badge" style="background:{f_colour}">'
                        f"{finding.severity.name}</span> "
                        f'<span class="f-title">{esc(finding.title)}</span>'
                    )
                    if finding.description:
                        parts.append(
                            f'<p class="f-desc">{esc(finding.description)}</p>'
                        )
                    if finding.reference:
                        parts.append(
                            f'<p class="f-ref">{_reference_html(finding.reference)}</p>'
                        )
                    parts.append("</li>")
                parts.append("</ul>")
            parts.append("</section>")

    parts.append(
        "<footer>Generated by vulnscan. Only scan systems you own or are "
        "explicitly authorised to test.</footer>"
    )
    parts.append("</div>")
    parts.append("</body>")
    parts.append("</html>")
    return "\n".join(parts) + "\n"


def _reference_html(reference: str) -> str:
    """Render a reference, linking it only when it is a safe http(s) URL.

    Restricting the scheme prevents a crafted reference from emitting a
    ``javascript:`` link into the report.
    """
    safe = html.escape(reference, quote=True)
    if reference.startswith(("http://", "https://")):
        return (
            f'Reference: <a href="{safe}" rel="noopener noreferrer" '
            f'target="_blank">{safe}</a>'
        )
    return f"Reference: {safe}"


#: Format name -> renderer. Declared after the functions it references.
_RENDERERS = {
    "text": render_text,
    "json": render_json,
    "html": render_html,
}
