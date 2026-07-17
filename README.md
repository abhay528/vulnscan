# vulnscan

[![CI](https://github.com/your-username/vulnscan/actions/workflows/ci.yml/badge.svg)](https://github.com/your-username/vulnscan/actions)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

> A simple, **educational** network vulnerability scanner written in pure Python.
> It scans a target for open ports, fingerprints the running services via banner
> grabbing, flags weak/insecure services and outdated software versions, and
> generates a report in **text, JSON, or HTML**.

---

## ⚠️ Legal & ethical disclaimer

This tool is for **learning about vulnerability assessment and penetration
testing**. Only scan systems you **own** or have **explicit written permission**
to test (for example `127.0.0.1`, your own lab VM, or `scanme.nmap.org`, which
Nmap provides for legal practice). Unauthorised scanning of third-party systems
is illegal in most jurisdictions.

---

## ✨ Features

- **Concurrent TCP port scanning** with a configurable thread pool.
- **Service fingerprinting** via banner grabbing (SSH, HTTP, FTP, MySQL, and more).
- **Weak-configuration detection** for risky services (Telnet, SMB, RDP, Redis, ...).
- **Version-based vulnerability checks** against a JSON signature database.
- **Severity ratings** (INFO / LOW / MEDIUM / HIGH / CRITICAL) with a summary.
- **Optional HTTP security-header audit** for web applications.
- **Three report formats**: human-readable text, machine-readable JSON, and a
  styled standalone HTML report.
- **Zero runtime dependencies** — pure standard library. `pytest` is only needed
  for development.
- **Tested** with a unit-test suite and **GitHub Actions CI**.

---

## 📦 Installation

```bash
git clone https://github.com/your-username/vulnscan.git
cd vulnscan
python -m pip install -e .
```

Or run it without installing:

```bash
python -m vulnscan --help
```

---

## 🚀 Usage

```bash
# Scan common ports on your own machine
vulnscan 127.0.0.1

# Scan a port range
vulnscan 127.0.0.1 -p 1-1024

# Scan specific ports and save an HTML report
vulnscan scanme.nmap.org -p 22,80,443 -f html -o report.html

# JSON output (great for piping into other tools)
vulnscan 127.0.0.1 -f json -o result.json

# Also audit a web app's HTTP security headers
vulnscan example.com -p 80,443 --web https://example.com
```

### Command-line options

| Option | Description |
| --- | --- |
| `host` | Target host or IP (required) |
| `-p, --ports` | Ports to scan: `22,80,443` or `1-1024` (default: common ports) |
| `-f, --format` | `text` (default), `json`, or `html` |
| `-o, --output` | Write the report to a file instead of stdout |
| `-t, --timeout` | Per-port connection timeout in seconds (default: 1.0) |
| `-w, --workers` | Concurrent worker threads (default: 100) |
| `--web URL` | Also check HTTP security headers for this URL |
| `--no-banner` | Hide the ASCII banner |

The process exit code is `1` when any finding is reported and `0` otherwise,
so `vulnscan` can be used as a gate in CI pipelines.

---

## 🧪 Sample output

```text
============================================================
           VULNERABILITY SCAN REPORT
============================================================
Target        : scanme.nmap.org (45.33.32.156)
Open ports    : 2
Total findings: 2
Severity      : CRITICAL:0  HIGH:1  MEDIUM:0  LOW:1
------------------------------------------------------------

[22/tcp] SSH
  Product: OpenSSH 6.6
  Banner : SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
  [HIGH] Outdated OpenSSH 6.6 [multiple]
        OpenSSH versions before 8.0 contain several known vulnerabilities.

[80/tcp] HTTP
  [LOW] Weak/insecure service: HTTP
        HTTP has no transport encryption; prefer HTTPS.
```

---

## 🏗️ Project structure

```
vulnscan/
├── vulnscan/
│   ├── __init__.py        # package metadata & exports
│   ├── __main__.py        # `python -m vulnscan`
│   ├── cli.py             # argparse command-line interface
│   ├── scanner.py         # concurrent port scanner + port parsing
│   ├── banner.py          # banner grabbing & fingerprinting
│   ├── vulndb.py          # signature DB & version comparison
│   ├── report.py          # text / JSON / HTML reports
│   ├── web_checks.py      # HTTP security-header audit
│   ├── constants.py       # ports, weak services, headers
│   ├── models.py          # dataclasses & Severity enum
│   └── data/
│       └── vuln_signatures.json
├── tests/                 # pytest suite
├── .github/workflows/ci.yml
├── pyproject.toml
├── requirements.txt
├── Makefile
├── LICENSE
└── README.md
```

---

## 🧭 How it works

1. **Resolve** the target hostname to an IP.
2. **Scan** each port concurrently using a `ThreadPoolExecutor`. A port is
   “open” when a TCP `connect_ex` returns `0`.
3. **Grab the banner** from each open port (with small protocol-specific probes
   for HTTP and Redis).
4. **Fingerprint** the product and version from the banner using regexes.
5. **Assess** each service: flag weak/insecure services and compare the detected
   version against the signature database.
6. **Report** the findings with severity ratings in the chosen format.

---

## 🗺️ Roadmap

- UDP scanning support
- Pull signatures live from the NVD / CVE APIs
- Rich TUI progress bar
- CSV / SARIF export

---

## 📚 What I learned (project notes)

This project was built to understand the fundamentals of **vulnerability
assessment**: TCP connect scanning, service enumeration, banner-based version
fingerprinting, severity scoring, and report generation — the same pipeline that
tools like Nmap and Nessus automate at scale.

## 📄 License

MIT — see [LICENSE](LICENSE).
