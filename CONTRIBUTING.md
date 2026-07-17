# Contributing

Thanks for your interest in improving vulnscan!

## Development setup

```bash
git clone https://github.com/your-username/vulnscan.git
cd vulnscan
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -v
```

## Guidelines

- Keep the core dependency-free (standard library only).
- Add a unit test for any new behaviour.
- Run `pytest` before opening a pull request.
- Add new vulnerability signatures to `vulnscan/data/vuln_signatures.json`.

## Adding a signature

```json
{
  "product": "nginx",
  "max_vulnerable": "1.19.99",
  "severity": "MEDIUM",
  "cve": "multiple",
  "description": "Why this version is a problem."
}
```

The `product` must match the name emitted by the fingerprinter in `banner.py`.
