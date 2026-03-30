# Contributing to ArCHie Analyzer

Thank you for your interest in contributing. This document covers bug reports, feature suggestions, and submitting code changes.

---

## Reporting Bugs

Open an issue with:

1. **Clear title** -- what broke and where
2. **Steps to reproduce** -- exact commands and IOCs tested
3. **Expected vs. actual behavior**
4. **Environment** -- Python version, OS, which API sources were enabled
5. **Logs** -- relevant output from `output/logs/` if available

Example:
```
Title: VirusTotal timeout on bulk analysis with 50+ IOCs

Steps:
1. Run: archie -f large_iocs.txt
2. Expected: process all IOCs
3. Actual: request times out after ~30 IOCs

Environment: Python 3.11, Windows 11, VirusTotal key configured
```

---

## Suggesting Features

Open an issue with:

1. **Feature title** -- concise description
2. **Use case** -- why is this useful for SOC/VAPT teams?
3. **Proposed solution** -- how should it work?
4. **Alternatives** -- other ways to solve the same problem?

---

## Submitting Code Changes

### Before you start

1. Check existing issues -- avoid duplicate work
2. Discuss large changes first -- open an issue before starting
3. Test against sample IOCs in `tests/sample_iocs.txt` before submitting

### Code style

- Python: follow PEP 8, 4-space indents, max 88 chars per line
- No hardcoded secrets -- credentials always go in `.env`
- Comments: explain *why*, not *what*

### Branch naming

```
feature/short-description      # New feature
fix/issue-title-slug           # Bug fix
docs/update-section            # Documentation update
refactor/module-cleanup        # Code refactoring
```

### Pull request checklist

- [ ] Changes tested locally against sample IOCs
- [ ] No hardcoded credentials or API keys
- [ ] `.env` is NOT tracked
- [ ] README updated if behavior changes

### PR description template

```
## Description
Brief description of what this change does.

## Type of change
- [ ] Feature
- [ ] Bug fix
- [ ] Breaking change (requires version bump)
- [ ] Documentation update

## Testing
Describe how you tested this. Include sample IOCs used.

## Related issues
Closes #123
```

---

## Adding a New API Source

Steps to integrate a new threat intel API (example: Shodan).

### 1. Create `apis/shodan.py`

All API modules use `ThreatIntelClient` from `apis/base.py` for HTTP with automatic retry and backoff.

```python
# apis/shodan.py
import os
from apis.base import ThreatIntelClient

_client = ThreatIntelClient(timeout=15)
_API_KEY = os.getenv("SHODAN_KEY", "")
_BASE    = "https://api.shodan.io"

def analyze_ip(ip: str, proxies: dict | None = None) -> dict:
    if not _API_KEY:
        return {"source": "Shodan", "verdict": "skipped", "data": {}, "raw_response": None, "error": None}
    try:
        resp = _client.get(f"{_BASE}/shodan/host/{ip}", params={"key": _API_KEY}, proxies=proxies)
        resp.raise_for_status()
        data = resp.json()
        # ... parse data, determine verdict ...
        return {
            "source":       "Shodan",
            "verdict":      "info",      # clean / suspicious / malicious / not_found / info
            "data":         {"ports": ", ".join(str(p) for p in data.get("ports", []))},
            "raw_response": data,
            "error":        None,
        }
    except Exception as e:
        return {"source": "Shodan", "verdict": "error", "data": {}, "raw_response": None, "error": str(e)}
```

The return dict must follow this schema:

| Key | Type | Description |
|---|---|---|
| `source` | str | Display name shown in the verdict table |
| `verdict` | str | One of: `malicious`, `suspicious`, `clean`, `not_found`, `skipped`, `info`, `error`, `unknown` |
| `data` | dict | Parsed key-value pairs shown in KEY FINDINGS column |
| `raw_response` | dict or None | Full API response (used in `--log-raw` mode) |
| `error` | str or None | Error message if the call failed |

### 2. Add API key to `.env.example`

```
# Shodan -- https://www.shodan.io/
# Free: 1 query/month | Paid: unlimited
SHODAN_KEY=
```

### 3. Update `analyzer.py` -- `_build_dispatch()`

```python
from apis import shodan

# Inside _build_dispatch():
"ipv4": [
    ...,
    (shodan.analyze_ip, "Shodan"),
],
```

### 4. (Optional) Add a rate limit entry in `.env`

```
RATE_LIMIT_SHODAN=1     # requests per minute
```

The rate limiter reads `RATE_LIMIT_<SOURCE_UPPER>` automatically.

### 5. Update the README API Sources table

Add a row to the API Sources table in `README.md`.

---

## Updating Documentation

- **README.md**: update when features change or new sources are added
- **CHANGELOG.md**: document all changes under the appropriate version section
- **Docstrings**: keep function documentation in sync with the code

---

## Questions

Open an issue labelled as a question. Keep discussions focused on the topic.

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License (see [LICENSE](LICENSE)).

---

*ArCHie Analyzer -- Made with ❤️ by Akshar*
