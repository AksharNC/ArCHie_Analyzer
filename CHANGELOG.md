# Changelog

All notable changes to ArCHie Analyzer are documented here.

---

## v4.0 -- Reliability, UX & Developer Experience

### Added
- **`archie` command**: `archie.bat` launcher -- run `archie` from any terminal after adding the project folder to PATH
- **Short CLI flags**: `-v` (verbose), `-np` (no-proxy), `-nc` (no-cache), `-w` (workers), `-o` (output format), `-lr` / `-ls` (log modes)
- **Quiet vs verbose bulk mode**: default (`-f`) shows progress bar then summary table only; `--verbose` shows per-IOC header and full tables
- **VirusTotal-style detection**: findings now read "4/94 security vendors flagged this IP address as malicious"
- **Cache layer** (`output/cache/`): 24 h TTL file-based cache keyed on `(source, ioc_value)`. Bypass with `-nc`
- **Rate limiter**: per-source sliding-window throttle -- warns at 80% of limit, auto-throttles at limit. Override via `RATE_LIMIT_*` env vars in `.env`
- **Multi-key rotation**: each source supports N API keys (`VT_API_KEY`, `VT_API_KEY_2`, `VT_API_KEY_3`, ...). On a 429 the tool automatically rotates to the next key and retries with no sleep. Rate limits auto-scale proportionally (2 keys = 2x quota). Add a `_3`, `_4`... key to `.env` with no code changes required.
- **CSV export** (`-o csv`): saved to `output/logs/csv/`
- **JSON export** (`-o json`): saved to `output/logs/json/` alongside per-run logs
- **`apis/base.py`**: shared HTTP client with automatic retry + exponential backoff on 429/503/timeouts
- **Windows Unicode fix**: all verdict symbols and banner art rewritten to plain ASCII -- no more garbled output on CP1252 terminals

### Fixed
- **Hybrid Analysis 400 error**: corrected endpoint from `/search/hash` to `/search/hashes`
- **Cache lookup in verbose mode**: cache was bypassed when `-v` was active; now consistently checked in all modes

### Changed
- **Log directory structure**: logs split into `output/logs/json/` and `output/logs/csv/`
- **Project restructure**: Java proxy files documented under `proxy/`; cache data moved to `output/cache/`
- **Quiet mode auto-log**: non-verbose runs always save a summary log; verbose is opt-in
- All API modules updated to use shared `ThreatIntelClient` from `apis/base.py`

---

## v3.0 -- Interactive Menu + Flexible Logging

### Added
- **Interactive menu**: running `python analyzer.py` without flags shows a numbered action menu
- **Help flag**: `python analyzer.py -h` prints all CLI flags and usage examples
- **Optional logging** with two modes:
  - `--log-raw` -- full dump including every raw API response
  - `--log-summary` -- parsed fields + verdict only (no raw responses)
  - Default (no flag) -- no log file written
- Interactive menu loops so multiple analyses can be run in one session

---

## v2.0 -- Advanced Build

### Added
- 11 API sources dispatched concurrently per IOC type: VirusTotal, AbuseIPDB, GreyNoise, OTX, IPInfo, URLScan, MalwareBazaar, Hybrid Analysis, PhishTank, crt.sh, NVD
- Bulk IOC analysis from file (`-f / --file`)
- Rich TUI: coloured verdict tables, verdict panel, bulk summary table, random ASCII banners
- Embedded Java proxy for routing requests through a local tunnel (useful in restricted networks) with `--no-proxy` override
- JSON run log saved after every execution (full raw API dump)
- Auto-detect IOC type: MD5/SHA1/SHA256, IPv4/CIDR, domain, URL, email, file path, CVE
- Email extracts domain and re-dispatches; file path does local extension + path risk analysis

---

## v1.0 -- Primary Build

### Added
- Single IOC analysis via `-i` flag
- VirusTotal hash + IP + domain + URL lookups
- Basic tabular output with verdict
- `.env`-based API key management

---

*ArCHie Analyzer -- Made with ❤️ by Akshar*
