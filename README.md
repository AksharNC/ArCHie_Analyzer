# ArCHie Analyzer

Threat Intel CLI for SOC / VAPT / phishing triage.
Paste any IOC to auto-detect its type, query up to 11 sources concurrently, and get a verdict table.

Includes an embedded Java proxy that routes requests through a local tunnel, useful for working around
network-level URL restrictions in corporate or managed environments. May not work in all cases -- skip with `--no-proxy`.

See [CHANGELOG.md](CHANGELOG.md) for full version history.

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set up API keys
copy .env.example .env
# open .env and fill in your keys

# 3. (One-time) Add project folder to PATH so you can run 'archie' from anywhere
setx PATH "%PATH%;C:\Automations Stuff\ArCHie_Analyzer"
# Open a new terminal after this step

# 4. Run
archie                              # interactive menu
archie -h                           # all CLI flags
archie -i "45.33.32.156"            # single IOC (quiet)
archie -i "45.33.32.156" -v         # single IOC verbose
archie -f tests/sample_iocs.txt     # bulk from file
archie -f tests/sample_iocs.txt -v  # bulk verbose
archie -i "1.2.3.4" -np             # skip proxy
archie -i "1.2.3.4" -nc             # bypass cache
archie -f iocs.txt -o csv           # export CSV to output/logs/csv/
archie -f iocs.txt -o json          # export JSON to output/logs/json/
archie -i "1.2.3.4" -lr             # full raw-dump log
archie -i "1.2.3.4" -ls             # summary-only log
archie -f iocs.txt -w 10 -np        # 10 workers, no proxy
```

> Java is required for the proxy. If `java` is not on PATH, the tool warns and runs without it.

---

## CLI Flags

```
-i,  --ioc         Single IOC to analyze
-f,  --file        Path to a file with one IOC per line
-v,  --verbose     Show per-API results as they arrive (default: quiet summary)
-np, --no-proxy    Skip the Java proxy (use direct connection)
-nc, --no-cache    Bypass the 24 h result cache
-w,  --workers     Thread pool size for concurrent API calls (default: 5)
-o,  --output      Export format: csv or json
-lr, --log-raw     Save full raw API dump to output/logs/json/
-ls, --log-summary Save summary log (parsed fields only) to output/logs/json/
```

---

## Supported IOC Types

| Type | Example | Notes |
|---|---|---|
| MD5 / SHA1 / SHA256 | `44d88612fea8a8f36de82e1278abb02f` | Hash lookup |
| IPv4 (+ CIDR) | `45.33.32.156`, `10.0.0.0/8` | IP reputation |
| Domain | `evil.ru` | Domain intel + cert recon |
| URL | `https://phish.evil.ru/login` | URL scan + phish check |
| Email | `attacker@phish.ru` | Domain extracted and re-dispatched |
| File Path | `C:\Temp\payload.exe` | Extension + path risk check |
| CVE | `CVE-2024-12345` | NVD CVSS lookup |

---

## API Sources

| Source | Covers | Key Required |
|---|---|---|
| VirusTotal | Hash, IP, Domain, URL | Yes |
| AbuseIPDB | IP | Yes |
| OTX AlienVault | Hash, IP, Domain, URL | Yes |
| GreyNoise | IP | Yes |
| URLScan.io | Domain, URL | Yes |
| MalwareBazaar | Hash | Yes (free account) |
| Hybrid Analysis | Hash | Yes (free account) |
| PhishTank | URL | Yes (free account) |
| IPInfo | IP | No (basic geo is free) |
| crt.sh | Domain | No (public CT logs) |
| NVD | CVE | No (optional key for higher rate limit) |

Sign-up links for all keys are in `.env.example`.
Missing keys show `~ NO KEY` in the verdict table -- the tool never crashes on missing keys.

---

## Sample Output

```
  IOC  >> 45.33.32.156
  TYPE >> IPv4 Address

 +------------------+----------------+---------------------------------------------+
 | SOURCE           | VERDICT        | KEY FINDINGS                                |
 +------------------+----------------+---------------------------------------------+
 | VirusTotal       | [!] MALICIOUS  | 14/94 security vendors flagged this IP ...  |
 | AbuseIPDB        | [!] MALICIOUS  | 87% | 234 reports | Linode                  |
 | GreyNoise        | [!] MALICIOUS  | malicious | scanner                         |
 | OTX AlienVault   | [~] SUSPICIOUS | 3 threat pulses                             |
 | IPInfo           | [i] INFO       | AS63949 Linode | US                          |
 +------------------+----------------+---------------------------------------------+

 // VERDICT
 [!] MALICIOUS   (3 of 4 sources agree)
   Flagged  : VirusTotal, AbuseIPDB, GreyNoise

  Run log -> output/logs/json/run_20260320_222739.json
```

---

## Project Structure

```
ArCHie_Analyzer/
|-- analyzer.py           <- CLI entry point (dispatch, bulk/single, log, export)
|-- detector.py           <- IOC type detection (hash/ip/domain/url/email/cve/filepath)
|-- proxy_manager.py      <- Java proxy lifecycle (start / auto-stop on exit)
|-- cache.py              <- File-based result cache (24 h TTL)
|-- rate_limiter.py       <- Per-source sliding-window rate limiter (auto-scales with multi-key)
|-- archie.bat            <- Windows launcher (run as: archie [flags])
|-- apis/
|   |-- base.py             <- Shared HTTP client (retry + backoff)
|   |-- virustotal.py       <- Hash / IP / Domain / URL
|   |-- abuseipdb.py        <- IP reputation + abuse reports
|   |-- malwarebazaar.py    <- Hash (malware database)
|   |-- hybridanalysis.py   <- Hash (sandbox verdict + threat score)
|   |-- otx.py              <- Hash / IP / Domain / URL (threat pulses)
|   |-- greynoise.py        <- IP (internet scanner classification)
|   |-- urlscan.py          <- Domain / URL (live browser scan)
|   |-- phishtank.py        <- URL (verified phishing database)
|   |-- ipinfo.py           <- IP geolocation
|   |-- crtsh.py            <- Domain cert transparency / subdomain recon
|   `-- nvd.py              <- CVE CVSS score + description
|-- output/
|   |-- renderer.py         <- Rich TUI (tables, verdict box, ASCII banners)
|   `-- logs/
|       |-- json/             <- Run logs + JSON exports
|       `-- csv/              <- CSV exports
|-- tests/
|   `-- sample_iocs.txt
|-- .env.example          <- Template -- copy to .env and fill in your keys
|-- requirements.txt
`-- CHANGELOG.md
```

---

## Run Logs

Logging is opt-in -- nothing is written unless you request it.

| Mode | Flag | What is saved |
|---|---|---|
| Raw dump | `--log-raw` / `-lr` | IOC, type, verdict, parsed fields + full raw API response per source |
| Summary | `--log-summary` / `-ls` | IOC, type, verdict, parsed fields (raw responses stripped) |
| None | (default) | Nothing written |

Logs are saved to `output/logs/json/run_<timestamp>.json`.

Log structure example (summary mode):
```json
{
  "run_at": "2026-03-27T14:00:00",
  "log_mode": "summary",
  "iocs": [
    {
      "value": "45.33.32.156",
      "type": "ipv4",
      "verdict": "malicious",
      "sources": [
        { "source": "VirusTotal", "verdict": "malicious", "data": { "detections": "14/94" }, "error": null }
      ]
    }
  ],
  "summary": { "malicious": 1 }
}
```

---

## API Keys Setup

```bash
copy .env.example .env
```

Open `.env` and fill in keys for the sources you want active.
The tool works with zero keys -- missing sources display `~ NO KEY` and are skipped cleanly.

### Multi-key rotation

Every source supports N keys from N different accounts. Add numbered keys to `.env`:

```ini
VT_API_KEY=<account1>
VT_API_KEY_2=<account2>
VT_API_KEY_3=<account3>
```

The tool rotates to the next key automatically on any 429 response. The rate limiter auto-scales the per-minute budget proportionally (2 keys = 2x, 3 keys = 3x). No other configuration needed, numbering must be contiguous (no gaps).

---

*ArCHie Analyzer -- Made with ❤️ by Akshar*
