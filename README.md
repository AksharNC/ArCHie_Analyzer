# !! ArCHie Analyzer

**Threat Intel CLI for SOC / VAPT / phishing triage.**  
Paste any IOC → auto-detect type → fan out to up to 5 sources simultaneously → get a verdict table + final verdict panel.

Runs requests through an embedded Java proxy (Netskope bypass) — the tool starts and stops it automatically. Can be skipped via `--no-proxy`.

---

## !! Changelog

### v3.0 — Interactive Menu + Flexible Logging
- **Interactive menu**: running `python analyzer.py` now shows a numbered action menu instead of a raw paste prompt
- **Help flag**: `python analyzer.py -h` prints all CLI flags and usage examples
- **Optional logging** with two distinct modes:
  - `--log-raw` / menu option — full dump including every raw API response
  - `--log-summary` / menu option — parsed fields + verdict only (no raw responses)
  - Default (no flag) — no log file written
- `--log-raw` and `--log-summary` are mutually exclusive CLI flags
- Interactive menu loops so the user can run multiple analyses in one session

### v2.0 — Advanced Build
- Added 11 API sources dispatched concurrently per IOC type (VirusTotal, AbuseIPDB, GreyNoise, OTX, IPInfo, URLScan, MalwareBazaar, Hybrid Analysis, PhishTank, crt.sh, NVD)
- Bulk IOC analysis from file (`-f / --file`)
- Rich TUI: coloured verdict tables, verdict panel, bulk summary table, 9 random ASCII banners
- Embedded Java proxy for Netskope bypass with `--no-proxy` override
- JSON run log saved after every execution (full raw API dump)
- Auto-detect IOC type: MD5/SHA1/SHA256, IPv4/CIDR, domain, URL, email, file path, CVE
- Email → domain extraction + re-dispatch; file path → local-only risk analysis

### v1.0 — Primary Build
- Single IOC analysis via `-i` flag
- VirusTotal hash + IP + domain + URL lookups
- Basic tabular output with verdict
- `.env`-based API key management

---

## !! Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set up API keys
copy .env.example .env
# open .env and fill in your keys

# 3. Run
python analyzer.py                                      # interactive menu
python analyzer.py -h                                   # show all CLI flags
python analyzer.py -i "45.33.32.156"                    # single IOC
python analyzer.py -f tests/sample_iocs.txt             # bulk from file
python analyzer.py --no-proxy                           # skip proxy (direct connection)
python analyzer.py -i "1.2.3.4" --log-raw               # single IOC + save full raw log
python analyzer.py -i "1.2.3.4" --log-summary           # single IOC + save summary log
python analyzer.py -f iocs.txt --log-summary --no-proxy # combine flags freely
```

> **Java required** for the proxy. If `java` is not on PATH the tool runs without it and warns you.

---

## !! Supported IOC Types

| Type | Example | Handled As |
|---|---|---|
| MD5 / SHA1 / SHA256 | `44d88612fea8a8f36de82e1278abb02f` | Hash lookup |
| IPv4 (+ CIDR) | `45.33.32.156`, `10.0.0.0/8` | IP reputation |
| Domain | `evil.ru` | Domain intel + cert recon |
| URL | `https://phish.evil.ru/login` | URL scan + phish check |
| Email | `attacker@phish.ru` | Domain extracted → domain analysis |
| File Path | `C:\Temp\payload.exe` | Local extension + path risk check |
| CVE | `CVE-2024-12345` | NVD CVSS lookup |

---

## !! API Sources

| Source | Covers | Key Required |
|---|---|---|
| VirusTotal | Hash, IP, Domain, URL | ✅ |
| AbuseIPDB | IP | ✅ |
| OTX AlienVault | Hash, IP, Domain, URL | ✅ |
| GreyNoise | IP | ✅ |
| URLScan.io | Domain, URL | ✅ |
| MalwareBazaar | Hash | ✅ (free account) |
| Hybrid Analysis | Hash | ✅ (free account) |
| PhishTank | URL | ✅ (free account) |
| IPInfo | IP | ❌ (basic geo free) |
| crt.sh | Domain | ❌ (public CT log) |
| NVD | CVE | ❌ (optional key for higher rate) |

Sign-up links for all keys are in `.env.example`.  
Missing keys show `~ NO KEY` in the table — the tool never crashes on missing keys.

---

## !! Sample Output

```
  IOC  » 45.33.32.156
  TYPE » 🌐 IPv4 Address

 ┌──────────────────┬───────────────┬─────────────────────────────────┐
 │ SOURCE           │ VERDICT       │ KEY FINDINGS                    │
 ├──────────────────┼───────────────┼─────────────────────────────────┤
 │ VirusTotal       │ 🔴 MALICIOUS  │ 14/94 | United States | AS63949 │
 │ AbuseIPDB        │ 🔴 MALICIOUS  │ 87%   | 234 reports | Linode    │
 │ GreyNoise        │ 🔴 MALICIOUS  │ malicious | scanner             │
 │ OTX AlienVault   │ 🟡 SUSPICIOUS │ 3 threat pulses                 │
 │ IPInfo           │ ℹ️  INFO       │ AS63949 Linode | US             │
 └──────────────────┴───────────────┴─────────────────────────────────┘

 ╭─ VERDICT ──────────────────────────────────────────────────────────╮
 │ 🔴 MALICIOUS   (3 of 4 sources agree)                             │
 │ Flagged : VirusTotal, AbuseIPDB, GreyNoise                        │
 ╰────────────────────────────────────────────────────────────────────╯

  Run log → output/logs/run_20260320_222739.json
```

---

## !! Project Structure

```
ArCHie_Analyzer/
├── analyzer.py           ← CLI entry point, IOC dispatch, bulk/single mode, JSON log
├── detector.py           ← IOC auto-detection (sha256/sha1/md5/cve/url/email/ipv4/domain/filepath)
├── proxy_manager.py      ← Java proxy lifecycle (compile + start + auto-stop on exit)
├── SimpleProxy.java      ← Optimized HTTPS tunnel on port 8888
├── apis/
│   ├── virustotal.py     ← Hash / IP / Domain / URL
│   ├── abuseipdb.py      ← IP reputation + abuse reports
│   ├── malwarebazaar.py  ← Hash (malware database)
│   ├── hybridanalysis.py ← Hash (sandbox verdict + threat score)
│   ├── otx.py            ← Hash / IP / Domain / URL (threat pulses)
│   ├── greynoise.py      ← IP (internet scanner classification)
│   ├── urlscan.py        ← Domain / URL (live browser scan)
│   ├── phishtank.py      ← URL (verified phishing database)
│   ├── ipinfo.py         ← IP geolocation
│   ├── crtsh.py          ← Domain certificate transparency / subdomain recon
│   └── nvd.py            ← CVE CVSS score + description
├── output/
│   ├── renderer.py       ← Rich TUI (tables, verdict box, 9 ASCII banners)
│   └── logs/             ← JSON run logs saved per execution (gitignored)
├── tests/
│   └── sample_iocs.txt   ← Sample IOCs for testing
├── .env.example          ← Template — copy to .env and fill keys
└── requirements.txt
```

---

## !! Run Logs

Logging is **opt-in** — no log is written unless you request one.

| Mode | How to trigger | What is saved |
|---|---|---|
| **Raw dump** | `--log-raw` flag or menu option `[1]` | IOC, type, verdict, all parsed fields **+ full raw API response** from every source |
| **Summary** | `--log-summary` flag or menu option `[2]` | IOC, type, verdict, key parsed fields only — raw responses stripped |
| **None** | default (no flag / menu option `[0]`) | Nothing written |

Logs are written to `output/logs/run_<timestamp>.json`.

Raw dump example:
```json
{
  "run_at": "2026-03-20T22:27:17",
  "log_mode": "raw",
  "iocs": [
    {
      "value": "evil.com",
      "type": "domain",
      "verdict": "malicious",
      "sources": [
        {
          "source": "VirusTotal",
          "verdict": "malicious",
          "data": { "detections": "7/94" },
          "raw_response": { "...full VT JSON response..." },
          "error": null
        }
      ]
    }
  ],
  "summary": { "malicious": 1 }
}
```

Summary log example (same structure, `raw_response` omitted from every source):
```json
{
  "run_at": "2026-03-20T22:27:17",
  "log_mode": "summary",
  "iocs": [
    {
      "value": "evil.com",
      "type": "domain",
      "verdict": "malicious",
      "sources": [
        { "source": "VirusTotal", "verdict": "malicious", "data": { "detections": "7/94" }, "error": null }
      ]
    }
  ],
  "summary": { "malicious": 1 }
}
```

---

## !! What's Working

- 9 ASCII banners load randomly on startup
- **Interactive menu** on launch — numbered options for single IOC, bulk file, or exit
- **`-h` / `--help`** prints all CLI flags and usage examples
- Table: white cells, coloured VERDICT column + verdict panel only (no expand)
- OTX malware families capped at 4 + `(+N more)`
- URLScan 400 / 429 errors handled cleanly
- File path risk: human-readable findings (no raw booleans)
- GreyNoise: clean findings strings (no raw `True`/`False`)
- **Optional run logs** — `--log-raw` (full dump), `--log-summary` (parsed only), or no log (default)
- Both log modes also available interactively from the menu after each analysis
- All 11 API sources dispatched concurrently per IOC type

---

## !! Pending / Roadmap

| Feature | Notes |
|---|---|
| Shodan | IP — open ports, device fingerprint |
| Talos Intelligence | IP/Domain — sender reputation |
| Export report | JSON / Markdown report per run |
| History search | Query/filter past runs beyond raw log files |

---

## !! API Keys Setup

```bash
copy .env.example .env
```

Open `.env` and fill in keys for the sources you want active.  
The tool works with zero keys — missing sources display `~ NO KEY` in the verdict table and are skipped cleanly.

---

*ArCHie AnAlyzeR — by Akshar*
