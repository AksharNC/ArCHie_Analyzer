"""
apis/nvd.py — NIST National Vulnerability Database (NVD) API module.

Covers: CVE IDs only.
No key required (rate-limited to 5 req/30s without key).
Optional env var: NVD_API_KEY (raises limit to 50 req/30s)
API: https://nvd.nist.gov/developers/vulnerabilities
"""

import requests
from apis.base import KeyPool, ThreatIntelClient

_BASE   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SOURCE  = "NVD"
_client = ThreatIntelClient(timeout=20, source=SOURCE)
_pool   = KeyPool("NVD_API_KEY")   # optional; loads NVD_API_KEY, NVD_API_KEY_2, _3 ...


def _headers() -> dict:
    # NVD key goes in header; key_pool/key_header not used because the key is
    # optional and there are no _no_key() guards in this module.
    key = _pool.current()
    if key:
        return {"apiKey": key}
    return {}


def analyze_cve(value: str, proxies: dict) -> dict:
    try:
        resp = _client.get(
            _BASE,
            params={"cveId": value.upper()},
            headers=_headers(),
            proxies=proxies,
        )
        resp.raise_for_status()
        data  = resp.json()
        vulns = data.get("vulnerabilities", [])

        if not vulns:
            return {
                "source":  SOURCE,
                "verdict": "not_found",
                "data":    {"note": "CVE not found in NVD"},
                "raw_response": data,
                "error":   None,
            }

        cve = vulns[0].get("cve", {})

        # Extract English description
        description = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", "")[:100]
                break

        # Extract CVSS score — prefer v3.1, then v3.0, then v2
        cvss_score = None
        severity   = "—"
        metrics    = cve.get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            bucket = metrics.get(metric_key, [])
            if bucket:
                m          = bucket[0].get("cvssData", {})
                cvss_score = m.get("baseScore")
                severity   = m.get("baseSeverity", "—")
                break

        # Verdict based on CVSS base score
        if cvss_score is not None:
            if cvss_score >= 9.0:
                verdict = "malicious"    # Critical
            elif cvss_score >= 7.0:
                verdict = "suspicious"   # High (requires auth / different conditions)
            elif cvss_score >= 4.0:
                verdict = "suspicious"   # Medium
            else:
                verdict = "clean"        # Low
        else:
            verdict = "info"

        # Published date
        published = cve.get("published", "—")[:10]

        return {
            "source":  SOURCE,
            "verdict": verdict,
            "data": {
                "cvss":        f"{cvss_score}" if cvss_score else "—",
                "severity":    severity,
                "published":   published,
                "description": description,
            },
            "raw_response": data,
            "error": None,
        }

    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            return {"source": SOURCE, "verdict": "not_found",
                    "data": {"note": "CVE not found"}, "raw_response": None, "error": None}
        return {"source": SOURCE, "verdict": "error", "data": {}, "raw_response": None, "error": str(e)}
    except Exception as e:
        return {"source": SOURCE, "verdict": "error", "data": {}, "raw_response": None, "error": str(e)}
