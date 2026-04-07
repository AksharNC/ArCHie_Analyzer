"""
apis/abuseipdb.py — AbuseIPDB v2 API module.

Covers: IPv4 addresses only.
Free tier: 1,000 checks/day.
Sign up: https://www.abuseipdb.com/register
"""

import requests
from apis.base import KeyPool, ThreatIntelClient

_BASE   = "https://api.abuseipdb.com/api/v2"
SOURCE  = "AbuseIPDB"
_client = ThreatIntelClient(timeout=10, source=SOURCE)
_pool   = KeyPool("ABUSEIPDB_KEY")   # loads ABUSEIPDB_KEY, ABUSEIPDB_KEY_2, _3 ...


def analyze_ip(value: str, proxies: dict) -> dict:
    if not _pool:
        return {"source": SOURCE, "verdict": "skipped", "data": {}, "raw_response": None, "error": "No API key"}

    try:
        ip   = value.split("/")[0]  # strip CIDR
        resp = _client.get(
            f"{_BASE}/check",
            key_pool=_pool,
            key_header="Key",
            headers={"Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            proxies=proxies,
        )
        resp.raise_for_status()
        raw        = resp.json()
        d          = raw.get("data", {})
        confidence = d.get("abuseConfidenceScore", 0)

        if confidence >= 75:
            verdict = "malicious"
        elif confidence >= 10:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return {
            "source":  SOURCE,
            "verdict": verdict,
            "data": {
                "abuse_confidence": f"{confidence}%",
                "total_reports":    d.get("totalReports", 0),
                "country":          d.get("countryCode", "—"),
                "isp":              d.get("isp", "—"),
                "is_tor":           d.get("isTor", False),
                "last_reported":    d.get("lastReportedAt", "—"),
            },
            "raw_response": raw,
            "error": None,
        }
    except Exception as e:
        return {"source": SOURCE, "verdict": "error", "data": {}, "raw_response": None, "error": str(e)}
