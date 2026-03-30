"""
apis/ipinfo.py — IPInfo.io geolocation module.

Covers: IPv4 addresses.
No API key needed for basic geo (org, city, country).
Optional key for higher rate limits: https://ipinfo.io/signup
"""

import requests
from apis.base import KeyPool, ThreatIntelClient

SOURCE  = "IPInfo"
_client = ThreatIntelClient(timeout=8)
_pool   = KeyPool("IPINFO_KEY")   # optional; loads IPINFO_KEY, IPINFO_KEY_2, _3 ...


def analyze_ip(value: str, proxies: dict) -> dict:
    try:
        ip    = value.split("/")[0]   # strip CIDR
        # IPInfo key goes in URL as ?token=; key_pool/key_header not applicable.
        key   = _pool.current()
        token = f"?token={key}" if key else ""
        resp  = _client.get(
            f"https://ipinfo.io/{ip}/json{token}",
            proxies=proxies,
        )
        resp.raise_for_status()
        d    = resp.json()
        org  = d.get("org", "—")

        # IPInfo always returns geo — verdict is always INFO (not a threat feed)
        return {
            "source":  SOURCE,
            "verdict": "info",
            "data": {
                "org":      org,
                "city":     d.get("city", "—"),
                "region":   d.get("region", "—"),
                "country":  d.get("country", "—"),
                "timezone": d.get("timezone", "—"),
            },
            "raw_response": d,
            "error": None,
        }
    except Exception as e:
        return {"source": SOURCE, "verdict": "error", "data": {}, "raw_response": None, "error": str(e)}
