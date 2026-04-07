"""
apis/ipinfo.py — IPInfo.io geolocation module.

Covers: IPv4 addresses.
No API key needed for basic geo (org, city, country).
Optional key for higher rate limits: https://ipinfo.io/signup
"""

import requests
from apis.base import KeyPool, ThreatIntelClient

SOURCE  = "IPInfo"
_client = ThreatIntelClient(timeout=8, source=SOURCE)
_pool   = KeyPool("IPINFO_KEY")   # optional; loads IPINFO_KEY, IPINFO_KEY_2, _3 ...


def analyze_ip(value: str, proxies: dict) -> dict:
    try:
        ip  = value.split("/")[0]   # strip CIDR
        # Pass the key as Authorization: Bearer so it never appears in the URL
        # (prevents leaking the token in exception messages or proxy access logs).
        key     = _pool.current()
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        resp = _client.get(
            f"https://ipinfo.io/{ip}/json",
            headers=headers,
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
