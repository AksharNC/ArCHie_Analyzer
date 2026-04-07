"""
apis/phishtank.py — PhishTank URL verification module.

Covers: URLs only.
Free API key required.
Sign up: https://www.phishtank.com/developer_info.php
Env var: PHISHTANK_KEY
"""

import urllib.parse
import requests
from apis.base import KeyPool, ThreatIntelClient

_BASE   = "https://checkurl.phishtank.com/checkurl/"
SOURCE  = "PhishTank"
_client = ThreatIntelClient(timeout=15, source=SOURCE)
_pool   = KeyPool("PHISHTANK_KEY")   # loads PHISHTANK_KEY, PHISHTANK_KEY_2, _3 ...


def _no_key():
    return {"source": SOURCE, "verdict": "skipped", "data": {}, "raw_response": None, "error": "No API key"}


def analyze_url(value: str, proxies: dict) -> dict:
    if not _pool:
        return _no_key()
    try:
        # PhishTank requires the key in the POST body, not headers.
        # Key rotation is not supported (body keys can't be swapped by ThreatIntelClient).
        resp = _client.post(
            _BASE,
            data={
                "url":     urllib.parse.quote(value, safe=""),
                "format":  "json",
                "app_key": _pool.current(),
            },
            headers={"User-Agent": "phishtank/ArCHie-Analyzer"},
            proxies=proxies,
        )
        resp.raise_for_status()
        body    = resp.json()
        result  = body.get("results", {})

        in_database = result.get("in_database", False)
        valid       = result.get("valid", False)       # currently active phish

        if not in_database:
            return {
                "source":  SOURCE,
                "verdict": "clean",
                "data":    {"note": "Not in PhishTank database"},
                "raw_response": body,
                "error":   None,
            }

        if valid:
            return {
                "source":  SOURCE,
                "verdict": "malicious",
                "data": {
                    "phish_id":  str(result.get("phish_id", "—")),
                    "verified":  "Yes" if result.get("verified") else "Pending",
                    "submitted": result.get("phish_submit_time", "—")[:10],
                },
                "raw_response": body,
                "error": None,
            }
        else:
            # In database but no longer active / unverified
            return {
                "source":  SOURCE,
                "verdict": "suspicious",
                "data":    {"note": "Previously reported, no longer active"},
                "raw_response": body,
                "error":   None,
            }

    except requests.HTTPError as e:
        return {"source": SOURCE, "verdict": "error", "data": {}, "raw_response": None, "error": str(e)}
    except Exception as e:
        return {"source": SOURCE, "verdict": "error", "data": {}, "raw_response": None, "error": str(e)}
