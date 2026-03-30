"""
apis/urlscan.py — URLScan.io API module.

Covers: URLs and domains.
Free tier: generous quota.
Sign up: https://urlscan.io/user/signup
"""

import time
import requests
from apis.base import KeyPool, ThreatIntelClient

_BASE   = "https://urlscan.io/api/v1"
SOURCE  = "URLScan.io"
_client = ThreatIntelClient(timeout=12)
_pool   = KeyPool("URLSCAN_KEY")   # loads URLSCAN_KEY, URLSCAN_KEY_2, _3 ...


def _no_key():
    return {"source": SOURCE, "verdict": "skipped", "data": {}, "raw_response": None, "error": "No API key"}


def _scan(value: str, proxies: dict) -> dict:
    """Submit a URL/domain for scanning and poll for result."""
    resp = _client.post(
        f"{_BASE}/scan/",
        key_pool=_pool,
        key_header="API-Key",
        headers={"Content-Type": "application/json"},
        json={"url": value, "visibility": "public"},
        proxies=proxies,
    )
    resp.raise_for_status()
    return resp.json()


def _poll_result(uuid: str, proxies: dict, retries: int = 8, delay: float = 3.0) -> dict:
    """Poll the result endpoint until the scan is done."""
    for _ in range(retries):
        time.sleep(delay)
        try:
            resp = _client.get(
                f"{_BASE}/result/{uuid}/",
                proxies=proxies,
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
    return {}


def _get_verdict(verdicts: dict) -> str:
    overall = verdicts.get("overall", {})
    score   = overall.get("score", 0)
    malicious = overall.get("malicious", False)
    if malicious or score >= 50:
        return "malicious"
    if score >= 10:
        return "suspicious"
    return "clean"


# ─────────────────────────────────────────────────────────────────────────────

def analyze_url(value: str, proxies: dict) -> dict:
    if not _pool:
        return _no_key()
    try:
        scan     = _scan(value, proxies)
        uuid     = scan.get("uuid", "")
        scan_url = scan.get("result", "")

        if not uuid:
            return {"source": SOURCE, "verdict": "error", "data": {},
                    "raw_response": None, "error": "No UUID returned from scan submission"}

        result    = _poll_result(uuid, proxies)
        verdicts  = result.get("verdicts", {})
        page      = result.get("page", {})
        verdict   = _get_verdict(verdicts)

        return {
            "source":  SOURCE,
            "verdict": verdict,
            "data": {
                "score":       verdicts.get("overall", {}).get("score", "—"),
                "title":       page.get("title", "—"),
                "final_url":   page.get("url", "—"),
                "screenshot":  f"https://urlscan.io/screenshots/{uuid}.png",
                "report":      scan_url,
            },
            "raw_response": result,
            "error": None,
        }
    except requests.HTTPError as e:
        # 400 = URLScan rejected the URL (private IP, unscannable domain, etc.)
        if e.response is not None and e.response.status_code == 400:
            try:
                detail = e.response.json().get("message", "URLScan rejected this URL")
            except Exception:
                detail = "URLScan rejected this URL (400)"
            return {"source": SOURCE, "verdict": "error", "data": {}, "raw_response": None, "error": detail}
        # 429 = rate limited
        if e.response is not None and e.response.status_code == 429:
            return {"source": SOURCE, "verdict": "error", "data": {}, "raw_response": None, "error": "Rate limited (429)"}
        return {"source": SOURCE, "verdict": "error", "data": {}, "raw_response": None, "error": str(e)}
    except Exception as e:
        return {"source": SOURCE, "verdict": "error", "data": {}, "raw_response": None, "error": str(e)}


def analyze_domain(value: str, proxies: dict) -> dict:
    """Treat domain as a URL (prepend https://) for scanning."""
    return analyze_url(f"https://{value}", proxies)
