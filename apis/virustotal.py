"""
apis/virustotal.py — VirusTotal v3 API module.

Covers: MD5 / SHA1 / SHA256 hashes, IPv4 addresses, domains, URLs.
Free tier: 4 requests/min, 500/day.
Sign up: https://www.virustotal.com/gui/join-us
"""

import base64
import requests
from apis.base import KeyPool, ThreatIntelClient

_BASE   = "https://www.virustotal.com/api/v3"
SOURCE  = "VirusTotal"
_client = ThreatIntelClient(timeout=15)
_pool   = KeyPool("VT_API_KEY")   # loads VT_API_KEY, VT_API_KEY_2, _3 ...


def _no_key():
    return {"source": SOURCE, "verdict": "skipped", "data": {}, "raw_response": None, "error": "No API key"}


def _get(endpoint: str, proxies: dict):
    resp = _client.get(
        f"{_BASE}{endpoint}",
        key_pool=_pool,
        key_header="x-apikey",
        proxies=proxies,
    )
    resp.raise_for_status()
    return resp.json()


def _stats_verdict(stats: dict) -> str:
    malicious = stats.get("malicious", 0)
    if malicious >= 5:
        return "malicious"
    if malicious > 0:
        return "suspicious"
    return "clean"


# ─────────────────────────────────────────────────────────────────────────────

def analyze_hash(value: str, proxies: dict) -> dict:
    if not _pool:
        return _no_key()
    try:
        data  = _get(f"/files/{value}", proxies)
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        mal   = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        label = (attrs.get("popular_threat_classification", {})
                     .get("suggested_threat_label", "—"))
        return {
            "source":  SOURCE,
            "verdict": _stats_verdict(stats),
            "data": {
                "detections": f"{mal}/{total}",
                "family":     label,
                "file_type":  attrs.get("type_description", "—"),
                "first_seen": attrs.get("first_submission_date", "—"),
            },
            "raw_response": data,
            "error": None,
        }
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            return {"source": SOURCE, "verdict": "not_found",
                    "data": {"note": "Not in VT database"}, "raw_response": None, "error": None}
        return {"source": SOURCE, "verdict": "error", "data": {}, "raw_response": None, "error": str(e)}
    except Exception as e:
        return {"source": SOURCE, "verdict": "error", "data": {}, "raw_response": None, "error": str(e)}


def analyze_ip(value: str, proxies: dict) -> dict:
    if not _pool:
        return _no_key()
    try:
        ip    = value.split("/")[0]  # strip CIDR
        data  = _get(f"/ip_addresses/{ip}", proxies)
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        mal   = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        return {
            "source":  SOURCE,
            "verdict": _stats_verdict(stats),
            "data": {
                "detections": f"{mal}/{total}",
                "country":    attrs.get("country", "—"),
                "asn":        attrs.get("asn", "—"),
                "as_owner":   attrs.get("as_owner", "—"),
            },
            "raw_response": data,
            "error": None,
        }
    except Exception as e:
        return {"source": SOURCE, "verdict": "error", "data": {}, "raw_response": None, "error": str(e)}


def analyze_domain(value: str, proxies: dict) -> dict:
    if not _pool:
        return _no_key()
    try:
        data  = _get(f"/domains/{value}", proxies)
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        mal   = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        return {
            "source":  SOURCE,
            "verdict": _stats_verdict(stats),
            "data": {
                "detections":  f"{mal}/{total}",
                "registrar":   attrs.get("registrar", "—"),
                "reputation":  attrs.get("reputation", "—"),
                "creation":    attrs.get("creation_date", "—"),
            },
            "raw_response": data,
            "error": None,
        }
    except Exception as e:
        return {"source": SOURCE, "verdict": "error", "data": {}, "raw_response": None, "error": str(e)}


def analyze_url(value: str, proxies: dict) -> dict:
    if not _pool:
        return _no_key()
    try:
        # VT URL lookup: URL-safe base64 of the raw URL, no padding
        url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        data   = _get(f"/urls/{url_id}", proxies)
        attrs  = data.get("data", {}).get("attributes", {})
        stats  = attrs.get("last_analysis_stats", {})
        mal    = stats.get("malicious", 0)
        total  = sum(stats.values()) if stats else 0
        return {
            "source":  SOURCE,
            "verdict": _stats_verdict(stats),
            "data": {
                "detections": f"{mal}/{total}",
                "final_url":  attrs.get("last_final_url", "—"),
                "title":      attrs.get("title", "—"),
            },
            "raw_response": data,
            "error": None,
        }
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            return {"source": SOURCE, "verdict": "not_found",
                    "data": {"note": "Not scanned yet"}, "raw_response": None, "error": None}
        return {"source": SOURCE, "verdict": "error", "data": {}, "raw_response": None, "error": str(e)}
    except Exception as e:
        return {"source": SOURCE, "verdict": "error", "data": {}, "raw_response": None, "error": str(e)}
