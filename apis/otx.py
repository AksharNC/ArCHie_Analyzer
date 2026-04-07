"""
apis/otx.py — OTX AlienVault Open Threat Exchange API module.

Covers: MD5/SHA1/SHA256 hashes, IPv4, domains, URLs.
Free tier: generous rate limits.
Sign up: https://otx.alienvault.com/api
"""

import requests
from apis.base import KeyPool, ThreatIntelClient

_BASE   = "https://otx.alienvault.com/api/v1"
SOURCE  = "OTX AlienVault"
_client = ThreatIntelClient(timeout=12, source=SOURCE)
_pool   = KeyPool("OTX_KEY")   # loads OTX_KEY, OTX_KEY_2, _3 ...


def _no_key():
    return {"source": SOURCE, "verdict": "skipped", "data": {}, "raw_response": None, "error": "No API key"}


def _get(endpoint: str, proxies: dict):
    resp = _client.get(
        f"{_BASE}{endpoint}",
        key_pool=_pool,
        key_header="X-OTX-API-KEY",
        proxies=proxies,
    )
    resp.raise_for_status()
    return resp.json()


def _pulse_verdict(pulse_count: int) -> str:
    """For hashes and IPs — lower thresholds are appropriate."""
    if pulse_count >= 5:
        return "malicious"
    if pulse_count >= 1:
        return "suspicious"
    return "clean"


def _domain_verdict(pulse_count: int) -> str:
    """
    Verdict for domain-type indicators.
    Popular domains appear in research pulses legitimately — only flag at higher counts.
    """
    if pulse_count >= 20:
        return "malicious"
    if pulse_count >= 10:
        return "suspicious"
    return "clean"


def _url_verdict(pulse_count: int) -> str:
    """
    Verdict for direct URL lookups.
    OTX URL index is noisier than domain index — benign URLs (e.g. google.com)
    regularly appear in 15-30 research/reference pulses.  Raise thresholds
    considerably to avoid false positives on clean URLs.
    """
    if pulse_count >= 40:
        return "malicious"
    if pulse_count >= 20:
        return "suspicious"
    return "clean"


def _extract_families(pulses: list) -> str:
    """
    Safely extract malware family names from the pulse list.
    Each pulse's malware_families field is a list of dicts with 'id' and 'display_name' keys.
    Families are deduplicated and capped at 4 to prevent table overflow.
    """
    families = set()
    for p in pulses:
        for fam in p.get("malware_families", []):
            if isinstance(fam, dict):
                name = fam.get("display_name") or fam.get("id", "")
            else:
                name = str(fam)
            if name:
                families.add(name)
    if not families:
        return "—"
    sorted_fams = sorted(families)
    # Cap at 4 families to prevent table overflow; note extras
    if len(sorted_fams) > 4:
        display = ", ".join(sorted_fams[:4]) + f" (+{len(sorted_fams)-4} more)"
    else:
        display = ", ".join(sorted_fams)
    return display


# ─────────────────────────────────────────────────────────────────────────────

def analyze_hash(value: str, proxies: dict) -> dict:
    if not _pool:
        return _no_key()
    try:
        length     = len(value)
        htype      = "MD5" if length == 32 else ("SHA1" if length == 40 else "SHA256")
        data       = _get(f"/indicators/file/{value}/general", proxies)
        pulse_info = data.get("pulse_info", {})
        pulses     = pulse_info.get("count", 0)
        return {
            "source":  SOURCE,
            "verdict": _pulse_verdict(pulses),
            "data": {
                "pulses":           pulses,
                "hash_type":        htype,
                "malware_families": _extract_families(pulse_info.get("pulses", [])),
            },
            "raw_response": data,
            "error": None,
        }
    except Exception as e:
        return {"source": SOURCE, "verdict": "error", "data": {}, "raw_response": None, "error": str(e)}


def analyze_ip(value: str, proxies: dict) -> dict:
    if not _pool:
        return _no_key()
    try:
        ip         = value.split("/")[0]
        data       = _get(f"/indicators/IPv4/{ip}/general", proxies)
        pulse_info = data.get("pulse_info", {})
        pulses     = pulse_info.get("count", 0)
        return {
            "source":  SOURCE,
            "verdict": _pulse_verdict(pulses),
            "data": {
                "pulses":  pulses,
                "country": data.get("country_name", "—"),
                "asn":     data.get("asn", "—"),
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
        data       = _get(f"/indicators/domain/{value}/general", proxies)
        pulse_info = data.get("pulse_info", {})
        pulses     = pulse_info.get("count", 0)
        return {
            "source":  SOURCE,
            "verdict": _domain_verdict(pulses),
            "data": {
                "pulses": pulses,
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
        import urllib.parse
        encoded    = urllib.parse.quote(value, safe="")
        data       = _get(f"/indicators/url/{encoded}/general", proxies)
        pulse_info = data.get("pulse_info", {})
        pulses     = pulse_info.get("count", 0)
        domain     = data.get("domain", "—")
        return {
            "source":  SOURCE,
            "verdict": _url_verdict(pulses),
            "data": {
                "pulses": pulses,
                "domain": domain,
            },
            "raw_response": data,
            "error": None,
        }
    except Exception as e:
        return {"source": SOURCE, "verdict": "error", "data": {}, "raw_response": None, "error": str(e)}
