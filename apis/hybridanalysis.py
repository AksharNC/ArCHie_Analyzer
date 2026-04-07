"""
apis/hybridanalysis.py — Hybrid Analysis sandbox API module.

Covers: MD5 / SHA1 / SHA256 hashes.
Free API key required.
Sign up: https://www.hybrid-analysis.com/signup
Env var: HYBRID_ANALYSIS_KEY
"""

import requests
from apis.base import KeyPool, ThreatIntelClient

_BASE   = "https://www.hybrid-analysis.com/api/v2"
SOURCE  = "Hybrid Analysis"
_client = ThreatIntelClient(timeout=20, source=SOURCE)
_pool   = KeyPool("HYBRID_ANALYSIS_KEY")   # loads HYBRID_ANALYSIS_KEY, HYBRID_ANALYSIS_KEY_2, _3 ...


def _no_key():
    return {"source": SOURCE, "verdict": "skipped", "data": {}, "raw_response": None, "error": "No API key"}


def analyze_hash(value: str, proxies: dict) -> dict:
    if not _pool:
        return _no_key()
    try:
        # POST /search/hashes — see Hybrid Analysis v2 API docs
        resp = _client.post(
            f"{_BASE}/search/hashes",
            key_pool=_pool,
            key_header="api-key",
            headers={
                "user-agent":   "Falcon Sandbox",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={"hash": value},
            proxies=proxies,
        )
        resp.raise_for_status()
        results = resp.json()

        if not results:
            return {
                "source":  SOURCE,
                "verdict": "not_found",
                "data":    {"note": "Not in Hybrid Analysis database"},
                "raw_response": results,
                "error":   None,
            }

        report       = results[0]
        verdict_raw  = report.get("verdict", "") or ""
        threat_score = report.get("threat_score")
        av_detect    = report.get("av_detect")        # AV detection %
        type_short   = report.get("type_short", "—")

        if verdict_raw == "malicious":
            verdict = "malicious"
        elif verdict_raw == "suspicious":
            verdict = "suspicious"
        elif verdict_raw in ("no specific threat", "whitelisted"):
            verdict = "clean"
        else:
            # Fall back to threat score
            if threat_score is not None:
                if threat_score >= 70:
                    verdict = "malicious"
                elif threat_score >= 30:
                    verdict = "suspicious"
                else:
                    verdict = "clean"
            else:
                verdict = "unknown"

        return {
            "source":  SOURCE,
            "verdict": verdict,
            "data": {
                "verdict":      verdict_raw or "—",
                "threat_score": f"{threat_score}/100" if threat_score is not None else "—",
                "av_detect":    f"{av_detect}%" if av_detect is not None else "—",
                "file_type":    type_short,
            },
            "raw_response": results,
            "error": None,
        }

    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            return {"source": SOURCE, "verdict": "not_found",
                    "data": {"note": "Not in database"}, "raw_response": None, "error": None}
        return {"source": SOURCE, "verdict": "error", "data": {}, "raw_response": None, "error": str(e)}
    except Exception as e:
        return {"source": SOURCE, "verdict": "error", "data": {}, "raw_response": None, "error": str(e)}
