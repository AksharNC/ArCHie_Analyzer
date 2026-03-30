"""
apis/crtsh.py — crt.sh Certificate Transparency Log module.

Covers: Domains only.
No authentication required.
Endpoint: https://crt.sh/?q=<domain>&output=json
Purpose: Subdomain enumeration and org discovery for VAPT recon.
"""

import requests
from apis.base import ThreatIntelClient

_BASE   = "https://crt.sh"
SOURCE  = "crt.sh"
_client = ThreatIntelClient(timeout=20)


def analyze_domain(value: str, proxies: dict) -> dict:
    try:
        resp = _client.get(
            _BASE,
            params={"q": value, "output": "json"},
            proxies=proxies,
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        entries = resp.json()

        if not entries:
            return {
                "source":  SOURCE,
                "verdict": "info",
                "data":    {"note": "No certificates found"},
                "raw_response": entries,
                "error":   None,
            }

        # Extract unique subdomains / SAN names
        names = set()
        for e in entries:
            raw = e.get("name_value", "")
            for name in raw.split("\n"):
                name = name.strip().lstrip("*.")
                if name and name != value:
                    names.add(name)

        cert_count = len(entries)
        sub_count  = len(names)

        # First 3 unique subdomains for display
        preview = sorted(names)[:3]
        preview_str = ", ".join(preview) if preview else "none"
        if sub_count > 3:
            preview_str += f" (+{sub_count - 3} more)"

        return {
            "source":  SOURCE,
            "verdict": "info",
            "data": {
                "certificates": cert_count,
                "subdomains":   f"{sub_count} found",
                "preview":      preview_str,
            },
            "raw_response": entries,
            "error": None,
        }

    except requests.HTTPError as e:
        return {"source": SOURCE, "verdict": "error", "data": {}, "raw_response": None, "error": str(e)}
    except Exception as e:
        return {"source": SOURCE, "verdict": "error", "data": {}, "raw_response": None, "error": str(e)}
