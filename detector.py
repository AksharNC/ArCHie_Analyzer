"""
detector.py — IOC type auto-detection engine for ArCHie Analyzer.

Parses raw string input (single or multi-line) and returns typed IOC objects.
Order of patterns matters: more specific checks come before looser ones.
"""

import re
from dataclasses import dataclass
from typing import List


@dataclass
class IOC:
    value:         str
    ioc_type:      str   # sha256 | sha1 | md5 | cve | url | email | ipv4 | domain | filepath | unknown
    display_label: str   # Human-readable label shown in TUI
    emoji:         str   # Emoji badge shown in header


# ─── Pattern Table ────────────────────────────────────────────────────────────
# (ioc_type, compiled_regex, display_label, emoji)
# Each pattern is tried in order — first match wins.

_PATTERNS = [
    # Hashes — most specific first (longest match)
    ("sha256",   re.compile(r"^[a-fA-F0-9]{64}$"),
                 "SHA-256 Hash", ""),
    ("sha1",     re.compile(r"^[a-fA-F0-9]{40}$"),
                 "SHA-1 Hash",   ""),
    ("md5",      re.compile(r"^[a-fA-F0-9]{32}$"),
                 "MD5 Hash",     ""),

    # CVE — must come before domain (CVE-2024-1234 could loosely match domain)
    ("cve",      re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE),
                 "CVE ID",       ""),

    # URL — must come before domain (full URL contains domain)
    ("url",      re.compile(r"^https?://[^\s]+", re.IGNORECASE),
                 "URL",          ""),

    # Email — must come before domain (email contains domain part)
    ("email",    re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"),
                 "Email Address",""),

    # IPv4 (with optional CIDR)
    ("ipv4",     re.compile(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$"),
                 "IPv4 Address", ""),

    # Domain — loose check, must have dot and valid TLD
    ("domain",   re.compile(r"^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$"),
                 "Domain",       ""),

    # File paths: Windows (C:\), Unix (/), home (~), env (%TEMP%)
    ("filepath", re.compile(r"^([A-Za-z]:\\|/|~/|%[A-Z_]+%)"),
                 "File Path",    ""),
]


# ─── Public API ───────────────────────────────────────────────────────────────

def detect_single(raw: str) -> IOC:
    """Detect the IOC type of a single trimmed string."""
    value = raw.strip()
    for ioc_type, pattern, label, emoji in _PATTERNS:
        if pattern.search(value):
            return IOC(value=value, ioc_type=ioc_type, display_label=label, emoji=emoji)
    return IOC(value=value, ioc_type="unknown", display_label="Unknown", emoji="")


def detect_bulk(raw_input: str) -> List[IOC]:
    """
    Parse multi-line input. Each non-empty line is treated as a separate IOC.
    Lines starting with # are ignored (comments).
    """
    results = []
    for line in raw_input.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        results.append(detect_single(line))
    return results
