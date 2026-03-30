"""
tests/test_multikey.py  --  ArCHie Analyzer multi-key / KeyPool test suite

Run:  python tests/test_multikey.py
"""

import importlib
import os
import sys

# Ensure project root is on the path when running as: python tests/test_multikey.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── helpers ──────────────────────────────────────────────────────────────────

_KEY_VARS = [
    "VT_API_KEY", "VT_API_KEY_2", "VT_API_KEY_3", "VT_API_KEY_5",
    "ABUSEIPDB_KEY", "ABUSEIPDB_KEY_2",
    "GREYNOISE_KEY", "GREYNOISE_KEY_2",
    "OTX_KEY", "OTX_KEY_2",
    "URLSCAN_KEY", "URLSCAN_KEY_2",
    "MALWAREBAZAAR_KEY", "MALWAREBAZAAR_KEY_2",
    "HYBRID_ANALYSIS_KEY", "HYBRID_ANALYSIS_KEY_2",
    "PHISHTANK_KEY", "PHISHTANK_KEY_2",
    "NVD_API_KEY", "NVD_API_KEY_2",
    "IPINFO_KEY", "IPINFO_KEY_2",
]


def _clear_keys():
    for k in _KEY_VARS:
        os.environ.pop(k, None)


def _reload_apis():
    """Reload all api modules so KeyPool re-reads the current env."""
    for mod in list(sys.modules):
        if mod.startswith("apis.") and mod != "apis.base":
            del sys.modules[mod]
    # Also reload base so KeyPool instances are fresh
    if "apis.base" in sys.modules:
        del sys.modules["apis.base"]


_PASS = 0
_FAIL = 0


def check(label: str, condition: bool, detail: str = ""):
    global _PASS, _FAIL
    if condition:
        print(f"  OK   {label}")
        _PASS += 1
    else:
        print(f"  FAIL {label}" + (f"  ({detail})" if detail else ""))
        _FAIL += 1


# ── Section 1: KeyPool unit tests ────────────────────────────────────────────

print("\n=== 1. KeyPool unit tests ===")
_clear_keys()
_reload_apis()

from apis.base import KeyPool

# 1a. no keys → falsy
p = KeyPool("VT_API_KEY")
check("no keys: bool=False", not p)
check("no keys: len=0", len(p) == 0)
check("no keys: current=''", p.current() == "")

# 1b. one key
os.environ["VT_API_KEY"] = "key1"
p = KeyPool("VT_API_KEY")
check("1 key: bool=True", bool(p))
check("1 key: len=1", len(p) == 1)
check("1 key: current=key1", p.current() == "key1")
p.rotate()
check("1 key: rotate is no-op", p.current() == "key1")

# 1c. two keys — round-robin
os.environ["VT_API_KEY_2"] = "key2"
p = KeyPool("VT_API_KEY")
check("2 keys: len=2", len(p) == 2)
check("2 keys: starts at key1", p.current() == "key1")
p.rotate()
check("2 keys: rotates to key2", p.current() == "key2")
p.rotate()
check("2 keys: wraps to key1", p.current() == "key1")

# 1d. three keys
os.environ["VT_API_KEY_3"] = "key3"
p = KeyPool("VT_API_KEY")
check("3 keys: len=3", len(p) == 3)
p.rotate(); p.rotate()
check("3 keys: reaches key3", p.current() == "key3")

# 1e. gap stops scan (key4 absent, key5 set → only 3 loaded)
os.environ["VT_API_KEY_5"] = "key5-orphan"
p = KeyPool("VT_API_KEY")
check("gap stops scan: len stays 3", len(p) == 3, f"got {len(p)}")

# ── Section 2: rate_limiter auto-scaling ─────────────────────────────────────

print("\n=== 2. Rate limiter auto-scaling ===")
_clear_keys()
# Reload rate_limiter so it re-reads env
if "rate_limiter" in sys.modules:
    del sys.modules["rate_limiter"]

from rate_limiter import _count_active_keys, _DEFAULTS

# 2a. no keys → count=1 (minimum)
count = _count_active_keys("VirusTotal")
check("no keys: count=1", count == 1, f"got {count}")

# 2b. one key
os.environ["VT_API_KEY"] = "k1"
if "rate_limiter" in sys.modules: del sys.modules["rate_limiter"]
from rate_limiter import _count_active_keys
count = _count_active_keys("VirusTotal")
check("1 key: count=1", count == 1, f"got {count}")

# 2c. two keys
os.environ["VT_API_KEY_2"] = "k2"
if "rate_limiter" in sys.modules: del sys.modules["rate_limiter"]
from rate_limiter import _count_active_keys
count = _count_active_keys("VirusTotal")
check("2 keys: count=2", count == 2, f"got {count}")

# 2d. limit scales 2x
if "rate_limiter" in sys.modules: del sys.modules["rate_limiter"]
from rate_limiter import _load_limits, _DEFAULTS
limits = _load_limits()
expected = _DEFAULTS["VirusTotal"] * 2
check(f"2 keys: VT limit={expected}", limits["VirusTotal"] == expected,
      f"got {limits['VirusTotal']}")

# 2e. crt.sh (no key env var) → always 1
if "rate_limiter" in sys.modules: del sys.modules["rate_limiter"]
from rate_limiter import _count_active_keys
check("crt.sh no base env: count=1", _count_active_keys("crt.sh") == 1)

# ── Section 3: API module imports ────────────────────────────────────────────

print("\n=== 3. API module imports ===")
_clear_keys()
_reload_apis()

MODULE_FUNCS = {
    "apis.virustotal":     ["analyze_hash", "analyze_ip", "analyze_domain", "analyze_url"],
    "apis.abuseipdb":      ["analyze_ip"],
    "apis.greynoise":      ["analyze_ip"],
    "apis.otx":            ["analyze_hash", "analyze_ip", "analyze_domain", "analyze_url"],
    "apis.urlscan":        ["analyze_url", "analyze_domain"],
    "apis.malwarebazaar":  ["analyze_hash"],
    "apis.hybridanalysis": ["analyze_hash"],
    "apis.phishtank":      ["analyze_url"],
    "apis.nvd":            ["analyze_cve"],
    "apis.ipinfo":         ["analyze_ip"],
    "apis.crtsh":          ["analyze_domain"],
}

for mod_name, fns in MODULE_FUNCS.items():
    try:
        mod = importlib.import_module(mod_name)
        missing = [f for f in fns if not hasattr(mod, f)]
        check(mod_name, not missing, f"missing: {missing}")
    except Exception as e:
        check(mod_name, False, str(e))

# ── Section 4: no-key guard paths (no network) ───────────────────────────────

print("\n=== 4. No-key guard paths ===")
_clear_keys()
_reload_apis()

import apis.virustotal as vt
import apis.abuseipdb  as ab
import apis.greynoise  as gn
import apis.otx        as otx
import apis.malwarebazaar  as mb
import apis.hybridanalysis as ha
import apis.phishtank      as pt
import apis.urlscan        as us

HASH   = "44d88612fea8a8f36de82e1278abb02f"
IP     = "8.8.8.8"
DOMAIN = "evil.ru"
URL    = "https://evil.ru"
PX     = {}

NOKEY_CASES = [
    ("VT hash",       vt.analyze_hash,   HASH),
    ("VT ip",         vt.analyze_ip,     IP),
    ("VT domain",     vt.analyze_domain, DOMAIN),
    ("VT url",        vt.analyze_url,    URL),
    ("AbuseIPDB",     ab.analyze_ip,     IP),
    ("GreyNoise",     gn.analyze_ip,     IP),
    ("OTX hash",      otx.analyze_hash,  HASH),
    ("OTX ip",        otx.analyze_ip,    IP),
    ("OTX domain",    otx.analyze_domain,DOMAIN),
    ("OTX url",       otx.analyze_url,   URL),
    ("MalwareBazaar", mb.analyze_hash,   HASH),
    ("HybridAnalysis",ha.analyze_hash,   HASH),
    ("PhishTank",     pt.analyze_url,    URL),
    ("URLScan",       us.analyze_url,    URL),
]

for name, fn, ioc in NOKEY_CASES:
    r = fn(ioc, PX)
    ok = (r.get("verdict") == "skipped" and r.get("error") == "No API key")
    check(name + ": skipped/no-key", ok,
          f"verdict={r.get('verdict')} error={r.get('error')}")

# ── Summary ───────────────────────────────────────────────────────────────────

print(f"\n{'='*50}")
total = _PASS + _FAIL
print(f"Results: {_PASS}/{total} passed  |  {_FAIL} failed")
if _FAIL:
    sys.exit(1)
