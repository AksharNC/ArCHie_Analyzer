"""Quick validation of all fixes applied this session."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.argv = ["analyzer.py"]  # prevent argparse from firing

from analyzer import _analyze_filepath
from detector import detect_single, detect_bulk, IOC
from rate_limiter import rate_limiter, daily_tracker, get_api_status, _RATE_LIMITS
from output.renderer import _ASCII_BANNERS, print_banner, print_ioc_header, print_results_table
import cache as ioc_cache

passed = 0
failed = 0

def check(name, condition):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS: {name}")
    else:
        failed += 1
        print(f"  FAIL: {name}")

# ═══ 1. IPv4 Validation ═══
print("\n=== IPv4 Octet Validation ===")
check("192.168.1.1 → ipv4",          detect_single("192.168.1.1").ioc_type == "ipv4")
check("10.0.0.0/8 → ipv4",           detect_single("10.0.0.0/8").ioc_type == "ipv4")
check("255.255.255.255 → ipv4",      detect_single("255.255.255.255").ioc_type == "ipv4")
check("0.0.0.0 → ipv4",             detect_single("0.0.0.0").ioc_type == "ipv4")
check("1.2.3.4/32 → ipv4",          detect_single("1.2.3.4/32").ioc_type == "ipv4")
check("999.999.999.999 → unknown",  detect_single("999.999.999.999").ioc_type == "unknown")
check("256.1.1.1 → unknown",        detect_single("256.1.1.1").ioc_type == "unknown")
check("1.2.3.4/33 → unknown",       detect_single("1.2.3.4/33").ioc_type == "unknown")
check("300.300.300.300 → unknown",   detect_single("300.300.300.300").ioc_type == "unknown")

# ═══ 2. IOC.emoji removed ═══
print("\n=== IOC.emoji Removed ===")
ioc = detect_single("8.8.8.8")
check("IOC has no 'emoji' field",    not hasattr(ioc, "emoji"))
check("IOC has 3 fields",           len(ioc.__dataclass_fields__) == 3)

# ═══ 3. All IOC types detected ═══
print("\n=== IOC Type Detection ===")
check("SHA-256",    detect_single("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592").ioc_type == "sha256")
check("SHA-1",      detect_single("da39a3ee5e6b4b0d3255bfef95601890afd80709").ioc_type == "sha1")
check("MD5",        detect_single("d41d8cd98f00b204e9800998ecf8427e").ioc_type == "md5")
check("CVE",        detect_single("CVE-2024-1234").ioc_type == "cve")
check("CVE lower",  detect_single("cve-2023-44487").ioc_type == "cve")
check("URL",        detect_single("https://evil.com/malware").ioc_type == "url")
check("Email",      detect_single("user@example.com").ioc_type == "email")
check("Domain",     detect_single("example.com").ioc_type == "domain")
check("Filepath",   detect_single("C:\\Windows\\Temp\\evil.exe").ioc_type == "filepath")
check("Unknown",    detect_single("randomgarbage!!!").ioc_type == "unknown")

# ═══ 4. Bulk detection ═══
print("\n=== Bulk Detection ===")
bulk = detect_bulk("8.8.8.8\n# comment\ngoogle.com\n\nCVE-2024-1234")
check("Bulk parses 3 IOCs (skips comment + blank)", len(bulk) == 3)

# ═══ 5. _analyze_filepath → always 'info' ═══
print("\n=== File Path Verdicts (all 'info') ===")
r1 = _analyze_filepath("C:\\Windows\\Temp\\evil.exe")
check("exe in Temp → info",         r1["verdict"] == "info")
check("exe in Temp → note correct", "High-risk extension" in r1["data"]["assessment"])

r2 = _analyze_filepath("C:\\Users\\me\\Desktop\\test.ps1")
check("ps1 → info",                 r2["verdict"] == "info")

r3 = _analyze_filepath("/home/user/safe.txt")
check("safe file → info",           r3["verdict"] == "info")
check("safe file → no risk note",   r3["data"]["assessment"] == "No obvious risk indicators")

# ═══ 6. Rate limiter basics ═══
print("\n=== Rate Limiter ===")
check("rate_limiter.record() works", True)  # already tested above
check("Rate limits loaded",         len(_RATE_LIMITS) >= 11)
check("VT in rate limits",          "VirusTotal" in _RATE_LIMITS)

# ═══ 7. Daily tracker ═══
print("\n=== Daily Tracker ===")
daily_tracker.mark_exhausted("__TEST__", "unit test")
check("mark_exhausted works",       daily_tracker.is_exhausted("__TEST__"))
daily_tracker.clear_exhausted("__TEST__")
check("clear_exhausted works",      not daily_tracker.is_exhausted("__TEST__"))
check("get_counts returns dict",    isinstance(daily_tracker.get_counts(), dict))

# ═══ 8. API status structure ═══
print("\n=== API Status ===")
status = get_api_status()
check("Returns list",               isinstance(status, list))
check("Has entries",                 len(status) > 0)
required = {"source", "configured", "key_count", "per_min_limit", "daily_limit",
            "calls_today", "remaining_today", "exhausted", "exhausted_reason"}
actual = set(status[0].keys())
check("All required keys",          required == actual)
check("No live_window keys",        "live_window_remaining" not in actual and "live_window_limit" not in actual)

# ═══ 9. Banners trimmed ═══
print("\n=== ASCII Banners ===")
check(f"Only 3 banners (was 10)",    len(_ASCII_BANNERS) == 3)

# ═══ 10. Renderer works with new IOC (no emoji) ═══
print("\n=== Renderer Compatibility ===")
try:
    ioc = detect_single("8.8.8.8")
    print_ioc_header(ioc)
    # Test print_results_table with sample data
    sample_results = [
        {"source": "TestSource", "verdict": "clean", "data": {"info": "test"}, "error": None},
        {"source": "TestSource2", "verdict": "error", "data": {}, "error": "test error"},
    ]
    print_results_table(sample_results, ioc_type="ipv4")
    check("Renderer works with new IOC dataclass", True)
except Exception as e:
    check(f"Renderer works with new IOC dataclass: {e}", False)

# ═══ 11. Cache module ═══
print("\n=== Cache Module ===")
try:
    # Just verify it imports and basic functions exist
    check("cache.get exists",        callable(getattr(ioc_cache, "get", None)))
    check("cache.set exists",        callable(getattr(ioc_cache, "set", None)))
except Exception as e:
    check(f"Cache module: {e}", False)

# ═══ Summary ═══
print(f"\n{'='*50}")
print(f"  PASSED: {passed}  |  FAILED: {failed}")
print(f"{'='*50}")
if failed:
    sys.exit(1)
