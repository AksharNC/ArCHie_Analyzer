"""
cache.py — File-based IOC result cache for ArCHie Analyzer.

  Cache key : SHA-256( "{source}:{ioc_value}" )
  Cache store: JSON files in  cache/  directory (auto-created)
  TTL        : 24 hours (override with CACHE_TTL_HOURS env var)

Usage:
    import cache
    result = cache.get("VirusTotal", "1.2.3.4")
    if result is None:
        result = virustotal.analyze_ip("1.2.3.4", proxies)
        cache.set("VirusTotal", "1.2.3.4", result)

Disable at runtime:
    cache.enable(False)   # honours --no-cache flag
"""

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Optional

_CACHE_DIR = Path(__file__).parent / "output" / "cache"
_TTL_SECS  = int(os.getenv("CACHE_TTL_HOURS", "24")) * 3600
_enabled   = True


# ─── Public API ──────────────────────────────────────────────────────────────

def enable(val: bool) -> None:
    """Toggle cache on/off (used by --no-cache flag)."""
    global _enabled
    _enabled = val


def get(source: str, ioc_value: str) -> Optional[dict]:
    """Return a cached result dict, or None on miss / expiry / disabled."""
    if not _enabled:
        return None
    path = _cache_path(source, ioc_value)
    if not path.exists():
        return None
    try:
        entry = json.loads(path.read_text(encoding="utf-8"))
        if time.time() - entry.get("cached_at", 0) > _TTL_SECS:
            path.unlink(missing_ok=True)
            return None
        return entry.get("result")
    except Exception:
        return None


def set(source: str, ioc_value: str, result: dict) -> None:  # noqa: A001
    """Write *result* to cache. Cache write failures are silent."""
    if not _enabled:
        return
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = _cache_path(source, ioc_value)
    try:
        entry = {"cached_at": time.time(), "result": result}
        path.write_text(json.dumps(entry, default=str), encoding="utf-8")
    except Exception:
        pass  # non-fatal


def flush() -> int:
    """Delete all cache files. Returns the number of files removed."""
    if not _CACHE_DIR.exists():
        return 0
    removed = 0
    for f in _CACHE_DIR.glob("*.json"):
        try:
            f.unlink()
            removed += 1
        except Exception:
            pass
    return removed


# ─── Internal ────────────────────────────────────────────────────────────────

def _cache_path(source: str, ioc_value: str) -> Path:
    key    = f"{source}:{ioc_value}".encode()
    digest = hashlib.sha256(key).hexdigest()
    return _CACHE_DIR / f"{digest}.json"
