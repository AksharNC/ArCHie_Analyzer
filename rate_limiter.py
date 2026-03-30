"""
rate_limiter.py — Per-source API rate limit tracker for ArCHie Analyzer.

Tracks requests-per-minute per source using a sliding window.
  - Warns to console when usage reaches 80 % of the configured limit.
  - Throttles (sleeps) automatically when the limit is exhausted.

Usage:
    from rate_limiter import rate_limiter
    rate_limiter.record("VirusTotal")   # call before each API request
"""

import os
import threading
import time
from collections import deque

from rich.console import Console

_console = Console(stderr=True, legacy_windows=False)

# Per-minute defaults per source (free-tier safe).
# Override any value via .env:  RATE_LIMIT_VIRUSTOTAL=500
# Set env var to 0 to disable throttling for that source entirely.
_DEFAULTS: dict[str, int] = {
    "VirusTotal":      4,     # Free: 4/min | Standard: 1 000/min | Premium: higher
    "AbuseIPDB":       60,
    "GreyNoise":       3,     # Community: 50/day
    "MalwareBazaar":   30,
    "OTX AlienVault":  60,
    "Hybrid Analysis": 5,
    "URLScan.io":      10,
    "PhishTank":       30,
    "IPInfo":          60,
    "crt.sh":          30,
    "NVD":             5,
}

# Env-var name mapping:  source → RATE_LIMIT_<KEY>
_ENV_KEYS: dict[str, str] = {
    "VirusTotal":      "RATE_LIMIT_VIRUSTOTAL",
    "AbuseIPDB":       "RATE_LIMIT_ABUSEIPDB",
    "GreyNoise":       "RATE_LIMIT_GREYNOISE",
    "MalwareBazaar":   "RATE_LIMIT_MALWAREBAZAAR",
    "OTX AlienVault":  "RATE_LIMIT_OTX",
    "Hybrid Analysis": "RATE_LIMIT_HYBRID_ANALYSIS",
    "URLScan.io":      "RATE_LIMIT_URLSCAN",
    "PhishTank":       "RATE_LIMIT_PHISHTANK",
    "IPInfo":          "RATE_LIMIT_IPINFO",
    "crt.sh":          "RATE_LIMIT_CRTSH",
    "NVD":             "RATE_LIMIT_NVD",
}

# Base env var name per source.  The rate limiter uses the same auto-scan
# convention as KeyPool: it checks BASE, BASE_2, BASE_3 ... (stopping at first
# gap) to count how many keys are active.  Adding e.g. VT_API_KEY_3 to .env
# is all that's needed to have the limit auto-scale — no code changes required.
_KEY_BASE_ENV: dict[str, str] = {
    "VirusTotal":      "VT_API_KEY",
    "AbuseIPDB":       "ABUSEIPDB_KEY",
    "GreyNoise":       "GREYNOISE_KEY",
    "MalwareBazaar":   "MALWAREBAZAAR_KEY",
    "OTX AlienVault":  "OTX_KEY",
    "Hybrid Analysis": "HYBRID_ANALYSIS_KEY",
    "URLScan.io":      "URLSCAN_KEY",
    "PhishTank":       "PHISHTANK_KEY",
    "IPInfo":          "IPINFO_KEY",
    "NVD":             "NVD_API_KEY",
}

_MAX_KEY_SCAN = 10   # upper bound for numbered-suffix scanning


def _count_active_keys(source: str, max_keys: int = _MAX_KEY_SCAN) -> int:
    """
    Count how many non-empty API keys are configured for *source*.

    Mirrors the KeyPool scanning convention: checks BASE_ENV, BASE_ENV_2,
    BASE_ENV_3 ... and stops at the first missing/empty slot.  Returns at
    least 1 so the default rate limit is never reduced below its free-tier value.
    """
    base = _KEY_BASE_ENV.get(source)
    if not base:
        return 1
    count = 0
    if os.getenv(base, "").strip():
        count = 1
        for i in range(2, max_keys + 1):
            if os.getenv(f"{base}_{i}", "").strip():
                count += 1
            else:
                break
    return max(count, 1)


def _load_limits() -> dict[str, int | None]:
    """
    Merge defaults with any RATE_LIMIT_* overrides from the environment.

    When no explicit override is set, the default limit is automatically scaled
    by the number of active keys for that source (uses the same contiguous-scan
    convention as KeyPool: VT_API_KEY, VT_API_KEY_2, VT_API_KEY_3 ...).
    Adding more numbered keys to .env scales the rate limit up automatically.
    """
    limits: dict[str, int | None] = {}
    for source, default in _DEFAULTS.items():
        env_key = _ENV_KEYS.get(source)
        if env_key:
            raw = os.getenv(env_key, "").strip()
            if raw.isdigit():
                val = int(raw)
                limits[source] = val if val > 0 else None  # 0 → disabled
                continue
        # Scale the free-tier default by the number of configured keys.
        limits[source] = default * _count_active_keys(source)
    return limits


_RATE_LIMITS: dict[str, int | None] = _load_limits()

_WARN_AT = 0.80   # emit warning when this fraction of the limit is used


class _SourceTracker:
    """Sliding-window (60-second) tracker for a single API source."""

    def __init__(self, limit: int):
        self._limit  = limit
        self._window: deque[float] = deque()
        self._lock   = threading.Lock()
        self._warned = False

    def _prune(self) -> None:
        cutoff = time.monotonic() - 60.0
        while self._window and self._window[0] < cutoff:
            self._window.popleft()

    def record(self, source: str) -> None:
        with self._lock:
            self._prune()
            current = len(self._window)

            # Hard limit reached → throttle until oldest entry expires
            if current >= self._limit:
                oldest = self._window[0]
                wait   = 60.0 - (time.monotonic() - oldest) + 0.1
                if wait > 0:
                    _console.print(
                        f"\n  [yellow]⏳  Rate limit reached for "
                        f"[bold]{source}[/bold]. "
                        f"Throttling {wait:.1f}s to stay within limits...[/yellow]\n"
                    )
                    time.sleep(wait)
                self._prune()
                self._warned = False

            else:
                # Approaching limit → warn once per filling window
                usage = (current + 1) / self._limit
                if usage >= _WARN_AT and not self._warned:
                    remaining = self._limit - current - 1
                    _console.print(
                        f"\n  [yellow]⚠️   [bold]{source}[/bold] approaching "
                        f"rate limit — {current + 1}/{self._limit} req/min "
                        f"({remaining} remaining this minute)[/yellow]\n"
                    )
                    self._warned = True
                elif usage < _WARN_AT:
                    self._warned = False

            self._window.append(time.monotonic())


class RateLimiter:
    """Thread-safe, per-source rate limiter singleton."""

    def __init__(self) -> None:
        self._trackers: dict[str, _SourceTracker] = {}
        self._lock = threading.Lock()

    def record(self, source: str) -> None:
        """
        Record one request for *source*.
        Throttles if the configured per-minute limit is reached.
        Warns at 80 % of the limit.
        No-op if the source has no configured limit.
        """
        limit = _RATE_LIMITS.get(source)
        if limit is None:
            return

        with self._lock:
            if source not in self._trackers:
                self._trackers[source] = _SourceTracker(limit)

        # Call record outside the creation lock to avoid holding it during sleep
        self._trackers[source].record(source)


# Module-level singleton — import directly:
#   from rate_limiter import rate_limiter
rate_limiter = RateLimiter()
