"""
apis/base.py — Shared HTTP client for ArCHie API modules.

Provides:
  - KeyPool: auto-discovers all numbered API keys for a source from the
    environment (VT_API_KEY, VT_API_KEY_2, VT_API_KEY_3, ...) using a single
    base env var name.  Add a new key simply by setting the next numbered env
    var — no code changes required.

    Per-key 429 cooldown: when a key receives a 429, it is marked as cooling
    for 65 seconds before being eligible again.  If ALL keys are cooling,
    ThreatIntelClient sleeps until the earliest one becomes available rather
    than failing immediately.

  - ThreatIntelClient: a requests.Session wrapper with:
      - Automatic retry + exponential backoff on transient failures
      - Retries on: 429 (rate limited), 503 (unavailable), timeouts, connection errors
      - Retry count scales with key pool size (min 4, or len(keys)+2)
      - Full per-key cooldown cycling — never fails while a key will recover
      - Key rotation via KeyPool when key_pool + key_header are supplied
"""

import os
import threading
import time
import requests

from rate_limiter import daily_tracker, _RATE_LIMITS

_KEY_COOLDOWN_SECS = 65   # how long a 429'd key sits out (slightly over 1 min)


class KeyPool:
    """
    Auto-discovers all API keys for a source from numbered env vars.

    Per-key 429 cooldown: each key that receives a 429 is marked as cooling
    for 65 seconds.  current() and rotate() both skip cooling keys.
    If every key is currently cooling, next_available_in() returns the
    seconds until the earliest key recovers (ThreatIntelClient sleeps that long).
    """

    def __init__(self, base_env: str, max_keys: int = 10) -> None:
        self._keys: list[str] = []
        primary = os.getenv(base_env, "").strip()
        if primary:
            self._keys.append(primary)
        for i in range(2, max_keys + 1):
            val = os.getenv(f"{base_env}_{i}", "").strip()
            if val:
                self._keys.append(val)
            else:
                break
        self._idx: int = 0
        self._cooldowns: dict[int, float] = {}   # key_index -> monotonic time it cools off
        self._lock = threading.Lock()

    def __bool__(self) -> bool:
        return bool(self._keys)

    def __len__(self) -> int:
        return len(self._keys)

    def _is_cooling(self, idx: int) -> bool:
        """True if this key index is still in its cooldown window."""
        until = self._cooldowns.get(idx)
        if until is None:
            return False
        if time.monotonic() >= until:
            del self._cooldowns[idx]   # expired, clean up
            return False
        return True

    def current(self) -> str:
        """Return the currently active key (skipping cooling ones), or '' if none."""
        if not self._keys:
            return ""
        with self._lock:
            # Try each slot once starting from _idx
            for offset in range(len(self._keys)):
                idx = (self._idx + offset) % len(self._keys)
                if not self._is_cooling(idx):
                    self._idx = idx
                    return self._keys[idx]
            # All keys are cooling — return current anyway; caller will sleep
            return self._keys[self._idx]

    def mark_cooldown(self) -> None:
        """Mark the currently active key as cooling for _KEY_COOLDOWN_SECS."""
        with self._lock:
            self._cooldowns[self._idx] = time.monotonic() + _KEY_COOLDOWN_SECS
            # Advance to next key immediately
            if len(self._keys) > 1:
                self._idx = (self._idx + 1) % len(self._keys)

    def rotate(self) -> None:
        """Advance to the next non-cooling key. No-op with only one key."""
        if len(self._keys) > 1:
            with self._lock:
                for _ in range(len(self._keys)):
                    self._idx = (self._idx + 1) % len(self._keys)
                    if not self._is_cooling(self._idx):
                        return
                # All cooling — leave index as-is; next_available_in handles sleep

    def all_cooling(self) -> bool:
        """Return True if every key is currently in cooldown."""
        with self._lock:
            return all(self._is_cooling(i) for i in range(len(self._keys)))

    def next_available_in(self) -> float:
        """
        Seconds until the earliest cooling key becomes available.
        Returns 0 if any key is free right now.
        """
        with self._lock:
            now = time.monotonic()
            waits = []
            for i in range(len(self._keys)):
                until = self._cooldowns.get(i)
                if until is None or until <= now:
                    return 0.0
                waits.append(until - now)
            return min(waits) + 0.2 if waits else 0.0


class ThreatIntelClient:
    """Thin requests.Session wrapper with automatic retry + key-rotation logic."""

    def __init__(self, timeout: int = 15, max_retries: int = 3, source: str = ""):
        self.timeout     = timeout
        self.max_retries = max_retries
        self.source      = source      # used for live quota + exhaustion tracking
        self._session    = requests.Session()

    def _request(
        self,
        method: str,
        url: str,
        key_pool: KeyPool | None = None,
        key_header: str | None = None,
        **kwargs,
    ) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", False)

        # Scale retries with key pool size so we can cycle through all keys
        # before giving up.  Minimum 4 attempts even with a single key.
        effective_retries = max(self.max_retries, len(key_pool) + 2) if key_pool else self.max_retries

        last_exc: Exception | None = None

        for attempt in range(effective_retries):
            # If all keys are in cooldown, sleep until the earliest recovers
            if key_pool and key_pool.all_cooling():
                wait = key_pool.next_available_in()
                if wait > 0:
                    from rich.console import Console as _C
                    _C(stderr=True, legacy_windows=False).print(
                        f"\n  [yellow]⏳  All {self.source or 'API'} keys are rate-limited. "
                        f"Waiting {wait:.0f}s for cooldown...[/yellow]\n"
                    )
                    time.sleep(wait)

            # Inject the currently active (non-cooling) key
            if key_pool and key_header:
                headers = dict(kwargs.get("headers", {}))
                headers[key_header] = key_pool.current()
                kwargs["headers"] = headers

            try:
                resp = self._session.request(method, url, **kwargs)

                if resp.status_code == 429:
                    # Check if this is a daily-quota exhaustion (not just per-min)
                    if self.source:
                        self._check_daily_exhaustion(resp)
                    if key_pool and len(key_pool) > 0:
                        # Only use the 65s per-key cooldown when rate limiting is
                        # active for this source.  When the user has set
                        # RATE_LIMIT_X=0 (unlimited mode) we just rotate
                        # immediately — same fast behaviour as before.
                        rate_limiting_on = _RATE_LIMITS.get(self.source) is not None
                        if rate_limiting_on:
                            key_pool.mark_cooldown()
                        else:
                            key_pool.rotate()
                    else:
                        time.sleep(min(2 ** attempt, 60))
                    continue

                if resp.status_code == 503:
                    time.sleep(min(2 ** attempt, 30))
                    continue

                return resp
            except (requests.Timeout, requests.ConnectionError) as exc:
                last_exc = exc
                time.sleep(min(2 ** attempt, 30))

        if last_exc:
            raise last_exc
        raise requests.RequestException(
            f"Max retries ({effective_retries}) exceeded for {url}"
        )

    def _check_daily_exhaustion(self, resp: requests.Response) -> None:
        """
        Inspect a 429 response body for daily/quota exhaustion keywords.
        If found, mark the source as exhausted in DailyUsageTracker so
        --api-status can show EXHAUSTED until midnight.
        """
        # Common exhaustion phrases across APIs
        _EXHAUSTION_PHRASES = (
            "dailyquotaexceeded",
            "quota exceeded",
            "daily limit",
            "day limit",
            "exceeded your daily",
            "quota_exceeded",
        )
        try:
            body = resp.text.lower()
        except Exception:
            return
        for phrase in _EXHAUSTION_PHRASES:
            if phrase in body:
                daily_tracker.mark_exhausted(self.source, phrase)
                return
        # Also check Retry-After — a very large value signals daily exhaustion
        retry_after = resp.headers.get("retry-after", "")
        try:
            if int(retry_after) >= 3600:   # ≥1 hour → treat as daily cap
                daily_tracker.mark_exhausted(self.source, f"retry-after={retry_after}s")
        except (ValueError, TypeError):
            pass

    def get(
        self,
        url: str,
        key_pool: KeyPool | None = None,
        key_header: str | None = None,
        **kwargs,
    ) -> requests.Response:
        return self._request("GET", url, key_pool=key_pool, key_header=key_header, **kwargs)

    def post(
        self,
        url: str,
        key_pool: KeyPool | None = None,
        key_header: str | None = None,
        **kwargs,
    ) -> requests.Response:
        return self._request("POST", url, key_pool=key_pool, key_header=key_header, **kwargs)
