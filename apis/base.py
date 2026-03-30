"""
apis/base.py — Shared HTTP client for ArCHie API modules.

Provides:
  - KeyPool: auto-discovers all numbered API keys for a source from the
    environment (VT_API_KEY, VT_API_KEY_2, VT_API_KEY_3, ...) using a single
    base env var name.  Add a new key simply by setting the next numbered env
    var — no code changes required.
    On a 429 response ThreatIntelClient rotates to the next available key and
    retries immediately (no sleep) before falling back to exponential backoff.

  - ThreatIntelClient: a requests.Session wrapper with:
      - Automatic retry + exponential backoff on transient failures
      - Retries on: 429 (rate limited), 503 (unavailable), timeouts, connection errors
      - Backoff schedule: 1s → 2s → 4s (max 3 attempts by default)
      - Key rotation via KeyPool when key_pool + key_header are supplied

Usage in each API module:
    from apis.base import KeyPool, ThreatIntelClient

    _pool   = KeyPool("VT_API_KEY")   # auto-loads VT_API_KEY, VT_API_KEY_2, _3 ...
    _client = ThreatIntelClient(timeout=15)

    resp = _client.get(
        url,
        key_pool=_pool,
        key_header="x-apikey",
        proxies=proxies,
    )
"""

import os
import time
import requests


class KeyPool:
    """
    Auto-discovers all API keys for a source from numbered env vars.

    Given a base name such as "VT_API_KEY", it loads:
      VT_API_KEY        (primary)
      VT_API_KEY_2      (secondary)
      VT_API_KEY_3      (tertiary)
      ...up to VT_API_KEY_<max_keys>

    Scanning stops at the first missing/empty slot so the numbering must be
    contiguous (no gaps).  Keys are rotated round-robin; the active key is
    injected into request headers by ThreatIntelClient automatically.

    To add more keys in future: just set VT_API_KEY_3=... in .env — done.

    Example:
        _pool = KeyPool("VT_API_KEY")
        if not _pool:
            return _no_key()
    """

    def __init__(self, base_env: str, max_keys: int = 10) -> None:
        self._keys: list[str] = []
        # Primary — no numeric suffix
        primary = os.getenv(base_env, "").strip()
        if primary:
            self._keys.append(primary)
        # Secondary and beyond — _2, _3, ...
        for i in range(2, max_keys + 1):
            val = os.getenv(f"{base_env}_{i}", "").strip()
            if val:
                self._keys.append(val)
            else:
                break   # stop at first gap — numbering must be contiguous
        self._idx: int = 0

    def __bool__(self) -> bool:
        return bool(self._keys)

    def __len__(self) -> int:
        return len(self._keys)

    def current(self) -> str:
        """Return the currently active key, or an empty string if none configured."""
        return self._keys[self._idx] if self._keys else ""

    def rotate(self) -> None:
        """Advance to the next key (wraps around). No-op with only one key."""
        if len(self._keys) > 1:
            self._idx = (self._idx + 1) % len(self._keys)


class ThreatIntelClient:
    """Thin requests.Session wrapper with automatic retry + key-rotation logic."""

    def __init__(self, timeout: int = 15, max_retries: int = 3):
        self.timeout     = timeout
        self.max_retries = max_retries
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

        last_exc: Exception | None = None

        for attempt in range(self.max_retries):
            # Inject the currently active key into headers before each attempt.
            if key_pool and key_header:
                headers = dict(kwargs.get("headers", {}))
                headers[key_header] = key_pool.current()
                kwargs["headers"] = headers

            try:
                resp = self._session.request(method, url, **kwargs)
                if resp.status_code in (429, 503):
                    if key_pool and len(key_pool) > 1:
                        # Rotate to the next key and retry immediately — no sleep.
                        key_pool.rotate()
                    else:
                        time.sleep(2 ** attempt)
                    continue
                return resp
            except (requests.Timeout, requests.ConnectionError) as exc:
                last_exc = exc
                time.sleep(2 ** attempt)

        if last_exc:
            raise last_exc
        raise requests.RequestException(
            f"Max retries ({self.max_retries}) exceeded for {url}"
        )

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
