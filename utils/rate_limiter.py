"""
WebOSINT Pro - Rate Limiter
Token-bucket algorithm — thread-safe, adaptive, per-host capable.

Fixed bugs vs original:
  - tokens=0 assigned outside lock after sleep (race condition)
  - sleep calculation could produce negative values
  - no per-host limiting support
"""

from __future__ import annotations

import threading
import time


class RateLimiter:
    """
    Thread-safe token-bucket rate limiter.

    acquire() blocks until a token is available.
    """

    def __init__(self, max_per_minute: int) -> None:
        self.rate: float = max(max_per_minute, 1) / 60.0  # tokens/sec
        self.max_tokens: float = float(max_per_minute)
        self._tokens: float = float(max_per_minute)
        self._last: float = time.monotonic()
        self._lock: threading.Lock = threading.Lock()

    def acquire(self) -> None:
        """Block until one token is available, then consume it."""
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                self._tokens = min(
                    self.max_tokens,
                    self._tokens + elapsed * self.rate,
                )
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # Calculate wait time while still holding the lock
                deficit = 1.0 - self._tokens
                wait_secs = deficit / self.rate

            # Sleep outside the lock so other threads can also wake up
            time.sleep(max(0.005, wait_secs))

    @property
    def tokens_available(self) -> float:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            return min(self.max_tokens, self._tokens + elapsed * self.rate)


class PerHostRateLimiter:
    """
    Maintains separate token-bucket limiters per target host.
    Falls back to the global limiter for unknown hosts.
    """

    def __init__(
        self,
        default_max_per_minute: int,
        per_host_overrides: dict[str, int] | None = None,
    ) -> None:
        self._default_rpm = default_max_per_minute
        self._global = RateLimiter(default_max_per_minute)
        self._limiters: dict[str, RateLimiter] = {}
        self._lock = threading.Lock()

        if per_host_overrides:
            for host, rpm in per_host_overrides.items():
                self._limiters[host.lower()] = RateLimiter(rpm)

    def acquire(self, host: str | None = None) -> None:
        if host:
            limiter = self._get_or_create(host.lower())
            limiter.acquire()
        else:
            self._global.acquire()

    def _get_or_create(self, host: str) -> RateLimiter:
        with self._lock:
            if host not in self._limiters:
                self._limiters[host] = RateLimiter(self._default_rpm)
            return self._limiters[host]
