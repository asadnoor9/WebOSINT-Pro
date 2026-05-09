"""
WebOSINT Pro - Rate Limiter
Token bucket algorithm for request rate limiting
"""

import time
import threading


class RateLimiter:
    """Thread-safe token bucket rate limiter."""

    def __init__(self, max_per_minute: int):
        self.rate = max_per_minute / 60.0  # tokens per second
        self.max_tokens = max_per_minute
        self.tokens = float(max_per_minute)
        self.last_check = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self):
        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_check
            self.last_check = now
            self.tokens = min(self.max_tokens, self.tokens + elapsed * self.rate)

            if self.tokens >= 1:
                self.tokens -= 1
                return

        # No token available - sleep
        sleep_time = (1 - self.tokens) / self.rate
        time.sleep(max(0.01, sleep_time))
        self.tokens = 0
