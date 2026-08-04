"""
WebOSINT Pro - Shared response cache.

Several modules independently fetch the same URLs (e.g. the target homepage).
A single per-scan cache lets them share those idempotent responses instead of
each re-requesting, which reduces load on the target during an authorized
assessment.

Only safe, body-less idempotent methods (GET, HEAD) are cached.
"""

from __future__ import annotations

import threading
from typing import Any

_CACHEABLE_METHODS = {"GET", "HEAD"}


class ResponseCache:
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self._store: dict[tuple[str, str], Any] = {}
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    @staticmethod
    def is_cacheable(method: str, has_body: bool) -> bool:
        return method.upper() in _CACHEABLE_METHODS and not has_body

    def _key(self, method: str, url: str) -> tuple[str, str]:
        return (method.upper(), url)

    def get(self, method: str, url: str) -> Any | None:
        if not self.enabled:
            return None
        with self._lock:
            value = self._store.get(self._key(method, url))
            if value is None:
                self.misses += 1
            else:
                self.hits += 1
            return value

    def set(self, method: str, url: str, response: Any) -> None:
        if not self.enabled or response is None:
            return
        with self._lock:
            self._store[self._key(method, url)] = response

    def stats(self) -> dict[str, int]:
        return {"hits": self.hits, "misses": self.misses, "size": len(self._store)}
