"""
Shared, deduplicating cache for expensive network work.

The single biggest source of wasted time in the legacy scanner was repeated
work: several modules each resolving the same name and re-fetching the same
homepage. This cache guarantees a given lookup happens exactly once per scan,
even when many plugins request it concurrently.

The key property is *single-flight*: concurrent callers asking for the same key
block on one in-flight computation rather than all performing it.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

T = TypeVar("T")


@dataclass(slots=True)
class CacheEntry(Generic[T]):
    value: T
    created_at: float = field(default_factory=time.monotonic)
    hits: int = 0

    def is_fresh(self, ttl: float) -> bool:
        if ttl <= 0:
            return True
        return (time.monotonic() - self.created_at) < ttl


@dataclass(slots=True)
class CacheStats:
    hits: int = 0
    misses: int = 0
    coalesced: int = 0
    errors: int = 0

    @property
    def total(self) -> int:
        return self.hits + self.misses

    @property
    def hit_rate(self) -> float:
        return (self.hits / self.total) if self.total else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "coalesced": self.coalesced,
            "errors": self.errors,
            "hit_rate": round(self.hit_rate, 3),
        }


class SharedCache:
    """Namespaced, TTL'd, single-flight cache.

    Namespaces keep unrelated data separate (``dns``, ``http``, ``tls`` ...) so
    they can be inspected and expired independently.
    """

    def __init__(self, default_ttl: float = 0.0) -> None:
        self._data: dict[str, dict[str, CacheEntry[Any]]] = {}
        self._locks: dict[tuple[str, str], threading.Lock] = {}
        self._guard = threading.Lock()
        self._stats = CacheStats()
        self.default_ttl = default_ttl

    @staticmethod
    def _normalize(key: Any) -> str:
        if isinstance(key, str):
            return key.strip().lower()
        if isinstance(key, (list, tuple)):
            return "|".join(SharedCache._normalize(part) for part in key)
        return str(key)

    def _entry_lock(self, namespace: str, key: str) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault((namespace, key), threading.Lock())

    def get(self, namespace: str, key: Any, ttl: float | None = None) -> Any | None:
        key = self._normalize(key)
        ttl = self.default_ttl if ttl is None else ttl
        with self._guard:
            entry = self._data.get(namespace, {}).get(key)
            if entry is not None and entry.is_fresh(ttl):
                entry.hits += 1
                self._stats.hits += 1
                return entry.value
        return None

    def set(self, namespace: str, key: Any, value: Any) -> None:
        key = self._normalize(key)
        with self._guard:
            self._data.setdefault(namespace, {})[key] = CacheEntry(value=value)

    def get_or_compute(
        self,
        namespace: str,
        key: Any,
        producer: Callable[[], T],
        ttl: float | None = None,
    ) -> T:
        """Return the cached value, computing it at most once across threads."""
        normalized = self._normalize(key)
        ttl = self.default_ttl if ttl is None else ttl

        cached = self.get(namespace, normalized, ttl)
        if cached is not None:
            return cached

        lock = self._entry_lock(namespace, normalized)
        already_held = not lock.acquire(blocking=False)
        if already_held:
            # Another thread is computing this exact key: wait for its result
            # instead of duplicating the network call.
            with self._guard:
                self._stats.coalesced += 1
            lock.acquire()
        try:
            cached = self.get(namespace, normalized, ttl)
            if cached is not None:
                return cached
            with self._guard:
                self._stats.misses += 1
            try:
                value = producer()
            except Exception:
                with self._guard:
                    self._stats.errors += 1
                raise
            self.set(namespace, normalized, value)
            return value
        finally:
            lock.release()

    def invalidate(self, namespace: str, key: Any | None = None) -> None:
        with self._guard:
            if key is None:
                self._data.pop(namespace, None)
            else:
                self._data.get(namespace, {}).pop(self._normalize(key), None)

    def namespace_keys(self, namespace: str) -> list[str]:
        with self._guard:
            return sorted(self._data.get(namespace, {}))

    @property
    def stats(self) -> CacheStats:
        return self._stats

    def summary(self) -> dict[str, Any]:
        with self._guard:
            sizes = {ns: len(items) for ns, items in self._data.items()}
        return {"namespaces": sizes, "stats": self._stats.to_dict()}

    def clear(self) -> None:
        with self._guard:
            self._data.clear()
            self._locks.clear()
            self._stats = CacheStats()
