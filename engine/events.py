"""
In-process publish/subscribe event bus.

Plugins never call each other. When a plugin learns something another plugin
might need, it publishes an event; interested parties subscribe. This keeps the
dependency graph flat and makes plugin ordering an optimisation rather than a
correctness requirement.

The bus is thread-safe and deliberately fail-soft: a broken subscriber is
isolated and logged, never allowed to abort the publisher.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

LOG = logging.getLogger(__name__)


class Topic(str):
    """Marker type for event topics (a plain string at runtime)."""


# Well-known topics. Plugins may publish their own; these are the contract
# points the engine itself relies on.
TARGET_NORMALIZED = "target.normalized"
DNS_RESOLVED = "dns.resolved"
IP_RESOLVED = "ip.resolved"
HTTP_RESPONSE = "http.response"
TLS_INSPECTED = "tls.inspected"
TECHNOLOGY_DETECTED = "technology.detected"
SURFACE_CLASSIFIED = "surface.classified"
ASSET_DISCOVERED = "asset.discovered"
FINDING_RAISED = "finding.raised"
PLUGIN_STARTED = "plugin.started"
PLUGIN_FINISHED = "plugin.finished"
PLUGIN_FAILED = "plugin.failed"
PLUGIN_SKIPPED = "plugin.skipped"
SCAN_PROGRESS = "scan.progress"
SCAN_COMPLETED = "scan.completed"


@dataclass(frozen=True, slots=True)
class Event:
    """An immutable message on the bus."""

    topic: str
    payload: dict[str, Any] = field(default_factory=dict)
    source: str = ""
    timestamp: float = field(default_factory=time.time)

    def get(self, key: str, default: Any = None) -> Any:
        return self.payload.get(key, default)


Subscriber = Callable[[Event], None]


class EventBus:
    """Thread-safe synchronous event bus with a bounded audit history."""

    def __init__(self, history_size: int = 2000) -> None:
        self._subscribers: dict[str, list[Subscriber]] = defaultdict(list)
        self._wildcard: list[Subscriber] = []
        self._lock = threading.RLock()
        self._history: deque[Event] = deque(maxlen=history_size)
        self._counts: dict[str, int] = defaultdict(int)

    # -- subscription ------------------------------------------------------

    def subscribe(self, topic: str, handler: Subscriber) -> Callable[[], None]:
        """Register ``handler`` for ``topic``. Returns an unsubscribe callable.

        Use ``"*"`` to receive every event (used by the recorder and the live
        dashboard feed).
        """
        with self._lock:
            if topic == "*":
                self._wildcard.append(handler)
            else:
                self._subscribers[topic].append(handler)

        def unsubscribe() -> None:
            self.unsubscribe(topic, handler)

        return unsubscribe

    def unsubscribe(self, topic: str, handler: Subscriber) -> None:
        with self._lock:
            bucket = self._wildcard if topic == "*" else self._subscribers.get(topic, [])
            if handler in bucket:
                bucket.remove(handler)

    # -- publication -------------------------------------------------------

    def publish(self, topic: str, payload: dict[str, Any] | None = None, source: str = "") -> Event:
        """Deliver an event to all matching subscribers.

        Subscribers are snapshotted under the lock and invoked outside it, so a
        slow or re-entrant handler cannot deadlock the bus.
        """
        event = Event(topic=topic, payload=dict(payload or {}), source=source)
        with self._lock:
            handlers = list(self._subscribers.get(topic, ())) + list(self._wildcard)
            self._history.append(event)
            self._counts[topic] += 1

        for handler in handlers:
            try:
                handler(event)
            except Exception:
                LOG.exception("Event subscriber failed for topic %s", topic)
        return event

    def emit(self, event: Event) -> Event:
        return self.publish(event.topic, event.payload, event.source)

    # -- introspection -----------------------------------------------------

    def history(self, topic: str | None = None, limit: int = 100) -> list[Event]:
        with self._lock:
            events = list(self._history)
        if topic:
            events = [item for item in events if item.topic == topic]
        return events[-limit:]

    def counts(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)

    def topics(self) -> Iterable[str]:
        with self._lock:
            return sorted(self._subscribers)

    def clear(self) -> None:
        with self._lock:
            self._subscribers.clear()
            self._wildcard.clear()
            self._history.clear()
            self._counts.clear()
