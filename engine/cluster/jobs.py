"""Job model and lifecycle states for the distributed queue."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class JobState(str, Enum):
    """Every state a job can occupy.

    Inheriting from ``str`` keeps these directly JSON-serialisable and lets
    them be compared against plain strings, which avoids a conversion layer at
    every database and API boundary.
    """

    PENDING = "pending"  # accepted, not yet eligible (delayed jobs sit here)
    QUEUED = "queued"  # eligible for a worker to claim
    RUNNING = "running"  # claimed, lease active
    PAUSED = "paused"  # operator suspended it; will not be claimed
    WAITING = "waiting"  # blocked on a dependency or rate limit
    RETRYING = "retrying"  # failed, waiting out its backoff before requeue
    CANCELLED = "cancelled"  # operator cancelled it; terminal
    COMPLETED = "completed"  # finished successfully; terminal
    FAILED = "failed"  # exhausted its retries; terminal
    TIMED_OUT = "timed_out"  # exceeded its execution budget
    LOST = "lost"  # worker vanished mid-flight; lease expired

    @property
    def is_terminal(self) -> bool:
        """True when no further transition is possible without operator action."""
        return self in _TERMINAL

    @property
    def is_claimable(self) -> bool:
        """True when a worker may take this job, subject to its schedule."""
        return self in _CLAIMABLE

    @property
    def is_active(self) -> bool:
        """True while the job still occupies queue capacity."""
        return not self.is_terminal


_TERMINAL = frozenset({JobState.CANCELLED, JobState.COMPLETED, JobState.FAILED})
_CLAIMABLE = frozenset({JobState.QUEUED, JobState.RETRYING, JobState.LOST})


class JobPriority(int, Enum):
    """Scheduling priority. Higher values are dispatched first.

    Integer-backed rather than string-backed so the database can ``ORDER BY``
    the stored column directly, and so callers may pass an arbitrary integer
    for finer-grained control without being boxed in by the enum.
    """

    BULK = 0  # opportunistic sweeps of a large inventory
    LOW = 10
    NORMAL = 50
    HIGH = 80
    URGENT = 100  # incident response; jumps everything


# A job that has been claimed but whose worker has gone silent for longer than
# its lease is presumed lost and handed to another worker. Sixty seconds is
# long enough to ride out a GC pause or a brief network partition, short enough
# that a crashed worker does not strand a job for long.
DEFAULT_LEASE_SECONDS = 60.0

# Retry backoff is exponential with a ceiling, so a target that is simply down
# does not get hammered while a transient blip still recovers quickly.
DEFAULT_MAX_ATTEMPTS = 3
BACKOFF_BASE_SECONDS = 5.0
BACKOFF_CEILING_SECONDS = 900.0


def backoff_delay(attempt: int, *, base: float = BACKOFF_BASE_SECONDS) -> float:
    """Seconds to wait before retry number ``attempt`` (1-based).

    Exponential with a hard ceiling. Deliberately deterministic: jitter is
    applied by the queue at enqueue time, where it can be seeded for tests,
    rather than hidden inside this calculation.
    """
    if attempt < 1:
        return 0.0
    delay = base * (2 ** (attempt - 1))
    return min(delay, BACKOFF_CEILING_SECONDS)


@dataclass(slots=True)
class Job:
    """A single unit of scheduled work.

    A job is the durable record of *intent to scan*, distinct from the
    ``ScanResult`` that records what was found. It carries everything a
    stateless worker needs to pick the work up cold.
    """

    target: str
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    priority: int = int(JobPriority.NORMAL)
    state: JobState = JobState.QUEUED

    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    available_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    expires_at: float | None = None

    attempts: int = 0
    max_attempts: int = DEFAULT_MAX_ATTEMPTS

    assigned_worker: str | None = None
    lease_expires_at: float | None = None

    stage: str = ""
    progress: float = 0.0

    dedup_key: str = ""
    last_error: str = ""
    payload: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # An empty dedup key means "deduplicate on the target". Callers that
        # genuinely want a duplicate job pass an explicitly unique key.
        if not self.dedup_key:
            self.dedup_key = self.target

    @property
    def is_expired(self) -> bool:
        """True once the job has outlived its usefulness.

        A scan queued for a nightly sweep is worthless if it only reaches a
        worker two days later; expiry stops the queue from draining stale work
        after a long outage.
        """
        return self.expires_at is not None and time.time() >= self.expires_at

    @property
    def lease_is_expired(self) -> bool:
        return self.lease_expires_at is not None and time.time() >= self.lease_expires_at

    @property
    def can_retry(self) -> bool:
        return self.attempts < self.max_attempts

    @property
    def duration_seconds(self) -> float:
        """Wall-clock execution time, or time so far if still running."""
        if self.started_at is None:
            return 0.0
        end = self.finished_at if self.finished_at is not None else time.time()
        return max(0.0, end - self.started_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "priority": self.priority,
            "state": self.state.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "available_at": self.available_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "expires_at": self.expires_at,
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "assigned_worker": self.assigned_worker,
            "lease_expires_at": self.lease_expires_at,
            "stage": self.stage,
            "progress": self.progress,
            "dedup_key": self.dedup_key,
            "last_error": self.last_error,
            "payload": self.payload,
            "duration_seconds": self.duration_seconds,
        }

    @classmethod
    def from_row(cls, row: Any) -> Job:
        """Rebuild a job from a ``sqlite3.Row``."""
        payload = row["payload"]
        return cls(
            id=row["id"],
            target=row["target"],
            priority=row["priority"],
            state=JobState(row["state"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            available_at=row["available_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            expires_at=row["expires_at"],
            attempts=row["attempts"],
            max_attempts=row["max_attempts"],
            assigned_worker=row["assigned_worker"],
            lease_expires_at=row["lease_expires_at"],
            stage=row["stage"] or "",
            progress=row["progress"],
            dedup_key=row["dedup_key"],
            last_error=row["last_error"] or "",
            payload=json.loads(payload) if payload else {},
        )
