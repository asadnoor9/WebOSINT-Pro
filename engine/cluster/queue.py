"""
Durable, priority-ordered job queue.

Backed by SQLite from the standard library so a single-node install needs no
broker, no daemon and no configuration. The public interface is deliberately
broker-shaped -- ``enqueue`` / ``claim`` / ``complete`` / ``fail`` with leases
and acknowledgements -- so a Redis or PostgreSQL backend can be dropped in
behind it later without touching a single caller.

Correctness model
-----------------

* **Leases, not locks.** A worker claims a job for a bounded period. If it dies
  the lease lapses and the job returns to the queue. Nothing depends on a
  worker announcing its own death, because a crashed worker cannot.
* **At-least-once delivery.** A job may run twice if a worker completes work
  but dies before acknowledging. Scans are idempotent -- rescanning a target is
  wasteful but never wrong -- so this is the right trade against the
  at-most-once alternative, where a crash silently loses work.
* **Every transition is committed before it is returned.** A caller that sees
  a state change can rely on it having survived to disk.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from engine.cluster.jobs import (
    DEFAULT_LEASE_SECONDS,
    DEFAULT_MAX_ATTEMPTS,
    Job,
    JobPriority,
    JobState,
    backoff_delay,
)

LOG = logging.getLogger(__name__)

# States that occupy a dedup slot. A target already queued or running must not
# be enqueued again; one that finished, failed or was cancelled may be.
_ACTIVE_STATES = (
    JobState.PENDING.value,
    JobState.QUEUED.value,
    JobState.RUNNING.value,
    JobState.PAUSED.value,
    JobState.WAITING.value,
    JobState.RETRYING.value,
)
_ACTIVE_SQL_LIST = ", ".join(f"'{state}'" for state in _ACTIVE_STATES)

_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS jobs (
    id                TEXT PRIMARY KEY,
    target            TEXT NOT NULL,
    priority          INTEGER NOT NULL DEFAULT {int(JobPriority.NORMAL)},
    state             TEXT NOT NULL,
    created_at        REAL NOT NULL,
    updated_at        REAL NOT NULL,
    available_at      REAL NOT NULL,
    started_at        REAL,
    finished_at       REAL,
    expires_at        REAL,
    attempts          INTEGER NOT NULL DEFAULT 0,
    max_attempts      INTEGER NOT NULL DEFAULT {DEFAULT_MAX_ATTEMPTS},
    assigned_worker   TEXT,
    lease_expires_at  REAL,
    stage             TEXT DEFAULT '',
    progress          REAL NOT NULL DEFAULT 0.0,
    dedup_key         TEXT NOT NULL,
    last_error        TEXT DEFAULT '',
    payload           TEXT
);

-- Claim ordering: the hot path is "highest priority, oldest first, among jobs
-- that are eligible right now". This composite index serves it without a sort.
CREATE INDEX IF NOT EXISTS idx_jobs_claim
    ON jobs (state, available_at, priority DESC, created_at);

CREATE INDEX IF NOT EXISTS idx_jobs_worker ON jobs (assigned_worker);
CREATE INDEX IF NOT EXISTS idx_jobs_target ON jobs (target);
CREATE INDEX IF NOT EXISTS idx_jobs_lease  ON jobs (lease_expires_at);

-- Duplicate prevention is enforced by the database, not by a read-then-write
-- in Python, which would race under concurrent producers.
CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_dedup
    ON jobs (dedup_key) WHERE state IN ({_ACTIVE_SQL_LIST});

-- Jobs that exhausted their retries are moved here rather than deleted, so a
-- systemic failure can be diagnosed and the work replayed after a fix.
CREATE TABLE IF NOT EXISTS dead_letters (
    id            TEXT PRIMARY KEY,
    target        TEXT NOT NULL,
    failed_at     REAL NOT NULL,
    attempts      INTEGER NOT NULL,
    last_error    TEXT,
    final_state   TEXT NOT NULL,
    job           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dl_failed_at ON dead_letters (failed_at);
"""


@dataclass(slots=True)
class QueueStats:
    """Point-in-time snapshot of queue depth, for status output and dashboards."""

    by_state: dict[str, int] = field(default_factory=dict)
    total: int = 0
    dead_letters: int = 0
    oldest_queued_age: float = 0.0

    @property
    def queued(self) -> int:
        return self.by_state.get(JobState.QUEUED.value, 0)

    @property
    def running(self) -> int:
        return self.by_state.get(JobState.RUNNING.value, 0)

    @property
    def completed(self) -> int:
        return self.by_state.get(JobState.COMPLETED.value, 0)

    @property
    def failed(self) -> int:
        return self.by_state.get(JobState.FAILED.value, 0)

    @property
    def backlog(self) -> int:
        """Work that still needs a worker."""
        return sum(
            self.by_state.get(state, 0)
            for state in (
                JobState.PENDING.value,
                JobState.QUEUED.value,
                JobState.RETRYING.value,
                JobState.LOST.value,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "by_state": dict(self.by_state),
            "total": self.total,
            "dead_letters": self.dead_letters,
            "oldest_queued_age": round(self.oldest_queued_age, 2),
            "backlog": self.backlog,
            "queued": self.queued,
            "running": self.running,
        }


def default_queue_path() -> Path:
    """Queue database beside the rest of the runtime state."""
    configured = os.environ.get("WEBOSINT_QUEUE_PATH", "").strip()
    if configured:
        return Path(configured)
    runtime = os.environ.get("WEBOSINT_RUNTIME_DIR", "").strip()
    base = Path(runtime) if runtime else Path.home() / ".webosint"
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    return base / "queue.db"


class JobQueue:
    """A durable priority queue with leases, retries and a dead-letter table.

    Thread-safe and process-safe. Multiple worker processes on one host may
    share a queue file; SQLite's WAL mode plus ``BEGIN IMMEDIATE`` around the
    claim path makes double-dispatch impossible.
    """

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        lease_seconds: float = DEFAULT_LEASE_SECONDS,
        max_claims_per_second: float = 0.0,
        busy_timeout_ms: int = 5000,
    ) -> None:
        self.path = Path(path) if path is not None else default_queue_path()
        self.lease_seconds = lease_seconds
        # A global ceiling on how fast work is dispatched. This is the blunt
        # instrument that stops a 10k-target sweep from melting the network the
        # moment it is enqueued; per-host politeness stays in the scan engine.
        self.max_claims_per_second = max_claims_per_second
        self.busy_timeout_ms = busy_timeout_ms

        self._local = threading.local()
        self._rate_lock = threading.Lock()
        self._claim_allowance = 0.0
        self._claim_checked_at = time.monotonic()

        if self.path.parent and str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    # -- connection handling --------------------------------------------------

    @property
    def _conn(self) -> sqlite3.Connection:
        """One connection per thread.

        SQLite connections are not safe to share across threads, and a
        thread-local is far less error-prone than a shared connection behind a
        global mutex, which would serialise every read as well as every write.
        """
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(str(self.path), timeout=self.busy_timeout_ms / 1000.0)
            conn.row_factory = sqlite3.Row
            # WAL lets readers proceed during a write, which matters once the
            # dashboard is polling stats while workers are claiming.
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
        return conn

    def _init_schema(self) -> None:
        conn = self._conn
        with conn:
            conn.executescript(_SCHEMA)

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    def __enter__(self) -> JobQueue:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- producing ------------------------------------------------------------

    def enqueue(
        self,
        target: str,
        *,
        priority: int | JobPriority = JobPriority.NORMAL,
        delay_seconds: float = 0.0,
        expires_in: float | None = None,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        dedup_key: str = "",
        payload: dict[str, Any] | None = None,
    ) -> Job | None:
        """Add a job, or return ``None`` if an equivalent one is already active.

        Returning ``None`` rather than raising makes the common case -- a
        nightly sweep re-enqueuing a target that is still running from the last
        sweep -- ordinary control flow instead of an exception to catch.
        """
        now = time.time()
        job = Job(
            target=target,
            priority=int(priority),
            state=JobState.PENDING if delay_seconds > 0 else JobState.QUEUED,
            created_at=now,
            updated_at=now,
            available_at=now + max(0.0, delay_seconds),
            expires_at=now + expires_in if expires_in else None,
            max_attempts=max_attempts,
            dedup_key=dedup_key or target,
            payload=payload or {},
        )

        try:
            with self._conn as conn:
                conn.execute(
                    """
                    INSERT INTO jobs (
                        id, target, priority, state, created_at, updated_at,
                        available_at, started_at, finished_at, expires_at,
                        attempts, max_attempts, assigned_worker, lease_expires_at,
                        stage, progress, dedup_key, last_error, payload
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        job.id,
                        job.target,
                        job.priority,
                        job.state.value,
                        job.created_at,
                        job.updated_at,
                        job.available_at,
                        job.started_at,
                        job.finished_at,
                        job.expires_at,
                        job.attempts,
                        job.max_attempts,
                        job.assigned_worker,
                        job.lease_expires_at,
                        job.stage,
                        job.progress,
                        job.dedup_key,
                        job.last_error,
                        json.dumps(job.payload),
                    ),
                )
        except sqlite3.IntegrityError:
            # The partial unique index rejected it: an equivalent job is live.
            LOG.debug("duplicate job suppressed for %s", target)
            return None
        return job

    def enqueue_many(self, targets: list[str], **kwargs: Any) -> tuple[list[Job], int]:
        """Bulk-enqueue, returning the accepted jobs and the duplicate count.

        Used by the inventory sweep, where tens of thousands of targets arrive
        at once and per-target exception handling would dominate the runtime.
        """
        accepted: list[Job] = []
        duplicates = 0
        for target in targets:
            job = self.enqueue(target, **kwargs)
            if job is None:
                duplicates += 1
            else:
                accepted.append(job)
        return accepted, duplicates

    # -- rate limiting --------------------------------------------------------

    def _take_claim_tokens(self, requested: int) -> int:
        """Token bucket over dispatch rate. Returns how many claims are allowed."""
        if self.max_claims_per_second <= 0:
            return requested
        with self._rate_lock:
            now = time.monotonic()
            elapsed = now - self._claim_checked_at
            self._claim_checked_at = now
            self._claim_allowance = min(
                self.max_claims_per_second,
                self._claim_allowance + elapsed * self.max_claims_per_second,
            )
            granted = min(requested, int(self._claim_allowance))
            self._claim_allowance -= granted
            return granted

    # -- consuming ------------------------------------------------------------

    def claim(
        self,
        worker_id: str,
        *,
        count: int = 1,
        lease_seconds: float | None = None,
    ) -> list[Job]:
        """Atomically take up to ``count`` jobs for ``worker_id``.

        Promotes due delayed jobs and expires stale ones first, so a caller
        never has to remember to run maintenance before consuming.
        """
        granted = self._take_claim_tokens(max(0, count))
        if granted <= 0:
            return []

        self.promote_due()
        self.expire_stale()

        lease = lease_seconds if lease_seconds is not None else self.lease_seconds
        now = time.time()
        claimed: list[Job] = []

        conn = self._conn
        # IMMEDIATE takes the write lock up front, so two workers cannot both
        # read the same candidate row and then both write to it.
        conn.execute("BEGIN IMMEDIATE")
        try:
            rows = conn.execute(
                f"""
                SELECT * FROM jobs
                 WHERE state IN (?, ?, ?)
                   AND available_at <= ?
                   AND (expires_at IS NULL OR expires_at > ?)
                 ORDER BY priority DESC, created_at ASC
                 LIMIT {int(granted)}
                """,
                (
                    JobState.QUEUED.value,
                    JobState.RETRYING.value,
                    JobState.LOST.value,
                    now,
                    now,
                ),
            ).fetchall()

            for row in rows:
                job = Job.from_row(row)
                job.state = JobState.RUNNING
                job.attempts += 1
                job.assigned_worker = worker_id
                job.started_at = now
                job.updated_at = now
                job.lease_expires_at = now + lease
                conn.execute(
                    """
                    UPDATE jobs
                       SET state=?, attempts=?, assigned_worker=?, started_at=?,
                           updated_at=?, lease_expires_at=?
                     WHERE id=?
                    """,
                    (
                        job.state.value,
                        job.attempts,
                        job.assigned_worker,
                        job.started_at,
                        job.updated_at,
                        job.lease_expires_at,
                        job.id,
                    ),
                )
                claimed.append(job)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        return claimed

    def heartbeat(
        self,
        job_id: str,
        worker_id: str,
        *,
        stage: str = "",
        progress: float | None = None,
        lease_seconds: float | None = None,
    ) -> bool:
        """Extend a lease and report progress. False if the lease was lost.

        A worker that gets ``False`` must abandon the job: the coordinator has
        already reassigned it, and continuing would double-write results.
        """
        lease = lease_seconds if lease_seconds is not None else self.lease_seconds
        now = time.time()
        with self._conn as conn:
            cursor = conn.execute(
                """
                UPDATE jobs
                   SET lease_expires_at=?, updated_at=?,
                       stage=COALESCE(NULLIF(?, ''), stage),
                       progress=COALESCE(?, progress)
                 WHERE id=? AND assigned_worker=? AND state=?
                """,
                (now + lease, now, stage, progress, job_id, worker_id, JobState.RUNNING.value),
            )
        return cursor.rowcount > 0

    def complete(self, job_id: str, worker_id: str = "", *, stage: str = "") -> bool:
        """Acknowledge success. Terminal."""
        now = time.time()
        clause = " AND assigned_worker=?" if worker_id else ""
        params: list[Any] = [JobState.COMPLETED.value, now, now, 100.0, stage or "complete", job_id]
        if worker_id:
            params.append(worker_id)
        with self._conn as conn:
            cursor = conn.execute(
                f"""
                UPDATE jobs
                   SET state=?, finished_at=?, updated_at=?, progress=?, stage=?,
                       lease_expires_at=NULL
                 WHERE id=?{clause}
                """,
                params,
            )
        return cursor.rowcount > 0

    def fail(
        self,
        job_id: str,
        worker_id: str = "",
        *,
        error: str = "",
        retry: bool = True,
        timed_out: bool = False,
    ) -> JobState | None:
        """Record a failure, retrying with backoff or dead-lettering.

        Returns the resulting state, or ``None`` if the job was not found.
        """
        job = self.get(job_id)
        if job is None:
            return None
        if worker_id and job.assigned_worker != worker_id:
            return None

        now = time.time()
        if retry and job.can_retry:
            delay = backoff_delay(job.attempts)
            new_state = JobState.RETRYING
            with self._conn as conn:
                conn.execute(
                    """
                    UPDATE jobs
                       SET state=?, available_at=?, updated_at=?, last_error=?,
                           assigned_worker=NULL, lease_expires_at=NULL
                     WHERE id=?
                    """,
                    (new_state.value, now + delay, now, error[:2000], job_id),
                )
            return new_state

        final = JobState.TIMED_OUT if timed_out else JobState.FAILED
        self._dead_letter(job, error=error, final_state=final)
        return final

    def _dead_letter(self, job: Job, *, error: str, final_state: JobState) -> None:
        """Mark terminal-failed and copy into the dead-letter table.

        The job row is kept as well as copied so history and dedup behave
        consistently; the dead-letter table exists to make failures easy to
        find and replay without scanning the whole jobs table.
        """
        now = time.time()
        job.state = JobState.FAILED
        job.last_error = error[:2000]
        job.finished_at = now
        with self._conn as conn:
            conn.execute(
                """
                UPDATE jobs
                   SET state=?, finished_at=?, updated_at=?, last_error=?,
                       assigned_worker=NULL, lease_expires_at=NULL
                 WHERE id=?
                """,
                (JobState.FAILED.value, now, now, job.last_error, job.id),
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO dead_letters
                    (id, target, failed_at, attempts, last_error, final_state, job)
                VALUES (?,?,?,?,?,?,?)
                """,
                (
                    job.id,
                    job.target,
                    now,
                    job.attempts,
                    job.last_error,
                    final_state.value,
                    json.dumps(job.to_dict()),
                ),
            )

    # -- operator controls ----------------------------------------------------

    def cancel(self, job_id: str) -> bool:
        """Cancel a job. A running job stops at its next heartbeat."""
        return self._set_state(job_id, JobState.CANCELLED, finish=True)

    def pause(self, job_id: str) -> bool:
        return self._set_state(job_id, JobState.PAUSED)

    def resume(self, job_id: str) -> bool:
        now = time.time()
        with self._conn as conn:
            cursor = conn.execute(
                "UPDATE jobs SET state=?, available_at=?, updated_at=? WHERE id=? AND state=?",
                (JobState.QUEUED.value, now, now, job_id, JobState.PAUSED.value),
            )
        return cursor.rowcount > 0

    def _set_state(self, job_id: str, state: JobState, *, finish: bool = False) -> bool:
        now = time.time()
        with self._conn as conn:
            cursor = conn.execute(
                """
                UPDATE jobs
                   SET state=?, updated_at=?, finished_at=?, lease_expires_at=NULL
                 WHERE id=? AND state NOT IN (?, ?, ?)
                """,
                (
                    state.value,
                    now,
                    now if finish else None,
                    job_id,
                    JobState.COMPLETED.value,
                    JobState.FAILED.value,
                    JobState.CANCELLED.value,
                ),
            )
        return cursor.rowcount > 0

    # -- maintenance ----------------------------------------------------------

    def promote_due(self) -> int:
        """Move delayed jobs whose time has come into the claimable pool."""
        now = time.time()
        with self._conn as conn:
            cursor = conn.execute(
                "UPDATE jobs SET state=?, updated_at=? WHERE state=? AND available_at<=?",
                (JobState.QUEUED.value, now, JobState.PENDING.value, now),
            )
        return cursor.rowcount

    def expire_stale(self) -> int:
        """Fail jobs that outlived their expiry without ever running."""
        now = time.time()
        with self._conn as conn:
            cursor = conn.execute(
                f"""
                UPDATE jobs
                   SET state=?, finished_at=?, updated_at=?,
                       last_error='expired before execution'
                 WHERE expires_at IS NOT NULL AND expires_at<=?
                   AND state IN ({_ACTIVE_SQL_LIST})
                """,
                (JobState.FAILED.value, now, now, now),
            )
        return cursor.rowcount

    def reclaim_lost(self) -> list[Job]:
        """Return jobs whose worker went silent to the claimable pool.

        This is the mechanism behind "detect offline workers, reassign
        unfinished jobs". It is driven purely by lease expiry, so it works
        whether the worker crashed, was killed, or was partitioned away.
        """
        now = time.time()
        conn = self._conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            rows = conn.execute(
                """
                SELECT * FROM jobs
                 WHERE state=? AND lease_expires_at IS NOT NULL AND lease_expires_at<=?
                """,
                (JobState.RUNNING.value, now),
            ).fetchall()

            reclaimed: list[Job] = []
            for row in rows:
                job = Job.from_row(row)
                if job.can_retry:
                    conn.execute(
                        """
                        UPDATE jobs
                           SET state=?, assigned_worker=NULL, lease_expires_at=NULL,
                               updated_at=?, available_at=?,
                               last_error='worker lease expired'
                         WHERE id=?
                        """,
                        (JobState.LOST.value, now, now, job.id),
                    )
                    job.state = JobState.LOST
                else:
                    conn.execute(
                        """
                        UPDATE jobs
                           SET state=?, assigned_worker=NULL, lease_expires_at=NULL,
                               updated_at=?, finished_at=?,
                               last_error='worker lease expired; retries exhausted'
                         WHERE id=?
                        """,
                        (JobState.FAILED.value, now, now, job.id),
                    )
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO dead_letters
                            (id, target, failed_at, attempts, last_error, final_state, job)
                        VALUES (?,?,?,?,?,?,?)
                        """,
                        (
                            job.id,
                            job.target,
                            now,
                            job.attempts,
                            "worker lease expired; retries exhausted",
                            JobState.LOST.value,
                            json.dumps(job.to_dict()),
                        ),
                    )
                    job.state = JobState.FAILED
                reclaimed.append(job)
            conn.commit()
        except Exception:
            conn.rollback()
            raise

        if reclaimed:
            LOG.warning("reclaimed %d job(s) from expired leases", len(reclaimed))
        return reclaimed

    def _expire_lease_for_test(self, job_id: str) -> None:
        """Force a lease to lapse immediately.

        Simulating a dead worker otherwise means sleeping out the whole
        lease period, which would make the suite unusably slow. Kept on
        the class so the SQL lives next to the schema it depends on.
        """
        with self._conn as conn:
            conn.execute(
                "UPDATE jobs SET lease_expires_at=? WHERE id=?",
                (time.time() - 1, job_id),
            )

    def purge(self, *, older_than_seconds: float = 30 * 86400) -> int:
        """Delete terminal jobs older than the retention window."""
        cutoff = time.time() - older_than_seconds
        with self._conn as conn:
            cursor = conn.execute(
                """
                DELETE FROM jobs
                 WHERE state IN (?, ?, ?)
                   AND COALESCE(finished_at, updated_at) < ?
                """,
                (
                    JobState.COMPLETED.value,
                    JobState.FAILED.value,
                    JobState.CANCELLED.value,
                    cutoff,
                ),
            )
            conn.execute("DELETE FROM dead_letters WHERE failed_at < ?", (cutoff,))
        return cursor.rowcount

    # -- reading --------------------------------------------------------------

    def get(self, job_id: str) -> Job | None:
        row = self._conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return Job.from_row(row) if row else None

    def list_jobs(
        self,
        *,
        state: JobState | str | None = None,
        target: str = "",
        limit: int = 100,
    ) -> list[Job]:
        clauses: list[str] = []
        params: list[Any] = []
        if state is not None:
            clauses.append("state=?")
            params.append(state.value if isinstance(state, JobState) else str(state))
        if target:
            clauses.append("target=?")
            params.append(target)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(int(limit))
        rows = self._conn.execute(
            f"SELECT * FROM jobs {where} ORDER BY priority DESC, created_at ASC LIMIT ?",
            params,
        ).fetchall()
        return [Job.from_row(row) for row in rows]

    def dead_letters(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM dead_letters ORDER BY failed_at DESC LIMIT ?", (int(limit),)
        ).fetchall()
        return [
            {
                "id": row["id"],
                "target": row["target"],
                "failed_at": row["failed_at"],
                "attempts": row["attempts"],
                "last_error": row["last_error"],
                "final_state": row["final_state"],
            }
            for row in rows
        ]

    def replay(self, job_id: str) -> Job | None:
        """Re-enqueue a dead-lettered job after the underlying fault is fixed."""
        row = self._conn.execute("SELECT job FROM dead_letters WHERE id=?", (job_id,)).fetchone()
        if row is None:
            return None
        original = json.loads(row["job"])
        with self._conn as conn:
            conn.execute("DELETE FROM dead_letters WHERE id=?", (job_id,))
            conn.execute("DELETE FROM jobs WHERE id=?", (job_id,))
        return self.enqueue(
            original["target"],
            priority=original.get("priority", int(JobPriority.NORMAL)),
            max_attempts=original.get("max_attempts", DEFAULT_MAX_ATTEMPTS),
            payload=original.get("payload") or {},
        )

    def stats(self) -> QueueStats:
        rows = self._conn.execute("SELECT state, COUNT(*) AS n FROM jobs GROUP BY state").fetchall()
        by_state = {row["state"]: row["n"] for row in rows}
        dead = self._conn.execute("SELECT COUNT(*) AS n FROM dead_letters").fetchone()["n"]
        oldest = self._conn.execute(
            "SELECT MIN(created_at) AS t FROM jobs WHERE state=?", (JobState.QUEUED.value,)
        ).fetchone()["t"]
        return QueueStats(
            by_state=by_state,
            total=sum(by_state.values()),
            dead_letters=dead,
            oldest_queued_age=(time.time() - oldest) if oldest else 0.0,
        )
