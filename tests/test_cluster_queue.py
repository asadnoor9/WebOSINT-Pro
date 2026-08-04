"""Tests for the durable job queue (engine.cluster).

These cover the properties the rest of the distributed platform relies on:
ordering, exactly-one dispatch, lease reclaim, retry backoff, dead-lettering
and duplicate suppression. Where a test needs time to pass it manipulates the
queue inputs rather than sleeping, so the suite stays fast.
"""

from __future__ import annotations

import threading
import time

import pytest

from engine.cluster import Job, JobPriority, JobQueue, JobState
from engine.cluster.jobs import backoff_delay


@pytest.fixture()
def queue(tmp_path):
    q = JobQueue(tmp_path / "queue.db")
    yield q
    q.close()


def test_terminal_states_are_terminal():
    for state in (JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED):
        assert state.is_terminal
    for state in (JobState.QUEUED, JobState.RUNNING, JobState.RETRYING, JobState.LOST):
        assert not state.is_terminal


def test_claimable_states():
    assert JobState.QUEUED.is_claimable
    assert JobState.RETRYING.is_claimable
    assert JobState.LOST.is_claimable
    assert not JobState.RUNNING.is_claimable
    assert not JobState.PAUSED.is_claimable


@pytest.mark.parametrize(
    ("attempt", "expected"),
    [(0, 0.0), (1, 5.0), (2, 10.0), (3, 20.0), (99, 900.0)],
)
def test_backoff_is_exponential_with_ceiling(attempt, expected):
    assert backoff_delay(attempt) == expected


def test_dedup_key_defaults_to_target():
    assert Job(target="example.com").dedup_key == "example.com"


def test_enqueue_and_get_round_trip(queue):
    job = queue.enqueue("example.com", payload={"profile": "safe"})
    assert job is not None
    loaded = queue.get(job.id)
    assert loaded is not None
    assert loaded.target == "example.com"
    assert loaded.payload == {"profile": "safe"}
    assert loaded.state is JobState.QUEUED


def test_duplicate_target_is_suppressed(queue):
    assert queue.enqueue("example.com") is not None
    assert queue.enqueue("example.com") is None


def test_duplicate_allowed_once_previous_completed(queue):
    first = queue.enqueue("example.com")
    claimed = queue.claim("w1")
    queue.complete(claimed[0].id, "w1")
    second = queue.enqueue("example.com")
    assert second is not None
    assert second.id != first.id


def test_explicit_dedup_key_allows_parallel_jobs_per_target(queue):
    assert queue.enqueue("example.com", dedup_key="example.com:dns") is not None
    assert queue.enqueue("example.com", dedup_key="example.com:ports") is not None


def test_enqueue_many_reports_duplicates(queue):
    accepted, duplicates = queue.enqueue_many(["a.com", "b.com", "a.com"])
    assert len(accepted) == 2
    assert duplicates == 1


def test_claim_respects_priority(queue):
    queue.enqueue("low.com", priority=JobPriority.LOW)
    queue.enqueue("urgent.com", priority=JobPriority.URGENT)
    queue.enqueue("normal.com", priority=JobPriority.NORMAL)
    order = [job.target for job in queue.claim("w1", count=3)]
    assert order == ["urgent.com", "normal.com", "low.com"]


def test_equal_priority_is_fifo(queue):
    for name in ("first", "second", "third"):
        queue.enqueue(name + ".com")
        time.sleep(0.001)
    order = [job.target for job in queue.claim("w1", count=3)]
    assert order == ["first.com", "second.com", "third.com"]


def test_claim_marks_running_and_assigns_worker(queue):
    queue.enqueue("example.com")
    job = queue.claim("worker-a")[0]
    assert job.state is JobState.RUNNING
    assert job.assigned_worker == "worker-a"
    assert job.attempts == 1
    assert job.lease_expires_at is not None


def test_claimed_job_is_not_offered_twice(queue):
    queue.enqueue("example.com")
    assert len(queue.claim("w1")) == 1
    assert queue.claim("w2") == []


def test_concurrent_claims_never_double_dispatch(tmp_path):
    """The property everything else depends on: one job, one worker."""
    q = JobQueue(tmp_path / "queue.db")
    for i in range(50):
        q.enqueue(f"target-{i}.com")

    claimed = []
    lock = threading.Lock()

    def worker(name):
        local_q = JobQueue(tmp_path / "queue.db")
        try:
            while True:
                jobs = local_q.claim(name, count=3)
                if not jobs:
                    return
                with lock:
                    claimed.extend(job.id for job in jobs)
        finally:
            local_q.close()

    threads = [threading.Thread(target=worker, args=(f"w{i}",)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert len(claimed) == 50
    assert len(set(claimed)) == 50, "a job was dispatched to more than one worker"
    q.close()


def test_delayed_job_is_not_immediately_claimable(queue):
    queue.enqueue("later.com", delay_seconds=60)
    assert queue.claim("w1") == []


def test_delayed_job_becomes_claimable_when_due(queue):
    job = queue.enqueue("later.com", delay_seconds=60)
    with queue._conn as conn:
        conn.execute("UPDATE jobs SET available_at=? WHERE id=?", (time.time() - 1, job.id))
    assert len(queue.claim("w1")) == 1


def test_expired_job_is_failed_not_dispatched(queue):
    job = queue.enqueue("stale.com", expires_in=30)
    with queue._conn as conn:
        conn.execute("UPDATE jobs SET expires_at=? WHERE id=?", (time.time() - 1, job.id))
    assert queue.claim("w1") == []
    assert queue.get(job.id).state is JobState.FAILED


def test_complete_is_terminal(queue):
    queue.enqueue("example.com")
    job = queue.claim("w1")[0]
    assert queue.complete(job.id, "w1")
    done = queue.get(job.id)
    assert done.state is JobState.COMPLETED
    assert done.progress == 100.0
    assert done.finished_at is not None


def test_complete_from_wrong_worker_is_rejected(queue):
    queue.enqueue("example.com")
    job = queue.claim("w1")[0]
    assert queue.complete(job.id, "imposter") is False
    assert queue.get(job.id).state is JobState.RUNNING


def test_heartbeat_extends_lease_and_records_progress(queue):
    queue.enqueue("example.com")
    job = queue.claim("w1")[0]
    original_lease = job.lease_expires_at
    time.sleep(0.01)
    assert queue.heartbeat(job.id, "w1", stage="dns", progress=25.0)
    updated = queue.get(job.id)
    assert updated.stage == "dns"
    assert updated.progress == 25.0
    assert updated.lease_expires_at > original_lease


def test_heartbeat_from_stale_worker_is_rejected(queue):
    """A worker whose job was reassigned must be told to stop."""
    queue.enqueue("example.com")
    job = queue.claim("w1")[0]
    queue._expire_lease_for_test(job.id)
    queue.reclaim_lost()
    queue.claim("w2")
    assert queue.heartbeat(job.id, "w1", stage="http") is False


def test_failure_schedules_a_retry(queue):
    queue.enqueue("flaky.com")
    job = queue.claim("w1")[0]
    assert queue.fail(job.id, "w1", error="connection reset") is JobState.RETRYING
    retried = queue.get(job.id)
    assert retried.assigned_worker is None
    assert retried.available_at > time.time()
    assert "connection reset" in retried.last_error


def test_retries_are_exhausted_into_the_dead_letter_queue(queue):
    queue.enqueue("broken.com", max_attempts=2)
    job = None
    for _ in range(2):
        job = queue.claim("w1")[0]
        state = queue.fail(job.id, "w1", error="boom")
        if state is JobState.RETRYING:
            with queue._conn as conn:
                conn.execute("UPDATE jobs SET available_at=? WHERE id=?", (time.time() - 1, job.id))
    assert queue.get(job.id).state is JobState.FAILED
    letters = queue.dead_letters()
    assert len(letters) == 1
    assert letters[0]["target"] == "broken.com"


def test_dead_letter_can_be_replayed(queue):
    queue.enqueue("broken.com", max_attempts=1)
    job = queue.claim("w1")[0]
    queue.fail(job.id, "w1", error="boom")
    assert queue.dead_letters()
    replayed = queue.replay(job.id)
    assert replayed is not None
    assert replayed.target == "broken.com"
    assert replayed.state is JobState.QUEUED
    assert queue.dead_letters() == []


def test_timed_out_failure_records_final_state(queue):
    queue.enqueue("slow.com", max_attempts=1)
    job = queue.claim("w1")[0]
    result = queue.fail(job.id, "w1", error="budget exceeded", timed_out=True)
    assert result is JobState.TIMED_OUT
    assert queue.dead_letters()[0]["final_state"] == JobState.TIMED_OUT.value


def test_expired_lease_returns_job_to_the_queue(queue):
    queue.enqueue("example.com")
    job = queue.claim("w1")[0]
    queue._expire_lease_for_test(job.id)

    reclaimed = queue.reclaim_lost()
    assert [j.id for j in reclaimed] == [job.id]
    assert queue.get(job.id).state is JobState.LOST

    retaken = queue.claim("w2")
    assert retaken[0].id == job.id
    assert retaken[0].assigned_worker == "w2"


def test_reclaim_dead_letters_when_retries_exhausted(queue):
    queue.enqueue("example.com", max_attempts=1)
    job = queue.claim("w1")[0]
    queue._expire_lease_for_test(job.id)
    reclaimed = queue.reclaim_lost()
    assert reclaimed[0].state is JobState.FAILED
    assert queue.dead_letters()[0]["final_state"] == JobState.LOST.value


def test_healthy_lease_is_not_reclaimed(queue):
    queue.enqueue("example.com")
    queue.claim("w1")
    assert queue.reclaim_lost() == []


def test_pause_and_resume(queue):
    job = queue.enqueue("example.com")
    assert queue.pause(job.id)
    assert queue.claim("w1") == []
    assert queue.resume(job.id)
    assert len(queue.claim("w1")) == 1


def test_cancel_is_terminal_and_not_dispatched(queue):
    job = queue.enqueue("example.com")
    assert queue.cancel(job.id)
    assert queue.get(job.id).state is JobState.CANCELLED
    assert queue.claim("w1") == []


def test_completed_job_cannot_be_cancelled(queue):
    job = queue.enqueue("example.com")
    claimed = queue.claim("w1")[0]
    queue.complete(claimed.id, "w1")
    assert queue.cancel(job.id) is False


def test_rate_limit_caps_dispatch(tmp_path):
    q = JobQueue(tmp_path / "rl.db", max_claims_per_second=5)
    for i in range(20):
        q.enqueue(f"t{i}.com")
    first = q.claim("w1", count=20)
    assert len(first) < 20
    q.close()


def test_no_rate_limit_by_default(queue):
    for i in range(10):
        queue.enqueue(f"t{i}.com")
    assert len(queue.claim("w1", count=10)) == 10


def test_stats_counts_by_state(queue):
    queue.enqueue("a.com")
    queue.enqueue("b.com")
    queue.enqueue("c.com")
    claimed = queue.claim("w1")[0]
    queue.complete(claimed.id, "w1")

    stats = queue.stats()
    assert stats.total == 3
    assert stats.completed == 1
    assert stats.queued == 2
    assert stats.backlog == 2
    assert "by_state" in stats.to_dict()


def test_list_jobs_filters(queue):
    queue.enqueue("a.com")
    queue.enqueue("b.com")
    queue.claim("w1", count=1)
    assert len(queue.list_jobs(state=JobState.RUNNING)) == 1
    assert len(queue.list_jobs(target="b.com")) == 1


def test_purge_removes_only_old_terminal_jobs(queue):
    keep = queue.enqueue("keep.com")
    old = queue.enqueue("old.com")
    for job in queue.claim("w1", count=2):
        queue.complete(job.id, "w1")
    with queue._conn as conn:
        conn.execute("UPDATE jobs SET finished_at=? WHERE id=?", (time.time() - 40 * 86400, old.id))
    assert queue.purge(older_than_seconds=30 * 86400) == 1
    assert queue.get(old.id) is None
    assert queue.get(keep.id) is not None


def test_survives_reopen(tmp_path):
    """Durability: a job outlives the process that created it."""
    path = tmp_path / "persist.db"
    q1 = JobQueue(path)
    job = q1.enqueue("example.com", priority=JobPriority.HIGH)
    q1.close()

    q2 = JobQueue(path)
    reloaded = q2.get(job.id)
    assert reloaded is not None
    assert reloaded.target == "example.com"
    assert reloaded.priority == int(JobPriority.HIGH)
    q2.close()
