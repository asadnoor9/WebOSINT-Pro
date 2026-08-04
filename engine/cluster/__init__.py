"""
Distributed coordination primitives.

This package holds everything that lets a scan run somewhere other than the
process that requested it: the durable job queue, the worker registry and the
lease bookkeeping that ties them together.

Design constraints that shaped this package:

* **No new required dependencies.** The queue is built on the ``sqlite3``
  module in the standard library. A Redis or PostgreSQL backend can be added
  later behind the same interface, but the default install must keep working
  with zero setup.
* **Durability over throughput.** Every state transition is committed before
  it is acknowledged. A power failure must never lose a job, which matters far
  more here than shaving microseconds off a claim.
* **Workers are stateless.** All authority lives in the queue. A worker holds
  nothing that cannot be reconstructed from the database, so any worker can be
  killed at any moment and its work reassigned.
"""

from engine.cluster.jobs import Job, JobPriority, JobState
from engine.cluster.queue import JobQueue, QueueStats

__all__ = ["Job", "JobPriority", "JobQueue", "JobState", "QueueStats"]
