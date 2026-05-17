"""JobRegistry: queue cap, TTL eviction, error sanitization, backend pluggability."""

from __future__ import annotations

import threading
import time

import pytest

from orchestrator.server.jobs import (
    InProcessBackend,
    JobRegistry,
    JobRejected,
    SqliteBackend,
)


def _block_until(event: threading.Event):
    def _fn(_job):
        event.wait(timeout=5)
        return {"done": True}
    return _fn


def _wait_for(predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def test_queue_cap_rejects_when_full():
    reg = JobRegistry(max_workers=1, max_pending=2, ttl_seconds=60)
    block = threading.Event()
    reg.submit(_block_until(block))
    reg.submit(_block_until(block))
    with pytest.raises(JobRejected):
        reg.submit(_block_until(block))
    block.set()
    reg.shutdown()


def test_ttl_evicts_finished_jobs():
    reg = JobRegistry(max_workers=1, max_pending=8, ttl_seconds=0.05)
    job = reg.submit(lambda _j: {"answer": 42})
    assert _wait_for(lambda: reg.get(job.id) is not None and reg.get(job.id).status == "completed")
    time.sleep(0.1)
    # Next .get() triggers eviction.
    assert reg.get(job.id) is None
    reg.shutdown()


def test_failure_records_error_id_not_traceback():
    reg = JobRegistry(max_workers=1, max_pending=4, ttl_seconds=60)

    def _boom(_j):
        raise ValueError("secret-internal-detail-do-not-leak")

    job = reg.submit(_boom)
    assert _wait_for(lambda: reg.get(job.id) is not None and reg.get(job.id).status == "failed")
    finished = reg.get(job.id)
    assert finished is not None
    assert finished.error_id is not None and len(finished.error_id) == 32
    assert finished.error_class == "ValueError"
    # No traceback string should be exposed on the Job object.
    assert not hasattr(finished, "error")
    reg.shutdown()


def test_result_stored_as_dict():
    reg = JobRegistry(max_workers=1, max_pending=4, ttl_seconds=60)
    job = reg.submit(lambda _j: {"hello": "world", "n": 5})
    assert _wait_for(lambda: reg.get(job.id) is not None and reg.get(job.id).status == "completed")
    finished = reg.get(job.id)
    assert isinstance(finished.result, dict)  # type: ignore[union-attr]
    assert finished.result == {"hello": "world", "n": 5}  # type: ignore[union-attr]
    reg.shutdown()


def test_sqlite_backend_persists_across_registry_instances(tmp_path):
    """Submit on one registry, shut it down, read from a *new* registry on the
    same file — simulates a pod restart."""
    db = tmp_path / "jobs.sqlite"

    reg1 = JobRegistry(
        max_workers=1, max_pending=4, ttl_seconds=60,
        backend=SqliteBackend(db),
    )
    job = reg1.submit(lambda _j: {"persistent": True})
    assert _wait_for(lambda: reg1.get(job.id) is not None and reg1.get(job.id).status == "completed")
    reg1.shutdown()

    # New registry, same file.
    reg2 = JobRegistry(
        max_workers=1, max_pending=4, ttl_seconds=60,
        backend=SqliteBackend(db),
    )
    recovered = reg2.get(job.id)
    assert recovered is not None
    assert recovered.status == "completed"
    assert recovered.result == {"persistent": True}
    reg2.shutdown()


def test_sqlite_backend_tracks_pending_count(tmp_path):
    db = tmp_path / "jobs.sqlite"
    reg = JobRegistry(
        max_workers=1, max_pending=2, ttl_seconds=60,
        backend=SqliteBackend(db),
    )
    block = threading.Event()
    reg.submit(_block_until(block))
    reg.submit(_block_until(block))
    with pytest.raises(JobRejected):
        reg.submit(_block_until(block))
    block.set()
    reg.shutdown()


def test_inprocess_backend_pending_count():
    backend = InProcessBackend()
    assert backend.pending_count() == 0
