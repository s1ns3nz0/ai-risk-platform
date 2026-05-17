"""Cross-replica janitor: heartbeat, orphan reclaim, retry budget, lock."""

from __future__ import annotations

import json
import time

import fakeredis
import pytest

from orchestrator.server.jobs import (
    Heartbeat,
    Janitor,
    Job,
    RedisBackend,
)


@pytest.fixture
def shared_redis():
    return fakeredis.FakeServer()


def _client(server) -> RedisBackend:
    return RedisBackend(client=fakeredis.FakeRedis(server=server, decode_responses=True))


# ---------------- heartbeat ----------------


def test_heartbeat_starts_with_key_present(shared_redis):
    backend = _client(shared_redis)
    hb = Heartbeat(backend, "pod-A", interval=0.05, ttl_seconds=2)
    hb.start()
    try:
        # touch_heartbeat runs synchronously in start() before the thread spins.
        assert backend.is_replica_alive("pod-A")
        assert "pod-A" in backend.list_replicas()
    finally:
        hb.stop()


def test_heartbeat_refreshes_periodically(shared_redis):
    backend = _client(shared_redis)
    hb = Heartbeat(backend, "pod-A", interval=0.1, ttl_seconds=1)
    hb.start()
    try:
        time.sleep(0.3)  # multiple refreshes
        # Heartbeat key should still be alive.
        assert backend.is_replica_alive("pod-A")
    finally:
        hb.stop()


def test_heartbeat_stop_unregisters(shared_redis):
    backend = _client(shared_redis)
    hb = Heartbeat(backend, "pod-A", interval=1, ttl_seconds=60)
    hb.start()
    hb.stop()
    # Best-effort cleanup on graceful shutdown.
    assert "pod-A" not in backend.list_replicas()


# ---------------- janitor ----------------


def _seed_dead_replica(backend: RedisBackend, replica_id: str, descriptors: list[dict]):
    """Pretend `replica_id` died with the given items in its processing list:
    register the replica, push items, but DON'T touch the heartbeat."""
    backend.register_replica(replica_id)
    for d in descriptors:
        backend._r.lpush(backend.processing_key(replica_id), json.dumps(d))


def test_janitor_reclaims_from_dead_replica(shared_redis):
    backend = _client(shared_redis)
    backend.create(Job(id="job-1"))
    backend.create(Job(id="job-2"))
    _seed_dead_replica(backend, "dead-pod", [
        {"type": "assess", "job_id": "job-1"},
        {"type": "assess", "job_id": "job-2"},
    ])

    janitor = Janitor(backend, "sweeper", interval=999, max_attempts=3, lock_ttl_seconds=5)
    counts = janitor.sweep()

    assert counts["reclaimed"] == 2
    assert counts["failed_max_attempts"] == 0
    assert backend.queue_length() == 2
    # Dead replica scrubbed from the registry.
    assert "dead-pod" not in backend.list_replicas()
    # Items in the queue now have attempts=1.
    raw = backend._r.rpop(backend.queue_key())
    assert json.loads(raw)["attempts"] == 1


def test_janitor_skips_alive_replicas(shared_redis):
    backend = _client(shared_redis)
    # Live replica: register + heartbeat.
    backend.register_replica("alive-pod")
    backend.touch_heartbeat("alive-pod", ttl_seconds=60)
    backend._r.lpush(backend.processing_key("alive-pod"), json.dumps({"type": "x", "job_id": "j"}))

    janitor = Janitor(backend, "sweeper", max_attempts=3)
    counts = janitor.sweep()

    assert counts["reclaimed"] == 0
    # Item still in alive replica's processing list — janitor didn't touch it.
    assert backend._r.llen(backend.processing_key("alive-pod")) == 1
    assert "alive-pod" in backend.list_replicas()


def test_janitor_marks_failed_after_max_attempts(shared_redis):
    backend = _client(shared_redis)
    backend.create(Job(id="doomed"))
    # Descriptor with attempts already at max-1; janitor will push to max.
    _seed_dead_replica(backend, "dead-pod", [
        {"type": "assess", "job_id": "doomed", "attempts": 2},
    ])

    janitor = Janitor(backend, "sweeper", max_attempts=3)
    counts = janitor.sweep()

    assert counts["reclaimed"] == 0
    assert counts["failed_max_attempts"] == 1
    # Not re-queued.
    assert backend.queue_length() == 0
    # Job marked failed with a stable error class.
    finished = backend.get("doomed")
    assert finished.status == "failed"
    assert finished.error_class == "MaxRetriesExceeded"
    assert finished.error_id is not None


def test_janitor_lock_prevents_concurrent_sweeps(shared_redis):
    """When janitor A holds the lock, janitor B's sweep is a no-op."""
    backend = _client(shared_redis)
    _seed_dead_replica(backend, "dead-pod", [{"type": "x", "job_id": "j1"}])

    janitor_a = Janitor(backend, "A", max_attempts=3, lock_ttl_seconds=10)
    janitor_b = Janitor(backend, "B", max_attempts=3, lock_ttl_seconds=10)

    # Manually take the lock as A first.
    assert backend.try_acquire_lock("A", 10) is True

    counts_b = janitor_b.sweep()
    assert counts_b["skipped_locked"] == 1
    assert counts_b["reclaimed"] == 0
    # Items still stuck because no one swept.
    assert backend._r.llen(backend.processing_key("dead-pod")) == 1

    # A releases; B can now sweep.
    backend.release_lock("A")
    counts_b = janitor_b.sweep()
    assert counts_b["reclaimed"] == 1


def test_janitor_drops_malformed_descriptor(shared_redis):
    backend = _client(shared_redis)
    backend.register_replica("dead-pod")
    backend._r.lpush(backend.processing_key("dead-pod"), "not-valid-json{")
    janitor = Janitor(backend, "sweeper", max_attempts=3)
    counts = janitor.sweep()
    # Malformed entry doesn't count as reclaimed or failed; it's dropped.
    assert counts["reclaimed"] == 0
    assert counts["failed_max_attempts"] == 0
    assert backend.queue_length() == 0


def test_janitor_reclaims_unregistered_processing_list(shared_redis):
    """If a replica unregistered itself but left items in its processing list
    (graceful shutdown gone wrong), the janitor still finds and reclaims them
    by scanning processing:* keys."""
    backend = _client(shared_redis)
    backend.create(Job(id="leaked"))
    # Push without calling register_replica — replica is unknown to the set.
    backend._r.lpush(
        backend.processing_key("forgotten-pod"),
        '{"type":"x","job_id":"leaked"}',
    )
    assert "forgotten-pod" not in backend.list_replicas()

    janitor = Janitor(backend, "sweeper", max_attempts=3)
    counts = janitor.sweep()

    assert counts["reclaimed"] == 1
    assert backend.queue_length() == 1
    assert backend._r.llen(backend.processing_key("forgotten-pod")) == 0


def test_release_lock_only_when_owner(shared_redis):
    """A replica must not release another replica's lock."""
    backend = _client(shared_redis)
    assert backend.try_acquire_lock("A", 30) is True
    # B tries to release A's lock — should be a no-op.
    assert backend.release_lock("B") is False
    # A's lock still held.
    assert backend.try_acquire_lock("X", 30) is False
    # Now A releases its own lock.
    assert backend.release_lock("A") is True
