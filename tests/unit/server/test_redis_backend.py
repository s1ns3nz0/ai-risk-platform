"""RedisBackend state sharing + cross-replica work pickup."""

from __future__ import annotations

import time

import fakeredis
import pytest

from orchestrator.server.jobs import (
    Job,
    JobRegistry,
    JobRejected,
    RedisBackend,
    WorkerLoop,
)


def _wait_for(predicate, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


@pytest.fixture
def shared_redis():
    """A single in-memory Redis server shared between simulated replicas."""
    server = fakeredis.FakeServer()
    return server


def _client(server) -> RedisBackend:
    return RedisBackend(client=fakeredis.FakeRedis(server=server, decode_responses=True))


def test_create_get_roundtrip(shared_redis):
    backend = _client(shared_redis)
    job = Job(id="abc123")
    backend.create(job)
    fetched = backend.get("abc123")
    assert fetched is not None
    assert fetched.id == "abc123"
    assert fetched.status == "pending"


def test_state_visible_across_clients(shared_redis):
    """Replica A writes; replica B reads."""
    pod_a = _client(shared_redis)
    pod_b = _client(shared_redis)

    job = Job(id="cross-replica")
    pod_a.create(job)
    pod_a.update("cross-replica", status="completed", result={"score": 9.5}, finished_at=time.time())

    fetched = pod_b.get("cross-replica")
    assert fetched is not None
    assert fetched.status == "completed"
    assert fetched.result == {"score": 9.5}


def test_pending_count_tracks_active_set(shared_redis):
    backend = _client(shared_redis)
    backend.create(Job(id="j1"))
    backend.create(Job(id="j2"))
    assert backend.pending_count() == 2
    backend.update("j1", status="completed", finished_at=time.time())
    assert backend.pending_count() == 1


def test_terminal_status_sets_expiry(shared_redis):
    backend = _client(shared_redis)
    backend.create(Job(id="ttl-test"))
    # No TTL on a pending job.
    raw = backend._r.ttl(backend._job_key("ttl-test"))
    assert raw == -1  # -1 = no TTL set
    backend.update("ttl-test", status="completed", finished_at=time.time())
    ttl = backend._r.ttl(backend._job_key("ttl-test"))
    assert ttl > 0


def test_queue_cap_via_active_set(shared_redis):
    backend = _client(shared_redis)
    reg = JobRegistry(max_pending=2, ttl_seconds=60, backend=backend)
    reg.submit_descriptor({"type": "import-assess", "product": "x"})
    reg.submit_descriptor({"type": "import-assess", "product": "x"})
    with pytest.raises(JobRejected):
        reg.submit_descriptor({"type": "import-assess", "product": "x"})
    reg.shutdown()


def test_worker_loop_executes_descriptor(shared_redis):
    """A WorkerLoop picks up a descriptor pushed by a different client and
    executes the registered handler."""
    pod_a = _client(shared_redis)
    pod_b = _client(shared_redis)
    reg = JobRegistry(max_pending=8, ttl_seconds=60, backend=pod_a)

    seen: list[dict] = []

    def handler(descriptor: dict) -> dict:
        seen.append(descriptor)
        return {"echo": descriptor["product"]}

    worker = WorkerLoop(
        backend=pod_b,
        handlers={"test-job": handler},
        replica_id="pod-b",
        concurrency=1,
    )
    worker.start()
    try:
        job = reg.submit_descriptor({"type": "test-job", "product": "payment-api"})
        assert _wait_for(lambda: reg.get(job.id) and reg.get(job.id).status == "completed")
        result = reg.get(job.id)
        assert result.result == {"echo": "payment-api"}
        assert len(seen) == 1
    finally:
        worker.stop()
        reg.shutdown()


def test_two_replicas_share_one_queue(shared_redis):
    """Two WorkerLoops on the same Redis split the load fairly enough that
    each picks up at least one job from a batch."""
    backend_submit = _client(shared_redis)
    backend_a = _client(shared_redis)
    backend_b = _client(shared_redis)

    reg = JobRegistry(max_pending=64, ttl_seconds=60, backend=backend_submit)

    executed_by: dict[str, str] = {}
    lock = __import__("threading").Lock()

    def make_handler(replica: str):
        def _h(descriptor: dict) -> dict:
            time.sleep(0.05)  # Slow enough that both replicas get a turn
            with lock:
                executed_by[descriptor["job_id"]] = replica
            return {"by": replica}
        return _h

    worker_a = WorkerLoop(backend_a, {"job": make_handler("A")}, replica_id="A", concurrency=1)
    worker_b = WorkerLoop(backend_b, {"job": make_handler("B")}, replica_id="B", concurrency=1)
    worker_a.start()
    worker_b.start()

    try:
        job_ids = [reg.submit_descriptor({"type": "job"}).id for _ in range(10)]
        assert _wait_for(
            lambda: all(reg.get(jid) and reg.get(jid).status == "completed" for jid in job_ids),
            timeout=10,
        )
        replicas = set(executed_by.values())
        assert replicas == {"A", "B"}, f"Both replicas should have run jobs, got {replicas}"
    finally:
        worker_a.stop()
        worker_b.stop()
        reg.shutdown()


def test_worker_marks_job_failed_on_handler_exception(shared_redis):
    backend = _client(shared_redis)
    reg = JobRegistry(max_pending=8, ttl_seconds=60, backend=backend)

    def boom(_d: dict) -> dict:
        raise RuntimeError("handler-failure-detail")

    worker = WorkerLoop(backend, {"boom": boom}, replica_id="pod-x", concurrency=1)
    worker.start()
    try:
        job = reg.submit_descriptor({"type": "boom"})
        assert _wait_for(lambda: reg.get(job.id) and reg.get(job.id).status == "failed")
        finished = reg.get(job.id)
        assert finished.error_class == "RuntimeError"
        assert finished.error_id and len(finished.error_id) == 32
        # Handler error message not leaked.
        assert finished.result is None
    finally:
        worker.stop()
        reg.shutdown()


def test_unknown_descriptor_type_marks_failed(shared_redis):
    backend = _client(shared_redis)
    reg = JobRegistry(max_pending=8, ttl_seconds=60, backend=backend)
    worker = WorkerLoop(backend, {"known": lambda d: {}}, replica_id="pod-x", concurrency=1)
    worker.start()
    try:
        job = reg.submit_descriptor({"type": "made-up-type"})
        assert _wait_for(lambda: reg.get(job.id) and reg.get(job.id).status == "failed")
        finished = reg.get(job.id)
        assert finished.error_class == "UnknownJobType"
    finally:
        worker.stop()
        reg.shutdown()


def test_reclaim_orphans(shared_redis):
    """Pre-populate the processing list (simulating a prior crash); reclaim
    moves descriptors back to the queue."""
    backend = _client(shared_redis)
    backend._r.lpush(backend.processing_key("pod-x"), '{"type":"job","job_id":"a"}', '{"type":"job","job_id":"b"}')
    moved = backend.reclaim_orphans("pod-x")
    assert moved == 2
    assert backend.queue_length() == 2
