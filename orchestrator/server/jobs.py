"""Job manager — pluggable storage so jobs survive pod restarts (or share state
across replicas via Redis).

Backends:
- InProcessBackend: RAM-only; lost on restart.
- SqliteBackend: durable across restarts; one pod (or shared PVC).
- RedisBackend: cross-replica state sharing.

Execution models:
- Local (closure-based): the replica that received the HTTP POST runs the job.
  Used by InProcess / SQLite backends. Call `submit(fn)`.
- Distributed (descriptor-based): submit pushes a typed descriptor onto Redis;
  any replica's `WorkerLoop` may pick it up. Used by Redis backend.
  Call `submit_descriptor(descriptor)`; handlers are registered at app boot.
"""

from __future__ import annotations

import json
import logging
import socket
import sqlite3
import threading
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal, Protocol

logger = logging.getLogger(__name__)

JobStatus = Literal["pending", "running", "completed", "failed"]


class JobRejected(Exception):
    """Raised when the job queue is full."""


@dataclass
class Job:
    id: str
    status: JobStatus = "pending"
    # Serialized result. Backends never store arbitrary Python objects —
    # only JSON-serializable dicts.
    result: dict[str, Any] | None = None
    error_id: str | None = None
    error_class: str | None = None
    progress: dict[str, Any] = field(default_factory=dict)
    # Epoch seconds (NOT monotonic) so timestamps survive restart.
    created_at: float = field(default_factory=time.time)
    finished_at: float | None = None


class JobBackend(Protocol):
    def create(self, job: Job) -> None: ...
    def get(self, job_id: str) -> Job | None: ...
    def update(self, job_id: str, **changes: Any) -> None: ...
    def pending_count(self) -> int: ...
    def evict_expired(self, ttl_seconds: float) -> None: ...
    def close(self) -> None: ...


# ---------------- in-process backend ----------------


class InProcessBackend:
    """RAM-only storage. Lost on process restart. Default."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, Job] = {}

    def create(self, job: Job) -> None:
        with self._lock:
            self._jobs[job.id] = job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def update(self, job_id: str, **changes: Any) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            for key, val in changes.items():
                setattr(job, key, val)

    def pending_count(self) -> int:
        with self._lock:
            return sum(1 for j in self._jobs.values() if j.status in ("pending", "running"))

    def evict_expired(self, ttl_seconds: float) -> None:
        now = time.time()
        with self._lock:
            stale = [
                jid for jid, j in self._jobs.items()
                if j.finished_at is not None and (now - j.finished_at) > ttl_seconds
            ]
            for jid in stale:
                del self._jobs[jid]

    def close(self) -> None:
        pass


# ---------------- sqlite backend ----------------


_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    result_json TEXT,
    error_id TEXT,
    error_class TEXT,
    progress_json TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL,
    finished_at REAL
);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_finished ON jobs(finished_at);
"""


class SqliteBackend:
    """SQLite-backed storage. WAL mode so multiple replicas can poll the same
    file (mounted from a PVC) without blocking each other on reads."""

    def __init__(self, db_path: str | Path) -> None:
        self._path = str(db_path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.executescript(_SCHEMA)

    def create(self, job: Job) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO jobs (id, status, progress_json, created_at, finished_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (job.id, job.status, json.dumps(job.progress), job.created_at, job.finished_at),
            )

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, status, result_json, error_id, error_class, progress_json, "
                "created_at, finished_at FROM jobs WHERE id = ?",
                (job_id,),
            ).fetchone()
        if row is None:
            return None
        return Job(
            id=row[0],
            status=row[1],
            result=json.loads(row[2]) if row[2] else None,
            error_id=row[3],
            error_class=row[4],
            progress=json.loads(row[5] or "{}"),
            created_at=row[6],
            finished_at=row[7],
        )

    def update(self, job_id: str, **changes: Any) -> None:
        column_map = {
            "status": "status",
            "result": "result_json",
            "error_id": "error_id",
            "error_class": "error_class",
            "progress": "progress_json",
            "finished_at": "finished_at",
        }
        sets: list[str] = []
        vals: list[Any] = []
        for key, val in changes.items():
            col = column_map.get(key)
            if col is None:
                continue
            if key in ("result", "progress"):
                vals.append(json.dumps(val) if val is not None else None)
            else:
                vals.append(val)
            sets.append(f"{col} = ?")
        if not sets:
            return
        vals.append(job_id)
        with self._lock:
            self._conn.execute(f"UPDATE jobs SET {', '.join(sets)} WHERE id = ?", vals)

    def pending_count(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM jobs WHERE status IN ('pending','running')"
            ).fetchone()
        return int(row[0]) if row else 0

    def evict_expired(self, ttl_seconds: float) -> None:
        cutoff = time.time() - ttl_seconds
        with self._lock:
            self._conn.execute(
                "DELETE FROM jobs WHERE finished_at IS NOT NULL AND finished_at < ?",
                (cutoff,),
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# ---------------- redis backend ----------------


_DEFAULT_PREFIX = "orchestrator"


class RedisBackend:
    """Redis-backed state. Cross-replica polling works because every replica
    reads the same keys. Pair with a `WorkerLoop` per replica for distributed
    execution.

    Keys (with default prefix `orchestrator`):
        orchestrator:job:{id}        hash — status, result, error, timestamps
        orchestrator:active          set — job ids in pending/running state
        orchestrator:queue:assess    list — pending work descriptors (JSON)
        orchestrator:processing:{rid}  list — descriptors a given replica is running
    """

    def __init__(
        self,
        url: str | None = None,
        client: Any = None,
        prefix: str = _DEFAULT_PREFIX,
        ttl_seconds: int = 3600,
    ) -> None:
        if client is None:
            if url is None:
                raise ValueError("RedisBackend needs url or client")
            import redis  # lazy
            client = redis.from_url(url, decode_responses=True)
        self._r = client
        self._prefix = prefix
        self._ttl_seconds = ttl_seconds

    # --- key helpers ---
    def _job_key(self, job_id: str) -> str:
        return f"{self._prefix}:job:{job_id}"

    def _active_set(self) -> str:
        return f"{self._prefix}:active"

    def queue_key(self) -> str:
        return f"{self._prefix}:queue:assess"

    def processing_key(self, replica_id: str) -> str:
        return f"{self._prefix}:processing:{replica_id}"

    def _heartbeat_key(self, replica_id: str) -> str:
        return f"{self._prefix}:heartbeat:{replica_id}"

    def _replicas_set(self) -> str:
        return f"{self._prefix}:replicas"

    def _janitor_lock_key(self) -> str:
        return f"{self._prefix}:janitor:lock"

    # --- (de)serialization ---
    @staticmethod
    def _to_hash(job: Job) -> dict[str, str]:
        return {
            "id": job.id,
            "status": job.status,
            "result": json.dumps(job.result) if job.result is not None else "",
            "error_id": job.error_id or "",
            "error_class": job.error_class or "",
            "progress": json.dumps(job.progress),
            "created_at": str(job.created_at),
            "finished_at": "" if job.finished_at is None else str(job.finished_at),
        }

    @staticmethod
    def _from_hash(data: dict[str, str]) -> Job:
        return Job(
            id=data["id"],
            status=data["status"],  # type: ignore[arg-type]
            result=json.loads(data["result"]) if data.get("result") else None,
            error_id=data.get("error_id") or None,
            error_class=data.get("error_class") or None,
            progress=json.loads(data.get("progress") or "{}"),
            created_at=float(data["created_at"]),
            finished_at=float(data["finished_at"]) if data.get("finished_at") else None,
        )

    # --- JobBackend protocol ---
    def create(self, job: Job) -> None:
        pipe = self._r.pipeline()
        pipe.hset(self._job_key(job.id), mapping=self._to_hash(job))
        pipe.sadd(self._active_set(), job.id)
        pipe.execute()

    def get(self, job_id: str) -> Job | None:
        data = self._r.hgetall(self._job_key(job_id))
        if not data:
            return None
        return self._from_hash(data)

    def update(self, job_id: str, **changes: Any) -> None:
        mapping: dict[str, str] = {}
        for key, val in changes.items():
            if key == "result":
                mapping["result"] = json.dumps(val) if val is not None else ""
            elif key == "progress":
                mapping["progress"] = json.dumps(val or {})
            elif val is None:
                mapping[key] = ""
            else:
                mapping[key] = str(val)
        if mapping:
            self._r.hset(self._job_key(job_id), mapping=mapping)
        new_status = changes.get("status")
        if new_status in ("completed", "failed"):
            pipe = self._r.pipeline()
            pipe.srem(self._active_set(), job_id)
            pipe.expire(self._job_key(job_id), self._ttl_seconds)
            pipe.execute()

    def pending_count(self) -> int:
        return int(self._r.scard(self._active_set()))

    def evict_expired(self, ttl_seconds: float) -> None:
        # Redis EXPIRE (set at terminal-status time) handles eviction; no-op.
        return

    def close(self) -> None:
        try:
            self._r.close()
        except Exception:
            pass

    # --- queue ops (used by submit_descriptor + WorkerLoop) ---
    def enqueue(self, descriptor: dict[str, Any]) -> None:
        self._r.lpush(self.queue_key(), json.dumps(descriptor))

    def queue_length(self) -> int:
        return int(self._r.llen(self.queue_key()))

    def reclaim_orphans(self, replica_id: str) -> int:
        """On startup, move anything stuck in this replica's processing list
        back to the queue (prior process crashed mid-job)."""
        moved = 0
        while True:
            item = self._r.rpoplpush(self.processing_key(replica_id), self.queue_key())
            if item is None:
                break
            moved += 1
        return moved

    # --- replica registry + heartbeat ---

    def register_replica(self, replica_id: str) -> None:
        self._r.sadd(self._replicas_set(), replica_id)

    def unregister_replica(self, replica_id: str) -> None:
        self._r.srem(self._replicas_set(), replica_id)
        self._r.delete(self._heartbeat_key(replica_id))

    def list_replicas(self) -> list[str]:
        members = self._r.smembers(self._replicas_set())
        return sorted(members)

    def touch_heartbeat(self, replica_id: str, ttl_seconds: int) -> None:
        self._r.set(self._heartbeat_key(replica_id), str(time.time()), ex=ttl_seconds)

    def is_replica_alive(self, replica_id: str) -> bool:
        return bool(self._r.exists(self._heartbeat_key(replica_id)))

    def scan_processing_replicas(self) -> list[str]:
        """All replica ids that currently have a processing list in Redis.

        Uses SCAN (cursor-paginated) instead of KEYS, safe under load.
        """
        pattern = f"{self._prefix}:processing:*"
        prefix_len = len(f"{self._prefix}:processing:")
        seen: set[str] = set()
        cursor = 0
        while True:
            cursor, keys = self._r.scan(cursor=cursor, match=pattern, count=100)
            for key in keys:
                seen.add(key[prefix_len:])
            if cursor == 0:
                break
        return sorted(seen)

    def drain_processing(self, replica_id: str) -> list[str]:
        """Remove and return everything in a replica's processing list.

        Used by the janitor to reclaim work from a dead pod. Items are popped
        from the *right* (FIFO order matching how the worker pushed them via
        BRPOPLPUSH, which puts items on the left).
        """
        items: list[str] = []
        while True:
            item = self._r.rpop(self.processing_key(replica_id))
            if item is None:
                break
            items.append(item)
        return items

    def lpush_queue(self, raw: str) -> None:
        self._r.lpush(self.queue_key(), raw)

    # --- distributed lock (best-effort, SETNX EX) ---

    def try_acquire_lock(self, owner: str, ttl_seconds: int) -> bool:
        return bool(self._r.set(self._janitor_lock_key(), owner, nx=True, ex=ttl_seconds))

    def release_lock(self, owner: str) -> bool:
        """Release only if we still own the lock.

        Uses WATCH/MULTI/EXEC for portability (fakeredis doesn't ship Lua by
        default). The watched key prevents another client from changing the
        lock between the GET and the DEL.
        """
        key = self._janitor_lock_key()
        with self._r.pipeline() as pipe:
            try:
                pipe.watch(key)
                current = pipe.get(key)
                if current != owner:
                    pipe.unwatch()
                    return False
                pipe.multi()
                pipe.delete(key)
                pipe.execute()
                return True
            except Exception:
                return False


# ---------------- registry ----------------


class JobRegistry:
    """Thread-pool registry with bounded queue, TTL eviction, pluggable storage."""

    def __init__(
        self,
        max_workers: int = 2,
        max_pending: int = 32,
        ttl_seconds: float = 3600,
        backend: JobBackend | None = None,
    ) -> None:
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="assess")
        self._backend: JobBackend = backend or InProcessBackend()
        self._max_pending = max_pending
        self._ttl_seconds = ttl_seconds

    @property
    def backend(self) -> JobBackend:
        return self._backend

    # --- local (closure) submission path ---
    def submit(self, fn: Callable[[Job], Any]) -> Job:
        self._backend.evict_expired(self._ttl_seconds)
        if self._backend.pending_count() >= self._max_pending:
            raise JobRejected(f"queue full ({self._max_pending})")
        job = Job(id=uuid.uuid4().hex)
        self._backend.create(job)

        def _runner() -> None:
            self._backend.update(job.id, status="running")
            try:
                result = fn(job)
                payload = result.to_dict() if hasattr(result, "to_dict") else result
                self._backend.update(
                    job.id, status="completed", result=payload, finished_at=time.time(),
                )
            except Exception as exc:
                error_id = uuid.uuid4().hex
                logger.error(
                    "job %s failed error_id=%s: %s\n%s",
                    job.id, error_id, exc, traceback.format_exc(),
                )
                self._backend.update(
                    job.id, status="failed", error_id=error_id,
                    error_class=type(exc).__name__, finished_at=time.time(),
                )

        self._executor.submit(_runner)
        return self._backend.get(job.id) or job

    # --- distributed (descriptor) submission path ---
    def submit_descriptor(self, descriptor: dict[str, Any]) -> Job:
        """Push a descriptor onto the shared queue. Any replica's WorkerLoop
        may execute it. Requires a backend that implements `enqueue`."""
        if not hasattr(self._backend, "enqueue"):
            raise RuntimeError("backend does not support distributed execution")
        if self._backend.pending_count() >= self._max_pending:
            raise JobRejected(f"queue full ({self._max_pending})")
        job_id = uuid.uuid4().hex
        job = Job(id=job_id)
        self._backend.create(job)
        descriptor = {**descriptor, "job_id": job_id}
        self._backend.enqueue(descriptor)  # type: ignore[attr-defined]
        return self._backend.get(job_id) or job

    def get(self, job_id: str) -> Job | None:
        self._backend.evict_expired(self._ttl_seconds)
        return self._backend.get(job_id)

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)
        self._backend.close()


# ---------------- distributed worker loop ----------------


Handler = Callable[[dict[str, Any]], Any]


class Heartbeat:
    """Refreshes this replica's heartbeat key on a ticker. When the replica
    dies (crash, SIGKILL), the key expires and the Janitor on another
    replica reclaims its in-flight work."""

    def __init__(
        self,
        backend: RedisBackend,
        replica_id: str,
        interval: float = 20.0,
        ttl_seconds: int = 60,
    ) -> None:
        self._backend = backend
        self._replica_id = replica_id
        self._interval = interval
        self._ttl_seconds = ttl_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._backend.register_replica(self._replica_id)
        self._backend.touch_heartbeat(self._replica_id, self._ttl_seconds)
        self._thread = threading.Thread(
            target=self._loop, name=f"heartbeat-{self._replica_id}", daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 1.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        # Best-effort de-registration. If the process is being killed this
        # may not run, which is fine — the janitor handles that case.
        try:
            self._backend.unregister_replica(self._replica_id)
        except Exception:
            pass

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._backend.touch_heartbeat(self._replica_id, self._ttl_seconds)
            except Exception as exc:
                logger.warning("heartbeat refresh failed for %s: %s", self._replica_id, exc)
            self._stop.wait(self._interval)


class Janitor:
    """Periodically reclaims orphaned work from dead replicas.

    Detection: a replica is "dead" when its heartbeat key has expired but it's
    still listed in the replicas set. Reclaim: drain its processing list,
    bump each descriptor's `attempts`, push back onto the queue, or mark the
    job failed if attempts >= max.

    Coordination: SET NX EX lock so only one replica sweeps at a time.
    Re-execution semantics are at-least-once — handlers should be idempotent.
    """

    def __init__(
        self,
        backend: RedisBackend,
        replica_id: str,
        interval: float = 30.0,
        max_attempts: int = 3,
        lock_ttl_seconds: int = 30,
    ) -> None:
        self._backend = backend
        self._replica_id = replica_id
        self._interval = interval
        self._max_attempts = max_attempts
        self._lock_ttl = lock_ttl_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._loop, name=f"janitor-{self._replica_id}", daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 1.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.sweep()
            except Exception as exc:
                logger.exception("janitor sweep failed: %s", exc)
            self._stop.wait(self._interval)

    def sweep(self) -> dict[str, int]:
        """Run one sweep cycle. Returns counts for telemetry/tests."""
        result = {"reclaimed": 0, "failed_max_attempts": 0, "skipped_locked": 0}

        if not self._backend.try_acquire_lock(self._replica_id, self._lock_ttl):
            result["skipped_locked"] = 1
            return result

        try:
            # Look at every replica that has a processing list, not just
            # whoever's still in the replicas set. This catches both ungraceful
            # crashes (heartbeat expired, replica still in set) and odd cases
            # where a replica unregistered before draining its list.
            candidates = set(self._backend.list_replicas())
            candidates.update(self._backend.scan_processing_replicas())
            for rid in sorted(candidates):
                if self._backend.is_replica_alive(rid):
                    continue
                items = self._backend.drain_processing(rid)
                if not items:
                    # No work to reclaim — just scrub the registry.
                    self._backend.unregister_replica(rid)
                    continue
                logger.warning(
                    "janitor: replica %s has no heartbeat, reclaiming %d items",
                    rid, len(items),
                )
                for raw in items:
                    handled = self._handle_orphan(raw)
                    if handled == "requeued":
                        result["reclaimed"] += 1
                    elif handled == "failed":
                        result["failed_max_attempts"] += 1
                self._backend.unregister_replica(rid)
        finally:
            self._backend.release_lock(self._replica_id)

        return result

    def _handle_orphan(self, raw: str) -> str:
        try:
            descriptor = json.loads(raw)
        except json.JSONDecodeError:
            logger.error("janitor: dropping malformed descriptor %r", raw[:200])
            return "dropped"

        descriptor["attempts"] = int(descriptor.get("attempts", 0)) + 1
        job_id = descriptor.get("job_id")

        if descriptor["attempts"] >= self._max_attempts:
            if job_id:
                self._backend.update(
                    job_id, status="failed",
                    error_id=uuid.uuid4().hex,
                    error_class="MaxRetriesExceeded",
                    finished_at=time.time(),
                )
            logger.error(
                "janitor: job %s exceeded max attempts (%d), marked failed",
                job_id, self._max_attempts,
            )
            return "failed"

        self._backend.lpush_queue(json.dumps(descriptor))
        logger.info(
            "janitor: re-queued job %s (attempt %d/%d)",
            job_id, descriptor["attempts"], self._max_attempts,
        )
        return "requeued"


class WorkerLoop:
    """Pulls descriptors off the Redis queue and runs the matching handler.

    One instance per replica. Spawns N worker threads internally, plus an
    optional Heartbeat and Janitor.
    """

    def __init__(
        self,
        backend: RedisBackend,
        handlers: dict[str, Handler],
        replica_id: str | None = None,
        concurrency: int = 2,
        ttl_seconds: float = 3600,
        heartbeat_ttl: int = 60,
        heartbeat_interval: float | None = None,
        janitor_interval: float = 30.0,
        janitor_max_attempts: int = 3,
        enable_janitor: bool = True,
    ) -> None:
        self._backend = backend
        self._handlers = handlers
        self._replica_id = replica_id or _default_replica_id()
        self._concurrency = concurrency
        self._ttl_seconds = ttl_seconds
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        # Refresh interval must be well under TTL so the key never expires
        # between refreshes. Default: TTL/3, capped at 20s.
        if heartbeat_interval is None:
            heartbeat_interval = min(20.0, max(1.0, heartbeat_ttl / 3))
        self._heartbeat = Heartbeat(
            backend=backend,
            replica_id=self._replica_id,
            interval=heartbeat_interval,
            ttl_seconds=heartbeat_ttl,
        )
        self._janitor: Janitor | None = None
        if enable_janitor:
            self._janitor = Janitor(
                backend=backend,
                replica_id=self._replica_id,
                interval=janitor_interval,
                max_attempts=janitor_max_attempts,
            )

    @property
    def replica_id(self) -> str:
        return self._replica_id

    def start(self) -> None:
        self._heartbeat.start()
        reclaimed = self._backend.reclaim_orphans(self._replica_id)
        if reclaimed:
            logger.warning("replica %s reclaimed %d orphaned jobs", self._replica_id, reclaimed)
        for i in range(self._concurrency):
            t = threading.Thread(
                target=self._loop, name=f"worker-{self._replica_id}-{i}", daemon=True,
            )
            t.start()
            self._threads.append(t)
        if self._janitor is not None:
            self._janitor.start()

    def stop(self, timeout: float = 1.0) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=timeout)
        if self._janitor is not None:
            self._janitor.stop(timeout=timeout)
        # Best-effort: move our own in-flight work back to the queue so the
        # next replica picks it up. The janitor would eventually do this too,
        # but only after our heartbeat expires.
        try:
            self._backend.reclaim_orphans(self._replica_id)
        except Exception:
            pass
        self._heartbeat.stop(timeout=timeout)

    def _loop(self) -> None:
        q = self._backend.queue_key()
        p = self._backend.processing_key(self._replica_id)
        while not self._stop.is_set():
            try:
                # BRPOPLPUSH = atomic pop from queue + push to processing list.
                raw = self._backend._r.brpoplpush(q, p, timeout=1)  # type: ignore[attr-defined]
            except Exception as exc:
                logger.warning("worker brpoplpush failed: %s", exc)
                time.sleep(0.5)
                continue
            if raw is None:
                continue
            self._execute(raw, p)

    def _execute(self, raw: str, processing_key: str) -> None:
        try:
            descriptor = json.loads(raw)
        except json.JSONDecodeError:
            logger.error("dropping malformed descriptor: %r", raw[:200])
            self._backend._r.lrem(processing_key, 1, raw)  # type: ignore[attr-defined]
            return

        job_id = descriptor.get("job_id")
        kind = descriptor.get("type")
        handler = self._handlers.get(kind) if kind else None
        if job_id is None or handler is None:
            logger.error("descriptor missing job_id or unknown type=%s", kind)
            self._backend._r.lrem(processing_key, 1, raw)  # type: ignore[attr-defined]
            if job_id:
                self._backend.update(
                    job_id, status="failed",
                    error_id=uuid.uuid4().hex, error_class="UnknownJobType",
                    finished_at=time.time(),
                )
            return

        self._backend.update(job_id, status="running")
        try:
            result = handler(descriptor)
            payload = result.to_dict() if hasattr(result, "to_dict") else result
            self._backend.update(
                job_id, status="completed", result=payload, finished_at=time.time(),
            )
        except Exception as exc:
            error_id = uuid.uuid4().hex
            logger.error(
                "job %s failed on replica %s error_id=%s: %s\n%s",
                job_id, self._replica_id, error_id, exc, traceback.format_exc(),
            )
            self._backend.update(
                job_id, status="failed", error_id=error_id,
                error_class=type(exc).__name__, finished_at=time.time(),
            )
        finally:
            # Remove the descriptor from the processing list.
            self._backend._r.lrem(processing_key, 1, raw)  # type: ignore[attr-defined]


def _default_replica_id() -> str:
    return socket.gethostname() or uuid.uuid4().hex[:8]
