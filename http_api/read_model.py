"""Single-worker, reference-published background read models."""
import json
import threading
import time


class BackgroundReadModel:
    """One explicit-start daemon publishes immutable-by-convention dictionaries.

    ``capture(previous_token)`` runs only on the worker and returns either None
    (unchanged) or ``(token, inputs)``. None as the previous token means a forced
    capture, including cold start and hard invalidation. Tokens and published
    dictionaries must not be mutated by callers. ``build(inputs)`` is worker-only.
    The byte limit measures standard JSON encoded as UTF-8, not Python heap size.
    Reads return the published reference and a fresh small metadata dictionary;
    generated_at is Unix time in seconds, version counts successful publications.
    """

    def __init__(self, capture, build, interval=1.0, max_bytes=32 * 1024 * 1024):
        if (type(interval) not in (int, float)
                or not 0.001 <= interval <= threading.TIMEOUT_MAX):
            raise ValueError("interval must be between 0.001 and TIMEOUT_MAX seconds")
        if type(max_bytes) is not int or not 1 <= max_bytes <= 32 * 1024 * 1024:
            raise ValueError("max_bytes must be an integer from 1 through 32 MiB")
        self._capture, self._build = capture, build
        self._interval, self._max_bytes = interval, max_bytes
        self._condition = threading.Condition()
        self._thread = None
        self._stopped = False
        self._payload = None
        self._token = None
        self._generated_at = None
        self._version = 0
        self._dirty = True
        self._stale = False
        self._epoch = 0
        self._error = None

    def start(self):
        """Start at most once; stopping is terminal, including before start."""
        with self._condition:
            if self._thread is None and not self._stopped:
                self._thread = threading.Thread(target=self._worker, daemon=True)
                self._thread.start()

    def read(self):
        """Never capture, build, encode, or copy history on the calling thread."""
        with self._condition:
            ready = self._payload is not None
            return self._payload, {
                "ready": ready, "stale": self._stale, "source_version": self._token,
                "generated_at": self._generated_at, "version": self._version,
                "status": ("stopped" if self._stopped else "error" if self._error
                           else "stale" if self._stale
                           else "ready" if ready else "building"),
                "error_code": self._error,
            }

    def invalidate(self, hard=False):
        """Coalesce work; hard invalidation also revokes all older publications."""
        retired = None
        with self._condition:
            if not self._stopped:
                if hard:
                    self._epoch += 1
                    retired = self._payload
                    self._payload = self._token = self._generated_at = None
                    self._error = None
                self._dirty = True
                self._stale = self._payload is not None
                self._condition.notify_all()
        del retired  # Large payload destruction must not hold the read lock.

    def stop_admission(self):
        """Prevent new attempts and publication without pretending to cancel work."""
        with self._condition:
            self._stopped = True
            self._dirty = False
            self._condition.notify_all()

    def close(self, timeout=1):
        """Drain within one deadline; counts describe surviving worker threads."""
        deadline = time.monotonic() + max(0, timeout)
        self.stop_admission()
        with self._condition:
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(max(0, deadline - time.monotonic()))
        running = int(thread is not None and thread.is_alive())
        return {"remaining": running, "running": running, "queued": 0}

    def _worker(self):
        due = 0
        retry_at = 0
        while True:
            with self._condition:
                while not self._stopped:
                    now = time.monotonic()
                    delay = max(retry_at - now, 0 if self._dirty else due - now)
                    if delay <= 0:
                        break
                    self._condition.wait(delay)
                if self._stopped:
                    return
                previous = self._token
                epoch = self._epoch
                # Consume before capture; notifications during any work survive.
                self._dirty = False
            error = None
            captured = payload = token = inputs = None
            try:
                captured = self._capture(previous)
                if captured is not None:
                    with self._condition:
                        if self._stopped or epoch != self._epoch:
                            continue
                        self._stale = self._payload is not None
                    token, inputs = captured
                    payload = self._build(inputs)
                    if not isinstance(payload, dict):
                        raise ValueError("payload must be a dictionary")
                    if len(json.dumps(payload, allow_nan=False).encode("utf-8")) > self._max_bytes:
                        raise ValueError("payload exceeds byte limit")
            except Exception:
                error = "build_failed"
            retired = None
            with self._condition:
                if not self._stopped and epoch == self._epoch:
                    self._error = error
                    if error:
                        self._stale = self._payload is not None
                    elif captured is not None:
                        retired = self._payload
                        self._payload, self._token = payload, token
                        self._generated_at = time.time()
                        self._version += 1
                        self._stale = self._dirty
                    else:
                        self._stale = self._dirty and self._payload is not None
                due = time.monotonic() + self._interval
                retry_at = due if error else 0
            # Do not retain discarded candidates or captured history while idle.
            captured = payload = token = inputs = None
            del retired
