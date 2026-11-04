"""Non-preemptive, completion-based dispatch with a separate full deadline."""
import time

from security.jobs import finish_force


class MonitorScheduler:
    def __init__(self, store, *, clock=time.monotonic):
        self.store = store
        self.clock = clock
        self.last_full_completion = None
        self._full_due = True
        self._full_generation = None

    @property
    def deadline(self):
        if self.last_full_completion is None:
            return self.clock()
        return self.last_full_completion + self.store.snapshot().interval

    @property
    def audit(self):
        lookup = getattr(self.store.state_repository, 'lookup_runtime', None)
        owner = getattr(lookup, 'audit', None)
        if owner is not None:
            owner.retire = self.stop
        return owner

    def _dequeue(self, *, retiring=False):
        """Caller holds config condition; reserve before removing the envelope."""
        queue = self.store.raw.get('_force_resolve_queue')
        job = queue[0] if isinstance(queue, list) and queue else self.store.raw.get('_force_resolve')
        owner = self.audit
        if job is not None and owner is not None and not owner.reserve(job, retiring=retiring):
            return None
        return self.store._dequeue_force_locked()

    def next_scan(self, *, block=True):
        # Snapshot, due check, dequeue and wait share the config condition;
        # writers notify while holding exactly this lock, preventing lost wake.
        while True:
            stale = None
            with self.store.condition:
                while not (self.store.raw.get('_monitor_stopped') or
                           getattr(self.store.raw.get('_signal_stop'), 'requested', False)):
                    snap = self.store._snapshot_locked()
                    deadline = (self.last_full_completion + snap.interval
                                if self.last_full_completion is not None else self.clock())
                    if (self._full_due or snap.generation != self._full_generation
                            or self.clock() >= deadline):
                        return snap
                    job = self._dequeue()
                    if job is not None:
                        repo = self.store.state_repository
                        leases = job.get('_target_leases')
                        if repo is not None and (leases is None or not all(
                                repo.valid(lease) for lease in leases.values())):
                            stale = job
                            break
                        snap.force_req = job
                        return snap
                    if not block:
                        return None
                    self.store.condition.wait(max(0, deadline - self.clock()))
                else:
                    return None
            finish_force(stale, 'failure')

    def completed(self, snapshot, *, accepted):
        if snapshot.force_req is None:
            self._full_due = not accepted
            if accepted:
                self.last_full_completion = self.clock()
                self._full_generation = snapshot.generation

    def active_force(self):
        """At most one dequeue per pump; never advance the full-scan clock."""
        job = None
        # A busy config writer cannot stall the full-scan pump or its stop latch.
        if not self.store.condition.acquire(blocking=False):
            return None
        try:
            try:
                if self.store.stop_requested:
                    return None
                job = self._dequeue()
                if job is None:
                    return None
                snapshot = self.store._snapshot_locked()
                snapshot.force_req = job
                return snapshot
            finally:
                self.store.condition.release()
        except Exception:
            if job is not None:
                finish_force(job, 'failure')
            raise

    def stop(self):
        # Publish before a possibly blocked source admission's config lock.
        self.store.raw['_monitor_stopped'] = True
        repo = self.store.state_repository
        lookup = getattr(repo, 'lookup_runtime', None)
        if lookup is not None:
            lookup.fence()
        owner = self.audit
        if owner is not None:
            owner.backlog = True
            owner.fence()
        if not self.store.condition.acquire(blocking=lookup is None):
            # Queue remains with its original owner. A later stop retries audit
            # retirement; no dequeue, duplicate audit, or ledger close is implied.
            return False
        pending = []
        try:
            try:
                while True:
                    job = self._dequeue(retiring=True)
                    if job is None:
                        break
                    pending.append(job)
                if owner is not None:
                    owner.backlog = bool(self.store.raw.get('_force_resolve_queue')
                                         or self.store.raw.get('_force_resolve'))
            finally:
                self.store.condition.notify_all()
        finally:
            self.store.condition.release()
            for job in pending:
                finish_force(job, 'failure')
        return owner is None or (not owner.backlog and not owner.status()['pending'])
