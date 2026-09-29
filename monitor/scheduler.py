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
                    job = self.store._dequeue_force_locked()
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

    def stop(self):
        pending = []
        try:
            with self.store.condition:
                self.store.raw['_monitor_stopped'] = True
                try:
                    while True:
                        job = self.store._dequeue_force_locked()
                        if job is None:
                            break
                        pending.append(job)
                finally:
                    self.store.condition.notify_all()
        finally:
            # A later failed dequeue must not abandon already removed jobs.
            # Audit outside the lock; the runner still owns running work.
            for job in pending:
                finish_force(job, 'failure')
