"""One application-owned terminal audit worker: 17 total duties, never replaced.

Reservations precede force dequeue. A blocked callback retains its reservation;
shutdown can retire the original queue incrementally without dropping envelopes.
No external callback runs under this owner's bookkeeping mutex.
"""
from collections import deque
import threading
import time


class TerminalAuditOwner:
    CAPACITY = 17

    def __init__(self):
        self.condition = threading.Condition()
        self.reservations = {}
        self.queue = deque()
        self.active = None
        self.thread = None
        self.stopping = False
        self.failed = False
        self.backlog = False
        self.retire = None

    def reserve(self, job, *, retiring=False):
        with self.condition:
            if id(job) in self.reservations:
                return True
            if (self.failed or (self.stopping and not retiring)
                    or len(self.reservations) >= self.CAPACITY):
                return False
            if self.thread is None:
                thread = threading.Thread(target=self._run, name='terminal-audit', daemon=True)
                try:
                    thread.start()
                except Exception:
                    self.failed = True
                    raise
                self.thread = thread
            self.reservations[id(job)] = job
            job['_terminal_audit_owner'] = self
            self.condition.notify_all()
            return True

    def submit(self, job, outcome):
        with self.condition:
            if job.get('_terminal_outcome') is not None:
                return
            if self.reservations.get(id(job)) is not job:
                raise RuntimeError('terminal_audit_reservation_missing')
            job['_terminal_outcome'] = outcome
            self.queue.append(job)
            self.condition.notify_all()

    def _run(self):
        from security.jobs import terminal_audit_attempt
        while True:
            # Refill only after actual callback return; never take config locks
            # while holding the audit mutex. The callback uses nonblocking admission.
            retired = self.stopping and self.retire is not None
            if retired:
                self.retire()
            with self.condition:
                if not self.queue:
                    if (self.stopping and not self.reservations and not self.backlog
                            and (retired or self.retire is None)):
                        return
                    self.condition.wait(.05)
                    continue
                job = self.queue.popleft()
                self.active = job
            try:
                terminal_audit_attempt(job, job['_terminal_outcome'])
            finally:
                with self.condition:
                    job['_terminal_audit_done'] = True
                    self.reservations.pop(id(job))
                    self.active = None
                    self.condition.notify_all()

    def fence(self):
        self.stopping = True
        with self.condition:
            for job in self.reservations.values():
                self.submit(job, 'failure')
            self.condition.notify_all()

    def status(self):
        with self.condition:
            return {'stopped': self.stopping and not self.backlog and not self.reservations
                    and (self.thread is None or not self.thread.is_alive()),
                    'active': int(self.active is not None), 'pending': len(self.reservations),
                    'queued': len(self.queue), 'backlog': self.backlog, 'start_failed': self.failed}

    def stop(self, *, join_seconds=3):
        deadline = time.monotonic() + min(3, max(0, join_seconds))
        self.fence()
        if self.retire is not None:
            self.retire()
        with self.condition:
            self.condition.notify_all()
        if self.thread is not None and self.thread is not threading.current_thread():
            self.thread.join(max(0, deadline - time.monotonic()))
        return self.status()
