"""Application-owned fixed cooperative lookup workers.

Timeouts fence results, never terminate Python callbacks or replace workers.
Mailbox ownership (including late work) lasts through actual callback return.
"""
from collections import deque
from contextlib import nullcontext
from dataclasses import dataclass, field
import threading
import time


class NotDispatched(Exception):
    """Unavailable capacity/authority is not query evidence."""


@dataclass(eq=False)
class TargetWork:
    kwargs: dict
    deadline: float
    scan: object = None
    settled: bool = False
    done: bool = False
    result: list = field(default_factory=list)
    error: object = None


@dataclass(eq=False)
class ProviderWork:
    domain: object
    server: str
    registry: object
    lease: object
    deadline: float
    started: bool = False
    done: bool = False
    consumed: bool = False
    cancelled: bool = False
    value: object = None
    error: object = None

    @property
    def key(self):
        return self.lease.target, self.server

    dht_token: object = None


def provider_budget(domain):
    kind = str(domain.type).upper()
    if kind == 'DHT':
        return float((domain.dht_options or {}).get('duration', 30)) + 5
    return {'ENS': 30, 'SNS': 20, 'RPC': 35}.get(kind, 5)


class LookupRuntime:
    def __init__(self, repository, *, clock=time.monotonic, scheduler=None):
        self.repository = repository
        self.clock = clock
        self.scheduler = scheduler
        from .terminal_audit import TerminalAuditOwner
        self.audit = TerminalAuditOwner()
        self._pump = threading.Lock()
        self._entitlement = 0
        self.condition = threading.Condition()
        self.stopping = False
        self.targets = deque()
        self.active_targets = []
        self.controllers = []
        self.providers = []
        self.provider_queue = deque()
        self.active_providers = []
        self.singleflight = set()
        self.max_workers = 1
        self._last_provider_target = None
        with repository._coord:
            if repository.lookup_runtime is not None:
                raise RuntimeError('lookup_owner_already_attached')
            repository.lookup_runtime = self

    def start(self, max_workers=8):
        try:
            with self.condition:
                if self.stopping:
                    return
                self.max_workers = max(1, min(64, int(max_workers)))
                for index in range(len(self.providers), self.max_workers):
                    thread = threading.Thread(target=self._provider,
                                              name=f'lookup-provider-{index}', daemon=True)
                    thread.start()
                    self.providers.append(thread)
                for index in range(len(self.controllers), 4):
                    thread = threading.Thread(target=self._controller,
                                              name=f'lookup-target-{index}', daemon=True)
                    thread.start()
                    self.controllers.append(thread)
                self.condition.notify_all()

        except Exception:
            self.stop()
            raise

    def _take_provider(self):
        if len(self.active_providers) >= self.max_workers:
            return None
        counts = {}
        for item in self.active_providers:
            counts[item.lease.name] = counts.get(item.lease.name, 0) + 1
        dht_active = sum(str(item.domain.type).upper() == 'DHT' for item in self.active_providers)
        choices = [item for item in self.provider_queue if counts.get(item.lease.name, 0) < 2
                   and (str(item.domain.type).upper() != 'DHT' or dht_active < 2)]
        if not choices:
            return None
        work = min(choices, key=lambda item: (counts.get(item.lease.name, 0),
                                              item.lease.name == self._last_provider_target))
        self.provider_queue.remove(work)
        work.started = True
        work.deadline = min(work.deadline, self.clock() + provider_budget(work.domain))
        self.active_providers.append(work)
        self._last_provider_target = work.lease.name
        self.condition.notify_all()
        return work

    def cancelled(self, work):
        return (self.stopping or work.cancelled or self.clock() >= work.deadline
                or not self.repository.valid(work.lease)
                or self.repository.delivery_runtime.stopping)

    def _provider(self):
        from . import engine
        from .collect import lookup_scope
        from decoder_registry import use_registry
        while True:
            with self.condition:
                work = None
                while work is None and not self.stopping:
                    work = self._take_provider()
                    if work is None:
                        self.condition.wait(.05)
                if work is None:
                    return
            self.repository.lookup_provider_progress(work.lease, starting=True)
            try:
                if self.cancelled(work):
                    raise NotDispatched()
                if str(work.domain.type).upper() == 'DHT':
                    candidate = self.repository.observation_candidate(work.lease)
                    if candidate is None or self.cancelled(work):
                        raise NotDispatched()
                    version, _, history, _ = candidate
                    work.dht_token = self.repository.begin_dht(work.lease, version, history)
                    del candidate, history
                    if work.dht_token is None:
                        raise NotDispatched()
                    if self.cancelled(work):
                        # Positive acknowledgment: collection has not begun.
                        self.repository.delivery_runtime.store.abort_dht(work.lease.name, work.dht_token)
                        raise NotDispatched()
                with (use_registry(work.registry) if work.registry is not None else nullcontext()), lookup_scope(
                        lambda: self.cancelled(work), lambda: max(0, work.deadline - self.clock())):
                    if str(work.domain.type).upper() == 'DHT':
                        work.value = engine.collect_snapshot(work.domain, work.server,
                                                            cancelled=lambda: self.cancelled(work))
                    else:
                        work.value = engine.collect_snapshot(work.domain, work.server)
            except Exception as error:
                work.error = error
            finally:
                self.repository.lookup_provider_progress(work.lease, starting=False)
                with self.condition:
                    work.done = True
                    self.condition.notify_all()
                    while not work.consumed and not self.stopping:
                        self.condition.wait(.05)
                # Exact-token cleanup is outside the owner mutex and remains
                # counted until acknowledged evidence has actually been retired.
                try:
                    observation = getattr(work.value, 'dht_observation', None) or {}
                    if (work.dht_token is not None and observation.get('status') == 'cancelled'
                            and observation.get('coverage', {}).get('termination') == 'cancelled'
                            and not observation.get('records') and work.value.snapshot is None):
                        self.repository.delivery_runtime.store.abort_dht(work.lease.name, work.dht_token)
                except Exception:
                    # Keep the durable pending fence; cleanup failure is not
                    # permission to clear or adopt another attempt's token.
                    import logging
                    logging.getLogger(__name__).warning('DHT cancellation cleanup incomplete')
                finally:
                    with self.condition:
                        self.active_providers.remove(work)
                        self.singleflight.discard(work.key)
                        work.value = work.error = None
                        self.condition.notify_all()

    def _consume(self, work):
        with self.condition:
            work.consumed = True
            if work in self.provider_queue:
                self.provider_queue.remove(work)
                self.singleflight.discard(work.key)
            self.condition.notify_all()

    def collect(self, domain, servers, registry, lease, deadline):
        pending = []
        iterator = iter(servers)
        exhausted = False
        try:
            while pending or not exhausted:
                ready = []
                with self.condition:
                    changed = False
                    revoked = (self.stopping or self.repository.delivery_runtime.stopping
                               or not self.repository.valid(lease))
                    expired = self.clock() >= deadline
                    if (revoked or expired) and not exhausted:
                        exhausted = True
                        # One incomplete marker covers the unvisited provider cursor.
                        ready.append(('', None, NotDispatched(), None))
                    while not exhausted and len(pending) < 2 and len(self.provider_queue) < 16:
                        try:
                            server = str(next(iterator))
                        except StopIteration:
                            exhausted = True
                            break
                        work = ProviderWork(domain, server, registry, lease, deadline)
                        if work.key in self.singleflight:
                            ready.append((server, None, NotDispatched(), None))
                            # Bound one controller's cursor work per iteration.
                            break
                        pending.append(work)
                        self.singleflight.add(work.key)
                        self.provider_queue.append(work)
                        changed = True
                    for work in list(pending):
                        late = self.clock() >= work.deadline
                        if revoked or late:
                            if not work.cancelled:
                                changed = True
                            work.cancelled = True
                            error = TimeoutError() if late and work.started and not revoked else NotDispatched()
                            ready.append((work.server, None, error, work))
                        elif work.done:
                            ready.append((work.server, work.value, work.error, work))
                    if changed:
                        self.condition.notify_all()
                    if not ready:
                        self.condition.wait(.05)
                for server, value, error, work in ready:
                    try:
                        yield server, value, error, work
                    finally:
                        if work is not None:
                            self._consume(work)
                            # Keep unvisited ready mailboxes owned on early close.
                            pending.remove(work)
        finally:
            for work in pending:
                work.cancelled = True
                self._consume(work)

    def _controller(self):
        from . import engine
        while True:
            with self.condition:
                work = None
                while work is None:
                    if self.stopping:
                        return
                    names = {item.kwargs['target_lease'].name for item in self.active_targets}
                    choices = [item for item in self.targets
                               if item.kwargs['target_lease'].name not in names]
                    want_force = self._entitlement == 3
                    work = next((item for item in choices
                                 if (item.scan.job is not None) == want_force), None)
                    if work is not None:
                        self._entitlement = (self._entitlement + 1) % 4
                    elif choices:
                        work = choices[0]
                    if work is None:
                        self.condition.wait(.05)
                self.targets.remove(work)
                self.active_targets.append(work)
                self.condition.notify_all()
            try:
                work.result = engine.run_domain_cycle(**work.kwargs, lookup_runtime=self,
                                                       target_deadline=work.deadline)
            except Exception as error:
                work.error = error
                work.kwargs['cycle_quality'].append(False)
            finally:
                with self.condition:
                    work.done = True
                    self.condition.notify_all()
                    # Completed but unconsumed controllers retain capacity.
                    if self.stopping:
                        self._settle(work, incomplete=True)
                    while work in self.active_targets and not work.settled:
                        self.condition.wait(.05)
                    if work in self.active_targets:
                        self.active_targets.remove(work)
                    self.condition.notify_all()

    def _settle(self, work, *, incomplete=False):
        if not work.settled:
            work.settled = True
            work.scan.pending -= 1
            if incomplete:
                work.kwargs['cycle_quality'].append(False)
                work.scan.invalid = True

    def run_scan(self, full):
        from .engine import OwnedScan
        if not self._pump.acquire(blocking=False):
            raise RuntimeError('lookup_scan_already_running')
        force = None
        try:
            self.start(full.args['max_workers'])
            while not full.exhausted or full.pending or force is not None:
                if self.repository.delivery_runtime.stopping and not self.stopping:
                    self.fence()
                # Never take the config condition under the lookup mutex.
                if (force is None and full.job is None and self.scheduler is not None
                        and not self.stopping and (not full.exhausted or full.pending)):
                    snapshot = self.scheduler.active_force()
                    if snapshot is not None:
                        args = dict(full.args, domains_raw=snapshot.domains, servers=snapshot.servers,
                            force_req=snapshot.force_req, target_leases=snapshot.target_leases,
                            registry_view=snapshot.registry_view, max_workers=snapshot.max_workers,
                            ens_rpc_url=snapshot.ens_rpc_url, sns_proxy_hosts=snapshot.sns_proxy_hosts)
                        force = OwnedScan(args, snapshot=snapshot)
                with self.condition:
                    changed = False
                    scans = [full] + ([force] if force is not None else [])
                    if self.stopping:
                        self.fence()
                    for scan in scans:
                        if self.stopping:
                            scan.invalid = scan.exhausted = True
                    # Reap bounded target mailboxes before refilling.
                    for work in list(self.active_targets):
                        expired = self.clock() >= work.deadline
                        if work.done or expired:
                            if not work.settled:
                                changed = True
                            self._settle(work, incomplete=expired or work.error is not None)
                        if work.done:
                            self.active_targets.remove(work)
                            changed = True
                    for work in list(self.targets):
                        if self.clock() >= work.deadline:
                            self._settle(work, incomplete=True)
                            self.targets.remove(work)
                            changed = True
                    # Retain lazy cursors, not an expanded scan x provider queue.
                    # Reserve four ready entries for an arriving force envelope.
                    for scan in reversed(scans):
                        limit = (4 if scan is force else 12) if force is not None else 16
                        queued = sum(item.scan is scan for item in self.targets)
                        while not scan.exhausted and len(self.targets) < 16 and queued < limit:
                            try:
                                args = next(scan.iterator)
                            except StopIteration:
                                scan.exhausted = True
                                break
                            work = TargetWork(args, self.clock() + 75, scan=scan)
                            self.targets.append(work)
                            queued += 1
                            scan.pending += 1
                            changed = True
                    if changed:
                        self.condition.notify_all()
                    self.condition.wait(.05)
                if force is not None and force.exhausted and not force.pending:
                    force.finish_force()
                    force = None
            return full.result()
        except Exception:
            self.fence()
            raise
        finally:
            if force is not None:
                from security.jobs import finish_force
                finish_force(force.job, 'failure')
            self._pump.release()

    def status(self):
        audit = self.audit.status()
        locked = self.condition.acquire(blocking=False)
        try:
            active = len(self.active_providers)
            queued = len(self.targets) + len(self.provider_queue)
            return {'stopped': locked and self.stopping and audit['stopped'] and not any(
                thread.is_alive() for thread in self.controllers + self.providers),
                'active': active, 'queued': queued,
                'overdue': sum(self.clock() >= work.deadline for work in tuple(self.active_providers)),
                'controllers': len(self.active_targets), 'target_queued': len(self.targets),
                'provider_queued': len(self.provider_queue), 'workers': len(self.providers),
                'bookkeeping_pending': not locked, 'audit': audit}
        finally:
            if locked:
                self.condition.release()

    def fence(self):
        # Revoke authority before ANY possibly blocked owner/state lock.
        self.stopping = True
        self.audit.fence()
        if not self.condition.acquire(blocking=False):
            return False
        try:
            for work in self.targets:
                self._settle(work, incomplete=True)
                work.done = True
            self.targets.clear()
            for work in self.active_targets:
                self._settle(work, incomplete=True)
            for work in self.provider_queue:
                self.singleflight.discard(work.key)
                work.cancelled = True
            self.provider_queue.clear()
            for work in self.active_providers:
                work.cancelled = True
            self.condition.notify_all()
            return True
        finally:
            self.condition.release()

    def stop(self, *, join_seconds=3):
        deadline = time.monotonic() + min(3, max(0, join_seconds))
        self.fence()
        self.audit.fence()
        for thread in self.controllers + self.providers:
            thread.join(max(0, deadline - time.monotonic()))
        audit = self.audit.stop(join_seconds=max(0, deadline - time.monotonic()))
        status = self.status()
        status['audit'] = audit
        status['stopped'] = status['stopped'] and audit['stopped']
        return status
