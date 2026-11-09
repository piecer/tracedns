"""Transition notifications, not unchanged wait returns, wake lookup peers."""
from collections import deque
from contextlib import contextmanager
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from monitor import engine
from test_lookup_liveness import MonotonicClock, owned_app, owned_scan, success, wait_for


def state(runtime):
    """Data-only ownership snapshot, always taken under the real condition."""
    def provider(work):
        return (id(work), work.started, work.done, work.consumed, work.cancelled, work.deadline)

    def target(work):
        return (id(work), work.done, work.settled, work.deadline, work.scan.pending)

    return (tuple(map(provider, runtime.provider_queue)), tuple(map(provider, runtime.active_providers)),
            tuple(map(target, runtime.targets)), tuple(map(target, runtime.active_targets)),
            frozenset(runtime.singleflight), runtime.stopping)


class ObservedCondition:
    """Delegate all synchronization; gates release the underlying RLock fully."""
    def __init__(self, runtime):
        self.real = runtime.condition
        self.runtime = runtime
        self.armed = False
        self.closed = False
        self.gates = {}
        self.trace = deque(maxlen=1024)
        self.test_wakes = 0

    def __enter__(self):
        return self.real.__enter__()

    def __exit__(self, *args):
        return self.real.__exit__(*args)

    def acquire(self, *args, **kwargs):
        return self.real.acquire(*args, **kwargs)

    def release(self):
        return self.real.release()

    def notify_all(self):
        origin = sys._getframe(1).f_code.co_name
        ident = threading.get_ident()
        gate = self.gates.get(ident)
        if gate is not None and gate.stage == 'checking':
            gate.broadcasts.append(origin)
        if not self.armed:
            self.trace.append((origin, state(self.runtime)))
        return self.real.notify_all()

    def park(self, event):
        saved = self.real._release_save()
        try:
            assert event.wait(8), 'condition gate rescue deadline'
        finally:
            self.real._acquire_restore(saved)

    def wait(self, timeout=None):
        role = sys._getframe(1).f_code.co_name
        ident = threading.get_ident()
        if not self.armed or self.closed or role not in ('collect', 'run_scan'):
            return self.real.wait(timeout)
        gate = self.gates.get(ident)
        if gate is None:
            gate = SimpleNamespace(role=role, stage='parked', permit=threading.Event(),
                                   waiting=threading.Event(), finished=threading.Event(),
                                   release=threading.Event(), broadcasts=[], before=None, after=None,
                                   timeout=timeout, returned=None)
            self.gates[ident] = gate
            self.park(gate.permit)
            if self.closed:
                return self.real.wait(timeout)
            gate.waiting.set()
            returned = self.real.wait(timeout)
            gate.before = state(self.runtime)
            gate.returned = returned
            gate.stage = 'checking'
            return returned
        assert gate.stage == 'checking'
        gate.after = state(self.runtime)
        gate.stage = 'finished'
        gate.finished.set()
        self.park(gate.release)
        return self.real.wait(timeout)

    def sample(self, gate):
        gate.permit.set()
        assert gate.waiting.wait(2), 'sample did not enter real Condition.wait'
        with self.real:
            # Acquiring here proves the sampled real wait released its mutex.
            self.test_wakes += 1
            self.real.notify_all()  # Explicit test-origin wake, not a product broadcast.
        assert gate.finished.wait(2), 'unchanged pass did not reach its next wait'
        assert gate.returned is True, 'sample must return from the labelled notification'
        assert gate.timeout == .05
        assert gate.before == gate.after, 'sample contained an ownership transition'
        return list(gate.broadcasts)

    def close(self):
        with self.real:
            self.closed = True
            for gate in self.gates.values():
                gate.permit.set()
                gate.release.set()
            self.real.notify_all()


class ScanOwner:
    def __init__(self, app):
        self.app = app
        self.threads = []
        self.events = []
        self.errors = []
        self.results = []
        self.observer = ObservedCondition(app.lookup)
        app.lookup.condition = self.observer

    def event(self):
        event = threading.Event()
        self.events.append(event)
        return event

    def spawn(self, callback):
        def run():
            try:
                callback()
            except BaseException as error:
                self.errors.append(error)
        thread = threading.Thread(target=run, name='wakeup-test-owner')
        self.threads.append(thread)  # Ownership precedes start and fallible observation.
        thread.start()
        return thread

    def scan(self):
        return self.spawn(lambda: self.results.append(owned_scan(self.app)))

    def close(self):
        errors = []
        for event in self.events:
            event.set()
        try:
            self.observer.close()
        except BaseException as error:
            errors.append(error)
        end = time.monotonic() + 4
        for thread in self.threads:
            if thread.ident is not None:
                thread.join(max(0, end - time.monotonic()))
        try:
            assert self.app.lookup.stop()['stopped'], 'lookup threads not retired'
        except BaseException as error:
            errors.append(error)
        try:
            assert self.app.delivery.stop()['closed'], 'delivery not closed'
        except BaseException as error:
            errors.append(error)
        if any(thread.is_alive() for thread in self.threads):
            errors.append(AssertionError('test-owned thread not retired'))
        errors.extend(self.errors)
        if errors:
            raise errors[0]


@contextmanager
def owned(tmp_path, **kwargs):
    app = owned_app(tmp_path, **kwargs)
    owner = None
    primary = None
    try:
        owner = ScanOwner(app)
        yield owner
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            if owner is not None:
                owner.close()
            else:
                try:
                    app.lookup.stop()
                finally:
                    app.delivery.stop()
        except BaseException as error:
            if primary is None:
                raise
            primary.add_note('cleanup failure: ' + repr(error))


@pytest.mark.parametrize('peers', ['pump_collect', 'collect_collect'])
def test_unchanged_wait_return_does_not_rebroadcast(tmp_path, monkeypatch, peers):
    domains = ['one.example'] if peers == 'pump_collect' else ['one.example', 'two.example']
    clock = MonotonicClock()
    with owned(tmp_path, domains=domains, servers=['fixture'], clock=clock) as owner:
        release = owner.event()
        called = []

        def collect(domain, server):
            called.append(domain.name)
            assert release.wait(8), 'collector rescue deadline'
            return success(domain, server)

        monkeypatch.setattr(engine, 'collect_snapshot', collect)
        thread = owner.scan()
        assert wait_for(lambda: len(called) == len(domains))
        observer = owner.observer
        with observer:
            observer.armed = True
        assert wait_for(lambda: len(observer.gates) == len(domains) + 1)
        with observer:
            gates = list(observer.gates.values())
            assert sorted(g.role for g in gates) == ['collect'] * len(domains) + ['run_scan']
            assert not owner.app.lookup.provider_queue and not owner.app.lookup.targets
            assert all(not work.done for work in owner.app.lookup.active_providers)
        selected = gates if peers == 'pump_collect' else [g for g in gates if g.role == 'collect']
        observed = [(gate.role, observer.sample(gate)) for gate in selected]
        assert not owner.errors and thread.is_alive() and not release.is_set()
        assert observer.test_wakes == len(selected)
        assert all(not broadcasts for _, broadcasts in observed), (
            'transitionless product rebroadcast after real wait return', observed)


def test_real_provider_and_target_transitions_refill_and_retire(tmp_path, monkeypatch):
    # One worker holds its first consumed mailbox; the third provider must not
    # dispatch until physical retirement. One beyond the target queue cap proves
    # refill while the first durable consumer remains blocked.
    domains = [f'wakeup-{index}.example' for index in range(17)]
    with owned(tmp_path, domains=domains, servers=['one', 'two', 'three'],
               clock=MonotonicClock()) as owner:
        app = owner.app
        app.cfg.raw['max_workers'] = 1
        entered, release = owner.event(), owner.event()
        persist = engine.persist_history_entry
        held = []
        calls = []

        def delayed(*args, **kwargs):
            if not held:
                held.append(True)
                entered.set()
                assert release.wait(8)
            return persist(*args, **kwargs)

        def collect(domain, server):
            calls.append((domain.name, server))
            return success(domain, server)

        monkeypatch.setattr(engine, 'persist_history_entry', delayed)
        monkeypatch.setattr(engine, 'collect_snapshot', collect)
        thread = owner.scan()
        assert entered.wait(2)
        assert wait_for(lambda: len({target[0] for origin, s in list(owner.observer.trace)
                                    if origin == 'run_scan' for target in s[2]}) == len(domains))
        with app.lookup.condition:
            assert len(app.lookup.active_providers) == 1 and len(calls) == 1
            work = app.lookup.active_providers[0]
            assert work.done and not work.consumed and work.key in app.lookup.singleflight
            assert app.lookup.provider_queue
            before = len(owner.observer.trace)
            assert app.lookup._take_provider() is None
            assert len(owner.observer.trace) == before, 'unsuccessful selection must stay silent'
        release.set()
        thread.join(4)
        assert not thread.is_alive() and not owner.errors and owner.results[0].complete
        assert wait_for(lambda: not app.lookup.active_providers and not app.lookup.active_targets)
        assert len(calls) == len(domains) * 3 and len(set(calls)) == len(calls)
        assert not app.lookup.singleflight and not app.lookup.provider_queue and not app.lookup.targets
        trace = list(owner.observer.trace)
        # Notifications must accompany real queue removal, not just eventual
        # progress after a fallback poll. Payload snapshots bind actual ownership.
        provider_dequeues = [s for origin, s in trace if origin == '_take_provider']
        assert provider_dequeues and all(s[1] and s[1][-1][1] for s in provider_dequeues)
        assert all(s[1][-1][-1] == 5 for s in provider_dequeues)
        assert any(origin == '_controller' and s[3] and not s[3][-1][1] for origin, s in trace)
        assert any(origin == 'collect' and s[0] for origin, s in trace)
        assert any(origin == '_provider' and any(p[2] for p in s[1]) for origin, s in trace)
        assert any(origin == '_consume' and any(p[3] for p in s[1]) for origin, s in trace)
        assert any(origin == '_provider' and not s[1] for origin, s in trace)
        assert any(origin == 'run_scan' and s[2] for origin, s in trace)
        assert any(origin == 'run_scan' and not s[2] and not s[3] for origin, s in trace)


def test_successful_provider_dequeue_refills_full_queue(tmp_path, monkeypatch):
    from models import coerce_domains

    domains = [f'queue-{index}.example' for index in range(9)]
    with owned(tmp_path, domains=domains, servers=['one', 'two'], clock=MonotonicClock()) as owner:
        app = owner.app
        snapshot = app.cfg.snapshot()
        release, entered = owner.event(), owner.event()
        calls, results = [], []

        def collect(domain, server):
            calls.append((domain.name, server))
            entered.set()
            assert release.wait(8)
            return success(domain, server)

        monkeypatch.setattr(engine, 'collect_snapshot', collect)
        for domain in coerce_domains(snapshot.domains):
            def consume(domain=domain):
                results.extend(app.lookup.collect(domain, snapshot.servers, snapshot.registry_view,
                                                  snapshot.target_leases[domain.name], 75))
            owner.spawn(consume)
        assert wait_for(lambda: len(app.lookup.provider_queue) == 16)
        with app.lookup.condition:
            before = {id(work) for work in app.lookup.provider_queue}
        app.lookup.start(1)
        assert entered.wait(2)
        assert wait_for(lambda: len(app.lookup.provider_queue) == 16)
        with app.lookup.condition:
            assert len(app.lookup.active_providers) == 1 and len(calls) == 1
            assert {id(work) for work in app.lookup.provider_queue} - before
            assert app.lookup.active_providers[0].deadline == 5
        assert any(origin == '_take_provider' and len(s[0]) == 15 and len(s[1]) == 1
                   for origin, s in list(owner.observer.trace))
        release.set()
        for thread in owner.threads:
            thread.join(3)
        assert all(not thread.is_alive() for thread in owner.threads) and not owner.errors
        assert len(results) == 18 and len(set(calls)) == 18
        assert all(error is None for _, _, error, _ in results)
        assert wait_for(lambda: not app.lookup.active_providers and not app.lookup.singleflight)


def test_settled_physically_retained_target_is_silent(tmp_path, monkeypatch):
    clock = MonotonicClock()
    with owned(tmp_path, domains=['held.example', 'live.example'], servers=['fixture'], clock=clock) as owner:
        app = owner.app
        held, release = owner.event(), owner.event()
        live = owner.event()
        original = engine.run_domain_cycle

        def delayed(**kwargs):
            if kwargs.get('lookup_runtime') is app.lookup and kwargs['target_lease'].name == 'held.example':
                held.set()
                assert release.wait(8)
            return original(**kwargs)

        def collect(domain, server):
            if domain.name == 'live.example':
                live.set()
                assert release.wait(8)
            return success(domain, server)

        monkeypatch.setattr(engine, 'run_domain_cycle', delayed)
        monkeypatch.setattr(engine, 'collect_snapshot', collect)
        thread = owner.scan()
        assert held.wait(2) and live.wait(2)
        # Keep the real full scan open through a config-only force envelope with
        # a fresh target deadline; the original two targets expire physically held.
        from monitor.scheduler import MonitorScheduler
        from test_lookup_force import enqueue
        app.lookup.scheduler = MonitorScheduler(app.cfg)
        clock.now = 74
        enqueue(app, ['held.example'])
        assert wait_for(lambda: any(w.scan.job is not None for w in app.lookup.targets))
        clock.now = 75
        assert wait_for(lambda: len(app.lookup.active_targets) == 1
                        and app.lookup.active_targets[0].settled and not app.lookup.active_targets[0].done)
        with owner.observer:
            retained = [w for w in app.lookup.active_targets if w.settled and not w.done]
            assert retained
            owner.observer.armed = True
        assert wait_for(lambda: any(g.role == 'run_scan' for g in owner.observer.gates.values()))
        with owner.observer:
            gate = next(g for g in owner.observer.gates.values() if g.role == 'run_scan')
        broadcasts = owner.observer.sample(gate)
        assert not broadcasts, 'already-settled physical owner is not fresh pump progress'
        assert all(w in app.lookup.active_targets and w.settled and not w.done for w in retained)
        assert thread.is_alive() and not release.is_set() and not owner.errors


def test_clock_only_expiry_cancels_without_early_physical_release(tmp_path, monkeypatch):
    clock = MonotonicClock()
    with owned(tmp_path, servers=['fixture'], clock=clock) as owner:
        entered, release = owner.event(), owner.event()

        def collect(domain, server):
            entered.set()
            assert release.wait(8)
            return success(domain, server)

        monkeypatch.setattr(engine, 'collect_snapshot', collect)
        thread = owner.scan()
        assert entered.wait(2)
        app = owner.app
        with app.lookup.condition:
            work = app.lookup.active_providers[0]
        clock.now = 5  # No lookup notification: unchanged .05 fallback discovers this.
        thread.join(2)
        assert not thread.is_alive() and not owner.errors and not owner.results[0].complete
        with app.lookup.condition:
            assert work.cancelled and work.consumed and not work.done
            assert work in app.lookup.active_providers and work.key in app.lookup.singleflight
        assert any(origin == 'collect' and any(p[4] for p in s[1])
                   for origin, s in list(owner.observer.trace))
        release.set()
        assert wait_for(lambda: not app.lookup.active_providers and not app.lookup.singleflight)
        assert not app.current['test.example']
