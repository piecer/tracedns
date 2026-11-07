"""Additional real-owner controls for the frozen acceptance matrix."""
import threading
from types import SimpleNamespace

import pytest

from monitor import engine
from monitor.scheduler import MonitorScheduler
from test_lookup_liveness import (owned_app, owned_scan, background_scan, success,
                                 wait_for, MonotonicClock)
from test_lookup_force import enqueue


def test_sibling_timeout_cannot_erase_already_admitted_success(tmp_path, monkeypatch):
    clock = MonotonicClock()
    app = owned_app(tmp_path, clock=clock, current={'test.example': {
        'slow': {'type': 'A', 'values': ['192.0.2.1'], 'ts': 1}}})
    release = threading.Event()
    def collect(domain, server):
        if server == 'slow':
            assert release.wait(10)
        return success(domain, server)
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    thread, results, errors = background_scan(app)
    try:
        assert wait_for(lambda: 'healthy' in app.current['test.example'])
        clock.now = 5
        thread.join(2)
        assert not thread.is_alive() and not errors
        assert not results[0].complete and set(results[0].positive) == {'192.0.2.2'}
        assert app.current['test.example']['slow']['values'] == ['192.0.2.1']
        assert app.current['test.example']['healthy']['values'] == ['192.0.2.2']
        release.set()
        assert wait_for(lambda: app.lookup.status()['active'] == 0)
        assert app.current['test.example']['slow']['values'] == ['192.0.2.1']
    finally:
        release.set()
        thread.join(3)
        app.lookup.stop()
        app.delivery.stop()


def test_same_target_force_waits_through_history_and_does_not_drain_backlog(tmp_path, monkeypatch):
    app = owned_app(tmp_path, servers=['healthy'])
    app.lookup.scheduler = MonitorScheduler(app.cfg)
    entered, release = threading.Event(), threading.Event()
    persist = engine.persist_history_entry
    held, calls = [], []
    def blocked(*args, **kwargs):
        if not held:
            held.append(True)
            entered.set()
            assert release.wait(10)
        return persist(*args, **kwargs)
    def collect(domain, server):
        calls.append(server)
        return success(domain, server)
    monkeypatch.setattr(engine, 'persist_history_entry', blocked)
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    thread, results, errors = background_scan(app)
    jobs = []
    try:
        assert entered.wait(2)
        jobs = [enqueue(app, ['test.example']) for _ in range(3)]
        assert wait_for(lambda: len(app.cfg.raw.get('_force_resolve_queue', [])) == 2)
        assert calls == ['healthy']
        assert jobs[0].get('_terminal_outcome') is None
        release.set()
        thread.join(3)
        assert not thread.is_alive() and not errors
        assert len(calls) == 2
        assert jobs[0]['_terminal_outcome'] == 'completed'
        assert len(app.cfg.raw['_force_resolve_queue']) == 2
    finally:
        release.set()
        thread.join(3)
        app.lookup.scheduler.stop()
        app.lookup.stop()
        app.delivery.stop()
    for job in jobs:
        job['_security_store'].audit.assert_called_once()


def test_force_positive_evidence_excludes_cached_provider(tmp_path, monkeypatch):
    app = owned_app(tmp_path, current={'test.example': {
        'slow': {'type': 'A', 'values': ['192.0.2.1'], 'ts': 1},
        'healthy': {'type': 'A', 'values': ['192.0.2.2'], 'ts': 1}}})
    calls = []
    def collect(domain, server):
        calls.append(server)
        return success(domain, server, '192.0.2.3')
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    job = enqueue(app, ['test.example'], servers=['healthy'])
    app.cfg.dequeue_force()
    try:
        result = owned_scan(app, force_req=job)
        assert calls == ['healthy']
        assert set(result.positive) == {'192.0.2.3'}
        assert set(result) == {'192.0.2.1', '192.0.2.3'}
    finally:
        app.lookup.stop()
        app.delivery.stop()


def test_one_worker_cannot_run_healthy_target_until_physical_return(tmp_path, monkeypatch):
    app = owned_app(tmp_path, domains=['first.example', 'second.example'], servers=['healthy'])
    app.cfg.raw['max_workers'] = 1
    entered, release = threading.Event(), threading.Event()
    calls = []
    def collect(domain, server):
        calls.append(domain.name)
        if domain.name == 'first.example':
            entered.set()
            assert release.wait(10)
        return success(domain, server)
    # Four target controllers race even with one provider worker. Establish the
    # named occupant before allowing the second controller to request a slot.
    run_domain_cycle = engine.run_domain_cycle
    def ordered_cycle(**kwargs):
        if kwargs['target_lease'].name == 'second.example':
            assert entered.wait(2)
        return run_domain_cycle(**kwargs)
    monkeypatch.setattr(engine, 'run_domain_cycle', ordered_cycle)
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    thread, results, errors = background_scan(app)
    try:
        assert entered.wait(2)
        # Exercise real provider contention, not a controller still at the gate.
        assert wait_for(lambda: app.lookup.status()['provider_queued'] == 1)
        assert calls == ['first.example'] and app.lookup.status()['active'] == 1
        release.set()
        thread.join(3)
        assert not thread.is_alive() and not errors and results[0].complete
        assert calls == ['first.example', 'second.example']
    finally:
        release.set()
        thread.join(3)
        app.lookup.stop()
        app.delivery.stop()


def test_stop_uses_one_shared_drain_budget(tmp_path, monkeypatch):
    from monitor import lookup_runtime
    app = owned_app(tmp_path)
    release = threading.Event()
    calls = []
    def collect(domain, server):
        calls.append(server)
        release.wait(10)
        return success(domain, server)
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    thread, results, errors = background_scan(app)
    try:
        assert wait_for(lambda: len(calls) == 2)
        clock = MonotonicClock()
        budgets = []
        with monkeypatch.context() as change:
            change.setattr(lookup_runtime, 'time', SimpleNamespace(monotonic=clock))
            for worker in app.lookup.controllers + app.lookup.providers:
                join = worker.join
                def observed(timeout, join=join):
                    budgets.append(timeout)
                    clock.now += timeout
                    join(0)
                change.setattr(worker, 'join', observed)
            status = app.lookup.stop(join_seconds=3)
        assert sum(budgets) == 3 and not status['stopped']
        assert status['active'] == 2
    finally:
        release.set()
        thread.join(3)
        app.lookup.stop()
        app.delivery.stop()
    assert not errors


@pytest.mark.parametrize('rtype,budget', [('ENS', 30), ('SNS', 20)])
def test_ens_sns_operation_deadline_uses_monotonic_budget(tmp_path, monkeypatch, rtype, budget):
    clock = MonotonicClock()
    domain = {'name': 'test.eth' if rtype == 'ENS' else 'test.sol', 'type': rtype}
    app = owned_app(tmp_path, domains=[domain], clock=clock)
    app.cfg.raw.update(ens_rpc_url='fixture', DEFAULT_SNS_PROXY_HOSTS=['fixture'])
    entered, release = threading.Event(), threading.Event()
    def collect(ds, server):
        entered.set()
        assert release.wait(10)
        return success(ds, server)
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    thread, results, errors = background_scan(app)
    try:
        assert entered.wait(2)
        clock.now = budget
        thread.join(2)
        assert not thread.is_alive() and not errors and not results[0].complete
        assert not any(app.current.values())
    finally:
        release.set()
        thread.join(3)
        app.lookup.stop()
        app.delivery.stop()
