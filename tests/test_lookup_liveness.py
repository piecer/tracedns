"""Owned lookup acceptance: real main/engine/repository, synthetic collectors only."""
import json
import sqlite3
import threading
import time
from unittest.mock import Mock

import pytest

import dns_monitor
from models import QueryResult, Snapshot
from monitor import engine
from monitor.collect import Collected


def wait_for(predicate, seconds=2):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(.005)
    return False


def success(domain, server, ip='192.0.2.2'):
    return Collected(QueryResult(server=server, domain=domain.name, rtype='A',
                                 status='ok', values=[ip]),
                     Snapshot(type='A', values=[ip], decoded_ips=[], ts=100000))


def test_main_slow_first_target_does_not_hide_healthy_second(tmp_path, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    captured, errors = {}, []
    from monitor import delivery_runtime
    from test_delivery_adapters_steps import Response, Transport
    real_delivery = delivery_runtime.DeliveryRuntime
    monkeypatch.setattr(delivery_runtime, 'DeliveryRuntime',
                        lambda *a, **k: real_delivery(*a, **k, transport=Transport(Response())))
    monkeypatch.setattr('sys.argv', ['dns_monitor.py', '--config', str(tmp_path / 'cfg')])
    monkeypatch.setattr('security.startup.open_security', lambda args: Mock())
    monkeypatch.setattr('security.startup.start_housekeeping', lambda store: threading.Event())
    monkeypatch.setattr(dns_monitor, 'read_config', lambda path: {
        'domains': ['slow.example', 'healthy.example'], 'servers': ['fixture'],
        'alerts': {'teams_webhook': 'https://teams.invalid/hook'}, 'max_workers': 2})
    monkeypatch.setattr(dns_monitor, 'ThreadingHTTPServer', lambda *a: Mock())
    monkeypatch.setattr(dns_monitor, 'SignalStopBridge', lambda *a: Mock(requested=False))
    def handler(*args, **kwargs):
        captured['repo'] = kwargs['state_repository']
        captured['config'] = args[0]
        return Mock()
    monkeypatch.setattr(dns_monitor, 'make_handler', handler)
    def collect(domain, server):
        if domain.name == 'slow.example':
            entered.set()
            assert release.wait(10), 'fixture rescue deadline'
        return success(domain, server)
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    def run():
        try:
            dns_monitor.main()
        except BaseException as error:
            errors.append(error)
    thread = threading.Thread(target=run)
    thread.start()
    try:
        assert entered.wait(2)
        repo = captured['repo']
        assert wait_for(lambda: bool(repo.current.get('healthy.example'))), (
            'healthy target must publish before first collector returns')
        with sqlite3.connect(repo.delivery_runtime.store.path) as db:
            assert db.execute('SELECT COUNT(*) FROM receipt').fetchone()[0] == 1
        saved = tmp_path / 'cfg.history' / 'healthy.example.json'
        assert wait_for(saved.exists)
        assert json.loads(saved.read_text())['current']
        assert not release.is_set()
    finally:
        if 'config' in captured:
            cfg = captured['config']
            with cfg['_monitor_condition']:
                cfg['_monitor_stopped'] = True
                cfg['_monitor_condition'].notify_all()
        release.set()
        thread.join(5)
    assert not thread.is_alive()
    assert errors == []


def owned_app(tmp_path, *, domains=None, servers=None, current=None, clock=None):
    from test_stage3_core_runtime import app_factory
    from monitor.lookup_runtime import LookupRuntime
    app = app_factory(tmp_path, current=current, config={
        'domains': domains or ['test.example'], 'servers': servers or ['slow', 'healthy'],
        'max_workers': 2, 'alerts': {'teams_webhook': 'https://teams.invalid/hook'}})
    app.lookup = LookupRuntime(app.repo, **({'clock': clock} if clock else {}))
    return app


def owned_scan(app, **kwargs):
    snap = app.cfg.snapshot()
    return engine.run_full_cycle(domains_raw=snap.domains, servers=snap.servers,
        current_results=app.current, history=app.history, history_dir=app.repo.history_dir,
        query_fail_counts={}, max_workers=snap.max_workers, state_repository=app.repo,
        target_leases=snap.target_leases, registry_view=snap.registry_view,
        ens_rpc_url=snap.ens_rpc_url, sns_proxy_hosts=snap.sns_proxy_hosts,
        lookup_runtime=app.lookup, **kwargs)


def background_scan(app, **kwargs):
    result, errors = [], []
    def run():
        try:
            result.append(owned_scan(app, **kwargs))
        except BaseException as error:
            errors.append(error)
    thread = threading.Thread(target=run)
    thread.start()
    return thread, result, errors


@pytest.mark.parametrize('populated', [False, True])
def test_provider_publishes_before_stuck_sibling(tmp_path, monkeypatch, populated):
    from test_stage3_core_runtime import rows
    current = {'test.example': {'slow': {'type': 'A', 'values': ['192.0.2.1'], 'ts': 1}}} if populated else None
    app = owned_app(tmp_path, current=current)
    entered, release = threading.Event(), threading.Event()
    def collect(domain, server):
        if server == 'slow':
            entered.set()
            assert release.wait(10)
        return success(domain, server)
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    thread, results, errors = background_scan(app)
    try:
        assert entered.wait(2)
        assert wait_for(lambda: 'healthy' in app.current['test.example']), 'provider result held behind sibling'
        assert len(rows(app, 'receipt')) == 1
        saved = tmp_path / 'test.example.json'
        assert wait_for(saved.exists)
        assert 'healthy' in json.loads(saved.read_text())['current']
        if populated:
            assert app.current['test.example']['slow']['values'] == ['192.0.2.1']
        assert not release.is_set()
    finally:
        release.set()
        thread.join(3)
        app.lookup.stop()
        app.delivery.stop()
    assert not thread.is_alive() and not errors
    assert results[0].complete


class MonotonicClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


@pytest.mark.parametrize('completion', [4.999, 5.0, 5.001])
def test_provider_deadline_observed_boundary(tmp_path, monkeypatch, completion):
    clock = MonotonicClock()
    app = owned_app(tmp_path, servers=['slow'], clock=clock)
    entered, release = threading.Event(), threading.Event()
    def collect(domain, server):
        entered.set()
        assert release.wait(10)
        return success(domain, server)
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    thread, results, errors = background_scan(app)
    try:
        assert entered.wait(2)
        clock.now = completion
        release.set()
        thread.join(2)
        assert not thread.is_alive() and not errors
        assert bool(app.current['test.example']) == (completion < 5)
        assert results[0].complete == (completion < 5)
    finally:
        release.set()
        thread.join(3)
        app.lookup.stop()
        app.delivery.stop()


def test_timeout_retains_physical_slots_and_singleflight(tmp_path, monkeypatch):
    clock = MonotonicClock()
    app = owned_app(tmp_path, clock=clock)
    release = threading.Event()
    calls = []
    def collect(domain, server):
        calls.append((domain.name, server))
        assert release.wait(10)
        return success(domain, server)
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    thread, results, errors = background_scan(app)
    second = None
    try:
        assert wait_for(lambda: len(calls) == 2)
        workers = tuple(app.lookup.providers)
        clock.now = 5
        thread.join(1)
        assert not thread.is_alive(), 'logical timeout must not wait for physical return'
        assert not results[0].complete and app.current['test.example'] == {}
        second, again, second_errors = background_scan(app)
        second.join(1)
        assert not second.is_alive(), 'same-incarnation stuck pairs must be unavailable, not duplicated'
        assert not again[0].complete and not second_errors
        assert len(calls) == 2 and tuple(app.lookup.providers) == workers
        release.set()
        assert wait_for(lambda: app.lookup.status()['active'] == 0)
        assert app.current['test.example'] == {}, 'late mailbox must never publish'
        recovered = owned_scan(app)
        assert recovered.complete and len(calls) == 4
        assert tuple(app.lookup.providers) == workers
    finally:
        release.set()
        thread.join(3)
        if second:
            second.join(3)
        app.lookup.stop()
        app.delivery.stop()
    assert not errors


def test_stop_fences_ready_admission_and_retains_ledger(tmp_path, monkeypatch):
    app = owned_app(tmp_path, servers=['healthy'])
    entered, release = threading.Event(), threading.Event()
    candidate = app.repo.observation_candidate
    def delayed(lease):
        result = candidate(lease)
        entered.set()
        assert release.wait(10)
        return result
    monkeypatch.setattr(app.repo, 'observation_candidate', delayed)
    monkeypatch.setattr(engine, 'collect_snapshot', success)
    thread, results, errors = background_scan(app)
    try:
        assert entered.wait(2)
        status = app.lookup.stop(join_seconds=0)
        assert not status['stopped']
        stopped = app.delivery.stop(producers_stopped=status['stopped'], join_seconds=0)
        assert not stopped['closed'] and not app.delivery.store._closed
        release.set()
        thread.join(2)
        assert not thread.is_alive() and not errors
        assert app.current['test.example'] == {}
        assert not (tmp_path / 'test.example.json').exists()
        assert app.lookup.stop()['stopped']
        assert app.delivery.stop(producers_stopped=True)['closed']
    finally:
        release.set()
        thread.join(3)
        app.lookup.stop()
        app.delivery.stop()


def test_lookup_stop_alone_prevents_late_history_replace(tmp_path, monkeypatch):
    app = owned_app(tmp_path, servers=['healthy'])
    entered, release = threading.Event(), threading.Event()
    persist = engine.persist_history_entry
    def delayed(*args, **kwargs):
        entered.set()
        assert release.wait(10)
        return persist(*args, **kwargs)
    monkeypatch.setattr(engine, 'persist_history_entry', delayed)
    monkeypatch.setattr(engine, 'collect_snapshot', success)
    thread, results, errors = background_scan(app)
    try:
        assert entered.wait(2)
        assert not app.lookup.stop(join_seconds=0)['stopped']
        release.set()
        thread.join(2)
        assert not (tmp_path / 'test.example.json').exists(), 'stop must fence history publication too'
    finally:
        release.set()
        thread.join(3)
        app.lookup.stop()
        app.delivery.stop()
    assert not errors
