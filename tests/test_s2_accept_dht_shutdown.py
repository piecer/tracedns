"""DHT and shutdown schedules, with state captured before fixture rescue."""
import copy
import json
import threading
import time  # noqa: F401 - preserve promoted independent probe AST
from pathlib import Path  # noqa: F401 - preserve independent probe AST
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import dns_monitor
from monitor import engine
from monitor.scheduler import MonitorScheduler
from monitor.collect import Collected
from models import QueryResult
from test_lookup_force import enqueue
from test_lookup_liveness import background_scan, success, wait_for
from test_stage3_core_runtime import rows
from test_dht_monitor import observation, target
from test_s2_accept_runtime_boundaries import app_at, cleanup, Clock, isolation  # noqa: F401 - autouse isolation fixture


@pytest.mark.parametrize('boundary', ['native_verification', 'reduction_verification', 'finish', 'history'])
def test_dht_stop_at_owned_boundaries(tmp_path, monkeypatch, boundary):
    import dht_query
    obs, key = observation(7)
    domain = target(key)
    app = app_at(tmp_path, domains=[domain])
    name = next(iter(app.repo.capture()))
    entered, release = threading.Event(), threading.Event()
    monkeypatch.setattr(dht_query, 'fetch_dht_records', lambda *a, **k: obs)
    count = []
    if 'verification' in boundary:
        owner, method = dht_query, 'reconcile_dht'
        number = 1 if boundary == 'native_verification' else 2
    elif boundary == 'finish':
        owner, method, number = app.delivery.store, 'finish_dht', 1
    else:
        owner, method, number = app.repo, 'commit_history', 1
    original = getattr(owner, method)
    def delayed(*args, **kwargs):
        count.append(True)
        if len(count) == number:
            entered.set()
            assert release.wait(12)
        return original(*args, **kwargs)
    monkeypatch.setattr(owner, method, delayed)
    thread, results, errors = background_scan(app)
    try:
        assert entered.wait(2)
        before = rows(app, 'dht_state')[0]
        current = copy.deepcopy(app.current[name])
        receipts = rows(app, 'receipt')
        assert bool(before['pending']) == (boundary != 'history')
        status = app.lookup.stop(join_seconds=0)
        assert not status['stopped']
        assert not app.delivery.stop(producers_stopped=False, join_seconds=0)['closed']
        assert not release.is_set()
        release.set()
        thread.join(3)
        assert not thread.is_alive() and not errors
        assert wait_for(lambda: app.lookup.status()['active'] == 0)
        after = rows(app, 'dht_state')[0]
        if boundary == 'native_verification':
            assert after['pending'] is None, 'positively discarded evidence should retire its ticket'
        elif boundary != 'history':
            assert after['pending'] == before['pending'], 'uncertain acquired evidence lost its pending fence'
        else:
            assert after == before and json.loads(after['data'])
        assert app.current[name] == current
        assert rows(app, 'receipt') == receipts
        assert not list(tmp_path.glob('*.json')), 'late DHT history replacement'
    finally:
        cleanup(app, thread, release)


def test_late_dht_cancellation_cannot_abort_replacement_token(tmp_path, monkeypatch):
    clock = Clock()
    obs, key = observation(7)
    app = app_at(tmp_path, domains=[target(key)], clock=clock)
    name = next(iter(app.repo.capture()))
    entered, release = threading.Event(), threading.Event()
    abort_entered, abort_release = threading.Event(), threading.Event()
    def collect(domain, server, *, cancelled=None):
        entered.set()
        assert release.wait(12)
        assert cancelled()
        return Collected(QueryResult(server=server, domain=domain.name, rtype='DHT', status='error', values=[]),
            None, {'records': [], 'status': 'cancelled', 'coverage': {'termination': 'cancelled'}})
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    real_abort = app.delivery.store.abort_dht
    aborts = []
    def delay_abort(target_name, token):
        aborts.append((target_name, token))
        abort_entered.set()
        assert abort_release.wait(12)
        return real_abort(target_name, token)
    monkeypatch.setattr(app.delivery.store, 'abort_dht', delay_abort)
    thread, results, errors = background_scan(app)
    try:
        assert entered.wait(2)
        first = rows(app, 'dht_state')[0]
        clock.now = 106
        thread.join(2)
        assert not thread.is_alive() and not results[0].complete and not errors
        release.set()
        assert abort_entered.wait(2)
        assert real_abort(name, first['pending'])
        replacement = app.delivery.store.begin_dht(name, json.loads(first['data']), lambda: False)
        assert replacement and replacement != first['pending']
        abort_release.set()
        assert wait_for(lambda: app.lookup.status()['active'] == 0)
        assert aborts == [(name, first['pending'])]
        assert rows(app, 'dht_state')[0]['pending'] == replacement
        assert app.current[name] == {} and not rows(app, 'receipt')
    finally:
        cleanup(app, thread, release, abort_release)


def test_actual_replace_cannot_block_logical_stop_latch(tmp_path, monkeypatch):
    import monitor.repository as repository_module
    app = app_at(tmp_path, domains=['writer.example', 'blocked.example'])
    blocked, release_provider = threading.Event(), threading.Event()
    replace_entered, release_replace = threading.Event(), threading.Event()
    valid_waiter, stop_done = threading.Event(), threading.Event()
    valid, replace = app.repo.valid, repository_module.os.replace
    def collect(domain, server):
        if domain.name == 'blocked.example':
            blocked.set()
            assert release_provider.wait(12)
        else:
            assert blocked.wait(2)
        return success(domain, server)
    def delayed_replace(source, destination):
        if str(destination).endswith('writer.example.json'):
            replace_entered.set()
            assert release_replace.wait(12)
        return replace(source, destination)
    def traced_valid(lease):
        if (replace_entered.is_set() and lease.name == 'blocked.example'
                and app.lookup.condition._is_owned()):
            valid_waiter.set()
        return valid(lease)
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    monkeypatch.setattr(repository_module.os, 'replace', delayed_replace)
    monkeypatch.setattr(app.repo, 'valid', traced_valid)
    thread, results, errors = background_scan(app)
    stops, stop_errors = [], []
    def stop():
        try:
            stops.append(app.lookup.stop(join_seconds=0))
        except BaseException as error:
            stop_errors.append(repr(error))
        finally:
            stop_done.set()
    stopper = threading.Thread(target=stop)
    try:
        assert replace_entered.wait(2)
        assert valid_waiter.wait(2), 'required condition -> state_lock waiter did not occur'
        stopper.start()
        returned = stop_done.wait(.4)
        observed = {'stop_returned_before_rescue': returned, 'stopping_latch_before_rescue': app.lookup.stopping,
                    'actual_replace_blocked': not release_replace.is_set(), 'condition_valid_waiter': valid_waiter.is_set()}
        (tmp_path / 'stop-latch-observation.json').write_text(json.dumps(observed, indent=2))
        assert observed['stopping_latch_before_rescue'], 'logical stop latch blocked behind actual os.replace/state_lock/lookup.condition'
        assert returned, 'zero-drain stop blocked before it could report retained I/O ownership'
    finally:
        release_replace.set()
        release_provider.set()
        if stopper.ident:
            stopper.join(5)
        cleanup(app, thread, release_replace, release_provider)
    assert not stop_errors


def main_harness(tmp_path, monkeypatch):
    from monitor import delivery_runtime
    from test_delivery_adapters_steps import Transport, Response
    captured = {}
    real_delivery = delivery_runtime.DeliveryRuntime
    def delivery(*args, **kwargs):
        captured['delivery'] = real_delivery(*args, **kwargs, transport=Transport(Response()))
        return captured['delivery']
    monkeypatch.setattr(delivery_runtime, 'DeliveryRuntime', delivery)
    monkeypatch.setattr('sys.argv', ['dns_monitor.py', '--config', str(tmp_path / 'owned-config')])
    monkeypatch.setattr('security.startup.open_security', lambda *a: Mock())
    housekeeping = threading.Event()
    monkeypatch.setattr('security.startup.start_housekeeping', lambda *a: housekeeping)
    monkeypatch.setattr(dns_monitor, 'read_config', lambda path: {
        'domains': ['test.example'], 'servers': ['fixture'], 'max_workers': 2,
        'alerts': {'teams_webhook': 'https://teams.invalid/hook'}})
    http_stopped, http_closed, signal_closed = threading.Event(), threading.Event(), threading.Event()
    class HTTP:
        def __init__(self, *args): pass
        def serve_forever(self): http_stopped.wait(15)
        def shutdown(self): http_stopped.set()
        def server_close(self): http_closed.set()
    class Signal:
        requested = False
        def __init__(self, stop): captured['scheduler_stop'] = stop
        def start(self, *args): pass
        def close(self): signal_closed.set(); return True
    monkeypatch.setattr(dns_monitor, 'ThreadingHTTPServer', HTTP)
    monkeypatch.setattr(dns_monitor, 'SignalStopBridge', Signal)
    def handler(*args, **kwargs):
        captured['repo'] = kwargs['state_repository']
        captured['raw'] = args[0]
        return Mock()
    monkeypatch.setattr(dns_monitor, 'make_handler', handler)
    captured.update(housekeeping=housekeeping, http_stopped=http_stopped,
                    http_closed=http_closed, signal_closed=signal_closed)
    errors = []
    def run():
        try:
            dns_monitor.main()
        except BaseException as error:
            errors.append(error)
    return captured, errors, threading.Thread(target=run)


def test_real_main_incomplete_source_stop_retains_ledger(tmp_path, monkeypatch):
    captured, errors, thread = main_harness(tmp_path, monkeypatch)
    entered, release = threading.Event(), threading.Event()
    def collect(domain, server):
        entered.set()
        assert release.wait(12)
        return success(domain, server)
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    thread.start()
    try:
        assert entered.wait(2)
        captured['scheduler_stop']()
        thread.join(5)
        assert not thread.is_alive() and not errors
        repo, delivery = captured['repo'], captured['delivery']
        status = repo.lookup_runtime.status()
        observed = {'main_returned': True, 'lookup': status, 'ledger_closed': delivery.store._closed,
                    'housekeeping_stopped': captured['housekeeping'].is_set(),
                    'http_closed': captured['http_closed'].is_set(), 'signal_closed': captured['signal_closed'].is_set()}
        (tmp_path / 'main-incomplete-observation.json').write_text(json.dumps(observed, indent=2))
        assert not release.is_set() and not status['stopped'] and status['active'] == 1
        assert not delivery.store._closed and repo.lookup_runtime is not None
        assert captured['housekeeping'].is_set() and captured['http_closed'].is_set() and captured['signal_closed'].is_set()
        release.set()
        assert repo.lookup_runtime.stop()['stopped']
        assert not any(repo.current.values())
        assert delivery.stop(producers_stopped=True)['closed']
    finally:
        release.set()
        if 'scheduler_stop' in captured:
            captured['scheduler_stop']()
        thread.join(5)
        if 'repo' in captured:
            captured['repo'].lookup_runtime.stop()
            captured['delivery'].stop()
        captured['http_stopped'].set()
    assert not thread.is_alive()


def test_real_main_blocked_audit_does_not_prevent_other_cleanup(tmp_path, monkeypatch):
    captured, errors, thread = main_harness(tmp_path, monkeypatch)
    entered, release = threading.Event(), threading.Event()
    audit_calls = []
    def audit(*args, **kwargs):
        audit_calls.append(kwargs)
        entered.set()
        assert release.wait(12)
    job = {'actor': {'id': 1}, '_security_store': SimpleNamespace(audit=audit),
           'job_id': 'owned-audit', 'request_id': 'owned-audit', 'source_ip': '127.0.0.1'}
    def fail_scan(**kwargs):
        captured['raw']['_force_resolve_queue'] = [job]
        raise RuntimeError('owned-main-primary-failure')
    monkeypatch.setattr(dns_monitor, 'run_full_cycle', fail_scan)
    thread.start()
    try:
        assert entered.wait(2)
        cleaned = wait_for(lambda: captured['http_closed'].is_set() and captured['housekeeping'].is_set(), seconds=.5)
        observed = {'audit_entered': True, 'audit_released': release.is_set(),
                    'other_cleanup_before_rescue': cleaned, 'signal_closed': captured['signal_closed'].is_set(),
                    'lookup_stopping': captured['repo'].lookup_runtime.stopping,
                    'ledger_closed': captured['delivery'].store._closed}
        (tmp_path / 'blocked-audit-observation.json').write_text(json.dumps(observed, indent=2))
        assert cleaned, 'synchronous terminal audit blocked unrelated main cleanup'
    finally:
        release.set()
        thread.join(5)
        captured['http_stopped'].set()
        if thread.is_alive():
            captured['scheduler_stop']()
            thread.join(3)
        captured['repo'].lookup_runtime.stop()
        captured['delivery'].stop()
    assert not thread.is_alive() and len(audit_calls) == 1
    assert len(errors) == 1 and str(errors[0]) == 'owned-main-primary-failure'


def test_blocked_force_audit_does_not_stop_full_admissions(tmp_path, monkeypatch):
    domains = [f'target-{index}.example' for index in range(24)] + ['force.example']
    app = app_at(tmp_path, domains=domains)
    app.lookup.scheduler = MonitorScheduler(app.cfg)
    job = enqueue(app, ['force.example'])
    entered, release = threading.Event(), threading.Event()
    calls = []
    def audit(*args, **kwargs):
        entered.set()
        assert release.wait(12)
    job['_security_store'].audit.side_effect = audit
    def collect(domain, server):
        calls.append(domain.name)
        return success(domain, server)
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    thread, results, errors = background_scan(app)
    try:
        assert entered.wait(2)
        progressed = wait_for(lambda: 'target-23.example' in calls, seconds=1)
        # status is sampled before releasing the arbitrary audit callback.
        observed = {'calls_before_rescue': list(calls), 'status': app.lookup.status(),
                    'last_full_target_dispatched': progressed, 'audit_released': release.is_set()}
        (tmp_path / 'audit-progress-observation.json').write_text(json.dumps(observed, indent=2))
        assert progressed, 'synchronous force terminal audit blocked full target admission with physical provider capacity free'
    finally:
        cleanup(app, thread, release)
    assert not errors and results[0].complete
