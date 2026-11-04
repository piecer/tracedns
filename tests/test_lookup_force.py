"""Force envelopes are dispatched inside the full scan, not after it."""
import threading
from unittest.mock import Mock

from monitor import engine
from monitor.scheduler import MonitorScheduler
from test_lookup_liveness import owned_app, background_scan, success, wait_for


def enqueue(app, names, servers=None):
    snapshot = app.cfg.snapshot()
    job = {'domains': names, 'servers': servers or snapshot.servers,
           '_target_leases': {name: snapshot.target_leases[name] for name in names},
           '_registry_view': snapshot.registry_view,
           'actor': {'id': 1}, '_security_store': Mock(),
           'job_id': 'fixture', 'request_id': 'fixture', 'source_ip': '127.0.0.1'}
    with app.cfg.condition:
        app.cfg.raw.setdefault('_force_resolve_queue', []).append(job)
        app.cfg.condition.notify_all()
    return job


def test_force_runs_inside_full_scan_and_finishes_once(tmp_path, monkeypatch):
    app = owned_app(tmp_path, domains=['slow.example', 'force.example'], servers=['healthy'])
    app.lookup.scheduler = MonitorScheduler(app.cfg)
    entered, release, forced = threading.Event(), threading.Event(), threading.Event()
    calls = []
    def collect(domain, server):
        calls.append(domain.name)
        if domain.name == 'slow.example':
            entered.set()
            assert release.wait(10)
        if domain.name == 'force.example' and calls.count(domain.name) == 2:
            forced.set()
        return success(domain, server)
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    reconciled = []
    complete = app.delivery.complete
    def reconcile(snap, current):
        reconciled.append((snap.force_req, current.positive))
        return complete(snap, current)
    monkeypatch.setattr(app.delivery, 'complete', reconcile)
    thread, results, errors = background_scan(app)
    try:
        assert entered.wait(2)
        assert wait_for(lambda: bool(app.current['force.example']))
        job = enqueue(app, ['force.example'])
        assert forced.wait(2), 'queued force waited behind whole full scan'
        assert wait_for(lambda: job.get('_terminal_outcome') == 'completed')
        assert thread.is_alive() and not release.is_set()
        assert app.lookup.scheduler.last_full_completion is None
        assert len(reconciled) == 1 and reconciled[0][0] is job
        assert wait_for(lambda: job.get('_terminal_audit_done'))
        job['_security_store'].audit.assert_called_once()
    finally:
        release.set()
        thread.join(3)
        app.lookup.stop()
        app.delivery.stop()
    assert not errors and results[0].complete


def test_full_and_force_controller_entitlement_is_three_to_one(tmp_path, monkeypatch):
    domains = [f'target-{i}.example' for i in range(20)]
    app = owned_app(tmp_path, domains=domains, servers=['full'])
    app.lookup.scheduler = MonitorScheduler(app.cfg)
    job = enqueue(app, domains, servers=['force'])
    release = threading.Event()
    selected = []
    run_domain = engine.run_domain_cycle
    def domain_cycle(**kwargs):
        if kwargs.get('lookup_runtime') is not None:
            selected.append(kwargs['servers'][0])
        return run_domain(**kwargs)
    def collect(domain, server):
        assert release.wait(10)
        return success(domain, server)
    monkeypatch.setattr(engine, 'run_domain_cycle', domain_cycle)
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    thread, results, errors = background_scan(app)
    try:
        assert wait_for(lambda: len(selected) >= 4)
        assert selected[:4].count('full') == 3 and selected[:4].count('force') == 1
        assert app.lookup.status()['target_queued'] <= 16
    finally:
        release.set()
        thread.join(8)
        app.lookup.stop()
        app.delivery.stop()
    assert not thread.is_alive() and not errors
    assert job['_terminal_outcome'] == 'completed'
    job['_security_store'].audit.assert_called_once()


def test_stop_latch_does_not_wait_for_blocked_config_admission(tmp_path):
    from monitor.engine import CycleResult, reconcile_scan
    app = owned_app(tmp_path, servers=['healthy'])
    scheduler = MonitorScheduler(app.cfg)
    snap = app.cfg.snapshot()
    entered, release = threading.Event(), threading.Event()
    def hold():
        with app.cfg.lock:
            entered.set()
            release.wait(10)
    holder = threading.Thread(target=hold)
    holder.start()
    stopped = threading.Event()
    errors = []
    def stop():
        try:
            scheduler.stop()
            assert app.cfg.stop_requested
            assert reconcile_scan(app.cfg, snap, {}, CycleResult({}, {}, False), None) == (False, {})
            stopped.set()
        except BaseException as error:
            errors.append(error)
    stopper = threading.Thread(target=stop)
    try:
        assert entered.wait(2)
        stopper.start()
        assert stopped.wait(1), 'shutdown waited for config lock before publishing its fence'
    finally:
        release.set()
        holder.join(2)
        stopper.join(2)
        scheduler.stop()
        app.lookup.stop()
        app.delivery.stop()
    assert not errors


def test_dequeued_force_snapshot_failure_keeps_terminal_audit_duty(tmp_path, monkeypatch):
    import pytest
    app = owned_app(tmp_path)
    scheduler = MonitorScheduler(app.cfg)
    job = enqueue(app, ['test.example'])
    monkeypatch.setattr(app.cfg, '_snapshot_locked', lambda: (_ for _ in ()).throw(RuntimeError('snapshot failed')))
    try:
        with pytest.raises(RuntimeError, match='snapshot failed'):
            scheduler.active_force()
        assert job.get('_terminal_outcome') == 'failure'
        assert wait_for(lambda: job.get('_terminal_audit_done'))
        job['_security_store'].audit.assert_called_once()
    finally:
        app.lookup.stop()
        app.delivery.stop()
