"""Production core integration with real ledger and no provider/DNS traffic."""
import json
import sqlite3
import threading
from types import SimpleNamespace

import pytest

from monitor import engine
from monitor.config_service import ConfigService
from monitor.repository import MonitorStateRepository
from monitor.stores import ConfigStore
from models import Snapshot


class Clock:
    def __init__(self):
        self.now = 100000

    def __call__(self):
        return self.now


def rows(app, table):
    with sqlite3.connect(app.delivery.store.path) as db:
        db.row_factory = sqlite3.Row
        return [dict(row) for row in db.execute('SELECT * FROM ' + table)]


def app_factory(tmp_path, *, current=None, config=None, limits=None, clock=None, transport=None):
    from monitor import delivery_runtime
    config = config or {'domains': [{'name': 'test.example', 'type': 'A'}],
                        'servers': ['fake'], 'alerts': {'teams_webhook': 'https://teams.invalid/hook'},
                        'config_revision': 0}
    current = current or {}
    history = {name: {'meta': {}, 'events': [], 'current': dict(values)} for name, values in current.items()}
    lock = threading.RLock()
    repo = MonitorStateRepository(current, history, str(tmp_path), config['domains'])
    cfg = ConfigStore(config, lock, repo)
    service = ConfigService(config, lock, str(tmp_path / 'config'), state_repository=repo,
                            current_results=current, history=history, history_dir=str(tmp_path))
    clock = clock or Clock()
    delivery = delivery_runtime.DeliveryRuntime(cfg, history_dir=str(tmp_path),
                                                clock=clock, limits=limits, transport=transport)
    service.delivery_runtime = delivery
    return SimpleNamespace(delivery=delivery, repo=repo, cfg=cfg, service=service,
                           current=current, history=history, clock=clock)


def scan(app, monkeypatch, ips, *, status='ok', force=None):
    def collect(domain, server):
        return SimpleNamespace(query=SimpleNamespace(server=server, status=status, error='fixture'),
                               snapshot=None if status == 'error' else Snapshot(
                                   type='A', values=list(ips), decoded_ips=[], ts=int(app.clock())))
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    snap = app.cfg.snapshot()
    snap.force_req = force
    result = engine.run_full_cycle(domains_raw=snap.domains, servers=snap.servers,
        current_results=app.current, history=app.history, history_dir=app.repo.history_dir,
        query_fail_counts={}, state_repository=app.repo, target_leases=snap.target_leases,
        force_req=force)
    accepted, _ = engine.reconcile_scan(app.cfg, snap, {}, result, None)
    return accepted, result


def test_empty_configured_target_first_observation_admits_before_publication(tmp_path, monkeypatch):
    from monitor import delivery_runtime
    assert hasattr(delivery_runtime, 'DeliveryRuntime')
    app = app_factory(tmp_path)
    try:
        assert len(rows(app, 'cursor')) == 1
        assert json.loads(rows(app, 'cursor')[0]['ips']) == []
        record = app.delivery.store.record_domain
        def admission(*args):
            assert app.current['test.example'] == {}
            assert app.history['test.example']['current'] == {}
            assert not (tmp_path / 'test.example.json').exists()
            return record(*args)
        monkeypatch.setattr(app.delivery.store, 'record_domain', admission)
        monkeypatch.setattr(engine, 'alert_new_ips', lambda *a, **k: pytest.fail('legacy provider path'))
        accepted, result = scan(app, monkeypatch, ['1.2.3.4'])
        assert accepted and set(result) == {'1.2.3.4'}
        assert len(rows(app, 'receipt')) == 1
        assert len(rows(app, 'batch')) == 1
        assert app.current['test.example']['fake']['values'] == ['1.2.3.4']
        assert json.loads((tmp_path / 'test.example.json').read_text())['current']['fake']['values'] == ['1.2.3.4']
    finally:
        app.delivery.stop()


def test_source_errors_do_not_advance_absence_or_busy_loop(tmp_path, monkeypatch):
    app = app_factory(tmp_path, current={'test.example': {'fake': {'values': ['1.2.3.4']}}})
    try:
        baseline = rows(app, 'baseline')
        from monitor.scheduler import MonitorScheduler
        scheduler = MonitorScheduler(app.cfg, clock=app.clock)
        for _ in range(3):
            snap = scheduler.next_scan(block=False)
            if snap is None:
                snap = app.cfg.snapshot()
            accepted, result = scan(app, monkeypatch, [], status='error')
            scheduler.completed(snap, accepted=accepted)
            assert accepted, 'completed error cycle must retain ordinary cadence'
            assert rows(app, 'baseline') == baseline
            assert rows(app, 'grace') == []
        assert app.current['test.example'] == {}
        assert not result.complete
        assert scheduler.next_scan(block=False) is None
    finally:
        app.delivery.stop()
