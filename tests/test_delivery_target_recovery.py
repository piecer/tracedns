"""Per-target recovery through owned collectors, repository and durable delivery."""
import json
import sqlite3
import threading

import pytest

from models import QueryResult, Snapshot
from monitor import engine
from monitor.collect import Collected
from test_lookup_liveness import owned_app, owned_scan
from test_stage3_core_runtime import rows
from test_lookup_liveness import background_scan, wait_for


def cursor(app, name):
    return next(row for row in rows(app, 'cursor') if row['target'] == name)


def collect_values(domain, server, ips):
    return Collected(QueryResult(server=server, domain=domain.name, rtype='A',
                                 status='error' if ips is None else 'ok', values=ips or []),
                     None if ips is None else Snapshot(type='A', values=list(ips), decoded_ips=[], ts=100000))


def test_healthy_target_rebases_then_admits_while_other_always_fails(tmp_path, monkeypatch):
    app = owned_app(tmp_path, domains=['a.example', 'b.example'], servers=['fixture'])
    store = app.delivery.store
    values = ['192.0.2.1']
    monkeypatch.setattr(engine, 'collect_snapshot', lambda d, s: collect_values(
        d, s, values if d.name == 'a.example' else None))
    monkeypatch.setattr(app.delivery, 'complete', lambda *a: (_ for _ in ()).throw(
        AssertionError('full completion is not target recovery authority')))
    try:
        baseline = rows(app, 'baseline')
        store._execute('PRAGMA query_only=ON')
        assert not owned_scan(app).complete
        assert app.current['a.example']['fixture']['values'] == values
        assert rows(app, 'receipt') == []
        assert store.health_snapshot()['missed_unpersisted'] == 1
        store._execute('PRAGMA query_only=OFF')
        app.delivery.worker.run_pass(max_provider_calls=0)
        assert store.dispatch_available()
        assert not owned_scan(app).complete
        first = cursor(app, 'a.example')
        assert json.loads(first['ips']) == values, 'fresh A must rebase independently of failed B'
        assert rows(app, 'receipt') == []
        values.append('192.0.2.2')
        assert not owned_scan(app).complete
        assert [r['ip'] for r in rows(app, 'receipt')] == ['192.0.2.2']
        assert cursor(app, 'b.example')['addition_epoch'] != cursor(app, 'a.example')['addition_epoch']
        assert store.health_snapshot()['missed_total'] == 1
        assert rows(app, 'baseline') == baseline and rows(app, 'grace') == []
        assert store.health_snapshot()['coverage'] == 'rebaselining'
    finally:
        store._execute('PRAGMA query_only=OFF')
        assert app.lookup.stop()['stopped']
        assert app.delivery.stop()['closed']
        with sqlite3.connect(store.path) as db:
            assert json.loads(db.execute('SELECT data FROM control').fetchone()[0])['clean'] is False


@pytest.mark.parametrize('empty', [False, True])
def test_target_boundary_precedes_other_target_finish_and_full_keeps_operations(tmp_path, monkeypatch, empty):
    app = owned_app(tmp_path, domains=['a.example', 'b.example'], servers=['fixture'])
    store = app.delivery.store
    release, entered = threading.Event(), threading.Event()
    values = [] if empty else ['192.0.2.1']
    def collect(domain, server):
        if domain.name == 'b.example':
            entered.set()
            assert release.wait(5)
        return collect_values(domain, server, values if domain.name == 'a.example' else [])
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    store.enter_gap('delivery_storage', {})
    app.delivery.worker.run_pass(max_provider_calls=0)
    epoch = store._read_control()['addition_epoch']
    thread, results, errors = background_scan(app)
    try:
        assert entered.wait(2)
        assert wait_for(lambda: cursor(app, 'a.example')['addition_epoch'] == epoch)
        assert rows(app, 'receipt') == []
        assert not release.is_set()
        release.set()
        thread.join(3)
        assert not thread.is_alive() and errors == []
        saved = rows(app, 'cursor')
        snap = app.cfg.snapshot()
        assert app.delivery.complete(snap, results[0])
        assert rows(app, 'cursor') == saved, 'absence rebase cannot reset accepted source operations'
        assert store.health_snapshot()['coverage'] == 'covered'
        values.append('192.0.2.2')
        assert owned_scan(app).complete
        assert [row['ip'] for row in rows(app, 'receipt')] == ['192.0.2.2']
    finally:
        release.set()
        thread.join(3)
        app.lookup.stop()
        app.delivery.stop()


def test_partial_fresh_evidence_cannot_rebase_cached_union_then_ready_partial_progresses(tmp_path, monkeypatch):
    app = owned_app(tmp_path, current={'test.example': {
        'slow': {'type': 'A', 'values': ['192.0.2.90'], 'ts': 1}}})
    store = app.delivery.store
    values = ['192.0.2.1']
    slow = None
    monkeypatch.setattr(engine, 'collect_snapshot', lambda d, s: collect_values(
        d, s, slow if s == 'slow' else values))
    try:
        store.enter_gap('delivery_storage', {})
        app.delivery.worker.run_pass(max_provider_calls=0)
        epoch = store._read_control()['addition_epoch']
        assert not owned_scan(app).complete
        assert cursor(app, 'test.example')['addition_epoch'] != epoch
        assert rows(app, 'receipt') == []
        assert store.health_snapshot()['missed_total'] == 1
        values.append('192.0.2.2')
        assert not owned_scan(app).complete
        assert store.health_snapshot()['missed_total'] == 2
        assert cursor(app, 'test.example')['addition_epoch'] != epoch
        slow = []
        assert owned_scan(app).complete
        assert cursor(app, 'test.example')['addition_epoch'] == epoch
        assert rows(app, 'receipt') == []
        slow = None
        values.append('192.0.2.3')
        assert not owned_scan(app).complete
        assert [r['ip'] for r in rows(app, 'receipt')] == ['192.0.2.3']
        assert store.health_snapshot()['missed_total'] == 2
    finally:
        app.lookup.stop()
        app.delivery.stop()


def test_unclean_start_uses_durable_cursor_not_newer_history(tmp_path, monkeypatch):
    from test_stage3_core_runtime import app_factory
    from monitor.lookup_runtime import LookupRuntime
    app = app_factory(tmp_path, current={'test.example': {'fake': {
        'type': 'A', 'values': ['192.0.2.1'], 'ts': 1}}})
    app.delivery.store.close(clean=False)
    newer = {'test.example': {'fake': {'type': 'A', 'values': ['192.0.2.2'], 'ts': 2}}}
    app = app_factory(tmp_path, current=newer)
    app.lookup = LookupRuntime(app.repo)
    values = ['192.0.2.2']
    monkeypatch.setattr(engine, 'collect_snapshot', lambda d, s: collect_values(d, s, values))
    try:
        assert owned_scan(app).complete
        assert rows(app, 'receipt') == [], 'restart must not replay observations ahead of durable cursor'
        assert app.delivery.store.health_snapshot()['missed_total'] == 1
        values.append('192.0.2.3')
        assert owned_scan(app).complete
        assert [r['ip'] for r in rows(app, 'receipt')] == ['192.0.2.3']
    finally:
        app.lookup.stop()
        app.delivery.stop()


def test_unrelated_config_and_clean_restart_preserve_ready_target_while_absence_pending(tmp_path, monkeypatch):
    app = owned_app(tmp_path, domains=['a.example', 'b.example'], servers=['fixture'])
    values = ['192.0.2.1']
    monkeypatch.setattr(engine, 'collect_snapshot', lambda d, s: collect_values(
        d, s, values if d.name == 'a.example' else None))
    try:
        app.delivery.store.enter_gap('delivery_storage', {})
        app.delivery.worker.run_pass(max_provider_calls=0)
        assert not owned_scan(app).complete
        saved = cursor(app, 'a.example')
        result = app.service.commit('config', {'interval': 81}, expected_revision=0)
        assert result['warnings'] == []
        assert cursor(app, 'a.example') == saved
        config, current = app.cfg.raw.copy(), app.current.copy()
        assert app.lookup.stop()['stopped']
        assert app.delivery.stop()['closed']
        from test_stage3_core_runtime import app_factory
        from monitor.lookup_runtime import LookupRuntime
        app = app_factory(tmp_path, config=config, current=current)
        app.lookup = LookupRuntime(app.repo)
        assert cursor(app, 'a.example') == saved
        assert app.delivery.store._read_control()['addition_epoch'] == saved['addition_epoch']
        assert app.delivery.store.health_snapshot()['coverage'] == 'rebaselining'
        values.append('192.0.2.2')
        assert not owned_scan(app).complete
        assert [r['ip'] for r in rows(app, 'receipt')] == ['192.0.2.2']
    finally:
        app.lookup.stop()
        app.delivery.stop()
