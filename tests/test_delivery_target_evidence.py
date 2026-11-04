"""Fresh provider evidence, full-only absence and configuration fencing."""
import json
import sqlite3

import pytest

from monitor import engine
from monitor.lookup_runtime import LookupRuntime
from test_delivery_target_recovery import collect_values, cursor
from test_lookup_liveness import owned_app, owned_scan
from test_stage3_core_runtime import app_factory, rows


def test_restart_partial_never_counts_retained_old_provider_as_fresh_loss(tmp_path, monkeypatch):
    config = {'domains': ['test.example'], 'servers': ['slow', 'healthy'],
              'alerts': {'teams_webhook': 'https://teams.invalid/hook'}}
    app = app_factory(tmp_path, config=config)
    app.delivery.store.close(clean=False)
    app = app_factory(tmp_path, config=config, current={'test.example': {
        'slow': {'type': 'A', 'values': ['192.0.2.90'], 'ts': 1}}})
    app.lookup = LookupRuntime(app.repo)
    monkeypatch.setattr(engine, 'collect_snapshot', lambda d, s: collect_values(
        d, s, None if s == 'slow' else ['192.0.2.1']))
    try:
        assert not owned_scan(app).complete
        assert app.delivery.store.health_snapshot()['missed_total'] == 1
        assert cursor(app, 'test.example')['addition_epoch'] != app.delivery.store._read_control()['addition_epoch']
        assert rows(app, 'receipt') == []
    finally:
        app.lookup.stop()
        app.delivery.stop()


@pytest.mark.parametrize('point', ['before_commit', 'after_commit'])
def test_absence_unknown_commit_keeps_ready_cursor_operations_and_resolves_once(tmp_path, monkeypatch, point):
    app = owned_app(tmp_path, servers=['healthy'])
    store = app.delivery.store
    monkeypatch.setattr(engine, 'collect_snapshot', lambda d, s: collect_values(d, s, []))
    read = store._read_control
    hits = []
    try:
        # Retained full baseline and pending removal belong to absence, not additions.
        store._put_grace('192.0.2.9', ['test.example'], app.clock() - 86400)
        store.enter_gap('delivery_storage', {})
        app.delivery.worker.run_pass(max_provider_calls=0)
        result = owned_scan(app)
        assert result.complete
        saved = rows(app, 'cursor')
        def fault(actual):
            if actual == point:
                hits.append(actual)
                raise sqlite3.OperationalError('owned absence fault')
        def unreadable():
            raise sqlite3.OperationalError('owned independent readback fault')
        store._fault, store._read_control = fault, unreadable
        snap = app.cfg.snapshot()
        assert app.delivery.complete(snap, result)
        assert hits == [point] and store._unresolved['kind'] == 'absence'
        assert rows(app, 'cursor') == saved
        committed = point == 'after_commit'
        control = json.loads(rows(app, 'control')[0]['data'])
        assert control['absence_pending'] == (not committed)
        assert control['missed_total'] == int(committed)
        for _ in range(2):
            store._monotonic = lambda: store._recovery_next
            app.delivery.worker.run_pass(max_provider_calls=0)
            assert store._unresolved is not None
            assert rows(app, 'cursor') == saved
        store._fault, store._read_control = lambda point: None, read
        store._monotonic = lambda: store._recovery_next
        app.delivery.worker.run_pass(max_provider_calls=0)
        assert store._unresolved is None
        assert rows(app, 'cursor') == saved
        assert store._rebaseline == (not committed), 'exact COMMIT must publish durable absence readiness once'
        assert app.delivery.complete(snap, result)
        assert rows(app, 'cursor') == saved
        assert store.health_snapshot()['coverage'] == 'covered'
        assert store.health_snapshot()['missed_total'] == 1
        assert rows(app, 'receipt') == rows(app, 'grace') == []
    finally:
        store._fault, store._read_control = lambda point: None, read
        app.lookup.stop()
        app.delivery.stop()


def test_failed_retirement_retries_current_authority_without_full_scan(tmp_path, monkeypatch):
    app = owned_app(tmp_path, domains=['a.example', 'b.example'], servers=['healthy'])
    monkeypatch.setattr(engine, 'collect_snapshot', lambda d, s: collect_values(d, s, ['192.0.2.1']))
    try:
        assert owned_scan(app).complete
        store = app.delivery.store
        prior = rows(app, 'receipt')
        store._execute('PRAGMA query_only=ON')
        changed = app.service.commit('config', {'domains': ['a.example']}, expected_revision=0)
        assert changed['warnings'] == ['delivery_configuration_refresh_failed']
        assert len(rows(app, 'cursor')) == 2
        store._execute('PRAGMA query_only=OFF')
        app.delivery.worker.run_pass(max_provider_calls=0)
        assert [r['target'] for r in rows(app, 'cursor')] == ['a.example']
        assert store._read_control()['revision'] == app.delivery.revision()
        assert rows(app, 'receipt') == prior
        assert store._read_control()['absence_pending']
    finally:
        app.delivery.store._execute('PRAGMA query_only=OFF')
        app.lookup.stop()
        app.delivery.stop()


def test_gap_rebase_consumes_only_returned_holds_and_preserves_other_deadlines(tmp_path, monkeypatch):
    app = owned_app(tmp_path, domains=['a.example', 'b.example'], servers=['healthy'],
        current={'a.example': {'healthy': {'type': 'A', 'values': ['192.0.2.1', '192.0.2.2'], 'ts': 1}}})
    store = app.delivery.store
    values = []
    monkeypatch.setattr(engine, 'collect_snapshot', lambda d, s: collect_values(
        d, s, values if d.name == 'a.example' else None))
    try:
        assert not owned_scan(app).complete
        baseline = rows(app, 'baseline')
        holds = {r['ip']: r for r in rows(app, 'reappearance')}
        assert set(holds) == {'192.0.2.1', '192.0.2.2'}
        store._execute('PRAGMA query_only=ON')
        values.append('192.0.2.1')
        assert not owned_scan(app).complete
        assert store.health_snapshot()['missed_unpersisted'] == 0
        store._execute('PRAGMA query_only=OFF')
        app.delivery.worker.run_pass(max_provider_calls=0)
        app.clock.now += 100
        assert not owned_scan(app).complete
        assert rows(app, 'reappearance') == [holds['192.0.2.2']]
        app.clock.now += 100
        values.clear()
        assert not owned_scan(app).complete
        latest = {r['ip']: r for r in rows(app, 'reappearance')}
        assert latest['192.0.2.2'] == holds['192.0.2.2']
        assert latest['192.0.2.1']['expires'] == app.clock() + 86400
        assert latest['192.0.2.1']['expires'] > holds['192.0.2.1']['expires']
        assert rows(app, 'receipt') == rows(app, 'grace') == []
        assert rows(app, 'baseline') == baseline
        assert store.health_snapshot()['missed_total'] == 0
    finally:
        store._execute('PRAGMA query_only=OFF')
        app.lookup.stop()
        app.delivery.stop()


def test_empty_generation_recovers_absence_only_from_real_complete_scan(tmp_path):
    app = owned_app(tmp_path, servers=['healthy'])
    store = app.delivery.store
    try:
        store.enter_gap('delivery_storage', {})
        app.service.commit('config', {'domains': []}, expected_revision=0)
        app.delivery.worker.run_pass(max_provider_calls=0)
        snap = app.cfg.snapshot()
        assert store._read_control()['absence_pending']
        app.delivery.complete(snap, {})
        assert store._read_control()['absence_pending'], 'plain mapping is not completed-generation evidence'
        result = owned_scan(app)
        assert result.complete and result.target_complete == {}
        assert app.delivery.complete(snap, result)
        assert store.health_snapshot()['coverage'] == 'covered'
        assert not store._read_control()['absence_pending']
        assert rows(app, 'cursor') == []
    finally:
        app.lookup.stop()
        app.delivery.stop()


def test_old_generation_full_and_config_only_never_certify_absence(tmp_path, monkeypatch):
    app = owned_app(tmp_path, servers=['healthy'])
    monkeypatch.setattr(engine, 'collect_snapshot', lambda d, s: collect_values(d, s, []))
    try:
        store = app.delivery.store
        store.enter_gap('delivery_storage', {})
        app.delivery.worker.run_pass(max_provider_calls=0)
        snap = app.cfg.snapshot()
        result = owned_scan(app)
        saved = rows(app, 'baseline'), rows(app, 'grace')
        app.service.commit('config', {'servers': ['replacement']}, expected_revision=0)
        assert not app.delivery.complete(snap, result)
        assert (rows(app, 'baseline'), rows(app, 'grace')) == saved
        assert store._read_control()['absence_pending']
        assert cursor(app, 'test.example')['addition_epoch'] != store._read_control()['addition_epoch']
        assert rows(app, 'receipt') == []
    finally:
        app.lookup.stop()
        app.delivery.stop()
