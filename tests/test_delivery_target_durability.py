"""Durable epoch migration, unknown outcomes and evidence authority."""
import json
import sqlite3

import pytest

from monitor import engine
from test_delivery_store_atomic import AUTH, BINDINGS, obs, rows as ledger_rows, store_at
from test_delivery_store_tracking import projection
from test_delivery_target_recovery import collect_values, cursor
from test_lookup_liveness import owned_app, owned_scan
from test_stage3_core_runtime import rows


def test_schema_one_epoch_migration_preserves_clean_legacy_rows_and_capacity(tmp_path):
    store = store_at(tmp_path, limits={'cursor_targets': 1})
    store.bootstrap(projection(['192.0.2.1']), {}, AUTH)
    store.close(clean=True)
    with sqlite3.connect(store.path) as db:
        db.execute('ALTER TABLE cursor DROP COLUMN addition_epoch')
        control = json.loads(db.execute('SELECT data FROM control').fetchone()[0])
        for key in ('addition_epoch', 'absence_pending', 'session_closed', 'restart_rebaseline'):
            control.pop(key, None)
        db.execute('UPDATE control SET data=?', (json.dumps(control),))
    old = ledger_rows(tmp_path, 'cursor')
    marker = store.path.with_name('delivery.initialized').read_bytes()
    store = store_at(tmp_path, limits={'cursor_targets': 1})
    try:
        assert store.bootstrap(projection(['192.0.2.1']), {}, AUTH)['ready']
        current = ledger_rows(tmp_path, 'cursor')[0]
        assert current.pop('addition_epoch') == ''
        assert current == old[0]
        assert store._read_control()['schema'] == 1
        assert store.path.with_name('delivery.initialized').read_bytes() == marker
        assert store.record_domain(obs(['192.0.2.1', '192.0.2.2']), AUTH, BINDINGS)['admitted_receipts'] == 1
        store.enter_gap('delivery_storage', {})
        assert store.recover_delivery(100)['state'] == 'ready'
        fresh = obs(['192.0.2.3'], target='other.example', target_complete=True,
                    fresh_positive_ips=['192.0.2.3'])
        assert store.record_domain(fresh, AUTH, BINDINGS)['admitted_receipts'] == 0
        assert len(ledger_rows(tmp_path, 'cursor')) == 1
        assert not store.health_snapshot()['tracking_complete']
    finally:
        store.close(clean=True)


def test_overflow_target_needs_complete_evidence_before_ready_and_epoch_bytes_are_charged(tmp_path):
    store = store_at(tmp_path, limits={'target_ips': 1})
    store.bootstrap(projection(['192.0.2.1', '192.0.2.2']), {}, AUTH)
    try:
        candidate = obs(['192.0.2.1'], before_ips=['192.0.2.1', '192.0.2.2'],
                        target_complete=False, fresh_positive_ips=['192.0.2.1'])
        assert store.record_domain(candidate, AUTH, BINDINGS)['admitted_receipts'] == 0
        row = ledger_rows(tmp_path, 'cursor')[0]
        assert row['addition_epoch'] != store._read_control()['addition_epoch']
        candidate = obs(['192.0.2.1'], target_complete=True, fresh_positive_ips=['192.0.2.1'])
        assert store.record_domain(candidate, AUTH, BINDINGS)['admitted_receipts'] == 0
        store.enter_gap('delivery_storage', {})
        store.recover_delivery(100)
        store.record_domain(candidate | {'source_operation_id': 'new-boundary'}, AUTH, BINDINGS)
        row = ledger_rows(tmp_path, 'cursor')[0]
        assert row['bytes'] == sum(len(row[k].encode()) for k in ('target', 'signature', 'ips', 'addition_epoch'))
    finally:
        store.close(clean=True)


@pytest.mark.parametrize('field,value', [('addition_epoch', None), ('addition_epoch', 'wrong'),
                                         ('absence_pending', 'false'), ('restart_rebaseline', 1),
                                         ('session_closed', 1)])
def test_unknown_readback_rejects_malformed_recovery_control(tmp_path, monkeypatch, field, value):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    read = store._read_control
    try:
        store.enter_gap('delivery_storage', {})
        def fault(point):
            if point == 'after_commit':
                raise sqlite3.OperationalError('owned uncertain recovery')
        def unreadable():
            raise sqlite3.OperationalError('owned unreadable control')
        store._fault, store._read_control = fault, unreadable
        assert store.recover_delivery(100)['state'] == 'failed'
        saved = ledger_rows(tmp_path, 'control')
        store._fault = lambda point: None
        store._read_control = lambda: {**read(), field: value}
        store._monotonic = lambda: store._recovery_next
        assert store.recover_delivery(100)['state'] == 'uncertain'
        assert ledger_rows(tmp_path, 'control') == saved
        assert store._unresolved is not None and not store.dispatch_available()
        store._read_control = read
        assert store.recover_delivery(100)['state'] == 'ready'
    finally:
        store._fault, store._read_control = lambda point: None, read
        store.close(clean=False)


@pytest.mark.parametrize('point', ['before_commit', 'after_commit'])
def test_process_death_at_target_rebase_keeps_atomic_epoch_and_no_replay(tmp_path, monkeypatch, point):
    import os
    from pathlib import Path
    import subprocess
    import sys
    from test_stage3_core_runtime import app_factory
    from monitor.lookup_runtime import LookupRuntime
    root = Path(__file__).resolve().parents[1]
    code = '''
import os, sys
from pathlib import Path
from unittest.mock import patch
from monitor import engine
from test_lookup_liveness import owned_app, owned_scan
from test_delivery_target_recovery import collect_values
assert Path(engine.__file__).resolve().parents[1] == Path(sys.argv[3])
app = owned_app(Path(sys.argv[1]), servers=['healthy'])
store = app.delivery.store
store.enter_gap('delivery_storage', {})
app.delivery.worker.run_pass(max_provider_calls=0)
record = store.record_domain
def boundary(value, *args, **kwargs):
    if value['target_complete']:
        store._fault = lambda point: os._exit(23) if point == sys.argv[2] else None
    return record(value, *args, **kwargs)
store.record_domain = boundary
with patch.object(engine, 'collect_snapshot', lambda d, s: collect_values(d, s, ['192.0.2.1'])):
    owned_scan(app)
os._exit(99)
'''
    env = {**os.environ, 'PYTHONPATH': str(root) + ':' + str(root / 'tests'), 'PYTHONDONTWRITEBYTECODE': '1'}
    result = subprocess.run([sys.executable, '-c', code, str(tmp_path), point, str(root)],
                            cwd=root, env=env, capture_output=True, timeout=15)
    assert result.returncode == 23, result.stderr.decode()
    prior = ledger_rows(tmp_path, 'cursor')[0]
    control = json.loads(ledger_rows(tmp_path, 'control')[0]['data'])
    assert (prior['addition_epoch'] == control['addition_epoch']) == (point == 'after_commit')
    assert ledger_rows(tmp_path, 'receipt') == []
    config = {'domains': ['test.example'], 'servers': ['healthy'],
              'alerts': {'teams_webhook': 'https://teams.invalid/hook'}}
    app = app_factory(tmp_path, config=config)
    app.lookup = LookupRuntime(app.repo)
    values = ['192.0.2.1']
    monkeypatch.setattr(engine, 'collect_snapshot', lambda d, s: collect_values(d, s, values))
    try:
        assert owned_scan(app).complete
        assert rows(app, 'receipt') == []
        assert app.delivery.store.health_snapshot()['missed_total'] == 1
        values.append('192.0.2.2')
        assert owned_scan(app).complete
        assert [r['ip'] for r in rows(app, 'receipt')] == ['192.0.2.2']
    finally:
        app.lookup.stop()
        app.delivery.stop()


def test_required_provider_subset_never_completes_pending_target(tmp_path, monkeypatch):
    app = owned_app(tmp_path)
    store = app.delivery.store
    monkeypatch.setattr(engine, 'collect_snapshot', lambda d, s: collect_values(d, s, ['192.0.2.1']))
    try:
        store.enter_gap('delivery_storage', {})
        app.delivery.worker.run_pass(max_provider_calls=0)
        snap = app.cfg.snapshot()
        force = {'domains': snap.domains, 'servers': ['healthy'],
                 '_target_leases': snap.target_leases, '_registry_view': snap.registry_view}
        result = owned_scan(app, force_req=force)
        assert result.positive == {'192.0.2.1': {'test.example'}}
        assert cursor(app, 'test.example')['addition_epoch'] != store._read_control()['addition_epoch']
        assert rows(app, 'receipt') == []
        assert owned_scan(app).complete
        assert cursor(app, 'test.example')['addition_epoch'] == store._read_control()['addition_epoch']
    finally:
        app.lookup.stop()
        app.delivery.stop()


@pytest.mark.parametrize('point', ['before_commit', 'after_commit'])
@pytest.mark.parametrize('readable', [False, True])
def test_target_boundary_commit_consumption_and_accounting(tmp_path, monkeypatch, point, readable):
    app = owned_app(tmp_path, servers=['healthy'])
    store = app.delivery.store
    values = ['192.0.2.1']
    monkeypatch.setattr(engine, 'collect_snapshot', lambda d, s: collect_values(d, s, values))
    read, record = store._read_control, store.record_domain
    hits, operations = [], []
    def fault(actual):
        if actual == point:
            hits.append(actual)
            raise sqlite3.OperationalError('owned target boundary fault')
    def unreadable():
        raise sqlite3.OperationalError('owned independent readback fault')
    def boundary(observation, *args, **kwargs):
        if observation['target_complete'] and not hits:
            operations.append(observation['source_operation_id'])
            store._fault = fault
            if not readable:
                store._read_control = unreadable
        try:
            return record(observation, *args, **kwargs)
        finally:
            store._fault = lambda point: None
    try:
        store.enter_gap('delivery_storage', {})
        app.delivery.worker.run_pass(max_provider_calls=0)
        epoch = store._read_control()['addition_epoch']
        monkeypatch.setattr(store, 'record_domain', boundary)
        owned_scan(app)
        assert hits == [point]
        committed = point == 'after_commit'
        assert (cursor(app, 'test.example')['operation'] == operations[0]) == committed
        assert rows(app, 'receipt') == []
        saved = rows(app, 'cursor')
        if not readable:
            for _ in range(2):
                store._monotonic = lambda: store._recovery_next
                app.delivery.worker.run_pass(max_provider_calls=0)
                assert store._unresolved is not None
                assert rows(app, 'cursor') == saved
        store._read_control = read
        store._monotonic = lambda: store._recovery_next
        app.delivery.worker.run_pass(max_provider_calls=0)
        assert store._unresolved is None
        assert store._read_control()['addition_epoch'] == epoch, 'pending target failure must not invalidate ready peers'
        if committed:
            assert cursor(app, 'test.example')['operation'] == operations[0]
        else:
            assert owned_scan(app).complete
        values.append('192.0.2.2')
        assert owned_scan(app).complete
        assert [r['ip'] for r in rows(app, 'receipt')] == ['192.0.2.2']
        assert store.health_snapshot()['missed_total'] == 1
    finally:
        store._fault = lambda point: None
        store._read_control = read
        app.lookup.stop()
        app.delivery.stop()
