import json
import sqlite3

import pytest

from test_stage3_core_runtime import app_factory, rows, scan
from test_delivery_core_gap_authority import assert_exact_authority, control


@pytest.mark.parametrize('boundary,readback', [('before_commit', True), ('after_commit', True),
                                              ('before_commit', False), ('after_commit', False)])
def test_config_refresh_commit_resolution_then_real_observation(tmp_path, monkeypatch, boundary, readback):
    app = app_factory(tmp_path)
    try:
        scan(app, monkeypatch, ['1.2.3.4'])
        prior_cursor, prior_receipts = rows(app, 'cursor'), rows(app, 'receipt')
        prior_baseline = rows(app, 'baseline')
        store = app.delivery.store
        original_read = store._read_control
        fired = []
        def fail(point):
            if point == boundary and not fired:
                fired.append(point)
                raise sqlite3.OperationalError('fixture commit uncertainty')
        def unreadable():
            raise sqlite3.OperationalError('fixture independent read unavailable')
        store._fault = fail
        if not readback:
            monkeypatch.setattr(store, '_read_control', unreadable)
        result = app.service.commit('config', {'servers': ['replacement']}, expected_revision=0)
        assert fired == [boundary]
        committed = boundary == 'after_commit'
        assert control(app)['revision'] == (1 if committed else 0)
        assert rows(app, 'baseline') == prior_baseline
        assert rows(app, 'grace') == []
        assert rows(app, 'receipt') == prior_receipts
        if committed:
            assert rows(app, 'cursor')[0]['incarnation'] != prior_cursor[0]['incarnation']
            assert json.loads(rows(app, 'cursor')[0]['ips']) == []
        else:
            assert rows(app, 'cursor') == prior_cursor
        if committed and readback:
            assert result['warnings'] == []
            assert store.health_snapshot()['coverage'] == 'covered'
        else:
            assert result['warnings'] == ['delivery_configuration_refresh_failed']
            assert store.health_snapshot()['coverage'] == 'gap'
            assert not store.health_snapshot()['accounting_complete']
        store._fault = lambda point: None
        scan(app, monkeypatch, ['2.3.4.5'])
        assert app.current['test.example']['replacement']['values'] == ['2.3.4.5']
        assert json.loads((tmp_path / 'test.example.json').read_text())['current']['replacement']['values'] == ['2.3.4.5']
        if not readback:
            assert store.health_snapshot()['coverage'] == 'gap'
            assert store._unresolved is not None
            monkeypatch.setattr(store, '_read_control', original_read)
        scan(app, monkeypatch, ['2.3.4.5'])
        assert_exact_authority(app)
        assert store.health_snapshot()['coverage'] == 'covered'
        assert len(rows(app, 'receipt')) == (2 if committed and readback else 1)
        scan(app, monkeypatch, ['2.3.4.5', '3.4.5.6'])
        assert len(rows(app, 'receipt')) == (3 if committed and readback else 2)
    finally:
        app.delivery.stop()


def test_actual_sqlite_full_real_producer_and_delete_readd_recover_without_replay(tmp_path, monkeypatch):
    app = app_factory(tmp_path)
    try:
        scan(app, monkeypatch, ['1.2.3.4'])
        receipt = rows(app, 'receipt')
        store = app.delivery.store
        failures = []
        execute = store._execute
        def observed(sql, args=()):
            try:
                return execute(sql, args)
            except sqlite3.OperationalError as exc:
                failures.append(str(exc))
                raise
        monkeypatch.setattr(store, '_execute', observed)
        with store._lock:
            count = store._one('PRAGMA page_count')[0]
            store._execute('PRAGMA max_page_count=' + str(count))
        ips = ['10.0.0.' + str(i) for i in range(1, 200)]
        scan(app, monkeypatch, ips)
        assert any('full' in message.lower() for message in failures), failures
        assert app.current['test.example']['fake']['values'] == ips
        assert json.loads((tmp_path / 'test.example.json').read_text())['current']['fake']['values'] == ips
        assert rows(app, 'receipt') == receipt
        assert store.health_snapshot()['coverage'] == 'gap'
        result = app.service.commit('config', {'domains': []}, expected_revision=0)
        assert result['warnings'] == ['delivery_configuration_refresh_failed']
        assert app.current == {}
        assert rows(app, 'receipt') == receipt
        app.service.commit('config', {'domains': [{'name': 'test.example', 'type': 'A'}]}, expected_revision=1)
        with store._lock:
            store._execute('PRAGMA max_page_count=' + str(store.limits['pages']))
        scan(app, monkeypatch, ips)
        assert_exact_authority(app)
        assert store.health_snapshot()['coverage'] == 'covered'
        assert not store.health_snapshot()['accounting_complete']
        assert rows(app, 'receipt') == receipt
        scan(app, monkeypatch, ips)
        assert rows(app, 'receipt') == receipt
        assert store.health_snapshot()['missed_total'] >= len(ips)
    finally:
        app.delivery.stop()


@pytest.mark.parametrize('boundary', ['before_commit', 'after_commit'])
def test_real_source_unknown_commit_keeps_observing_and_resolves_once(tmp_path, monkeypatch, boundary):
    app = app_factory(tmp_path)
    try:
        store = app.delivery.store
        read = store._read_control
        fired = []
        def fail(point):
            if point == boundary and not fired:
                fired.append(point)
                raise sqlite3.OperationalError('fixture')
        store._fault = fail
        monkeypatch.setattr(store, '_read_control', lambda: (_ for _ in ()).throw(sqlite3.OperationalError('fixture')))
        scan(app, monkeypatch, ['1.2.3.4'])
        assert fired == [boundary]
        assert store._unresolved is not None
        assert app.current['test.example']['fake']['values'] == ['1.2.3.4']
        assert store.health_snapshot()['coverage'] == 'gap'
        assert store.health_snapshot()['missed_unpersisted'] == 0
        count = 1 if boundary == 'after_commit' else 0
        assert len(rows(app, 'receipt')) == count
        scan(app, monkeypatch, ['1.2.3.4'])
        assert len(rows(app, 'receipt')) == count
        monkeypatch.setattr(store, '_read_control', read)
        store._fault = lambda point: None
        scan(app, monkeypatch, ['1.2.3.4'])
        assert store._unresolved is None
        assert len(rows(app, 'receipt')) == count
        assert store.health_snapshot()['missed_total'] == 1 - count
        assert store.health_snapshot()['coverage'] == 'covered'
    finally:
        app.delivery.stop()
