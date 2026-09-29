import json
import os
import stat

from test_stage3_core_runtime import app_factory, rows, scan
from test_delivery_adapters_steps import Response, Transport


def test_history_diagnostic_is_sticky_through_saved_uncertain_ack_and_storage_recovery(tmp_path, monkeypatch):
    app = app_factory(tmp_path, transport=Transport(Response(status=200)))
    try:
        original = app.repo.commit_history
        monkeypatch.setattr(app.repo, 'commit_history', lambda *a: (_ for _ in ()).throw(OSError('fixture')))
        for _ in range(2):
            scan(app, monkeypatch, ['1.2.3.4'])
            assert app.delivery.history_persistence == 'failed'
            health = app.delivery.store.health_snapshot()
            assert health['last_error'] == 'history_persistence'
            assert health['coverage'] == 'covered'
            assert health['storage_ok']
            assert health['missed_total'] == 0
        assert len(rows(app, 'receipt')) == 1
        monkeypatch.setattr(app.repo, 'commit_history', original)
        scan(app, monkeypatch, ['1.2.3.4'])
        assert app.delivery.history_persistence == 'saved'
        assert json.loads((tmp_path / 'test.example.json').read_text())['current']['fake']['values'] == ['1.2.3.4']
        app.delivery.worker.run_pass()
        assert app.delivery.store.health_snapshot()['acked_total'] == 1
        assert app.delivery.store.health_snapshot()['last_error'] == 'history_persistence'
        fsync = os.fsync
        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError('fixture')
            fsync(fd)
        with monkeypatch.context() as mp:
            mp.setattr(os, 'fsync', fail_directory)
            scan(app, mp, ['1.2.3.4'])
        assert app.delivery.history_persistence == 'uncertain'
        assert app.delivery.store.health_snapshot()['last_error'] == 'history_persistence'
        app.delivery.store.enter_gap('delivery_storage', {})
        app.delivery.store.note_history_failure()
        assert app.delivery.store.health_snapshot()['last_error'] == 'delivery_storage'
        scan(app, monkeypatch, ['1.2.3.4'])
        health = app.delivery.store.health_snapshot()
        assert health['coverage'] == 'covered'
        assert health['last_error'] == 'history_persistence'
        assert not health['accounting_complete']
        assert health['acked_total'] == 1
        assert rows(app, 'receipt') == []
    finally:
        app.delivery.stop()


def test_history_diagnostic_never_masks_failed_recovery_health_refresh(tmp_path, monkeypatch):
    import sqlite3
    app = app_factory(tmp_path)
    try:
        app.delivery.store.note_history_failure()
        app.delivery.store.enter_gap('delivery_storage', {})
        one = app.delivery.store._one
        def fail_health(sql, args=()):
            if sql.startswith('SELECT COUNT(*),COALESCE(SUM(reserved),0),MIN(created)'):
                raise sqlite3.OperationalError('fixture health read failure')
            return one(sql, args)
        recovered_health = []
        recover = app.delivery.store.recover_gap
        def recovery(*args, **kwargs):
            result = recover(*args, **kwargs)
            recovered_health.append(app.delivery.store.health_snapshot())
            return result
        with monkeypatch.context() as mp:
            mp.setattr(app.delivery.store, '_one', fail_health)
            mp.setattr(app.delivery.store, 'recover_gap', recovery)
            scan(app, mp, [])
            assert recovered_health[0]['last_error'] == 'delivery_storage'
            health = app.delivery.store.health_snapshot()
            assert not health['storage_ok'] and health['counts_stale']
            assert health['last_error'] == 'delivery_storage'
        scan(app, monkeypatch, [])
        assert app.delivery.store.health_snapshot()['last_error'] == 'history_persistence'
    finally:
        app.delivery.stop()
