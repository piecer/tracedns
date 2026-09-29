import threading

from monitor.runtime_state import state_lock
from test_stage3_core_runtime import app_factory, rows, scan
from test_delivery_core_gap_authority import control, assert_exact_authority


def test_refresh_linearizes_all_cursor_authority_without_holding_state_lock(tmp_path, monkeypatch):
    app = app_factory(tmp_path, current={'test.example': {'fake': {'values': ['1.2.3.4']}}})
    entered, release, state_free = threading.Event(), threading.Event(), threading.Event()
    errors = []
    writer = None
    try:
        prior_cursor, prior_baseline = rows(app, 'cursor'), rows(app, 'baseline')
        old_snapshot = app.cfg.snapshot()
        def barrier(point):
            if point == 'before_commit' and not entered.is_set():
                entered.set()
                assert release.wait(3)
        app.delivery.store._fault = barrier
        def commit():
            try:
                app.service.commit('config', {'servers': ['replacement'], 'domains': [
                    {'name': 'test.example', 'type': 'A'}, {'name': 'empty.example', 'type': 'A'}]}, expected_revision=0)
            except Exception as exc:
                errors.append(exc)
        writer = threading.Thread(target=commit)
        writer.start()
        assert entered.wait(2)
        def read_state():
            with state_lock():
                state_free.set()
        reader = threading.Thread(target=read_state)
        reader.start()
        assert state_free.wait(1), 'configuration SQL must not hold source state lock'
        reader.join(1)
        # Independent SQLite reader sees the full old committed view, not the
        # same-connection uncommitted replacement cursor/authority.
        assert control(app)['revision'] == 0
        assert rows(app, 'cursor') == prior_cursor
        assert rows(app, 'baseline') == prior_baseline
        assert not app.repo.valid(old_snapshot.target_leases['test.example'])
        release.set()
        writer.join(3)
        assert not writer.is_alive() and not errors
        assert_exact_authority(app)
        assert len(rows(app, 'cursor')) == 2
        assert rows(app, 'baseline') == prior_baseline
        assert rows(app, 'grace') == []
        from monitor.engine import CycleResult
        stale = CycleResult({}, {})
        stale.complete = True
        assert not app.delivery.complete(old_snapshot, stale)
        assert rows(app, 'baseline') == prior_baseline
        assert rows(app, 'grace') == []
        scan(app, monkeypatch, [])
        assert rows(app, 'grace')[0]['ip'] == '1.2.3.4'
    finally:
        release.set()
        if writer is not None:
            writer.join(3)
        app.delivery.stop()


def test_projection_budget_is_visible_and_reenrollment_never_backfills(tmp_path, monkeypatch):
    app = app_factory(tmp_path, limits={'cursor_targets': 1})
    try:
        app.service.commit('config', {'domains': [
            {'name': 'test.example', 'type': 'A'}, {'name': 'empty.example', 'type': 'A'}]}, expected_revision=0)
        assert_exact_authority(app)
        assert len(rows(app, 'cursor')) == 1
        assert not app.delivery.store.health_snapshot()['tracking_complete']
        assert not app.delivery.store.health_snapshot()['accounting_complete']
        scan(app, monkeypatch, ['1.2.3.4'])
        receipts = rows(app, 'receipt')
        app.service.commit('config', {'domains': [{'name': 'empty.example', 'type': 'A'}]}, expected_revision=1)
        assert len(rows(app, 'cursor')) == 1
        assert rows(app, 'cursor')[0]['target'] == 'empty.example'
        scan(app, monkeypatch, ['1.2.3.4'])
        assert rows(app, 'receipt') == receipts
        scan(app, monkeypatch, ['1.2.3.4', '2.3.4.5'])
        assert len(rows(app, 'receipt')) == len(receipts) + 1
    finally:
        app.delivery.stop()
