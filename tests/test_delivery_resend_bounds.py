"""Finite source frames, stable response shapes, and resource admission."""
import sqlite3
import pytest

from rpc_query import PROVIDER
from test_delivery_resend_vertical import rpc_app, preserved, STORAGE_TARGET
from test_delivery_resend_admission import preview, confirm
from test_delivery_resend_guards import CONFIRM_KEYS
from test_delivery_review_components import rows


@pytest.mark.parametrize('ips,reason', [([], 'no_managed_ips'), (['not-an-ip'], 'no_managed_ips'),
    (['192.0.2.10', 'not-an-ip'], 'no_managed_ips'),
    ([f'10.0.{i // 256}.{i % 256}' for i in range(257)], 'delivery_capacity')])
def test_empty_invalid_or_over_budget_source_never_truncates(tmp_path, monkeypatch, ips, reason):
    app, transport, target = rpc_app(tmp_path, monkeypatch)
    try:
        app.current[STORAGE_TARGET][PROVIDER]['decoded_ips'] = ips
        before = preserved(app)
        result = preview(app.delivery, target)
        assert result['status'] == 'not_ready' and result['reason'] == reason
        assert result['request_id'] is None and result['ips'] == []
        assert not rows(app.delivery.store, 'receipt')
        assert preserved(app) == before and not transport.calls
    finally:
        app.delivery.stop()


def test_exact_256_ip_boundary_is_not_truncated_and_real_batches_ack(tmp_path, monkeypatch):
    app, transport, target = rpc_app(tmp_path, monkeypatch)
    try:
        ips = [f'10.0.0.{i}' for i in range(256)]
        app.current[STORAGE_TARGET][PROVIDER]['decoded_ips'] = ips
        intent = preview(app.delivery, target, ['teams'])
        assert intent['status'] == 'ready' and intent['ips'] == sorted(ips)
        result = confirm(app.delivery, intent)
        assert result['status'] == 'queued' and result['receipt_count'] == 256
        assert len(rows(app.delivery.store, 'receipt')) == 256
        app.delivery.worker.run_pass()
        assert not rows(app.delivery.store, 'receipt')
        assert len(transport.calls) == 5  # Existing 60-item Teams batches.
    finally:
        app.delivery.stop()


def test_source_budget_refuses_before_deep_clone(tmp_path, monkeypatch):
    app, _, target = rpc_app(tmp_path, monkeypatch)
    try:
        class Unclonable(list):
            def __deepcopy__(self, memo):
                pytest.fail('unbounded source cloned')
        app.current[STORAGE_TARGET][PROVIDER]['rpc_record']['oversized'] = Unclonable(['x'] * 65537)
        result = preview(app.delivery, target)
        assert result['reason'] == 'delivery_capacity'
        assert not app.delivery._resend_coordinator().intents
    finally:
        app.delivery.stop()


@pytest.mark.parametrize('token', [None, '', 'a' * 31, 'A' * 32, 'a' * 33, ['a' * 32]])
def test_invalid_confirmation_token_is_closed_without_io(tmp_path, monkeypatch, token):
    app, _, _ = rpc_app(tmp_path, monkeypatch)
    try:
        monkeypatch.setattr(app.delivery.store, 'read_resend', lambda _: pytest.fail('invalid token read'))
        result = app.delivery.resend_target(token, actor_id='actor')
        assert set(result) == CONFIRM_KEYS
        assert result['status'] == 'not_queued' and result['reason'] == 'invalid_request'
        assert result['request_id'] is None
    finally:
        app.delivery.stop()


@pytest.mark.parametrize('status', ['error', 'uncertain'])
def test_failed_metadata_marks_last_good_even_without_target_progress(tmp_path, monkeypatch, status):
    app, _, target = rpc_app(tmp_path, monkeypatch)
    try:
        app.repo._targets[STORAGE_TARGET].lookup_uncertain = False
        app.repo._targets[STORAGE_TARGET].lookup_failed = False
        app.history[STORAGE_TARGET]['meta']['rpc_observation']['status'] = status
        result = preview(app.delivery, target)
        assert result['status'] == 'ready' and result['retained'] is True
    finally:
        app.delivery.stop()


def test_preview_reads_without_any_sql_or_source_writes(tmp_path, monkeypatch):
    app, _, target = rpc_app(tmp_path, monkeypatch)
    try:
        store = app.delivery.store
        before = preserved(app)
        changes = store._db.total_changes
        control = rows(store, 'control')
        assert preview(app.delivery, target)['status'] == 'ready'
        assert store._db.total_changes == changes
        assert rows(store, 'control') == control and preserved(app) == before
    finally:
        app.delivery.stop()


def test_storage_failure_before_admission_has_closed_result(tmp_path, monkeypatch):
    app, _, target = rpc_app(tmp_path, monkeypatch)
    try:
        intent = preview(app.delivery, target)
        original = app.delivery.store._one
        def unavailable(sql, args=()):
            if sql.startswith('SELECT MAX(created)'):
                raise sqlite3.OperationalError('fixture unavailable')
            return original(sql, args)
        monkeypatch.setattr(app.delivery.store, '_one', unavailable)
        result = confirm(app.delivery, intent)
        assert set(result) == CONFIRM_KEYS
        assert result['status'] == 'not_queued' and result['reason'] == 'delivery_storage'
        assert not rows(app.delivery.store, 'receipt') and not rows(app.delivery.store, 'manual_resend')
    finally:
        app.delivery.stop()


def test_readonly_capacity_probe_has_bounded_sql_work_at_full_ledger(tmp_path, monkeypatch):
    app, _, target = rpc_app(tmp_path, monkeypatch)
    store = app.delivery.store
    try:
        with store._lock:
            def seed():
                for index in range(255):
                    token = f'{index:032x}'
                    store._execute('INSERT INTO manual_resend VALUES(?,?,?,?,?,?,?,?)',
                        (token, 'actor', 'fixture-' + token, 1, '{}', '["misp"]', 1, 1))
                for index in range(4096):
                    store._execute('INSERT INTO receipt(operation,channel,binding,action,ip,payload,state,created,reserved) '
                        'VALUES(?,?,?,?,?,?,?,?,?)', ('manual:' + f'{index % 255:032x}', 'misp', '0' * 64,
                        'Added', '198.51.100.1', '{}', 'pending', 1, 1024))
            assert store._transaction('fixture-capacity', seed)[0]
        steps = [0]
        def count():
            steps[0] += 100
            return 0
        store._db.set_progress_handler(count, 100)
        try:
            result = preview(app.delivery, target)
        finally:
            store._db.set_progress_handler(None, 0)
        assert result['reason'] == 'delivery_capacity'
        assert steps[0] < 100000, steps[0]
    finally:
        app.delivery.stop()
