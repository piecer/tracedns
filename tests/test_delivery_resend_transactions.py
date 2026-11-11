"""Exact request readback and the existing SQLite uncertainty fence."""
import sqlite3
import pytest

from test_delivery_resend_vertical import rpc_app, preserved
from test_delivery_resend_admission import preview, confirm
from test_delivery_review_components import rows


@pytest.mark.parametrize('point,status,count', [('before_commit', 'not_queued', 0), ('after_commit', 'queued', 2)])
def test_commit_boundary_is_resolved_by_exact_durable_identity(tmp_path, monkeypatch, point, status, count):
    app, _, target = rpc_app(tmp_path, monkeypatch)
    runtime = app.delivery
    try:
        intent = preview(runtime, target)
        before = preserved(app)
        hit = []
        def fault(actual):
            if actual == point:
                hit.append(actual)
                raise OSError('fixture commit boundary')
        monkeypatch.setattr(runtime.store, '_fault', fault)
        result = confirm(runtime, intent)
        assert hit == [point]
        assert result['status'] == status
        assert len(rows(runtime.store, 'receipt')) == count
        assert len(rows(runtime.store, 'manual_resend')) == bool(count)
        assert preserved(app) == before
        if count:
            assert confirm(runtime, intent)['status'] == 'already_queued'
    finally:
        runtime.store._fault = lambda point: None
        runtime.stop()


@pytest.mark.parametrize('point', ['before_commit', 'after_commit'])
def test_unresolved_commit_never_reenters_admission_or_claims(tmp_path, monkeypatch, point):
    app, transport, target = rpc_app(tmp_path, monkeypatch)
    runtime = app.delivery
    try:
        intent = preview(runtime, target)
        before = preserved(app)
        read = runtime.store._read_control
        def blocked_read():
            raise sqlite3.OperationalError('fixture readback unavailable')
        def fault(actual):
            if actual == point:
                raise OSError('fixture commit error')
        monkeypatch.setattr(runtime.store, '_read_control', blocked_read)
        monkeypatch.setattr(runtime.store, '_fault', fault)
        assert confirm(runtime, intent)['status'] == 'unknown'
        assert runtime.store._unresolved is not None
        receipts = rows(runtime.store, 'receipt')
        assert len(receipts) == (2 if point == 'after_commit' else 0)
        assert confirm(runtime, intent)['status'] == 'unknown'
        assert not runtime.store.dispatch_available() and not transport.calls
        assert rows(runtime.store, 'receipt') == receipts
        assert preserved(app) == before
        monkeypatch.setattr(runtime.store, '_read_control', read)
        monkeypatch.setattr(runtime.store, '_fault', lambda point: None)
        resolved = confirm(runtime, intent)
        assert resolved['status'] == ('already_queued' if point == 'after_commit' else 'not_queued')
        assert runtime.store._unresolved is None
        assert rows(runtime.store, 'receipt') == receipts
    finally:
        runtime.store._fault = lambda point: None
        runtime.stop()


@pytest.mark.parametrize('readback_fault', ['unavailable', 'different_identity'])
def test_normal_commit_needs_exact_request_marker_readback(tmp_path, monkeypatch, readback_fault):
    app, _, target = rpc_app(tmp_path, monkeypatch)
    runtime = app.delivery
    try:
        intent = preview(runtime, target)
        read = runtime.store.read_resend
        def corrupted(token):
            row = read(token)
            if row is not None:
                if readback_fault == 'unavailable':
                    raise sqlite3.OperationalError('fixture marker unavailable')
                return {**row, 'actor_id': 'different-actor'}
            return row
        monkeypatch.setattr(runtime.store, 'read_resend', corrupted)
        result = confirm(runtime, intent)
        assert result['status'] == 'unknown' and result['reason'] == 'delivery_unknown'
        assert runtime.store._unresolved is not None
        assert len(rows(runtime.store, 'receipt')) == 2
        monkeypatch.setattr(runtime.store, 'read_resend', read)
        assert confirm(runtime, intent)['status'] == 'already_queued'
        assert runtime.store._unresolved is None
        assert len(rows(runtime.store, 'receipt')) == 2
    finally:
        runtime.stop()


def test_marker_persists_selected_binding_and_source_provenance(tmp_path, monkeypatch):
    app, _, target = rpc_app(tmp_path, monkeypatch)
    runtime = app.delivery
    try:
        import json
        intent = preview(runtime, target)
        bindings = runtime.bindings()
        assert confirm(runtime, intent)['status'] == 'queued'
        saved = json.loads(rows(runtime.store, 'manual_resend')[0]['source'])
        assert saved['target_identity'] == target and saved['revision'] == 0
        assert saved['bindings'] == bindings
        assert saved['source']['ips'] == ['192.0.2.10']
        assert len(saved['source']['digest']) == 64
        assert saved['incarnation'] == rows(runtime.store, 'cursor')[0]['incarnation']
    finally:
        runtime.stop()
