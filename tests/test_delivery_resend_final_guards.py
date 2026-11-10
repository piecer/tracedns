"""Final publication checks and original automatic-failure proof isolation."""
import json
import pytest

from test_delivery_resend_vertical import rpc_app, preserved, STORAGE_TARGET
from test_delivery_resend_admission import preview, confirm
from test_delivery_review_components import rows, Response


def test_rpc_successful_current_evidence_is_not_mislabelled_as_failed(tmp_path, monkeypatch):
    app, _, target = rpc_app(tmp_path, monkeypatch)
    try:
        lease = app.repo.capture()[STORAGE_TARGET]
        app.repo.lookup_target_progress(lease, complete=True, accepted=True, successful=True)
        result = preview(app.delivery, target)
        assert result['status'] == 'ready' and result['retained'] is False
    finally:
        app.delivery.stop()


def test_original_preview_deadline_is_checked_after_final_source_read(tmp_path, monkeypatch):
    app, _, target = rpc_app(tmp_path, monkeypatch)
    runtime = app.delivery
    try:
        coordinator = runtime._resend_coordinator()
        now = [100.0]
        monkeypatch.setattr(coordinator, 'monotonic', lambda: now[0])
        intent = preview(runtime, target)
        source = coordinator.source
        final_read = [False]
        def delayed(lease):
            value = source(lease)
            if final_read[0]:
                now[0] = 400.0
            return value
        monkeypatch.setattr(coordinator, 'source', delayed)
        monkeypatch.setattr(runtime.store, '_fault', lambda point: final_read.__setitem__(0, point == 'before_commit'))
        result = confirm(runtime, intent)
        assert result['status'] == 'not_queued' and result['reason'] == 'preview_expired'
        assert final_read[0]
        assert not rows(runtime.store, 'receipt') and not rows(runtime.store, 'manual_resend')
    finally:
        runtime.store._fault = lambda point: None
        runtime.stop()


@pytest.mark.parametrize('field,value', [('ip_count', 257), ('receipt_count', 513),
                                       ('channels', '["smtp"]'), ('source', '{}')])
def test_invalid_durable_marker_never_escapes_closed_contract(tmp_path, monkeypatch, field, value):
    app, _, target = rpc_app(tmp_path, monkeypatch)
    runtime = app.delivery
    try:
        intent = preview(runtime, target)
        assert confirm(runtime, intent)['status'] == 'queued'
        read = runtime.store.read_resend
        monkeypatch.setattr(runtime.store, 'read_resend', lambda token: {**read(token), field: value})
        result = confirm(runtime, intent)
        assert result['status'] == 'unknown' and result['reason'] == 'delivery_unknown'
        assert result['ip_count'] == result['receipt_count'] == 0
        assert result['channels'] == []
    finally:
        runtime.stop()


@pytest.mark.parametrize('status', [200, 400])
def test_manual_terminal_cannot_modify_existing_automatic_failed_proof(tmp_path, monkeypatch, status):
    app, transport, target = rpc_app(tmp_path, monkeypatch)
    runtime, store = app.delivery, app.delivery.store
    try:
        cursor = rows(store, 'cursor')[0]
        binding = next(b for b in runtime.bindings() if b['channel'] == 'teams')
        with store._lock:
            def failed_automatic():
                store._admit([['192.0.2.10', STORAGE_TARGET, 'RPC']], [binding], 'automatic-fixture',
                    'Added', app.clock(), source=(STORAGE_TARGET, cursor['incarnation'], cursor['signature']))
                row = store._one("SELECT * FROM receipt WHERE operation='automatic-fixture'")
                store._terminal(row, 'failed', 'attempts_exhausted', app.clock())
            assert store._transaction('fixture-failure', failed_automatic)[0]
        assert len(rows(store, 'failed_addition')) == 1
        before = preserved(app)
        transport.callback = lambda method, url, kwargs: Response(status=status)
        intent = preview(runtime, target, ['teams'])
        assert confirm(runtime, intent)['status'] == 'queued'
        runtime.worker.run_pass()
        assert not rows(store, 'receipt')
        assert preserved(app) == before
        metadata = json.loads(rows(store, 'manual_resend')[0]['source'])
        assert metadata['source']['ips'] == ['192.0.2.10']
    finally:
        runtime.stop()
