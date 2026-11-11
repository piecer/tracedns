"""Closed preview inputs and original source ownership are admission gates."""
from copy import deepcopy
import pytest

from rpc_query import PROVIDER
from test_delivery_resend_vertical import rpc_app, preserved, STORAGE_TARGET
from test_delivery_review_components import rows


PREVIEW_KEYS = {'status', 'reason', 'request_id', 'target', 'source_type', 'ips', 'observed_at',
                'retained', 'channels', 'expires_in_seconds', 'retry_after'}
CONFIRM_KEYS = {'status', 'reason', 'request_id', 'ip_count', 'receipt_count', 'channels', 'retry_after'}


@pytest.mark.parametrize('field,value', [
    ('target', None), ('target', ''), ('target', 'x' * 1025),
    ('channels', []), ('channels', ['teams', 'teams']), ('channels', ['smtp']),
    ('channels', 'teams'), ('channels', [['teams']]),
    ('revision', True), ('revision', -1), ('revision', 2**53), ('revision', 0.0),
    ('actor_id', None), ('actor_id', ''), ('actor_id', 'x' * 129),
])
def test_invalid_preview_is_closed_and_effect_free(tmp_path, monkeypatch, field, value):
    app, transport, target = rpc_app(tmp_path, monkeypatch)
    try:
        before = preserved(app)
        args = {'target': target, 'channels': ['teams'], 'revision': 0, 'actor_id': 'actor'}
        args[field] = value
        result = app.delivery.preview_resend(args['target'], args['channels'], args['revision'],
                                            actor_id=args['actor_id'])
        assert set(result) == PREVIEW_KEYS
        assert result['status'] == 'not_ready' and result['reason'] == 'invalid_request'
        assert result['request_id'] is None and result['ips'] == []
        assert not rows(app.delivery.store, 'manual_resend')
        assert preserved(app) == before and not transport.calls
    finally:
        app.delivery.stop()


@pytest.mark.parametrize('change,reason', [
    ('ips', 'snapshot_changed'), ('timestamp', 'snapshot_changed'), ('meta', 'snapshot_changed'),
    ('version', 'snapshot_changed'), ('generation', 'snapshot_changed'),
    ('incarnation', 'snapshot_changed'), ('revision', 'configuration_changed'),
    ('removed', 'target_not_found'), ('stopped', 'runtime_unavailable'),
    ('unapplied', 'destination_unavailable'), ('expired', 'preview_expired'),
])
def test_confirmation_revalidates_original_preview(tmp_path, monkeypatch, change, reason):
    app, transport, target = rpc_app(tmp_path, monkeypatch)
    runtime = app.delivery
    try:
        preview = runtime.preview_resend(target, ['teams', 'misp'], 0, actor_id='actor')
        if change == 'ips':
            app.current[STORAGE_TARGET][PROVIDER]['decoded_ips'] = ['192.0.2.88']
        elif change == 'timestamp':
            app.current[STORAGE_TARGET][PROVIDER]['ts'] += 1
        elif change == 'meta':
            app.history[STORAGE_TARGET]['meta']['rpc_observation']['status'] = 'error'
        elif change == 'version':
            app.repo._targets[STORAGE_TARGET].version += 1
        elif change == 'generation':
            app.repo.generation += 1
        elif change == 'incarnation':
            app.repo._targets[STORAGE_TARGET].active = False
            app.repo._targets[STORAGE_TARGET] = deepcopy(app.repo._targets[STORAGE_TARGET])
            app.repo._targets[STORAGE_TARGET].active = True
        elif change == 'revision':
            app.cfg.raw['config_revision'] = 1
        elif change == 'removed':
            app.repo._targets.pop(STORAGE_TARGET).active = False
        elif change == 'stopped':
            runtime.stopping = True
        elif change == 'unapplied':
            runtime._pending_bindings = runtime.bindings()
        else:
            coordinator = runtime._resend_coordinator()
            monkeypatch.setattr(coordinator, 'monotonic', lambda: coordinator.intents[preview['request_id']].deadline)
        before = preserved(app)
        result = runtime.resend_target(preview['request_id'], actor_id='actor')
        assert set(result) == CONFIRM_KEYS
        assert (result['status'], result['reason']) == ('not_queued', reason)
        assert result['receipt_count'] == 0
        assert not rows(runtime.store, 'manual_resend') and not rows(runtime.store, 'receipt')
        assert preserved(app) == before and not transport.calls
    finally:
        runtime.stop()


def test_preview_capacity_and_monotonic_expiry_do_not_evict_live_tokens(tmp_path, monkeypatch):
    app, _, target = rpc_app(tmp_path, monkeypatch)
    runtime = app.delivery
    try:
        coordinator = runtime._resend_coordinator()
        now = [50.0]
        monkeypatch.setattr(coordinator, 'monotonic', lambda: now[0])
        previews = [runtime.preview_resend(target, ['teams'], 0, actor_id='actor') for _ in range(128)]
        assert all(p['status'] == 'ready' for p in previews)
        assert runtime.preview_resend(target, ['teams'], 0, actor_id='actor')['reason'] == 'preview_capacity'
        now[0] = 350.0
        assert runtime.resend_target(previews[0]['request_id'], actor_id='actor')['reason'] == 'preview_expired'
        assert runtime.preview_resend(target, ['teams'], 0, actor_id='actor')['status'] == 'ready'
        assert len(coordinator.intents) == 1
        assert not rows(runtime.store, 'receipt')
    finally:
        runtime.stop()


@pytest.mark.parametrize('phase', ['before_admission', 'before_commit'])
def test_final_guard_fences_source_change_during_admission(tmp_path, monkeypatch, phase):
    app, _, target = rpc_app(tmp_path, monkeypatch)
    runtime = app.delivery
    try:
        preview = runtime.preview_resend(target, ['teams', 'misp'], 0, actor_id='actor')
        def change():
            app.current[STORAGE_TARGET][PROVIDER]['decoded_ips'] = ['192.0.2.90']
        if phase == 'before_commit':
            monkeypatch.setattr(runtime.store, '_fault', lambda point: change() if point == phase else None)
        else:
            original = runtime.store.admit_resend
            def delayed(*args, **kwargs):
                change()
                return original(*args, **kwargs)
            monkeypatch.setattr(runtime.store, 'admit_resend', delayed)
        result = runtime.resend_target(preview['request_id'], actor_id='actor')
        assert result['status'] == 'not_queued' and result['reason'] == 'snapshot_changed'
        assert not rows(runtime.store, 'receipt') and not rows(runtime.store, 'manual_resend')
    finally:
        runtime.store._fault = lambda point: None
        runtime.stop()
