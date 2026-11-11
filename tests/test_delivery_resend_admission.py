"""All-or-none manual admission, durable limits and immutable provider fences."""
from copy import deepcopy
import pytest

from monitor.delivery_types import encode
from test_delivery_resend_vertical import rpc_app, preserved, STORAGE_TARGET
from test_delivery_review_components import rows, Response
from test_stage3_core_runtime import app_factory


def preview(runtime, target, channels=None):
    return runtime.preview_resend(target, channels or ['teams', 'misp'], runtime.revision(), actor_id='actor')


def confirm(runtime, value):
    return runtime.resend_target(value['request_id'], actor_id='actor')


def test_cooldown_is_per_target_across_channels_and_restart_then_pending_blocks(tmp_path, monkeypatch):
    app, transport, target = rpc_app(tmp_path, monkeypatch)
    runtime = app.delivery
    try:
        one, two = preview(runtime, target, ['teams']), preview(runtime, target, ['misp'])
        assert confirm(runtime, one)['status'] == 'queued'
        assert confirm(runtime, two)['reason'] == 'resend_cooldown'
        refused = preview(runtime, target, ['misp'])
        assert refused['reason'] == 'resend_cooldown' and refused['retry_after'] == 30
        config = {k: deepcopy(app.cfg.raw[k]) for k in ('domains', 'servers', 'alerts', 'config_revision')}
        current = deepcopy(app.current)
        assert runtime.stop()['closed']
        successor = app_factory(tmp_path, config=config, current=current, clock=app.clock, transport=transport)
        try:
            assert preview(successor.delivery, target, ['misp'])['reason'] == 'resend_cooldown'
            app.clock.now += 30
            assert preview(successor.delivery, target, ['teams'])['reason'] == 'delivery_pending'
            assert preview(successor.delivery, target, ['misp'])['status'] == 'ready'
            assert len(rows(successor.delivery.store, 'receipt')) == 1
        finally:
            successor.delivery.stop()
    finally:
        runtime.stop()


@pytest.mark.parametrize('limit,value', [('receipts', 1), ('payload_bytes', 1), ('unit_bytes', 1), ('batch_bytes', 1)])
def test_capacity_refuses_all_selected_channels_without_losses(tmp_path, monkeypatch, limit, value):
    app, transport, target = rpc_app(tmp_path, monkeypatch)
    runtime = app.delivery
    try:
        intent = preview(runtime, target)
        runtime.store.limits[limit] = value
        before = preserved(app)
        losses = runtime.store.health_snapshot()['missed_total']
        result = confirm(runtime, intent)
        assert result['status'] == 'not_queued' and result['reason'] == 'delivery_capacity'
        assert not rows(runtime.store, 'receipt') and not rows(runtime.store, 'manual_resend')
        assert runtime.store.health_snapshot()['missed_total'] == losses
        assert preserved(app) == before and not transport.calls
    finally:
        runtime.stop()


def test_renderer_failure_is_rejection_not_partial_or_terminal_admission(tmp_path, monkeypatch):
    app, _, target = rpc_app(tmp_path, monkeypatch)
    runtime = app.delivery
    try:
        intent = preview(runtime, target)
        def unavailable(*args):
            raise RuntimeError('private provider details must not escape')
        monkeypatch.setattr(runtime.store, '_render', unavailable)
        before = preserved(app)
        result = confirm(runtime, intent)
        assert (result['status'], result['reason']) == ('not_queued', 'delivery_storage')
        assert not rows(runtime.store, 'receipt') and not rows(runtime.store, 'manual_resend')
        assert preserved(app) == before
    finally:
        runtime.stop()


def test_pending_automatic_receipt_blocks_manual_without_resetting_it(tmp_path, monkeypatch):
    app, _, target = rpc_app(tmp_path, monkeypatch)
    runtime = app.delivery
    try:
        intent = preview(runtime, target)
        bindings = runtime.bindings()
        with runtime.store._lock:
            runtime.store._transaction('fixture-automatic', lambda: runtime.store._admit(
                [['192.0.2.10', target, 'RPC']], bindings, 'automatic', 'Added', app.clock()))
        before = rows(runtime.store, 'receipt')
        assert confirm(runtime, intent)['reason'] == 'delivery_pending'
        assert rows(runtime.store, 'receipt') == before
        assert not rows(runtime.store, 'manual_resend')
    finally:
        runtime.stop()


def test_auth_block_cannot_be_bypassed_by_new_target_ip_or_binding(tmp_path, monkeypatch):
    app, transport, target = rpc_app(tmp_path, monkeypatch)
    runtime = app.delivery
    try:
        transport.callback = lambda method, url, kwargs: Response(status=401)
        intent = preview(runtime, target, ['misp'])
        assert confirm(runtime, intent)['status'] == 'queued'
        runtime.worker.run_pass()
        blocked = rows(runtime.store, 'receipt')
        assert blocked[0]['error'] == 'provider_auth'
        app.clock.now += 31
        from rpc_query import PROVIDER
        app.current[STORAGE_TARGET][PROVIDER]['decoded_ips'] = ['192.0.2.77']
        assert preview(runtime, target, ['misp'])['reason'] == 'destination_unavailable'
        runtime.registry.apply({**runtime.selected_alerts, 'push_event_id': '2'}, revision=runtime.revision())
        assert preview(runtime, target, ['misp'])['reason'] == 'destination_unavailable'
        assert rows(runtime.store, 'receipt') == blocked
        assert len(rows(runtime.store, 'manual_resend')) == 1
    finally:
        runtime.stop()


def test_marker_capacity_retains_active_authority_and_prunes_only_terminal_expired(tmp_path, monkeypatch):
    app, _, target = rpc_app(tmp_path, monkeypatch)
    runtime = app.delivery
    try:
        intent = preview(runtime, target)
        assert confirm(runtime, intent)['status'] == 'queued'
        # Finite persisted marker pool; all synthetic entries are old but active.
        with runtime.store._lock:
            def seed():
                for index in range(255):
                    token = f'{index:032x}'
                    runtime.store._execute('INSERT INTO manual_resend VALUES(?,?,?,?,?,?,?,?)',
                        (token, 'actor', 'fixture-' + token, 1, '{}', encode(['misp']), 1, 1))
                    runtime.store._execute('INSERT INTO receipt(operation,channel,binding,action,ip,payload,state,created,reserved) '
                        'VALUES(?,?,?,?,?,?,?,?,?)', ('manual:' + token, 'misp', '0' * 64, 'Added',
                         '198.51.100.1', encode({'entries': [['198.51.100.1', 'fixture', 'A']]}), 'pending', 1, 5000))
            assert runtime.store._transaction('fixture-markers', seed)[0]
        app.clock.now += 86401
        from rpc_query import PROVIDER
        app.current[STORAGE_TARGET][PROVIDER]['decoded_ips'] = ['192.0.2.55']
        # Current request has pending rows too: none of the 256 markers can go.
        refused = preview(runtime, target)
        assert refused['reason'] == 'delivery_capacity'
        assert len(rows(runtime.store, 'manual_resend')) == 256
        # Terminal cleanup may remove old rows, never rebuild an old UUID.
        with runtime.store._lock:
            def terminal_cleanup():
                for row in list(runtime.store._db.execute('SELECT * FROM receipt WHERE operation=?',
                                                          ('manual:' + intent['request_id'],))):
                    runtime.store._terminal(row, 'acked', None, app.clock())
                runtime.store._execute('DELETE FROM receipt WHERE operation=?', ('manual:' + '0' * 32,))
            assert runtime.store._transaction('fixture-terminal-cleanup', terminal_cleanup)[0]
        fresh = preview(runtime, target)
        assert fresh['status'] == 'ready'
        assert confirm(runtime, fresh)['status'] == 'queued'
        assert len(rows(runtime.store, 'manual_resend')) <= 256
        assert confirm(runtime, intent)['status'] in ('already_queued', 'not_queued')
        assert sum(r['operation'] == 'manual:' + intent['request_id'] for r in rows(runtime.store, 'receipt')) == 0
    finally:
        runtime.stop()


def test_manual_terminal_failure_never_grants_or_clears_automatic_failed_addition(tmp_path, monkeypatch):
    app, transport, target = rpc_app(tmp_path, monkeypatch)
    runtime = app.delivery
    try:
        before = preserved(app)
        transport.callback = lambda method, url, kwargs: Response(status=400)
        intent = preview(runtime, target)
        assert confirm(runtime, intent)['status'] == 'queued'
        runtime.worker.run_pass()
        assert not rows(runtime.store, 'receipt')
        assert preserved(app) == before
    finally:
        runtime.stop()
