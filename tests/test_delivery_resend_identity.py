"""Request identity, custody, and terminal cleanup are independent of work rows."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import threading

from test_delivery_resend_vertical import rpc_app, preserved
from test_delivery_review_components import rows
from test_stage3_core_runtime import app_factory


def test_same_actor_token_survives_race_configuration_restart_and_cleanup(tmp_path, monkeypatch):
    app, transport, target = rpc_app(tmp_path, monkeypatch)
    runtime = app.delivery
    try:
        preview = runtime.preview_resend(target, ['teams', 'misp'], 0, actor_id='actor-one')
        token = preview['request_id']
        before = preserved(app)
        denied = runtime.resend_target(token, actor_id='actor-two')
        assert denied['status'] == 'not_queued' and denied['reason'] == 'invalid_request'
        assert not rows(runtime.store, 'manual_resend')
        barrier = threading.Barrier(3)
        def confirm():
            barrier.wait(timeout=3)
            return runtime.resend_target(token, actor_id='actor-one')
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(confirm) for _ in range(2)]
            barrier.wait(timeout=3)
            results = [f.result(timeout=3) for f in futures]
        assert sorted(r['status'] for r in results) == ['already_queued', 'queued']
        assert len(rows(runtime.store, 'receipt')) == 2
        assert len(rows(runtime.store, 'manual_resend')) == 1
        assert preserved(app) == before
        runtime.worker.run_pass()
        assert not rows(runtime.store, 'receipt')
        calls = len(transport.calls)
        app.cfg.raw['config_revision'] = 1
        retry = runtime.resend_target(token, actor_id='actor-one')
        assert retry['status'] == 'already_queued' and retry['receipt_count'] == 2
        assert len(transport.calls) == calls
        config = {k: deepcopy(app.cfg.raw[k]) for k in ('domains', 'servers', 'alerts', 'config_revision')}
        current = deepcopy(app.current)
        assert runtime.stop()['closed']
        # No in-memory intent survives. Durable marker is still the authority.
        successor = app_factory(tmp_path, config=config, current=current, transport=transport)
        try:
            restarted = successor.delivery.resend_target(token, actor_id='actor-one')
            assert restarted == retry
            assert successor.delivery.resend_target(token, actor_id='actor-two')['reason'] == 'invalid_request'
            assert not rows(successor.delivery.store, 'receipt')
            assert successor.delivery.resend_target('1' * 32, actor_id='actor-one')['reason'] == 'preview_expired'
        finally:
            successor.delivery.stop()
    finally:
        runtime.stop()
