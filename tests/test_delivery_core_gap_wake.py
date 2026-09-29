import threading

import pytest

from test_stage3_core_runtime import app_factory, rows, scan
from test_delivery_adapters_steps import Response, Transport


@pytest.mark.parametrize('boundary', ['before_wait', 'during_wait'])
def test_real_config_repair_wakes_worker_without_poll_delay(tmp_path, monkeypatch, boundary):
    transport = Transport(Response(status=401), Response(status=200))
    app = app_factory(tmp_path, transport=transport)
    waiting, release, sent = threading.Event(), threading.Event(), threading.Event()
    completed_pass = threading.Event()
    try:
        scan(app, monkeypatch, ['1.2.3.4'])
        app.delivery.worker.run_pass()
        assert rows(app, 'receipt')[0]['state'] == 'blocked_config'
        worker = app.delivery.worker
        assert callable(getattr(worker, 'wake', None)), 'production worker must implement wake'
        event = worker._wake
        original_wait = event.wait
        original_request = transport.request
        def request(*a, **k):
            result = original_request(*a, **k)
            sent.set()
            return result
        monkeypatch.setattr(transport, 'request', request)
        waits = []
        def wait(timeout=None):
            waits.append(True)
            if len(waits) > 1:
                completed_pass.set()
            elif boundary == 'before_wait':
                waiting.set()
                assert release.wait(3)
            return original_wait(30)  # disable polling fallback, not wake
        monkeypatch.setattr(event, 'wait', wait)
        if boundary == 'during_wait':
            condition_wait = event._cond.wait
            def at_condition_wait(timeout=None):
                # Event.set must acquire this condition lock. Once signaled,
                # the setter cannot run until Condition.wait releases it.
                waiting.set()
                return condition_wait(timeout)
            monkeypatch.setattr(event._cond, 'wait', at_condition_wait)
        old_epoch = rows(app, 'receipt')[0]['claim_revision']
        wake = worker.wake
        def checked_wake():
            import json
            control = json.loads(rows(app, 'control')[0]['data'])
            assert control['adapter_revision_teams'] > old_epoch
            wake()
        monkeypatch.setattr(worker, 'wake', checked_wake)
        assert worker.start()
        assert waiting.wait(2)
        app.service.commit('settings', {'alerts': {'teams_webhook': 'https://teams.invalid/hook'}}, expected_revision=0)
        release.set()
        assert sent.wait(2), 'retry must be event-driven, not 30-second fallback'
        assert completed_pass.wait(2)
        assert app.delivery.store.health_snapshot()['acked_total'] == 1
        result = app.delivery.stop()
        assert result['stopped'] and result['closed']
        assert len(transport.calls) == 2
    finally:
        release.set()
        app.delivery.stop()


def test_stop_wakes_actual_idle_wait(tmp_path, monkeypatch):
    app = app_factory(tmp_path)
    waiting = threading.Event()
    try:
        worker = app.delivery.worker
        assert callable(getattr(worker, 'wake', None))
        original = worker._wake.wait
        def wait(timeout=None):
            waiting.set()
            return original(30)
        monkeypatch.setattr(worker._wake, 'wait', wait)
        assert worker.start()
        assert waiting.wait(2)
        result = app.delivery.stop(join_seconds=1)
        assert result['stopped'] and result['closed']
        assert not worker._thread.is_alive()
    finally:
        app.delivery.stop()


def test_stop_between_loop_check_and_wake_clear_cannot_sleep(tmp_path, monkeypatch):
    app = app_factory(tmp_path)
    worker = app.delivery.worker
    clearing, release, stop_notified = threading.Event(), threading.Event(), threading.Event()
    clear, wait, set_event = worker._wake.clear, worker._wake.wait, worker._wake.set
    result = []
    stopper = None
    def paused_clear():
        clearing.set()
        assert release.wait(3)
        clear()
    def notified():
        set_event()
        stop_notified.set()
    monkeypatch.setattr(worker._wake, 'clear', paused_clear)
    monkeypatch.setattr(worker._wake, 'wait', lambda timeout=None: wait(30))
    monkeypatch.setattr(worker._wake, 'set', notified)
    try:
        worker.start()
        assert clearing.wait(2)
        stopper = threading.Thread(target=lambda: result.append(worker.stop(join_seconds=1)))
        stopper.start()
        assert stop_notified.wait(1)
        release.set()
        stopper.join(2)
        assert result and result[0]['stopped'], 'stop notification was cleared before idle wait'
        assert not worker._thread.is_alive()
    finally:
        release.set()
        set_event()
        if stopper is not None:
            stopper.join(2)
        app.delivery.stop()
