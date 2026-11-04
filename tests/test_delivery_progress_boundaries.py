"""Boundary and lifecycle controls use real SQLite/worker, fake transport only."""
import threading

import pytest

from test_delivery_review_components import MISP, TEAMS, Transport, attr as make_attr
from test_lookup_liveness import wait_for
from test_stage3_core_runtime import app_factory, scan


@pytest.mark.parametrize('operation', ['recover_storage', 'seal_batches', 'claim', 'finish_step',
                                       'observation_hook', 'sightings_step'])
def test_each_real_boundary_stalls_without_fabricating_ack(tmp_path, monkeypatch, operation):
    transport = Transport([make_attr('192.0.2.1')]) if operation == 'observation_hook' else Transport()
    app = app_factory(tmp_path, transport=transport, config={
        'domains': ['test.example'], 'servers': ['fixture'], 'alerts': MISP if operation == 'observation_hook' else TEAMS})
    worker = app.delivery.worker
    mono = [100.0]
    worker._monotonic = lambda: mono[0]
    entered, release = threading.Event(), threading.Event()
    target, attr = {
        'recover_storage': (worker, '_maintenance'), 'seal_batches': (app.delivery.store, 'seal_due_batches'),
        'claim': (worker, '_claim_admission'), 'finish_step': (app.delivery.store, 'finish_step'),
        'observation_hook': (worker, '_observation_hook'), 'sightings_step': (worker, '_sightings_step'),
    }[operation]
    original = getattr(target, attr)
    def block(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        if operation == 'observation_hook':
            return None
        if operation == 'sightings_step':
            return {'provider_calls': 0, 'has_more': False}
        return original(*args, **kwargs)
    monkeypatch.setattr(target, attr, block)
    try:
        assert scan(app, monkeypatch, ['192.0.2.1'])[0]
        worker.start()
        assert entered.wait(3)
        first = app.delivery.health_snapshot(include_progress=True)
        assert first['progress']['operation'] == operation
        assert first['progress']['state'] == 'active'
        mono[0] = 159.999
        assert worker.progress_snapshot()['state'] == 'active'
        app.clock.now -= 90000
        mono[0] = 160
        health = app.delivery.health_snapshot(include_progress=True)
        assert health['progress']['state'] == 'stalled'
        assert health['acked_total'] == (1 if operation in ('observation_hook', 'sightings_step') else 0)
        assert not worker.stop(join_seconds=0)['stopped']
        mono[0] = 161
        assert worker.progress_snapshot()['state'] == 'stopping'
        assert worker.progress_snapshot()['in_flight_age_seconds'] == 61
        assert not worker.start()
    finally:
        release.set()
        assert app.delivery.stop()['stopped']
    assert worker.progress_snapshot()['state'] == 'stopped'


@pytest.mark.parametrize('failure', ['start', 'construct', 'pass', 'claim', 'finish'])
def test_terminal_failure_is_not_restart_permission(tmp_path, monkeypatch, failure):
    app = app_factory(tmp_path, transport=Transport())
    worker = app.delivery.worker
    def broken(*args):
        raise RuntimeError('PRIVATE-CANARY')
    try:
        if failure in ('start', 'construct'):
            with monkeypatch.context() as patch:
                if failure == 'construct':
                    patch.setattr(threading, 'Thread', lambda **kwargs: broken())
                else:
                    patch.setattr(threading.Thread, 'start', broken)
                with pytest.raises(RuntimeError):
                    worker.start()
            assert worker._thread is None
        else:
            if failure == 'finish':
                assert scan(app, monkeypatch, ['192.0.2.1'])[0]
                monkeypatch.setattr(app.delivery.store, 'finish_step', broken)
            else:
                monkeypatch.setattr(worker, '_claim_admission' if failure == 'claim' else '_maintenance', broken)
            worker.start()
            assert wait_for(lambda: worker.progress_snapshot()['state'] == 'failed')
        health = app.delivery.health_snapshot(include_progress=True)
        assert health['progress']['state'] == 'failed'
        assert health['status'] == 'degraded'
        if failure == 'claim':
            assert health['progress']['operation'] == 'claim'
        if failure == 'finish':
            assert health['progress']['in_flight_age_seconds'] is None
            assert health['progress']['channels']['teams']['state'] == 'unavailable'
            assert health['acked_total'] == 0
        worker.run_pass()
        assert worker.progress_snapshot()['state'] == 'failed'
        assert not worker.start(), 'terminal workers must not be manually restarted either'
    finally:
        app.delivery.stop()
    assert worker.progress_snapshot()['state'] == 'failed'


def test_configured_destination_requires_worker_before_first_receipt(tmp_path):
    app = app_factory(tmp_path)
    try:
        health = app.delivery.health_snapshot(include_progress=True)
        assert health['channels']['teams']['enabled']
        assert health['progress']['state'] == 'not_started'
        assert health['status'] == 'degraded'
    finally:
        app.delivery.stop()
