"""Counts and oldest identity share a monotonic, copy-on-publish sample."""
import math

from monitor.delivery_types import MAX_COUNTER
from test_delivery_store_atomic import AUTH, BINDINGS, obs, store_at


def test_oldest_zero_wall_rollback_all_cache_updates_and_empty(tmp_path):
    wall, mono = [100.0], [100.0]
    store = store_at(tmp_path, clock=lambda: wall[0])
    store._monotonic = lambda: mono[0]
    try:
        store.bootstrap({}, {}, AUTH)
        store.record_domain(obs(['192.0.2.1'], observed_at=0), AUTH, BINDINGS)
        assert store.health_snapshot()['oldest_pending_age_seconds'] == 100
        mono[0] = 110
        wall[0] = 10
        store._safe_refresh()
        assert store.health_snapshot()['oldest_pending_age_seconds'] == 110
        updates = [lambda: store.set_worker_thread_running(True), store.worker_enter,
                   store.worker_exit, store.note_history_failure,
                   lambda: store.enter_gap('delivery_storage', {})]
        for update in updates:
            update()
            mono[0] += 1
            health, counts_age, *_ = store.progress_health_snapshot()
            assert health['oldest_pending_age_seconds'] == mono[0]
            assert counts_age == mono[0] - 110
        assert health['counts_stale']
        clone = store.health_snapshot()
        clone['channels']['misp']['pending'] = 999
        assert store.health_snapshot()['channels']['misp']['pending'] == 1
        mono[0] = 2**70
        assert store.health_snapshot()['oldest_pending_age_seconds'] == MAX_COUNTER
        for bad in (math.inf, -math.inf, math.nan):
            mono[0] = bad
            h, age, *_ = store.progress_health_snapshot()
            assert h['oldest_pending_age_seconds'] == 110
            assert age is None
        mono[0] = 116
        for bad in (math.inf, -math.inf, math.nan):
            wall[0] = bad
            store._safe_refresh()
            projected = store.health_snapshot()
            assert projected['counts_stale']
            assert projected['oldest_pending_age_seconds'] == 116
        wall[0], mono[0] = 500, 117
        store._safe_refresh()
        assert store.health_snapshot()['oldest_pending_age_seconds'] == 500
        wall[0], mono[0] = 100, 118
        store._safe_refresh()
        assert store.health_snapshot()['oldest_pending_age_seconds'] == 501
    finally:
        store.close(clean=False)
    # A fresh process/owner never reuses the prior monotonic clock origin.
    reopened = store_at(tmp_path, clock=lambda: 1000)
    try:
        assert reopened.bootstrap({}, {}, AUTH)['ready']
        assert reopened.health_snapshot()['oldest_pending_age_seconds'] == 1000
    finally:
        reopened.close(clean=False)
    empty = store_at(tmp_path / 'empty', clock=lambda: 0)
    try:
        empty.bootstrap({}, {}, AUTH)
        assert empty.health_snapshot()['oldest_pending_age_seconds'] is None
    finally:
        empty.close(clean=True)


def test_gap_publishes_readiness_without_waiting_for_recovery(tmp_path):
    from test_stage3_core_runtime import app_factory
    app = app_factory(tmp_path)
    try:
        assert app.delivery.maintain_delivery(app.clock())['state'] == 'ready'
        app.delivery.store.enter_gap('delivery_storage', {})
        recovery = app.delivery.health_snapshot(include_progress=True)['recovery']
        assert recovery['state'] == 'recovering'
        assert recovery['targets_rebaselining'] == 1
        assert recovery['absence_state'] != 'ready'
    finally:
        app.delivery.stop()


def test_monotonic_idle_progress_wall_jumps_and_nonfinite_projection(tmp_path):
    from test_stage3_core_runtime import app_factory
    app = app_factory(tmp_path)
    mono = [100.0]
    worker = app.delivery.worker
    worker._monotonic = lambda: mono[0]
    try:
        worker.run_pass(max_provider_calls=0)
        assert worker.progress_snapshot()['state'] == 'idle'
        app.clock.now += 1000000
        mono[0] = 159.999
        assert worker.progress_snapshot()['state'] == 'idle'
        app.clock.now = 0
        mono[0] = 160
        assert worker.progress_snapshot()['state'] == 'stalled'
        for invalid in (math.inf, -math.inf, math.nan):
            mono[0] = invalid
            snapshot = worker.progress_snapshot()
            assert snapshot['last_progress_age_seconds'] is None
        mono[0] = 161
        worker.run_pass(max_provider_calls=0)
        assert worker.progress_snapshot()['state'] == 'idle'
        assert worker.progress_snapshot()['last_progress_at'] == 0
    finally:
        app.delivery.stop()


def test_frozen_idle_loop_degrades_even_without_enabled_destination(tmp_path):
    from test_stage3_core_runtime import app_factory
    app = app_factory(tmp_path, config={'domains': [], 'servers': [], 'alerts': {}})
    mono = [100.0]
    app.delivery.worker._monotonic = lambda: mono[0]
    try:
        app.delivery.worker.run_pass(max_provider_calls=0)
        assert app.delivery.health_snapshot()['status'] == 'disabled'
        mono[0] = 160
        health = app.delivery.health_snapshot(include_progress=True)
        assert health['progress']['state'] == 'stalled'
        assert health['status'] == 'degraded'
    finally:
        app.delivery.stop()
