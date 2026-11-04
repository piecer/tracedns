"""Lookup producer lifecycle feeds delivery health, never an HTTP traversal."""
from monitor import engine
from test_lookup_liveness import owned_app, owned_scan, success
from test_stage3_core_runtime import rows


def test_actual_lookup_success_failure_and_generation_are_not_universal_coverage(tmp_path, monkeypatch):
    app = owned_app(tmp_path, servers=['fixture'])
    monkeypatch.setattr(engine, 'collect_snapshot', success)
    try:
        assert owned_scan(app).complete
        first = app.delivery.health_snapshot(include_progress=True)['lookup']
        assert first['last_attempt_at'] == app.clock()
        assert first['last_success_at'] == app.clock()
        assert first['failed_targets'] == first['uncertain_targets'] == 0
        # A target success is not a completed/accepted full absence gate.
        assert first['coverage'] == 'partial'
        app.clock.now += 1
        def fail(*args):
            raise RuntimeError('PRIVATE-CANARY')
        monkeypatch.setattr(engine, 'collect_snapshot', fail)
        assert not owned_scan(app).complete
        failed = app.delivery.health_snapshot(include_progress=True)['lookup']
        assert failed['last_success_at'] == first['last_success_at']
        assert failed['last_attempt_at'] == app.clock()
        assert failed['failed_targets'] == failed['uncertain_targets'] == 1
        assert failed['coverage'] == 'partial'
        with app.cfg.lock:
            app.repo.configure({**app.cfg.raw, 'domains': ['replacement.example']})
        replacement = app.delivery.health_snapshot(include_progress=True)['lookup']
        assert replacement['failed_targets'] == 0
        assert replacement['uncertain_targets'] == 1
        assert replacement['coverage'] == 'unknown'
        assert replacement['last_success_at'] == first['last_success_at']
    finally:
        app.lookup.stop()
        app.delivery.stop()


def test_accepted_sibling_and_retired_late_result_publish_truthfully(tmp_path, monkeypatch):
    import threading
    from test_lookup_liveness import background_scan, wait_for
    app = owned_app(tmp_path)
    entered, release = threading.Event(), threading.Event()
    def collect(domain, server):
        if server == 'slow':
            entered.set()
            assert release.wait(5)
        return success(domain, server)
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    thread, _, errors = background_scan(app)
    try:
        assert entered.wait(2)
        assert wait_for(lambda: 'healthy' in app.current['test.example'])
        health = app.delivery.health_snapshot(include_progress=True)['lookup']
        assert health['last_attempt_at'] == app.clock()
        assert health['last_success_at'] == app.clock()
        assert health['in_flight'] == 1
        assert health['uncertain_targets'] == 1
        assert health['coverage'] == 'partial'
        with app.cfg.lock:
            app.repo.configure({**app.cfg.raw, 'domains': ['replacement.example']})
        replacement = app.delivery.health_snapshot(include_progress=True)['lookup']
        assert replacement['in_flight'] == 1, 'retired callback still owns real provider capacity'
        app.clock.now += 10
        release.set()
        thread.join(3)
        assert not thread.is_alive() and not errors
        assert app.delivery.health_snapshot(include_progress=True)['lookup'] == {**replacement, 'in_flight': 0}
    finally:
        release.set()
        thread.join(3)
        app.lookup.stop()
        app.delivery.stop()


def test_target_rebase_is_independent_of_full_absence_readiness(tmp_path, monkeypatch):
    app = owned_app(tmp_path, domains=['a.example', 'b.example'], servers=['fixture'])
    ip = ['192.0.2.1']
    def collect(domain, server):
        if domain.name == 'b.example':
            raise RuntimeError('fixture failed target')
        return success(domain, server, ip[0])
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    try:
        app.delivery.store.enter_gap('delivery_storage', {})
        assert app.delivery.maintain_delivery(app.clock())['state'] == 'ready'
        assert not owned_scan(app).complete
        health = app.delivery.health_snapshot(include_progress=True)
        assert health['recovery']['targets_rebaselining'] == 1
        assert health['recovery']['absence_state'] == 'awaiting_full'
        assert health['lookup']['failed_targets'] == 1
        assert rows(app, 'receipt') == []
        ip[0] = '192.0.2.2'
        assert not owned_scan(app).complete
        assert len(rows(app, 'receipt')) == 1
        assert app.delivery.health_snapshot(include_progress=True)['recovery']['targets_rebaselining'] == 1
    finally:
        app.lookup.stop()
        app.delivery.stop()


def test_dht_verified_target_is_not_global_lookup_coverage(tmp_path, monkeypatch):
    from dht_state_helpers import application
    from monitor.lookup_runtime import LookupRuntime
    from test_dht_monitor import observation, target
    evidence, key = observation(5)
    app = application(tmp_path, [target(key)])
    app.lookup = LookupRuntime(app.repo)
    monkeypatch.setattr('dht_query.fetch_dht_records', lambda *a, **k: evidence)
    try:
        snapshot = app.cfg.snapshot()
        result = owned_scan(app)
        assert result.complete
        assert app.delivery.complete(snapshot, result)
        lookup = app.delivery.health_snapshot(include_progress=True)['lookup']
        assert lookup['last_success_at'] is not None
        assert lookup['coverage'] == 'partial'
    finally:
        app.lookup.stop()
        app.delivery.stop()
