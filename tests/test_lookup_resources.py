"""Conservation and physical-versus-logical owner retirement."""
import threading

import pytest

from monitor import engine
from test_lookup_liveness import (owned_app, background_scan, MonotonicClock,
                                 success, wait_for)


@pytest.mark.parametrize('reason', ['stop', 'target_deadline'])
def test_blocked_persistence_does_not_hold_logical_scan_forever(tmp_path, monkeypatch, reason):
    clock = MonotonicClock()
    app = owned_app(tmp_path, servers=['healthy'], clock=clock)
    entered, release = threading.Event(), threading.Event()
    persist = engine.persist_history_entry
    def blocked(*args, **kwargs):
        entered.set()
        assert release.wait(10)
        return persist(*args, **kwargs)
    monkeypatch.setattr(engine, 'persist_history_entry', blocked)
    monkeypatch.setattr(engine, 'collect_snapshot', success)
    thread, results, errors = background_scan(app)
    try:
        assert entered.wait(2)
        if reason == 'stop':
            app.cfg.raw['_monitor_stopped'] = True
        else:
            clock.now = 75
        thread.join(1)
        assert not thread.is_alive(), 'logical scan waited on unbounded local publication'
        assert not errors and not results[0].complete
        status = app.lookup.stop(join_seconds=0)
        assert not status['stopped'] and status['controllers'] == 1
        assert not app.delivery.stop(join_seconds=0, producers_stopped=False)['closed']
        assert not (tmp_path / 'test.example.json').exists()
    finally:
        release.set()
        thread.join(3)
        assert wait_for(lambda: app.lookup.stop(join_seconds=0)['stopped'])
        app.delivery.stop()


def test_partial_worker_start_failure_permanently_fences_owner(tmp_path, monkeypatch):
    app = owned_app(tmp_path, servers=['healthy'])
    start = threading.Thread.start
    def fail_second(thread):
        if thread.name == 'lookup-provider-1':
            raise RuntimeError('synthetic start failure')
        return start(thread)
    monkeypatch.setattr(threading.Thread, 'start', fail_second)
    try:
        with pytest.raises(RuntimeError, match='synthetic start failure'):
            app.lookup.start(2)
        assert app.lookup.stopping, 'partial startup must fence rather than leave a reusable pool'
        assert app.lookup.stop()['stopped']
        previous = tuple(app.lookup.providers)
        app.lookup.start(64)
        assert tuple(app.lookup.providers) == previous
    finally:
        app.lookup.stop()
        app.delivery.stop()


def test_saturation_conserves_capacity_queues_and_not_dispatched_counts(tmp_path, monkeypatch):
    clock = MonotonicClock()
    app = owned_app(tmp_path, domains=[f'target-{i}.example' for i in range(25)],
                    servers=[f'provider-{i}' for i in range(6)], clock=clock)
    release = threading.Event()
    called = []
    def collect(domain, server):
        called.append((domain.name, server))
        assert release.wait(10)
        return success(domain, server)
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    thread, results, errors = background_scan(app)
    try:
        assert wait_for(lambda: len(called) == 2)
        workers = tuple(app.lookup.providers)
        app.lookup.start(1)  # Lowering cannot reclaim the two occupied slots.
        for _ in range(12):
            status = app.lookup.status()
            assert status['active'] <= 2 and status['controllers'] <= 4
            assert status['target_queued'] <= 16 and status['provider_queued'] <= 16
            assert tuple(app.lookup.providers) == workers
            clock.now += 75
            with app.lookup.condition:
                app.lookup.condition.notify_all()
            thread.join(.1)
            if not thread.is_alive():
                break
        assert not thread.is_alive() and not errors
        assert not results[0].complete and len(called) == 2
        assert set(results[0].target_complete) == {f'target-{i}.example' for i in range(25)}
        assert app.lookup.status()['overdue'] == 2
        assert sum(sum(lease.target.failures.values()) for lease in app.repo.capture().values()) <= 2
        for lease in app.repo.capture().values():
            assert sum(name == lease.name for name, _ in called) <= 2
        status = app.lookup.stop(join_seconds=.02)
        assert not status['stopped'] and status['active'] == 2
        assert app.lookup.providers == list(workers)
    finally:
        release.set()
        thread.join(3)
        assert wait_for(lambda: app.lookup.stop(join_seconds=0)['stopped'])
        app.delivery.stop()


@pytest.mark.parametrize('requested,effective', [(0, 1), (100, 64)])
def test_worker_population_clamps_to_existing_global_setting(tmp_path, requested, effective):
    app = owned_app(tmp_path)
    try:
        app.lookup.start(requested)
        assert len(app.lookup.providers) == effective
        assert len(app.lookup.controllers) == 4
    finally:
        assert app.lookup.stop()['stopped']
        app.delivery.stop()


def test_failed_pump_fences_its_unfinished_producers(tmp_path, monkeypatch):
    from types import SimpleNamespace
    app = owned_app(tmp_path, servers=['healthy'])
    entered, release = threading.Event(), threading.Event()
    def collect(domain, server):
        entered.set()
        assert release.wait(10)
        return success(domain, server)
    def force():
        if entered.is_set():
            raise RuntimeError('synthetic pump failure')
        return None
    app.lookup.scheduler = SimpleNamespace(active_force=force)
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    thread, results, errors = background_scan(app)
    try:
        assert entered.wait(2)
        thread.join(2)
        assert not thread.is_alive() and len(errors) == 1
        assert str(errors[0]) == 'synthetic pump failure'
        assert app.lookup.stopping
        assert not app.lookup.status()['stopped']
        release.set()
        assert wait_for(lambda: app.lookup.status()['stopped'])
        assert app.current['test.example'] == {}
    finally:
        release.set()
        thread.join(3)
        app.lookup.stop()
        app.delivery.stop()
