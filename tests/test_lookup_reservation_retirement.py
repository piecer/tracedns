"""Deterministic required stop/retirement schedules, real candidate owners."""
import json
import threading

import pytest

from monitor import engine
from test_lookup_liveness import owned_app, background_scan, success


@pytest.mark.parametrize('stop_at_reservation', [False, True], ids=['on_time_control', 'stop_after_reserve'])
def test_provider_reserved_before_stop_is_physically_retired(tmp_path, monkeypatch, stop_at_reservation):
    app = owned_app(tmp_path, servers=['fixture'])
    app.cfg.raw['max_workers'] = 1
    entered, release = threading.Event(), threading.Event()
    original = app.lookup._take_provider
    captured = []
    calls = []

    def take():
        work = original()
        if work is not None and not captured:
            captured.append(work)
            entered.set()
            assert release.wait(10), 'fixture rescue'
        return work

    def collect(domain, server):
        calls.append((domain.name, server))
        return success(domain, server)

    monkeypatch.setattr(app.lookup, '_take_provider', take)
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    thread, results, errors = background_scan(app)
    try:
        assert entered.wait(2)
        if stop_at_reservation:
            early = app.lookup.stop(join_seconds=0)
            assert app.lookup.stopping and not early['stopped']
            assert early['active'] == 1 and not release.is_set()
        release.set()
        thread.join(3)
        assert not thread.is_alive() and not errors
        status = app.lookup.stop()
        second = app.lookup.stop(join_seconds=0)
        observed = {'first_stop': status, 'repeated_stop': second,
                    'provider_calls': calls, 'singleflight': len(app.lookup.singleflight),
                    'captured_started': captured[0].started, 'captured_done': captured[0].done,
                    'captured_consumed': captured[0].consumed,
                    'all_threads_retired': all(not t.is_alive() for t in app.lookup.providers + app.lookup.controllers)}
        (tmp_path/'retirement-observation.json').write_text(json.dumps(observed, indent=2))
        assert observed['all_threads_retired']
        assert bool(calls) is (not stop_at_reservation)
        assert status['stopped'] and second['stopped']
        assert status['active'] == second['active'] == 0, 'returned provider reservation leaked after physical worker exit'
        assert not app.lookup.singleflight, 'retired attempt retained single-flight identity'
    finally:
        release.set()
        thread.join(3)
        app.lookup.stop()
        app.delivery.stop()


@pytest.mark.parametrize('boundary', ['before_selection', 'after_selection', 'running'])
def test_stop_fence_retires_only_returned_provider_work(tmp_path, monkeypatch, boundary):
    from test_lookup_liveness import wait_for

    app = owned_app(tmp_path, servers=['fixture'])
    app.cfg.raw['max_workers'] = 1
    entered, release = threading.Event(), threading.Event()
    original = app.lookup._take_provider
    captured, calls = [], []
    paused = False

    def take():
        nonlocal paused
        if boundary == 'before_selection' and app.lookup.provider_queue and not paused:
            paused = True
            entered.set()
            assert release.wait(10)
        work = original()
        if work is not None:
            captured.append(work)
            if boundary == 'after_selection' and not paused:
                paused = True
                entered.set()
                assert release.wait(10)
        return work

    def collect(domain, server):
        calls.append((domain.name, server))
        assert not app.lookup.stopping, 'collector dispatched after the stop fence'
        if boundary == 'running':
            entered.set()
            assert release.wait(10)
        return success(domain, server)

    monkeypatch.setattr(app.lookup, '_take_provider', take)
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    thread, results, errors = background_scan(app)
    try:
        assert entered.wait(2)
        workers = tuple(app.lookup.providers)
        early = app.lookup.stop(join_seconds=0)
        assert app.lookup.stopping and not early['stopped'] and not release.is_set()
        assert early['active'] == (0 if boundary == 'before_selection' else 1)
        assert early['provider_queued'] == (1 if boundary == 'before_selection' else 0)
        assert len(app.lookup.singleflight) == 1
        assert len(calls) == (1 if boundary == 'running' else 0)
        if boundary == 'running':
            assert not captured[0].done
            assert not app.lookup.stop(join_seconds=0)['stopped']
            assert app.lookup.status()['active'] == 1
            assert len(app.lookup.singleflight) == 1
        release.set()
        thread.join(3)
        assert not thread.is_alive() and not errors and not results[0].complete
        assert wait_for(lambda: all(not t.is_alive() for t in app.lookup.providers + app.lookup.controllers))
        for _ in range(2):
            status = app.lookup.stop()
            assert status['stopped']
            assert status['active'] == status['queued'] == status['controllers'] == 0
            assert not app.lookup.singleflight
        assert len(captured) == 1 and captured[0].started and captured[0].done
        assert len(calls) == (1 if boundary == 'running' else 0)
        assert tuple(app.lookup.providers) == workers
        assert app.current['test.example'] == {}
    finally:
        release.set()
        thread.join(3)
        app.lookup.stop()
        app.delivery.stop()
