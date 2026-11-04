"""Bounded terminal audit ownership, including original-queue saturation."""
import threading

import pytest

from monitor.scheduler import MonitorScheduler
from security.jobs import finish_force
from test_lookup_force import enqueue
from test_lookup_liveness import owned_app, wait_for


def test_audit_capacity_retains_original_queue_until_actual_return(tmp_path):
    app = owned_app(tmp_path)
    scheduler = MonitorScheduler(app.cfg)
    app.lookup.scheduler = scheduler
    entered, release = threading.Event(), threading.Event()
    jobs = [enqueue(app, ['test.example']) for _ in range(18)]
    for index, job in enumerate(jobs):
        job['job_id'] = str(index)
    def blocked(*args, **kwargs):
        entered.set()
        assert release.wait(12)
    jobs[0]['_security_store'].audit.side_effect = blocked
    try:
        first = scheduler.active_force()
        finish_force(first.force_req, 'completed')
        assert entered.wait(2)
        for _ in range(16):
            snap = scheduler.active_force()
            assert snap is not None
            finish_force(snap.force_req, 'failure')
        assert scheduler.active_force() is None
        assert app.cfg.raw['_force_resolve_queue'] == [jobs[-1]]
        owner = app.lookup.audit
        status = owner.status()
        assert status['active'] == 1 and status['pending'] == 17
        assert not scheduler.stop()
        assert not owner.stop(join_seconds=0)['stopped']
        assert not app.lookup.status()['stopped']
        assert not app.delivery.stop(join_seconds=0)['closed']
        assert not scheduler.stop()
        assert app.cfg.raw['_force_resolve_queue'] == [jobs[-1]]
        assert jobs[-1].get('_terminal_outcome') is None
        release.set()
        assert wait_for(lambda: all(j.get('_terminal_audit_done') for j in jobs))
        assert owner.stop()['stopped']
        assert scheduler.stop()
        for job in jobs:
            finish_force(job, 'failure')
            job['_security_store'].audit.assert_called_once()
            call = job['_security_store'].audit.call_args
            assert call.kwargs['job_id'] == job['job_id']
            assert call.args[0] == job['actor']
        assert owner.status()['pending'] == 0
    finally:
        release.set()
        scheduler.stop()
        app.lookup.stop()
        app.delivery.stop()


def test_audit_thread_start_failure_keeps_original_force(tmp_path, monkeypatch):
    app = owned_app(tmp_path)
    scheduler = MonitorScheduler(app.cfg)
    job = enqueue(app, ['test.example'])
    start = threading.Thread.start
    def fail(thread):
        if thread.name == 'terminal-audit':
            raise RuntimeError('audit start failed')
        return start(thread)
    monkeypatch.setattr(threading.Thread, 'start', fail)
    try:
        with pytest.raises(RuntimeError, match='audit start failed'):
            scheduler.active_force()
        assert app.cfg.raw['_force_resolve_queue'] == [job]
        assert job.get('_terminal_outcome') is None
        assert not scheduler.stop()
        assert not app.lookup.audit.stop(join_seconds=0)['stopped']
        job['_security_store'].audit.assert_not_called()
    finally:
        app.lookup.stop()
        app.delivery.stop()


def test_owned_direct_force_uses_reserved_audit_worker(tmp_path, monkeypatch):
    from monitor import engine
    from test_lookup_liveness import background_scan, success
    app = owned_app(tmp_path)
    job = enqueue(app, ['test.example'])
    assert app.cfg.dequeue_force() is job
    entered, release = threading.Event(), threading.Event()
    def audit(*args, **kwargs):
        entered.set()
        assert release.wait(12)
    job['_security_store'].audit.side_effect = audit
    monkeypatch.setattr(engine, 'collect_snapshot', success)
    thread, results, errors = background_scan(app, force_req=job)
    try:
        assert entered.wait(2)
        thread.join(.4)
        assert not thread.is_alive(), 'direct owned force retained synchronous audit'
        assert not errors and results[0].complete
        assert app.lookup.audit.status()['pending'] == 1
    finally:
        release.set()
        thread.join(3)
        app.lookup.stop()
        app.delivery.stop()


def test_audit_fence_race_retires_original_queue_before_worker_exit(tmp_path):
    app = owned_app(tmp_path)
    scheduler = MonitorScheduler(app.cfg)
    first = enqueue(app, ['test.example'])
    owner = app.lookup.audit
    original = owner.condition
    entered, release = threading.Event(), threading.Event()
    paused = []

    class PauseBeforeIdleLock:
        def __getattr__(self, name):
            return getattr(original, name)

        def __enter__(self):
            if (threading.current_thread().name == 'terminal-audit'
                    and first.get('_terminal_audit_done') and not paused):
                paused.append(True)
                entered.set()
                assert release.wait(12)
            return original.__enter__()

        def __exit__(self, *args):
            return original.__exit__(*args)

    owner.condition = PauseBeforeIdleLock()
    try:
        scheduler.active_force()
        finish_force(first, 'completed')
        assert entered.wait(2)
        second = enqueue(app, ['test.example'])
        app.lookup.fence()
        release.set()
        assert wait_for(lambda: second.get('_terminal_audit_done'))
        assert first['_terminal_outcome'] == 'completed'
        assert second['_terminal_outcome'] == 'failure'
        assert app.lookup.stop()['stopped']
        for job in (first, second):
            job['_security_store'].audit.assert_called_once()
    finally:
        release.set()
        app.lookup.stop(join_seconds=0)
        app.delivery.stop()


def test_stop_finalizes_dequeued_but_unsubmitted_force_once(tmp_path):
    app = owned_app(tmp_path)
    scheduler = MonitorScheduler(app.cfg)
    job = enqueue(app, ['test.example'])
    try:
        assert scheduler.active_force().force_req is job
        scheduler.stop()
        assert wait_for(lambda: job.get('_terminal_audit_done'))
        assert job['_terminal_outcome'] == 'failure'
        finish_force(job, 'completed')
        assert app.lookup.stop()['stopped']
        job['_security_store'].audit.assert_called_once()
    finally:
        app.lookup.stop(join_seconds=0)
        app.delivery.stop()


def test_audit_exception_and_repeated_finish_retire_exact_reservation(tmp_path):
    app = owned_app(tmp_path)
    scheduler = MonitorScheduler(app.cfg)
    job = enqueue(app, ['test.example'])
    job['_security_store'].audit.side_effect = RuntimeError('audit failure')
    try:
        assert scheduler.active_force().force_req is job
        finish_force(job, 'failure')
        finish_force(job, 'completed')
        assert wait_for(lambda: job.get('_terminal_audit_done'))
        assert job['_terminal_outcome'] == 'failure'
        job['_security_store'].audit.assert_called_once()
        assert app.lookup.audit.status()['pending'] == 0
        assert scheduler.stop()
        assert app.lookup.audit.stop()['stopped']
        assert app.lookup.audit.stop()['stopped']
    finally:
        app.lookup.stop()
        app.delivery.stop()
