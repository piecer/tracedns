"""Fake-clock serial scheduling: startup/full deadlines always beat backlog."""
import threading
from unittest.mock import patch

import pytest

from monitor.stores import ConfigStore


class Clock:
    value = 0

    def __call__(self):
        return self.value


def test_full_startup_completion_deadline_and_force_backlog_fairness():
    from monitor.scheduler import MonitorScheduler
    clock = Clock()
    cfg = {'domains': [], 'servers': [], 'interval': 60,
           '_force_resolve_queue': [{'domains': [], 'id': n} for n in range(4)]}
    store = ConfigStore(cfg, threading.RLock())
    scheduler = MonitorScheduler(store, clock=clock)
    first = scheduler.next_scan(block=False)
    assert first.force_req is None
    assert len(cfg['_force_resolve_queue']) == 4
    clock.value = 10
    scheduler.completed(first, accepted=True)
    clock.value = 20
    force = scheduler.next_scan(block=False)
    assert force.force_req['id'] == 0
    clock.value = 25
    scheduler.completed(force, accepted=True)
    assert scheduler.deadline == 70
    clock.value = 69
    force = scheduler.next_scan(block=False)
    assert force.force_req['id'] == 1
    clock.value = 75
    scheduler.completed(force, accepted=True)
    full = scheduler.next_scan(block=False)
    assert full.force_req is None
    clock.value = 1000
    scheduler.completed(full, accepted=True)
    assert scheduler.deadline == 1060  # no catch-up bursts
    assert scheduler.next_scan(block=False).force_req['id'] == 2


def test_generation_changes_schedule_full_and_stale_full_cannot_reset_deadline(tmp_path):
    from monitor.scheduler import MonitorScheduler
    from monitor.repository import MonitorStateRepository
    clock = Clock()
    cfg = {'domains': ['a.test'], 'servers': ['dns'], 'interval': 60}
    repo = MonitorStateRepository({}, {}, str(tmp_path), cfg['domains'])
    store = ConfigStore(cfg, threading.RLock(), repo)
    scheduler = MonitorScheduler(store, clock=clock)
    snap = scheduler.next_scan(block=False)
    clock.value = 10
    scheduler.completed(snap, accepted=True)
    cfg['interval'] = 120
    assert scheduler.deadline == 130
    clock.value = 50
    cfg['interval'] = 30
    assert scheduler.next_scan(block=False).force_req is None
    cfg['interval'] = 120
    assert scheduler.next_scan(block=False) is None
    # A snapshot must be an observer, not a config publication/revocation.
    before = repo.capture()['a.test']
    with __import__('unittest.mock', fromlist=['patch']).patch.object(repo, 'configure') as configure:
        store.snapshot()
    configure.assert_not_called()
    cfg['domains'] = ['b.test']
    repo.configure(cfg)
    assert not repo.valid(before)
    changed = scheduler.next_scan(block=False)
    assert changed is not None and changed.force_req is None
    scheduler.completed(changed, accepted=False)
    assert scheduler.deadline == 130
    assert scheduler.next_scan(block=False).force_req is None
    scheduler.completed(scheduler.next_scan(block=False), accepted=True)
    assert scheduler.next_scan(block=False) is None


@pytest.mark.parametrize('action', ['enqueue', 'config', 'stop'])
def test_idle_condition_wakes_without_lost_admission_or_stop(tmp_path, action):
    from monitor.scheduler import MonitorScheduler
    from tests.test_stage2_force import context, admit
    ctx = context(tmp_path)
    store = ConfigStore(ctx.shared_config, ctx.config_lock, ctx.state_repository)
    clock = Clock()
    scheduler = MonitorScheduler(store, clock=clock)
    scheduler.completed(scheduler.next_scan(block=False), accepted=True)
    condition = ctx.shared_config.get('_monitor_condition')
    assert condition is not None
    entered, returned = threading.Event(), threading.Event()
    result = []
    original_wait = condition.wait

    def waiting(timeout):
        entered.set()
        return original_wait(timeout)

    def dispatch():
        result.append(scheduler.next_scan())
        returned.set()

    with patch.object(condition, 'wait', side_effect=waiting):
        thread = threading.Thread(target=dispatch, daemon=True)
        thread.start()
        try:
            assert entered.wait(2)
            if action == 'enqueue':
                assert admit(ctx, {'domain': 'x.test'}).status == 200
            elif action == 'config':
                with ctx.config_lock:
                    ctx.shared_config['interval'] = 1
                    clock.value = 2
                    condition.notify_all()  # ConfigService's exact notification contract
            else:
                scheduler.stop()
            assert returned.wait(2)
        finally:
            scheduler.stop()
            thread.join(2)
    assert not thread.is_alive()
    if action == 'stop':
        assert result == [None]
    else:
        assert (result[0].force_req is not None) == (action == 'enqueue')


def test_shutdown_fails_pending_once_but_not_running_work(tmp_path):
    from monitor.scheduler import MonitorScheduler
    from tests.test_stage2_force import context, admit
    ctx = context(tmp_path)
    store = ConfigStore(ctx.shared_config, ctx.config_lock, ctx.state_repository)
    scheduler = MonitorScheduler(store, clock=Clock())
    scheduler.completed(scheduler.next_scan(block=False), accepted=True)
    running = admit(ctx, {'domain': 'x.test'})
    scan = scheduler.next_scan(block=False)
    pending = admit(ctx, {'domain': 'x.test'})
    scheduler.stop()
    scheduler.stop()
    assert scheduler.next_scan(block=False) is None
    assert not ctx.shared_config.get('_force_resolve_queue')
    assert [c.kwargs['outcome'] for c in pending.security_store.audit.call_args_list] == ['started', 'failure']
    assert [c.kwargs['outcome'] for c in running.security_store.audit.call_args_list] == ['started']
    assert '_terminal_outcome' not in scan.force_req
    assert admit(ctx, {'domain': 'x.test'}).status == 503


def test_stale_fifo_job_fails_before_dispatch_then_current_job_runs(tmp_path):
    from monitor.scheduler import MonitorScheduler
    from tests.test_stage2_force import context, admit
    ctx = context(tmp_path)
    store = ConfigStore(ctx.shared_config, ctx.config_lock, ctx.state_repository)
    scheduler = MonitorScheduler(store, clock=Clock())
    old = admit(ctx, {'domain': 'x.test'})
    ctx.state_repository.configure({'domains': []})
    ctx.state_repository.configure(ctx.shared_config)
    fresh = admit(ctx, {'domain': 'x.test'})
    # Required full after configuration change runs before either force.
    scheduler.completed(scheduler.next_scan(block=False), accepted=True)
    force = scheduler.next_scan(block=False)
    assert force.force_req['_security_store'] is fresh.security_store
    assert [c.kwargs['outcome'] for c in old.security_store.audit.call_args_list] == ['started', 'failure']
    assert not ctx.shared_config.get('_force_resolve_queue')
