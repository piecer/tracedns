"""Full-generation reconciliation fences absence and never holds delivery locks."""
import threading
from unittest.mock import patch

from monitor.removal_grace import IpRemovalGraceTracker
from monitor.stores import ConfigStore
from tests.test_stage2_force import context


def test_stale_full_cannot_advance_baseline_or_removal_grace(tmp_path):
    from monitor.engine import reconcile_scan
    ctx = context(tmp_path)
    store = ConfigStore(ctx.shared_config, ctx.config_lock, ctx.state_repository)
    snap = store.snapshot()
    prior = {'192.0.2.1': {'x.test'}}
    tracker = IpRemovalGraceTracker(grace_seconds=0)
    ctx.shared_config['domains'] = []
    ctx.state_repository.configure(ctx.shared_config)
    with patch('monitor.engine.alert_removed_ips') as alerts:
        accepted, baseline = reconcile_scan(store, snap, prior, {}, tracker)
    assert not accepted
    assert baseline is prior
    assert tracker.pending_ips() == set()
    alerts.assert_not_called()


def test_removal_admission_holds_config_fence_but_delivery_is_unlocked(tmp_path):
    from monitor.engine import reconcile_scan
    ctx = context(tmp_path)
    store = ConfigStore(ctx.shared_config, ctx.config_lock, ctx.state_repository)
    snap = store.snapshot()
    tracker = IpRemovalGraceTracker(grace_seconds=0)
    acquired = threading.Event()

    def delivery(*args, **kwargs):
        def writer():
            with ctx.config_lock:
                ctx.state_repository.configure({'domains': []})
            acquired.set()
        thread = threading.Thread(target=writer, daemon=True)
        thread.start()
        assert acquired.wait(2), 'external delivery must not hold config/repository/state locks'
        thread.join(2)

    with patch('monitor.engine.alert_removed_ips', side_effect=delivery) as alerts:
        accepted, baseline = reconcile_scan(store, snap, {'192.0.2.123': {'x.test'}}, {}, tracker)
    assert accepted and baseline == {}
    alerts.assert_called_once()
    assert acquired.is_set()


def test_force_cancels_grace_only_for_fresh_positive_observations(tmp_path):
    from monitor.engine import reconcile_scan
    from tests.test_stage2_force import admit, execute
    from tests.test_monitor_state_ownership import _collected
    ctx = context(tmp_path, domains=[{'name': 'a.example', 'type': 'A'}], servers=['dns', 'other'])
    repo = ctx.state_repository
    repo.current['a.example'] = {'other': {'type': 'A', 'values': ['192.0.2.20']}}
    store = ConfigStore(ctx.shared_config, ctx.config_lock, repo)
    snap = store.snapshot()
    admit(ctx, {'domain': 'a.example', 'servers': ['dns']})
    snap.force_req = store.dequeue_force()
    tracker = IpRemovalGraceTracker(grace_seconds=100, now_fn=lambda: 10)
    previous = {'192.0.2.10': {'a.example'}, '192.0.2.20': {'a.example'}}
    tracker.reconcile(previous, {})
    with patch('monitor.engine.collect_snapshot', side_effect=_collected):
        result = execute(ctx, snap.force_req)
    # Runtime projection still retains other configured providers; forced scope
    # never establishes absence or treats cached votes as new positive queries.
    assert '192.0.2.20' in result
    accepted, baseline = reconcile_scan(store, snap, previous, result, tracker)
    assert accepted
    assert baseline is previous
    assert tracker.pending_ips() == {'192.0.2.20'}
