"""Exception-safe source fences and terminal duties after partial queue drain."""
import threading
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from http_api.config_post import handle_resolve
from http_api.read_source import create_read_model, capture_read_inputs, build_read_views
from models import DomainSpec, QueryResult
from monitor import engine
from monitor.collect import Collected
from monitor.config_service import ConfigService, get_config_service
from monitor.projection_authority import security_projection_revision
from monitor.repository import MonitorStateRepository
from monitor.runtime_state import get_state_version
from monitor.scheduler import MonitorScheduler
from monitor.stores import ConfigStore
from tests.test_config_revision import request


def app(tmp_path, attached=True):
    config = {'domains': [{'name': 'a.test', 'type': 'A'}], 'servers': ['r'],
              'custom_decoders': [], 'custom_a_decoders': [], 'ens_rpc_url': 'synthetic-old-secret'}
    lock = threading.RLock()
    snap = {'type': 'A', 'values': ['192.0.2.1'], 'ts': 1}
    current = {'a.test': {'r': snap}}
    history = {'a.test': {'meta': {'first_seen': 1}, 'events': [], 'current': {'r': dict(snap)}}}
    repo = MonitorStateRepository(current, history, str(tmp_path), config['domains'])
    model = create_read_model(config, lock, current, history)
    service = ConfigService(config, lock, '', state_repository=repo, read_model=model,
                            current_results=current, history=history, history_dir=str(tmp_path))
    ctx = SimpleNamespace(shared_config=config, config_lock=lock, config_path='',
        current_results=current, history=history, history_dir=str(tmp_path),
        state_repository=repo, read_model=model, config_service=service, max_body_bytes=10000)
    if attached:
        assert get_config_service(ctx) is service
    store = ConfigStore(config, lock, repo)
    return SimpleNamespace(cfg=config, lock=lock, current=current, history=history,
                           repo=repo, model=model, service=service, ctx=ctx, store=store)


def enqueue(o, actor=1, audit=None):
    h = request({'domain': 'a.test'})
    h.principal['id'] = actor
    h.security_store = Mock()
    if audit is not None:
        h.security_store.audit.side_effect = audit
    h.request_id, h.source_ip = 'offline-request', '127.0.0.1'
    handle_resolve(o.ctx, h)
    return h


@pytest.mark.parametrize('after_revoke', [False, True])
def test_shutdown_second_revoke_failure_must_finish_already_popped_job(tmp_path, after_revoke, record_property):
    o = app(tmp_path)
    first_h, second_h = enqueue(o), enqueue(o)
    first, second = o.cfg['_force_resolve_queue']
    scheduler = MonitorScheduler(o.store, clock=lambda: 0)
    original, calls = o.model.invalidate, []
    def fail_second(*, hard=False):
        calls.append(hard)
        if len(calls) == 2:
            if after_revoke:
                original(hard=hard)
            raise RuntimeError('second dequeue revoke failure')
        original(hard=hard)
    with patch.object(o.model, 'invalidate', side_effect=fail_second):
        with pytest.raises(RuntimeError, match='second dequeue'):
            scheduler.stop()
    assert o.cfg['_force_resolve_queue'] == [second]
    assert o.cfg['_monitor_stopped'] is True
    scheduler.stop()  # Recovery does not recover local first pending job.
    assert second['_terminal_outcome'] == 'failure'
    outcomes = [c.kwargs['outcome'] for c in first_h.security_store.audit.call_args_list]
    record_property('first_outcomes_after_retry', outcomes)
    record_property('first_terminal', first.get('_terminal_outcome'))
    record_property('second_outcomes', [c.kwargs['outcome'] for c in second_h.security_store.audit.call_args_list])
    assert first.get('_terminal_outcome') == 'failure', 'already popped pending job lost before terminal audit loop'


def test_shutdown_builtin_overflow_retains_terminal_duty(tmp_path, record_property):
    o = app(tmp_path)
    first_h, _ = enqueue(o), enqueue(o)
    first, second = o.cfg['_force_resolve_queue']
    o.cfg['_security_projection_revision'] = 9007199254740990
    epoch = o.model._epoch
    with pytest.raises(OverflowError):
        MonitorScheduler(o.store).stop()
    assert security_projection_revision(o.cfg) == 9007199254740991
    assert o.model._epoch == epoch + 1
    assert o.cfg['_force_resolve_queue'] == [second]
    assert o.cfg['_monitor_stopped']
    record_property('first_outcomes', [c.kwargs['outcome'] for c in first_h.security_store.audit.call_args_list])
    assert first.get('_terminal_outcome') == 'failure', 'valid near-overflow authority loses popped job terminal audit obligation'


@pytest.mark.parametrize('bad', [None, [], 0, 'malformed'])
@pytest.mark.parametrize('via_cycle', [False, True])
def test_removed_current_then_malformed_history_must_fence(tmp_path, bad, via_cycle):
    o = app(tmp_path)
    o.history['a.test'] = bad
    lease = o.repo.capture()['a.test']
    old = capture_read_inputs(o.cfg, o.lock, o.current, o.history, None)
    before = get_state_version()
    if via_cycle:
        lease.target.failures[('a.test', 'r', 'A')] = 2
    with pytest.raises(AttributeError):
        if via_cycle:
            failed = Collected(QueryResult('r', 'a.test', 'A', 'error', []), None)
            with patch.object(engine, 'collect_snapshot', return_value=failed):
                engine.run_domain_cycle(domain=DomainSpec('a.test'), servers=['r'],
                    current_results=o.current, history=o.history, history_dir=str(tmp_path),
                    query_fail_counts={}, state_repository=o.repo, target_lease=lease, max_workers=1)
        else:
            engine.drop_snapshot_for_failed_target(o.current, o.history, 'a.test', 'r', ts=2)
    assert 'r' not in o.current['a.test']
    assert o.history['a.test'] is bad  # Preserve malformed data and the original exception.
    fresh = capture_read_inputs(o.cfg, o.lock, o.current, o.history, None)
    assert build_read_views(old[1])['results'] != build_read_views(fresh[1])['results']
    assert get_state_version() == before + 1
    assert fresh[0] != old[0]
    assert capture_read_inputs(o.cfg, o.lock, o.current, o.history, old[0]) is not None


@pytest.mark.parametrize('bad', [None, [], 0, 'malformed'])
def test_malformed_history_without_removal_does_not_advance_version(tmp_path, bad):
    o = app(tmp_path)
    o.current['a.test'].clear()
    o.history['a.test'] = bad
    before = get_state_version()
    with pytest.raises(AttributeError):
        engine.drop_snapshot_for_failed_target(o.current, o.history, 'a.test', 'r', ts=2)
    assert get_state_version() == before
    assert o.history['a.test'] is bad


@pytest.mark.parametrize('fail_at', [1, 2])
@pytest.mark.parametrize('audit_fails', [False, True])
def test_failed_stop_wakes_waiter_and_audits_unlocked(tmp_path, fail_at, audit_fails):
    o = app(tmp_path)
    handlers = [enqueue(o), enqueue(o)]
    jobs = list(o.cfg['_force_resolve_queue'])
    ready, woke = threading.Event(), threading.Event()
    audits = []

    def audit(*args, **kwargs):
        audits.append((kwargs['outcome'], o.store.condition._is_owned()))
        if audit_fails:
            raise RuntimeError('terminal audit unavailable')

    for handler in handlers:
        handler.security_store.audit.side_effect = audit

    def wait_for_stop():
        with o.store.condition:
            ready.set()
            if o.store.condition.wait_for(lambda: o.cfg.get('_monitor_stopped'), timeout=2):
                woke.set()

    waiter = threading.Thread(target=wait_for_stop)
    waiter.start()
    original, calls = o.model.invalidate, []
    failure = RuntimeError('dequeue authority failure')

    def invalidate(*, hard=False):
        calls.append(hard)
        if len(calls) == fail_at:
            raise failure
        original(hard=hard)

    try:
        assert ready.wait(2)
        with patch.object(o.model, 'invalidate', side_effect=invalidate):
            with pytest.raises(RuntimeError) as raised:
                MonitorScheduler(o.store).stop()
        assert raised.value is failure
        assert woke.wait(1)
    finally:
        waiter.join(3)
    assert not waiter.is_alive()
    assert audits == [('failure', False)] * (fail_at - 1)
    assert o.cfg['_force_resolve_queue'] == jobs[fail_at - 1:]
    assert all(job.get('_terminal_outcome') is None for job in jobs[fail_at - 1:])
