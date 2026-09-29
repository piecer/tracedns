"""F05: security projection fences through the real force-queue owners."""
from unittest.mock import patch

import pytest

from http_api.config_post import handle_resolve
from http_api.read_model import BackgroundReadModel
from monitor.config_service import get_config_service
from monitor.projection_authority import security_projection_revision
from monitor.stores import ConfigStore
from security.redaction import sanitize
from tests.test_stage2_force import admit, context


def attached(tmp_path, **config):
    ctx = context(tmp_path, **config)
    ctx.config_path = ''
    ctx.read_model = BackgroundReadModel(lambda previous: None, lambda value: {})
    service = get_config_service(ctx)
    store = ConfigStore(ctx.shared_config, ctx.config_lock, ctx.state_repository)
    return ctx, service, store


def test_http_enqueue_revokes_before_queue_creation_once(tmp_path):
    ctx, service, _ = attached(tmp_path)
    cfg, model = ctx.shared_config, service.read_model
    observed = []
    original = model.invalidate

    def invalidate(*, hard=False):
        observed.append((hard, '_force_resolve_queue' in cfg))
        original(hard=hard)

    with patch.object(model, 'invalidate', side_effect=invalidate):
        handler = admit(ctx, {'domain': 'x.test'})
    assert handler.status == 200
    assert cfg.get('_security_projection_revision', 0) == 1
    assert observed == [(True, False)]
    assert model._epoch == 1
    assert len(cfg['_force_resolve_queue']) == 1
    assert service.snapshot()['config_revision'] == 0
    assert [c.kwargs['outcome'] for c in handler.security_store.audit.call_args_list] == ['started']


def test_old_provider_rotation_then_dequeue_fences_changed_sanitizer(tmp_path):
    domain = {'name': 'x.eth', 'type': 'ENS'}
    ctx, service, store = attached(tmp_path, domains=[domain], servers=[],
                                   ens_rpc_url='synthetic-old-endpoint')
    cfg, model = ctx.shared_config, service.read_model
    assert admit(ctx, {'domains': [domain]}).status == 200
    queue = cfg['_force_resolve_queue']
    job = queue[0]
    before_commit = model._epoch
    result = service.commit('config', {'ens_rpc_url': 'synthetic-new-endpoint'}, expected_revision=0)
    assert result['revision'] == 1
    assert model._epoch == before_commit + 2  # Existing ConfigService fences.
    assert cfg['_force_resolve_queue'] is queue
    assert job['ens_rpc_url'] == 'synthetic-old-endpoint'
    before = sanitize('synthetic-old-endpoint', cfg)
    revision, epoch = cfg.get('_security_projection_revision', 0), model._epoch
    observed = []
    original = model.invalidate

    def invalidate(*, hard=False):
        observed.append((hard, tuple(queue), sanitize('synthetic-old-endpoint', cfg)))
        original(hard=hard)

    with patch.object(model, 'invalidate', side_effect=invalidate):
        assert store.dequeue_force() is job
    assert before != sanitize('synthetic-old-endpoint', cfg)
    assert sanitize('synthetic-old-endpoint', cfg) == 'synthetic-old-endpoint'
    assert cfg.get('_security_projection_revision', 0) == revision + 1
    assert model._epoch == epoch + 1
    assert observed == [(True, (job,), before)]
    assert '_force_resolve_queue' not in cfg
    assert service.snapshot()['config_revision'] == 1


@pytest.mark.parametrize('legacy', [{'ens_rpc_url': 'legacy-endpoint'}, None, {}])
def test_legacy_force_key_removal_revokes_even_falsey_values(tmp_path, legacy):
    ctx, service, store = attached(tmp_path)
    cfg, model = ctx.shared_config, service.read_model
    cfg['_force_resolve'] = legacy
    observed = []
    original = model.invalidate

    def invalidate(*, hard=False):
        observed.append((hard, '_force_resolve' in cfg))
        original(hard=hard)

    with patch.object(model, 'invalidate', side_effect=invalidate):
        assert store.dequeue_force() is legacy
    assert cfg.get('_security_projection_revision', 0) == 1
    assert model._epoch == 1
    assert observed == [(True, True)]
    assert '_force_resolve' not in cfg
    assert store.dequeue_force() is None
    assert cfg['_security_projection_revision'] == 1
    assert model._epoch == 1


@pytest.mark.parametrize('owner', ['enqueue', 'fifo', 'legacy'])
def test_exhausted_authority_rejects_before_graph_mutation(tmp_path, owner):
    ctx, service, store = attached(tmp_path)
    cfg, model = ctx.shared_config, service.read_model
    cfg['_security_projection_revision'] = 9007199254740991
    job = {'ens_rpc_url': 'pinned-endpoint'}
    if owner == 'fifo':
        cfg['_force_resolve_queue'] = [job]
    elif owner == 'legacy':
        cfg['_force_resolve'] = job
    before = dict(cfg)
    with pytest.raises(OverflowError, match='security projection revision'):
        if owner == 'enqueue':
            admit(ctx, {'domain': 'x.test'})
        else:
            store.dequeue_force()
    assert cfg == before
    assert model._epoch == 0
    if owner == 'fifo':
        assert cfg['_force_resolve_queue'] == [job]


class CallbackInt(int):
    def __add__(self, other):
        raise AssertionError('revision callback invoked')

    def __eq__(self, other):
        raise AssertionError('revision callback invoked')


@pytest.mark.parametrize('value', [None, True, -1, 9007199254740992, 1.0, '1', [], {}, CallbackInt(1)])
@pytest.mark.parametrize('owner', ['enqueue', 'fifo', 'legacy'])
def test_malformed_authority_fails_closed_without_coercion(tmp_path, value, owner):
    ctx, service, store = attached(tmp_path)
    cfg, model = ctx.shared_config, service.read_model
    cfg['_security_projection_revision'] = value
    job = {'ens_rpc_url': 'pinned-endpoint'}
    if owner == 'fifo':
        cfg['_force_resolve_queue'] = [job]
    elif owner == 'legacy':
        cfg['_force_resolve'] = job
    before_keys = tuple(cfg)
    with pytest.raises(ValueError, match='security projection revision'):
        if owner == 'enqueue':
            admit(ctx, {'domain': 'x.test'})
        else:
            store.dequeue_force()
    with pytest.raises(ValueError, match='security projection revision'):
        security_projection_revision(cfg)
    assert tuple(cfg) == before_keys
    assert cfg['_security_projection_revision'] is value
    assert model._epoch == 0
    if owner == 'fifo':
        assert cfg['_force_resolve_queue'] == [job]
    elif owner == 'legacy':
        assert cfg['_force_resolve'] is job


def test_invalidation_failure_aborts_enqueue_and_finishes_started_audit(tmp_path):
    from unittest.mock import Mock
    from tests.test_config_revision import request

    ctx, service, _ = attached(tmp_path)
    cfg, model = ctx.shared_config, service.read_model
    handler = request({'domain': 'x.test'})
    handler.security_store = Mock()
    handler.request_id, handler.source_ip = 'request', 'local'
    error = RuntimeError('publisher revoke failed')
    with patch.object(model, 'invalidate', side_effect=error):
        with pytest.raises(RuntimeError) as caught:
            handle_resolve(ctx, handler)
    assert caught.value is error
    assert '_force_resolve_queue' not in cfg
    assert security_projection_revision(cfg) == 0
    assert model._epoch == 0  # No false claim that a failed invalidate revoked.
    assert [c.kwargs['outcome'] for c in handler.security_store.audit.call_args_list] == ['started', 'failure']


def test_fifo_append_pop_and_final_key_removal_each_advance_once(tmp_path):
    ctx, service, store = attached(tmp_path)
    cfg, model = ctx.shared_config, service.read_model
    assert admit(ctx, {'domain': 'x.test'}).status == 200
    queue = cfg['_force_resolve_queue']
    first = queue[0]
    assert admit(ctx, {'domain': 'x.test'}).status == 200
    second = queue[1]
    assert cfg['_force_resolve_queue'] is queue
    assert security_projection_revision(cfg) == model._epoch == 2
    assert store.dequeue_force() is first
    assert cfg['_force_resolve_queue'] is queue
    assert queue == [second]
    assert security_projection_revision(cfg) == model._epoch == 3
    assert store.dequeue_force() is second
    assert '_force_resolve_queue' not in cfg
    assert security_projection_revision(cfg) == model._epoch == 4
    assert store.dequeue_force() is None
    assert security_projection_revision(cfg) == model._epoch == 4


@pytest.mark.parametrize('queue', [None, [], 'not-a-queue'])
@pytest.mark.parametrize('revision', [None, 9007199254740991, 'malformed'])
def test_noop_dequeue_does_not_create_keys_or_advance(tmp_path, queue, revision):
    ctx, service, store = attached(tmp_path)
    cfg = ctx.shared_config
    if queue is not None:
        cfg['_force_resolve_queue'] = queue
    if revision is not None:
        cfg['_security_projection_revision'] = revision
    before = dict(cfg)
    with patch.object(service.read_model, 'invalidate') as invalidate:
        assert store.dequeue_force() is None
    assert cfg == before
    invalidate.assert_not_called()


@pytest.mark.parametrize('reason', ['full', 'actor_full', 'unavailable', 'invalid', 'audit_failure'])
def test_rejected_admission_does_not_create_queue_or_advance(tmp_path, reason):
    from unittest.mock import Mock
    from tests.test_config_revision import request

    ctx, service, _ = attached(tmp_path)
    cfg = ctx.shared_config
    if reason == 'full':
        cfg['_force_resolve_queue'] = [{'actor': {'id': n}} for n in range(64)]
    elif reason == 'actor_full':
        for _ in range(4):
            assert admit(ctx, {'domain': 'x.test'}).status == 200
    elif reason == 'unavailable':
        ctx.state_repository.configure({'domains': []})
    handler = request({'domain': 'missing.test' if reason == 'invalid' else 'x.test'})
    handler.security_store = Mock()
    handler.request_id, handler.source_ip = 'request', 'local'
    if reason == 'audit_failure':
        handler.security_store.audit.side_effect = RuntimeError('audit unavailable')
    before = dict(cfg)
    queue_before = list(cfg.get('_force_resolve_queue', []))
    with patch.object(service.read_model, 'invalidate') as invalidate:
        if reason == 'audit_failure':
            with pytest.raises(RuntimeError, match='audit unavailable'):
                handle_resolve(ctx, handler)
        else:
            handle_resolve(ctx, handler)
            assert handler.status == (429 if reason in ('full', 'actor_full') else 400)
    assert cfg == before
    assert cfg.get('_force_resolve_queue', []) == queue_before
    invalidate.assert_not_called()


def test_startup_without_publisher_counts_without_constructing_service(tmp_path):
    ctx = context(tmp_path)
    cfg = ctx.shared_config
    store = ConfigStore(cfg, ctx.config_lock, ctx.state_repository)
    before = tuple(cfg)
    assert security_projection_revision(cfg) == 0
    assert tuple(cfg) == before
    with patch('monitor.config_service.ConfigService', side_effect=AssertionError('service created')):
        with patch.object(BackgroundReadModel, 'start', side_effect=AssertionError('publisher started')):
            assert admit(ctx, {'domain': 'x.test'}).status == 200
            assert store.dequeue_force() is not None
    assert '_config_service' not in cfg
    assert security_projection_revision(cfg) == 2
    ctx.config_path = ''
    ctx.read_model = BackgroundReadModel(lambda previous: None, lambda value: {})
    service = get_config_service(ctx)
    assert security_projection_revision(service.shared_config) == 2
    assert service.read_model._thread is None
    assert admit(ctx, {'domain': 'x.test'}).status == 200
    assert security_projection_revision(cfg) == 3
    assert service.read_model._epoch == 1


def test_largest_revision_is_readable_but_cannot_advance(tmp_path):
    ctx, service, store = attached(tmp_path)
    cfg = ctx.shared_config
    cfg['_security_projection_revision'] = 9007199254740990
    assert admit(ctx, {'domain': 'x.test'}).status == 200
    assert security_projection_revision(cfg) == 9007199254740991
    with pytest.raises(OverflowError):
        store.dequeue_force()
    assert len(cfg['_force_resolve_queue']) == 1
    assert service.read_model._epoch == 1


@pytest.mark.parametrize('owner', ['enqueue', 'fifo', 'legacy'])
@pytest.mark.parametrize('after_revoke', [False, True])
def test_invalidation_exception_preserves_queue_and_propagates(tmp_path, owner, after_revoke):
    ctx, service, store = attached(tmp_path)
    cfg, model = ctx.shared_config, service.read_model
    assert admit(ctx, {'domain': 'x.test'}).status == 200
    queue = cfg['_force_resolve_queue']
    job = queue[0]
    if owner == 'legacy':
        assert store.dequeue_force() is job
        cfg['_force_resolve'] = job
    before = dict(cfg)
    revision, epoch = security_projection_revision(cfg), model._epoch
    error = RuntimeError('invalidation failed')
    original = model.invalidate

    def fail(*, hard=False):
        assert hard is True
        if after_revoke:
            original(hard=hard)
        raise error

    with patch.object(model, 'invalidate', side_effect=fail):
        with patch.object(store.condition, 'notify_all') as notify:
            with pytest.raises(RuntimeError) as caught:
                if owner == 'enqueue':
                    admit(ctx, {'domain': 'x.test'})
                else:
                    store.dequeue_force()
    assert caught.value is error
    assert cfg == before
    assert security_projection_revision(cfg) == revision
    assert model._epoch == epoch + int(after_revoke)
    if owner != 'legacy':
        assert cfg['_force_resolve_queue'] is queue
        assert queue == [job]
    else:
        assert cfg['_force_resolve'] is job
    notify.assert_not_called()


def test_scheduler_stale_drain_uses_same_projection_authority(tmp_path):
    from monitor.scheduler import MonitorScheduler

    ctx, service, store = attached(tmp_path, ens_rpc_url='old-endpoint')
    cfg, model = ctx.shared_config, service.read_model
    handler = admit(ctx, {'domain': 'x.test'})
    job = cfg['_force_resolve_queue'][0]
    service.commit('config', {'servers': ['replacement'], 'ens_rpc_url': 'new-endpoint'},
                   expected_revision=0)
    scheduler = MonitorScheduler(store, clock=lambda: 0)
    scheduler.completed(scheduler.next_scan(block=False), accepted=True)
    revision, epoch = security_projection_revision(cfg), model._epoch
    assert sanitize('old-endpoint', cfg) != 'old-endpoint'
    assert scheduler.next_scan(block=False) is None
    assert security_projection_revision(cfg) == revision + 1
    assert model._epoch == epoch + 1
    assert sanitize('old-endpoint', cfg) == 'old-endpoint'
    assert job['_terminal_outcome'] == 'failure'
    assert [c.kwargs['outcome'] for c in handler.security_store.audit.call_args_list] == ['started', 'failure']
    assert scheduler.next_scan(block=False) is None
    assert security_projection_revision(cfg) == revision + 1


def test_scheduler_stop_drains_pending_once_without_finishing_running(tmp_path):
    from monitor.scheduler import MonitorScheduler

    ctx, service, store = attached(tmp_path)
    cfg, model = ctx.shared_config, service.read_model
    scheduler = MonitorScheduler(store, clock=lambda: 0)
    scheduler.completed(scheduler.next_scan(block=False), accepted=True)
    running_handler = admit(ctx, {'domain': 'x.test'})
    running = scheduler.next_scan(block=False).force_req
    pending = [admit(ctx, {'domain': 'x.test'}) for _ in range(2)]
    jobs = list(cfg['_force_resolve_queue'])
    revision, epoch = security_projection_revision(cfg), model._epoch
    scheduler.stop()
    assert security_projection_revision(cfg) == revision + 2
    assert model._epoch == epoch + 2
    assert '_force_resolve_queue' not in cfg
    assert '_terminal_outcome' not in running
    assert [c.kwargs['outcome'] for c in running_handler.security_store.audit.call_args_list] == ['started']
    for handler, job in zip(pending, jobs):
        assert job['_terminal_outcome'] == 'failure'
        assert [c.kwargs['outcome'] for c in handler.security_store.audit.call_args_list] == ['started', 'failure']
    scheduler.stop()
    assert admit(ctx, {'domain': 'x.test'}).status == 503
    assert scheduler.next_scan(block=False) is None
    assert security_projection_revision(cfg) == revision + 2
    assert model._epoch == epoch + 2


def test_config_cas_persistence_and_delivery_signals_remain_separate(tmp_path):
    import json
    from unittest.mock import Mock
    from monitor.config_service import ConfigError

    ctx, service, store = attached(tmp_path)
    cfg, model = ctx.shared_config, service.read_model
    service.config_path = str(tmp_path / 'owned-config.json')
    delivery = Mock()
    delivery.configuration_committed.return_value = []
    delivery.apply_configuration.return_value = []
    service.delivery_runtime = delivery
    assert admit(ctx, {'domain': 'x.test'}).status == 200
    delivery.assert_not_called()
    assert delivery.mock_calls == []
    revision, epoch = security_projection_revision(cfg), model._epoch
    result = service.commit('config', {'interval': 123}, expected_revision=0)
    assert result['revision'] == 1
    assert security_projection_revision(cfg) == revision
    assert model._epoch == epoch + 2
    disk = json.loads((tmp_path / 'owned-config.json').read_text())
    assert disk['config_revision'] == 1
    assert not any(key.startswith('_') for key in disk)
    assert not any(key.startswith('_') for key in result['config'])
    delivery.configuration_committed.assert_called_once()
    assert delivery.configuration_committed.call_args.args[1] == ()
    delivery.apply_configuration.assert_called_once()
    calls = list(delivery.mock_calls)
    assert store.dequeue_force() is not None
    assert admit(ctx, {'domain': 'x.test'}).status == 200
    assert delivery.mock_calls == calls
    assert service.snapshot()['config_revision'] == 1
    before = (security_projection_revision(cfg), model._epoch)
    with pytest.raises(ConfigError) as conflict:
        service.commit('config', {'interval': 321}, expected_revision=0)
    assert conflict.value.status == 409
    assert (security_projection_revision(cfg), model._epoch) == before
    assert cfg['interval'] == 123
    assert json.loads((tmp_path / 'owned-config.json').read_text()) == disk


def test_queue_writer_progresses_with_capture_waiting_config_and_state_held(tmp_path):
    import threading
    from http_api.read_source import create_read_model
    from monitor.runtime_state import state_lock

    ctx, service, store = attached(tmp_path)
    cfg = ctx.shared_config
    assert admit(ctx, {'domain': 'x.test'}).status == 200
    repo = ctx.state_repository
    model = create_read_model(cfg, ctx.config_lock, repo.current, repo.history)
    service.read_model = model
    capture_entered, writer_done = threading.Event(), threading.Event()
    errors, jobs = [], []
    original_capture = model._capture

    def capture(previous):
        capture_entered.set()
        return original_capture(previous)

    model._capture = capture

    def writer():
        try:
            with ctx.config_lock:
                model.start()
                assert capture_entered.wait(2)
                # Real worker capture is waiting for config. Invalidation must
                # neither retain a publication->config edge nor acquire state.
                jobs.append(store.dequeue_force())
        except BaseException as exc:
            errors.append(exc)
        finally:
            writer_done.set()

    thread = threading.Thread(target=writer, daemon=True)
    try:
        with state_lock():
            thread.start()
            assert writer_done.wait(2), 'queue writer blocked on publication/state ownership'
        thread.join(2)
        assert not thread.is_alive()
        assert errors == []
        assert len(jobs) == 1 and jobs[0] is not None
        assert security_projection_revision(cfg) == 2
        assert model._epoch == 1
    finally:
        assert model.close(timeout=2)['remaining'] == 0
        thread.join(2)


def test_attached_service_without_publisher_ignores_opaque_graph_leaves(tmp_path):
    from monitor.projection_authority import advance_security_projection_locked

    class Opaque:
        def __getattr__(self, name):
            raise AssertionError('opaque leaf callback invoked')

        def __call__(self):
            raise AssertionError('opaque leaf callback invoked')

    ctx, service, store = attached(tmp_path)
    cfg = ctx.shared_config
    service.read_model = None
    cfg['_opaque_runtime'] = Opaque()
    with ctx.config_lock:
        assert security_projection_revision(cfg) == 0
        assert advance_security_projection_locked(cfg) == 1
    assert admit(ctx, {'domain': 'x.test'}).status == 200
    assert store.dequeue_force() is not None
    assert security_projection_revision(cfg) == 3
    assert cfg['_config_service'] is service
    assert service.read_model is None
