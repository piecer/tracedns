"""Actual accepted owner mutations, authority fences and detached graph release."""
import gc
import json
import weakref
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from http_api.read_capture import Capture, CaptureBudget, CaptureOwners, RootCursor
from http_api.read_model import BackgroundReadModel
from monitor.config_service import ConfigService, get_config_service
from monitor.repository import MonitorStateRepository
from monitor.runtime_state import get_state_version, state_lock
from tests.test_stage4_read_capture import source, drain


def attached():
    owners = CaptureOwners(*source())
    repo = MonitorStateRepository(owners.current, owners.history, '', owners.config['domains'])
    with owners.lock:
        repo.configure(owners.config)
    ctx = SimpleNamespace(shared_config=owners.config, config_lock=owners.lock, config_path='',
                          state_repository=repo, read_model=owners.model,
                          current_results=owners.current, history=owners.history)
    service = get_config_service(ctx)
    assert type(service) is ConfigService
    return owners, repo, service


def prepare(cap, phase):
    assert cap.slice() == 'more'
    if phase == 'slice':
        assert cap.slice() == 'more'
        return
    while cap.slice() == 'more':
        pass
    assert cap.status == 'done'
    if phase == 'take':
        assert cap.seal() == 'done'


def reject(cap, phase, status='mutation'):
    if phase == 'slice':
        assert cap.slice() == status
    elif phase == 'seal':
        assert cap.seal() == status
    else:
        assert cap.take() is None
        assert cap.status == status
    before = cap.budget.counters()
    assert cap.take() is None
    assert cap.slice() == cap.seal() == cap.discard() == cap.discard() == status
    assert cap.budget.counters() == before
    assert cap.counters()['workspace'] == 0


@pytest.mark.parametrize('phase', ['slice', 'seal', 'take'])
@pytest.mark.parametrize('owner', ['capture_insert', 'configure_remove', 'purge', 'legacy_drop',
                                 'provider_commit', 'service_rebind', 'stop'])
def test_real_owners_fence_every_capture_boundary(owner, phase):
    from monitor import engine
    from http_server import purge_removed_domains_state
    owners, repo, service = attached()
    with owners.lock:
        lease = repo.capture()['a.test']
    cap = Capture(owners, 'current', ('a.test',), budget=CaptureBudget.for_test(slice_steps=1))
    prepare(cap, phase)
    before = get_state_version()
    if owner == 'capture_insert':
        with owners.lock:
            repo.configure({'domains': ['a.test', 'b.test']})
            repo.capture()
        assert 'b.test' in owners.current and get_state_version() > before
    elif owner == 'configure_remove':
        with owners.lock:
            repo.configure({'domains': []})
        assert not repo.valid(lease)
    elif owner == 'purge':
        purge_removed_domains_state(owners.current, owners.history, '', ['a.test'])
        assert not repo.valid(lease)
    elif owner == 'legacy_drop':
        assert engine.drop_snapshot_for_failed_target(owners.current, owners.history, 'a.test', 'r', ts=2)
    elif owner == 'provider_commit':
        assert service.commit('config', {'ens_rpc_url': 'synthetic-new'}, expected_revision=0)['revision'] == 1
    elif owner == 'service_rebind':
        replacement = BackgroundReadModel(lambda _: None, lambda _: {})
        with owners.lock:
            get_config_service(SimpleNamespace(shared_config=owners.config, config_lock=owners.lock,
                config_path='', read_model=replacement))
        assert owners.model._epoch == 0  # Actual detach without old model epoch bump.
    else:
        owners.model.stop_admission()
    reject(cap, phase, 'stopped' if owner == 'stop' else 'mutation')


@pytest.mark.parametrize('phase', ['slice', 'seal', 'take'])
def test_real_accept_same_size_clear_update_fenced(tmp_path, phase):
    from tests.test_stage3_core_runtime import app_factory
    app = app_factory(tmp_path, current={'test.example': {'r': {'v': 'old'}}},
                      config={'domains': [{'name': 'test.example', 'type': 'A'}],
                              'servers': ['r'], 'alerts': {}, 'config_revision': 0})
    model = BackgroundReadModel(lambda _: None, lambda _: {})
    owners = CaptureOwners(app.cfg.raw, app.cfg.lock, app.current, app.history, model)
    try:
        with owners.lock:
            lease = app.repo.capture()['test.example']
        old_identity = id(lease.current)
        cap = Capture(owners, 'current', ('test.example',), budget=CaptureBudget.for_test(slice_steps=1))
        prepare(cap, phase)
        assert app.repo.accept_observation(lease, lease.target.version,
            {'r': {'v': 'new'}}, {'meta': {}, 'events': [], 'current': {}}, {}, None)
        assert id(lease.current) == old_identity and app.repo.valid(lease)
        reject(cap, phase)
    finally:
        app.delivery.stop()


@pytest.mark.parametrize('phase', ['slice', 'seal', 'take'])
def test_rotation_then_actual_queue_dequeue_fences(phase, tmp_path):
    from tests.test_stage4_projection_authority import attached as force_attached
    from tests.test_stage2_force import admit
    ctx, service, store = force_attached(tmp_path, domains=[{'name': 'x.eth', 'type': 'ENS'}],
        servers=[], ens_rpc_url='synthetic-old-endpoint')
    repo = ctx.state_repository
    with ctx.config_lock:
        repo.capture()
    assert admit(ctx, {'domains': [{'name': 'x.eth', 'type': 'ENS'}]}).status == 200
    service.commit('config', {'ens_rpc_url': 'synthetic-new-endpoint'}, expected_revision=0)
    owners = CaptureOwners(ctx.shared_config, ctx.config_lock, repo.current, repo.history, service.read_model)
    cap = Capture(owners, 'config', ('domains',), budget=CaptureBudget.for_test(slice_steps=1))
    prepare(cap, phase)
    old_revision = service.snapshot()['config_revision']
    assert store.dequeue_force()['ens_rpc_url'] == 'synthetic-old-endpoint'
    assert service.snapshot()['config_revision'] == old_revision
    reject(cap, phase)


def test_root_iterator_revoked_before_next_through_actual_insert():
    owners, repo, _ = attached()
    cursor = RootCursor(owners, 'current', budget=CaptureBudget())
    # Make an initial root larger than one, through real owner materialization.
    with owners.lock:
        repo.configure({'domains': ['a.test', 'b.test']})
        repo.capture()
    assert cursor.next_key() == 'a.test'
    with owners.lock:
        repo.configure({'domains': ['a.test', 'b.test', 'c.test']})
        repo.capture()
    assert cursor.next_key() is None and cursor.status == 'mutation'
    assert cursor._iterator is None


def test_no_nested_borrowed_graph_survives_unlock_or_failure():
    class Marker:
        pass
    owners, repo, _ = attached()
    marker = Marker()
    marker_ref = weakref.ref(marker)
    owners.history['a.test']['events'] = [{'v': 'x' * 9000, 'opaque': [marker] * 50000}]
    del marker
    cap = Capture(owners, 'history', ('a.test', 'events'),
                  budget=CaptureBudget.for_test(slice_steps=1), skip_fields=('opaque',))
    for _ in range(8):
        assert cap.slice() == 'more'
    # Actual repository removes the root graph. No retained lease in this test.
    with owners.lock:
        repo.configure({'domains': []})
    gc.collect()
    assert marker_ref() is None, 'a suspended frame pinned a detached nested source graph'
    reject(cap, 'slice')


def test_unversioned_real_legacy_telemetry_parity_and_lifecycle_fence():
    from http_api.read_source import build_read_views, capture_read_inputs
    from models import DomainSpec, QueryResult, Snapshot
    from monitor import engine
    from monitor.collect import Collected
    owners, repo, _ = attached()
    with owners.lock:
        lease = repo.capture()['a.test']
    snapshot = Snapshot(type='A', values=['192.0.2.1'], ts=1).to_dict()
    owners.current['a.test']['r'] = snapshot
    owners.history['a.test']['current'] = {'r': dict(snapshot)}

    def cycle(now, servers, status='ok'):
        def collect(domain, server):
            return Collected(QueryResult(server, domain.name, 'A', status, ['192.0.2.1']),
                             Snapshot(type='A', values=['192.0.2.1'] if status == 'ok' else [], ts=2))
        with patch.object(engine, 'collect_snapshot', side_effect=collect), \
                patch.object(engine.time, 'time', return_value=now), \
                patch.object(engine, 'persist_history_entry', return_value=True):
            engine.run_domain_cycle(domain=DomainSpec('a.test'), servers=servers,
                current_results=owners.current, history=owners.history, history_dir='',
                query_fail_counts={}, state_repository=repo, target_lease=lease, max_workers=1)

    cycle(20, ['r'])
    before = get_state_version()
    original_meta = json.dumps(owners.history['a.test']['meta'])
    views = build_read_views(capture_read_inputs(owners.config, owners.lock, owners.current, owners.history, None)[1])
    cap = Capture(owners, 'history', ('a.test', 'meta'), budget=CaptureBudget.for_test(slice_steps=1), projection='prepared_meta')
    expected = drain(Capture(owners, 'history', ('a.test', 'meta'), budget=CaptureBudget(), projection='prepared_meta'))
    assert cap.slice() == 'more'
    cycle(30, ['r', 'r'])
    assert get_state_version() == before
    assert original_meta != json.dumps(owners.history['a.test']['meta'])
    assert drain(cap) == expected
    projected = {'a.test': {'meta': json.loads(expected), 'events': []}}
    assert build_read_views((owners.current, projected, owners.config['domains'])) == views
    cap = Capture(owners, 'history', ('a.test', 'meta'), budget=CaptureBudget(), projection='prepared_meta')
    while cap.slice() == 'more':
        pass
    assert cap.seal() == 'done'
    cycle(40, ['r'])
    assert cap.take() == expected
    cap = Capture(owners, 'history', ('a.test', 'meta'), budget=CaptureBudget(), projection='prepared_meta')
    assert cap.slice() == 'more'
    cycle(50, ['r'], 'nxdomain')
    assert get_state_version() > before
    assert cap.slice() == 'mutation'
    assert state_lock().acquire(blocking=False)
    state_lock().release()
