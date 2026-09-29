"""Actual-owner semantic progress; no relaxed limits or precertifying cursor."""
import json
import threading
from types import SimpleNamespace

import pytest

from http_api.read_capture import Capture, CaptureBudget, CaptureOwners
from http_api.read_model import BackgroundReadModel
from monitor.config_service import ConfigService, get_config_service
from monitor.projection_authority import security_projection_revision
from monitor.repository import MonitorStateRepository
from monitor.runtime_state import get_state_version, state_lock


def actual_source(root_size=1, config_size=128, current=None):
    config = {'domains': [f'd{i:03d}.test' for i in range(root_size)], '_config_revision': 0}
    config.update({f'_review_pad_{i:03d}': None for i in range(config_size - 3)})
    lock = threading.RLock()
    current, history = {} if current is None else current, {}
    model = BackgroundReadModel(lambda previous: None, lambda value: {})
    repo = MonitorStateRepository(current, history, '', config['domains'])
    with lock:
        repo.configure(config)
        repo.capture()
    service = get_config_service(SimpleNamespace(shared_config=config, config_lock=lock,
        config_path='', state_repository=repo, read_model=model,
        current_results=current, history=history))
    assert type(service) is ConfigService and service.read_model is model
    assert config['_config_service'] is service
    assert len(config) == config_size and len(current) == len(history) == root_size
    assert model._thread is None
    return CaptureOwners(config, lock, current, history, model), repo, service


def token(owners):
    with owners.lock, state_lock(), owners.model._condition:
        return (get_state_version(), owners.config.get('_config_revision', 0),
                security_projection_revision(owners.config), id(owners.model),
                owners.model._epoch, owners.model._stopped)


def complete(cap):
    trace = []
    for _ in range(1024):
        before = cap.budget.visits
        status = cap.slice()
        trace.append((status, cap.budget.visits - before, cap.budget.descriptors,
                      cap.bytes, cap.nodes, len(cap._frames)))
        assert trace[-1][1] <= 512
        if status != 'more':
            break
    result = None
    if cap.status == 'done':
        assert cap.seal() == 'done'
        result = cap.take()
    print('PROGRESS_TRACE', json.dumps(trace))
    return result


def released(cap):
    cap.discard()
    assert cap.budget.workspace == 0
    assert cap.budget._unit is cap.budget._running is cap._root_cursor is None
    assert not cap._frames and not cap._buffer
    before = cap.budget.counters()
    assert cap.take() is None
    assert cap.slice() == cap.seal() == cap.discard()
    assert cap.budget.counters() == before


@pytest.mark.parametrize('fixture_id,root_size', [('P1', 125), ('P2', 129), ('P3', 128)])
def test_actual_owner_root_headroom_exact_empty_unit(fixture_id, root_size):
    owners, _, _ = actual_source(root_size)
    expected = json.dumps(owners.current['d000.test'], ensure_ascii=False,
                          separators=(',', ':'), allow_nan=False).encode('utf-8')
    assert expected == b'{}'
    authority_before = token(owners)
    budget = CaptureBudget()
    cap = Capture(owners, 'current', ('d000.test',), budget=budget)
    try:
        result = complete(cap)
        assert result == expected, (fixture_id, root_size, 'small complete unit must yield exact bytes', cap.status)
        assert token(owners) == authority_before
        assert owners.current['d000.test'] == {}
        assert budget.descriptors == root_size, 'root admission must not be duplicated'
        assert cap.max_slice_visits <= 512 and cap.max_slice_bytes <= 16384
        assert budget.visits <= 262144 and budget.descriptors <= 16384
        assert budget.peak_workspace <= 16 * 1024 * 1024
        assert cap.slices <= 8
    finally:
        released(cap)


@pytest.mark.parametrize('members', [1, 128])
def test_actual_owner_composed_nested_prefix_progress(members):
    # Both dictionaries are individually admitted; resolving the three owned
    # keys must not replay the first validation until the attempt expires.
    inner = {'leaf': {}}
    outer = {'inner': inner}
    for index in range(members - 1):
        inner[f'pad{index}'] = None
        outer[f'pad{index}'] = None
    owners, _, _ = actual_source(config_size=3, current={'d000.test': outer})
    cap = Capture(owners, 'current', ('d000.test', 'inner', 'leaf'), budget=CaptureBudget())
    before = token(owners)
    try:
        assert complete(cap) == b'{}', 'admitted composed prefix must reach its complete unit'
        assert token(owners) == before
        assert cap.max_slice_visits <= 512
        assert cap.budget.descriptors == 1
        assert cap.slices <= 10
    finally:
        released(cap)


@pytest.mark.parametrize('root', ['current', 'history', 'config'])
def test_composed_prefix_with_maximum_authority_headroom(root):
    inner = dict.fromkeys((f'pad{i}' for i in range(127)))
    inner['leaf'] = {'unicode': 'é😀', 'tuple': (None, True, 7)}
    outer = dict.fromkeys((f'pad{i}' for i in range(127)))
    outer['inner'] = inner
    owners, _, _ = actual_source(current={'d000.test': outer})
    if root == 'current':
        path = ('d000.test', 'inner', 'leaf')
    elif root == 'history':
        owners.history['d000.test']['events'] = [outer]
        path = ('d000.test', 'events', 0, 'inner', 'leaf')
    else:
        # Initial admitted fixture, before any capture. Config root remains
        # freshly validated even though the selected domains graph is fenced.
        owners.config['domains'] = [outer]
        path = ('domains', 0, 'inner', 'leaf')
    cap = Capture(owners, root, path, budget=CaptureBudget())
    expected = json.dumps(inner['leaf'], ensure_ascii=False, separators=(',', ':')).encode()
    try:
        for _ in range(32):
            before = cap._progress
            status = cap.slice()
            assert cap.max_slice_visits <= 512
            if status != 'more':
                break
            assert cap._progress > before or cap._root_cursor is not None
            assert len(cap._validated_paths) <= 32
            for owned_path, state in cap._validated_paths.items():
                assert type(owned_path) is tuple and len(owned_path) <= 32
                assert all(type(part) in (str, int) for part in owned_path)
                assert type(state) is tuple and all(type(part) is int for part in state)
            assert cap._workspace >= len(cap._validated_paths) * 65536
        assert cap.status == cap.seal() == 'done'
        assert cap.take() == expected
        assert not cap._validated_paths
    finally:
        released(cap)


@pytest.mark.parametrize('phase', ['slice', 'seal', 'take'])
def test_owned_certificates_reject_real_same_size_publication(tmp_path, phase):
    from tests.test_stage3_core_runtime import app_factory
    inner = dict.fromkeys((f'pad{i}' for i in range(127)))
    inner['leaf'] = 'x' * 9000
    app = app_factory(tmp_path, current={'test.example': {'inner': inner}},
        config={'domains': [{'name': 'test.example', 'type': 'A'}],
                'servers': ['r'], 'alerts': {}, 'config_revision': 0})
    model = BackgroundReadModel(lambda _: None, lambda _: {})
    get_config_service(SimpleNamespace(shared_config=app.cfg.raw, config_lock=app.cfg.lock,
        config_path='', state_repository=app.repo, read_model=model,
        current_results=app.current, history=app.history))
    owners = CaptureOwners(app.cfg.raw, app.cfg.lock, app.current, app.history, model)
    with owners.lock:
        for index in range(128 - len(owners.config)):
            owners.config[f'_progress_pad{index}'] = None
        lease = app.repo.capture()['test.example']
    cap = Capture(owners, 'current', ('test.example', 'inner', 'leaf'), budget=CaptureBudget())
    try:
        assert cap.slice() == cap.slice() == 'more'
        assert any(offset < size for size, offset in cap._validated_paths.values())
        if phase != 'slice':
            while cap.slice() == 'more':
                pass
            assert cap.status == 'done' and cap._validated_paths
            if phase == 'take':
                assert cap.seal() == 'done'
        before = token(owners)
        identity = id(lease.current)
        assert app.repo.accept_observation(lease, lease.target.version,
            {'inner': {'leaf': 'replacement'}}, {'meta': {}, 'events': [], 'current': {}}, {}, None)
        assert id(lease.current) == identity and token(owners) != before
        result = getattr(cap, phase)()
        assert result == (None if phase == 'take' else 'mutation')
        assert cap.status == 'mutation' and not cap._validated_paths
    finally:
        released(cap)
        app.delivery.stop()


def collision(callbacks, target):
    class Collision:
        def __hash__(self):
            return hash(target)

        def __eq__(self, other):
            callbacks.append('equality')
            return False
    return Collision()


def test_partial_validation_rejects_last_colliding_key_before_lookup():
    callbacks = []
    value = dict.fromkeys((f'pad{i}' for i in range(127)))
    value[collision(callbacks, 'leaf')] = None
    owners, _, _ = actual_source(current={'d000.test': value})
    callbacks.clear()
    cap = Capture(owners, 'current', ('d000.test', 'leaf'), budget=CaptureBudget())
    try:
        assert cap.slice() == cap.slice() == 'more'
        assert cap._validated_paths and callbacks == []
        assert cap.slice() == 'invalid'
        assert callbacks == [] and cap.take() is None
    finally:
        released(cap)


def test_owned_path_certificate_never_certifies_nested_config_alias():
    owners, _, _ = actual_source(config_size=3)
    owners.current['d000.test']['alias'] = owners.config
    cap = Capture(owners, 'current', ('d000.test', 'alias', 'domains'),
                  budget=CaptureBudget.for_test(slice_steps=1))
    try:
        assert cap.slice() == cap.slice() == 'more'
        assert cap._validated_paths
        assert ('d000.test', 'alias') not in cap._validated_paths
        callbacks = []
        # Private shape is deliberately NOT fenced by persistent revision.
        with owners.lock:
            owners.config[collision(callbacks, '_config_revision')] = None
        callbacks.clear()
        assert cap.slice() == 'invalid' and callbacks == []
    finally:
        released(cap)


def test_metadata_never_uses_retained_validation_even_after_root_certificate():
    owners, _, _ = actual_source(config_size=3)
    owners.history['d000.test']['meta'] = {'dns_cycle_total': 7}
    cap = Capture(owners, 'history', ('d000.test', 'meta'),
                  budget=CaptureBudget.for_test(slice_steps=1), projection='prepared_meta')
    try:
        assert cap.slice() == cap.slice() == 'more'
        assert not cap._validated_paths
        callbacks = []
        with owners.lock, state_lock():
            owners.history['d000.test']['meta'][collision(callbacks, 'nxdomain_active')] = None
        callbacks.clear()
        assert cap.slice() == 'invalid' and callbacks == []
        assert not cap._validated_paths
    finally:
        released(cap)


def test_validation_paths_never_pin_detached_nested_graph():
    import gc
    import weakref

    class Marker:
        pass

    marker = Marker()
    reference = weakref.ref(marker)
    value = dict.fromkeys((f'pad{i}' for i in range(126)))
    value.update(leaf={}, opaque=marker)
    owners, repo, _ = actual_source(current={'d000.test': value})
    del marker, value
    cap = Capture(owners, 'current', ('d000.test', 'leaf'), budget=CaptureBudget())
    try:
        assert cap.slice() == cap.slice() == 'more'
        assert cap._validated_paths
        with owners.lock:
            repo.configure({'domains': []})
        gc.collect()
        assert reference() is None, 'validation state retained a borrowed nested graph'
        assert cap.slice() == 'mutation' and not cap._validated_paths
    finally:
        released(cap)


def test_authority_replay_alone_is_not_reported_as_semantic_progress():
    owners, _, _ = actual_source(config_size=3)
    cap = Capture(owners, 'current', ('d000.test',),
                  budget=CaptureBudget.for_test(slice_visits=10))
    try:
        assert cap.slice() == 'more'  # Own a resumable root cursor.
        assert cap.slice() == 'capacity'  # Lower-only seam cannot admit one key.
        assert cap.bytes == cap.nodes == cap.budget.descriptors == 0
        assert cap.max_slice_visits == 10
    finally:
        released(cap)
