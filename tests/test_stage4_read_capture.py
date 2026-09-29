"""Persistent capture-v2 regressions; historical RED stays in evidence."""
import json
import threading

import pytest

from http_api.read_model import BackgroundReadModel


def source():
    return ({'domains': [{'name': 'a.test', 'type': 'A'}], '_config_revision': 0},
            threading.RLock(),
            {'a.test': {'r': {'type': 'A', 'values': ['192.0.2.1'], 'ts': 1}}},
            {'a.test': {'meta': {'first_seen': 1}, 'events': []}},
            BackgroundReadModel(lambda previous: None, lambda inputs: {}))


def drain(cap):
    for _ in range(20000):
        status = cap.slice()
        if status != 'more':
            assert status == 'done', cap.counters()
            assert cap.seal() == 'done'
            result = cap.take()
            assert type(result) is bytes, cap.counters()
            return result
    raise AssertionError('capture made no finite completion')


@pytest.mark.parametrize('slot,target', [
    ('meta', 'nxdomain_active'), ('config', '_config_revision'),
    ('config', '_security_projection_revision'), ('config', '_config_service'),
    ('current', 'a.test'), ('history', 'a.test'), ('entry', 'meta'),
])
def test_colliding_stored_keys_execute_zero_callbacks(slot, target):
    from http_api.read_capture import Capture, CaptureBudget, CaptureOwners
    callbacks = []

    class Collision:
        def __hash__(self):
            return hash(target)

        def __eq__(self, other):
            callbacks.append('equality')
            return False

    owners = CaptureOwners(*source())
    poison = Collision()
    if slot == 'meta':
        owners.history['a.test']['meta'] = {poison: 'ignored', 'dns_cycle_total': 7}
    elif slot == 'entry':
        owners.history['a.test'] = {poison: 'ignored', 'meta': {'first_seen': 1}}
    else:
        root = getattr(owners, slot)
        saved = tuple(root.items())
        root.clear()
        root[poison] = 'ignored'
        root.update(saved)
    callbacks.clear()
    root, path, projection = ('current', ('a.test',), 'complete') if slot == 'current' else (
        'history', ('a.test', 'meta'), 'prepared_meta')
    cap = Capture(owners, root, path, budget=CaptureBudget(), projection=projection)
    first_status = cap.slice()
    if slot in ('meta', 'config', 'current', 'history', 'entry'):
        assert first_status in ('invalid', 'capacity')
    for _ in range(100):
        if cap.slice() != 'more':
            break
    assert callbacks == [], 'source hook ran before rejection'
    assert cap.status in ('invalid', 'capacity')
    assert cap.take() is None


def test_real_current_small_unit_sliced_owned_exact_bytes():
    from http_api.read_capture import Capture, CaptureBudget, CaptureOwners
    from monitor.repository import MonitorStateRepository
    owners = CaptureOwners(*source())
    repo = MonitorStateRepository(owners.current, owners.history, '', owners.config['domains'])
    with owners.lock:
        repo.configure(owners.config)
        lease = repo.capture()['a.test']
    budget = CaptureBudget.for_test(slice_steps=1)
    cap = Capture(owners, 'current', ('a.test',), budget=budget)
    expected = json.dumps(lease.current, ensure_ascii=False, separators=(',', ':'),
                          allow_nan=False).encode()
    assert cap.slice() == 'more'
    assert cap.take() is None
    result = drain(cap)
    assert result == expected
    assert cap.counters()['slices'] > 1
    assert cap.take() is None
    lease.current['r']['values'].append('post-transfer')
    assert result == expected
    assert cap.counters()['workspace'] == 0


def test_root_certificate_cannot_authorize_config_hashing_through_alias():
    from http_api.read_capture import Capture, CaptureBudget, CaptureOwners
    config, lock, _, history, model = source()
    config['a.test'] = 0
    owners = CaptureOwners(config, lock, config, history, model)
    budget = CaptureBudget()
    cap = Capture(owners, 'current', ('a.test',), budget=budget)
    assert cap.slice() == 'more'
    callbacks = []
    class Collision:
        def __hash__(self):
            return hash('_config_revision')
        def __eq__(self, other):
            callbacks.append('equality')
            return False
    del config['_config_revision']
    config[Collision()] = 'ignored'
    callbacks.clear()
    assert cap.slice() == 'invalid'
    assert callbacks == []
    assert cap.take() is None
