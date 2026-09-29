"""Real legacy publication failures must revoke captures before owner unlock."""
import threading
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from http_api.read_capture import Capture, CaptureBudget, CaptureOwners
from http_api.read_model import BackgroundReadModel
from models import DomainSpec, QueryResult, Snapshot
from monitor import engine
from monitor.collect import Collected
from monitor.config_service import ConfigService, get_config_service
from monitor.repository import MonitorStateRepository
from monitor.runtime_state import get_state_version, state_lock


def owner(current, history, history_dir=''):
    config = {'domains': ['a.test'], '_config_revision': 0}
    lock = threading.RLock()
    model = BackgroundReadModel(lambda _: None, lambda _: {})
    repo = MonitorStateRepository(current, history, history_dir, config['domains'])
    with lock:
        repo.configure(config)
        lease = repo.capture()['a.test']
    service = get_config_service(SimpleNamespace(
        shared_config=config, config_lock=lock, config_path='', state_repository=repo,
        read_model=model, current_results=current, history=history))
    assert type(service) is ConfigService and config['_config_service'] is service
    assert service.read_model is model and model._thread is None
    assert repo.delivery_runtime is None
    return CaptureOwners(config, lock, current, history, model), repo, lease


def cycle(o, repo, lease):
    return engine.run_domain_cycle(
        domain=DomainSpec('a.test'), servers=['r'], current_results=o.current,
        history=o.history, history_dir=repo.history_dir, query_fail_counts={},
        state_repository=repo, target_lease=lease, max_workers=1)


def changed():
    return Collected(QueryResult('r', 'a.test', 'A', 'ok', ['192.0.2.2']),
                     Snapshot(type='A', values=['192.0.2.2'], ts=2))


def finish(cap):
    for _ in range(1024):
        if cap.slice() != 'more':
            break
    assert cap.status == 'done'


def assert_released(cap):
    cap.discard()
    assert cap.budget.workspace == 0
    assert cap.budget._unit is cap.budget._running is cap._root_cursor is None
    assert not cap._frames and not cap._buffer and not cap._validated_paths


def watch_bumps(monkeypatch):
    real, calls = engine.bump_state_version, []

    def bump():
        assert state_lock()._is_owned(), 'publication fence must precede owner unlock'
        calls.append(real())
        return calls[-1]

    monkeypatch.setattr(engine, 'bump_state_version', bump)
    return calls


def test_changed_event_failure_revokes_sealed_capture(monkeypatch):
    """Persistent C-RR-01: valid events plus initially ignored meta=None."""
    snap = Snapshot(type='A', values=['192.0.2.1'], ts=1).to_dict()
    o, repo, lease = owner({'a.test': {'r': snap}},
        {'a.test': {'meta': None, 'events': [{'ts': 1}], 'current': {'r': dict(snap)}}})
    cap = Capture(o, 'history', ('a.test', 'events'), budget=CaptureBudget())
    bumps = watch_bumps(monkeypatch)
    try:
        finish(cap)
        assert cap.seal() == 'done' and cap._validated_paths
        before = get_state_version()
        with patch.object(engine, 'collect_snapshot', return_value=changed()) as transport, \
                patch.object(engine, 'persist_history_entry') as persistence:
            with pytest.raises(TypeError) as caught:
                cycle(o, repo, lease)
        assert str(caught.value) == "'NoneType' object does not support item assignment"
        assert transport.call_count == 1 and persistence.call_count == 0
        assert lease.history is o.history['a.test'] and lease.current is o.current['a.test']
        assert repo.valid(lease) and lease.history['meta'] is None
        assert lease.current == {'r': snap} and lease.history['current'] == {'r': snap}
        assert lease.history['events'] == [{'ts': 1}, {
            'ts': 2, 'server': 'r', 'type': 'A',
            'old': {'values': ['192.0.2.1'], 'decoded_ips': [], 'ts': 1},
            'new': {'values': ['192.0.2.2'], 'decoded_ips': [], 'ts': 2}}]
        result = cap.take()
        assert result is None and cap.status == 'mutation', 'partial event publication must revoke sealed bytes'
        assert get_state_version() == before + 1 and bumps == [before + 1]
    finally:
        assert_released(cap)


def test_initial_current_failure_revokes_sealed_capture(monkeypatch):
    """Initial current is published before malformed history-current raises."""
    o, repo, lease = owner({'a.test': {}},
        {'a.test': {'meta': {}, 'events': [], 'current': None}})
    cap = Capture(o, 'current', ('a.test',), budget=CaptureBudget())
    bumps = watch_bumps(monkeypatch)
    try:
        finish(cap)
        assert cap.seal() == 'done'
        before = get_state_version()
        with patch.object(engine, 'collect_snapshot', return_value=changed()) as transport, \
                patch.object(engine, 'persist_history_entry') as persistence:
            with pytest.raises(TypeError) as caught:
                cycle(o, repo, lease)
        assert str(caught.value) == "'NoneType' object does not support item assignment"
        assert transport.call_count == 1 and persistence.call_count == 0
        assert lease.current == {'r': changed().snapshot.to_dict()}
        assert lease.history == {'meta': {}, 'events': [], 'current': None}
        assert lease.current is o.current['a.test'] and lease.history is o.history['a.test']
        assert repo.valid(lease)
        result = cap.take()
        assert result is None and cap.status == 'mutation', 'partial initial publication must revoke sealed bytes'
        assert get_state_version() == before + 1 and bumps == [before + 1]
    finally:
        assert_released(cap)


def prepare(cap, phase):
    if phase == 'slice':
        assert cap.slice() == 'more'
    else:
        finish(cap)
        if phase == 'take':
            assert cap.seal() == 'done'


def reject(cap, phase):
    if phase == 'take':
        assert cap.take() is None
    else:
        assert getattr(cap, phase)() == 'mutation'
    assert cap.status == 'mutation'
    counters = cap.budget.counters()
    assert cap.take() is None
    assert cap.slice() == cap.seal() == cap.discard() == 'mutation'
    assert counters == cap.budget.counters()
    assert_released(cap)


@pytest.mark.parametrize('phase', ['slice', 'seal', 'take'])
@pytest.mark.parametrize('case', ['initial_root', 'initial_current', 'initial_meta',
                                 'event_meta', 'event_current'])
def test_partial_publication_fences_every_boundary(case, phase, monkeypatch):
    initial = case.startswith('initial')
    snap = Snapshot(type='A', values=['192.0.2.1'], ts=1).to_dict()
    current = {'a.test': {} if initial else {'r': snap}}
    hist = {'meta': {'first_seen': 1}, 'events': [{'ts': 1}], 'current': {}}
    if case.endswith('root'):
        hist = None
        error, message = AttributeError, "'NoneType' object has no attribute 'setdefault'"
    elif case.endswith('current'):
        hist['current'] = None
        error, message = TypeError, "'NoneType' object does not support item assignment"
    else:
        hist['meta'] = None
        error = AttributeError if initial else TypeError
        message = ("'NoneType' object has no attribute 'setdefault'" if initial else
                   "'NoneType' object does not support item assignment")
    o, repo, lease = owner(current, {'a.test': hist})
    cap = Capture(o, 'current' if initial else 'history',
                  ('a.test',) if initial else ('a.test', 'events'),
                  budget=CaptureBudget.for_test(slice_steps=1))
    bumps = watch_bumps(monkeypatch)
    try:
        prepare(cap, phase)
        before = get_state_version()
        with patch.object(engine, 'collect_snapshot', return_value=changed()), \
                patch.object(engine, 'persist_history_entry') as persistence:
            with pytest.raises(error) as caught:
                cycle(o, repo, lease)
        assert str(caught.value) == message and persistence.call_count == 0
        assert repo.valid(lease) and lease.history is hist and lease.current is current['a.test']
        if initial:
            assert lease.current == {'r': changed().snapshot.to_dict()}
        else:
            assert lease.current == {'r': snap} and len(hist['events']) == 2
        if case.endswith('current'):
            assert hist['current'] is None
        elif case.endswith('meta'):
            assert hist['meta'] is None
        assert get_state_version() == before + 1 and bumps == [before + 1]
        reject(cap, phase)
    finally:
        assert_released(cap)


@pytest.mark.parametrize('initial', [False, True])
@pytest.mark.parametrize('helper', ['clone_history_entry', 'snapshot_or_trim'])
def test_ordinary_helper_failure_identity_and_partial_state(initial, helper, monkeypatch):
    snap = Snapshot(type='A', values=['192.0.2.1'], ts=1).to_dict()
    hist = {'meta': {'first_seen': 1}, 'events': [{'ts': 1}], 'current': {}}
    o, repo, lease = owner({'a.test': {} if initial else {'r': snap}}, {'a.test': hist})
    cap = Capture(o, 'current' if initial else 'history',
                  ('a.test',) if initial else ('a.test', 'events'), budget=CaptureBudget())
    failure = RuntimeError('ordinary publication helper failed')
    helper_name = ('_snapshot_dict' if initial else 'trim_history_events') if helper == 'snapshot_or_trim' else helper
    real_helper = getattr(engine, helper_name)
    calls = []
    bumps = watch_bumps(monkeypatch)

    def fail(*args, **kwargs):
        calls.append(1)
        # Initial conversion #1 precedes its actual current assignment; #2 follows it.
        if helper_name == '_snapshot_dict' and len(calls) == 1:
            return real_helper(*args, **kwargs)
        assert state_lock()._is_owned()
        raise failure

    try:
        finish(cap)
        assert cap.seal() == 'done'
        before = get_state_version()
        with patch.object(engine, 'collect_snapshot', return_value=changed()), \
                patch.object(engine, helper_name, side_effect=fail), \
                patch.object(engine, 'persist_history_entry') as persistence:
            with pytest.raises(RuntimeError) as caught:
                cycle(o, repo, lease)
        assert caught.value is failure and str(caught.value) == 'ordinary publication helper failed'
        assert len(calls) == (2 if helper_name == '_snapshot_dict' else 1)
        assert persistence.call_count == 0 and repo.valid(lease)
        if initial or helper == 'clone_history_entry':
            assert lease.current == {'r': changed().snapshot.to_dict()}
        else:
            assert lease.current == {'r': snap}
        assert len(hist['events']) == (1 if initial else 2)
        assert get_state_version() == before + 1 and bumps == [before + 1]
        reject(cap, 'take')
    finally:
        assert_released(cap)


@pytest.mark.parametrize('case', ['event_events', 'event_root', 'initial_timestamp'])
def test_natural_failure_before_publication_does_not_advance(case, monkeypatch):
    snap = Snapshot(type='A', values=['192.0.2.1'], ts=1).to_dict()
    initial = case == 'initial_timestamp'
    hist = {'meta': None, 'events': None, 'current': {}} if case != 'event_root' else None
    current = {'a.test': {} if initial else {'r': snap}}
    o, repo, lease = owner(current, {'a.test': hist})
    cap = Capture(o, 'current', ('a.test',), budget=CaptureBudget())
    before = get_state_version()
    bumps = watch_bumps(monkeypatch)
    collected = changed()
    if initial:
        collected.snapshot.ts = 'malformed'
        error, message = ValueError, "invalid literal for int() with base 10: 'malformed'"
    else:
        error = AttributeError
        message = "'NoneType' object has no attribute '" + ('append' if case == 'event_events' else 'setdefault') + "'"
    try:
        finish(cap)
        assert cap.seal() == 'done'
        with patch.object(engine, 'collect_snapshot', return_value=collected), \
                patch.object(engine, 'persist_history_entry') as persistence:
            with pytest.raises(error) as caught:
                cycle(o, repo, lease)
        assert str(caught.value) == message
        assert persistence.call_count == 0 and not bumps and get_state_version() == before
        assert lease.current == ({} if initial else {'r': snap})
        assert lease.history is hist and repo.valid(lease)
        assert cap.take() is not None and cap.status == 'taken'
    finally:
        assert_released(cap)


@pytest.mark.parametrize('initial', [False, True])
@pytest.mark.parametrize('persistence_fails', [False, True])
def test_success_publication_once_with_real_persistence_or_preserved_failure(initial, persistence_fails, tmp_path, monkeypatch):
    import json
    from history_manager import history_file_path, MAX_HISTORY_EVENTS

    snap = Snapshot(type='A', values=['192.0.2.1'], ts=1).to_dict()
    events = [{'ts': i} for i in range(MAX_HISTORY_EVENTS)]
    hist = {'meta': {'first_seen': 1, 'last_changed': 1}, 'events': events,
            'current': {} if initial else {'r': dict(snap)}}
    o, repo, lease = owner({'a.test': {} if initial else {'r': snap}}, {'a.test': hist}, str(tmp_path))
    bumps = watch_bumps(monkeypatch)
    before = get_state_version()
    real_persist = engine.persist_history_entry
    saved = []

    def persist(*args, **kwargs):
        assert not state_lock()._is_owned()
        assert get_state_version() == before + 1
        saved.append(args[2])
        if persistence_fails:
            raise OSError('ordinary persistence failure')
        return real_persist(*args, **kwargs)

    with patch.object(engine, 'collect_snapshot', return_value=changed()), \
            patch.object(engine, 'persist_history_entry', side_effect=persist), \
            patch.object(engine.time, 'time', return_value=20):
        assert cycle(o, repo, lease) == [('192.0.2.2', 'a.test', 'A')]
    assert get_state_version() == before + 1 and bumps == [before + 1]
    assert repo.valid(lease) and lease.history is hist and lease.current is o.current['a.test']
    assert lease.current == hist['current'] == {'r': changed().snapshot.to_dict()}
    assert len(saved) == 1
    assert saved[0]['current'] == hist['current']
    assert saved[0]['meta'] == {'first_seen': 1, 'last_changed': 1 if initial else 2}
    if initial:
        assert hist['events'] is events and len(events) == MAX_HISTORY_EVENTS
    else:
        assert len(events) == MAX_HISTORY_EVENTS + 1
        assert hist['events'] == events[1:] and hist['events'] is not events
    assert saved[0]['events'] == hist['events']
    if not persistence_fails:
        with open(history_file_path(str(tmp_path), 'a.test')) as f:
            assert json.load(f) == saved[0]
    else:
        assert list(tmp_path.iterdir()) == []


def test_unchanged_observation_keeps_ignored_telemetry_unversioned(monkeypatch):
    from http_api.read_source import build_read_views, capture_read_inputs

    snap = changed().snapshot.to_dict()
    hist = {'meta': {'dns_cycle_total': 7}, 'events': [{'ts': 1}], 'current': {'r': dict(snap)}}
    o, repo, lease = owner({'a.test': {'r': snap}}, {'a.test': hist})
    cap = Capture(o, 'history', ('a.test', 'meta'), budget=CaptureBudget(), projection='prepared_meta')
    bumps = watch_bumps(monkeypatch)
    before = get_state_version()
    old = build_read_views(capture_read_inputs(o.config, o.lock, o.current, o.history, None)[1])
    events = hist['events']
    try:
        finish(cap)
        assert cap.seal() == 'done'
        with patch.object(engine, 'collect_snapshot', return_value=changed()), \
                patch.object(engine.time, 'time', return_value=20), \
                patch.object(engine, 'persist_history_entry') as persistence:
            assert cycle(o, repo, lease) == []
        assert not bumps and get_state_version() == before and persistence.call_count == 0
        assert hist['meta']['dns_cycle_total'] == 1 and hist['meta']['dns_last_success_ts'] == 20
        assert hist['events'] is events and lease.current == hist['current'] == {'r': snap}
        assert build_read_views(capture_read_inputs(o.config, o.lock, o.current, o.history, None)[1]) == old
        assert cap.take() == (b'{"nxdomain_active":false,"nxdomain_since":0,"nxdomain_first_seen":0,'
                              b'"nxdomain_cleared_ts":0,"dns_error_only_active":false}')
        assert repo.valid(lease)
    finally:
        assert_released(cap)
