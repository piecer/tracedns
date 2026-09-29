"""Real owner mutations must fence prepared observations and root iteration."""
import threading

import pytest

from http_api.read_source import build_read_views, capture_read_inputs
from monitor import repository
from monitor.repository import MonitorStateRepository
from monitor.runtime_state import get_state_version, state_lock


def _history():
    return {'meta': {}, 'events': [], 'current': {}}


@pytest.mark.parametrize('missing', ['both', 'current', 'history', 'neither'])
def test_capture_materializes_roots_once_and_preserves_leases(missing, monkeypatch):
    names = ['a.test', 'b.test', 'c.test']
    current = {name: {} for name in names if name == 'a.test' or missing not in ('both', 'current')}
    history = {name: _history() for name in names if name == 'a.test' or missing not in ('both', 'history')}
    config, lock = {'domains': names}, threading.RLock()
    repo = MonitorStateRepository(current, history, '', names)
    identities = [(root, name, entry) for root in (current, history) for name, entry in root.items()]
    before = capture_read_inputs(config, lock, current, history, None)
    with state_lock():
        cursors = [iter(current), iter(history)]
        assert [next(cursor) for cursor in cursors] == ['a.test', 'a.test']
    bumps = []
    real_bump = repository.bump_state_version

    def publish():
        assert state_lock()._is_owned() and repo._coord._is_owned()
        assert set(current) == set(history) == set(names)
        bumps.append(real_bump())
        return bumps[-1]

    monkeypatch.setattr(repository, 'bump_state_version', publish)
    with lock:
        leases = repo.capture()
    expected = int(missing != 'neither')
    after = capture_read_inputs(config, lock, current, history, before[0])
    assert (after is not None) == bool(expected), 'changed roots must not hit the previous-token shortcut'
    assert get_state_version() == before[0][0] + expected
    assert len(bumps) == expected
    for root, name, entry in identities:
        assert root[name] is entry
    for name, lease in leases.items():
        assert lease.current is current[name] and lease.history is history[name]
        assert repo.valid(lease)
    if expected:
        assert after[1] != before[1]
        if missing in ('both', 'current'):
            assert build_read_views(after[1])['results'] != build_read_views(before[1])['results']
    # A real suspended root iterator is invalid after insertion. Its consumer
    # must observe the new token BEFORE attempting the next structural advance.
    with state_lock():
        for root_name, cursor in zip(('current', 'history'), cursors):
            if missing in ('both', root_name):
                assert get_state_version() != before[0][0]
                with pytest.raises(RuntimeError, match='dictionary changed size'):
                    next(cursor)
            else:
                assert next(cursor) == 'b.test'
    with lock:
        repeated = repo.capture()
    assert get_state_version() == before[0][0] + expected
    assert len(bumps) == expected
    assert capture_read_inputs(config, lock, current, history, (get_state_version(), 0)) is None
    for name, lease in repeated.items():
        assert lease.target is leases[name].target
        assert lease.current is leases[name].current
        assert lease.history is leases[name].history


@pytest.mark.parametrize('roots', [
    ('snapshot', None), (None, 'snapshot'), ('snapshot', 'snapshot'),
    ('empty', 'snapshot'), ('snapshot', 'empty'), ('empty', 'empty'), (None, None),
])
@pytest.mark.parametrize('timestamp', [None, 0, 9])
def test_failed_target_removal_fences_either_side_without_inventing_history(roots, timestamp, monkeypatch):
    from copy import deepcopy
    from monitor import engine

    current_kind, history_kind = roots
    snapshot = {'type': 'A', 'values': ['192.0.2.1'], 'ts': 1}
    current = {} if current_kind is None else {'a.test': {'r': snapshot} if current_kind == 'snapshot' else {}}
    events = [{'ts': 1, 'type': 'A', 'values': ['192.0.2.1']}]
    history = {} if history_kind is None else {'a.test': {
        'meta': {'last_changed': 2}, 'events': events,
        'current': {'r': snapshot} if history_kind == 'snapshot' else {},
    }}
    saved = deepcopy((current, history))
    config, lock = {'domains': ['a.test']}, threading.RLock()
    before = capture_read_inputs(config, lock, current, history, None)
    real_bump, bumps = engine.bump_state_version, []

    def publish():
        assert state_lock()._is_owned()
        assert 'r' not in current.get('a.test', {})
        assert 'r' not in history.get('a.test', {}).get('current', {})
        bumps.append(real_bump())
        return bumps[-1]

    monkeypatch.setattr(engine, 'bump_state_version', publish)
    removed = engine.drop_snapshot_for_failed_target(current, history, 'a.test', 'r', ts=timestamp)
    expected = 'snapshot' in roots
    assert removed is expected, 'removal on either side must report its actual mutation'
    assert get_state_version() == before[0][0] + int(expected)
    assert len(bumps) == int(expected)
    assert set(current) == set(saved[0]) and set(history) == set(saved[1])
    assert 'r' not in current.get('a.test', {})
    assert 'r' not in history.get('a.test', {}).get('current', {})
    after = capture_read_inputs(config, lock, current, history, before[0])
    assert (after is not None) is expected
    if current_kind == 'snapshot':
        assert build_read_views(before[1])['results'] != build_read_views(after[1])['results']
    if history_kind is not None:
        assert history['a.test']['events'] is events
        assert history['a.test']['meta'] == {'last_changed': timestamp if expected and timestamp else 2}
    if not expected:
        assert (current, history) == saved
    saved = deepcopy((current, history))
    assert engine.drop_snapshot_for_failed_target(current, history, 'a.test', 'r', ts=19) is False
    assert (current, history) == saved
    assert get_state_version() == before[0][0] + int(expected)
    assert len(bumps) == int(expected)


@pytest.mark.parametrize('initial_meta', ['absent', 'empty', 'telemetry', 'active'])
def test_legacy_cycle_fences_first_meta_projection_not_ignored_telemetry(initial_meta, tmp_path, monkeypatch):
    from copy import deepcopy
    from unittest.mock import Mock
    from http_api.basic_handlers import _build_results_payload
    from models import DomainSpec, QueryResult, Snapshot
    from monitor import engine
    from monitor.collect import Collected

    snap = Snapshot(type='A', values=['192.0.2.1'], ts=1).to_dict()
    current = {'a.test': {'r': snap}}
    hist = {'events': [], 'current': {'r': deepcopy(snap)}}
    if initial_meta != 'absent':
        hist['meta'] = ({'nxdomain_active': True, 'nxdomain_since': 5} if initial_meta == 'active'
                        else {'dns_cycle_total': 7} if initial_meta == 'telemetry' else {})
    history = {'a.test': hist}
    config, lock = {'domains': ['a.test']}, threading.RLock()
    repo = MonitorStateRepository(current, history, str(tmp_path), config['domains'])
    with lock:
        lease = repo.capture()['a.test']
    before = capture_read_inputs(config, lock, current, history, None)
    old_views = build_read_views(before[1])
    old_reduced = _build_results_payload(current, {'a.test': hist.get('meta', {})}, False)
    saved_current, saved_history_current = deepcopy(current), deepcopy(hist['current'])
    events = hist['events']
    real_lifecycle, lifecycle_results = engine.update_nxdomain_lifecycle, []
    real_bump, bumps = engine.bump_state_version, []

    def lifecycle(*args):
        assert state_lock()._is_owned()
        result = real_lifecycle(*args)
        lifecycle_results.append(result)
        return result

    def publish():
        assert state_lock()._is_owned() and hist['meta']
        bumps.append(real_bump())
        return bumps[-1]

    def collect(domain, server):
        return Collected(QueryResult(server, domain.name, 'A', 'ok', ['192.0.2.1']),
                         Snapshot(type='A', values=['192.0.2.1'], ts=2))

    persist = Mock(wraps=engine.persist_history_entry)
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    monkeypatch.setattr(engine, 'update_nxdomain_lifecycle', lifecycle)
    monkeypatch.setattr(engine, 'bump_state_version', publish)
    monkeypatch.setattr(engine, 'persist_history_entry', persist)
    monkeypatch.setattr(engine.time, 'time', lambda: 20)

    def cycle(servers):
        return engine.run_domain_cycle(domain=DomainSpec('a.test'), servers=servers,
            current_results=current, history=history, history_dir=str(tmp_path), query_fail_counts={},
            state_repository=repo, target_lease=lease, max_workers=1)

    assert cycle(['r']) == []
    assert lifecycle_results == [initial_meta == 'active']
    assert current == saved_current and hist['current'] == saved_history_current
    assert hist['events'] is events and events == []
    assert repo.valid(lease)
    assert hist['meta']['dns_cycle_total'] == 1
    assert hist['meta']['dns_last_success_ts'] == 20
    new_reduced = _build_results_payload(current, {'a.test': hist['meta']}, False)
    expected = initial_meta != 'telemetry'
    assert (old_reduced != new_reduced) is expected
    if initial_meta in ('absent', 'empty'):
        assert old_reduced['domain_meta'] == {}
        assert new_reduced['domain_meta'] == {'a.test': {
            'nxdomain_active': False, 'nxdomain_since': 0,
            'nxdomain_first_seen': 0, 'nxdomain_cleared_ts': 0,
        }}
    after = capture_read_inputs(config, lock, current, history, before[0])
    assert (after is not None) is expected, 'new prepared domain_meta must invalidate the capture shortcut'
    assert get_state_version() == before[0][0] + int(expected)
    assert len(bumps) == int(expected)
    assert persist.call_count == int(initial_meta == 'active')
    assert bool(list(tmp_path.iterdir())) is (initial_meta == 'active')
    new_views = build_read_views(capture_read_inputs(config, lock, current, history, None)[1])
    assert (old_views != new_views) is expected
    # Real later cycles change ignored counters/time, not the prepared projection.
    token = (get_state_version(), 0)
    meta = deepcopy(hist['meta'])
    monkeypatch.setattr(engine.time, 'time', lambda: 30)
    assert cycle(['r', 'r']) == []
    assert hist['meta'] != meta
    assert hist['meta']['dns_cycle_total'] == 2 and hist['meta']['dns_last_success_ts'] == 30
    assert lifecycle_results == [initial_meta == 'active', False]
    assert get_state_version() == token[0] and len(bumps) == int(expected)
    assert persist.call_count == int(initial_meta == 'active')
    assert capture_read_inputs(config, lock, current, history, token) is None
    assert build_read_views(capture_read_inputs(config, lock, current, history, None)[1]) == new_views


@pytest.mark.parametrize('present', ['both', 'current', 'history', 'neither'])
@pytest.mark.parametrize('value', [None, False, 0, [], {}])
def test_purge_fences_root_membership_not_stored_value(present, value, tmp_path, monkeypatch):
    from pathlib import Path
    from history_manager import history_file_path
    import http_server

    current, history = {'keep.test': {}}, {'keep.test': _history()}
    for root_name, root in (('current', current), ('history', history)):
        if present in ('both', root_name):
            root['gone.test'] = value
            root['also-gone.test'] = value
    identities = current['keep.test'], history['keep.test']
    files = {name: Path(history_file_path(str(tmp_path), name))
             for name in ('keep.test', 'gone.test', 'also-gone.test')}
    for path in files.values():
        path.write_text('{}')
    config, lock = {'domains': ['keep.test']}, threading.RLock()
    before = capture_read_inputs(config, lock, current, history, None)
    with state_lock():
        cursors = [iter(current), iter(history)]
        assert [next(cursor) for cursor in cursors] == ['keep.test', 'keep.test']
    real_bump, bumps = http_server.bump_state_version, []

    def publish():
        assert state_lock()._is_owned()
        assert set(current) == set(history) == {'keep.test'}
        bumps.append(real_bump())
        return bumps[-1]

    monkeypatch.setattr(http_server, 'bump_state_version', publish)
    http_server.purge_removed_domains_state(current, history, str(tmp_path),
                                           ['gone.test', 'also-gone.test', 'absent.test', 'gone.test'])
    assert set(current) == set(history) == {'keep.test'}
    assert current['keep.test'] is identities[0] and history['keep.test'] is identities[1]
    expected = int(present != 'neither')
    after = capture_read_inputs(config, lock, current, history, before[0])
    assert (after is not None) == bool(expected), 'even skipped malformed roots require a structural fence'
    assert get_state_version() == before[0][0] + expected
    assert len(bumps) == expected
    with state_lock():
        for root_name, cursor in zip(('current', 'history'), cursors):
            if present in ('both', root_name):
                assert get_state_version() != before[0][0]
                with pytest.raises(RuntimeError, match='dictionary changed size'):
                    next(cursor)
            else:
                assert next(cursor, None) is None
    assert files['keep.test'].read_text() == '{}'
    assert not files['gone.test'].exists() and not files['also-gone.test'].exists()
    http_server.purge_removed_domains_state(current, history, str(tmp_path), ['gone.test'])
    http_server.purge_removed_domains_state(current, history, str(tmp_path), [])
    assert get_state_version() == before[0][0] + expected
    assert len(bumps) == expected
    assert capture_read_inputs(config, lock, current, history, (get_state_version(), 0)) is None
    assert set(current) == set(history) == {'keep.test'}
    assert files['keep.test'].read_text() == '{}'
