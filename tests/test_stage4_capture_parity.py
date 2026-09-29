"""JSON and selected-metadata parity with the actual retained reducers."""
import json

import pytest

from http_api.read_capture import Capture, CaptureBudget, CaptureOwners
from tests.test_stage4_read_capture import source, drain


@pytest.mark.parametrize('value', [
    None, False, True, 0, -1, (1 << 128) - 1, -(1 << 127), 1.25, -0.0,
    '', 'a"\\\n\t\x00é😀', '😀\\\n' * 2000,
    [], (), {}, {'z': (None, True, {'é': '😀'}), 'a': [1, -2, 3.5]},
])
def test_complete_matches_compact_json(value):
    owners = CaptureOwners(*source())
    owners.current['a.test'] = value
    cap = Capture(owners, 'current', ('a.test',), budget=CaptureBudget())
    assert drain(cap) == json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()
    assert cap.counters()['max_slice_visits'] <= 512
    assert cap.counters()['max_slice_bytes'] <= 16384


@pytest.mark.parametrize('meta', [None, {}, {'dns_cycle_total': 7},
    dict(zip(('nxdomain_active', 'nxdomain_since', 'nxdomain_first_seen',
              'nxdomain_cleared_ts', 'dns_error_only_active'), [True, 1, 2, 3, True])),
    dict.fromkeys(('nxdomain_active', 'nxdomain_since', 'nxdomain_first_seen',
                   'nxdomain_cleared_ts', 'dns_error_only_active'), None),
    dict.fromkeys(('nxdomain_active', 'nxdomain_since', 'nxdomain_first_seen',
                   'nxdomain_cleared_ts', 'dns_error_only_active'), 0),
])
def test_selected_defaults_match_both_actual_builders(meta):
    from http_api.basic_handlers import _build_results_payload
    from http_api.read_views import build_domain_rows
    owners = CaptureOwners(*source())
    owners.history['a.test']['meta'] = meta
    result = json.loads(drain(Capture(owners, 'history', ('a.test', 'meta'),
                              budget=CaptureBudget(), projection='prepared_meta')))
    keys = ['nxdomain_active', 'nxdomain_since', 'nxdomain_first_seen',
            'nxdomain_cleared_ts', 'dns_error_only_active']
    assert list(result) == (keys if meta else [])
    original, selected = {'a.test': meta}, {'a.test': result}
    assert _build_results_payload(owners.current, original, True) == _build_results_payload(owners.current, selected, True)
    assert build_domain_rows(owners.current, original, owners.config['domains']) == build_domain_rows(owners.current, selected, owners.config['domains'])
    del owners.history['a.test']['meta']
    assert drain(Capture(owners, 'history', ('a.test', 'meta'), budget=CaptureBudget(), projection='prepared_meta')) == b'{}'


def test_cursor_large_root_capture_and_same_attempt_completion():
    from http_api.read_capture import RootCursor
    owners = CaptureOwners(*source())
    owners.current.clear()
    owners.current.update((f'd{i}', {'v': i}) for i in range(600))
    budget = CaptureBudget()
    cursor = RootCursor(owners, 'current', budget=budget)
    found = []
    while (key := cursor.next_key()) is not None:
        found.append(key)
    assert cursor.status == 'done'
    assert found == list(owners.current)
    assert budget.counters()['descriptors'] == len(found)
    assert cursor.next_key() is None
    assert drain(Capture(owners, 'current', ('d599',), budget=budget)) == b'{"v":599}'
    assert budget.counters()['descriptors'] == len(found)
    assert budget.counters()['workspace'] == 0


def test_direct_capture_large_root_validates_sliced_without_keylist():
    owners = CaptureOwners(*source())
    owners.current.update((f'd{i}', 1) for i in range(600))
    cap = Capture(owners, 'current', ('a.test',), budget=CaptureBudget())
    assert cap.slice() == 'more'
    assert drain(cap) == json.dumps(owners.current['a.test'], separators=(',', ':')).encode()
    assert cap.counters()['max_slice_visits'] <= 512
    assert cap.counters()['slices'] >= 2


def test_descendant_index_does_not_admit_the_large_parent_list():
    owners = CaptureOwners(*source())
    owners.history['a.test']['events'] = [None] * 4096 + [{'ts': 7}]
    cap = Capture(owners, 'history', ('a.test', 'events', 4096), budget=CaptureBudget())
    assert drain(cap) == b'{"ts":7}'
    assert cap.nodes == 3


def test_root_key_certificate_does_not_exempt_meta_member_limit():
    from http_api.read_capture import RootCursor
    from tests.test_stage4_capture_limits import finish
    owners = CaptureOwners(*source())
    owners.current.clear()
    owners.current.update((str(i), None) for i in range(129))
    owners.history['a.test']['meta'] = owners.current
    budget = CaptureBudget()
    cursor = RootCursor(owners, 'current', budget=budget)
    while cursor.next_key() is not None:
        pass
    assert cursor.status == 'done'
    cap = Capture(owners, 'history', ('a.test', 'meta'), budget=budget, projection='prepared_meta')
    assert finish(cap) == 'capacity'
    assert cap.take() is None
