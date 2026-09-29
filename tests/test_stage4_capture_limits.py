"""Finite termination, admission, exact byte/work/node ceilings."""
import json
import threading

import pytest

from http_api.read_capture import Capture, CaptureBudget, CaptureOwners, RootCursor
from monitor.runtime_state import state_lock
from tests.test_stage4_read_capture import source, drain


def finish(cap):
    for _ in range(20000):
        if cap.slice() != 'more':
            return cap.status
    pytest.fail('unbounded more')


@pytest.mark.parametrize('lock_name', ['config', 'state', 'publication'])
@pytest.mark.parametrize('phase', ['slice', 'seal', 'take', 'cursor'])
def test_all_locks_busy_are_terminal_without_source_work(lock_name, phase):
    owners = CaptureOwners(*source())
    budget = CaptureBudget()
    cap = Capture(owners, 'current', ('a.test',), budget=budget)
    if phase in ('seal', 'take'):
        assert finish(cap) == 'done'
        if phase == 'take':
            assert cap.seal() == 'done'
    if phase == 'cursor':
        cap.discard()
        cap = RootCursor(owners, 'current', budget=budget)
    lock = owners.lock if lock_name == 'config' else state_lock() if lock_name == 'state' else owners.model._condition
    held, release = threading.Event(), threading.Event()

    def holder():
        with lock:
            held.set()
            assert release.wait(4)
    thread = threading.Thread(target=holder)
    thread.start()
    try:
        assert held.wait(4)
        visits = budget.visits
        result = getattr(cap, 'next_key' if phase == 'cursor' else phase)()
        assert result == ('lock_busy' if phase in ('slice', 'seal') else None)
        assert cap.status == 'lock_busy' and budget.visits == visits
        assert cap.counters()['workspace'] == 0
        assert cap.discard() == 'lock_busy'
    finally:
        release.set()
        thread.join(4)
    assert not thread.is_alive()


@pytest.mark.parametrize('reason', ['cancel', 'deadline', 'discard'])
@pytest.mark.parametrize('phase', ['slice', 'seal', 'take', 'cursor'])
def test_cancel_deadline_discard_never_revive(reason, phase):
    owners = CaptureOwners(*source())
    now = [0.0]
    budget = CaptureBudget(clock=lambda: now[0])
    cap = Capture(owners, 'current', ('a.test',), budget=budget)
    if phase in ('seal', 'take'):
        assert finish(cap) == 'done'
        if phase == 'take':
            assert cap.seal() == 'done'
    if phase == 'cursor':
        cap.discard()
        cap = RootCursor(owners, 'current', budget=budget)
    if reason == 'cancel':
        budget.cancel()
    elif reason == 'deadline':
        now[0] = 5
    else:
        cap.discard()
    expected = {'cancel': 'stopped', 'deadline': 'deadline', 'discard': 'invalid'}[reason]
    getattr(cap, 'next_key' if phase == 'cursor' else phase)()
    assert cap.status == expected
    before = budget.counters()
    assert cap.take() is None
    assert cap.discard() == expected
    assert budget.counters() == before
    assert cap._frames == [] and cap._buffer == b''


@pytest.mark.parametrize('value', ['\ud800', float('nan'), float('inf'), object(), {1: 'x'},
                                  {('x',): 1}, set(), b'bytes'])
def test_invalid_source_releases_without_exceptions(value):
    owners = CaptureOwners(*source())
    owners.current['a.test'] = value
    budget = CaptureBudget()
    cap = Capture(owners, 'current', ('a.test',), budget=budget)
    assert finish(cap) == 'invalid'
    assert cap.take() is None and budget._unit is None
    assert budget.workspace == 0
    assert all(type(v) in (str, int, float) for v in cap.counters().values())


@pytest.mark.parametrize('value', ['x' * 65536, [0] * 4097, {str(i): 0 for i in range(129)},
                                  1 << 128, {'x' * 257: 0}])
def test_giant_exact_builtins_reject_before_unbounded_encoding(value):
    owners = CaptureOwners(*source())
    owners.current['a.test'] = value
    cap = Capture(owners, 'current', ('a.test',), budget=CaptureBudget())
    assert finish(cap) == 'capacity'
    assert cap.take() is None
    assert cap.counters()['workspace'] == 0


def test_no_custom_leaf_protocol_even_under_skip():
    class Poison:
        def __getattribute__(self, name):
            raise AssertionError('getattribute hook')
        def __str__(self):
            raise AssertionError('str hook')
        def __repr__(self):
            raise AssertionError('repr hook')
        def __iter__(self):
            raise AssertionError('iter hook')
        def __len__(self):
            raise AssertionError('len hook')
    owners = CaptureOwners(*source())
    owners.current['a.test'] = {'skip': Poison(), 'ok': [1]}
    assert drain(Capture(owners, 'current', ('a.test',), budget=CaptureBudget(), skip_fields=('skip',))) == b'{"skip":[],"ok":[1]}'
    cap = Capture(owners, 'current', ('a.test',), budget=CaptureBudget())
    assert finish(cap) == 'invalid'


@pytest.mark.parametrize('value', [False, 'é😀\n', {'\\': '\x00'}, ['x' * 2000]])
def test_exact_output_bytes_and_plus_one(value):
    encoded = json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()
    owners = CaptureOwners(*source())
    owners.current['a.test'] = value
    assert drain(Capture(owners, 'current', ('a.test',), budget=CaptureBudget(), unit_bytes=len(encoded))) == encoded
    cap = Capture(owners, 'current', ('a.test',), budget=CaptureBudget(), unit_bytes=len(encoded) - 1)
    assert finish(cap) == 'capacity'


@pytest.mark.parametrize('value,expected', [([0] * 4095, 'done'), ([0] * 4096, 'capacity'),
    ({str(i): 0 for i in range(128)}, 'done'), ({str(i): 0 for i in range(129)}, 'capacity'),
    ({'😀' * 256: 0}, 'done'), ({'😀' * 257: 0}, 'capacity')])
def test_exact_nodes_members_keys_and_plus_one(value, expected):
    owners = CaptureOwners(*source())
    owners.current['a.test'] = value
    cap = Capture(owners, 'current', ('a.test',), budget=CaptureBudget())
    assert finish(cap) == expected
    assert cap.counters()['nodes'] <= 4096
    if expected == 'done':
        assert cap.seal() == 'done' and type(cap.take()) is bytes
    else:
        assert cap.take() is None


@pytest.mark.parametrize('depth,expected', [(32, 'done'), (33, 'capacity')])
def test_exact_depth_and_plus_one(depth, expected):
    value = 0
    for _ in range(depth - 1):
        value = [value]
    owners = CaptureOwners(*source())
    owners.current['a.test'] = value
    cap = Capture(owners, 'current', ('a.test',), budget=CaptureBudget())
    assert finish(cap) == expected


@pytest.mark.parametrize('limit,expected', [(3, 'done'), (2, 'capacity')])
def test_descriptors_exact_plus_one_and_empty_at_ceiling(limit, expected):
    owners = CaptureOwners(*source())
    owners.current.clear()
    owners.current.update(a=0, b=0, c=0)
    budget = CaptureBudget.for_test(descriptors=limit)
    cursor = RootCursor(owners, 'current', budget=budget)
    keys = []
    while (key := cursor.next_key()) is not None:
        keys.append(key)
    assert cursor.status == expected
    assert budget.descriptors == limit
    assert keys == list(owners.current)[:limit]
    owners.history.clear()
    empty = RootCursor(owners, 'history', budget=budget)
    assert empty.next_key() is None and empty.status == 'done'


def test_shared_examination_limit_not_refunded_by_release():
    owners = CaptureOwners(*source())
    owners.current['a.test'] = 'x'
    budget = CaptureBudget.for_test(examined_bytes=6)
    for _ in range(2):
        assert drain(Capture(owners, 'current', ('a.test',), budget=budget)) == b'"x"'
    assert budget.examined_bytes == 6
    cap = Capture(owners, 'current', ('a.test',), budget=budget)
    assert finish(cap) == 'capacity'
    assert budget.examined_bytes == 6
    cap.discard()
    assert budget.examined_bytes == 6


def test_workspace_reserved_at_constructor_and_released_once():
    owners = CaptureOwners(*source())
    budget = CaptureBudget()
    cap = Capture(owners, 'current', ('a.test',), budget=budget)
    assert budget.workspace > 0, 'constructor retained unit paths/buffers without reserving'
    before = budget.workspace
    cursor = RootCursor(owners, 'current', budget=budget)
    assert budget.workspace > before
    cursor.close()
    assert budget.workspace == before
    cap.discard()
    cap.discard()
    assert budget.workspace == 0


def test_terminal_cursor_does_not_expose_capture_transfer_api():
    owners = CaptureOwners(*source())
    cursor = RootCursor(owners, 'current', budget=CaptureBudget())
    assert cursor.next_key() == 'a.test'
    assert cursor.status == 'done'
    assert cursor.seal() == 'done'
    assert cursor.take() is None, 'a root cursor must never mint captured output'


def test_key_validation_counts_advances_and_keys_before_hashing():
    owners = CaptureOwners(*source())
    cap = Capture(owners, 'config', ('domains',), budget=CaptureBudget.for_test(slice_steps=1))
    cap.slice()
    # Two config stored keys: two nexts, two type/size validations, and the
    # terminating next, before the three authority-slot reads.
    assert cap.visits >= 8, cap.counters()


def test_selected_ignored_key_validation_is_node_charged():
    owners = CaptureOwners(*source())
    owners.history['a.test']['meta'] = {'ignored1': object(), 'ignored2': object()}
    cap = Capture(owners, 'history', ('a.test', 'meta'), budget=CaptureBudget(), projection='prepared_meta')
    assert drain(cap)
    assert cap.nodes >= 13  # projected object+5 names+5 values + 2 scanned names


@pytest.mark.parametrize('over', [0, 1])
def test_shared_visit_limit_exact_final_take_and_plus_one(over):
    owners = CaptureOwners(*source())
    owners.current['a.test'] = 0
    baseline = CaptureBudget(clock=lambda: 0)
    assert drain(Capture(owners, 'current', ('a.test',), budget=baseline)) == b'0'
    exact = baseline.visits
    budget = CaptureBudget.for_test(visits=exact - over, clock=lambda: 0)
    cap = Capture(owners, 'current', ('a.test',), budget=budget)
    assert finish(cap) == 'done'
    cap.seal()
    result = cap.take()
    if over:
        assert result is None and cap.status == 'capacity'
    else:
        assert result == b'0' and budget.visits == exact
    before = budget.visits
    cap.discard()
    next_cap = Capture(owners, 'current', ('a.test',), budget=budget)
    assert finish(next_cap) == 'capacity'
    assert before <= budget.visits <= budget.limits['visits']


@pytest.mark.parametrize('over', [0, 1])
def test_workspace_peak_exact_and_plus_one(over):
    owners = CaptureOwners(*source())
    owners.current['a.test'] = 0
    baseline = CaptureBudget(clock=lambda: 0)
    assert drain(Capture(owners, 'current', ('a.test',), budget=baseline)) == b'0'
    budget = CaptureBudget.for_test(workspace=baseline.peak_workspace - over, clock=lambda: 0)
    cap = Capture(owners, 'current', ('a.test',), budget=budget)
    if over:
        assert finish(cap) == 'capacity'
    else:
        assert drain(cap) == b'0'
    assert budget.workspace == 0
    assert budget.peak_workspace <= budget.limits['workspace']


@pytest.mark.parametrize('kwargs', [
    {'root_name': 'bad'}, {'root_name': True}, {'path': []}, {'path': ()},
    {'path': ('a.test', True)}, {'path': ('a.test', -1)}, {'path': ('a.test', 1 << 128)},
    {'path': ('a.test',) * 33}, {'path': ('\ud800',)}, {'path': ('x' * 257,)},
    {'unit_bytes': True}, {'unit_bytes': 0}, {'unit_bytes': 1032193}, {'unit_bytes': 1.0},
    {'skip_fields': []}, {'skip_fields': (object(),)}, {'skip_fields': tuple(str(i) for i in range(129))},
    {'projection': None}, {'projection': 'raw'},
    {'root_name': 'history', 'path': ('a.test',)},
    {'root_name': 'history', 'path': ('a.test', 'current')},
    {'root_name': 'history', 'path': ('a.test', 'meta')},
    {'root_name': 'history', 'path': ('a.test', 'meta', 'dns_cycle_total')},
    {'root_name': 'config', 'path': ('ens_rpc_url',)},
    {'root_name': 'history', 'path': ('a.test', 'meta'), 'projection': 'prepared_meta', 'skip_fields': ('x',)},
])
def test_constructor_grammar_before_any_resources(kwargs):
    owners = CaptureOwners(*source())
    budget = CaptureBudget()
    args = dict(root_name='current', path=('a.test',))
    args.update(kwargs)
    with pytest.raises((ValueError, TypeError)):
        Capture(owners, budget=budget, **args)
    assert budget.workspace == 0 and budget.visits == 0 and budget._unit is None


@pytest.mark.parametrize('limits', [{'visits': 262145}, {'descriptors': 16385}, {'nodes': 4097},
    {'depth': 33}, {'workspace': 16777217}, {'slice_bytes': 16385}, {'slice_visits': 513},
    {'dict_members': 129}, {'list_members': 4097}, {'examined_bytes': 67108865},
    {'slice_steps': True}, {'unknown': 1}, {'visits': 0}, {'visits': 1.5}])
def test_no_test_seam_can_raise_production_ceilings(limits):
    with pytest.raises(ValueError):
        CaptureBudget.for_test(**limits)


@pytest.mark.parametrize('revision', [True, None, -1, '0', 0.0, object()])
@pytest.mark.parametrize('slot', ['_config_revision', '_security_projection_revision'])
def test_authority_slot_malformed_is_finite_invalid(slot, revision):
    owners = CaptureOwners(*source())
    owners.config[slot] = revision
    cap = Capture(owners, 'current', ('a.test',), budget=CaptureBudget())
    assert finish(cap) == 'invalid'
    assert cap.take() is None


def test_unexpected_service_slot_never_executes_properties():
    class PoisonService:
        @property
        def read_model(self):
            pytest.fail('untrusted service property')
    owners = CaptureOwners(*source())
    owners.config['_config_service'] = PoisonService()
    cap = Capture(owners, 'current', ('a.test',), budget=CaptureBudget())
    assert finish(cap) == 'invalid'


def test_one_unit_at_a_time_and_attempt_identity_not_rebound():
    owners = CaptureOwners(*source())
    budget = CaptureBudget()
    cap = Capture(owners, 'current', ('a.test',), budget=budget)
    with pytest.raises(ValueError):
        Capture(owners, 'current', ('a.test',), budget=budget)
    assert drain(cap)
    other = CaptureOwners(*source())
    replacement = Capture(other, 'current', ('a.test',), budget=budget)
    assert finish(replacement) == 'mutation'


def test_attempt_clock_is_not_restarted_between_units():
    owners = CaptureOwners(*source())
    now = [0]
    budget = CaptureBudget(clock=lambda: now[0])
    assert drain(Capture(owners, 'current', ('a.test',), budget=budget))
    now[0] = 5
    cap = Capture(owners, 'current', ('a.test',), budget=budget)
    assert finish(cap) == 'deadline'
    assert budget.deadline == 5


@pytest.mark.parametrize('value', [None, True, float('nan'), float('inf'), 10 ** 1000, object()])
def test_clock_constructor_rejects_nonfinite_or_unrepresentable_values(value):
    with pytest.raises((ValueError, TypeError)):
        CaptureBudget(clock=lambda: value)


def test_clock_must_be_callable():
    with pytest.raises(TypeError):
        CaptureBudget(clock=0)
