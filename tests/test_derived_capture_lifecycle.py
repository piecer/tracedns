"""Shared admission, quiescence and one-fault bridge regressions."""
import sys
import time
import threading
import inspect
import dis
import linecache
import weakref
from contextlib import contextmanager
from unittest.mock import patch

import pytest

from http_api.read_capture import Capture, CaptureBudget
from security.derived_redaction import HEADER, RedactionBudget
from tests.test_derived_capture import api, bridge_for, finish
from tests.test_stage4_capture_progress import actual_source

FAULTS = []
MEASUREMENTS = []


def test_continuous_real_plan_capture_decode_admission_custody():
    from tests.test_derived_capture import plan
    from security.derived_redaction import _Lease
    owners, budget, attempt, unit = bridge_for({'한': '😀' * 1500})
    owned_plan = plan(owners, budget)
    paid = []
    transfer_debits = []
    cap_lease_id = id(unit.capture._lease)

    def observation(frame, event, arg):
        if event == 'call' and frame.f_code is _Lease.close.__code__ and id(frame.f_locals['self']) == cap_lease_id:
            transfer_debits.append(dict(bridge_worker=unit._lease.worker, bridge_metadata=unit._lease.metadata,
                prepaid=unit._lease.worker >= HEADER + 131072 + 128 + unit.unit_bytes,
                active=budget.counters()['active']))

    sys.setprofile(observation)
    try:
        for _ in range(20000):
            phase = unit.phase
            status = unit.slice()
            holders = [attempt, unit, owned_plan, unit.capture, unit.admission, unit.output]
            if unit.capture is not None:
                holders.append(unit.capture._root_cursor)
            leases = {id(o._lease): o._lease for o in holders if o is not None and o._lease is not None and not o._lease.closed}
            counts = budget.counters()
            assert counts['worker_bytes'] == sum(x.worker for x in leases.values()) <= budget.worker_capacity
            assert counts['metadata_bytes'] == sum(x.metadata for x in leases.values()) <= budget.metadata_capacity
            assert counts['hold_worker_bytes'] == counts['hold_metadata_bytes'] == 0
            if unit.encoded is not None:
                assert unit._lease.worker >= 128 + len(unit.encoded)
            if unit.graph is not None:
                assert unit._lease.worker >= 8 * unit.unit_bytes + 4096 * 256 + 65536
            paid.append(dict(phase=phase, next_phase=unit.phase, **counts))
            if status != 'more':
                break
    finally:
        sys.setprofile(None)
    assert status == 'done'
    assert transfer_debits and all(row['prepaid'] for row in transfer_debits)
    output = unit.take()
    assert output.value == {'한': '😀' * 1500} and output.budget is owned_plan.budget is budget
    MEASUREMENTS.append(dict(kind='continuous-both-axis-custody', slices=paid, capture_debits=transfer_debits))
    output.close()
    owned_plan.close()
    attempt.close()
    assert budget.counters()['worker_bytes'] == budget.counters()['metadata_bytes'] == 0


@pytest.mark.parametrize('boundary', ['capture', 'bytes', 'decode', 'admit_take'])
def test_single_fault_transition_retires_aliases_before_bridge_debit(boundary):
    from security.derived_redaction import _Lease
    m = api()
    _, budget, attempt, unit = bridge_for('x' * 3000 + '한')
    if boundary == 'capture':
        assert unit.slice() == 'more'  # root bootstrap, not output yet
        method, marker = Capture._emit, 'self._buffer.extend(blob)'
    elif boundary == 'decode':
        at_phase(unit, 'decode')
        method, marker = m._Decoder._string_step, "value = self.string.decode('utf8')"
    elif boundary == 'bytes':
        at_phase(unit, boundary)
        method, marker = m.CapturedPayload._advance, 'self.encoded = self.capture.take()'
    else:
        at_phase(unit, boundary)
        method, marker = m.CapturedPayload._advance, 'self.output = self.admission.take()'
    decoder_ref = weakref.ref(unit.decoder) if unit.decoder is not None else lambda: None
    lease_id = id(unit._lease)
    observations = []

    def observe(frame, event, arg):
        if event == 'call' and frame.f_code is _Lease.close.__code__ and id(frame.f_locals['self']) == lease_id:
            observations.append(dict(decoder_dead=decoder_ref() is None,
                aliases_gone=unit.capture is unit.decoder is unit.graph is unit.encoded is unit.admission is unit.output is None,
                funded=budget.counters()['worker_bytes'] >= unit._lease.worker,
                metadata_funded=budget.counters()['metadata_bytes'] >= unit._lease.metadata))
    sys.setprofile(observe)
    try:
        with one_fault(method, marker, {'CALL_METHOD', 'CALL'}):
            for _ in range(20000):
                if unit.slice() != 'more':
                    break
    finally:
        sys.setprofile(None)
    assert unit.status in ('capacity', 'invalid')
    assert observations and all(all(o.values()) for o in observations)
    assert unit.take() is None
    assert budget.counters()['worker_bytes'] == attempt._lease.worker
    assert budget.counters()['metadata_bytes'] == attempt._lease.metadata
    assert not budget.counters()['active']
    MEASUREMENTS.append(dict(kind='pre-debit-retirement', boundary=boundary, observations=observations))
    unit.discard()
    other = finish(m.OwnedPayload.admit_sliced('unrelated', budget=budget)).take()
    other.close()
    attempt.close()


@pytest.mark.parametrize('axis', ['worker', 'metadata'])
@pytest.mark.parametrize('less', [0, 1])
def test_shared_capture_growth_exact_residual_before_source(axis, less):
    owners, budget, attempt, unit = bridge_for({})
    # First real _run raises frame reservation from one to three.
    growth = 2 * (65536 if axis == 'worker' else 4096)
    capacity = getattr(budget, axis + '_capacity')
    held = budget.counters()[axis + '_bytes']
    sibling = budget.reserve(**{axis: capacity - held - HEADER - growth + less})
    before = budget.counters()
    count = attempt.visits
    state = unit.slice()
    assert state == ('capacity' if less else 'more')
    if less:
        assert attempt.visits == count == 0
        assert budget.counters()[axis + '_peak'] == before[axis + '_peak']
        assert attempt.workspace == 0
    else:
        assert attempt.visits > count
        assert budget.counters()[axis + '_bytes'] == capacity
    assert not sibling.closed
    unit.discard()
    assert budget.counters()['worker_bytes'] == sibling.worker + attempt._lease.worker
    assert budget.counters()['metadata_bytes'] == sibling.metadata + attempt._lease.metadata
    sibling.close()
    attempt.close()


@pytest.mark.parametrize('phase', ['capture', 'seal', 'bytes'])
@pytest.mark.parametrize('event', ['delete', 'private_commit', 'stop', 'rebind'])
def test_real_authority_changes_fence_bridge_capture_boundaries(phase, event):
    from http_api.read_model import BackgroundReadModel
    from monitor.config_service import get_config_service
    from types import SimpleNamespace
    owners, repo, service = actual_source(config_size=3, current={'d000.test': [1] * 1000})
    budget = RedactionBudget(deadline=time.monotonic() + 5)
    attempt = CaptureBudget(ledger=budget)
    unit = api().CapturedPayload(owners, 'current', ('d000.test',), capture_budget=attempt, budget=budget)
    assert unit.slice() == 'more'
    at_phase(unit, phase)
    if event == 'delete':
        with owners.lock:
            repo.configure({'domains': []})
    elif event == 'private_commit':
        assert service.commit('config', {'ens_rpc_url': 'local-synthetic'}, expected_revision=0)['revision'] == 1
    elif event == 'stop':
        owners.model.stop_admission()
    else:
        replacement = BackgroundReadModel(lambda _: None, lambda _: {})
        with owners.lock:
            get_config_service(SimpleNamespace(shared_config=owners.config, config_lock=owners.lock,
                config_path='', read_model=replacement))
    assert unit.slice() == ('stopped' if event == 'stop' else 'mutation')
    assert unit.take() is None
    unit.discard()
    attempt.close()
    assert budget.counters()['worker_bytes'] == budget.counters()['metadata_bytes'] == 0


def test_decoder_and_admission_do_not_read_or_lock_canonical_source():
    owners, budget, attempt, unit = bridge_for({'한': '😀'})
    at_phase(unit, 'decode_start')
    # Poisoning after the fresh take must not cause callbacks or fresh reads.
    owners.current.clear()
    owners.config.clear()
    entered, release = threading.Event(), threading.Event()
    def hold():
        from monitor.runtime_state import state_lock
        with owners.lock, state_lock(), owners.model._condition:
            entered.set()
            assert release.wait(4)
    thread = threading.Thread(target=hold)
    thread.start()
    try:
        assert entered.wait(4)
        result = finish(unit).take()
        assert result.value == {'한': '😀'}
        result.close()
    finally:
        release.set()
        thread.join(4)
    assert not thread.is_alive()
    attempt.close()


@pytest.mark.parametrize('bad', ['foreign', 'bool_bytes', 'subclass', 'empty_path', 'raw_meta'])
def test_bad_constructor_arguments_before_any_additional_admission(monkeypatch, bad):
    from http_api.read_capture import CaptureOwners
    owners, _, _ = actual_source(config_size=3)
    budget = RedactionBudget(deadline=time.monotonic() + 5)
    attempt = CaptureBudget(ledger=budget)
    args = dict(owners=owners, root_name='current', path=('d000.test',), capture_budget=attempt, budget=budget)
    if bad == 'foreign':
        args['budget'] = RedactionBudget(deadline=budget.deadline)
    elif bad == 'bool_bytes':
        args['unit_bytes'] = True
    elif bad == 'subclass':
        class Child(CaptureOwners):
            pass
        args['owners'] = Child(owners.config, owners.lock, owners.current, owners.history, owners.model)
    elif bad == 'empty_path':
        args['path'] = ()
    else:
        args.update(root_name='history', path=('d000.test', 'meta'))
    calls = []
    def denied(*a, **kw):
        calls.append(True)
        raise AssertionError('invalid request reached admission')
    monkeypatch.setattr(RedactionBudget, 'reserve', denied)
    with pytest.raises((TypeError, ValueError)):
        api().CapturedPayload(**args)
    assert calls == [] and attempt.visits == 0
    attempt.close()


def test_budget_close_keeps_live_owned_output_funded_until_handle_close():
    _, budget, attempt, unit = bridge_for('owned')
    output = finish(unit).take()
    before = budget.counters()
    budget.close()
    assert budget.counters()['worker_bytes'] == before['worker_bytes']
    attempt.close()
    assert budget.counters()['worker_bytes'] == output._lease.worker
    output.close()
    output.close()
    assert budget.counters()['worker_bytes'] == budget.counters()['metadata_bytes'] == 0


def test_final_transfer_call_entry_fault_has_no_ghost_or_lost_output():
    m = api()
    _, budget, attempt, unit = bridge_for('한')
    finish(unit)
    method = m.CapturedPayload._invoke
    marker = 'b.leave(self)' if 'b.leave(self)' in inspect.getsource(method) else 'self._lease.close()'
    result = None
    with one_fault(method, marker, {'CALL_METHOD', 'CALL'}, occurrence=0 if marker == 'b.leave(self)' else None):
        try:
            result = unit.take()
        except BaseException as exc:
            exc.__traceback__ = exc.__context__ = exc.__cause__ = None
    assert not budget.counters()['active'] and not unit._running
    assert result is None and unit.status == 'invalid'
    assert unit.take() is None and unit.slice() == 'invalid'
    assert budget.counters()['worker_bytes'] == attempt._lease.worker
    other = finish(m.OwnedPayload.admit_sliced('other', budget=budget)).take()
    other.close()
    unit.discard()
    attempt.close()


@contextmanager
def one_fault(method, marker, opnames, owner=None, occurrence=None, unwrap=True):
    method = inspect.unwrap(method) if unwrap else method
    start = method.__code__.co_firstlineno
    lines = inspect.getblock(linecache.getlines(method.__code__.co_filename)[start - 1:])
    found = [start + i for i, line in enumerate(lines) if marker in line]
    assert len(found) == 1
    line = None
    sites = []
    for instruction in dis.get_instructions(method):
        if instruction.starts_line is not None:
            line = instruction.starts_line
        if line == found[0] and instruction.opname in opnames:
            sites.append(instruction)
    if occurrence is not None:
        sites = [sites[occurrence]]  # normal-path duplicate of Python finally
    assert len(sites) == 1, [(s.offset, s.opname) for s in sites]
    record = dict(method=method.__qualname__, marker=marker, line=found[0],
                  opcode=sites[0].opname, offset=sites[0].offset, fired=0)
    references = []
    owner_id = None if owner is None else id(owner)
    owner = None  # The recursive trace closure must not keep the owner alive.

    def trace(frame, event, arg):
        if frame.f_code is method.__code__:
            if event == 'call':
                frame.f_trace_opcodes = True
            if event == 'opcode' and frame.f_lasti == sites[0].offset and not record['fired']:
                target = frame.f_locals['self']
                if owner_id is not None and id(target) != owner_id:
                    return trace
                references.append(weakref.ref(target))
                del target
                record['fired'] += 1
                raise MemoryError('single semantic allocation fault')
            return trace
        return None

    sys.settrace(trace)
    try:
        yield record, references
    finally:
        sys.settrace(None)
        FAULTS.append(record)
        assert record['fired'] == 1


def test_attempt_constructor_allocation_does_not_orphan_shared_lease():
    ledger = RedactionBudget(deadline=time.monotonic() + 5)
    sibling = ledger.reserve(worker=10, metadata=10)
    before = ledger.counters()
    result = error = None
    method = getattr(CaptureBudget, '_initialize_control', CaptureBudget.__init__)
    with one_fault(method, 'self.limits = dict', {'CALL_FUNCTION_KW', 'CALL'}) as (_, refs):
        try:
            result = CaptureBudget(ledger=ledger)
        except BaseException as exc:
            error = type(exc).__name__
            exc.__traceback__ = exc.__context__ = exc.__cause__ = None
    assert ledger.counters() == before, 'unreturned attempt stranded a committed lease'
    if result is not None:
        assert result.status == 'capacity'
        owners, _, _ = actual_source(config_size=3)
        unit = api().CapturedPayload(owners, 'current', ('d000.test',), capture_budget=result, budget=ledger)
        assert unit.status == 'stopped' and unit.take() is None
        unit.discard()
        assert ledger.counters() == before
        result.close()
        result.close()
        assert all(type(x) in (str, int, float) for x in result.counters().values())
    else:
        assert error == 'MemoryError' and refs[0]() is None
    sibling.close()


@pytest.mark.parametrize('cursor', [False, True])
def test_capture_constructor_refusal_and_cleanup_entry_no_unreturned_unit(cursor):
    from http_api.read_capture import RootCursor
    owners, _, _ = actual_source(config_size=3)
    budget = RedactionBudget(deadline=time.monotonic() + 5)
    attempt = CaptureBudget(ledger=budget)
    sibling = budget.reserve(worker=budget.worker_capacity - budget.counters()['worker_bytes'] - HEADER)
    before = budget.counters()
    cls = RootCursor if cursor else Capture
    obj = None
    with one_fault(cls.__init__, 'self._clear()', {'CALL_METHOD', 'CALL'}) as (_, refs):
        try:
            obj = cls(owners, 'current', **({'budget': attempt} if cursor else {'budget': attempt, 'path': ('d000.test',)}))
        except BaseException as exc:
            exc.__traceback__ = exc.__context__ = exc.__cause__ = None
    assert attempt._unit is None, 'unreturned constructor retained in attempt'
    assert attempt.workspace == 0 and budget.counters() == before
    if obj is not None:
        assert obj.status == 'capacity'
        obj.discard()
        assert obj.take() is None
        assert obj.counters()['workspace'] == 0
    else:
        assert refs[0]() is None
    sibling.close()
    attempt.close()


def test_capture_controller_tail_has_no_ghost_after_one_entry_fault():
    owners, _, _ = actual_source(config_size=3)
    budget = RedactionBudget(deadline=time.monotonic() + 5)
    attempt = CaptureBudget(ledger=budget)
    cap = Capture(owners, 'current', ('d000.test',), budget=attempt)
    method = Capture.discard
    code = method.__code__
    text = ''.join(inspect.getblock(linecache.getlines(code.co_filename)[code.co_firstlineno - 1:]))
    marker = 'b.ledger.leave(self)' if 'b.ledger.leave(self)' in text else 'self._clear()'
    with one_fault(method, marker, {'CALL_METHOD', 'CALL'}, occurrence=0 if 'leave' in marker else None, unwrap=False):
        try:
            cap.discard()
        except BaseException as exc:
            exc.__traceback__ = exc.__context__ = exc.__cause__ = None
    assert attempt._controller is attempt._running is None
    assert not budget.counters()['active']
    assert attempt.workspace == 0
    assert budget.counters()['worker_bytes'] == attempt._lease.worker
    cap.discard()
    attempt.close()


def test_constructor_refusal_plus_cleanup_entry_fault_has_no_orphan():
    m = api()
    owners, _, _ = actual_source(config_size=3)
    budget = RedactionBudget(deadline=time.monotonic() + 5)
    attempt = CaptureBudget(ledger=budget)
    sibling = budget.reserve(worker=budget.worker_capacity - budget.counters()['worker_bytes'] - 2 * HEADER - 131072)
    before = budget.counters()
    unit = error = None
    with one_fault(m.CapturedPayload.__init__, 'self._dispose()', {'CALL_METHOD', 'CALL'}) as (_, refs):
        try:
            unit = m.CapturedPayload(owners, 'current', ('d000.test',), capture_budget=attempt, budget=budget)
        except BaseException as exc:
            error = type(exc).__name__
            exc.__traceback__ = exc.__context__ = exc.__cause__ = None
    after = budget.counters()
    assert after['worker_bytes'] == before['worker_bytes']
    assert after['metadata_bytes'] == before['metadata_bytes']
    assert attempt.workspace == 0 and attempt._unit is None
    assert not after['active'] and after['hold_worker_bytes'] == after['hold_metadata_bytes'] == 0
    if unit is not None:
        assert unit.status == 'invalid'
        unit.discard()
        assert unit.take() is None and unit.counters()['status'] == 'invalid'
    else:
        assert error == 'MemoryError' and refs[0]() is None
    sibling.close()
    attempt.close()


@pytest.mark.parametrize('phase', ['seal', 'bytes', 'decode', 'admit', 'admit_take', 'done'])
def test_one_absolute_deadline_expires_in_later_phase(phase):
    with patch('time.monotonic', return_value=0):
        _, budget, attempt, unit = bridge_for([0] * 4095)
        if phase == 'done':
            finish(unit)
        else:
            at_phase(unit, phase)
        assert attempt.deadline == budget.deadline == 5
    with patch('time.monotonic', return_value=5):
        if phase == 'done':
            assert unit.take() is None
        else:
            assert unit.slice() == 'deadline'
        assert unit.status == 'deadline'
        assert unit.take() is None and unit.slice() == 'deadline'
        unit.discard()
        attempt.close()
    assert not budget.counters()['active']
    assert budget.counters()['worker_bytes'] == budget.counters()['metadata_bytes'] == 0


@pytest.mark.parametrize('phase', ['capture', 'bytes', 'decode', 'admit', 'admit_take', 'done'])
def test_idle_phase_cancellation_retains_sibling_and_repeat_terminal(phase):
    _, budget, attempt, unit = bridge_for([0] * 4095)
    sibling = budget.reserve(worker=123, metadata=321)
    if phase == 'done':
        finish(unit)
    else:
        at_phase(unit, phase)
    before = attempt.counters()
    unit.discard()
    unit.discard()
    assert unit.slice() == 'stopped' and unit.take() is None
    assert attempt.visits == before['visits'] and attempt.examined_bytes == before['examined_bytes']
    assert budget.counters()['worker_bytes'] == sibling.worker + attempt._lease.worker
    assert budget.counters()['metadata_bytes'] == sibling.metadata + attempt._lease.metadata
    follow = api().OwnedPayload.admit_sliced('still admissible', budget=budget)
    result = finish(follow).take()
    result.close()
    sibling.close()
    attempt.close()
    assert budget.counters()['worker_bytes'] == 0


def test_successive_units_keep_authority_work_and_deadline():
    owners, budget, attempt, first = bridge_for({'value': '한'})
    output = finish(first).take()
    output.close()
    counts = attempt.counters()
    authority = attempt._authority
    second = api().CapturedPayload(owners, 'current', ('d000.test',), capture_budget=attempt, budget=budget)
    output = finish(second).take()
    assert output.value == {'value': '한'}
    assert attempt._authority is authority
    assert attempt.visits > counts['visits']
    assert attempt.examined_bytes == 2 * counts['examined_bytes']
    assert attempt.descriptors == counts['descriptors']
    assert attempt.deadline == counts['deadline'] == budget.deadline
    output.close()
    attempt.close()
    assert budget.counters()['worker_bytes'] == 0


def test_bridge_controller_refused_before_capture_allocation():
    m = api()
    owners, _, _ = actual_source(config_size=3)
    ledger = RedactionBudget(deadline=time.monotonic() + 5)
    attempt = CaptureBudget(ledger=ledger)
    # Leave less than one controller header, preserving a live unrelated lease.
    sibling = ledger.reserve(metadata=ledger.metadata_capacity - ledger.counters()['metadata_bytes'] - 2 * HEADER + 1)
    before = ledger.counters()
    entered = []

    def observer(frame, event, arg):
        if event == 'call' and frame.f_code is Capture.__init__.__code__:
            entered.append(True)

    sys.setprofile(observer)
    try:
        unit = m.CapturedPayload(owners, 'current', ('d000.test',), capture_budget=attempt, budget=ledger)
    finally:
        sys.setprofile(None)
    assert entered == [], 'Capture controller allocated before bridge admission'
    assert unit.status == 'capacity'
    assert ledger.counters() == before
    assert attempt.workspace == attempt.visits == 0
    assert unit.slice() == 'capacity' and unit.take() is None
    unit.discard()
    sibling.close()
    attempt.close()
    assert ledger.counters()['worker_bytes'] == ledger.counters()['metadata_bytes'] == 0


def test_shared_active_sibling_excludes_capture_and_decode():
    m = api()
    owners, _, _ = actual_source(config_size=3, current={'d000.test': 'x' * 9000})
    ledger = RedactionBudget(deadline=time.monotonic() + 5)
    attempt = CaptureBudget(ledger=ledger)
    unit = m.CapturedPayload(owners, 'current', ('d000.test',), capture_budget=attempt, budget=ledger)
    sibling = object()
    ledger.enter(sibling)
    before = attempt.visits
    try:
        assert unit.slice() == 'lock_busy'
        assert attempt.visits == before, 'capture overlapped an active sibling'
        assert ledger._active is sibling
    finally:
        ledger.leave(sibling)
        unit.discard()
        attempt.close()
    assert not ledger.counters()['active']
    assert ledger.counters()['worker_bytes'] == 0


def at_phase(unit, phase):
    for _ in range(20000):
        if unit.phase == phase:
            return
        assert unit.slice() == 'more', unit.counters()
    raise AssertionError('phase not reached')


@pytest.mark.parametrize('action', ['reentry', 'discard'])
def test_executing_decode_keeps_custody_until_acknowledgement(monkeypatch, action):
    m = api()
    owners, _, _ = actual_source(config_size=3, current={'d000.test': 'x' * 9000})
    ledger = RedactionBudget(deadline=time.monotonic() + 5)
    attempt = CaptureBudget(ledger=ledger)
    unit = m.CapturedPayload(owners, 'current', ('d000.test',), capture_budget=attempt, budget=ledger)
    at_phase(unit, 'decode')
    entered, resume = threading.Event(), threading.Event()
    original = m._Decoder.step
    errors = []

    def blocked(decoder):
        if not entered.is_set():
            entered.set()
            assert resume.wait(4)
        return original(decoder)

    def work():
        try:
            unit.slice()
        except BaseException as exc:
            errors.append(type(exc).__name__)
            exc.__traceback__ = exc.__context__ = exc.__cause__ = None

    monkeypatch.setattr(m._Decoder, 'step', blocked)
    thread = threading.Thread(target=work)
    thread.start()
    try:
        assert entered.wait(4)
        before = ledger.counters()
        if action == 'reentry':
            assert unit.slice() == 'lock_busy'
            assert unit.status == 'more'
        else:
            unit.discard()
            unit.discard()
        assert ledger.counters() == before, 'running private graph lost its funding'
        assert unit.decoder is not None and ledger.counters()['active']
    finally:
        resume.set()
        thread.join(4)
    assert not thread.is_alive() and errors == []
    assert not ledger.counters()['active']
    if action == 'discard':
        assert unit.status == 'stopped'
        assert unit.decoder is unit.graph is unit.encoded is None
    unit.discard()
    attempt.close()
    assert ledger.counters()['worker_bytes'] == ledger.counters()['metadata_bytes'] == 0


@pytest.mark.parametrize('action', ['reentry', 'discard', 'attempt_close'])
def test_direct_capture_running_guard_is_nondestructive(monkeypatch, action):
    owners, _, _ = actual_source(config_size=3)
    ledger = RedactionBudget(deadline=time.monotonic() + 5)
    attempt = CaptureBudget(ledger=ledger)
    cap = Capture(owners, 'current', ('d000.test',), budget=attempt)
    entered, resume = threading.Event(), threading.Event()
    original = Capture._authority
    errors = []

    def blocked(self):
        entered.set()
        assert resume.wait(4)
        return original(self)

    def work():
        try:
            cap.slice()
        except BaseException as exc:
            errors.append(type(exc).__name__)
            exc.__traceback__ = exc.__context__ = exc.__cause__ = None

    monkeypatch.setattr(Capture, '_authority', blocked)
    thread = threading.Thread(target=work)
    thread.start()
    try:
        assert entered.wait(4)
        before = ledger.counters()
        if action == 'reentry':
            assert cap.slice() == 'lock_busy'
            assert cap.status == 'more'
        elif action == 'discard':
            cap.discard()
        else:
            attempt.close()
        assert ledger.counters() == before
        assert cap.owners is owners
    finally:
        resume.set()
        thread.join(4)
    assert errors == [] and not thread.is_alive()
    assert not ledger.counters()['active']
    if action != 'reentry':
        assert cap.status == 'stopped' and cap.owners is None
    cap.discard()
    attempt.close()
    assert ledger.counters()['worker_bytes'] == ledger.counters()['metadata_bytes'] == 0


def test_capture_pretry_clock_failure_retires_running_owner():
    """Persistent gap-01: real CALL, live sibling, public cleanup only."""
    owners, _, _ = actual_source(config_size=3, current={
        'd000.test': {'value': 'secret-bearing-current'}})
    budget = RedactionBudget(deadline=time.monotonic() + 5)
    sibling = budget.reserve(worker=123, metadata=321)
    sibling_before = (sibling.worker, sibling.metadata, sibling.closed)
    attempt = CaptureBudget(ledger=budget)
    unit = api().CapturedPayload(owners, 'current', ('d000.test',),
                                 capture_budget=attempt, budget=budget)
    cap_ref = weakref.ref(unit.capture)
    escaped = returned = None
    with one_fault(Capture._run, 'wait = time.monotonic()',
                   {'CALL_METHOD', 'CALL'}, owner=unit.capture) as (fault, _):
        try:
            returned = unit.slice()
        except BaseException as exc:
            escaped = type(exc).__name__
            exc.__traceback__ = exc.__context__ = exc.__cause__ = None
    after_fault = (sibling.worker, sibling.metadata, sibling.closed)
    unit.discard()
    unit.discard()
    attempt.close()
    attempt.close()
    after_cleanup = (sibling.worker, sibling.metadata, sibling.closed)
    counts = budget.counters()
    unrelated = finish(api().OwnedPayload.admit_sliced('unrelated', budget=budget)).take()
    unrelated_ok = unrelated is not None and unrelated.value == 'unrelated'
    if unrelated is not None:
        unrelated.close()
    sibling.close()
    assert fault['fired'] == 1
    assert escaped is None and returned in ('invalid', 'capacity', 'stopped')
    assert after_fault == after_cleanup == sibling_before
    assert attempt._running is None, 'quiesced Capture remains registered as running'
    assert attempt._controller is attempt._unit is attempt._lease is None
    assert attempt._owners is None and attempt.workspace == 0
    assert unit.capture is None and cap_ref() is None
    assert not counts['active'] and unrelated_ok
    assert counts['worker_bytes'] == sibling_before[0]
    assert counts['metadata_bytes'] == sibling_before[1]
    assert budget.counters()['worker_bytes'] == budget.counters()['metadata_bytes'] == 0


def source_locks_available(owners):
    """RLock ownership is proved from another thread, never by reentry."""
    from monitor.runtime_state import state_lock
    observed = []
    done = threading.Event()

    def check():
        for lock in (owners.lock, state_lock(), owners.model._condition):
            acquired = lock.acquire(False)
            observed.append(acquired)
            if acquired:
                lock.release()
        done.set()

    thread = threading.Thread(target=check)
    thread.start()
    assert done.wait(4)
    thread.join(4)
    assert not thread.is_alive()
    return observed


def test_capture_final_clock_fault_releases_acquired_locks_and_owner():
    owners, _, _ = actual_source(config_size=3)
    budget = RedactionBudget(deadline=time.monotonic() + 5)
    sibling = budget.reserve(worker=123, metadata=321)
    sibling_before = (sibling.worker, sibling.metadata, sibling.closed)
    attempt = CaptureBudget(ledger=budget)
    cap = Capture(owners, 'current', ('d000.test',), budget=attempt)
    # This is the final allocating clock CALL after all three real locks were
    # acquired, not the pre-acquisition clock and not a nonallocating STORE.
    with one_fault(Capture._run, 'self.max_slice_seconds = max(',
                   {'CALL_METHOD', 'CALL'}, owner=cap, occurrence=0) as (fault, _):
        status = cap.slice()
    locks = source_locks_available(owners)
    cap.discard()
    cap.discard()
    attempt.close()
    attempt.close()
    MEASUREMENTS.append(dict(kind='final-clock-unwind', fault=dict(fault),
        locks=locks, running_none=attempt._running is None, ledger=budget.counters()))
    assert status == 'capacity'
    assert locks == [True, True, True], 'diagnostic allocation stranded acquired locks'
    assert attempt._running is attempt._controller is attempt._unit is None
    assert cap.owners is None and cap._lease is None and attempt.workspace == 0
    assert (sibling.worker, sibling.metadata, sibling.closed) == sibling_before
    assert budget.counters()['worker_bytes'] == sibling.worker
    assert budget.counters()['metadata_bytes'] == sibling.metadata
    assert not budget.counters()['active']
    unrelated = finish(api().OwnedPayload.admit_sliced('unrelated', budget=budget)).take()
    assert unrelated.value == 'unrelated'
    unrelated.close()
    sibling.close()
    assert budget.counters()['worker_bytes'] == budget.counters()['metadata_bytes'] == 0


@pytest.mark.parametrize('case', [
    'cursor-initial-clock', 'nested-final-clock', 'capture-hold-clock',
    'capture-wait-arithmetic', 'seal-start-clock', 'take-final-arithmetic',
    'capture-counter-arithmetic', 'nested-cleanup-entry',
])
def test_shared_run_guard_family(case):
    """Compact same-owner boundary matrix, not an allocation-site sweep."""
    from http_api.read_capture import RootCursor
    nested = case.startswith('nested-')
    owners, _, _ = actual_source(root_size=129 if nested else 1,
        config_size=3, current=None if nested else {'d000.test': [0] * 500})
    budget = RedactionBudget(deadline=time.monotonic() + 5)
    sibling = budget.reserve(worker=123, metadata=321)
    sibling_before = (sibling.worker, sibling.metadata, sibling.closed)
    attempt = (CaptureBudget.for_test(ledger=budget, slice_steps=1)
               if case == 'capture-counter-arithmetic' else CaptureBudget(ledger=budget))
    bridge = None
    if case.startswith(('seal-', 'take-')):
        bridge = api().CapturedPayload(owners, 'current', ('d000.test',),
                                       capture_budget=attempt, budget=budget)
        at_phase(bridge, 'seal' if case.startswith('seal-') else 'bytes')
        cap = bridge.capture
        invoke = bridge.slice
    elif case.startswith('cursor-'):
        cap = RootCursor(owners, 'current', budget=attempt)
        invoke = cap.next_key
    else:
        cap = Capture(owners, 'current', ('d000.test',), budget=attempt)
        invoke = cap.slice
    target = cap
    if nested:
        assert cap.slice() == 'more'
        target = cap._root_cursor
        assert type(target) is RootCursor
    if case == 'capture-counter-arithmetic':
        while cap.slices <= 256:
            assert cap.slice() == 'more'
        # Adding to this actual large cumulative counter produces a new int;
        # no private counter store or small-int-cache fault is used.
    selectors = {
        'cursor-initial-clock': ('wait = time.monotonic()', {'CALL_METHOD', 'CALL'}, None),
        'nested-final-clock': ('self.max_slice_seconds = max(', {'CALL_METHOD', 'CALL'}, 0),
        'capture-hold-clock': ('hold = time.monotonic()', {'CALL_METHOD', 'CALL'}, None),
        'capture-wait-arithmetic': ('self.max_wait_seconds = max(', {'BINARY_SUBTRACT', 'BINARY_OP'}, None),
        'seal-start-clock': ('self._start = self.budget.now()', {'CALL_METHOD', 'CALL'}, None),
        'take-final-arithmetic': ('self.max_slice_seconds = max(', {'BINARY_SUBTRACT', 'BINARY_OP'}, 0),
        'capture-counter-arithmetic': ('self.slices += 1', {'INPLACE_ADD', 'BINARY_OP'}, 0),
        'nested-cleanup-entry': ('                self._clear()', {'CALL_METHOD', 'CALL'}, None),
    }
    if case == 'nested-cleanup-entry':
        attempt.cancel()  # ordinary cancellation followed by one cleanup fault
    marker, opnames, occurrence = selectors[case]
    with one_fault(Capture._run, marker, opnames, owner=target, occurrence=occurrence) as (fault, _):
        result = invoke()
    locks = source_locks_available(owners)
    status = bridge.status if bridge is not None else cap.status
    if bridge is not None:
        assert bridge.take() is None
        bridge.discard()
        bridge.discard()
    else:
        cap.discard()
        cap.discard()
    attempt.close()
    attempt.close()
    counts = budget.counters()
    MEASUREMENTS.append(dict(kind='run-guard-family', case=case, fault=dict(fault),
        returned=result, status=status, locks=locks, ledger=counts))
    assert status == ('stopped' if case == 'nested-cleanup-entry' else 'capacity')
    assert result is None if case.startswith('cursor-') else result == status
    assert locks == [True, True, True]
    assert attempt._running is attempt._controller is attempt._unit is attempt._owners is None
    assert cap.owners is target.owners is None
    assert cap._lease is target._lease is None and attempt.workspace == 0
    assert (sibling.worker, sibling.metadata, sibling.closed) == sibling_before
    assert counts['worker_bytes'] == sibling.worker and counts['metadata_bytes'] == sibling.metadata
    assert not counts['active']
    unrelated = finish(api().OwnedPayload.admit_sliced('unrelated', budget=budget)).take()
    assert unrelated.value == 'unrelated'
    unrelated.close()
    sibling.close()
    assert budget.counters()['worker_bytes'] == budget.counters()['metadata_bytes'] == 0


@pytest.mark.parametrize('nested', [False, True])
@pytest.mark.parametrize('action', ['reentry', 'discard', 'attempt_close'])
def test_running_cursor_guard_keeps_source_and_charge_until_ack(monkeypatch, nested, action):
    from http_api.read_capture import RootCursor
    owners, _, _ = actual_source(root_size=129 if nested else 1, config_size=3)
    budget = RedactionBudget(deadline=time.monotonic() + 5)
    attempt = CaptureBudget(ledger=budget)
    if nested:
        unit = Capture(owners, 'current', ('d000.test',), budget=attempt)
        assert unit.slice() == 'more'
        cursor = unit._root_cursor
        invoke = unit.slice
    else:
        unit = cursor = RootCursor(owners, 'current', budget=attempt)
        invoke = unit.next_key
    entered, resume = threading.Event(), threading.Event()
    original = Capture._authority
    results, errors = [], []

    def blocked(self):
        if self is cursor:
            entered.set()
            assert resume.wait(4)
        return original(self)

    def work():
        try:
            results.append(invoke())
        except BaseException as exc:
            errors.append(type(exc).__name__)
            exc.__traceback__ = exc.__context__ = exc.__cause__ = None

    monkeypatch.setattr(Capture, '_authority', blocked)
    thread = threading.Thread(target=work)
    thread.start()
    try:
        assert entered.wait(4)
        before = budget.counters()
        if action == 'reentry':
            assert invoke() == 'lock_busy' if nested else invoke() is None
            assert unit.status == 'more'
        elif action == 'discard':
            unit.discard()
            unit.discard()
        else:
            attempt.close()
        assert budget.counters() == before
        assert cursor.owners is owners and cursor._lease is not None
        assert attempt._running is cursor and budget._active is cursor
    finally:
        resume.set()
        thread.join(4)
    assert not thread.is_alive() and errors == []
    assert attempt._running is attempt._controller is None
    assert not budget.counters()['active']
    if action == 'reentry' and not nested:
        assert results == ['d000.test'] and cursor.status == 'done'
    elif action != 'reentry':
        assert unit.status == 'stopped' and unit.owners is None
    unit.discard()
    attempt.close()
    assert source_locks_available(owners) == [True, True, True]
    assert budget.counters()['worker_bytes'] == budget.counters()['metadata_bytes'] == 0


@pytest.mark.parametrize('path,boundary', [
    ('bridge', 'lock_wait'), ('bridge', 'action_return'),
    ('seal', 'lock_wait'), ('bytes', 'action_return'),
    ('cursor', 'lock_wait'), ('nested', 'action_return'),
])
@pytest.mark.parametrize('expired', [False, True])
def test_shared_original_deadline_after_wait_or_action(path, boundary, expired):
    """Real locks/actions and bounded barriers; one unchanged absolute clock."""
    from http_api.read_capture import RootCursor
    now = [100.0]
    with patch('time.monotonic', side_effect=lambda: now[0]):
        owners, _, _ = actual_source(root_size=129 if path == 'nested' else 1,
            config_size=3, current={'d000.test': {'value': 'deadline-current'}})
        budget = RedactionBudget(deadline=time.monotonic() + 5)
        attempt = CaptureBudget(ledger=budget)
        if path == 'cursor':
            unit = target = RootCursor(owners, 'current', budget=attempt)
            invoke = unit.next_key
        elif path == 'nested':
            unit = Capture(owners, 'current', ('d000.test',), budget=attempt)
            assert unit.slice() == 'more'
            target = unit._root_cursor
            invoke = unit.slice
        else:
            unit = api().CapturedPayload(owners, 'current', ('d000.test',),
                                         capture_budget=attempt, budget=budget)
            if path in ('seal', 'bytes'):
                at_phase(unit, path)
            target = unit.capture
            invoke = unit.slice
        assert attempt.deadline == budget.deadline == 105.0
        lines, start = inspect.getsourcelines(Capture._run)
        lock_line = [start + i for i, line in enumerate(lines) if 'if not acquired_config:' in line]
        assert len(lock_line) == 1
        acquiring, blocked, resume = threading.Event(), threading.Event(), threading.Event()
        results, errors, actions, acquisitions = [], [], [], []
        acquisition_starts, acquisition_finishes, action_codes = [], [], []
        target_id = id(target)

        def profile(frame, event, arg):
            if (event == 'c_call' and frame.f_code is Capture._run.__code__
                    and getattr(arg, '__self__', None) is owners.lock
                    and getattr(arg, '__name__', None) == 'acquire'):
                acquisition_starts.append(now[0])
                acquiring.set()

        def trace(frame, event, arg):
            stop = False
            if (frame.f_code is Capture._run.__code__
                    and id(frame.f_locals['self']) == target_id):
                if event == 'call':
                    action_codes.append(frame.f_locals['action'].__code__)
                if event == 'line' and frame.f_lineno == lock_line[0]:
                    acquisitions.append(frame.f_locals['acquired_config'])
                    acquisition_finishes.append(now[0])
                    stop = boundary == 'lock_wait'
            elif event == 'return' and action_codes and frame.f_code is action_codes[0]:
                actions.append(True)
                # Pause the actual source-action frame before its return to
                # _run, not an already-expired new call or a replacement action.
                stop = boundary == 'action_return'
            if stop and not blocked.is_set():
                blocked.set()
                assert resume.wait(4)
            return trace

        def work():
            sys.setprofile(profile)
            sys.settrace(trace)
            try:
                results.append(invoke())
            except BaseException as exc:
                errors.append(type(exc).__name__)
                exc.__traceback__ = exc.__context__ = exc.__cause__ = None
            finally:
                sys.settrace(None)
                sys.setprofile(None)

        thread = threading.Thread(target=work)
        if boundary == 'lock_wait':
            # The worker enters the actual native timed acquire while this
            # thread owns the config lock; release, then stop after acquisition.
            with owners.lock:
                thread.start()
                assert acquiring.wait(4)
                assert acquisition_starts == [100.0]
                assert not blocked.is_set() and results == []
                now[0] = 105.0 if expired else 104.0
        else:
            thread.start()
        try:
            assert blocked.wait(4)
            assert acquisitions == [True], 'must cross a successful real acquisition'
            assert acquisition_finishes == [now[0]]
            assert attempt._running is target
            assert budget.counters()['active']
            assert results == []
            if boundary == 'action_return':
                assert now[0] < attempt.deadline
                now[0] = 105.0 if expired else 104.0
        finally:
            resume.set()
            thread.join(4)
        assert not thread.is_alive() and errors == []
        assert attempt.deadline == budget.deadline == 105.0
        if expired:
            assert unit.status == 'deadline' and unit.take() is None
            assert results == [None] if path == 'cursor' else results == ['deadline']
            assert actions == ([] if boundary == 'lock_wait' else [True])
        elif path == 'cursor':
            assert results == ['d000.test'] and unit.status == 'done'
        elif path == 'nested':
            while unit.slice() == 'more':
                pass
            assert unit.seal() == 'done'
            assert unit.take() == b'{"value":"deadline-current"}'
        else:
            output = finish(unit).take()
            assert output.value == {'value': 'deadline-current'}
            output.close()
        unit.discard()
        unit.discard()
        attempt.close()
        attempt.close()
        locks = source_locks_available(owners)
        counts = budget.counters()
        MEASUREMENTS.append(dict(kind='original-deadline-crossing', path=path,
            boundary=boundary, expired=expired, deadline=attempt.deadline,
            admission_start_time=100.0, resumed_time=now[0], acquiring=acquiring.is_set(),
            acquisition_starts=acquisition_starts, acquisition_finishes=acquisition_finishes,
            acquisitions=acquisitions, action_returns=len(actions), results=results,
            locks=locks, ledger=counts))
        assert locks == [True, True, True]
        assert attempt._running is attempt._controller is attempt._unit is attempt._owners is None
        assert target.owners is None and target._lease is None
        assert not counts['active'] and attempt.workspace == 0
        assert counts['worker_bytes'] == counts['metadata_bytes'] == 0
