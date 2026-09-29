"""Actual component lifecycle: single allocation fault and public recovery."""
import sys
import ast
import dis
import inspect
import json
import os
from pathlib import Path
import threading

import pytest
import time
import weakref
from unittest.mock import patch

import security.derived_redaction as m
from tests.test_stage4_redaction_plan import build, owners, finish
from tests.test_stage4_redaction_projection import drain
from tests.test_stage4_redaction_cleanup import allocation_fault, reconciled


CONSTRUCTOR_RECEIPTS = []


def _initializer_entry_failure(kind):
    """One real call-entry fault; the input claim is a continuing sibling."""
    cls = {'encode': m.Encoding, 'project': m.Projector, 'admit': m._Admission}[kind]
    parsed = ast.parse(Path(m.__file__).read_text())
    class_node = next(n for n in parsed.body if isinstance(n, ast.ClassDef) and n.name == cls.__name__)
    method = next(n for n in class_node.body if isinstance(n, ast.FunctionDef) and n.name == '__init__')
    calls = [n for n in ast.walk(method) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
             and n.func.value.id == 'self' and n.func.attr == '_initialize']
    assert len(calls) == 1
    line = calls[0].lineno
    current_line = None
    sites = []
    for instruction in dis.get_instructions(cls.__init__):
        if instruction.starts_line is not None:
            current_line = instruction.starts_line
        if current_line == line and instruction.opname in ('CALL_METHOD', 'CALL'):
            sites.append(instruction)
    assert len(sites) == 1
    site = sites[0]
    record = {'kind': kind, 'phase': 'entry', 'line': line, 'opcode': site.opname,
              'offset': site.offset, 'fired': 0, 'budget_roots': 0,
              'source': m.__file__, 'nodeid': os.environ.get('PYTEST_CURRENT_TEST')}

    def census(frame, event, arg):
        if event == 'call' and frame.f_code is m.RedactionBudget.__init__.__code__:
            record['budget_roots'] += 1

    sys.setprofile(census)
    budget = m.RedactionBudget(deadline=time.monotonic() + 30)
    source = m.OwnedPayload.admit('public input', budget=budget)
    plan = build({'api_key': 'secret'}, budget=budget).take() if kind == 'project' else None
    before = budget.counters()
    refs = []
    result = error = None

    def trace(frame, event, arg):
        if frame.f_code is cls.__init__.__code__:
            if event == 'call':
                frame.f_trace_opcodes = True
            if event == 'opcode' and frame.f_lasti == site.offset and not record['fired']:
                state = frame.f_locals
                assert type(state['self']) is cls and state['budget'] is budget
                record['fields_at_fault'] = sorted(vars(state['self']))
                refs.append(weakref.ref(state['self']))
                del state
                record['fired'] += 1
                raise MemoryError('single actual initializer helper-entry allocation')
            return trace
        return None

    try:
        sys.settrace(trace)
        try:
            if kind == 'encode':
                result = m.Encoding(source, budget=budget)
            elif kind == 'project':
                result = m.Projector(plan, source, budget=budget)
            else:
                result = m.OwnedPayload.admit_sliced(['public input'], budget=budget)
        except BaseException as exc:
            error = (type(exc).__name__, str(exc))
            exc.__traceback__ = exc.__context__ = exc.__cause__ = None
        finally:
            sys.settrace(None)
        record.update(error=error, before=before, after=budget.counters())
        assert record['fired'] == record['budget_roots'] == 1
        assert budget.counters() == before
        assert source._pins == 0 and (plan is None or plan._pins == 0)
        assert budget._active is None and budget._hold_worker == budget._hold_metadata == 0
        if result is None:
            assert refs[0]() is None
            assert error is not None and (error[0] == 'MemoryError' or error == ('Reject', 'invalid')), error
        else:
            assert result.status == 'invalid' and result._lease is None
            for _ in range(2):
                assert result.slice() == 'invalid'
                assert result.take() is None
                result.discard()
                assert result.counters()['status'] == 'invalid'
        # Unrelated work remains admissible in the same naturally continuing ledger.
        following = m.OwnedPayload.admit('following', budget=budget)
        following.close()
    finally:
        sys.settrace(None)
        sys.setprofile(None)
        source.close()
        if plan is not None:
            plan.close()
        record['after_public_cleanup'] = budget.counters()
        CONSTRUCTOR_RECEIPTS.append(record)
    reconciled(budget)


def test_encoding_initializer_entry_is_effect_free():
    _initializer_entry_failure('encode')


def test_projector_initializer_entry_is_effect_free():
    _initializer_entry_failure('project')


def test_sliced_admission_initializer_entry_is_effect_free():
    _initializer_entry_failure('admit')


def _constructor_diagnostic_failure(kind, phase):
    """Small same-root matrix, not an allocation-site inventory or sweep."""
    cls = {'encode': m.Encoding, 'project': m.Projector, 'admit': m._Admission, 'builder': m.Builder}[kind]
    record = {'kind': kind, 'phase': phase, 'fired': 0, 'budget_roots': 0,
              'source': m.__file__, 'nodeid': os.environ.get('PYTEST_CURRENT_TEST')}

    def census(frame, event, arg):
        if event == 'call' and frame.f_code is m.RedactionBudget.__init__.__code__:
            record['budget_roots'] += 1

    sys.setprofile(census)
    budget = m.RedactionBudget(deadline=time.monotonic() + 30)
    source = m.OwnedPayload.admit('public input', budget=budget)
    plan = build({'api_key': 'secret'}, budget=budget).take() if kind == 'project' else None
    cfg = {'api_key': 'secret'}
    lock, model = owners(cfg)
    blocker = None
    if phase == 'capacity':
        blocker = budget.reserve(metadata=budget.metadata_capacity - budget.counters()['metadata_bytes'] - m.HEADER)
    elif phase == 'closed':
        budget.close()
    before = budget.counters()
    refs = [weakref.ref(source)]
    if plan is not None:
        refs.append(weakref.ref(plan))
    source_ref = weakref.ref(model)
    expected = 'capacity' if phase == 'capacity' else 'deadline' if phase == 'deadline' else 'invalid'
    result = error = None
    target = cls._initialize_control if phase == 'partial' else cls.__init__
    marker = ('self.preflights = []' if kind == 'project' else 'self.found = set()' if kind == 'builder'
              else 'self._pinned = [None, None]' if kind == 'encode'
              else 'self._pinned = []') if phase == 'partial' else 'self.gen = self.run(value)'
    if phase in ('partial', 'later'):
        lines, start = inspect.getsourcelines(target)
        matches = [start + i for i, text in enumerate(lines) if marker in text]
        assert len(matches) == 1
        current_line = None
        sites = []
        for instruction in dis.get_instructions(target):
            if instruction.starts_line is not None:
                current_line = instruction.starts_line
            allocating = (instruction.opname == 'BUILD_LIST' if phase == 'partial' and kind != 'builder'
                          else instruction.opname in ('CALL_FUNCTION', 'CALL_METHOD', 'CALL'))
            if current_line == matches[0] and allocating:
                sites.append(instruction)
        # Projector and Encoding select the actually reached arm below.
        assert sites
        record['sites'] = [{'offset': site.offset, 'opcode': site.opname, 'line': matches[0]} for site in sites]
    else:
        sites = []

    def trace(frame, event, arg):
        if frame.f_code is target.__code__:
            if event == 'call':
                frame.f_trace_opcodes = True
            if event == 'opcode' and frame.f_lasti in {site.offset for site in sites} and not record['fired']:
                owner = frame.f_locals['self']
                assert type(owner) is cls and owner.budget is budget
                if phase == 'partial':
                    assert owner._lease is None
                    assert budget._hold_worker > 0 and budget._hold_metadata > 0
                    assert not budget._lock._is_owned()
                record['fields_at_fault'] = sorted(vars(owner))
                record['fired_offset'] = frame.f_lasti
                del owner
                record['fired'] += 1
                raise MemoryError('single actual partial initialization allocation')
            return trace
        return None

    try:
        with patch.object(m.time, 'monotonic', return_value=budget.deadline if phase == 'deadline' else time.monotonic()):
            sys.settrace(trace)
            try:
                if kind == 'encode':
                    result = m.Encoding(source, budget=budget)
                elif kind == 'project':
                    result = m.Projector(plan, source, budget=budget)
                elif kind == 'builder':
                    result = m.Builder(cfg, lock, model, budget=budget)
                else:
                    result = m.OwnedPayload.admit_sliced(['public input'], budget=budget)
            except BaseException as exc:
                error = (type(exc).__name__, str(exc))
                exc.__traceback__ = exc.__context__ = exc.__cause__ = None
            finally:
                sys.settrace(None)
            record.update(error=error, before=before, after=budget.counters())
            assert record['budget_roots'] == 1
            assert record['fired'] == (1 if phase in ('partial', 'later') else 0)
            if phase != 'later':
                assert budget.counters() == before
            assert source._pins == 0 and (plan is None or plan._pins == 0)
            assert budget._active is None and budget._hold_worker == budget._hold_metadata == 0
            if result is None:
                assert error == ('Reject', expected) or (phase in ('partial', 'later') and error[0] == 'MemoryError'), error
            else:
                assert result.status == expected and result._lease is None
                for _ in range(2):
                    assert result.slice() == expected
                    assert result.take() is None
                    result.discard()
                    if kind == 'builder':
                        assert result.seal_slice() == expected
                    assert result.counters()['status'] == expected
                if phase == 'partial':
                    assert not any(type(value) in (list, dict, set) for value in vars(result).values())
    finally:
        sys.settrace(None)
        sys.setprofile(None)
        source.close()
        if plan is not None:
            plan.close()
        if blocker is not None:
            blocker.close()
        record['after_public_cleanup'] = budget.counters()
        CONSTRUCTOR_RECEIPTS.append(record)
    # The caller owns these references until this point; diagnostics must not.
    source = plan = cfg = lock = model = None
    # Opcode tracing can leave this observer frame's locals snapshot stale.
    # Refresh it after retiring caller references; retain no frame/dict oracle.
    sys._getframe().f_locals
    assert all(ref() is None for ref in refs) and source_ref() is None
    reconciled(budget)


def test_encoding_partial_initializer_has_safe_diagnostics():
    _constructor_diagnostic_failure('encode', 'partial')


def test_projector_partial_initializer_drops_control_storage():
    _constructor_diagnostic_failure('project', 'partial')


def test_builder_partial_initializer_has_safe_diagnostics():
    _constructor_diagnostic_failure('builder', 'partial')


def test_sliced_admission_partial_initializer_has_safe_diagnostics():
    _constructor_diagnostic_failure('admit', 'partial')


@pytest.mark.parametrize('kind', ['encode', 'project', 'admit', 'builder'])
def test_initial_capacity_refusal_has_safe_diagnostics(kind):
    _constructor_diagnostic_failure(kind, 'capacity')


@pytest.mark.parametrize('phase', ['closed', 'deadline', 'later'])
def test_sliced_admission_initial_and_later_refusal(phase):
    _constructor_diagnostic_failure('admit', phase)


def test_rejected_admission_fault_retires_lease_and_active():
    """H3: a failed admission must not strand its unreturned lease or token."""
    budget = m.RedactionBudget(deadline=time.monotonic() + 30)
    sibling = budget.reserve(worker=50000, metadata=10000)
    refs = []
    original = m._Lease.__init__

    def observe(lease, *args, **kwargs):
        original(lease, *args, **kwargs)
        refs.append(weakref.ref(lease))

    error = None
    with patch.object(m._Lease, '__init__', new=observe):
        with allocation_fault(m._Lease.close, 'self.budget._worker -= self.worker',
                              'budget_worker = self.budget._worker - self.worker',
                              lambda frame: frame.f_locals['self'] is not sibling) as fault:
            try:
                m.OwnedPayload.admit(object(), budget=budget)
            except (m.Reject, MemoryError) as exc:
                error = (type(exc).__name__, exc.args[0] if type(exc) is m.Reject else 'allocator')
                exc.__traceback__ = exc.__context__ = exc.__cause__ = None
    assert fault['fired']
    # No private lease rescue and no GC-assisted destruction before observations.
    assert len(refs) == 1 and refs[0]() is None
    assert error == ('Reject', 'invalid'), (error, budget.counters())
    reconciled(budget, sibling)
    assert budget._active is None
    source = m.OwnedPayload.admit('following unrelated admission', budget=budget)
    source.close()
    sibling.close()
    reconciled(budget)
    assert sys.gettrace() is None


def test_mint_is_provisionally_held_outside_lock_and_rechecked():
    budget = m.RedactionBudget(deadline=time.monotonic() + 30)
    sibling = budget.reserve(worker=333, metadata=444)
    before = budget.counters()
    original = m._Lease.__init__
    observed = []

    def revoke(lease, *args, **kwargs):
        original(lease, *args, **kwargs)
        observed.append((budget._lock._is_owned(), budget.counters()))
        budget.close()

    with patch.object(m._Lease, '__init__', new=revoke):
        try:
            budget.reserve(worker=100, metadata=200)
        except m.Reject as exc:
            assert exc.args == ('invalid',)
        else:
            raise AssertionError('mint ignored revocation during materialization')
    assert len(observed) == 1 and not observed[0][0]
    counts = observed[0][1]
    assert counts['worker_bytes'] == before['worker_bytes']
    assert counts['worker_peak'] == before['worker_peak']
    assert counts['hold_worker_bytes'] == 106728 + 100
    assert counts['hold_metadata_bytes'] == 106728 + 200
    assert budget.counters()['hold_worker_bytes'] == 0
    assert budget.counters()['hold_metadata_bytes'] == 0
    reconciled(budget, sibling)
    assert sibling.worker == 106728 + 333
    sibling.close()
    reconciled(budget)


def test_constructor_cleanup_entry_fault_has_automatic_custody():
    budget = m.RedactionBudget(deadline=time.monotonic() + 30)
    plan = build({'api_key': 'secret'}, budget=budget).take()
    source = m.OwnedPayload.admit('secret', budget=budget)
    before = budget.counters()['worker_bytes']
    original = m._Operation._dispose
    calls = []
    refs = []

    def fail(owner, *args, **kwargs):
        calls.append(True)
        refs.append(weakref.ref(owner._lease))
        if len(calls) == 1:
            raise MemoryError('one cleanup helper entry fault')
        return original(owner, *args, **kwargs)

    result = None
    with patch.object(source, '_pin', side_effect=m.Reject('invalid')):
        with patch.object(m._Operation, '_clear', new=fail), patch.object(m._Operation, '_dispose', new=fail):
            try:
                result = m.Projector(plan, source, budget=budget)
            except (m.Reject, MemoryError) as exc:
                exc.__traceback__ = exc.__context__ = exc.__cause__ = None
    assert calls
    assert budget.counters()['worker_bytes'] == before
    assert plan._pins == source._pins == 0
    assert budget._active is None
    assert all(ref() is None for ref in refs)
    if result is not None:
        assert result.status == 'invalid' and result._lease is None
        result.discard()
    source.close()
    plan.close()
    reconciled(budget)


@pytest.mark.parametrize('event', ['opaque', 'capacity', 'deadline', 'closed'])
def test_failed_admission_events_with_sibling_and_cleanup_entry_fault(event):
    clock = [0]
    with patch.object(m.time, 'monotonic', side_effect=lambda: clock[0]):
        budget = m.RedactionBudget(deadline=5)
        sibling = budget.reserve(worker=1000, metadata=2000)
        reserve, close = m._Lease.reserve, m._Lease.close
        fired = []
        events = []
        leases = []
        init = m._Lease.__init__

        def observe(lease, *args):
            init(lease, *args)
            leases.append(weakref.ref(lease))

        def grow(lease, **kw):
            reserve(lease, **kw)
            if not events and event in ('deadline', 'closed'):
                events.append(event)
                if event == 'deadline':
                    clock[0] = 5
                else:
                    budget.close()

        def abort(lease):
            if lease is not sibling and not fired:
                fired.append(True)
                raise MemoryError('single abort helper-entry allocation')
            return close(lease)

        value = object() if event == 'opaque' else [0] * 4096 if event == 'capacity' else ['text']
        with patch.object(m._Lease, '__init__', new=observe), patch.object(m._Lease, 'reserve', new=grow), patch.object(m._Lease, 'close', new=abort):
            with pytest.raises(m.Reject, match='invalid'):
                m.OwnedPayload.admit(value, budget=budget)
        assert fired == [True]
        assert events == ([event] if event in ('deadline', 'closed') else [])
        assert all(ref() is None for ref in leases)
        assert budget._active is None
        assert budget.counters()['hold_worker_bytes'] == budget.counters()['hold_metadata_bytes'] == 0
        reconciled(budget, sibling)
        if event in ('opaque', 'capacity'):
            following = m.OwnedPayload.admit('following', budget=budget)
            following.close()
        else:
            with pytest.raises(m.Reject, match=event if event == 'deadline' else 'invalid'):
                m.OwnedPayload.admit('following', budget=budget)
        sibling.close()
        reconciled(budget)


@pytest.mark.parametrize('kind', ['project', 'encode'])
def test_pending_shell_and_generator_retire_before_failed_take_debit(kind):
    budget = m.RedactionBudget(deadline=time.monotonic() + 30)
    plan = build({'api_key': 'secret'}, budget=budget).take()
    source = m.OwnedPayload.admit('secret' * 100, budget=budget)
    operation = m.Projector(plan, source, budget=budget) if kind == 'project' else m.Encoding(source, budget=budget, record_json=True)
    generator = weakref.ref(operation.gen)
    drain(operation)
    assert generator() is None
    refs = []
    init = m._Owned.__init__

    def mint(shell, *args):
        init(shell, *args)
        assert shell._lease is None and operation._lease is not None
        refs.append(weakref.ref(shell))
        source.close()

    lease = operation._lease
    close = m._Lease.close
    observations = []

    def debit(claim):
        if claim is lease:
            assert refs[0]() is None
            assert operation.gen is operation.result is None
            assert not any(operation._pinned)
            observations.append(True)
        close(claim)

    with patch.object(m._Owned, '__init__', new=mint), patch.object(m._Lease, 'close', new=debit):
        with allocation_fault(m._SerialOwner._retire, 'budget_worker = b._worker - lease.worker',
                              'budget_worker = b._worker - lease.worker',
                              lambda frame: frame.f_locals['handle'] is source) as fault:
            assert operation.take() is None
    assert fault['fired'] and observations == [True]
    assert operation.status == 'invalid' and operation._lease is None
    assert budget._active is None and not operation._running
    operation.discard()
    source.close()
    plan.close()
    reconciled(budget)


def test_public_drop_keeps_last_pin_charge_and_never_holds_locks():
    budget = m.RedactionBudget(deadline=time.monotonic() + 30)
    source = m.OwnedPayload.admit('text', budget=budget)
    operation = m.Encoding(source, budget=budget)
    entered, resume = threading.Event(), threading.Event()
    lines, start = inspect.getsourcelines(m._Owned.close)
    line = start + next(i for i, text in enumerate(lines) if 'del local' in text and i > 5)
    failures = []

    def trace(frame, event, arg):
        if frame.f_code.co_filename == m.__file__ and event == 'line' and frame.f_lineno == line and not entered.is_set():
            entered.set()
            if not resume.wait(4):
                raise RuntimeError('drop barrier')
        return trace

    def run():
        sys.settrace(trace)
        try:
            source.close()
        except BaseException as exc:
            failures.append(type(exc).__name__)
        finally:
            sys.settrace(None)

    worker = threading.Thread(target=run)
    worker.start()
    try:
        assert entered.wait(4)
        assert source._closed == 1 and source._pins == 1
        assert not budget._lock._is_owned()
        source.close()
        operation.discard()
        assert source._pins == 0 and not source._lease.closed
        reconciled(budget, source._lease)
    finally:
        resume.set()
        worker.join(4)
    assert not worker.is_alive() and not failures
    assert source._closed == 2 and source._lease.closed
    reconciled(budget)


@pytest.mark.parametrize('event', ['none', 'cancel', 'closed', 'writer'])
def test_real_builder_root_destruction_is_after_fence_and_before_eligibility(event):
    budget = m.RedactionBudget(deadline=time.monotonic() + 30)
    cfg = {'api_key': 'secret'}
    lock, model = owners(cfg)
    condition = model._condition
    observations = []
    target = None

    class Marker:
        def __del__(self):
            checks = []

            def locks():
                for guard in (lock, condition, budget._lock):
                    got = guard.acquire(False)
                    checks.append(got)
                    if got:
                        guard.release()

            worker = threading.Thread(target=locks)
            worker.start()
            worker.join(4)
            owner = target()
            observations.append((tuple(checks), not worker.is_alive(), owner._running))
            if event == 'cancel':
                owner.discard()
            elif event == 'closed':
                budget.close()
            elif event == 'writer':
                # A legitimate model owner transition after the fresh fence.
                model.invalidate(hard=True)

    marker = Marker()
    ref = weakref.ref(marker)
    cfg['opaque'] = marker
    builder = m.Builder(cfg, lock, model, budget=budget)
    target = weakref.ref(builder)
    finish(builder)
    assert builder.status == 'done'
    del cfg, marker
    output = builder.take()
    assert ref() is None
    assert observations == [((True, True, True), True, True)]
    assert builder.config is builder.model is builder.lock is None
    if event in ('none', 'writer'):
        assert output is not None and output.value.replacements
        output.close()
    else:
        assert output is None
        assert builder.status == ('stopped' if event == 'cancel' else 'invalid')
    reconciled(budget)


def test_constructor_borrowed_arguments_clear_before_internal_debit():
    budget = m.RedactionBudget(deadline=time.monotonic() + 30)
    plan = build({'api_key': 'secret'}, budget=budget).take()
    source = m.OwnedPayload.admit('secret', budget=budget)
    original = m._Lease.close
    observed = []

    def debit(lease):
        frame = sys._getframe(1)
        while frame is not None:
            if frame.f_code is m.Projector.__init__.__code__:
                state = frame.f_locals
                observed.append(state['owned_plan'] is None and state['owned_payload'] is None)
                del state
            frame = frame.f_back
        original(lease)

    with patch.object(m.Projector, 'project', side_effect=MemoryError('generator entry')):
        with patch.object(m._Lease, 'close', new=debit):
            operation = m.Projector(plan, source, budget=budget)
    assert observed == [True]
    assert operation.status == 'invalid'
    assert plan.value.replacements and source.value == 'secret'
    assert plan._pins == source._pins == 0
    plan.close()
    source.close()
    reconciled(budget)


def test_actual_second_encoding_text_and_chunk_lifetimes():
    budget = m.RedactionBudget(deadline=time.monotonic() + 30)
    source = m.OwnedPayload.admit({'text': 'é\\"\n' * 400}, budget=budget)
    operation = m.Encoding(source, budget=budget, record_json=True)
    original = m._Lease.release
    phases = []

    def release(lease, **kw):
        frame = sys._getframe(1)
        if frame.f_code is m.Encoding.assemble.__code__:
            state = frame.f_locals
            assert 'out' not in state and state.get('chunk') is None
            assert type(state['result']) is bytes
            phases.append((operation.assemblies, type(state['value']).__name__, lease.worker))
            del state
        del frame
        original(lease, **kw)

    with patch.object(m._Lease, 'release', new=release):
        drain(operation)
    assert [row[:2] for row in phases] == [(1, 'dict'), (2, 'str')]
    assert operation.gen is None and operation.status == 'done'
    lease = operation._lease
    output = operation.take()
    assert output._lease is lease and operation._lease is None
    inner = json.dumps(source.value, ensure_ascii=False, separators=(',', ':'))
    assert output.value == json.dumps(inner, ensure_ascii=False).encode()
    output.close()
    source.close()
    reconciled(budget)


def test_admission_shell_is_pending_until_final_eligibility():
    budget = m.RedactionBudget(deadline=time.monotonic() + 30)
    original = m._Owned.__init__
    observations = []

    def revoke(shell, *args):
        original(shell, *args)
        observations.append(shell._lease is None)
        budget.close()

    with patch.object(m._Owned, '__init__', new=revoke):
        with pytest.raises(m.Reject, match='invalid'):
            m.OwnedPayload.admit('text', budget=budget)
    assert observations == [True]
    reconciled(budget)
    assert budget._active is None


def test_postcommit_frame_retirement_revocation_keeps_delivered_handle():
    budget = m.RedactionBudget(deadline=time.monotonic() + 30)
    source = m.OwnedPayload.admit('text', budget=budget)
    operation = m.Encoding(source, budget=budget)
    drain(operation)
    events = []
    refs = []

    class Retirement:
        def __del__(self):
            events.append('retirement')
            assert not budget._lock._is_owned()
            assert operation._lease is None and not operation._running
            assert budget._active is None
            assert refs[0]() is not None and not refs[0]()._lease.closed
            budget.close()

    def profile(frame, event, arg):
        if (event == 'return' and frame.f_code is m.Encoding.take.__code__
                and frame.f_locals.get('self') is operation and type(arg) is m.OwnedBytes):
            refs.append(weakref.ref(arg))
            frame.f_locals['_retirement_observer_only'] = Retirement()
            events.append('committed-return')

    sys.setprofile(profile)
    try:
        output = operation.take()
        events.append('caller-receipt')
    finally:
        sys.setprofile(None)
    assert events == ['committed-return', 'retirement', 'caller-receipt']
    assert refs[0]() is output
    assert output._value == b'"text"' and not output._lease.closed
    with pytest.raises(m.Reject, match='invalid'):
        output.value
    output.close()
    source.close()
    reconciled(budget)


def test_terminal_tail_fault_cannot_leave_ghost_active_owner():
    budget = m.RedactionBudget(deadline=time.monotonic() + 30)
    source = m.OwnedPayload.admit('text', budget=budget)
    operation = m.Encoding(source, budget=budget)
    source.close()
    marker = 'pending = self._lease is not None or any(self._pinned)'
    # In-domain allocation: the any(list) call allocates a list iterator even
    # after the actual graph/pin/lease cleanup. Never fault a Boolean store.
    wrapper = __import__('types').FunctionType(m.Encoding.slice.__code__, m.Encoding.slice.__globals__, closure=m.Encoding.slice.__closure__)
    with allocation_fault(wrapper, marker, marker) as fault:
        assert operation.slice() == 'invalid'
    assert fault['fired']
    assert operation._lease is None and operation.gen is None
    assert not operation._running and budget._active is None
    assert source._lease.closed and not any(operation._pinned)
    following = m.OwnedPayload.admit('following', budget=budget)
    following.close()
    reconciled(budget)


def test_provisional_mint_blocks_both_new_claims_and_sibling_growth():
    budget = m.RedactionBudget(deadline=time.monotonic() + 30,
                               metadata_capacity=2 * m.HEADER)
    sibling = budget.reserve()
    original = m._Lease.__init__
    observations = []

    def materialize(lease, *args):
        original(lease, *args)
        before = budget.counters()
        assert before['metadata_bytes'] == before['metadata_peak'] == m.HEADER
        assert before['hold_metadata_bytes'] == m.HEADER
        with pytest.raises(m.Reject, match='capacity'):
            budget.reserve()
        with pytest.raises(m.Reject, match='capacity'):
            sibling.reserve(metadata=1)
        assert budget.counters() == before
        observations.append(before)

    with patch.object(m._Lease, '__init__', new=materialize):
        following = budget.reserve()
    assert len(observations) == 1
    assert budget.counters()['metadata_bytes'] == 2 * m.HEADER
    assert budget.counters()['hold_metadata_bytes'] == 0
    following.close()
    sibling.close()
    reconciled(budget)
