"""Single allocating-fault cleanup regressions; no malformed ledger doubles."""
import inspect
import os
import sys
import threading
import time
from contextlib import contextmanager

import pytest

import security.derived_redaction as m
from tests.test_stage4_redaction_plan import finish, owners
from tests.test_stage4_redaction_projection import drain


FAULT_RECEIPTS = []


@contextmanager
def allocation_fault(method, old, new, predicate=lambda frame: True):
    """Rebind an allocating RHS, never its nonallocating publication store."""
    lines, start = inspect.getsourcelines(inspect.unwrap(method))
    matches = [start + i for i, line in enumerate(lines)
               if old in line or new in line]
    assert len(matches) == 1, (old, new, matches)
    state = {'fired': False, 'line': matches[0]}

    def trace(frame, event, arg):
        if (event == 'line' and frame.f_code.co_filename == m.__file__
                and frame.f_lineno == state['line'] and predicate(frame)):
            state['fired'] = True
            raise MemoryError('one-shot allocating RHS')
        return trace

    sys.settrace(trace)
    try:
        yield state
    finally:
        sys.settrace(None)
        FAULT_RECEIPTS.append({**state, 'nodeid': os.environ.get('PYTEST_CURRENT_TEST'),
                               'method': method.__qualname__, 'old': old, 'new': new,
                               'source': m.__file__})
        assert state['fired'], state


def budget(**kwargs):
    return m.RedactionBudget(deadline=time.monotonic() + 30, **kwargs)


def reconciled(b, *leases):
    counts = b.counters()
    assert counts['worker_bytes'] == sum(lease.worker for lease in leases)
    assert counts['metadata_bytes'] == sum(lease.metadata for lease in leases)
    assert 0 <= counts['worker_bytes'] <= counts['worker_peak'] <= b.worker_capacity
    assert 0 <= counts['metadata_bytes'] <= counts['metadata_peak'] <= b.metadata_capacity


@pytest.mark.parametrize('method,old,new', [
    ('release', 'self.metadata -= metadata', 'new_metadata = self.metadata - metadata'),
    ('release', 'self.budget._worker -= worker', 'budget_worker = self.budget._worker - worker'),
    ('release', 'self.budget._metadata -= metadata', 'budget_metadata = self.budget._metadata - metadata'),
    ('close', 'self.budget._metadata -= self.metadata', 'budget_metadata = self.budget._metadata - self.metadata'),
])
def test_allocating_release_close_publishes_nothing_on_failure(method, old, new):
    b = budget(worker_capacity=200000 + 2 * (m.HEADER - 256), metadata_capacity=50000 + 2 * (m.HEADER - 256))
    a = b.reserve(worker=100000, metadata=12000)
    sibling = b.reserve(worker=50000, metadata=10000)
    before = b.counters()
    try:
        with allocation_fault(getattr(m._Lease, method), old, new):
            with pytest.raises(MemoryError):
                if method == 'release':
                    a.release(worker=10000, metadata=1000)
                else:
                    a.close()
        assert b.counters() == before
        reconciled(b, a, sibling)
        a.close()
        a.close()
        reconciled(b, sibling)
        with pytest.raises(m.Reject, match='capacity'):
            b.reserve(worker=b.worker_capacity - m.HEADER)
        reconciled(b, sibling)
        assert b.counters()['worker_peak'] == before['worker_peak']
    finally:
        a.close()
        sibling.close()
    reconciled(b)


def make(phase):
    b = budget()
    cfg = {'api_key': ['abcdefghi', 'redacted']}
    lock, model = owners(cfg)
    x = m.Builder(cfg, lock, model, budget=b)
    held = []
    if phase != 'discover':
        while x.status == 'more':
            x.slice()
    if phase not in ('discover', 'seal'):
        finish(x)
    if phase in ('project', 'encode', 'project_take', 'encode_take'):
        plan = x.take()
        payload = m.OwnedPayload.admit('abcdefghi' * 200, budget=b)
        held = [plan, payload]
        x = (m.Projector(plan, payload, budget=b) if phase.startswith('project')
             else m.Encoding(payload, budget=b, record_json=True))
        if phase.endswith('take'):
            drain(x)
    method = (x.seal_slice if phase == 'seal'
              else x.take if phase.endswith('take') else x.slice)
    return b, x, held, method


def cleanup(x, held):
    x.discard()
    for handle in held:
        handle.close()


@pytest.mark.parametrize('kind', ['project', 'encode'])
def test_actual_intermediate_release_fault_reconciles_live_sibling(kind):
    b, x, held, method = make(kind)
    sibling = b.reserve(worker=50000, metadata=10000)
    lease = x._lease
    try:
        with allocation_fault(m._Lease.release, 'self.budget._worker -= worker',
                              'budget_worker = self.budget._worker - worker',
                              lambda frame: frame.f_locals['self'] is lease):
            drain(x)
        assert x.status == x.slice() == 'invalid'
        assert x.take() is None
        reconciled(b, sibling, *(h._lease for h in held))
        assert not b.counters()['active'] and not x._running
    finally:
        cleanup(x, held)
        sibling.close()
    reconciled(b)


@pytest.mark.parametrize('phase', ['seal', 'builder_take', 'project', 'encode'])
@pytest.mark.parametrize('counter', ['worker', 'metadata'])
def test_cleanup_fault_releases_active_only_after_quiescence(phase, counter):
    b, x, held, method = make(phase)
    lease = x._lease
    # Real finite refusal, not replaced ledger arithmetic or synthetic integers.
    if isinstance(x, m.Builder):
        b.visit(m.VISITS - b.visits)
        sibling = b.reserve(worker=50000, metadata=10000)
    else:
        sibling = b.reserve(worker=b.worker_capacity - b.counters()['worker_bytes'] - m.HEADER)
    try:
        with allocation_fault(m._Lease.close, f'self.budget._{counter} -= self.{counter}',
                              f'budget_{counter} = self.budget._{counter} - self.{counter}',
                              lambda frame: frame.f_locals['self'] is lease):
            method()
        assert x.status == 'invalid'
        assert x.take() is None and not x._running
        assert not b.counters()['active']
        assert x._lease is None
        if isinstance(x, m.Builder):
            assert x.config is x.model is x.lock is None
        else:
            assert x.gen is None and x.result is None and not any(x._pinned)
        reconciled(b, sibling, *(h._lease for h in held))
    finally:
        cleanup(x, held)
        sibling.close()
    reconciled(b)
    admitted = m.OwnedPayload.admit('independent sibling', budget=b)
    admitted.close()
    reconciled(b)


@pytest.mark.parametrize('phase', ['project', 'encode', 'project_take', 'encode_take'])
def test_pin_cleanup_fault_preserves_reachable_transfer(phase):
    """Audit the sibling unpin/take paths with real overlapping input closure."""
    b, x, held, method = make(phase)
    lease = x._lease
    payload = held[1]
    entered, resume = threading.Event(), threading.Event()
    errors, results = [], []
    if phase.endswith('take'):
        fn, marker = m._Operation.take, 'self._clear(False)'
    else:
        fn, marker = m._Operation.slice, 'self._check_dependencies()'
    lines, start = inspect.getsourcelines(inspect.unwrap(fn))
    barriers = [start + i for i, line in enumerate(lines) if marker in line]
    assert len(barriers) == 1
    lines, start = inspect.getsourcelines(m._SerialOwner._retire)
    faults = [start + i for i, line in enumerate(lines)
              if 'budget_worker = b._worker - lease.worker' in line]
    assert len(faults) == 1
    fired = []

    def trace(frame, event, arg):
        if event == 'line' and frame.f_code.co_filename == m.__file__:
            if frame.f_lineno == barriers[0] and not entered.is_set():
                entered.set()
                if not resume.wait(4):
                    raise RuntimeError('owned barrier timeout')
            if frame.f_lineno == faults[0] and frame.f_locals['handle'] is payload:
                fired.append(True)
                raise MemoryError('one cleanup subtraction after overlapping close')
        return trace

    def run():
        sys.settrace(trace)
        try:
            results.append(method())
        except BaseException as exc:
            errors.append(type(exc).__name__)
            exc.__traceback__ = exc.__context__ = exc.__cause__ = None
        finally:
            sys.settrace(None)

    worker = threading.Thread(target=run)
    worker.start()
    try:
        assert entered.wait(4)
        before = b.counters()
        payload.close()
        assert payload._pins == 1 and not payload._lease.closed
        assert b.counters() == before and x._running and before['active']
        with pytest.raises(m.Reject, match='lock_busy'):
            m.OwnedPayload.admit('sibling cannot overlap live work', budget=b)
        assert method() is None if phase.endswith('take') else method() == 'lock_busy'
    finally:
        resume.set()
        worker.join(4)
    # Deliberately no rescue via private lease.close: it would hide lost ownership.
    assert not worker.is_alive() and fired == [True]
    assert not errors, {'errors': errors, 'counts': b.counters(),
                        'pins': payload._pins, 'output_lease_reachable': x._lease is lease}
    assert x.status == 'invalid' and x.take() is None and not x._running
    assert not b.counters()['active']
    cleanup(x, held)
    reconciled(b)


def test_admission_cleanup_fault_keeps_no_unreachable_reservation():
    b = budget()
    sibling = b.reserve(worker=50000, metadata=10000)
    with allocation_fault(m._Lease.close, 'self.budget._worker -= self.worker',
                          'budget_worker = self.budget._worker - self.worker',
                          lambda frame: frame.f_locals['self'] is not sibling):
        with pytest.raises((m.Reject, MemoryError)):
            m.OwnedPayload.admit(object(), budget=b)
    reconciled(b, sibling)
    assert not b.counters()['active']
    sibling.close()
    reconciled(b)
