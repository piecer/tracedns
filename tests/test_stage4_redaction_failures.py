"""Persistent independent-review regressions; no service/network operations."""
import sys
import threading
import time
import weakref
from unittest.mock import patch

import pytest
import security.derived_redaction as m
from tests.test_stage4_redaction_plan import build, owners, finish
from tests.test_stage4_redaction_projection import drain


class Collision:
    def __init__(self, target, raises=False):
        self.target = target
        self.raises = raises
        self.calls = []

    def __hash__(self):
        self.calls.append('hash')
        return hash(self.target)

    def __eq__(self, other):
        self.calls.append('eq')
        if self.raises:
            raise RuntimeError('synthetic callback')
        return False


def budget():
    return m.RedactionBudget(deadline=time.monotonic() + 30)


@pytest.mark.parametrize('target', ['config_revision', '_config_revision', '_config_service', '_security_projection_revision'])
@pytest.mark.parametrize('phase', ['first', 'discovery', 'seal', 'take'])
@pytest.mark.parametrize('raises', [False, True])
def test_root_collision_admitted_before_authority(target, phase, raises):
    cfg = {'api_key': 'secret'}
    lock, model = owners(cfg)
    bud = budget()
    b = m.Builder(cfg, lock, model, budget=bud, quantum=1)
    if phase != 'first':
        b.slice()
        if phase in ('seal', 'take'):
            while b.status == 'more':
                b.slice()
        if phase == 'take':
            finish(b)
    key = Collision(target, raises)
    cfg[key] = 0
    key.calls.clear()
    try:
        if phase == 'take':
            assert b.take() is None
        elif phase == 'seal':
            b.seal_slice()
        else:
            b.slice()
        assert key.calls == []
        assert b.status in ('invalid', 'mutation')
        assert bud.counters()['worker_bytes'] == 0
        assert b.take() is None
    finally:
        b.discard()


@pytest.mark.parametrize('raises', [False, True])
def test_reordered_nested_collision_and_resume_are_callback_free(raises):
    key = Collision('api_key', False)
    nested = {key: 0, 'api_key': 'nested-secret', 'tail': 'opaque'}
    del nested[key]
    nested[key] = 0
    key.raises = raises
    cfg = {'nested': nested}
    lock, model = owners(cfg)
    bud = budget()
    b = m.Builder(cfg, lock, model, budget=bud, quantum=1)
    key.calls.clear()
    try:
        finish(b)
        assert key.calls == []
        assert b.status == 'invalid'
        assert b.take() is None
        assert bud.counters()['worker_bytes'] == 0
    finally:
        b.discard()

@pytest.mark.parametrize('phase', ['digest', 'project_buffer', 'encode_buffer', 'encode_bytes', 'second_buffer', 'second_bytes', 'plan_take', 'project_take', 'encode_take'])
def test_allocation_fault_is_permanently_terminal(phase):
    import builtins
    bud = budget()
    b = build({'api_key': ['abcdefghi', 'redacted']}, budget=bud)
    held = []
    if phase == 'digest':
        b.discard()
        cfg = {'api_key': 'abcdefghi'}
        lock, model = owners(cfg)
        x = m.Builder(cfg, lock, model, budget=bud)
        while x.status == 'more':
            x.slice()
        target, attr, original = m.hashlib, 'sha256', m.hashlib.sha256
        invoke = x.seal_slice
    elif phase == 'plan_take':
        x = b
        target, attr, original = m._Owned, '__init__', m._Owned.__init__
        invoke = x.take
    else:
        plan = b.take()
        source = m.OwnedPayload.admit('abcdefghi' * 100, budget=bud)
        held.extend((plan, source))
        if phase.startswith('project'):
            x = m.Projector(plan, source, budget=bud)
        else:
            x = m.Encoding(source, budget=bud, record_json=phase.startswith('second'))
        if phase.endswith('take'):
            drain(x)
            target, attr, original = m._Owned, '__init__', m._Owned.__init__
            invoke = x.take
        else:
            target = m
            attr = 'bytes' if phase.endswith('bytes') else 'bytearray'
            original = getattr(builtins, attr)
            invoke = lambda: drain(x)
    count = 0

    def fail(*args, **kwargs):
        nonlocal count
        count += 1
        if count == (2 if phase.startswith('second') else 1):
            raise MemoryError('synthetic allocation failure')
        return original(*args, **kwargs)

    try:
        with patch.object(target, attr, new=fail, create=True):
            try:
                invoke()
            except MemoryError:
                pass
        assert count > 0
        assert x.status == 'invalid'
        assert x.slice() == 'invalid'
        if isinstance(x, m.Builder):
            assert x.seal_slice() == 'invalid'
        assert x.take() is None
    finally:
        x.discard()
        b.discard()
        for h in held:
            h.close()
    assert bud.counters()['worker_bytes'] == 0



def test_failed_lease_allocation_is_atomic():
    bud = budget()
    before = bud.counters()
    with patch.object(m, '_Lease', side_effect=MemoryError('synthetic allocation failure')):
        with pytest.raises(MemoryError):
            bud.reserve(worker=100)
    assert bud.counters() == before


@pytest.mark.parametrize('phase', ['builder_lease', 'project_lease', 'encode_lease', 'admit_grow', 'admit_mint', 'project_generator', 'encode_generator', 'second_pin'])
def test_constructor_allocation_rollback(phase):
    bud = budget()
    plan = build({'api_key': 'abcdefghi'}, budget=bud).take()
    source = m.OwnedPayload.admit('abcdefghi', budget=bud)
    baseline = bud.counters()['worker_bytes']
    cfg = {'api_key': 'abcdefghi'}
    lock, model = owners(cfg)
    if phase == 'builder_lease':
        invoke = lambda: m.Builder(cfg, lock, model, budget=bud)
    elif phase.startswith('admit'):
        invoke = lambda: m.OwnedPayload.admit('abcdefghi', budget=bud)
    elif phase.startswith('encode'):
        invoke = lambda: m.Encoding(source, budget=bud)
    else:
        invoke = lambda: m.Projector(plan, source, budget=bud)
    target, attr = m, '_Lease'
    if phase == 'admit_grow':
        target, attr = m._Lease, 'reserve'
    elif phase == 'admit_mint':
        target, attr = m._Owned, '__init__'
    elif phase == 'project_generator':
        target, attr = m.Projector, 'project'
    elif phase == 'encode_generator':
        target, attr = m.Encoding, 'run'
    elif phase == 'second_pin':
        target, attr = source, '_pin'
    result = None
    try:
        with patch.object(target, attr, side_effect=MemoryError('synthetic allocation failure')):
            try:
                result = invoke()
            except (MemoryError, m.Reject):
                pass
        if result is not None:
            assert result.status == 'invalid'
        assert bud.counters()['worker_bytes'] == baseline
        assert source._pins == plan._pins == 0
    finally:
        if result is not None:
            result.discard()
        plan.close()
        source.close()
    assert bud.counters()['worker_bytes'] == 0


import unittest


class ReviewRegressions(unittest.TestCase):

    def budget(self):
        return m.RedactionBudget(deadline=time.monotonic() + 30)

    def test_failed_lease_allocation_is_atomic(self):
        b = self.budget()
        before = b.counters()
        with patch.object(m, '_Lease', side_effect=MemoryError('synthetic allocation failure')):
            with self.assertRaises(MemoryError):
                b.reserve(worker=100)
        self.assertEqual(b.counters(), before, 'failed lease creation changed live reservation')

    def test_allocation_fault_cannot_become_successful_none_output(self):
        b = self.budget()
        p = build({'api_key': 'abcdefghi'}, budget=b).take()
        s = m.OwnedPayload.admit('abcdefghi' * 100, budget=b)
        x = m.Projector(p, s, budget=b)
        try:
            with patch.object(m, 'bytearray', create=True, side_effect=MemoryError('synthetic intermediate failure')):
                try:
                    drain(x)
                except MemoryError:
                    pass
            self.assertNotEqual(x.slice(), 'done', 'failed generator resumed as success with None')
        finally:
            x.discard()
            p.close()
            s.close()

    def test_cancelled_builder_drops_source_root(self):

        class Sentinel:
            pass
        obj = Sentinel()
        ref = weakref.ref(obj)
        cfg = {'opaque': obj}
        b = self.budget()
        lock, model = owners(cfg)
        builder = m.Builder(cfg, lock, model, budget=b)
        builder.discard()
        del obj, cfg
        self.assertIsNone(ref(), 'terminal Builder still owns source root')

    def test_old_intermediate_dropped_before_release(self):
        b = self.budget()
        p = build({'api_key': ['abcdefghi', 'redacted']}, budget=b).take()
        s = m.OwnedPayload.admit('abcdefghi' * 100, budget=b)
        x = m.Projector(p, s, budget=b)
        violations = []
        original = m._Lease.release

        def check(lease, **kw):
            caller = sys._getframe(1)
            if caller.f_code.co_name == 'string' and caller.f_locals['text'] is not s._value:
                violations.append(caller.f_locals['text'] is not caller.f_locals['new'])
            original(lease, **kw)
        try:
            with patch.object(m._Lease, 'release', new=check):
                drain(x)
            self.assertFalse(any(violations), 'old allocated intermediate still local at release')
        finally:
            x.discard()
            p.close()
            s.close()

    def test_capacity_cleanup_drops_traceback_intermediate_before_release(self):
        b = self.budget()
        p = build({'api_key': ['abcdefghi', 'redacted']}, budget=b).take()
        s = m.OwnedPayload.admit('abcdefghi' * 100, budget=b)
        x = m.Projector(p, s, budget=b)
        original = m._Lease.close
        reserve = x._lease.reserve
        n = 0
        violations = []

        def fail(**kw):
            nonlocal n
            n += 1
            if n == 4:
                raise m.Reject('capacity')
            reserve(**kw)

        def check(lease):
            f = sys._getframe(1)
            while f:
                if f.f_code.co_name == 'slice' and 'exc' in f.f_locals:
                    tb = f.f_locals['exc'].__traceback__
                    while tb:
                        if tb.tb_frame.f_code.co_name == 'string':
                            text = tb.tb_frame.f_locals.get('text')
                            violations.append(type(text) is str and text is not s._value)
                        tb = tb.tb_next
                    break
                f = f.f_back
            original(lease)
        try:
            with patch.object(m._Lease, 'close', new=check), patch.object(x._lease, 'reserve', new=fail):
                drain(x)
            self.assertFalse(any(violations), 'exception traceback keeps allocated intermediate at lease release')
        finally:
            x.discard()
            p.close()
            s.close()


@pytest.mark.parametrize('phase', ['created', 'running', 'captured', 'done', 'taken', 'capacity', 'deadline', 'fault'])
def test_terminal_builder_releases_borrowed_roots(phase):
    class Sentinel:
        pass
    obj = Sentinel()
    obj.payload = bytearray(1000000)
    ref = weakref.ref(obj)
    cfg = {'opaque': obj, 'api_key': 'secret'}
    lock, model = owners(cfg)
    model_ref = weakref.ref(model)
    bud = budget()
    b = m.Builder(cfg, lock, model, budget=bud, quantum=1)
    handle = None
    if phase == 'running':
        b.slice()
    elif phase in ('captured', 'done', 'taken'):
        while b.status == 'more':
            b.slice()
        if phase in ('done', 'taken'):
            finish(b)
        if phase == 'taken':
            handle = b.take()
    elif phase == 'capacity':
        bud.visit(m.VISITS)
        b.slice()
    elif phase == 'deadline':
        with patch.object(m.time, 'monotonic', return_value=bud.deadline):
            b.slice()
    elif phase == 'fault':
        with patch.object(m, 'bytearray', create=True, side_effect=MemoryError):
            b.slice()
    if phase in ('created', 'running', 'captured', 'done'):
        b.discard()
    del cfg, obj, lock, model
    try:
        assert ref() is None
        assert model_ref() is None
        assert b.config is b.model is b.lock is None
        if handle:
            assert handle.value.replacements
            assert bud.counters()['worker_bytes'] > 0
        else:
            assert bud.counters()['worker_bytes'] == 0
    finally:
        b.discard()
        if handle:
            handle.close()


@pytest.mark.parametrize('phase', ['discovery', 'seal', 'builder_take', 'project_slice', 'project_take', 'encode_slice', 'encode_take'])
@pytest.mark.parametrize('action', ['discard', 'reentry', 'budget_close', 'input_close'])
def test_active_owner_quiescence(phase, action):
    import inspect
    if action == 'input_close' and phase in ('discovery', 'seal', 'builder_take'):
        pytest.skip('Builder has no input handle')
    bud = budget()
    cfg = {'api_key': 'abcdefghi'}
    lock, model = owners(cfg)
    b = m.Builder(cfg, lock, model, budget=bud)
    held = []
    if phase in ('discovery', 'seal', 'builder_take'):
        if action == 'input_close':
            pytest.skip('Builder has no input handle')
        x = b
        if phase != 'discovery':
            while b.status == 'more':
                b.slice()
        if phase == 'builder_take':
            finish(b)
        method = b.slice if phase == 'discovery' else b.seal_slice if phase == 'seal' else b.take
        target = m.Builder.walk_locked if phase == 'discovery' else m.Builder.prepare if phase == 'seal' else m.Builder.take
        marker = 'kind = type(value)' if phase == 'discovery' else 'digest = hashlib.sha256()' if phase == 'seal' else 'handle = OwnedPlan('
    else:
        finish(b)
        plan = b.take()
        source = m.OwnedPayload.admit('abcdefghi' * 1000, budget=bud)
        held.extend((plan, source))
        x = m.Projector(plan, source, budget=bud) if phase.startswith('project') else m.Encoding(source, budget=bud)
        if phase.endswith('take'):
            drain(x)
            method, target, marker = x.take, m._Operation.take, 'handle = self._output_type('
        else:
            method = x.slice
            target = m.Projector.string if phase.startswith('project') else m.Encoding.assemble
            marker = 'out = bytearray('
    lines, start = inspect.getsourcelines(inspect.unwrap(target))
    lineno = start + next(i for i, line in enumerate(lines) if marker in line)
    entered, resume = threading.Event(), threading.Event()
    errors, results = [], []

    def trace(frame, event, arg):
        if event == 'line' and frame.f_code.co_filename == m.__file__ and frame.f_lineno == lineno:
            entered.set()
            assert resume.wait(3), 'barrier timeout'
        return trace

    def work():
        sys.settrace(trace)
        try:
            # Discovery of the projector's buffer can require multiple slices.
            for _ in range(10000):
                result = method()
                if entered.is_set() or x.status not in ('more', 'captured'):
                    results.append(result)
                    break
        except BaseException as exc:
            errors.append(type(exc).__name__)
        finally:
            sys.settrace(None)

    thread = threading.Thread(target=work)
    thread.start()
    try:
        assert entered.wait(3), 'work did not reach real execution barrier'
        before = bud.counters()['worker_bytes']
        state = x.status
        if action == 'discard':
            x.discard()
            x.discard()
        elif action == 'reentry':
            got = method()
            assert got is None if phase.endswith('take') else got == 'lock_busy'
            assert x.status == state
        elif action == 'budget_close':
            bud.close()
        else:
            source.close()
        assert bud.counters()['worker_bytes'] == before
        assert bud.counters()['active']
    finally:
        resume.set()
        thread.join(3)
    try:
        assert not thread.is_alive()
        assert not errors
        if action == 'reentry':
            if isinstance(x, m.Builder):
                finish(x)
            else:
                drain(x)
            handle = results[0] if results and isinstance(results[0], m._Owned) else x.take()
            assert handle is not None
            handle.close()
        else:
            # Active owner must acknowledge without requiring a second discard.
            assert x.status in ('stopped', 'invalid')
            assert x.take() is None
            assert x._lease is None
            if isinstance(x, m.Builder):
                assert x.config is x.model is x.lock is None
            else:
                assert x.gen is None
                assert not any(x._pinned)
    finally:
        x.discard()
        b.discard()
        for h in held:
            h.close()
    assert bud.counters()['worker_bytes'] == 0


@pytest.mark.parametrize('fault_kind', ['capacity', 'memory'])
def test_each_growing_reservation_failure_cleans_the_composition(fault_kind):
    def attempt(fail_at=None):
        bud = budget()
        held = []
        count = 0
        original = m._Lease.reserve

        def reserve(lease, **kwargs):
            nonlocal count
            count += 1
            if count == fail_at:
                if fault_kind == 'memory':
                    raise MemoryError('synthetic growing allocation')
                raise m.Reject('capacity')
            return original(lease, **kwargs)

        with patch.object(m._Lease, 'reserve', new=reserve):
            try:
                b = build({'api_key': ['abcdefghi', 'redacted']}, budget=bud)
                held.append(b)
                if b.status == 'done':
                    plan = b.take()
                    held.append(plan)
                    source = m.OwnedPayload.admit({'abcdefghi': ['abcdefghi' * 16]}, budget=bud)
                    held.append(source)
                    x = m.Projector(plan, source, budget=bud)
                    held.append(x)
                    drain(x)
                    if x.status == 'done':
                        projected = x.take()
                        held.append(projected)
                        enc = m.Encoding(projected, budget=bud, record_json=True)
                        held.append(enc)
                        drain(enc)
                        if enc.status == 'done':
                            held.append(enc.take())
            except m.Reject as exc:
                assert exc.args[0] == ('invalid' if fault_kind == 'memory' else 'capacity')
            finally:
                for obj in reversed(held):
                    if isinstance(obj, m._Owned):
                        obj.close()
                    else:
                        obj.discard()
        assert bud.counters()['worker_bytes'] == bud.counters()['metadata_bytes'] == 0
        return count

    count = attempt()
    assert count >= 26
    for position in range(1, count + 1):
        assert attempt(position) == position


@pytest.mark.parametrize('phase,method,marker', [
    ('discover', 'own_key', 'data = bytearray()'),
    ('discover', 'own_key', "return data.decode('utf8')"),
    ('discover', 'finish_secret', "text = data.decode('utf8')"),
    ('seal', 'prepare', 'rows = []'),
    ('seal', 'prepare', 'for secret in sorted('),
    ('seal', 'prepare', 'digest = hashlib.sha256()'),
    ('seal', 'prepare', 'data = secret['),
    ('seal', 'prepare', 'rows.append('),
    ('seal', 'prepare', 'return tuple(rows)'),
    ('seal', 'seal_slice', 'self.plan = Plan('),
    ('project', 'project', 'out = {}'),
    ('project', 'project', 'out = []'),
    ('project', 'string', "new = out.decode('utf8')"),
    ('encode', 'emit', 'yield json.dumps(value[i:'),
    ('encode', 'run', "result = yield from self.assemble(inner.decode('utf8'))"),
])
def test_allocation_at_internal_materialization_is_terminal(phase, method, marker):
    import inspect
    bud = budget()
    cfg = {'api_key': 'abcdefghi'}
    lock, model = owners(cfg)
    x = m.Builder(cfg, lock, model, budget=bud)
    held = []
    if phase != 'discover':
        while x.status == 'more':
            x.slice()
    if phase in ('project', 'encode'):
        finish(x)
        plan = x.take()
        source = m.OwnedPayload.admit({'k': ['abcdefghi' * 50]}, budget=bud)
        held.extend((plan, source))
        x = m.Projector(plan, source, budget=bud) if phase == 'project' else m.Encoding(source, budget=bud, record_json=True)
    target = getattr(type(x), method)
    lines, start = inspect.getsourcelines(inspect.unwrap(target))
    lineno = start + next(i for i, line in enumerate(lines) if marker in line)
    fired = False

    def trace(frame, event, arg):
        nonlocal fired
        if event == 'line' and frame.f_code.co_filename == m.__file__ and frame.f_lineno == lineno:
            fired = True
            raise MemoryError('synthetic materialization failure')
        return trace

    try:
        sys.settrace(trace)
        if isinstance(x, m.Builder):
            finish(x)
        else:
            drain(x)
    finally:
        sys.settrace(None)
    try:
        assert fired
        assert x.status == 'invalid'
        assert x.take() is None
        assert x._lease is None
    finally:
        x.discard()
        for h in held:
            h.close()
    assert bud.counters()['worker_bytes'] == 0


@pytest.mark.parametrize('operation', ['builder', 'projector', 'encoding'])
def test_same_thread_reentry_preserves_active_holder(operation):
    bud = budget()
    cfg = {'api_key': 'abcdefghi'}
    lock, model = owners(cfg)
    b = m.Builder(cfg, lock, model, budget=bud)
    held = []
    if operation == 'builder':
        x = b
        target, attr = b, 'walk_locked'
    else:
        finish(b)
        p = b.take()
        s = m.OwnedPayload.admit('abcdefghi' * 100, budget=bud)
        held.extend((p, s))
        x = m.Projector(p, s, budget=bud) if operation == 'projector' else m.Encoding(s, budget=bud)
        target, attr = x, '_check_dependencies'
    original = getattr(target, attr)
    calls = []

    def reenter():
        before = bud.counters()['worker_bytes']
        state = x.status
        calls.append(x.slice())
        assert calls[-1] == 'lock_busy'
        assert x.status == state
        assert bud.counters()['worker_bytes'] == before
        return original()

    try:
        with patch.object(target, attr, new=reenter):
            x.slice()
        assert calls
        if operation == 'builder':
            finish(x)
        else:
            drain(x)
        out = x.take()
        assert out is not None
        out.close()
    finally:
        x.discard()
        b.discard()
        for h in held:
            h.close()
    assert bud.counters()['worker_bytes'] == 0


def test_last_reference_is_gone_when_sibling_can_reserve():
    bud = budget()
    p = build({'api_key': ['abcdefghi', 'redacted']}, budget=bud).take()
    s = m.OwnedPayload.admit('abcdefghi' * 100, budget=bud)
    x = m.Projector(p, s, budget=bud)
    original = m._Lease.release
    observations = []

    def release(lease, **kwargs):
        frame = sys._getframe(1)
        if frame.f_code.co_name == 'string':
            assert frame.f_locals['text'] is frame.f_locals['new']
            assert 'out' not in frame.f_locals
            assert frame.f_locals.get('chunk') is None
            original(lease, **kwargs)
            sibling = bud.reserve(worker=kwargs.get('worker', 0))
            observations.append(sibling.worker)
            sibling.close()
        else:
            original(lease, **kwargs)

    try:
        with patch.object(m._Lease, 'release', new=release):
            drain(x)
        assert len(observations) == 2
        assert x.status == 'done'
    finally:
        x.discard()
        s.close()
        p.close()
    assert bud.counters()['worker_bytes'] == 0


@pytest.mark.parametrize('marker', ["if self.budget._closed or any(", 'self.max_slice_s = max('])
def test_operation_bookkeeping_allocation_failure_is_terminal(marker):
    bud = budget()
    source = m.OwnedPayload.admit('text', budget=bud)
    x = m.Encoding(source, budget=bud)
    lines = __import__('pathlib').Path(m.__file__).read_text().splitlines()
    if marker == 'if self.budget._closed or any(':
        assert not any(marker in line for line in lines)
        marker = 'elif time.monotonic() >= b._deadline:'
    matches = {i + 1 for i, line in enumerate(lines) if marker in line}
    assert matches
    fired = False

    def trace(frame, event, arg):
        nonlocal fired
        if event == 'line' and frame.f_code.co_filename == m.__file__ and frame.f_lineno in matches:
            fired = True
            raise MemoryError('synthetic bookkeeping allocation')
        return trace

    try:
        sys.settrace(trace)
        try:
            x.slice()
        except MemoryError:
            pass
        finally:
            sys.settrace(None)
        assert fired
        assert x.status == 'invalid'
        assert x._lease is None
        assert not x._running
        assert source._pins == 0
        assert x.take() is None
    finally:
        x.discard()
        source.close()
    assert bud.counters()['worker_bytes'] == 0
