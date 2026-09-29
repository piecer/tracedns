"""Owned bounded redaction: real owners, exact legacy ordering and lifetime."""
import importlib
import importlib.util
import ast
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from monitor.config_service import get_config_service
from monitor.stores import ConfigStore
from monitor.scheduler import MonitorScheduler
from monitor.signal_stop import SignalStopBridge
from tests.test_stage4_projection_authority import attached
from tests.test_stage2_force import admit
import threading
import time
import tracemalloc
from unittest.mock import patch

from http_api.read_model import BackgroundReadModel
from security.redaction import sanitize


def api():
    assert importlib.util.find_spec('security.derived_redaction') is not None, 'bounded foundation missing'
    return importlib.import_module('security.derived_redaction')


def owners(cfg):
    return threading.RLock(), BackgroundReadModel(lambda previous: None, lambda value: {})


def finish(builder):
    for _ in range(40000):
        if builder.slice() != 'more':
            break
    else:
        raise AssertionError('unbounded discovery')
    if builder.status == 'captured':
        for _ in range(40000):
            if builder.seal_slice() != 'more':
                break
        else:
            raise AssertionError('unbounded seal')
    return builder


def test_actual_config_secret_to_owned_plan():
    m = api()
    cfg = {'api_key': 'actual-secret'}
    lock, model = owners(cfg)
    budget = m.RedactionBudget(deadline=time.monotonic() + 5)
    builder = m.Builder(cfg, lock, model, budget=budget)
    assert finish(builder).status == 'done'
    handle = builder.take()
    assert type(handle) is m.OwnedPlan
    assert handle.value.replacements == (('actual-secret', sanitize('actual-secret', cfg)),)
    assert handle.value.authority == (0, 0, id(model), 0)
    assert builder.take() is None
    held = budget.counters()['worker_bytes']
    assert held > 0
    builder.discard()
    assert budget.counters()['worker_bytes'] == held
    handle.close()
    handle.close()
    assert budget.counters()['worker_bytes'] == 0
    assert budget.counters()['metadata_bytes'] == 0


def build(cfg, *, quantum=512, lock=None, model=None, budget=None):
    m = api()
    if lock is None:
        lock, model = owners(cfg)
    if budget is None:
        budget = m.RedactionBudget(deadline=time.monotonic() + 5)
    return finish(m.Builder(cfg, lock, model, budget=budget, quantum=quantum))


def seal(builder):
    for _ in range(40000):
        if builder.seal_slice() != 'more':
            return builder.status
    raise AssertionError('unbounded seal')


@pytest.mark.parametrize('writer', ['service', 'stopped', 'signal', 'same_size_order', 'same_keys_reorder', 'same_size_opaque'])
@pytest.mark.parametrize('phase', ['between_slices', 'before_seal', 'before_take'])
def test_root_structure_barriers(writer, phase):
    m = api()
    cfg = {'api_key': ['abcd', 'bcde'], '_opaque_a': object(), '_opaque_b': object()}
    lock, model = owners(cfg)
    store = ConfigStore(cfg, lock)
    ctx = SimpleNamespace(shared_config=cfg, config_lock=lock, config_path='', read_model=model)
    budget = m.RedactionBudget(deadline=time.monotonic() + 5)
    b = m.Builder(cfg, lock, model, budget=budget, quantum=1)
    assert b.slice() == 'more'
    if phase != 'between_slices':
        while b.slice() == 'more':
            pass
        assert b.status == 'captured'
    if phase == 'before_take':
        assert seal(b) == 'done'
    token = b.token
    if writer == 'service':
        get_config_service(ctx)
    elif writer == 'stopped':
        MonitorScheduler(store).stop()
    elif writer == 'signal':
        bridge = SignalStopBridge(lambda: None)
        source = Path(sys.modules['monitor.stores'].__file__).parents[1] / 'dns_monitor.py'
        tree = ast.parse(source.read_text())
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.With) and any(
            isinstance(a, ast.Assign) and isinstance(a.targets[0], ast.Subscript)
            and isinstance(a.targets[0].slice, ast.Constant)
            and a.targets[0].slice.value == '_signal_stop' for a in n.body))
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), 'exec'),
             {'shared_config': cfg, 'config_lock': lock, 'signal_stop': bridge})
    elif writer == 'same_keys_reorder':
        with lock:
            value = cfg.pop('_opaque_a')
            cfg['_opaque_a'] = value
    elif writer == 'same_size_order':
        with lock:
            del cfg['_opaque_a']
            cfg['_opaque_c'] = object()
    else:
        with lock:
            cfg['_opaque_a'] = object()
    assert b.authority() == token
    finish(b)
    result = b.take()
    if writer == 'same_size_opaque':
        assert result is not None
        assert {s for s, _ in result.value.replacements} == {'abcd', 'bcde'}
        result.close()
    else:
        assert b.status == 'mutation'
        assert b.take() is None and not b.frames and b.catalog is None
        assert budget.counters()['worker_bytes'] == budget.counters()['metadata_bytes'] == 0
    fresh = build(cfg, lock=lock, model=model)
    assert fresh.status == 'done'
    plan = fresh.take()
    assert {s for s, _ in plan.value.replacements} == {'abcd', 'bcde'}
    plan.close()


@pytest.mark.parametrize('phase', ['between_slices', 'before_seal', 'before_take'])
def test_actual_rotation_dequeue_barrier(tmp_path, phase):
    m = api()
    domain = {'name': 'x.eth', 'type': 'ENS'}
    ctx, service, store = attached(tmp_path, domains=[domain], servers=[], ens_rpc_url='synthetic-old-endpoint')
    cfg = ctx.shared_config
    assert admit(ctx, {'domains': [domain]}).status == 200
    job = cfg['_force_resolve_queue'][0]
    service.commit('config', {'ens_rpc_url': 'synthetic-new-endpoint'}, expected_revision=0)
    assert job['ens_rpc_url'] == 'synthetic-old-endpoint'
    prior = build(cfg, lock=ctx.config_lock, model=ctx.read_model).take()
    assert 'synthetic-old-endpoint' in dict(prior.value.replacements)
    prior.close()
    budget = m.RedactionBudget(deadline=time.monotonic() + 5)
    b = m.Builder(cfg, ctx.config_lock, ctx.read_model, budget=budget, quantum=2)
    assert b.slice() == 'more'
    if phase != 'between_slices':
        while b.slice() == 'more':
            pass
        assert b.status == 'captured'
    if phase == 'before_take':
        assert seal(b) == 'done'
    old = (cfg['_config_revision'], cfg['_security_projection_revision'], ctx.read_model._epoch)
    assert store.dequeue_force() is job
    new = (cfg['_config_revision'], cfg['_security_projection_revision'], ctx.read_model._epoch)
    assert old[0] == new[0] and new[1] == old[1] + 1 and new[2] == old[2] + 1
    if phase == 'between_slices':
        assert b.slice() == 'mutation'
    elif phase == 'before_seal':
        assert seal(b) == 'mutation'
    else:
        assert b.take() is None and b.status == 'mutation'
    assert not b.frames and b.catalog is None and b.pending is None
    assert budget.counters()['worker_bytes'] == 0
    fresh = build(cfg, lock=ctx.config_lock, model=ctx.read_model).take()
    assert 'synthetic-old-endpoint' not in dict(fresh.value.replacements)
    fresh.close()


R = {'boundaries': {}, 'mutations': []}


def Builder(cfg, lock, model, **kwargs):
    m = api()
    budget = kwargs.pop('budget', None)
    if budget is None:
        budget = m.RedactionBudget(deadline=time.monotonic() + 5)
    return m.Builder(cfg, lock, model, budget=budget, **kwargs)


class TrapDict(dict):
    def items(self):
        raise AssertionError('callback')

    def __iter__(self):
        raise AssertionError('callback')


class TrapStr(str):
    def __hash__(self):
        raise AssertionError('callback')

    def encode(self, *args, **kwargs):
        raise AssertionError('callback')



@pytest.mark.parametrize('n,expected',[(256,'done'),(257,'capacity')])
def test_secret_count(n,expected):
    b=build({'api_key':[f'secret-{i:03}' for i in range(n)]})
    assert b.status==expected,b.counters()
    R['boundaries'][f'secrets_{n}']=b.counters()


@pytest.mark.parametrize('n,expected',[(65536,'done'),(65537,'capacity')])
def test_secret_bytes(n,expected):
    b=build({'api_key':'é'*(n//2)+('a' if n%2 else '')})
    assert b.status==expected,b.counters()
    R['boundaries'][f'secret_utf8_{n}']=b.counters()


@pytest.mark.parametrize('depth,expected',[(32,'done'),(33,'capacity')])
def test_depth(depth,expected):
    cfg=0
    for _ in range(depth-1): cfg=[cfg]
    b=build({'ordinary':cfg})
    assert b.status==expected,b.counters()
    R['boundaries'][f'depth_{depth}']=b.counters()


@pytest.mark.parametrize('kind',['giant_secret','giant_plain','giant_key','giant_container','custom_dict','custom_str','cycle','surrogate'])
def test_invalid_giant_and_opaque(kind):
    cycle=[]; cycle.append(cycle)
    fixtures={'giant_secret':({'api_key':'a'*2000000},'capacity'),
      'giant_plain':({'ordinary':'a'*2000000},'done'),
      'giant_key':({'x'*2000000:0},'capacity'),
      'giant_container':({'ordinary':[0]*2000000},'capacity'),
      'custom_dict':({'ordinary':TrapDict()},'invalid'),
      'custom_str':({'api_key':TrapStr('secret')},'invalid'),
      'cycle':({'ordinary':cycle},'invalid'),
      'surrogate':({'api_key':'\ud800'},'invalid')}
    cfg,expected=fixtures[kind]
    b=build(cfg); assert b.status==expected,b.counters()
    assert b.visits<=api().VISITS and b.metadata_peak<=api().METADATA
    if kind in ('giant_secret','giant_key'): assert b.hash_bytes==0
    R['boundaries'][kind]=b.counters()


def test_1101_recovered_shape():
    cfg={'domains':[{'name':f'd{i}.test','type':'TXT'} for i in range(1100)]+[{'name':'small.test','type':'A'}]}
    start = time.monotonic()
    b = build(cfg)
    elapsed = time.monotonic() - start
    assert b.status == 'done', b.counters()
    assert b.visits <= api().VISITS and b.metadata_peak <= api().METADATA
    # Allocation tracing is a distinct sample, not a latency/RSS claim. Fixed
    # clock isolates tracer overhead from the cooperative real-clock slice gate.
    with patch('security.derived_redaction.time.monotonic', new=lambda: 0):
        tracemalloc.start()
        allocation = build(cfg)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        assert allocation.status == 'done', allocation.counters()
    allocation.discard()
    R['recovered_1101'] = {**b.counters(), 'elapsed_s': elapsed,
                           'tracemalloc_peak_fixed_clock': peak}
    b.discard()


def test_source_reference_release_and_shutdown():
    nested={'api_key':['abcde']}; cfg={'nested':nested}; lock,model=owners(cfg)
    b=Builder(cfg,lock,model,quantum=2); b.slice()
    # No retained iterator / nested mutable identity is stored on builder.
    assert all(v is not nested for v in vars(b).values())
    assert all(type(f) is tuple and type(f[0]) is tuple for f in b.frames)
    model._stopped=True
    assert b.slice()=='stopped' and not b.frames and b.catalog is None
    assert b.take() is None


def test_config_lock_busy_is_finite():
    cfg={'api_key':'abcd'}; lock=threading.Lock(); _,model=owners(cfg)
    b=Builder(cfg,lock,model); lock.acquire(); start=time.monotonic()
    try: assert b.slice()=='lock_busy'
    finally: lock.release()
    elapsed=time.monotonic()-start
    assert elapsed<.2
    R['lock_busy']={'elapsed_s':elapsed,'acquisition_cap_s':.02}


@pytest.mark.parametrize('writer',['enqueue','rotation','legacy_pop','model_rebind'])
def test_other_actual_owner_barriers(tmp_path,writer):
    domain={'name':'x.eth','type':'ENS'}
    ctx,service,store=attached(tmp_path,domains=[domain],servers=[],ens_rpc_url='old-provider')
    cfg=ctx.shared_config
    if writer=='legacy_pop': cfg['_force_resolve']={'ens_rpc_url':'legacy-provider'}
    b=Builder(cfg,ctx.config_lock,ctx.read_model,quantum=1)
    assert b.slice()=='more'
    if writer=='enqueue': assert admit(ctx,{'domains':[domain]}).status==200
    elif writer=='rotation': service.commit('config',{'ens_rpc_url':'new-provider'},expected_revision=0)
    elif writer=='legacy_pop': assert store.dequeue_force()['ens_rpc_url']=='legacy-provider'
    else:
        ctx.read_model=BackgroundReadModel(lambda previous:None,lambda value:{})
        get_config_service(ctx)
    assert b.slice()=='mutation'
    assert b.take() is None and not b.frames
    R['mutations'].append({'writer':writer,'status':b.status})


def test_graph_visit_exact_plus_one():
    # Deterministic fixed 14-step boundary search, not an open-ended mechanism
    # experiment: disable elapsed slicing ONLY for the counter-boundary test.
    def attempt(n):
        # Include an ignored scalar root so this real traversal's work lattice
        # reaches the exact inclusive cap after every copy/DFS iteration is
        # charged. The predecessor's single-root shape stops at 16383.
        b=build({'ordinary':[0]*n, 'ignored': None})
        if b.status=='done': b.take()
        return b
    with patch('security.derived_redaction.time.monotonic',return_value=0):
        low,high=0,16384
        for _ in range(14):
            mid=(low+high+1)//2
            if attempt(mid).status=='taken': low=mid
            else: high=mid-1
        exact=attempt(low); plus=attempt(low+1)
    assert exact.status=='taken' and exact.visits==16384,exact.counters()
    assert plus.status=='capacity' and plus.visits<=16384,plus.counters()
    R['boundaries']['whole_graph_visits']={'scalar_count':low,'exact':exact.counters(),'one_more_scalar':plus.counters()}


def test_visit_and_metadata_exact_plus_one():
    m = api()
    budget = m.RedactionBudget(deadline=time.monotonic() + 5)
    budget.visit(m.VISITS)
    with pytest.raises(m.Reject, match='capacity'):
        budget.visit()
    assert budget.visits == m.VISITS
    lease = budget.reserve(metadata=m.METADATA - m.HEADER)
    before = budget.counters()
    with pytest.raises(m.Reject, match='capacity'):
        lease.reserve(metadata=1)
    assert budget.counters() == before
    lease.close()
    assert build({'ordinary': [0] * 16384}).status == 'capacity'


def test_worker_full_exact_plus_one():
    m = api()
    budget = m.RedactionBudget(deadline=time.monotonic() + 5)
    lease = budget.reserve(worker=m.WORKER - m.HEADER)
    before = budget.counters()
    with pytest.raises(m.Reject, match='capacity'):
        lease.reserve(worker=1)
    assert budget.counters() == before
    lease.close()
    assert budget.counters()['worker_bytes'] == 0


@pytest.mark.parametrize('phase', ['discovery', 'seal', 'take'])
def test_absolute_deadline_all_builder_phases(phase):
    m = api()
    with patch.object(m.time, 'monotonic', return_value=10):
        budget = m.RedactionBudget(deadline=11)
        lock, model = owners({})
        b = m.Builder({'api_key': 'secret'}, lock, model, budget=budget)
        if phase != 'discovery':
            while b.slice() == 'more':
                pass
        if phase == 'take':
            assert seal(b) == 'done'
    with patch.object(m.time, 'monotonic', return_value=11):
        if phase == 'discovery':
            assert b.slice() == 'deadline'
        elif phase == 'seal':
            assert b.seal_slice() == 'deadline'
        else:
            assert b.take() is None and b.status == 'deadline'
    assert budget.counters()['worker_bytes'] == budget.counters()['metadata_bytes'] == 0
    assert b.slice() == b.seal_slice() == 'deadline'


def test_builder_cancel_during_seal_releases_secret_generator():
    m = api()
    cfg = {'api_key': 'secret' * 1000}
    lock, model = owners(cfg)
    budget = m.RedactionBudget(deadline=time.monotonic() + 5)
    b = m.Builder(cfg, lock, model, budget=budget, quantum=1)
    while b.slice() == 'more':
        pass
    assert b.seal_slice() == 'more'
    assert b.finalize_gen is not None
    b.discard()
    b.discard()
    assert b.finalize_gen is None and not b.frames and not b.found
    assert b.catalog is b.pending is b.plan is None
    assert b.take() is None and b.seal_slice() == b.slice() == 'stopped'
    assert budget.counters()['worker_bytes'] == 0


def test_atomic_root_catalog_must_finish_inside_slice():
    m = api()
    cfg = {'api_key': 'secret', 'opaque': object()}
    lock, model = owners(cfg)
    with patch.object(m.time, 'monotonic', return_value=0):
        b = m.Builder(cfg, lock, model, budget=m.RedactionBudget(deadline=100))
    ticks = iter([0, 0, 0, 0, 0, 0, .003])
    with patch.object(m.time, 'monotonic', side_effect=lambda: next(ticks, .003)):
        assert b.slice() == 'deadline'
    assert b.catalog is None and not b.frames


def test_lease_close_cannot_resurrect_or_underflow():
    m = api()
    budget = m.RedactionBudget(deadline=time.monotonic() + 5)
    lease = budget.reserve(worker=32, metadata=32)
    lease.close()
    before = budget.counters()
    with pytest.raises(m.Reject, match='invalid'):
        lease.reserve(worker=1)
    with pytest.raises(m.Reject, match='invalid'):
        lease.release(worker=1)
    lease.close()
    assert budget.counters() == before


def test_one_active_operation_slot_is_not_released_by_rejected_sibling():
    m = api()
    budget = m.RedactionBudget(deadline=time.monotonic() + 5)
    lock, model = owners({})
    b = m.Builder({}, lock, model, budget=budget)
    owner = object()
    budget.enter(owner)
    assert b.slice() == 'lock_busy'
    assert budget.counters()['active']
    with pytest.raises(m.Reject, match='lock_busy'):
        budget.enter(object())
    budget.leave(owner)
    assert not budget.counters()['active']


def test_closed_budget_never_revokes_live_charge():
    m = api()
    b = build({'api_key': 'secret'})
    p = b.take()
    before = b.budget.counters()['worker_bytes']
    b.budget.close()
    with pytest.raises(m.Reject, match='invalid'):
        p.value
    assert b.budget.counters()['worker_bytes'] == before
    with pytest.raises(m.Reject, match='invalid'):
        b.budget.reserve(worker=1)
    p.close()
    assert b.budget.counters()['worker_bytes'] == 0


def test_zero_size_leases_are_not_an_unbounded_metadata_channel():
    m = api()
    budget = m.RedactionBudget(deadline=time.monotonic() + 5, metadata_capacity=2 * m.HEADER)
    leases = []
    for _ in range(2):
        leases.append(budget.reserve())
    with pytest.raises(m.Reject, match='capacity'):
        budget.reserve()
    assert budget.counters()['metadata_bytes'] == 2 * m.HEADER
    for lease in leases:
        lease.close()


@pytest.mark.parametrize('operation', ['copy', 'deepcopy'])
def test_no_duplicate_lifetime_owners(operation):
    import copy
    b = build({'api_key': 'secret'})
    p = b.take()
    for value in (b, p, p._lease, p.budget):
        with pytest.raises(TypeError):
            getattr(copy, operation)(value)
    assert b.take() is None
    p.close()


def test_lease_header_cannot_be_released_before_owner_close():
    m = api()
    budget = m.RedactionBudget(deadline=time.monotonic() + 5)
    lease = budget.reserve(worker=100, metadata=100)
    lease.release(worker=100, metadata=100)
    before = budget.counters()
    with pytest.raises(m.Reject, match='invalid'):
        lease.release(worker=1)
    with pytest.raises(m.Reject, match='invalid'):
        lease.release(metadata=1)
    assert budget.counters() == before
    lease.close()


@pytest.mark.parametrize('field', ['deadline', 'worker_capacity', 'metadata_capacity'])
def test_budget_limits_cannot_be_reset(field):
    m = api()
    budget = m.RedactionBudget(deadline=5)
    with pytest.raises(AttributeError):
        setattr(budget, field, 999999999)


def test_seal_completion_rechecks_after_digest_work():
    m = api()
    cfg = {'api_key': 'secret'}
    lock, model = owners(cfg)
    b = m.Builder(cfg, lock, model, budget=m.RedactionBudget(deadline=time.monotonic() + 5))
    while b.slice() == 'more':
        pass
    original = m.hashlib.sha256

    def changing_digest():
        with lock:
            cfg['_monitor_stopped'] = True
        return original()

    with patch.object(m.hashlib, 'sha256', side_effect=changing_digest):
        assert seal(b) == 'mutation'
    assert b.plan is None and b.take() is None


@pytest.mark.parametrize('location', ['config', 'payload'])
def test_poisoned_metaclass_equality_never_runs(location):
    m = api()

    class Poison(type):
        def __eq__(self, other):
            raise AssertionError('type comparison callback')

    class Opaque(metaclass=Poison):
        pass

    if location == 'config':
        b = build({'ordinary': Opaque(), 'api_key': 'secret'})
        assert b.status == 'done'
        b.discard()
    else:
        budget = m.RedactionBudget(deadline=time.monotonic() + 5)
        with pytest.raises(m.Reject, match='invalid'):
            m.OwnedPayload.admit(Opaque(), budget=budget)
        assert budget.counters()['worker_bytes'] == 0


def test_frozen_plan_schema_and_api():
    import dataclasses
    import inspect
    import hashlib
    m = api()
    assert tuple(f.name for f in dataclasses.fields(m.Plan)) == (
        'authority', 'replacements', 'visits', 'secret_bytes', 'metadata_charge')
    assert m.Plan.__dataclass_params__.frozen
    assert (m.VISITS, m.DEPTH, m.SECRETS, m.SECRET_BYTES, m.METADATA, m.WORKER,
            m.SLICE, m.ACQUIRE) == (16384, 32, 256, 65536, 1048576, 16777216, .002, .020)
    for cls in (m.Builder, m.Projector, m.Encoding):
        signature = inspect.signature(cls)
        assert signature.parameters['budget'].default is inspect.Parameter.empty
        assert 'remaining' not in str(signature)
    p = build({'api_key': ['éabc', 'abcd', 'abc']}).take()
    value = p.value
    assert type(value.authority) is tuple and len(value.authority) == 4
    assert all(type(v) is int and 0 <= v <= 9007199254740991 for v in value.authority)
    assert type(value.replacements) is tuple
    assert sum(len(s.encode()) for s, _ in value.replacements) == value.secret_bytes
    assert value.visits <= m.VISITS and value.metadata_charge <= m.METADATA
    previous = 65537
    for row in value.replacements:
        assert type(row) is tuple and len(row) == 2
        text, replacement = row
        assert type(text) is type(replacement) is str
        assert len(text) <= previous
        previous = len(text)
        assert replacement == 'redacted-' + hashlib.sha256(text.encode()).hexdigest()[:12]
    p.close()


@pytest.mark.parametrize('field,value', [('deadline', True), ('deadline', float('inf')),
                                        ('worker_capacity', 16777217), ('metadata_capacity', 1048577),
                                        ('worker_capacity', -1), ('metadata_capacity', True)])
def test_budget_constructor_misuse(field, value):
    m = api()
    kw = {'deadline': time.monotonic() + 5, field: value}
    with pytest.raises(ValueError):
        m.RedactionBudget(**kw)


def test_shared_metadata_exact_denial_preserves_live_plan():
    m = api()
    p = build({'api_key': 'secret'}).take()
    budget = p.budget
    filler = budget.reserve(metadata=m.METADATA - budget.counters()['metadata_bytes'] - m.HEADER)
    before = budget.counters()
    lock, model = owners({})
    sibling = m.Builder({}, lock, model, budget=budget)
    assert sibling.status == 'capacity' and sibling.take() is None
    assert budget.counters() == before
    assert p.value.replacements
    filler.close()
    sibling = build({}, budget=budget)
    assert sibling.status == 'done'
    sibling.discard()
    p.close()
    assert budget.counters()['metadata_bytes'] == budget.counters()['worker_bytes'] == 0


def test_builder_metadata_exact_plus_one_complete_path():
    m = api()
    cfg = {'api_key': ['secret', 'second-secret']}
    p = build(cfg).take()
    required = p.budget.counters()['metadata_peak']
    p.close()
    exact = build(cfg, budget=m.RedactionBudget(deadline=time.monotonic() + 5, metadata_capacity=required))
    assert exact.status == 'done'
    owned = exact.take()
    assert owned is not None
    owned.close()
    lower = build(cfg, budget=m.RedactionBudget(deadline=time.monotonic() + 5, metadata_capacity=required - 1))
    assert lower.status == 'capacity' and lower.take() is None
    assert lower.budget.counters()['metadata_bytes'] == 0


def test_private_force_queues_preserve_complete_dfs_set_order():
    cfg = {'api_key': ['abcd', 'bcde'], '_force_resolve_queue': [
        {'ens_rpc_url': 'private-pinned', 'api_key': ('cdef', 'abcd')}],
        '_force_resolve': {'teams_webhook': ['old-hook', 'bcde']},
        'ordinary': {'nested': {'vt_api_key': 'defg'}}}
    p = build(cfg, quantum=1).take()
    found = set()
    for word in ['abcd', 'bcde', 'private-pinned', 'cdef', 'abcd', 'old-hook', 'bcde', 'defg']:
        found.add(word)
    assert [s for s, _ in p.value.replacements] == sorted(found, key=len, reverse=True)
    p.close()


def test_repeated_terminal_calls_never_reserve_again():
    m = api()
    b = build({'api_key': chr(0xd800)})
    assert b.status == 'invalid'
    before = b.budget.counters()
    for _ in range(3):
        assert b.slice() == b.seal_slice() == 'invalid'
        assert b.take() is None
        b.discard()
    assert b.budget.counters() == before
    with pytest.raises(TypeError):
        m.OwnedPlan(None, None)



def test_empty_plan_reports_its_complete_metadata_charge():
    p = build({}).take()
    assert p.value.metadata_charge == p._lease.metadata
    p.close()
