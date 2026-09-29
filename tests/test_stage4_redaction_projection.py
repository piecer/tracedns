"""Owned inner legacy projection; no HTTP/publication authorization here."""
import time
import tracemalloc
import ast
import inspect
from unittest.mock import patch
import json

import pytest

from security.redaction import sanitize
from tests.test_stage4_redaction_plan import api, build


def drain(operation):
    for _ in range(40000):
        if operation.slice() != 'more':
            return operation
    raise AssertionError('unbounded operation')


def test_one_owned_payload_projection():
    m = api()
    assert hasattr(m, 'OwnedPayload'), 'owned payload admission missing'
    cfg = {'api_key': 'actual-secret'}
    budget = m.RedactionBudget(deadline=time.monotonic() + 5)
    plan = build(cfg, budget=budget).take()
    raw = {'actual-secret': ['prefix-actual-secret', 1, True, None]}
    source = m.OwnedPayload.admit(raw, budget=budget)
    projector = m.Projector(plan, source, budget=budget)
    assert drain(projector).status == 'done'
    projected = projector.take()
    assert type(projected) is m.OwnedPayload
    assert projected.value == sanitize(raw, cfg)
    assert source.value is raw
    assert raw == {'actual-secret': ['prefix-actual-secret', 1, True, None]}
    held = budget.counters()['worker_bytes']
    assert held > 0
    assert projector.take() is None
    projector.discard()
    assert budget.counters()['worker_bytes'] == held
    projected.close()
    source.close()
    plan.close()
    assert budget.counters()['worker_bytes'] == budget.counters()['metadata_bytes'] == 0


_resources = []


@pytest.fixture(autouse=True)
def release_resources():
    yield
    for owner in reversed(_resources):
        if hasattr(owner, 'discard'):
            owner.discard()
        else:
            owner.close()
    _resources.clear()


def plan_for(cfg, **limits):
    m = api()
    budget = m.RedactionBudget(deadline=time.monotonic() + 5, **limits)
    b = build(cfg, budget=budget)
    assert b.status == 'done', b.counters()
    p = b.take()
    assert p is not None
    _resources.append(p)
    return p


def project(plan, payload, **kw):
    m = api()
    source = m.OwnedPayload.admit(payload, budget=plan.budget)
    _resources.append(source)
    x = m.Projector(plan, source, budget=plan.budget, **kw)
    _resources.append(x)
    return drain(x)


def encode(x, *, record_json=False, output_cap=1048576):
    m = api()
    assert hasattr(m, 'Encoding'), 'bounded encoding missing'
    if type(x) is m.Projector:
        value = x.take()
        _resources.append(value)
    else:
        value = x
    e = m.Encoding(value, budget=value.budget, output_cap=output_cap, record_json=record_json)
    _resources.append(e)
    drain(e)
    return e


secret='abcd'; replacement=sanitize(secret,{'api_key':secret})
CASES=[('overlap',{'api_key':['abcdef','abcd']},{'abcdef-abcd':'xxabcdefabcd'}),
 ('same_length',{'api_key':['abcd','bcde']},'abcde'),
 ('collision',{'api_key':secret},{secret:{'values':['first']},replacement:{'values':['second']}}),
 ('short',{'api_key':['a','abc']},['a','abc','cat','xabcx']),
 ('expansion',{'api_key':['abcd','redacted']},'abcd'*16),
 ('cascading_expansion',{'api_key':['abcdefgh','redacted']},'abcdefgh'*16),
 ('schema_keys',{'api_key':['values','snapshot','error']},{'snapshot':{'ready':True},'values':['values'],'error':'error'}),
 ('opaque_runtime',{'_monitor_condition':object(),'api_key':'secret'},'secret'),
 ('tuple_sensitive',{'alerts':{'api_key':('one','two')},'nonsensitive':['visible']},('one','two','someone'))]

@pytest.mark.parametrize('name,cfg,payload', CASES, ids=[c[0] for c in CASES])
def test_legacy_nine(name, cfg, payload):
    p = plan_for(cfg)
    x = project(p, payload)
    assert x.status == 'done'
    expected = sanitize(payload, cfg)
    assert x.result == expected
    if type(expected) is dict:
        assert list(x.result) == list(expected)
    projected = x.take()
    _resources.append(projected)
    e = encode(projected)
    assert e.status == 'done'
    out = e.take()
    _resources.append(out)
    encoded = out.value
    assert encoded == json.dumps(expected, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode()
    second = encode(projected, record_json=True)
    assert second.status == 'done'
    second_out = second.take()
    _resources.append(second_out)
    assert second_out.value == json.dumps(encoded.decode(), ensure_ascii=False).encode()


def test_expansion_preallocation_exact_plus_one():
    cfg = {'api_key': ['abcdefghi', 'redacted']}
    p = plan_for(cfg)
    x = project(p, 'abcdefghi' * 16)
    assert x.status == 'done'
    assert [row['output_bytes'] for row in x.preflights] == [336, 544]
    required = p.budget.counters()['worker_peak']
    equal = project(plan_for(cfg, worker_capacity=required), 'abcdefghi' * 16)
    lower = project(plan_for(cfg, worker_capacity=required - 1), 'abcdefghi' * 16)
    assert equal.status == 'done' and equal.result == sanitize('abcdefghi' * 16, cfg)
    assert lower.status == 'capacity' and lower.result is None
    assert lower.budget.counters()['worker_peak'] <= required - 1
    assert lower.preflights[-1]['required'] == required


@pytest.mark.parametrize('record_json', [False, True])
def test_output_exact_plus_one(record_json):
    cfg = {'api_key': ['abcdefgh', 'redacted']}
    p = plan_for(cfg)
    projected = project(p, {'abcdefgh': 'abcdefgh' * 16}).take()
    _resources.append(projected)
    e = encode(projected, record_json=record_json)
    expected = e.take()
    _resources.append(expected)
    equal = encode(projected, record_json=record_json, output_cap=len(expected.value))
    assert equal.status == 'done'
    out = equal.take()
    _resources.append(out)
    assert out.value == expected.value
    lower = encode(projected, record_json=record_json, output_cap=len(expected.value) - 1)
    assert lower.status == 'capacity' and lower.take() is None


R = {}


def test_nonidempotence_and_fixed_grammar_separation():
    cfg = {'api_key': ['abcd', 'redacted', 'snapshot']}
    p = plan_for(cfg)
    one = project(p, 'abcd').result
    two = project(p, one).result
    assert one == sanitize('abcd', cfg) and two == sanitize(one, cfg) and one != two
    schema = project(p, {'snapshot': 'abcd'})
    assert schema.result == sanitize({'snapshot': 'abcd'}, cfg)
    # The schema-only assertion is finished. Retire its input/output before
    # adding a fourth independent composition: the revised header admits nine
    # empty N claims, not the predecessor's 124. This is not a capacity test.
    schema.discard()
    _resources[-2].close()
    e = encode(project(p, 'abcd'), record_json=True)
    assert e.status == 'done'
    out = e.take()
    _resources.append(out)
    assert json.loads(json.loads(out.value)) == one != two


@pytest.mark.parametrize('reverse', [False, True])
def test_same_process_equal_length_discovery(reverse):
    words = ['abcd', 'bcde', 'cdef', 'defg', 'efgh', 'fghi', 'ghij', 'hijk']
    if reverse:
        words.reverse()
    cfg = {'api_key': words}
    p = plan_for(cfg)
    found = set()
    for word in words:
        found.add(word)
    assert [s for s, _ in p.value.replacements] == sorted(found, key=len, reverse=True)
    assert project(p, 'abcdefghijk').result == sanitize('abcdefghijk', cfg)


def test_unicode_and_chunk_edge():
    cfg = {'api_key': ['éabc', '😀four', 'abcde']}
    p = plan_for(cfg)
    payload = {'éabc': 'x' * 1023 + 'abcde' + '😀four' + '\\"\n\t' + 'éabc'}
    e = encode(project(p, payload))
    assert e.status == 'done'
    out = e.take()
    _resources.append(out)
    assert out.value == json.dumps(sanitize(payload, cfg), ensure_ascii=False, separators=(',', ':')).encode()


@pytest.mark.parametrize('kind', ['giant_string', 'giant_container', 'custom', 'cycle'])
def test_payload_giant_custom_cycle(kind):
    from tests.test_stage4_redaction_plan import TrapDict
    m = api()
    p = plan_for({'api_key': 'abcd'})
    cycle = []
    cycle.append(cycle)
    payload = {'giant_string': 'a' * 5000000, 'giant_container': [0] * 4097,
               'custom': TrapDict(a=1), 'cycle': cycle}[kind]
    before = p.budget.counters()['worker_bytes']
    with pytest.raises(m.Reject, match='capacity|invalid'):
        m.OwnedPayload.admit(payload, budget=p.budget)
    assert p.budget.counters()['worker_bytes'] == before
    assert p.budget.counters()['worker_peak'] <= m.WORKER


def test_projector_large_sliced_encoding():
    cfg = {'api_key': ['abcdefghi', 'redacted']}
    p = plan_for(cfg)
    payload = 'x' * 1023 + 'abcdefghi' * 4096
    tracemalloc.start()
    start = time.monotonic()
    x = project(p, payload)
    assert x.status == 'done'
    e = encode(x, record_json=True)
    assert e.status == 'done'
    out = e.take()
    _resources.append(out)
    elapsed = time.monotonic() - start
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    inner = json.dumps(sanitize(payload, cfg), ensure_ascii=False, separators=(',', ':'))
    assert out.value == json.dumps(inner, ensure_ascii=False).encode()
    R['large_projection'] = {'input_chars': len(payload), 'output_bytes': len(out.value),
                              'projector': x.counters(), 'encoding': e.counters(),
                              'elapsed_s': elapsed, 'tracemalloc_peak': peak}


def test_no_unrestricted_replace_or_looping_production_driver():
    m = api()
    tree = ast.parse(inspect.getsource(m))
    assert not any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                   and n.func.attr == 'replace' for n in ast.walk(tree))
    assert not hasattr(m.Builder, 'seal') and not hasattr(m.Projector, 'encoded')


def test_cancelled_input_remains_charged_until_borrower_discards():
    m = api()
    p = plan_for({'api_key': 'abcd'})
    source = m.OwnedPayload.admit('abcd' * 10000, budget=p.budget)
    _resources.append(source)
    x = m.Projector(p, source, budget=p.budget)
    _resources.append(x)
    assert x.slice() == 'more'
    before = p.budget.counters()['worker_bytes']
    source.close()
    assert p.budget.counters()['worker_bytes'] == before
    with pytest.raises(m.Reject, match='invalid'):
        source.value
    assert x.slice() == 'invalid'
    assert p.budget.counters()['worker_bytes'] == p._lease.worker
    assert x.gen is None and x.result is None


def test_close_plan_during_projection_keeps_borrow_charge():
    m = api()
    p = plan_for({'api_key': 'abcd'})
    source = m.OwnedPayload.admit('abcd' * 10000, budget=p.budget)
    _resources.append(source)
    x = m.Projector(p, source, budget=p.budget)
    _resources.append(x)
    assert x.slice() == 'more'
    before = p.budget.counters()['worker_bytes']
    p.close()
    assert p.budget.counters()['worker_bytes'] == before
    x.discard()
    assert p.budget.counters()['worker_bytes'] == source._lease.worker


@pytest.mark.parametrize('constructor', ['Projector', 'Encoding'])
def test_cross_budget_and_closed_handle_refusal_before_reserve(constructor):
    m = api()
    p = plan_for({'api_key': 'abcd'})
    source = m.OwnedPayload.admit('abcd', budget=p.budget)
    _resources.append(source)
    other = m.RedactionBudget(deadline=time.monotonic() + 5)
    before = other.counters()
    args = (p, source) if constructor == 'Projector' else (source,)
    with pytest.raises(ValueError, match='cross-budget'):
        getattr(m, constructor)(*args, budget=other)
    assert other.counters() == before
    source.close()
    before = p.budget.counters()
    with pytest.raises(m.Reject, match='invalid'):
        getattr(m, constructor)(*args, budget=p.budget)
    assert p.budget.counters() == before


@pytest.mark.parametrize('phase', ['project', 'encode', 'take'])
def test_shared_absolute_deadline_cannot_reset(phase):
    m = api()
    with patch.object(m.time, 'monotonic', return_value=0):
        p = plan_for({'api_key': 'abcd'})
        source = m.OwnedPayload.admit('abcd', budget=p.budget)
        _resources.append(source)
        x = m.Projector(p, source, budget=p.budget)
        _resources.append(x)
        if phase != 'project':
            assert drain(x).status == 'done'
            projected = x.take()
            _resources.append(projected)
            x = m.Encoding(projected, budget=p.budget)
            _resources.append(x)
        if phase == 'take':
            assert drain(x).status == 'done'
    with patch.object(m.time, 'monotonic', return_value=5):
        if phase == 'take':
            assert x.take() is None
        else:
            assert x.slice() == 'deadline'
        assert x.status == 'deadline'
        assert x.slice() == 'deadline' and x.take() is None
    assert x.gen is None and x.result is None


def test_composition_all_handles_coexist_until_actual_close():
    m = api()
    p = plan_for({'api_key': ['abcdefghi', 'redacted']})
    budget = p.budget
    source = m.OwnedPayload.admit({'abcdefghi': 'abcdefghi' * 1000}, budget=budget)
    _resources.append(source)
    x = m.Projector(p, source, budget=budget)
    _resources.append(x)
    assert drain(x).status == 'done'
    projected = x.take()
    _resources.append(projected)
    e = m.Encoding(projected, budget=budget, record_json=True)
    _resources.append(e)
    assert drain(e).status == 'done'
    out = e.take()
    _resources.append(out)
    assert type(out) is m.OwnedBytes
    handles = [p, source, projected, out]
    assert len({id(h._lease) for h in handles}) == 4
    assert budget.counters()['worker_bytes'] == sum(h._lease.worker for h in handles)
    assert budget.counters()['metadata_bytes'] == sum(h._lease.metadata for h in handles)
    assert budget.counters()['worker_peak'] <= m.WORKER
    assert budget.counters()['metadata_peak'] <= m.METADATA
    fill = budget.reserve(worker=m.WORKER - budget.counters()['worker_bytes'] - m.HEADER)
    before = budget.counters()
    sibling = m.Encoding(projected, budget=budget)
    assert sibling.status == 'capacity' and sibling.take() is None
    assert budget.counters() == before
    fill.close()
    out.close()
    sibling = m.Encoding(projected, budget=budget)
    assert drain(sibling).status == 'done'
    again = sibling.take()
    assert again is not None and sibling.take() is None
    assert e.take() is None
    again.close()
    for handle in handles:
        handle.close()
        handle.close()
        with pytest.raises(m.Reject, match='invalid'):
            handle.value
    assert budget.counters()['worker_bytes'] == budget.counters()['metadata_bytes'] == 0


@pytest.mark.parametrize('kind', ['surrogate', 'nonstring_key', 'huge_int', 'nan', 'infinity', 'opaque'])
def test_admission_invalid_builtin_values(kind):
    m = api()
    p = plan_for({})
    cases = {'surrogate': chr(0xd800), 'nonstring_key': {0: 'x'}, 'huge_int': 1 << 129,
             'nan': float('nan'), 'infinity': float('inf'), 'opaque': object()}
    before = p.budget.counters()['worker_bytes']
    with pytest.raises(m.Reject, match='invalid'):
        m.OwnedPayload.admit(cases[kind], budget=p.budget)
    assert p.budget.counters()['worker_bytes'] == before


def test_projection_output_cap_travels_with_the_owned_handle():
    p = plan_for({'api_key': 'abcd'})
    x = project(p, 'abcd', output_cap=5)
    assert x.status == 'done'
    projected = x.take()
    _resources.append(projected)
    assert projected.value == sanitize('abcd', {'api_key': 'abcd'})
    encoder = encode(projected)
    assert encoder.status == 'capacity'
    assert encoder.take() is None
