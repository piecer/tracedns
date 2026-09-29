"""Real Capture -> owned decode -> existing one-pass redaction composition."""
import hashlib
import importlib
import importlib.util
import json
import time
import sys
import tracemalloc
import inspect
from unittest.mock import patch
import pytest

from http_api.read_capture import CaptureBudget
from security.derived_redaction import Builder, Encoding, OwnedPayload, Projector, RedactionBudget
from tests.test_stage4_capture_progress import actual_source

MEASUREMENTS = []


def bridge_for(value, **kwargs):
    owners, _, _ = actual_source(config_size=3, current={'d000.test': value})
    budget = RedactionBudget(deadline=time.monotonic() + 5)
    attempt = CaptureBudget(ledger=budget)
    unit = api().CapturedPayload(owners, 'current', ('d000.test',), capture_budget=attempt, budget=budget, **kwargs)
    return owners, budget, attempt, unit


def api():
    assert importlib.util.find_spec('http_api.derived_capture') is not None, 'shared capture/decode bridge missing'
    return importlib.import_module('http_api.derived_capture')


def finish(owner):
    for _ in range(20000):
        status = owner.slice()
        if status != 'more':
            assert status == 'done', owner.counters()
            return owner
    raise AssertionError('no finite completion')


def plan(owners, budget):
    builder = Builder(owners.config, owners.lock, owners.model, budget=budget)
    for _ in range(20000):
        if builder.status == 'more':
            builder.slice()
        elif builder.status == 'captured':
            builder.seal_slice()
        else:
            break
    assert builder.status == 'done', builder.counters()
    result = builder.take()
    assert result is not None
    return result


def test_actual_current_secret_composes_once_and_record_json():
    m = api()
    raw = {'r': {'type': 'TXT', 'values': ['abcdefghi', 'prefix abcdefghi redacted'], 'ts': 1}}
    owners, repo, service = actual_source(config_size=3, current={'d000.test': raw})
    with owners.lock:
        owners.config['api_key'] = ['abcdefghi', 'redacted']
        lease = repo.capture()['d000.test']
    assert service.read_model is owners.model and lease.current is raw
    original = json.dumps(raw, ensure_ascii=False, separators=(',', ':'))
    first = 'redacted-' + hashlib.sha256(b'abcdefghi').hexdigest()[:12]
    second = 'redacted-' + hashlib.sha256(b'redacted').hexdigest()[:12]
    expected = {'r': {'type': 'TXT', 'values': [first.replace('redacted', second),
                 'prefix ' + first.replace('redacted', second) + ' ' + second], 'ts': 1}}
    budget = RedactionBudget(deadline=time.monotonic() + 5)
    capture_budget = CaptureBudget(ledger=budget)
    bridge = m.CapturedPayload(owners, 'current', ('d000.test',), capture_budget=capture_budget, budget=budget)
    assert capture_budget.visits == 0
    assert bridge.take() is None
    source = finish(bridge).take()
    assert type(source) is OwnedPayload and source.budget is budget
    assert source.value == raw and source.value is not raw
    assert bridge.take() is None
    owned_plan = plan(owners, budget)
    projected = finish(Projector(owned_plan, source, budget=budget)).take()
    assert projected.value == expected
    assert projected.value != raw
    once = json.dumps(expected, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode()
    outputs = []
    for record_json in (False, True):
        output = finish(Encoding(projected, budget=budget, record_json=record_json)).take()
        outputs.append(output)
        assert output.budget is budget
        assert output.value == (json.dumps(once.decode(), ensure_ascii=False).encode() if record_json else once)
    assert second in once.decode() and second.replace('redacted', second) != second
    assert json.dumps(raw, ensure_ascii=False, separators=(',', ':')) == original
    assert capture_budget.ledger is budget
    for handle in (*outputs, projected, source, owned_plan):
        handle.close()
    bridge.discard()
    capture_budget.close()
    assert budget.counters()['worker_bytes'] == budget.counters()['metadata_bytes'] == 0


@pytest.mark.parametrize('root_size', [125, 128, 129])
def test_shared_root_cursor_useful_complete_and_retired(root_size):
    owners, _, _ = actual_source(root_size=root_size)
    budget = RedactionBudget(deadline=time.monotonic() + 5)
    attempt = CaptureBudget(ledger=budget)
    unit = api().CapturedPayload(owners, 'current', ('d000.test',), capture_budget=attempt, budget=budget)
    result = finish(unit).take()
    assert result.value == {}
    assert attempt.descriptors == root_size
    result.close()
    attempt.close()
    assert budget.counters()['worker_bytes'] == budget.counters()['metadata_bytes'] == 0


@pytest.mark.parametrize('value', [
    None, False, True, 0, -1, (1 << 128) - 1, -((1 << 128) - 1), 1.25, -0.0,
    '', 'ASCII 한국어 😀 "\\\n\r\t\b\f\x00',
    'x' * 1023 + '😀한\\"\n' * 2000,
    [], (), {}, {'😀' * 256: ('한국어', True, None, 1)},
    {str(i): i for i in range(128)}, [0] * 4095,
])
def test_actual_producer_complete_decode_equality(value):
    owners, budget, attempt, unit = bridge_for(value)
    expected_bytes = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode()
    result = finish(unit).take()
    assert type(result) is OwnedPayload
    assert result.value == json.loads(expected_bytes)
    assert json.dumps(owners.current['d000.test'], ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode() == expected_bytes
    assert unit.decode_nodes <= 4096 and unit.max_decode_chunk <= 1024
    result.close()
    attempt.close()
    assert budget.counters()['worker_bytes'] == budget.counters()['metadata_bytes'] == 0


@pytest.mark.parametrize('depth,expected', [(32, 'done'), (33, 'capacity')])
def test_actual_depth_inclusive(depth, expected):
    value = 0
    for _ in range(depth - 1):
        value = [value]
    _, budget, attempt, unit = bridge_for(value)
    for _ in range(20000):
        if unit.slice() != 'more':
            break
    assert unit.status == expected
    if expected == 'done':
        result = unit.take()
        assert result.value == value
        result.close()
    else:
        assert unit.take() is None
    unit.discard()
    attempt.close()
    assert budget.counters()['worker_bytes'] == 0


@pytest.mark.parametrize('value', [[0] * 4096, {str(i): i for i in range(129)},
                                   {'한' * 257: 0}, 1 << 128, float('inf'), '\ud800'])
def test_actual_invalid_or_excess_source_has_no_partial_input(value):
    _, budget, attempt, unit = bridge_for(value)
    for _ in range(20000):
        if unit.slice() != 'more':
            break
    assert unit.status in ('capacity', 'invalid')
    assert unit.take() is None
    unit.discard()
    attempt.close()
    assert budget.counters()['worker_bytes'] == 0


@pytest.mark.parametrize('over', [0, 1])
def test_actual_exact_encoded_byte_boundary(over):
    value = {'한': '😀"\\\n' * 1000}
    encoded = json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()
    _, budget, attempt, unit = bridge_for(value, unit_bytes=len(encoded) - over)
    for _ in range(20000):
        if unit.slice() != 'more':
            break
    assert unit.status == ('capacity' if over else 'done')
    result = unit.take()
    if not over:
        assert result.value == value
        result.close()
    else:
        assert result is None
    attempt.close()
    assert budget.counters()['worker_bytes'] == 0


def test_nested_128_member_path_remains_useful():
    inner = dict.fromkeys((f'pad{i}' for i in range(127)))
    inner['leaf'] = {'한': '😀'}
    outer = dict.fromkeys((f'pad{i}' for i in range(127)))
    outer['inner'] = inner
    owners, _, _ = actual_source(current={'d000.test': outer})
    budget = RedactionBudget(deadline=time.monotonic() + 5)
    attempt = CaptureBudget(ledger=budget)
    unit = api().CapturedPayload(owners, 'current', ('d000.test', 'inner', 'leaf'), capture_budget=attempt, budget=budget)
    result = finish(unit).take()
    assert result.value == {'한': '😀'}
    result.close()
    attempt.close()
    assert budget.counters()['worker_bytes'] == 0


@pytest.mark.parametrize('blob', [b'', b'[', b'{"a":', b'"abc', b'"\\',
    b'"\\uD800"', b'"\\uDC00"', b'"\\uD800\\u0041"', b'"\\uxxxx"',
    b'"\xff"', b'"\xc0\x80"', b'"\xed\xa0\x80"', b'"\x01"', b'[1,]',
    b'{"a":1,}', b'{"a" 1}', b'01', b'+1', b'1e', b'1e309', b'NaN',
    b'null true', b'falseX', b'[' * 33 + b']' * 33])
def test_supplemental_malformed_bytes_never_complete(blob):
    from security.derived_redaction import Reject
    budget = RedactionBudget(deadline=time.monotonic() + 5)
    lease = budget.reserve(worker=2000000, metadata=200000)
    decoder = api()._Decoder(blob, lease)
    outcome = 'more'
    try:
        for _ in range(20000):
            outcome = decoder.slice(budget)
            if outcome != 'more':
                break
    except (Reject, ValueError, UnicodeError) as exc:
        outcome = 'invalid'
        exc.__traceback__ = exc.__context__ = exc.__cause__ = None
    decoder = None
    lease.close()
    assert outcome in ('invalid', 'capacity')


@pytest.mark.parametrize('padding', [1022, 1023, 1024])
def test_supplemental_escape_pairs_at_atomic_boundary(padding):
    blob = b'"' + b'x' * padding + b'\\uD83D\\uDE00\\uD55C\\n\\t\\b\\f\\r\\/\\\\\\\""'
    budget = RedactionBudget(deadline=time.monotonic() + 5)
    lease = budget.reserve(worker=2000000, metadata=200000)
    decoder = api()._Decoder(blob, lease)
    assert finish(decoder_wrapper(decoder, budget)) is not None
    assert decoder.result == json.loads(blob)
    decoder = None
    lease.close()


class decoder_wrapper:
    def __init__(self, decoder, budget):
        self.decoder, self.budget = decoder, budget
        self.status = 'more'

    def slice(self):
        self.status = self.decoder.slice(self.budget)
        return self.status


@pytest.mark.parametrize('value', [[0] * 4095, '한😀"\\\n' * 4000])
def test_actual_inner_work_single_phase_and_complete_progress(value):
    from http_api.read_capture import Capture
    from security.derived_redaction import _Admission
    m = api()
    with patch('time.monotonic', lambda: 0):
        owners, budget, attempt, unit = bridge_for(value)
        maxima = dict(decoder_steps=0, string_iterations=0, capture_visits=0, admission_nodes=0)
        calls = []
        per = dict(decoder_steps=0, string_iterations=0, capture_visits=0, admission_nodes=0)
        string_count = 0
        def line_for(method, marker):
            lines, start = inspect.getsourcelines(method)
            return next(start + i for i, line in enumerate(lines) if marker in line)

        body_line = line_for(m._Decoder._string_step, 'byte = self.data')
        visit_line = line_for(Capture._visit, 'self._sv += count')
        admission_line = line_for(_Admission.preflight, 'self._lease.reserve(metadata=32)')

        def trace(frame, event, arg):
            nonlocal string_count
            code = frame.f_code
            if code is m._Decoder.step.__code__ and event == 'call':
                per['decoder_steps'] += 1
            elif code is m._Decoder._string_step.__code__:
                if event == 'call':
                    string_count = 0
                elif event == 'line' and frame.f_lineno == body_line:
                    string_count += 1
                    per['string_iterations'] = max(per['string_iterations'], string_count)
            elif code is Capture._visit.__code__ and event == 'line' and frame.f_lineno == visit_line:
                per['capture_visits'] += frame.f_locals['count']
            elif code is _Admission.preflight.__code__ and event == 'line' and frame.f_lineno == admission_line:
                per['admission_nodes'] += 1
            return trace

        for _ in range(20000):
            phase = unit.phase
            per = dict.fromkeys(per, 0)
            sys.settrace(trace)
            try:
                status = unit.slice()
            finally:
                sys.settrace(None)
            for key, count in per.items():
                maxima[key] = max(maxima[key], count)
            assert per['decoder_steps'] <= 512
            assert per['string_iterations'] <= 1024
            assert per['capture_visits'] <= 512
            assert per['admission_nodes'] <= 512
            assert sum(per[key] > 0 for key in ('decoder_steps', 'capture_visits', 'admission_nodes')) <= 1
            if phase == 'capture' and unit.capture is not None:
                assert unit.capture.max_slice_bytes <= 16384
            calls.append(phase)
            if status != 'more':
                break
        assert status == 'done'
        result = unit.take()
        assert result.value == value and owners.current['d000.test'] == value
        assert maxima['decoder_steps'] > 0 and maxima['capture_visits'] > 0
        assert maxima['admission_nodes'] > 0
        if type(value) is str:
            assert maxima['string_iterations'] > 0
        else:
            assert unit.decode_nodes == 4096
        MEASUREMENTS.append(dict(kind='actual-inner-work', source_type=type(value).__name__,
                                 calls=len(calls), maxima=maxima, final=unit.counters(), ledger=budget.counters()))
        result.close()
        attempt.close()
        assert budget.counters()['worker_bytes'] == 0


@pytest.mark.parametrize('allocation', [False, True])
@pytest.mark.parametrize('value', [[0] * 4095, '한😀"\\\n' * 4000])
def test_finite_unprofiled_timing_separate_from_fixed_clock_allocation(value, allocation):
    from contextlib import nullcontext
    with patch('time.monotonic', lambda: 0) if allocation else nullcontext():
        _, budget, attempt, unit = bridge_for(value)
        if allocation:
            tracemalloc.start()
        started = time.perf_counter()
        result = finish(unit).take()
        duration = time.perf_counter() - started
        memory = tracemalloc.get_traced_memory() if allocation else None
        if allocation:
            tracemalloc.stop()
        assert result.value == value
        assert duration < 5
        MEASUREMENTS.append(dict(kind='fixed-clock-allocation' if allocation else 'unprofiled-time',
            type=type(value).__name__, seconds=None if allocation else duration,
            tracemalloc=memory, ledger=budget.counters(), unit=unit.counters()))
        result.close()
        attempt.close()
