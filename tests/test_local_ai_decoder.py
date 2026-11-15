"""Bounded deterministic decoder verification; no provider or model calls."""
import copy
import importlib

import pytest


def api():
    try:
        return importlib.import_module('local_ai.decoder')
    except ModuleNotFoundError:
        pytest.fail('local_ai.decoder validation API is not implemented')


def row(data='192.0.2.1', expected=None, usage='example', complete=True):
    return {'data': data, 'expected_ips': expected or ['192.0.2.1'],
            'usage': usage, 'complete_expected': complete}


def test_samples_preserve_raw_owned_records_and_exact_limits():
    decoder = api()
    samples = [row(('\u00e9' * 1023) + str(i), [f'192.0.2.{j}' for j in range(1, 9)],
                   'validation' if i else 'example') for i in range(6)]
    original = copy.deepcopy(samples)
    actual = decoder.validate_samples(samples)
    assert actual == original
    assert actual is not samples and actual[0] is not samples[0]
    samples[0]['expected_ips'][0] = '203.0.113.1'
    assert actual == original
    assert decoder.validate_samples([row(' \t192.0.2.1\n')])[0]['data'] == ' \t192.0.2.1\n'
    assert decoder.validate_samples([row('\u00e9' * 1024)])[0]['data'] == '\u00e9' * 1024


@pytest.mark.parametrize('samples,code', [
    (None, 'invalid_request'), ({}, 'invalid_request'), ([], 'invalid_request'),
    ([row(str(i)) for i in range(7)], 'too_large'),
    ([row('\u00e9' * 1024 + 'x')], 'too_large'),
    ([row('x' * 2049)], 'too_large'), ([row('\ud800')], 'invalid_request'),
    ([row(123)], 'invalid_request'),
    ([{**row(), 'expected_ips': []}], 'invalid_request'),
    ([row(expected=['192.0.2.1'] * 9)], 'too_large'),
    ([row(expected=['192.0.2.01'])], 'invalid_request'),
    ([row(expected=['::1'])], 'invalid_request'),
    ([row(expected=[True])], 'invalid_request'),
    ([row(expected=['192.0.2.1'] * 2)], 'invalid_request'),
    ([row(usage='validation')], 'invalid_request'),
    ([row(), row(usage='validation')], 'invalid_request'),
    ([row(), row(expected=['192.0.2.2'])], 'invalid_request'),
    ([row(), row()], 'invalid_request'),
    ([row(complete=1)], 'invalid_request'),
    ([{**row(), 'extra': 'private'}], 'invalid_request'),
    ([{'data': '192.0.2.1'}], 'invalid_request'),
])
def test_invalid_samples_have_stable_code_status(samples, code):
    decoder = api()
    with pytest.raises(decoder.DecoderError) as caught:
        decoder.validate_samples(samples)
    assert caught.value.code == code
    assert caught.value.status == (413 if code == 'too_large' else 400)


@pytest.mark.parametrize('kind', ['TXT', 'A'])
def test_generated_disjoint_schema_matches_validation_and_legacy_factory(kind):
    import jsonschema
    from a_decoder import create_custom_a_decoder
    from txt_decoder import create_custom_decoder
    decoder = api()
    schema = decoder.generated_step_schema(kind)
    jsonschema.Draft202012Validator.check_schema(schema)
    alternatives = schema['oneOf']
    assert len({s['properties']['op']['const'] for s in alternatives}) == len(alternatives)
    assert all(s['additionalProperties'] is False for s in alternatives)
    good = [{'op': op} for op in ('base64', 'urlsafe_b64', 'ascii', 'extract_ip_prefix')]
    good += [{'op': 'xor_hex', 'key': 'aB' * 64}]
    if kind == 'A':
        good += [{'op': 'xor32_ipv4', 'key': '0x00000000'}]
    for step in good:
        jsonschema.validate(step, schema)
        assert decoder.validate_generated_steps(kind, [step]) == [step]
    steps = [{'op': 'ascii'}] * 12
    result = decoder.validate_generated_steps(kind, steps)
    assert result == steps and result is not steps and result[0] is not steps[0]
    assert (create_custom_decoder if kind == 'TXT' else create_custom_a_decoder)(result)(['192.0.2.1']) == ['192.0.2.1']


@pytest.mark.parametrize('step', [
    {'op': 'base64', 'key': 'data'}, {'op': 'extract_ip_prefix', 'key': 'expected_ip'},
    {'op': 'ascii', 'extra': None}, {'op': 'regex', 'pattern': '(.*)'},
    {'op': 'exec'}, {'op': []}, {},
    {'op': 'xor_hex', 'key': ''}, {'op': 'xor_hex', 'key': 'a'},
    {'op': 'xor_hex', 'key': '00 '}, {'op': 'xor_hex', 'key': 'gg'},
    {'op': 'xor_hex', 'key': '00' * 65}, {'op': 'xor_hex', 'key': 12},
    {'op': 'xor32_ipv4', 'key': '00000000'}, {'op': 'xor32_ipv4', 'key': '0x0000000'},
    {'op': 'xor32_ipv4', 'key': '0x000000000'}, {'op': 'xor32_ipv4', 'key': 0},
    {'op': 'xor32_ipv4', 'key_hex': '0x00000000'},
    {'op': 'xor32_ipv4', 'key': '0x00000000', 'extra': 1},
])
@pytest.mark.parametrize('kind', ['TXT', 'A'])
def test_generated_steps_reject_extras_unknowns_and_typed_keys(kind, step):
    import jsonschema
    decoder = api()
    with pytest.raises(decoder.DecoderError) as caught:
        decoder.validate_generated_steps(kind, [step])
    assert caught.value.code == 'invalid_model_output'
    assert not jsonschema.Draft202012Validator(decoder.generated_step_schema(kind)).is_valid(step)


@pytest.mark.parametrize('kind,steps', [('ENS', [{'op': 'ascii'}]), ('txt', [{'op': 'ascii'}]),
                                      ('TXT', []), ('A', [{'op': 'ascii'}] * 13), ('TXT', None)])
def test_generated_steps_count_and_kind_are_closed(kind, steps):
    decoder = api()
    with pytest.raises(decoder.DecoderError):
        decoder.validate_generated_steps(kind, steps)


def test_native_probe_response_is_invalid_generated_despite_legacy_pass():
    import base64
    import txt_decoder
    steps = [{'op': 'base64', 'key': 'data'}, {'op': 'extract_ip_prefix', 'key': 'expected_ip'}]
    sample = base64.b64encode(b'192.0.2.10:443').decode()
    assert txt_decoder.create_custom_decoder(steps)([sample]) == ['192.0.2.10']
    decoder = api()
    with pytest.raises(decoder.DecoderError) as caught:
        decoder.validate_generated_steps('TXT', steps)
    assert caught.value.code == 'invalid_model_output'
    assert steps == [{'op': 'base64', 'key': 'data'}, {'op': 'extract_ip_prefix', 'key': 'expected_ip'}]


def definitions(kind, count):
    return [{'name': f'custom_{i}', 'steps': [{'op': 'ascii'}], 'decoder_type': kind} for i in range(count)]


@pytest.mark.parametrize('kind', ['TXT', 'A'])
def test_catalog_captures_only_selected_definitions_without_mutation(kind):
    import json
    import decoder_registry
    import a_decoder
    import txt_decoder
    decoder = api()
    builtin = sorted(txt_decoder._BUILTIN_DECODE_METHODS if kind == 'TXT' else a_decoder._BUILTIN_A_DECODE_METHODS)
    key = 'custom_decoders' if kind == 'TXT' else 'custom_a_decoders'
    custom = definitions(kind, 32 - len(builtin))
    # Broader persisted DSL fields must not be silently repaired.
    custom[0]['steps'] = [{'op': 'regex', 'pattern': '(.*)', 'group': 1}, {'op': 'ascii', 'key': 'legacy_ignored'}]
    config = {key: custom, 'unrelated_secret': object(), '_runtime': object()}
    before = decoder_registry.snapshot_registry()
    captured = decoder.capture_catalog(config, kind)
    assert captured == {'kind': kind, 'builtins': builtin, 'definitions': custom}
    assert len(captured['builtins']) + len(captured['definitions']) == 32
    json.dumps(captured)
    custom[0]['steps'][1]['key'] = 'mutated'
    assert captured['definitions'][0]['steps'][1]['key'] == 'legacy_ignored'
    assert decoder_registry.snapshot_registry() == before


@pytest.mark.parametrize('kind', ['TXT', 'A'])
def test_catalog_excess_rejects_before_serialization_or_copy(monkeypatch, kind):
    import json
    import a_decoder
    import txt_decoder
    decoder = api()
    builtin = sorted(txt_decoder._BUILTIN_DECODE_METHODS if kind == 'TXT' else a_decoder._BUILTIN_A_DECODE_METHODS)
    key = 'custom_decoders' if kind == 'TXT' else 'custom_a_decoders'
    def forbidden(*args, **kwargs):
        pytest.fail('excess catalog reached copying/serialization')
    monkeypatch.setattr(copy, 'deepcopy', forbidden)
    monkeypatch.setattr(json, 'dumps', forbidden)
    for custom in (definitions(kind, 33 - len(builtin)),
                   [{'name': 'x' * 32769, 'steps': [{'op': 'ascii'}]}],
                   [{'name': 'ordinary', 'steps': [{'op': 'ascii', 'ignored': '\u00e9' * 32768}]}]):
        with pytest.raises(decoder.DecoderError) as caught:
            decoder.capture_catalog({key: custom}, kind)
        assert caught.value.code == 'too_large'


def test_catalog_encoded_budget_exact_plus_one():
    import json
    import a_decoder
    decoder = api()
    custom = definitions('A', 1)
    expected = {'kind': 'A', 'builtins': sorted(a_decoder._BUILTIN_A_DECODE_METHODS), 'definitions': custom}
    size = len(json.dumps(expected, ensure_ascii=False, separators=(',', ':')).encode())
    custom[0]['name'] += 'n' * (32768 - size)
    captured = decoder.capture_catalog({'custom_a_decoders': custom}, 'A')
    assert len(json.dumps(captured, ensure_ascii=False, separators=(',', ':')).encode()) == 32768
    custom[0]['name'] += 'x'
    with pytest.raises(decoder.DecoderError) as caught:
        decoder.capture_catalog({'custom_a_decoders': custom}, 'A')
    assert caught.value.code == 'too_large'


@pytest.mark.parametrize('custom', [None, {}, [None], [{'name': 'bad/name', 'steps': [{'op': 'ascii'}]}],
                                  definitions('TXT', 1), definitions('A', 1) * 2,
                                  [{'name': 'none', 'steps': [{'op': 'ascii'}]}]])
def test_catalog_rejects_invalid_selected_configuration(custom):
    decoder = api()
    with pytest.raises(decoder.DecoderError):
        decoder.capture_catalog({'custom_a_decoders': custom}, 'A')


@pytest.mark.parametrize('kind', ['TXT', 'A'])
def test_generated_verification_uses_real_fresh_factory_and_reports_holdout(kind, monkeypatch):
    import time
    import a_decoder
    import txt_decoder
    import decoder_registry
    decoder = api()
    samples = [row('192.0.2.1'), row('203.0.113.7', ['203.0.113.7'], 'validation')]
    candidates = [{'steps': [{'op': 'ascii'}]}]
    before = decoder_registry.snapshot_registry()
    def forbidden(*args, **kwargs):
        pytest.fail('verification executed a parent factory')
    monkeypatch.setattr(txt_decoder, 'create_custom_decoder', forbidden)
    monkeypatch.setattr(a_decoder, 'create_custom_a_decoder', forbidden)
    report = decoder.evaluate_generated(kind, candidates, samples, time.monotonic() + 20)
    assert report['complete'] is True
    assert report['mode'] == 'generated' and report['kind'] == kind
    assert report['distinct_inputs'] == 2 and report['evaluations'] == 2
    assert report['example_count'] == report['validation_count'] == 1
    assert report['ranking_basis'] == 'fixed_generation_order'
    result = report['candidates'][0]
    assert result['source'] == 'generated' and result['steps'] == candidates[0]['steps']
    assert result['examples']['passed'] == result['validation']['passed'] == 1
    assert result['examples']['results'][0]['matched_ips'] == ['192.0.2.1']
    assert result['validation']['results'][0]['sample_index'] == 1
    assert result['validation']['results'][0]['matched_ips'] == ['203.0.113.7']
    assert decoder_registry.snapshot_registry() == before
    assert 'candidate_not_proof' in report['limitations']
    assert 'distinct_inputs_not_independent_observations' in report['limitations']


def test_catalog_uses_actual_defaults_and_ranks_on_examples_only():
    import time
    import a_decoder
    decoder = api()
    custom = [
        {'name': 'example_winner', 'steps': [{'op': 'regex', 'pattern': r'^(192\.0\.2\.1)$'}]},
        {'name': 'holdout_winner', 'steps': [{'op': 'regex', 'pattern': r'^(203\.0\.113\.7)$'}]},
    ]
    catalog = decoder.capture_catalog({'custom_a_decoders': custom}, 'A')
    samples = [row(), row('203.0.113.7', ['203.0.113.7'], 'validation')]
    report = decoder.evaluate_catalog('A', catalog, samples, time.monotonic() + 20)
    names = [c['name'] for c in report['candidates']]
    assert names[0] == 'example_winner'
    assert names.index('example_winner') < names.index('holdout_winner')
    assert report['ranking_basis'] == 'examples_only'
    assert report['evaluations'] == len(names) * 2
    by_name = {c['name']: c for c in report['candidates']}
    assert by_name['example_winner']['validation']['passed'] == 0
    assert by_name['holdout_winner']['validation']['passed'] == 1
    expected = a_decoder.decode_a_xor32_ipv4(['192.0.2.1'], domain=None)
    assert by_name['xor32_ipv4']['examples']['results'][0]['unexpected_ips'] == expected
    samples[1] = row('198.51.100.9', ['198.51.100.9'], 'validation')
    second = decoder.evaluate_catalog('A', catalog, samples, time.monotonic() + 20)
    assert [c['name'] for c in second['candidates']] == names


def test_reports_distinguish_missing_unexpected_partial_and_no_holdout():
    import time
    decoder = api()
    samples = [row('192.0.2.1|203.0.113.2', ['192.0.2.1', '198.51.100.3']),
               row('192.0.2.1,203.0.113.2', ['192.0.2.1'], complete=False)]
    report = decoder.evaluate_generated('TXT', [{'steps': [{'op': 'ascii'}]}], samples, time.monotonic() + 20)
    result = report['candidates'][0]
    first, second = result['examples']['results']
    assert first['matched_ips'] == ['192.0.2.1']
    assert first['missing_ips'] == ['198.51.100.3']
    assert first['unexpected_ips'] == ['203.0.113.2']
    assert first['unverified_extra_ips'] == [] and first['passed'] is False
    assert second['unexpected_ips'] == [] and second['passed'] is True
    assert second['unverified_extra_ips'] == ['203.0.113.2']
    assert result['validation']['tested'] == 0 and result['validation']['results'] == []
    assert 'no_validation_samples' in report['limitations']


@pytest.fixture
def child_factory(monkeypatch):
    import subprocess
    import sys
    children = []
    def install(code, *, survive_kill=False):
        def spawn(cutoff):
            child = subprocess.Popen([sys.executable, '-I', '-B', '-S', '-c', code],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     bufsize=0, close_fds=True, env={})
            children.append(child)
            if survive_kill:
                monkeypatch.setattr(child, 'kill', lambda: None)
            return child
        monkeypatch.setattr(api(), '_spawn_worker', spawn)
        return children
    try:
        yield install
    finally:
        # Independent fixture rescue only; normal-path assertions precede this.
        for child in children:
            if child.poll() is None:
                subprocess.Popen.kill(child)
                child.wait(timeout=2)
            for stream in (child.stdin, child.stdout, child.stderr):
                if not stream.closed:
                    stream.close()


def run_one(deadline=None):
    import time
    return api().evaluate_generated('TXT', [{'steps': [{'op': 'ascii'}]}], [row()],
                                    time.monotonic() + 20 if deadline is None else deadline)


@pytest.mark.parametrize('fd,size', [(1, 65537), (2, 4097)])
def test_pipe_overflow_stops_before_child_finishes_and_reaps(child_factory, fd, size):
    import time
    decoder = api()
    children = child_factory(f'import os,time; os.write({fd}, b"x"*{size}); time.sleep(3)')
    start = time.monotonic()
    with pytest.raises(decoder.DecoderError) as caught:
        run_one()
    assert caught.value.code == 'verification_failed'
    assert time.monotonic() - start < 2, 'must stop on overflow, not accumulate until completion'
    assert len(children) == 1 and children[0].poll() is not None
    assert all(s.closed for s in (children[0].stdin, children[0].stdout, children[0].stderr))


@pytest.mark.parametrize('output', ['{}', 'null', '{"complete":true,"complete":true}',
                                   '{"complete":true,"candidates":[]}'])
def test_invalid_worker_report_is_not_success(child_factory, output):
    decoder = api()
    children = child_factory(f'import sys; sys.stdin.buffer.read(); print({output!r})')
    with pytest.raises(decoder.DecoderError) as caught:
        run_one()
    assert caught.value.code == 'verification_failed'
    assert children[0].poll() is not None


def test_surviving_child_blocks_replacement_until_physically_reaped(child_factory):
    import time
    import subprocess
    decoder = api()
    children = child_factory('import time; time.sleep(60)', survive_kill=True)
    with pytest.raises(decoder.DecoderError) as first:
        run_one(time.monotonic() + 0.05)
    assert first.value.code == 'verification_failed'
    assert len(children) == 1 and children[0].poll() is None
    with pytest.raises(decoder.DecoderError) as second:
        run_one(time.monotonic() + 0.05)
    assert second.value.code == 'verification_failed'
    assert len(children) == 1, 'must not replace a still-alive owned child'
    subprocess.Popen.kill(children[0])
    children[0].wait(timeout=2)


def test_running_verification_has_single_physical_admission(child_factory):
    import threading
    import time
    decoder = api()
    children = child_factory('import time; time.sleep(60)')
    started = threading.Event()
    original_spawn = decoder._spawn_worker
    def spawn(cutoff):
        child = original_spawn(cutoff)
        started.set()
        return child
    errors = []
    decoder._spawn_worker = spawn
    def first():
        try:
            run_one(time.monotonic() + 1)
        except decoder.DecoderError as error:
            errors.append(error.code)
    thread = threading.Thread(target=first)
    thread.start()
    try:
        assert started.wait(1)
        with pytest.raises(decoder.DecoderError) as caught:
            run_one(time.monotonic() + 0.05)
        assert caught.value.code == 'busy'
        assert len(children) == 1
    finally:
        thread.join(timeout=3)
    assert not thread.is_alive()
    assert errors == ['verification_failed']
    assert children[0].poll() is not None


@pytest.mark.parametrize('kind', ['TXT', 'A'])
def test_generated_schema_does_not_accept_trailing_newline(kind):
    import jsonschema
    decoder = api()
    step = {'op': 'xor_hex', 'key': 'aa\n'}
    with pytest.raises(decoder.DecoderError):
        decoder.validate_generated_steps(kind, [step])
    assert not jsonschema.Draft202012Validator(decoder.generated_step_schema(kind)).is_valid(step)


def test_real_catalog_and_generated_maximum_evaluation_counts():
    import time
    import a_decoder
    decoder = api()
    samples = [row(f'192.0.2.{i}', [f'192.0.2.{i}'], 'validation' if i > 3 else 'example') for i in range(1, 7)]
    catalog = decoder.capture_catalog({'custom_a_decoders': definitions('A', 32 - len(a_decoder._BUILTIN_A_DECODE_METHODS))}, 'A')
    report = decoder.evaluate_catalog('A', catalog, samples, time.monotonic() + 20)
    assert len(report['candidates']) == 32 and report['evaluations'] == 192
    generated = [{'steps': [{'op': 'ascii'}] * 12} for _ in range(3)]
    report = decoder.evaluate_generated('A', generated, samples, time.monotonic() + 20)
    assert len(report['candidates']) == 3 and report['evaluations'] == 18
    assert all(c['validation']['passed'] == 3 for c in report['candidates'])


def test_real_txt_catalog_runs_all_builtins_at_defaults_without_mutation():
    import time
    import txt_decoder
    import decoder_registry
    decoder = api()
    catalog = decoder.capture_catalog({'custom_decoders': [
        {'name': 'legacy', 'steps': [{'op': 'regex', 'pattern': r'^(.*)$'}, {'op': 'ascii', 'key': 'ignored'}]}]}, 'TXT')
    before = decoder_registry.snapshot_registry()
    report = decoder.evaluate_catalog('TXT', catalog, [row()], time.monotonic() + 20)
    by_name = {c['name']: c for c in report['candidates']}
    assert set(by_name) == txt_decoder._BUILTIN_DECODE_METHODS | {'legacy'}
    assert by_name['plain_ip']['examples']['passed'] == by_name['legacy']['examples']['passed'] == 1
    assert decoder_registry.snapshot_registry() == before
    for name in catalog['builtins']:
        observed = set(txt_decoder.TXT_DECODE_METHODS[name](['192.0.2.1'], domain=None))
        result = by_name[name]['examples']['results'][0]
        assert set(result['matched_ips']) | set(result['unexpected_ips']) == observed


def test_exact_stdout_stderr_limits_accept_real_report(child_factory):
    import json
    report = run_one()
    encoded = json.dumps(report)
    code = f'import sys; sys.stdin.buffer.read(); sys.stderr.buffer.write(b"x"*4096); sys.stderr.flush(); sys.stdout.write({encoded!r}.ljust(65536)); sys.stdout.flush()'
    children = child_factory(code)
    assert run_one() == report
    assert children[0].poll() == 0
    assert all(s.closed for s in (children[0].stdin, children[0].stdout, children[0].stderr))


def test_stdin_exact_limit_and_plus_one_before_spawn(monkeypatch):
    import time
    import json
    decoder = api()
    payload = {'mode': 'generated', 'kind': 'TXT', 'candidates': [{'steps': [{'op': 'ascii'}]}],
               'samples': [row()], 'transport_padding': ''}
    size = len(json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode())
    payload['transport_padding'] = ' ' * (65536 - size)
    assert decoder._exchange(payload, time.monotonic() + 5)['complete'] is True
    def forbidden(*args):
        pytest.fail('oversized stdin reached spawn')
    monkeypatch.setattr(decoder, '_spawn_worker', forbidden)
    payload['transport_padding'] += ' '
    with pytest.raises(decoder.DecoderError) as caught:
        decoder._exchange(payload, time.monotonic() + 5)
    assert caught.value.code == 'too_large'


def test_generated_invalid_inventory_and_deadline_refuse_before_spawn(monkeypatch):
    import time
    decoder = api()
    def forbidden(*args):
        pytest.fail('invalid request reached spawn')
    monkeypatch.setattr(decoder, '_spawn_worker', forbidden)
    for candidates in ([{'steps': [{'op': 'ascii'}]}] * 4, [{'steps': [{'op': 'regex', 'pattern': '(.*)'}]}],
                       [{'steps': [{'op': 'ascii'}], 'score': 100}], None):
        with pytest.raises(decoder.DecoderError) as caught:
            decoder.evaluate_generated('TXT', candidates, [row()], time.monotonic() + 5)
        assert caught.value.code == 'invalid_model_output'
    for deadline in (time.monotonic() - 1, float('nan'), float('inf'), True, 'soon'):
        with pytest.raises(decoder.DecoderError):
            run_one(deadline)
    # Raw UTF-8 sample bounds and escaped wire bounds are independent.
    samples = [row('\x00' * 2047 + str(i)) for i in range(6)]
    with pytest.raises(decoder.DecoderError) as caught:
        decoder.evaluate_generated('TXT', [{'steps': [{'op': 'ascii'}]}], samples, time.monotonic() + 5)
    assert caught.value.code == 'too_large'


@pytest.mark.parametrize('remaining', [0.05, 60])
def test_real_work_cutoff_and_total_deadline_reap(child_factory, remaining):
    import time
    decoder = api()
    children = child_factory('import time; time.sleep(60)')
    start = time.monotonic()
    with pytest.raises(decoder.DecoderError) as caught:
        run_one(start + remaining)
    elapsed = time.monotonic() - start
    assert caught.value.code == 'verification_failed'
    assert min(remaining, 5) <= elapsed < min(remaining, 5) + 2
    assert children[0].poll() is not None
    assert all(s.closed for s in (children[0].stdin, children[0].stdout, children[0].stderr))


@pytest.mark.parametrize('fault', ['spawn', 'pump_setup', 'crash', 'malformed'])
def test_worker_failure_is_sanitized_and_owned_child_reaped(monkeypatch, child_factory, fault):
    import os
    decoder = api()
    children = []
    if fault == 'spawn':
        def fail(*args):
            raise OSError('/private/path secret')
        monkeypatch.setattr(decoder, '_spawn_worker', fail)
    elif fault == 'pump_setup':
        children = child_factory('import time; time.sleep(60)')
        monkeypatch.setattr(os, 'set_blocking', lambda *args: (_ for _ in ()).throw(OSError('private setup')))
    else:
        children = child_factory('raise RuntimeError("private source")' if fault == 'crash' else 'print("not json")')
    with pytest.raises(decoder.DecoderError) as caught:
        run_one()
    assert str(caught.value) == caught.value.code == 'verification_failed'
    assert all(c.poll() is not None for c in children)
    assert all(s.closed for c in children for s in (c.stdin, c.stdout, c.stderr))


def test_json_meter_matches_native_compact_utf8_and_rejects_plus_one():
    import json
    decoder = api()
    values = [None, True, False, 0, -12, 1.5, '\\"\b\f\n\r\t\x00\u00e9\u0800\U0001f600', [], {},
              {'x': [1, False, None, {'y': 'nested'}]}]
    for value in values:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode()
        assert decoder._bounded_json(value, len(encoded)) == encoded
        with pytest.raises(decoder.DecoderError):
            decoder._bounded_json(value, len(encoded) - 1)
    cycle = []
    cycle.append(cycle)
    for value in (cycle, float('nan'), float('inf'), object(), {1: 'bad'}, '\ud800'):
        with pytest.raises(decoder.DecoderError):
            decoder._bounded_json(value, 65536)


def test_real_legacy_regex_timeout_is_incomplete_not_no_match(monkeypatch):
    import time
    import decoder_registry
    from http_api.decoder_crud import _validate_steps
    import txt_decoder
    decoder = api()
    steps = [{'op': 'regex', 'pattern': '(a|aa)+$'}]
    assert _validate_steps(steps, 'TXT')[0] is True
    assert txt_decoder.create_custom_decoder(steps) is not None
    catalog = decoder.capture_catalog({'custom_decoders': [{'name': 'slow_legacy', 'steps': steps}]}, 'TXT')
    original_spawn, children = decoder._spawn_worker, []
    def observe(cutoff):
        child = original_spawn(cutoff)
        children.append(child)
        return child
    monkeypatch.setattr(decoder, '_spawn_worker', observe)
    before = decoder_registry.snapshot_registry()
    with pytest.raises(decoder.DecoderError) as caught:
        decoder.evaluate_catalog('TXT', catalog, [row('a' * 200 + '!')], time.monotonic() + 0.2)
    assert caught.value.code == 'verification_failed'
    assert len(children) == 1 and children[0].poll() is not None
    assert all(s.closed for s in (children[0].stdin, children[0].stdout, children[0].stderr))
    assert decoder_registry.snapshot_registry() == before
    assert run_one()['complete'] is True
    assert all(c.poll() is not None for c in children)


def test_delayed_preparation_cannot_admit_after_deadline(monkeypatch):
    import time
    import subprocess
    decoder = api()
    original = decoder._bounded_json
    def delayed(*args):
        encoded = original(*args)
        time.sleep(0.1)
        return encoded
    def forbidden(*args, **kwargs):
        pytest.fail('expired work reached actual process creation')
    monkeypatch.setattr(decoder, '_bounded_json', delayed)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    with pytest.raises(decoder.DecoderError) as caught:
        run_one(time.monotonic() + 0.05)
    assert caught.value.code == 'verification_failed'


def test_late_report_validation_does_not_publish_success(monkeypatch):
    import time
    decoder = api()
    original = decoder._validate_report
    def delayed(*args):
        report = original(*args)
        time.sleep(0.2)
        return report
    monkeypatch.setattr(decoder, '_validate_report', delayed)
    with pytest.raises(decoder.DecoderError) as caught:
        run_one(time.monotonic() + 0.1)
    assert caught.value.code == 'verification_failed'
    assert decoder._active_child is None


@pytest.mark.parametrize('mode', ['catalog', 'generated'])
def test_all_examples_finish_before_first_holdout(mode, monkeypatch):
    from local_ai import decoder_worker
    decoder = api()
    samples = [row(), row('203.0.113.7', ['203.0.113.7'], 'validation')]
    payload = {'kind': 'A', 'mode': mode, 'samples': samples}
    if mode == 'catalog':
        payload['catalog'] = decoder.capture_catalog({'custom_a_decoders': definitions('A', 2)}, 'A')
        count = len(payload['catalog']['builtins']) + 2
    else:
        payload['candidates'] = [{'steps': [{'op': 'ascii'}]} for _ in range(3)]
        count = 3
    phases = []
    original = decoder_worker._evaluate
    def observe(fn, indexed):
        usage = indexed[0][1]['usage']
        if usage == 'validation':
            assert phases.count('example') == count
        phases.append(usage)
        return original(fn, indexed)
    monkeypatch.setattr(decoder_worker, '_evaluate', observe)
    report = decoder_worker.verify(payload)
    assert report['complete'] is True
    assert phases == ['example'] * count + ['validation'] * count
