"""Compatible prompt/model contract; synthetic replies, never live inference."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import time
from types import MappingProxyType

import pytest

from local_ai.contracts import AIError
from local_ai.engine import model_metadata, prompt
from local_ai.provider import NativeReply


def compatible_metadata(**extra):
    return {'provider': 'openai_compatible', 'requested_model': 'gateway-alias',
            'reported_model': 'vendor/snapshot@v1', 'finish_reason': 'stop',
            'response_format': 'json_object', **extra}


def test_compatible_metadata_preserves_requested_and_reported_identity_without_native_facts():
    raw = compatible_metadata()
    result = model_metadata(NativeReply('{}', MappingProxyType(raw)))
    assert result == raw and result is not raw
    assert 'model_digest' not in result and 'total_duration' not in result
    assert model_metadata(NativeReply('{}', {'model': 'fixture:local', 'model_digest': 'a' * 64})) == {
        'model': 'fixture:local', 'model_digest': 'a' * 64}
    result['reported_model'] = 'changed'
    assert raw['reported_model'] == 'vendor/snapshot@v1'


@pytest.mark.parametrize('field,value', [
    ('provider', None), ('provider', 'unknown'), ('requested_model', ''),
    ('reported_model', 'has space'), ('reported_model', 'model\n'),
    ('finish_reason', 'tool_calls'), ('response_format', 'json_schema'),
    ('model_digest', 'a' * 64), ('extra', 'private'),
])
def test_compatible_metadata_is_closed(field, value):
    raw = compatible_metadata(**{field: value})
    before = copy.deepcopy(raw)
    with pytest.raises(AIError, match='^invalid_model_output$'):
        model_metadata(NativeReply('{}', raw))
    assert raw == before


@pytest.mark.parametrize('counter', ['prompt_tokens', 'completion_tokens', 'total_tokens'])
@pytest.mark.parametrize('value', [0, 1, (1 << 53) + 1, (1 << 63) - 1])
def test_optional_usage_is_observed_int64_not_zero_filled(counter, value):
    raw = compatible_metadata(**{counter: value})
    assert model_metadata(NativeReply('{}', raw)) == compatible_metadata(**{counter: str(value)})
    assert raw[counter] == value


def test_complete_usage_requires_consistent_sum():
    raw = compatible_metadata(prompt_tokens=2, completion_tokens=3, total_tokens=5)
    assert model_metadata(NativeReply('{}', raw)) == compatible_metadata(
        prompt_tokens='2', completion_tokens='3', total_tokens='5')
    raw['total_tokens'] = 4
    with pytest.raises(AIError, match='^invalid_model_output$'):
        model_metadata(NativeReply('{}', raw))


@pytest.mark.parametrize('value', [None, True, -1, 1.0, '1', 1 << 63])
def test_usage_does_not_coerce_or_overflow(value):
    with pytest.raises(AIError, match='^invalid_model_output$'):
        model_metadata(NativeReply('{}', compatible_metadata(prompt_tokens=value)))


def prompt_inputs(kind):
    from local_ai.contracts import decoder_schema, explanation_schema
    if kind in ('TXT', 'A'):
        snapshot = {'version': 1, 'kind': 'decoder_suggest', 'decoder_type': kind,
                    'examples': [{'data': '192.0.2.1', 'expected_ips': ['192.0.2.1'],
                                  'usage': 'example', 'complete_expected': True}]}
        schema = decoder_schema(kind, 'en', 'a' * 64)
    else:
        snapshot = {'version': 1, 'kind': kind, 'source': {},
                    'facts': [{'id': 'e1', 'key': 'controlled', 'value': 'safe fact'}], 'warnings': []}
        schema = explanation_schema(kind, 'en', 'a' * 64, ['e1'])
    return snapshot, schema


def canonical(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(',', ':')).encode('utf-8')


@pytest.mark.parametrize('kind', ['TXT', 'A', 'relationship_pair', 'delivery'])
def test_json_object_prompt_binds_schema_in_existing_system_message(kind):
    snapshot, schema = prompt_inputs(kind)
    native = prompt(snapshot, schema)
    compatible = prompt(snapshot, schema, prompt_mode='json_object')
    assert [message['role'] for message in compatible] == ['system', 'user']
    assert compatible[1] == native[1]
    assert compatible[0]['content'].startswith(native[0]['content'])
    assert canonical(schema).decode() in compatible[0]['content']
    assert len(canonical({'messages': compatible, 'schema': schema})) <= 16384


@pytest.mark.parametrize('kind,expected', [
    ('TXT', '1b50d5c9dafd5d092efd8904633639316c0eb3298d06e9122503b81484747a0b'),
    ('A', '72db2ee8cd092ba8a2be5e3aca31ce00222cbb18afc7032a58f552e854786329'),
    ('relationship_pair', 'afb19025865aa973b2dd9b10723f37352fc153c0dc3d360f629fd874cb00b436'),
    ('delivery', '11e1625800b26f3c0f6d10e6b71067fa24c6f1aff7e3de02963936e8faecd26f'),
])
def test_native_prompt_bytes_match_prechange_producer(kind, expected):
    assert hashlib.sha256(canonical(prompt(*prompt_inputs(kind)))).hexdigest() == expected


@pytest.mark.parametrize('mode', [None, False, 'unknown', 'json_schema'])
def test_prompt_mode_is_closed(mode):
    with pytest.raises(AIError, match='^invalid_request$'):
        prompt(*prompt_inputs('TXT'), prompt_mode=mode)


def test_augmented_schema_counts_toward_original_bundle_budget():
    snapshot, _ = prompt_inputs('TXT')
    schema = {'description': 'x' * 10000}
    assert prompt(snapshot, schema)
    with pytest.raises(AIError, match='^too_large$'):
        prompt(snapshot, schema, prompt_mode='json_object')


@pytest.mark.parametrize('kind', ['TXT', 'A', 'relationship_pair', 'delivery'])
def test_actual_task_checks_augmented_bundle_before_callback_and_retains_commitment(kind, monkeypatch, tmp_path):
    import local_ai.engine as module
    from test_local_ai_contracts import decoder_request
    from test_local_ai_engine import empty_proposal_reply, explanation_reply
    from test_local_ai_sources import ACTOR, context, original_job
    ctx, jobs, app = context(), None, None
    request = {'kind': kind, 'language': 'en'}
    if kind in ('TXT', 'A'):
        request = decoder_request(decoder_type=kind, samples=[
            {'data': '192.0.2.1 ' + 'x' * 1800, 'expected_ips': ['192.0.2.1'],
             'usage': 'example', 'complete_expected': True},
            {'data': '198.51.100.17 HOLDOUT', 'expected_ips': ['198.51.100.17'],
             'usage': 'validation', 'complete_expected': True}])
    elif kind == 'relationship_pair':
        jobs, request['source'], _ = original_job(monkeypatch, ctx)
    else:
        from test_stage3_core_runtime import app_factory
        monkeypatch.setenv('MISP_SIGHTING_BATCH_FILE', str(tmp_path / 'sightings.json'))
        app = app_factory(tmp_path / 'ledger')
        ctx.shared_config, ctx.config_lock = app.cfg.raw, app.cfg.lock
        ctx.delivery_diagnostics = app.delivery.store.diagnostics_snapshot
        ctx.delivery_health = app.delivery.health_snapshot
    checked, calls = [], []
    real_privacy = module.secret_free

    def observe(owner, value, deadline, **kwargs):
        encoded = real_privacy(owner, value, deadline, **kwargs)
        if set(value) == {'messages', 'schema'}:
            checked.append(encoded)
        return encoded

    def generate(messages, schema):
        bundle = canonical({'messages': messages, 'schema': schema})
        assert checked == [bundle]
        assert [message['role'] for message in messages] == ['system', 'user']
        assert canonical(schema).decode() in messages[0]['content']
        assert 'HOLDOUT' not in bundle.decode() and '198.51.100.17' not in bundle.decode()
        calls.append(bundle)
        reply = (empty_proposal_reply if kind in ('TXT', 'A') else explanation_reply)(messages, schema)
        return NativeReply(reply.content, compatible_metadata(prompt_tokens=3, completion_tokens=2, total_tokens=5))

    monkeypatch.setattr(module, 'secret_free', observe)
    deadline, task = time.monotonic() + 20, None
    try:
        task = module.AssistantEngine(ctx, jobs).prepare(
            request, {**ACTOR, 'role': 'admin'}, deadline, prompt_mode='json_object')
        wire = task.run(deadline, generate)
        result = json.loads(wire)
        assert len(calls) == 1
        assert result['model'] == compatible_metadata(prompt_tokens='3', completion_tokens='2', total_tokens='5')
        if kind in ('TXT', 'A'):
            assert result['model_input']['messages_schema_digest'] == hashlib.sha256(calls[0]).hexdigest()
            assert result['model_input']['messages_schema_bytes'] == len(calls[0])
            assert result['model_input']['coverage']['omitted_utf8_bytes'] > 0
        else:
            assert result['facts_summary']['snapshot_digest'] == result['snapshot_digest']
        consume_result_wire(wire, request)
    finally:
        if task is not None:
            task.dispose()
        if app is not None:
            app.delivery.stop()


@pytest.mark.parametrize('mode', [None])
def test_prepare_rejects_invalid_prompt_mode_before_source_acquisition(monkeypatch, mode):
    import local_ai.engine as module
    from test_local_ai_contracts import decoder_request
    from test_local_ai_sources import ACTOR, context
    monkeypatch.setattr(module, 'capture_decoder', lambda *a: pytest.fail('invalid mode acquired a lease'))
    with pytest.raises(AIError, match='^invalid_request$'):
        module.AssistantEngine(context(), None).prepare(
            decoder_request(), {**ACTOR, 'role': 'admin'}, time.monotonic() + 10, prompt_mode=mode)


ROOT = Path(__file__).resolve().parents[1]
MODEL_VM = r"""
const fs=require('node:fs'), vm=require('node:vm'), assert=require('node:assert/strict'), crypto=require('node:crypto');
const source=fs.readFileSync('local_ai_frontend.js','utf8'), sandbox={window:{},TextEncoder,AbortController};
vm.createContext(sandbox);
assert.equal(source.split('window.TraceLocalAI=Object.freeze({mount});').length,2);
vm.runInContext(source.replace('window.TraceLocalAI=Object.freeze({mount});',
 'window.TraceLocalAI=Object.freeze({mount,validModel,validResult});'),sandbox);
const cases=JSON.parse(fs.readFileSync(0,'utf8'));
for(const c of cases){
 assert.equal(crypto.createHash('sha256').update(c.wire,'utf8').digest('hex'),c.sha256);
 const value=JSON.parse(c.wire);let hooks=0;
 if(c.mutation==='getter')Object.defineProperty(value,'provider',{enumerable:true,get(){hooks++;return 'openai_compatible';}});
 if(c.mutation==='hidden')Object.defineProperty(value,'extra',{value:1});
 if(c.mutation==='symbol')value[Symbol('extra')]=1;
 if(c.mutation==='prototype')Object.setPrototypeOf(value,{provider:'openai_compatible'});
 const got=c.request?sandbox.window.TraceLocalAI.validResult(value,c.request):sandbox.window.TraceLocalAI.validModel(value);
 assert.equal(got,c.accept,c.name);assert.equal(hooks,0,c.name);
}
console.log(JSON.stringify({cases:cases.length,passed:true}));
"""


def browser_cases(cases):
    for case in cases:
        case['sha256'] = hashlib.sha256(case['wire'].encode()).hexdigest()
    result = subprocess.run(['node', '-e', MODEL_VM], input=json.dumps(cases), text=True,
                            capture_output=True, cwd=ROOT, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == {'cases': len(cases), 'passed': True}


def consume_result_wire(wire, request):
    import jsonschema
    import http_api.local_ai_schema as schema
    assert hasattr(schema, 'MODEL_METADATA_SCHEMA'), 'provider-specific public metadata grammar missing'
    jsonschema.Draft202012Validator(schema.RESULT_SCHEMA).validate(json.loads(wire))
    browser_cases([{'name': 'actual compatible engine bytes', 'wire': wire.decode(),
                    'request': request, 'accept': True}])


def metadata_wire_cases():
    from itertools import combinations
    cases = []
    usages = {'prompt_tokens': 2, 'completion_tokens': 3, 'total_tokens': 5}
    for count in range(4):
        for keys in combinations(usages, count):
            raw = compatible_metadata(**{key: usages[key] for key in keys})
            cases.append({'name': 'producer ' + ','.join(keys), 'model': model_metadata(NativeReply('{}', raw)),
                          'accept': True})
    cases.extend([
        {'name': 'native producer', 'model': model_metadata(NativeReply('{}', {
            'model': 'fixture:local', 'model_digest': 'c' * 64, 'eval_count': (1 << 63) - 1})), 'accept': True},
        {'name': 'compatible maximum counter', 'model': model_metadata(NativeReply('{}',
            compatible_metadata(prompt_tokens=(1 << 63) - 1))), 'accept': True},
    ])
    for key in compatible_metadata():
        value = compatible_metadata()
        del value[key]
        cases.append({'name': 'missing ' + key, 'model': value, 'accept': False})
    for key, value in [('provider', None), ('provider', 'ollama'), ('reported_model', 'model\n'),
                       ('requested_model', 'model with spaces'), ('requested_model', 'x' * 257),
                       ('finish_reason', 'tool_calls'), ('response_format', 'json_schema'),
                       ('model_digest', 'a' * 64), ('total_duration', '1'), ('extra', 'PRIVATE')]:
        cases.append({'name': 'invalid ' + key, 'model': compatible_metadata(**{key: value}), 'accept': False})
    for key in usages:
        for value in [None, True, 1, '-1', '00', '+1', ' 1', '1\n', '1e0', str(1 << 63)]:
            cases.append({'name': 'invalid ' + key + repr(value),
                          'model': compatible_metadata(**{key: value}), 'accept': False})
    native = {'model': 'fixture:local', 'model_digest': 'c' * 64}
    for key, value in [('model_digest', 'c' * 64 + '\n'), ('eval_count', '1\n'),
                       ('provider', None), ('provider', 'openai_compatible')]:
        cases.append({'name': 'native cannot disguise malformed ' + key,
                      'model': {**native, key: value}, 'accept': False})
    return cases


def test_public_metadata_schema_accepts_producer_bytes_and_closes_malformed_branches():
    import jsonschema
    import http_api.local_ai_schema as schema
    assert hasattr(schema, 'MODEL_METADATA_SCHEMA'), 'provider-specific public metadata grammar missing'
    validator = jsonschema.Draft202012Validator(schema.MODEL_METADATA_SCHEMA)
    for case in metadata_wire_cases():
        assert validator.is_valid(json.loads(canonical(case['model']))) == case['accept'], case['name']


def test_browser_metadata_accepts_same_producer_bytes_and_refuses_extra_native_facts():
    cases = [{'name': c['name'], 'wire': canonical(c['model']).decode(), 'accept': c['accept']}
             for c in metadata_wire_cases()]
    cases.append({'name': 'inconsistent usage sum', 'wire': canonical(compatible_metadata(
        prompt_tokens='2', completion_tokens='3', total_tokens='4')).decode(), 'accept': False})
    for mutation in ('getter', 'hidden', 'symbol', 'prototype'):
        cases.append({'name': mutation, 'wire': canonical(compatible_metadata()).decode(),
                      'accept': False, 'mutation': mutation})
    browser_cases(cases)


def test_decimal_wire_schema_and_browser_cover_full_int64_prefix_boundaries():
    import random
    import jsonschema
    from http_api.local_ai_schema import MODEL_METADATA_SCHEMA
    limit = (1 << 63) - 1
    rng = random.Random(731)
    numbers = {0, 1, limit, limit + 1, (1 << 64) - 1}
    for power in range(20):
        numbers.update((10 ** power - 1, 10 ** power, 10 ** power + 1))
    numbers.update(rng.randrange(1 << 64) for _ in range(100))
    validator = jsonschema.Draft202012Validator(MODEL_METADATA_SCHEMA)
    cases = []
    for number in sorted(numbers):
        accepted = 0 <= number <= limit
        model = (model_metadata(NativeReply('{}', compatible_metadata(prompt_tokens=number))) if accepted
                 else compatible_metadata(prompt_tokens=str(number)))
        wire = canonical(model).decode()
        assert validator.is_valid(json.loads(wire)) == accepted, number
        cases.append({'name': 'decimal ' + str(number), 'wire': wire, 'accept': accepted})
    browser_cases(cases)


def test_actual_engine_to_http_adapter_to_verifier_and_browser(monkeypatch):
    import os
    from local_ai.engine import AssistantEngine
    from local_ai.openai_provider import OpenAICompatibleProvider
    from local_ai.resolver import ResolverOwner
    from test_local_ai_contracts import decoder_request
    from test_local_ai_openai_provider import KEY, envelope, peer, response, settings
    from test_local_ai_sources import ACTOR, context
    for name in list(os.environ):
        if name.lower().endswith('_proxy'):
            monkeypatch.delenv(name)
    ctx, resolver, task = context(), ResolverOwner(), None
    deadline = time.monotonic() + 20
    request = decoder_request(samples=[
        {'data': '192.0.2.1 ' + 'x' * 1800, 'expected_ips': ['192.0.2.1'],
         'usage': 'example', 'complete_expected': True},
        {'data': '198.51.100.17 HOLDOUT', 'expected_ips': ['198.51.100.17'],
         'usage': 'validation', 'complete_expected': True}])
    steps = [{'op': 'extract_ip_prefix'}]

    def answer(sock, stop):
        packet = json.loads(requests[0]['body'])
        assert KEY not in requests[0]['body'].decode()
        assert 'HOLDOUT' not in requests[0]['body'].decode()
        schema = json.loads(packet['messages'][0]['content'].split('\nRequired JSON Schema: ', 1)[1])
        properties = schema['oneOf'][0]['properties']
        proposal = {key: properties[key]['const'] for key in ('version', 'kind', 'language', 'snapshot_digest')}
        proposal.update(candidates=[{'steps': steps}], insufficient_reason=None)
        completion = envelope(canonical(proposal).decode())
        completion['choices'][0]['message'].update(annotations=[], reasoning=KEY,
                                                   audio=None, function_call=None, tool_calls=[])
        sock.sendall(response(completion))

    try:
        with peer(answer) as (url, requests):
            ctx.shared_config['local_ai'] = settings(url + '/v1')
            provider = OpenAICompatibleProvider(ctx.shared_config['local_ai'], resolver=resolver)
            task = AssistantEngine(ctx, None).prepare(
                request, {**ACTOR, 'role': 'admin'}, deadline, prompt_mode='json_object')
            wire = task.run(deadline, lambda messages, schema: provider.generate(messages, schema, deadline))
            result = json.loads(wire)
            assert len(requests) == 1 and requests[0]['path'] == '/v1/chat/completions'
            assert requests[0]['headers']['Authorization'] == 'Bearer ' + KEY
            assert KEY not in wire.decode()
            assert result['model']['requested_model'] == 'requested/alias'
            assert result['model']['reported_model'] == 'reported/alias-2026'
            candidate = result['generated']['candidates'][0]
            assert candidate['examples']['results'][0]['passed'] is True
            assert candidate['validation']['results'][0]['passed'] is True
            consume_result_wire(wire, request)
    finally:
        if task is not None:
            task.dispose()
        assert resolver.close(time.monotonic() + 2)
