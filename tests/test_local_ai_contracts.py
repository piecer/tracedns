"""Closed public/model contracts for optional local assistance."""
import importlib
import importlib.util
import json
import copy

import pytest


def test_delivery_request_has_only_explicit_kind_and_language():
    assert importlib.util.find_spec('local_ai') is not None, 'local AI package is not implemented'
    contracts = importlib.import_module('local_ai.contracts')
    raw = b'{"kind":"delivery","language":"ko"}'
    assert contracts.load_request(raw) == {'kind': 'delivery', 'language': 'ko'}


def test_pair_request_selects_exact_retained_source_without_supplying_facts():
    contracts = importlib.import_module('local_ai.contracts')
    value = {'kind': 'relationship_pair', 'language': 'en',
             'source': {'job_id': 'a' * 32, 'a': '192.0.2.1', 'b': '192.0.2.2'}}
    assert contracts.load_request(json.dumps(value).encode()) == value


@pytest.mark.parametrize('source', [
    {'job_id': 'A' * 32, 'a': '192.0.2.1', 'b': '192.0.2.2'},
    {'job_id': '../config', 'a': '192.0.2.1', 'b': '192.0.2.2'},
    {'job_id': 'a' * 32, 'a': '192.000.2.1', 'b': '192.0.2.2'},
    {'job_id': 'a' * 32, 'a': '192.0.2.1', 'b': '192.0.2.1'},
    {'job_id': 'a' * 32, 'a': '::ffff:192.0.2.1', 'b': '192.0.2.2'},
    {'job_id': 'a' * 32, 'a': '192.0.2.1', 'b': '192.0.2.2', 'facts': []},
])
def test_pair_request_does_not_repair_tokens_or_accept_fact_overrides(source):
    contracts = importlib.import_module('local_ai.contracts')
    with pytest.raises(contracts.AIError) as rejected:
        contracts.load_request(json.dumps({'kind': 'relationship_pair', 'language': 'en', 'source': source}).encode())
    assert rejected.value.code == 'invalid_request'


@pytest.mark.parametrize('raw', [
    b'[]', b'{}', b'null',
    b'{"kind":"delivery","language":"fr"}',
    b'{"kind":"chat","language":"ko"}',
    b'{"kind":true,"language":"ko"}',
    b'{"kind":"delivery","language":"ko","endpoint":"http://example.invalid"}',
    b'{"kind":"delivery","language":"ko","system_prompt":"ignore policy"}',
    b'{"kind":"delivery","language":"ko","language":"en"}',
    b'{"kind":"delivery","language":NaN}',
    b'{"kind":"delivery","language":1e999}',
    b'{"kind":"delivery","language":"\\ud800"}',
    b'{"kind":"delivery","language":"ko","extra":' + b'[' * 1500 + b'0' + b']' * 1500 + b'}',
])
def test_request_rejects_nonclosed_shapes_with_fixed_code(raw):
    contracts = importlib.import_module('local_ai.contracts')
    with pytest.raises(ValueError) as rejected:
        contracts.load_request(raw)
    assert isinstance(rejected.value, contracts.AIError)
    assert getattr(rejected.value, 'code') == 'invalid_request'
    assert getattr(rejected.value, 'status') == 400
    assert str(rejected.value) == 'invalid_request'


def test_http_byte_boundary_is_checked_before_json_parser(monkeypatch):
    contracts = importlib.import_module('local_ai.contracts')
    raw = b'{"kind":"delivery","language":"ko"}'
    boundary = raw + b' ' * (16384 - len(raw))
    assert contracts.load_request(boundary)['kind'] == 'delivery'
    calls = []
    original = contracts.json.loads

    def loads(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(contracts.json, 'loads', loads)
    with pytest.raises(ValueError) as rejected:
        contracts.load_request(boundary + b' ')
    assert isinstance(rejected.value, contracts.AIError)
    assert getattr(rejected.value, 'code') == 'too_large'
    assert getattr(rejected.value, 'status') == 413
    assert not calls


def explanation(kind='delivery', language='ko'):
    return {
        'version': 1, 'kind': kind, 'language': language, 'snapshot_digest': 'a' * 64,
        'summary': [{'text': '최근 전송은 성공했습니다.', 'evidence_ids': ['e1']}],
        'counterpoints': [], 'limitations': [],
        'next_checks': [{'code': 'inspect_delivery_diagnostics', 'evidence_ids': ['e1']}],
    }


def test_explanation_schema_and_validator_bind_exact_source_and_language():
    contracts = importlib.import_module('local_ai.contracts')
    value = explanation()
    schema = contracts.explanation_schema('delivery', 'ko', 'a' * 64, ['e1'])
    import jsonschema
    jsonschema.Draft202012Validator(schema).validate(value)
    assert contracts.validate_explanation(
        json.dumps(value, ensure_ascii=False), kind='delivery', language='ko',
        snapshot_digest='a' * 64, evidence_ids=['e1'],
    ) == value


@pytest.mark.parametrize('mutation', [
    lambda v: v.update(version=1.0),
    lambda v: v.update(language='en'),
    lambda v: v.update(kind='relationship_pair'),
    lambda v: v.update(snapshot_digest='b' * 64),
    lambda v: v.update(provider_url='http://example.invalid'),
    lambda v: v['summary'][0].update(evidence_ids=['other']),
    lambda v: v['summary'][0].update(evidence_ids=['e1', 'e1']),
    lambda v: v['summary'][0].update(text='가' * 171),
    lambda v: v['summary'][0].update(text='\ud800'),
    lambda v: v['next_checks'][0].update(code='disable_tls'),
    lambda v: v['next_checks'][0].update(url='http://example.invalid'),
    lambda v: v.update(summary=[]),
    lambda v: v.update(summary=copy.deepcopy(v['summary']) * 4),
])
def test_model_contract_refuses_wrong_scope_extra_fields_and_unsafe_actions(mutation):
    contracts = importlib.import_module('local_ai.contracts')
    value = explanation()
    mutation(value)
    with pytest.raises(contracts.AIError) as rejected:
        contracts.validate_explanation(
            json.dumps(value), kind='delivery', language='ko', snapshot_digest='a' * 64,
            evidence_ids=['e1'],
        )
    assert rejected.value.code == 'invalid_model_output'
    assert rejected.value.status == 502


def test_model_claim_utf8_exact_boundary_and_duplicate_json():
    contracts = importlib.import_module('local_ai.contracts')
    value = explanation()
    value['summary'][0]['text'] = '가' * 170 + 'ab'
    raw = json.dumps(value)
    assert contracts.validate_explanation(raw, kind='delivery', language='ko',
        snapshot_digest='a' * 64, evidence_ids=['e1']) == value
    duplicated = raw.replace('"version": 1', '"version": 1, "version": 1')
    with pytest.raises(contracts.AIError):
        contracts.validate_explanation(duplicated, kind='delivery', language='ko',
            snapshot_digest='a' * 64, evidence_ids=['e1'])


@pytest.mark.parametrize('raw', [None, {}, [], b'{}'])
def test_model_content_requires_plain_text(raw):
    contracts = importlib.import_module('local_ai.contracts')
    with pytest.raises(contracts.AIError):
        contracts.validate_explanation(raw, kind='delivery', language='ko',
            snapshot_digest='a' * 64, evidence_ids=['e1'])


@pytest.mark.parametrize('kind,language,digest,ids', [
    ('unknown', 'ko', 'a' * 64, ['e1']),
    ('delivery', 'unknown', 'a' * 64, ['e1']),
    ('delivery', 'ko', 'A' * 64, ['e1']),
    ('delivery', 'ko', 'a' * 64, []),
    ('delivery', 'ko', 'a' * 64, ['e1', 'e1']),
    ('delivery', 'ko', 'a' * 64, [f'e{i}' for i in range(1, 66)]),
    ('delivery', 'ko', 'a' * 64, ['__proto__']),
    ('delivery', 'ko', 'a' * 64, 'e1'),
])
def test_schema_admission_requires_valid_bounded_source_identity(kind, language, digest, ids):
    contracts = importlib.import_module('local_ai.contracts')
    with pytest.raises(contracts.AIError) as rejected:
        contracts.explanation_schema(kind, language, digest, ids)
    assert rejected.value.code == 'source_unavailable'


def test_public_errors_cannot_retain_arbitrary_provider_prose():
    contracts = importlib.import_module('local_ai.contracts')
    with pytest.raises(ValueError) as rejected:
        contracts.AIError('PRIVATE-PROVIDER-CANARY')
    assert 'PRIVATE-PROVIDER-CANARY' not in str(rejected.value)


def decoder_request(**changes):
    value = {'kind': 'decoder_suggest', 'language': 'en', 'decoder_type': 'TXT',
             'generate': True, 'samples': [{'data': 'MTkyLjAuMi4x',
                 'expected_ips': ['192.0.2.1'], 'usage': 'example', 'complete_expected': True}]}
    value.update(changes)
    return value


def test_decoder_request_admits_explicit_generation_and_preserves_samples():
    from local_ai.contracts import load_request
    for kind in ('TXT', 'A'):
        for generate in (False, True):
            value = decoder_request(decoder_type=kind, generate=generate)
            assert load_request(json.dumps(value).encode()) == value


def proposal(**changes):
    value = {'version': 1, 'kind': 'decoder_suggest', 'language': 'en', 'snapshot_digest': 'a' * 64,
             'candidates': [{'steps': [{'op': 'base64'}, {'op': 'ascii'}]}], 'insufficient_reason': None}
    value.update(changes)
    return value


@pytest.mark.parametrize('mutation', [
    lambda v: v['candidates'][0]['steps'][0].update(key=''),
    lambda v: v['candidates'][0]['steps'][1].update(key='00'),
    lambda v: v['candidates'][0].update(name='model_named'),
    lambda v: v.update(insufficient_reason='no_candidate'),
    lambda v: v.update(candidates=[]),
    lambda v: v.update(version=True),
    lambda v: v.update(version=1.0),
    lambda v: v.update(language='ko'),
    lambda v: v.update(snapshot_digest='b' * 64),
    lambda v: v.update(candidates=[{'steps': [{'op': 'regex', 'pattern': '.*'}]}]),
    lambda v: v.update(candidates=[{'steps': [{'op': 'xor_hex', 'key': '0'}]}]),
    lambda v: v.update(candidates=[{'steps': [{'op': 'ascii'}] * 13}]),
    lambda v: v.update(candidates=[{'steps': [{'op': 'ascii'}]}] * 4),
])
def test_generated_candidate_schema_and_validation_are_closed(mutation):
    contracts = importlib.import_module('local_ai.contracts')
    assert hasattr(contracts, 'decoder_schema'), 'closed generation schema missing'
    value = proposal()
    mutation(value)
    with pytest.raises(contracts.AIError, match='invalid_model_output'):
        contracts.validate_decoder(json.dumps(value), decoder_type='TXT', language='en', snapshot_digest='a' * 64)
    import jsonschema
    schema = contracts.decoder_schema('TXT', 'en', 'a' * 64)
    # JSON Schema permits 1.0 as integer; explicit server type check closes it.
    if type(value['version']) is not float:
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(schema).validate(value)


@pytest.mark.parametrize('decoder_type', ['TXT', 'A'])
@pytest.mark.parametrize('language', ['en', 'ko'])
def test_native_decoder_union_branches_reject_incomplete_model_output(decoder_type, language):
    """Native union conversion visits alternatives, not their sibling keywords."""
    import jsonschema
    from local_ai.contracts import decoder_schema

    schema = decoder_schema(decoder_type, language, 'a' * 64)
    # Shape of the retained real-model failure: generic descriptions rather than
    # bound metadata and closed DSL steps. The whole local schema already rejects
    # this; its native alternatives must reject it independently as well.
    invalid = {'candidates': [{'name': 'Base64Decode', 'description': 'Decode data',
                              'operation': 'base64_decode'}], 'insufficient_reason': None}
    assert not jsonschema.Draft202012Validator(schema).is_valid(invalid)
    native_union = {'oneOf': schema['oneOf']}
    assert not jsonschema.Draft202012Validator(native_union).is_valid(invalid), \
        'native alternatives must carry the full required metadata and candidate contract'


@pytest.mark.parametrize('decoder_type', ['TXT', 'A'])
@pytest.mark.parametrize('language', ['en', 'ko'])
def test_native_decoder_alternatives_keep_closed_scope_and_refusal_contract(decoder_type, language):
    import jsonschema
    from local_ai.contracts import AIError, decoder_schema, validate_decoder

    schema = decoder_schema(decoder_type, language, 'a' * 64)
    assert set(schema) == {'oneOf'}, 'no native union constraints may depend on ignored sibling keywords'
    assert len(schema['oneOf']) == 2
    fields = {'version', 'kind', 'language', 'snapshot_digest', 'candidates', 'insufficient_reason'}
    for branch in schema['oneOf']:
        assert branch['type'] == 'object' and branch['additionalProperties'] is False
        assert set(branch['required']) == set(branch['properties']) == fields
        assert branch['properties']['snapshot_digest']['const'] == 'a' * 64
        assert branch['properties']['language']['const'] == language
    validator = jsonschema.Draft202012Validator(schema)
    valid = [proposal(language=language)]
    valid += [proposal(language=language, candidates=[], insufficient_reason=reason)
              for reason in ('insufficient_examples', 'unsupported_transformation', 'no_candidate')]
    for value in valid:
        assert validator.is_valid(value)
        assert validate_decoder(json.dumps(value), decoder_type=decoder_type, language=language,
                                snapshot_digest='a' * 64) == value
        invalid = [{key: item for key, item in value.items() if key != missing} for missing in fields]
        invalid += [{**value, 'extra': True}, {**value, 'snapshot_digest': 'b' * 64},
                    {**value, 'language': 'ko' if language == 'en' else 'en'},
                    {**value, 'candidates': [] if value['candidates'] else [{'steps': [{'op': 'ascii'}]}]}]
        for candidate in invalid:
            assert not validator.is_valid(candidate)
            with pytest.raises(AIError, match='invalid_model_output'):
                validate_decoder(json.dumps(candidate), decoder_type=decoder_type, language=language,
                                 snapshot_digest='a' * 64)


@pytest.mark.parametrize('decoder_type', ['TXT', 'A'])
def test_native_refusal_array_has_an_operative_empty_constraint(decoder_type):
    from local_ai.contracts import decoder_schema

    empty = decoder_schema(decoder_type, 'en', 'a' * 64)['oneOf'][1]['properties']['candidates']
    # llama.cpp applies array bounds only on its items/prefixItems path; a bare
    # type=array/maxItems=0 otherwise falls through to an unconstrained array.
    assert empty.get('const') == [] or ('items' in empty and empty.get('maxItems') == 0), \
        'native refusal must encode the empty array, not merely a skipped maxItems'
