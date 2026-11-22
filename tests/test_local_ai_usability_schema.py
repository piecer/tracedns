"""Public schema checks over exact pure-producer outputs, not HTTP/model acceptance."""
import copy
import hashlib
import json

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from http_api import local_ai_schema as wire
from local_ai import decoder_input
from local_ai.contracts import AIError, decoder_schema
from local_ai.engine import prompt
from local_ai import facts_summary
from test_local_ai_decoder_input import canonical, example, snapshot
from test_local_ai_facts_summary import delivery_snapshot, pair_snapshot, record


def validator(name):
    schema = getattr(wire, name, None)
    assert schema is not None, f'public {name} is missing'
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def model_input(rows=None, kind='TXT', language='en'):
    original = snapshot(rows if rows is not None else [example('192.0.2.1|' + 'x' * 1500)], kind)
    digest = hashlib.sha256(canonical(original)).hexdigest()
    schema = decoder_schema(kind, language, digest)
    messages = prompt(decoder_input.project_examples(original), schema)
    checked = canonical({'messages': messages, 'schema': schema})
    result = decoder_input.build_model_input(original, digest, messages, schema, checked)
    return original, result


def mutated(value, path, replacement):
    result = copy.deepcopy(value)
    parent = result
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = replacement
    return result


@pytest.mark.parametrize('kind', ['TXT', 'A'])
@pytest.mark.parametrize('language', ['en', 'ko'])
@pytest.mark.parametrize('rows', [
    [example('')],
    [example('192.0.2.1')],
    [example('x' * 1024)],
    [example('x' * 1025)],
    [example('한' * 600), example('🙂' * 400), example('short')],
    [example(str(index) * 1000) for index in range(6)],
])
def test_model_input_accepts_exact_producer_output(kind, language, rows):
    original, result = model_input(rows, kind, language)
    before = copy.deepcopy(result)
    validator('MODEL_INPUT_SCHEMA').validate(result)
    assert result == before
    assert result['source_snapshot_digest'] == hashlib.sha256(canonical(original)).hexdigest()
    assert result['coverage']['shown_utf8_bytes'] <= decoder_input.MAX_MODEL_DATA_BYTES


@pytest.mark.parametrize('path,replacement', [
    (('version',), True), (('version',), 2),
    (('policy',), 'decoder_examples_utf8_v2'),
    (('source_snapshot_digest',), 'A' * 64),
    (('messages_schema_digest',), 'a' * 63),
    (('messages_schema_bytes',), 16385), (('messages_schema_bytes',), -1),
    (('messages_schema_bytes',), True),
    (('view', 'version'), 2), (('view', 'kind'), 'delivery'),
    (('view', 'decoder_type'), 'AAAA'), (('view', 'examples'), []),
    (('view', 'examples', 0, 'usage'), 'validation'),
    (('view', 'examples', 0, 'complete_expected'), 'true'),
    (('view', 'examples', 0, 'expected_ips'), []),
    (('view', 'examples', 0, 'expected_ips'), ['192.0.2.1', '192.0.2.1']),
    (('view', 'examples', 0, 'expected_ips'), ['0192.0.2.1']),
    (('view', 'examples', 0, 'excerpt', 'original_utf8_bytes'), 2049),
    (('view', 'examples', 0, 'excerpt', 'omitted_utf8_bytes'), 0),
    (('view', 'examples', 0, 'excerpt', 'prefix'), 'x' * 769),
    (('view', 'examples', 0, 'excerpt', 'suffix'), 'x' * 257),
    (('coverage', 'original_utf8_bytes'), 8193),
    (('coverage', 'shown_utf8_bytes'), 1025),
    (('coverage', 'omitted_utf8_bytes'), -1),
    (('coverage', 'complete_examples'), 7),
    (('coverage', 'excerpted_examples'), 1.5),
])
def test_model_input_rejects_bad_fields(path, replacement):
    _, result = model_input()
    assert not validator('MODEL_INPUT_SCHEMA').is_valid(mutated(result, path, replacement))


@pytest.mark.parametrize('path', [(), ('view',), ('view', 'examples', 0),
                                 ('view', 'examples', 0, 'excerpt'), ('coverage',)])
def test_model_input_requires_exact_keys_at_each_object(path):
    _, result = model_input()
    target = result
    for key in path:
        target = target[key]
    check = validator('MODEL_INPUT_SCHEMA')
    for key in target:
        bad = copy.deepcopy(result)
        node = bad
        for segment in path:
            node = node[segment]
        del node[key]
        assert not check.is_valid(bad), (path, key)
    assert not check.is_valid(mutated(result, (*path, 'unexpected'), None))


def test_model_view_complete_and_excerpt_rows_are_disjoint():
    _, result = model_input([example('short'), example('x' * 1500)])
    check = validator('MODEL_INPUT_SCHEMA')
    check.validate(result)
    assert not check.is_valid(mutated(result, ('view', 'examples', 1, 'data'), 'not the original'))
    assert not check.is_valid(mutated(result, ('view', 'examples', 0, 'excerpt'),
                                     result['view']['examples'][1]['excerpt']))
    assert not check.is_valid(mutated(result, ('view', 'examples', 0, 'data'), 'x' * 1025))
    assert not check.is_valid(mutated(result, ('view', 'examples'), result['view']['examples'] * 4))


def test_model_input_documents_byte_budgets_not_character_or_http_proof():
    schema = validator('MODEL_INPUT_SCHEMA').schema
    assert schema['x-max-encoded-bytes'] == decoder_input.MAX_MODEL_INPUT_BYTES
    assert schema['x-max-metadata-bytes'] == decoder_input.MAX_INPUT_METADATA_BYTES
    view = schema['properties']['view']
    assert view['x-max-encoded-bytes'] == decoder_input.MAX_SOURCE_BYTES
    assert view['x-max-labels-bytes'] == decoder_input.MAX_LABEL_BYTES
    assert view['x-max-metadata-bytes'] == decoder_input.MAX_VIEW_METADATA_BYTES
    assert schema['properties']['messages_schema_bytes']['maximum'] == decoder_input.MAX_MESSAGES_SCHEMA_BYTES
    description = schema['description']
    for text in ('canonical', 'messages', 'schema', 'HTTP', 'options', 'tokens', 'latency'):
        assert text in description


EXPECTED_CODES = {
    'relationship_pair': {
        'summary': ('pair_assessment', 'pair_signals'),
        'counterpoints': (),
        'limitations': ('pair_scope', 'pair_coverage', 'pair_attribution'),
    },
    'delivery': {
        'summary': ('delivery_overview', 'delivery_teams', 'delivery_misp'),
        'counterpoints': ('delivery_recovery',),
        'limitations': ('delivery_snapshot_scope', 'delivery_capture_times', 'delivery_coverage', 'delivery_lookup'),
    },
}


def summary(kind='relationship_pair', language='en', history=False):
    original = (pair_snapshot() if kind == 'relationship_pair' else
                delivery_snapshot(record('acked', 112), record('failed', 111, 'provider_tls')) if history else
                delivery_snapshot())
    digest = hashlib.sha256(canonical(original)).hexdigest()
    return original, facts_summary.build_summary(original, language, digest)


@pytest.mark.parametrize('kind', EXPECTED_CODES)
@pytest.mark.parametrize('language', ['en', 'ko'])
@pytest.mark.parametrize('history', [False, True])
def test_facts_summary_accepts_exact_localized_producer_output(kind, language, history):
    original, result = summary(kind, language, history)
    before = copy.deepcopy(result)
    validator('FACTS_SUMMARY_SCHEMA').validate(result)
    assert result == before
    assert result['snapshot_digest'] == hashlib.sha256(canonical(original)).hexdigest()
    assert len(canonical(result)) <= facts_summary.MAX_SUMMARY_BYTES
    ids = {fact['id'] for fact in original['facts']}
    for section, codes in EXPECTED_CODES[kind].items():
        assert facts_summary.SUMMARY_CODES[kind][section] == codes
        assert tuple(claim['code'] for claim in result[section]) == codes
        for claim in result[section]:
            assert 1 <= len(claim['text'].encode('utf-8')) <= facts_summary.MAX_CLAIM_BYTES
            assert set(claim['evidence_ids']) <= ids


@pytest.mark.parametrize('kind', EXPECTED_CODES)
@pytest.mark.parametrize('path,replacement', [
    (('version',), True), (('version',), 2), (('kind',), 'decoder_suggest'),
    (('language',), 'fr'), (('snapshot_digest',), 'f' * 63),
    (('summary', 0, 'text'), ''), (('summary', 0, 'text'), 'x' * 513),
    (('summary', 0, 'text'), None), (('summary', 0, 'evidence_ids'), []),
    (('summary', 0, 'evidence_ids'), ['e0']), (('summary', 0, 'evidence_ids'), ['e1000']),
    (('summary', 0, 'evidence_ids'), ['e1', 'e1']),
    (('summary', 0, 'evidence_ids'), ['e1', 'e2', 'e3', 'e4']),
    (('summary', 0, 'evidence_ids'), [1]),
    (('next_checks',), []),
])
def test_facts_summary_rejects_malformed_claims_and_model_only_fields(kind, path, replacement):
    _, result = summary(kind)
    assert not validator('FACTS_SUMMARY_SCHEMA').is_valid(mutated(result, path, replacement))


@pytest.mark.parametrize('kind', EXPECTED_CODES)
def test_facts_summary_requires_every_exact_object_field(kind):
    _, result = summary(kind)
    check = validator('FACTS_SUMMARY_SCHEMA')
    for key in result:
        bad = copy.deepcopy(result)
        del bad[key]
        assert not check.is_valid(bad), key
    assert not check.is_valid({**result, 'extra': None})
    for section in EXPECTED_CODES[kind]:
        for index, claim in enumerate(result[section]):
            for key in claim:
                bad = copy.deepcopy(result)
                del bad[section][index][key]
                assert not check.is_valid(bad), (section, key)
            assert not check.is_valid(mutated(result, (section, index, 'extra'), None))


@pytest.mark.parametrize('kind', EXPECTED_CODES)
@pytest.mark.parametrize('section', ['summary', 'counterpoints', 'limitations'])
def test_facts_summary_requires_mandatory_codes_once_in_producer_order(kind, section):
    _, result = summary(kind)
    check = validator('FACTS_SUMMARY_SCHEMA')
    claims = result[section]
    if not claims:
        assert not check.is_valid(mutated(result, (section,), [result['summary'][0]]))
        return
    assert not check.is_valid(mutated(result, (section,), claims[:-1]))
    assert not check.is_valid(mutated(result, (section,), claims + claims[:1]))
    if len(claims) > 1:
        assert not check.is_valid(mutated(result, (section,), list(reversed(claims))))
        assert not check.is_valid(mutated(result, (section, 1, 'code'), claims[0]['code']))
    other_kind = next(key for key in EXPECTED_CODES if key != kind)
    for index in range(len(claims)):
        for code in ('invented_code', EXPECTED_CODES[other_kind]['summary'][0]):
            assert not check.is_valid(mutated(result, (section, index, 'code'), code))


def test_facts_summary_declares_utf8_and_whole_sidecar_caps():
    schema = validator('FACTS_SUMMARY_SCHEMA').schema
    assert schema['x-max-encoded-bytes'] == facts_summary.MAX_SUMMARY_BYTES
    for variant in schema['oneOf']:
        for section in ('summary', 'counterpoints', 'limitations'):
            array = variant['properties'][section]
            for claim in array.get('prefixItems', []):
                text = claim['properties']['text']
                assert text['minLength'] == 1
                assert text['maxLength'] == facts_summary.MAX_CLAIM_BYTES
                assert text['x-max-utf8-bytes'] == facts_summary.MAX_CLAIM_BYTES


def decoder_result(generate=True, kind='TXT', language='en', rows=None, abstain=False):
    """Compose the public envelope; all nested reports/sidecars use real pure producers."""
    from local_ai.contracts import validate_decoder
    from local_ai.decoder import capture_catalog
    from local_ai.decoder_worker import verify
    from local_ai.engine import model_metadata
    from local_ai.provider import NativeReply

    original, shown = model_input(rows if rows is not None else [example('192.0.2.1')], kind, language)
    samples = original['examples'] + [{**example('198.51.100.17', ['198.51.100.17']), 'usage': 'validation'}]
    catalog = verify({'kind': kind, 'mode': 'catalog', 'samples': samples,
                      'catalog': capture_catalog({}, kind)})
    result = {'snapshot': original, 'snapshot_digest': shown['source_snapshot_digest'], 'source_revision': 7,
              'model': None, 'catalog': catalog, 'generated': None, 'proposal': None, 'model_input': None}
    if generate:
        raw = json.dumps({'version': 1, 'kind': 'decoder_suggest', 'language': language,
                          'snapshot_digest': result['snapshot_digest'],
                          'candidates': [] if abstain else [{'steps': [{'op': 'ascii'}]}],
                          'insufficient_reason': 'no_candidate' if abstain else None})
        proposal = validate_decoder(raw, decoder_type=kind, language=language,
                                    snapshot_digest=result['snapshot_digest'])
        result.update(model=model_metadata(NativeReply(raw, {'model': 'fixture:local', 'model_digest': 'c' * 64})),
                      generated=verify({'kind': kind, 'mode': 'generated', 'samples': samples,
                                        'candidates': proposal['candidates']}),
                      proposal=proposal, model_input=shown)
    return result


def explanation_result(kind='relationship_pair', language='en'):
    from local_ai.contracts import explanation_schema, validate_explanation
    from local_ai.engine import model_metadata
    from test_local_ai_engine import explanation_reply

    original, facts = summary(kind, language, history=True)
    ids = [fact['id'] for fact in original['facts']]
    schema = explanation_schema(kind, language, facts['snapshot_digest'], ids)
    reply = explanation_reply(prompt(original, schema), schema)
    interpretation = validate_explanation(reply.content, kind=kind, language=language,
                                         snapshot_digest=facts['snapshot_digest'], evidence_ids=ids)
    return {'snapshot': original, 'snapshot_digest': facts['snapshot_digest'], 'source_revision': 7,
            'model': model_metadata(reply), 'interpretation': interpretation, 'facts_summary': facts}


def job(result, language='en'):
    return {'job_id': 'b' * 32, 'kind': result['snapshot']['kind'], 'language': language,
            'status': 'completed', 'created_at': 1, 'deadline_at': 120001,
            'audit_status': 'success', 'error': None, 'result': result, 'cancel_requested': False}


@pytest.mark.parametrize('mode,field', [('catalog', 'model_input'), ('generated', 'model_input'),
                                        ('relationship_pair', 'facts_summary'), ('delivery', 'facts_summary')])
def test_job_result_requires_new_sidecar_no_legacy_bypass(mode, field):
    result = decoder_result(mode == 'generated') if mode in ('catalog', 'generated') else explanation_result(mode)
    check = validator('JOB_SCHEMA')
    check.validate(job(result))
    del result[field]
    assert not check.is_valid(job(result)), f'{mode} silently accepts old result shape'


@pytest.mark.parametrize('kind', ['TXT', 'A'])
@pytest.mark.parametrize('language', ['en', 'ko'])
@pytest.mark.parametrize('generate', [False, True])
def test_decoder_public_results_keep_original_report_and_null_contract(kind, language, generate):
    result = decoder_result(generate, kind, language)
    before = copy.deepcopy(result)
    validator('RESULT_SCHEMA').validate(result)
    validator('JOB_SCHEMA').validate(job(result, language))
    cancelled = {**job(result, language), 'cancellation_requested': False, 'cancellation_confirmed': False}
    validator('CANCEL_SCHEMA').validate(cancelled)
    assert result == before
    assert '198.51.100.17' not in json.dumps(result['snapshot'])
    assert result['catalog']['validation_count'] == 1
    for field in ('model', 'generated', 'proposal', 'model_input'):
        assert (result[field] is not None) is generate
    if generate:
        assert result['generated']['candidates'][0]['validation']['passed'] == 1
        assert '198.51.100.17' not in json.dumps(result['model_input'])
    for field in result:
        bad = copy.deepcopy(result)
        del bad[field]
        assert not validator('RESULT_SCHEMA').is_valid(bad), field
    assert not validator('RESULT_SCHEMA').is_valid({**result, 'facts_summary': None})


@pytest.mark.parametrize('kind', EXPECTED_CODES)
@pytest.mark.parametrize('language', ['en', 'ko'])
def test_explanation_public_results_preserve_free_v1_interpretation(kind, language):
    result = explanation_result(kind, language)
    before = copy.deepcopy(result)
    validator('RESULT_SCHEMA').validate(result)
    validator('JOB_SCHEMA').validate(job(result, language))
    validator('CANCEL_SCHEMA').validate({**job(result, language), 'cancellation_requested': False,
                                       'cancellation_confirmed': False})
    assert result == before
    assert result['interpretation']['version'] == 1
    assert 'code' not in result['interpretation']['summary'][0]
    for field in result:
        bad = copy.deepcopy(result)
        del bad[field]
        assert not validator('RESULT_SCHEMA').is_valid(bad), field
    assert not validator('RESULT_SCHEMA').is_valid({**result, 'model_input': None})
    assert not validator('RESULT_SCHEMA').is_valid({**result, 'facts_summary': None})


@pytest.mark.parametrize('field', ['model', 'generated', 'proposal', 'model_input'])
def test_decoder_rejects_mixed_catalog_only_and_generated_results(field):
    result = decoder_result()
    check = validator('RESULT_SCHEMA')
    assert not check.is_valid({**result, field: None})
    catalog_only = decoder_result(False)
    assert not check.is_valid({**catalog_only, field: result[field]})


@pytest.mark.parametrize('kind', EXPECTED_CODES)
def test_job_and_result_reject_foreign_kind_or_language(kind):
    result = explanation_result(kind)
    other = next(key for key in EXPECTED_CODES if key != kind)
    check = validator('JOB_SCHEMA')
    assert not check.is_valid({**job(result), 'kind': other})
    assert not check.is_valid({**job(result), 'language': 'ko'})
    for field in ('facts_summary', 'interpretation'):
        assert not check.is_valid(job(mutated(result, (field, 'kind'), other)))
        assert not check.is_valid(job(mutated(result, (field, 'language'), 'ko')))
    assert not check.is_valid(job(mutated(result, ('facts_summary', 'summary', 0, 'code'), 'invented')))
    decoder = decoder_result()
    assert not check.is_valid(job(mutated(decoder, ('model_input', 'view', 'decoder_type'), 'A')))
    assert not check.is_valid({**job(decoder), 'language': 'ko'})
    assert not check.is_valid(job(mutated(decoder, ('model_input', 'policy'), 'foreign')))


@pytest.mark.parametrize('status', wire.STATES)
@pytest.mark.parametrize('audit_status', ['pending', 'success', 'failed'])
def test_job_keeps_null_result_through_nonpublication_states(status, audit_status):
    value = job(explanation_result())
    value.update(status=status, audit_status=audit_status, result=None)
    validator('JOB_SCHEMA').validate(value)
    value['result'] = explanation_result()
    assert validator('JOB_SCHEMA').is_valid(value) is (status == 'completed' and audit_status == 'success')


def test_errored_job_never_has_result_and_generic_objects_no_longer_bypass_schema():
    value = job(explanation_result())
    value['error'] = 'audit_unavailable'
    assert not validator('JOB_SCHEMA').is_valid(value)
    value.update(error=None, result={})
    assert not validator('JOB_SCHEMA').is_valid(value)


@pytest.mark.parametrize('abstain', [False, True])
def test_long_original_and_abstaining_proposal_keep_model_input(abstain):
    rows = [example('192.0.2.1|' + '한' * 600)]
    result = decoder_result(rows=rows, abstain=abstain)
    validator('JOB_SCHEMA').validate(job(result))
    assert result['snapshot']['examples'] == rows
    assert 'data' not in result['model_input']['view']['examples'][0]
    assert result['model_input']['coverage']['omitted_utf8_bytes'] > 0
    assert result['model_input']['source_snapshot_digest'] == result['snapshot_digest']
    if abstain:
        assert result['proposal']['candidates'] == result['generated']['candidates'] == []
        assert result['model_input'] is not None


VALID_EVIDENCE_IDS = ('e1', 'e12', 'e999')
INVALID_EVIDENCE_IDS = (
    'e1\n', 'e12\n', 'e999\n', 'e1\r', 'e1\r\n', 'e1\u2028', 'e1\u2029',
    '\ne1', ' e1', 'e1 ', 'e1x', 'e0', 'e01', 'e1000', 'e١', 'e１', '', 'e',
)


@pytest.mark.parametrize('evidence_id', VALID_EVIDENCE_IDS)
def test_facts_summary_preserves_complete_evidence_id_tokens(evidence_id):
    original = pair_snapshot()
    assert evidence_id not in {fact['id'] for fact in original['facts'][1:]}
    original['facts'][0]['id'] = evidence_id
    digest = hashlib.sha256(canonical(original)).hexdigest()
    result = facts_summary.build_summary(original, 'en', digest)
    assert result['summary'][0]['evidence_ids'] == [evidence_id]
    validator('FACTS_SUMMARY_SCHEMA').validate(result)


@pytest.mark.parametrize('kind', EXPECTED_CODES)
@pytest.mark.parametrize('evidence_id', INVALID_EVIDENCE_IDS)
def test_facts_summary_rejects_incomplete_evidence_id_tokens_like_producer(kind, evidence_id):
    original, result = summary(kind)
    check = validator('FACTS_SUMMARY_SCHEMA')
    check.validate(result)
    bad_source = mutated(original, ('facts', 0, 'id'), evidence_id)
    # Recompute the commitment so rejection cannot be a stale-digest accident.
    digest = hashlib.sha256(canonical(bad_source)).hexdigest()
    with pytest.raises(AIError, match='^source_unavailable$'):
        facts_summary.build_summary(bad_source, 'en', digest)
    assert not check.is_valid(mutated(result, ('summary', 0, 'evidence_ids', 0), evidence_id))


@pytest.mark.parametrize('kind', EXPECTED_CODES)
@pytest.mark.parametrize('field', [
    ('facts_summary', 'summary', 0, 'evidence_ids', 0), ('snapshot', 'facts', 0, 'id'),
], ids=['summary-citation', 'snapshot-fact'])
@pytest.mark.parametrize('path,method,status,cancel', [
    ('/ai/jobs', 'post', '202', False),
    ('/ai/jobs/{job_id}', 'get', '200', False),
    ('/ai/jobs/{job_id}/cancel', 'post', '200', True),
], ids=['create', 'read', 'cancel'])
def test_generated_openapi_rejects_incomplete_evidence_id_tokens(kind, field, path, method, status, cancel):
    from pathlib import Path
    from http_api.openapi import openapi_document

    document = json.loads((Path(__file__).resolve().parents[1] / 'docs/openapi.json').read_bytes())
    assert document == openapi_document()
    schema = document['paths'][path][method]['responses'][status]['content']['application/json']['schema']
    Draft202012Validator.check_schema(schema)
    check = Draft202012Validator(schema, format_checker=FormatChecker())
    value = job(explanation_result(kind))
    if cancel:
        value.update(cancellation_requested=False, cancellation_confirmed=False)
    check.validate(value)
    for evidence_id in INVALID_EVIDENCE_IDS:
        assert not check.is_valid(mutated(value, ('result', *field), evidence_id)), repr(evidence_id)


def test_evidence_id_pattern_uses_ecmascript_complete_token_matching():
    import subprocess

    tokens = [*VALID_EVIDENCE_IDS, *INVALID_EVIDENCE_IDS]
    completed = subprocess.run(
        ['node', '-e', "const fs = require('node:fs'); "
         "const {pattern, tokens} = JSON.parse(fs.readFileSync(0, 'utf8')); "
         "console.log(JSON.stringify(tokens.map(token => new RegExp(pattern).test(token))));"],
        input=json.dumps({'pattern': wire.EVIDENCE_ID['pattern'], 'tokens': tokens}),
        text=True, capture_output=True, check=True, timeout=10,
    )
    assert json.loads(completed.stdout) == [True] * len(VALID_EVIDENCE_IDS) + [False] * len(INVALID_EVIDENCE_IDS)


def test_generated_openapi_is_byte_fresh_and_embeds_current_result_schemas():
    from pathlib import Path
    from http_api.openapi import openapi_document

    document = openapi_document()
    generated = (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode('utf-8')
    root = Path(__file__).resolve().parents[1]
    fresh = (root / 'docs/openapi.json').read_bytes() == generated
    assert fresh, 'regenerate using python -m http_api.openapi'
    examples = [job(decoder_result(False)), job(decoder_result()),
                job(explanation_result()), job(explanation_result('delivery'))]
    for path, method, status, name in [('/ai/jobs', 'post', '202', 'JOB_SCHEMA'),
                                       ('/ai/jobs/{job_id}', 'get', '200', 'JOB_SCHEMA'),
                                       ('/ai/jobs/{job_id}/cancel', 'post', '200', 'CANCEL_SCHEMA')]:
        schema = document['paths'][path][method]['responses'][status]['content']['application/json']['schema']
        assert schema == getattr(wire, name)
        Draft202012Validator.check_schema(schema)
        check = Draft202012Validator(schema, format_checker=FormatChecker())
        for value in examples:
            if name == 'CANCEL_SCHEMA':
                value = {**value, 'cancellation_requested': False, 'cancellation_confirmed': False}
            check.validate(value)
            missing = copy.deepcopy(value)
            missing['result'].pop('model_input' if missing['kind'] == 'decoder_suggest' else 'facts_summary')
            assert not check.is_valid(missing)
    # Returning a document must not allow a caller to mutate the schema registry.
    document['paths']['/ai/jobs']['post']['responses']['202']['content']['application/json']['schema'].clear()
    assert openapi_document()['paths']['/ai/jobs']['post']['responses']['202']['content']['application/json']['schema'] == wire.JOB_SCHEMA
