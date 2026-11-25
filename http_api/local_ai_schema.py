"""Documented local-AI wire grammar; task validators also enforce byte budgets."""
from local_ai.contracts import ERROR_STATUS
from local_ai.decoder_input import (
    MAX_INPUT_METADATA_BYTES, MAX_LABEL_BYTES, MAX_MESSAGES_SCHEMA_BYTES,
    MAX_MODEL_DATA_BYTES, MAX_MODEL_INPUT_BYTES, MAX_SOURCE_BYTES,
    MAX_VIEW_METADATA_BYTES, POLICY,
)
from local_ai.facts_summary import MAX_CLAIM_BYTES, MAX_SUMMARY_BYTES, SUMMARY_CODES


def closed(properties):
    return {'type': 'object', 'properties': properties, 'required': list(properties),
            'additionalProperties': False}


KINDS = ['decoder_suggest', 'relationship_pair', 'delivery']
STATES = ['queued', 'running', 'cancel_pending', 'completed', 'failed', 'cancelled']
JOB_ID = {'type': 'string', 'pattern': '^[a-f0-9]{32}$', 'minLength': 32, 'maxLength': 32}
LANGUAGE = {'type': 'string', 'enum': ['ko', 'en']}
IP = {'type': 'string', 'format': 'ipv4', 'minLength': 7, 'maxLength': 15,
      'description': 'Canonical dotted-decimal IPv4 only; never normalized or contacted.'}
SAMPLE = closed({'data': {'type': 'string', 'maxLength': 2048, 'description': 'Raw string; also <=2048 UTF-8 bytes. No trimming.'},
                 'expected_ips': {'type': 'array', 'minItems': 1, 'maxItems': 8, 'uniqueItems': True, 'items': IP},
                 'usage': {'type': 'string', 'enum': ['example', 'validation']},
                 'complete_expected': {'type': 'boolean'}})
# OpenAPI 3.1 uses JSON Schema 2020-12. x-max-* byte annotations describe
# producer/consumer checks, not extra validation performed by JSON Schema.
SHA256 = {'type': 'string', 'pattern': '^[a-f0-9]{64}$', 'minLength': 64, 'maxLength': 64}
VERSION = {'type': 'integer', 'const': 1}
EXAMPLE_FIELDS = {key: SAMPLE['properties'][key] for key in ('expected_ips', 'complete_expected')}
EXAMPLE_FIELDS['usage'] = {'type': 'string', 'const': 'example'}
MODEL_EXCERPT = closed({
    'original_utf8_bytes': {'type': 'integer', 'minimum': 1, 'maximum': 2048},
    'prefix': {'type': 'string', 'maxLength': 768, 'x-max-utf8-bytes': 768},
    'suffix': {'type': 'string', 'maxLength': 256, 'x-max-utf8-bytes': 256},
    'omitted_utf8_bytes': {'type': 'integer', 'minimum': 1, 'maximum': 2048},
})
MODEL_EXAMPLE = {'oneOf': [
    closed({**EXAMPLE_FIELDS, 'data': {'type': 'string', 'maxLength': MAX_MODEL_DATA_BYTES,
                                     'x-max-utf8-bytes': MAX_MODEL_DATA_BYTES}}),
    closed({**EXAMPLE_FIELDS, 'excerpt': MODEL_EXCERPT}),
]}
MODEL_VIEW = closed({
    'version': VERSION, 'kind': {'type': 'string', 'const': 'decoder_suggest'},
    'decoder_type': {'type': 'string', 'enum': ['TXT', 'A']},
    'examples': {'type': 'array', 'minItems': 1, 'maxItems': 6, 'items': MODEL_EXAMPLE},
})
MODEL_VIEW.update({
    'x-max-encoded-bytes': MAX_SOURCE_BYTES,
    'x-max-labels-bytes': MAX_LABEL_BYTES,
    'x-max-metadata-bytes': MAX_VIEW_METADATA_BYTES,
    'description': 'Original example order and labels; complete rows verbatim. Excerpt prefix/suffix are separate, '
                   'never concatenated or complete samples. Total shown raw UTF-8 data <=1024 bytes. '
                   'Labels are metered as the array of expected_ips arrays; metadata blanks data/segments and labels. '
                   'Canonical allocation, byte sums and equality to the original examples require runtime validation.',
})
MODEL_INPUT_SCHEMA = closed({
    'version': VERSION, 'policy': {'type': 'string', 'const': POLICY},
    'source_snapshot_digest': SHA256, 'view': MODEL_VIEW,
    'coverage': closed({
        'original_utf8_bytes': {'type': 'integer', 'minimum': 0, 'maximum': MAX_SOURCE_BYTES},
        'shown_utf8_bytes': {'type': 'integer', 'minimum': 0, 'maximum': MAX_MODEL_DATA_BYTES},
        'omitted_utf8_bytes': {'type': 'integer', 'minimum': 0, 'maximum': MAX_SOURCE_BYTES},
        'complete_examples': {'type': 'integer', 'minimum': 0, 'maximum': 6},
        'excerpted_examples': {'type': 'integer', 'minimum': 0, 'maximum': 6},
    }),
    'messages_schema_bytes': {'type': 'integer', 'minimum': 1, 'maximum': MAX_MESSAGES_SCHEMA_BYTES},
    'messages_schema_digest': SHA256,
})
MODEL_INPUT_SCHEMA.update({
    'x-max-encoded-bytes': MAX_MODEL_INPUT_BYTES,
    'x-max-metadata-bytes': MAX_INPUT_METADATA_BYTES,
    'description': 'Server-recorded commitment to the exact privacy-checked canonical UTF-8 JSON '
                   '{messages,schema}, sorted keys, compact separators, ensure_ascii=False, allow_nan=False. '
                   'Not HTTP framing, provider options, runtime custody, model attention, tokens or latency proof. '
                   'source_snapshot_digest binds the unchanged original snapshot, not the excerpted view. '
                   'Metadata meters the sidecar with the view data/segments and labels blanked. '
                   'Digest equality and byte budgets require runtime checks; x-max-* are annotations only.',
})

# JSON Schema searches patterns; unlike $, this portable end assertion cannot
# match before a final line terminator (and does not require Python-only anchors).
EVIDENCE_ID = {'type': 'string', 'pattern': r'^e[1-9][0-9]{0,2}(?![\s\S])', 'minLength': 2, 'maxLength': 4}


def _summary_section(codes):
    if not codes:
        return {'type': 'array', 'maxItems': 0, 'const': []}
    return {
        'type': 'array', 'minItems': len(codes), 'maxItems': len(codes), 'items': False,
        'prefixItems': [closed({
            'code': {'type': 'string', 'const': code},
            'text': {'type': 'string', 'minLength': 1, 'maxLength': MAX_CLAIM_BYTES,
                     'x-max-utf8-bytes': MAX_CLAIM_BYTES},
            'evidence_ids': {'type': 'array', 'minItems': 1, 'maxItems': 3, 'uniqueItems': True,
                             'items': EVIDENCE_ID},
        }) for code in codes],
    }


FACTS_SUMMARIES = {kind: closed({
    'version': VERSION, 'kind': {'type': 'string', 'const': kind}, 'language': LANGUAGE,
    'snapshot_digest': SHA256,
    **{section: _summary_section(codes) for section, codes in sections.items()},
}) for kind, sections in SUMMARY_CODES.items()}
FACTS_SUMMARY_SCHEMA = {
    'oneOf': list(FACTS_SUMMARIES.values()), 'x-max-encoded-bytes': MAX_SUMMARY_BYTES,
    'description': 'Deterministic server facts from the exact original snapshot; separate from unchanged '
                   'free-prose interpretation.version=1. Each section has mandatory codes in producer order. '
                   'Claims have 1..512 UTF-8 bytes; x-max-* byte annotations require runtime enforcement. '
                   'Kind, language and snapshot digest must match the enclosing job/result. Each evidence ID '
                   'must cite the specific source fact for its code, not merely match the ID syntax. '
                   'Cross-field binding and fact semantics require runtime validation, not JSON Schema alone.',
}

REQUEST_SCHEMA = {'oneOf': [
    closed({'kind': {'const': 'delivery'}, 'language': LANGUAGE}),
    closed({'kind': {'const': 'relationship_pair'}, 'language': LANGUAGE,
            'source': closed({'job_id': JOB_ID, 'a': IP, 'b': IP})}),
    closed({'kind': {'const': 'decoder_suggest'}, 'language': LANGUAGE,
            'decoder_type': {'type': 'string', 'enum': ['TXT', 'A']}, 'generate': {'type': 'boolean'},
            'samples': {'type': 'array', 'minItems': 1, 'maxItems': 6, 'items': SAMPLE,
                        'contains': {'type': 'object', 'properties': {'usage': {'const': 'example'}}, 'required': ['usage']},
                        'description': 'At least one example; duplicate raw data across all rows refused. Validation data/answers/feedback never sent to the model. Examples must also fit the8KiB projection cap.'}}),
]}
EMPTY_SCHEMA = closed({})
ACTIVE_JOB = closed({'job_id': JOB_ID, 'kind': {'enum': KINDS}, 'status': {'enum': STATES}})
ACTIVE_JOB['description'] = 'Owned unfinished lifecycle; terminal execution may still await audit. Read the job and require audit_status=success before using a result.'
STATUS_SCHEMA = closed({'enabled': {'type': 'boolean'}, 'accepting': {'type': 'boolean'},
                        'provider_state': {'enum': ['ready', 'busy', 'unsettled', 'unavailable', 'disabled', 'stopped']},
                        'queued': {'type': 'integer', 'minimum': 0, 'maximum': 2},
                        'active_job': {'anyOf': [{'type': 'null'}, ACTIVE_JOB]}})
# The retained payloads remain governed by their task validators. These public
# schemas close the result envelope and the new sidecars; they do not replace
# the bound model-output schemas in local_ai.contracts or verifier semantics.
RETAINED_OBJECT = {'type': 'object', 'description': 'Retained task-validated payload; existing contract unchanged.'}


def _int64_decimal_schema():
    # A string counter must also fit int64 in ordinary JSON Schema validators,
    # not just in consumers implementing an optional format/x-* annotation.
    maximum = str((1 << 63) - 1)
    choices = ['0', '[1-9][0-9]{0,17}', maximum]
    for index, digit in enumerate(maximum):
        lower = 1 if index == 0 else 0
        if int(digit) > lower:
            choices.append(maximum[:index] + f'[{lower}-{int(digit) - 1}]'
                           + '[0-9]{' + str(len(maximum) - index - 1) + '}')
    return {'type': 'string', 'minLength': 1, 'maxLength': 19,
            'pattern': '^(?:' + '|'.join(choices) + r')(?![\s\S])'}


MODEL_COUNTER = _int64_decimal_schema()
NATIVE_MODEL_METADATA = {**closed({
    'model': {'type': 'string', 'minLength': 1, 'maxLength': 256, 'x-max-utf8-bytes': 256},
    'model_digest': SHA256,
    'done_reason': {'enum': ['stop', 'length']},
    **{key: MODEL_COUNTER for key in ('eval_count', 'prompt_eval_count', 'total_duration',
                                     'load_duration', 'prompt_eval_duration', 'eval_duration')},
}), 'required': ['model', 'model_digest']}
COMPATIBLE_MODEL_NAME = {'type': 'string', 'minLength': 1, 'maxLength': 256,
                         'pattern': r'^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}(?![\s\S])'}
COMPATIBLE_MODEL_METADATA = {**closed({
    'provider': {'const': 'openai_compatible'},
    'requested_model': COMPATIBLE_MODEL_NAME, 'reported_model': COMPATIBLE_MODEL_NAME,
    'finish_reason': {'enum': ['stop', 'length', 'content_filter']},
    'response_format': {'const': 'json_object'},
    **{key: MODEL_COUNTER for key in ('prompt_tokens', 'completion_tokens', 'total_tokens')},
}), 'required': ['provider', 'requested_model', 'reported_model', 'finish_reason', 'response_format']}
MODEL_METADATA_SCHEMA = {
    'oneOf': [NATIVE_MODEL_METADATA, COMPATIBLE_MODEL_METADATA],
    'description': 'Positive legacy native metadata or explicit OpenAI-compatible metadata, never a fallback '
                   'for malformed provider fields. Requested and reported model names may differ. '
                   'Compatible APIs do not claim native digests or timings. Missing usage is unobserved, '
                   'not zero; observed counters are decimal int64 strings. If all three compatible usage '
                   'counters are present, total must equal prompt plus completion (runtime validation).',
}
RESULT_COMMON = {
    'snapshot_digest': SHA256,
    'source_revision': {'type': 'integer', 'minimum': 0},
    'model': MODEL_METADATA_SCHEMA,
}
DECODER_SNAPSHOT = closed({
    'version': VERSION, 'kind': {'type': 'string', 'const': 'decoder_suggest'},
    'decoder_type': {'type': 'string', 'enum': ['TXT', 'A']},
    'examples': {'type': 'array', 'minItems': 1, 'maxItems': 6,
                 'items': closed({**EXAMPLE_FIELDS, 'data': SAMPLE['properties']['data']})},
})
DECODER_SNAPSHOT.update({'x-max-encoded-bytes': MAX_SOURCE_BYTES,
                         'description': 'Unchanged original example snapshot, never excerpted. Holdouts are not included.'})
DECODER_RESULT_SCHEMA = closed({
    **RESULT_COMMON, 'snapshot': DECODER_SNAPSHOT,
    'catalog': RETAINED_OBJECT,
    'model': {'anyOf': [{'type': 'null'}, MODEL_METADATA_SCHEMA]},
    'generated': {'anyOf': [{'type': 'null'}, RETAINED_OBJECT]},
    'proposal': {'anyOf': [{'type': 'null'}, RETAINED_OBJECT]},
    'model_input': {'anyOf': [{'type': 'null'}, MODEL_INPUT_SCHEMA]},
})
DECODER_RESULT_SCHEMA['allOf'] = [{
    'if': {'properties': {'model': {'type': 'null'}}},
    'then': {'properties': {key: {'type': 'null'} for key in ('generated', 'proposal', 'model_input')}},
    'else': {'properties': {key: {'type': 'object'} for key in ('generated', 'proposal', 'model_input')}},
}, *[{
    'if': {'properties': {'snapshot': {'properties': {'decoder_type': {'const': kind}}}}},
    'then': {'properties': {'model_input': {'properties': {'view': {'properties': {'decoder_type': {'const': kind}}}}}}},
} for kind in ('TXT', 'A')]]
DECODER_RESULT_SCHEMA['description'] = (
    'model_input is required: null for generate=false; populated for generate=true, including an abstaining proposal. '
    'Catalog-only model/generated/proposal are all null. Generated results retain the full original snapshot, '
    'catalog, generated verification report, original v1 proposal and model metadata.'
)
EXPLANATION_RESULTS = {kind: closed({
    **RESULT_COMMON,
    'snapshot': closed({
        'version': VERSION, 'kind': {'type': 'string', 'const': kind}, 'source': RETAINED_OBJECT,
        'facts': {'type': 'array', 'minItems': 1, 'maxItems': 64, 'items': closed({
            'id': EVIDENCE_ID, 'key': {'type': 'string'},
            'value': {'description': 'Original task-specific projected fact; validated by the evidence producer.'},
        })},
        'warnings': {'type': 'array', 'items': {'type': 'string'}},
    }),
    'interpretation': {**RETAINED_OBJECT, 'properties': {
        'version': VERSION, 'kind': {'type': 'string', 'const': kind},
        'language': LANGUAGE, 'snapshot_digest': SHA256,
    }, 'required': ['version', 'kind', 'language', 'snapshot_digest'],
        'description': 'Unchanged free-prose model v1 output, not the deterministic facts summary. '
                       'The existing bound explanation validator checks its complete shape and citations.'},
    'facts_summary': {**FACTS_SUMMARIES[kind], 'x-max-encoded-bytes': MAX_SUMMARY_BYTES,
                      'description': FACTS_SUMMARY_SCHEMA['description']},
}) for kind in SUMMARY_CODES}
RESULT_SCHEMA = {'oneOf': [DECODER_RESULT_SCHEMA, *EXPLANATION_RESULTS.values()],
                 'description': 'Closed result alternatives; required sidecars cannot be omitted by older producers. '
                                'Original snapshots, revision, model metadata and v1 model outputs are retained. '
                                'Digest equality, byte budgets and semantic consistency also require task/consumer validation.'}

JOB_FIELDS = {
    'job_id': JOB_ID, 'kind': {'enum': KINDS}, 'language': LANGUAGE,
    'status': {'enum': STATES},
    'created_at': {'type': 'integer', 'minimum': 0},
    'deadline_at': {'type': 'integer', 'minimum': 0},
    'audit_status': {'enum': ['pending', 'success', 'failed']},
    'error': {'anyOf': [{'type': 'null'}, {'type': 'string', 'enum': list(ERROR_STATUS)}]},
    'result': {'anyOf': [{'type': 'null'}, RESULT_SCHEMA],
               'description': 'No result before completed execution and successful terminal audit; failures stay null. '
                              'Citation syntax is not semantic proof.'},
    'cancel_requested': {'type': 'boolean'},
}
JOB_BINDINGS = [{
    'if': {'properties': {'status': {'const': 'completed'}, 'audit_status': {'const': 'success'},
                          'error': {'type': 'null'}}},
    'else': {'properties': {'result': {'type': 'null'}}},
}, *[{
    'if': {'properties': {'kind': {'const': kind}}},
    'then': {'properties': {'result': {'properties': {
        'snapshot': {'properties': {'kind': {'const': kind}}},
    }}}},
} for kind in KINDS], *[{
    'if': {'properties': {'language': {'const': language}}},
    'then': {'properties': {'result': {'properties': {
        key: {'properties': {'language': {'const': language}}}
        for key in ('proposal', 'interpretation', 'facts_summary')
    }}}},
} for language in LANGUAGE['enum']]]
JOB_SCHEMA = {**closed(JOB_FIELDS), 'allOf': JOB_BINDINGS}
CANCEL_SCHEMA = {**closed({**JOB_FIELDS, 'cancellation_requested': {'type': 'boolean'},
                          'cancellation_confirmed': {'type': 'boolean'}}), 'allOf': JOB_BINDINGS}
ERROR_SCHEMA = closed({'error': {'type': 'string', 'enum': list(ERROR_STATUS)},
                       'code': {'type': 'string', 'enum': list(ERROR_STATUS)},
                       'request_id': {'type': 'string'}})
