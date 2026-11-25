"""Closed AI settings schemas; distinct from inference/job metadata."""
from copy import deepcopy


def obj(properties, required=None):
    return {'type': 'object', 'properties': properties, 'additionalProperties': False,
            'required': list(properties) if required is None else list(required)}


REVISION = {'type': 'integer', 'minimum': 0, 'maximum': 9007199254740991}
URL = {'type': 'string', 'maxLength': 1024}
MODEL = {'type': 'string', 'maxLength': 256}
DIGEST = {'type': 'string', 'maxLength': 64, 'pattern': r'^(?:[0-9a-f]{64})?(?![\s\S])'}
POLICY = {'enum': ['public_https', 'loopback']}
TOKEN_FIELD = {'enum': ['max_completion_tokens', 'max_tokens']}
WARNINGS = ['ai_runtime_apply_failed', 'ai_previous_call_draining', 'ai_provider_unsettled']
RUNTIME = obj({'applied': {'type': 'boolean'}, 'state': {
    'enum': ['disabled', 'ready', 'draining', 'unsettled', 'unavailable', 'stopped']}})
COMMON = {'enabled': {'type': 'boolean'}, 'base_url': URL, 'model': MODEL}
PUBLIC_SETTINGS = {'oneOf': [
    obj({**COMMON, 'provider': {'const': 'ollama'}, 'model_digest': DIGEST,
         'configured': obj({'api_key': {'const': False}})}),
    obj({**COMMON, 'provider': {'const': 'openai_compatible'}, 'endpoint_policy': POLICY,
         'token_limit_field': TOKEN_FIELD, 'configured': obj({'api_key': {'type': 'boolean'}})}),
]}
PATCH = obj({**COMMON, 'provider': {'enum': ['ollama', 'openai_compatible']},
             'model_digest': DIGEST, 'endpoint_policy': POLICY, 'token_limit_field': TOKEN_FIELD,
             'api_key': {'type': 'string', 'maxLength': 4096, 'writeOnly': True}}, ())
PATCH['minProperties'] = 1
REQUEST_SCHEMA = obj({'revision': REVISION, 'settings': PATCH, 'clear_fields': {
    'type': 'array', 'items': {'const': 'api_key'}, 'maxItems': 1, 'uniqueItems': True}}, ('revision', 'settings'))
GET_SCHEMA = obj({'revision': REVISION, 'settings': PUBLIC_SETTINGS, 'runtime': RUNTIME})
POST_SCHEMA = obj({**deepcopy(GET_SCHEMA['properties']), 'status': {'const': 'ok'}, 'warnings': {
    'type': 'array', 'items': {'enum': WARNINGS}, 'maxItems': len(WARNINGS), 'uniqueItems': True}})
ERROR_CODES = ['invalid_request', 'privacy_unavailable', 'sensitive_input', 'too_large', 'source_revoked',
               'config_storage_unavailable', 'config_save_failed', 'config_revision_exhausted', 'stopped',
               'config_revision_conflict']
ERROR_SCHEMA = obj({'error': {'enum': ERROR_CODES + ['config revision conflict']},
                    'code': {'enum': ERROR_CODES}, 'request_id': {'type': 'string', 'maxLength': 64},
                    'revision': REVISION}, ('error', 'code', 'request_id'))
ERROR_SCHEMA['allOf'] = [{'if': {'properties': {'code': {'const': 'config_revision_conflict'}}},
                         'then': {'required': ['revision']}, 'else': {'not': {'required': ['revision']}}}]
