"""Closed admission and interpretation contracts; no model or application I/O."""
import json
import math
import ipaddress
import re

import jsonschema

MAX_REQUEST_BYTES = 16 * 1024
MAX_MODEL_CONTENT_BYTES = 16 * 1024
NEXT_CHECKS = {
    'relationship_pair': ('inspect_pair_evidence', 'inspect_pair_coverage'),
    'delivery': ('inspect_delivery_diagnostics', 'inspect_delivery_progress'),
}
ERROR_STATUS = {
    'invalid_request': 400, 'sensitive_input': 400, 'not_found': 404,
    'source_not_ready': 409, 'source_unavailable': 409, 'source_revoked': 409,
    'too_large': 413, 'verification_failed': 422, 'busy': 429,
    'invalid_model_output': 502, 'provider_failed': 502,
    'provider_request_rejected': 502, 'provider_auth_failed': 502, 'provider_rate_limited': 503,
    'disabled': 503, 'model_unavailable': 503, 'provider_unsettled': 503,
    'audit_unavailable': 503, 'privacy_unavailable': 503, 'stopped': 503,
    'deadline_exceeded': 504,
}


class AIError(ValueError):
    """Only a fixed public code is retained; never store request/provider prose."""

    def __init__(self, code, status=None):
        if type(code) is not str or code not in ERROR_STATUS:
            raise ValueError('unknown AI error code')
        expected = ERROR_STATUS[code]
        if status is not None and (type(status) is not int or status != expected):
            raise ValueError('invalid AI error status')
        super().__init__(code)
        self.code = code
        self.status = expected


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError('nonfinite constant')


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError('nonfinite number')
    return number


def parse_object(raw, *, limit=MAX_REQUEST_BYTES, code='invalid_request'):
    if type(raw) is not bytes:
        raise AIError(code)
    if len(raw) > limit:
        raise AIError('too_large', 413)
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object,
                           parse_constant=_reject_constant, parse_float=_finite_float)
    except (ValueError, UnicodeError, RecursionError):
        raise AIError(code) from None
    if type(value) is not dict:
        raise AIError(code)
    return value


def load_request(raw):
    data = parse_object(raw)
    if type(data.get('language')) is not str or data['language'] not in ('ko', 'en'):
        raise AIError('invalid_request')
    if data.get('kind') == 'delivery' and set(data) == {'kind', 'language'}:
        return data
    if data.get('kind') == 'decoder_suggest':
        from local_ai.decoder import DecoderError, validate_samples
        if (set(data) != {'kind', 'language', 'decoder_type', 'samples', 'generate'}
                or data['decoder_type'] not in ('TXT', 'A') or type(data['generate']) is not bool):
            raise AIError('invalid_request')
        try:
            data['samples'] = validate_samples(data['samples'])
        except DecoderError as exc:
            raise AIError(exc.code) from None
        return data
    if data.get('kind') != 'relationship_pair' or set(data) != {'kind', 'language', 'source'}:
        raise AIError('invalid_request')
    source = data['source']
    if (type(source) is not dict or set(source) != {'job_id', 'a', 'b'}
            or type(source['job_id']) is not str or not re.fullmatch('[a-f0-9]{32}', source['job_id'])):
        raise AIError('invalid_request')
    try:
        for key in ('a', 'b'):
            value = source[key]
            if type(value) is not str or len(value) > 15 or str(ipaddress.IPv4Address(value)) != value:
                raise ValueError('noncanonical IP')
        if source['a'] == source['b']:
            raise ValueError('same IP')
    except ValueError:
        raise AIError('invalid_request') from None
    return data


def _closed(properties):
    return {'type': 'object', 'properties': properties, 'required': list(properties),
            'additionalProperties': False}


def explanation_schema(kind, language, snapshot_digest, evidence_ids):
    if (type(kind) is not str or kind not in NEXT_CHECKS
            or type(language) is not str or language not in ('ko', 'en')
            or type(snapshot_digest) is not str or not re.fullmatch('[a-f0-9]{64}', snapshot_digest)
            or type(evidence_ids) not in (list, tuple) or not 1 <= len(evidence_ids) <= 64):
        raise AIError('source_unavailable')
    if (any(type(value) is not str or not re.fullmatch('e[1-9][0-9]{0,2}', value) for value in evidence_ids)
            or len(set(evidence_ids)) != len(evidence_ids)):
        raise AIError('source_unavailable')
    citations = {'type': 'array', 'minItems': 1, 'maxItems': 4, 'uniqueItems': True,
                 'items': {'type': 'string', 'enum': list(evidence_ids)}}
    claim = _closed({'text': {'type': 'string', 'minLength': 1, 'maxLength': 512},
                     'evidence_ids': citations})
    check = _closed({'code': {'type': 'string', 'enum': list(NEXT_CHECKS[kind])},
                     'evidence_ids': citations})
    return _closed({
        'version': {'type': 'integer', 'const': 1},
        'kind': {'type': 'string', 'const': kind},
        'language': {'type': 'string', 'const': language},
        'snapshot_digest': {'type': 'string', 'const': snapshot_digest},
        'summary': {'type': 'array', 'minItems': 1, 'maxItems': 3, 'items': claim},
        'counterpoints': {'type': 'array', 'maxItems': 4, 'items': claim},
        'limitations': {'type': 'array', 'maxItems': 4, 'items': claim},
        'next_checks': {'type': 'array', 'maxItems': 3, 'items': check},
    })


def validate_explanation(raw, *, kind, language, snapshot_digest, evidence_ids):
    schema = explanation_schema(kind, language, snapshot_digest, evidence_ids)
    if type(raw) is not str or len(raw) > MAX_MODEL_CONTENT_BYTES:
        raise AIError('invalid_model_output', 502)
    try:
        value = parse_object(raw.encode('utf-8'), limit=MAX_MODEL_CONTENT_BYTES,
                             code='invalid_model_output')
        jsonschema.Draft202012Validator(schema).validate(value)
        if type(value['version']) is not int:
            raise ValueError('version must be an integer')
        for field in ('summary', 'counterpoints', 'limitations'):
            for claim in value[field]:
                if not 1 <= len(claim['text'].encode('utf-8')) <= 512:
                    raise ValueError('claim byte limit')
    except (ValueError, TypeError, UnicodeError, RecursionError, jsonschema.ValidationError):
        raise AIError('invalid_model_output', 502) from None
    return value


def decoder_schema(decoder_type, language, snapshot_digest):
    from local_ai.decoder import generated_step_schema
    if (decoder_type not in ('TXT', 'A') or language not in ('ko', 'en')
            or type(snapshot_digest) is not str or not re.fullmatch('[a-f0-9]{64}', snapshot_digest)):
        raise AIError('source_unavailable')
    reasons = ['insufficient_examples', 'unsupported_transformation', 'no_candidate']
    metadata = {
        'version': {'type': 'integer', 'const': 1},
        'kind': {'type': 'string', 'const': 'decoder_suggest'},
        'language': {'type': 'string', 'const': language},
        'snapshot_digest': {'type': 'string', 'const': snapshot_digest},
    }
    # Native grammar conversion visits each union branch without inheriting
    # sibling properties/required. Keep both alternatives independently closed.
    return {'oneOf': [
        _closed({**metadata,
            'candidates': {'type': 'array', 'minItems': 1, 'maxItems': 3, 'items': _closed({
                'steps': {'type': 'array', 'minItems': 1, 'maxItems': 12,
                          'items': generated_step_schema(decoder_type)}})},
            'insufficient_reason': {'type': 'null'}}),
        _closed({**metadata,
            # A native array without items skips maxItems; const makes this
            # alternative empty in both JSON Schema and the native grammar.
            'candidates': {'type': 'array', 'maxItems': 0, 'const': []},
            'insufficient_reason': {'type': 'string', 'enum': reasons}}),
    ]}


def validate_decoder(raw, *, decoder_type, language, snapshot_digest):
    from local_ai.decoder import validate_generated_steps
    schema = decoder_schema(decoder_type, language, snapshot_digest)
    if type(raw) is not str or len(raw) > MAX_MODEL_CONTENT_BYTES:
        raise AIError('invalid_model_output')
    try:
        value = parse_object(raw.encode('utf-8'), limit=MAX_MODEL_CONTENT_BYTES, code='invalid_model_output')
        jsonschema.Draft202012Validator(schema).validate(value)
        if type(value['version']) is not int:
            raise ValueError('version must be an integer')
        for candidate in value['candidates']:
            validate_generated_steps(decoder_type, candidate['steps'])
    except (ValueError, TypeError, UnicodeError, RecursionError, jsonschema.ValidationError):
        raise AIError('invalid_model_output') from None
    return value
