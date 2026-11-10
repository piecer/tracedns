"""Closed target-resend HTTP facade; evidence/admission belong to the runtime."""
import ipaddress
import json
import re

from .delivery_diagnostics import _closed, _enum, _nullable
from .request_limits import get_request_body

PATHS = {'/delivery-resend/preview', '/delivery-resend'}
MAX_BODY = 4096
REASON_CODES = {
    'invalid_request': 400, 'target_not_found': 404,
    **dict.fromkeys(('no_managed_ips', 'snapshot_changed', 'configuration_changed',
                     'preview_expired', 'delivery_pending', 'destination_unavailable'), 409),
    'preview_capacity': 429, 'resend_cooldown': 429,
    **dict.fromkeys(('delivery_capacity', 'delivery_storage', 'runtime_unavailable', 'delivery_unknown'), 503),
}
TOKEN_SCHEMA = {'type': 'string', 'minLength': 32, 'maxLength': 32, 'pattern': '^[0-9a-f]{32}$'}
CHANNELS_SCHEMA = {'type': 'array', 'items': _enum(('teams', 'misp')), 'maxItems': 2, 'uniqueItems': True}
TARGET_SCHEMA = {'type': 'string', 'minLength': 1, 'maxLength': MAX_BODY,
                 'description': 'Exact canonical configuration identity (domain_identity), not a storage label or edited display name. Runtime label-byte limits also apply.'}
RETRY_SCHEMA = _nullable({'type': 'integer', 'minimum': 0, 'maximum': 30})
PREVIEW_REQUEST_SCHEMA = _closed({
    'target': TARGET_SCHEMA, 'channels': {**CHANNELS_SCHEMA, 'minItems': 1},
    'revision': {'type': 'integer', 'minimum': 0, 'maximum': 2**53 - 1},
})
CONFIRM_REQUEST_SCHEMA = _closed({'request_id': TOKEN_SCHEMA})
PREVIEW_RESULT_SCHEMA = _closed({
    'status': _enum(('ready', 'not_ready')), 'reason': _nullable(_enum(sorted(REASON_CODES))),
    'request_id': _nullable(TOKEN_SCHEMA), 'target': _nullable(TARGET_SCHEMA),
    'source_type': _nullable(_enum(('A', 'TXT', 'ENS', 'SNS', 'DHT', 'RPC'))),
    'ips': {'type': 'array', 'maxItems': 256, 'uniqueItems': True,
            'items': {'type': 'string', 'minLength': 2, 'maxLength': 45}},
    'observed_at': _nullable({'type': 'integer', 'minimum': 0, 'maximum': 2**63 - 1}),
    'retained': {'type': 'boolean'}, 'channels': CHANNELS_SCHEMA,
    'expires_in_seconds': {'type': 'integer', 'minimum': 0, 'maximum': 300},
    'retry_after': RETRY_SCHEMA,
})
CONFIRM_RESULT_SCHEMA = _closed({
    'status': _enum(('queued', 'already_queued', 'not_queued', 'unknown')),
    'reason': _nullable(_enum(sorted(REASON_CODES))), 'request_id': _nullable(TOKEN_SCHEMA),
    'ip_count': {'type': 'integer', 'minimum': 0, 'maximum': 256},
    'receipt_count': {'type': 'integer', 'minimum': 0, 'maximum': 512},
    'channels': CHANNELS_SCHEMA, 'retry_after': RETRY_SCHEMA,
})


# Outcome-dependent invariants are mirrored by _result before publication.
PREVIEW_RESULT_SCHEMA['allOf'] = [{
    'if': {'properties': {'status': {'const': 'ready'}}},
    'then': {'properties': {'reason': {'type': 'null'}, 'request_id': TOKEN_SCHEMA,
                            'target': TARGET_SCHEMA, 'source_type': {'type': 'string'},
                            'ips': {'minItems': 1}, 'channels': {'minItems': 1},
                            'expires_in_seconds': {'minimum': 1}}},
    'else': {'properties': {'reason': _enum(sorted(set(REASON_CODES) - {'delivery_unknown'}))}},
}]
CONFIRM_RESULT_SCHEMA['allOf'] = [{
    'if': {'properties': {'status': {'enum': ['queued', 'already_queued']}}},
    'then': {'properties': {'reason': {'type': 'null'}, 'request_id': TOKEN_SCHEMA,
                            'ip_count': {'minimum': 1}, 'receipt_count': {'minimum': 1},
                            'channels': {'minItems': 1}}},
    'else': {'if': {'properties': {'status': {'const': 'unknown'}}},
             'then': {'properties': {'reason': {'const': 'delivery_unknown'}}},
             'else': {'properties': {'reason': _enum(sorted(set(REASON_CODES) - {'delivery_unknown'})),
                                     'ip_count': {'const': 0}, 'receipt_count': {'const': 0}}}},
}]


def _project(value, schema, *, exact=False):
    """Validate bounded grammar before copying known fields; no coercion."""
    kind = schema['type']
    if isinstance(kind, list):
        if value is None:
            return None
        kind = kind[0]
    if kind == 'object':
        if type(value) is not dict or (exact and set(value) != set(schema['properties'])):
            raise ValueError('invalid object')
        return {k: _project(value[k], v, exact=exact) for k, v in schema['properties'].items()}
    if kind == 'array':
        if type(value) is not list or not schema.get('minItems', 0) <= len(value) <= schema['maxItems']:
            raise ValueError('invalid array')
        result = [_project(item, schema['items'], exact=exact) for item in value]
        if schema.get('uniqueItems') and len(set(result)) != len(result):
            raise ValueError('duplicate items')
        return result
    if kind == 'integer':
        valid = type(value) is int and schema['minimum'] <= value <= schema['maximum']
    elif kind == 'boolean':
        valid = type(value) is bool
    else:
        valid = (type(value) is str and schema.get('minLength', 0) <= len(value) <= schema.get('maxLength', 64)
                 and ('enum' not in schema or value in schema['enum'])
                 and ('pattern' not in schema or re.fullmatch(schema['pattern'], value)))
    if not valid:
        raise ValueError('invalid scalar')
    return value


def _unique(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError('duplicate keys')
    return value


def load_request(raw, preview):
    return _project(json.loads(raw, object_pairs_hook=_unique),
                    PREVIEW_REQUEST_SCHEMA if preview else CONFIRM_REQUEST_SCHEMA, exact=True)


def _failure(preview, reason, request_id=None, unknown=False):
    if preview:
        return dict(status='not_ready', reason=reason, request_id=None, target=None,
                    source_type=None, ips=[], observed_at=None, retained=True, channels=[],
                    expires_in_seconds=0, retry_after=None)
    return dict(status='unknown' if unknown else 'not_queued', reason=reason, request_id=request_id,
                ip_count=0, receipt_count=0, channels=[], retry_after=None)


def _result(value, preview, data):
    payload = _project(value, PREVIEW_RESULT_SCHEMA if preview else CONFIRM_RESULT_SCHEMA)
    status, reason = payload['status'], payload['reason']
    if preview:
        for ip in payload['ips']:
            if '%' in ip:
                raise ValueError('scoped IP')
            ipaddress.ip_address(ip)
        if status == 'ready':
            if (reason is not None or not payload['request_id'] or not payload['ips'] or
                    not payload['source_type'] or payload['target'] != data['target'] or
                    set(payload['channels']) != set(data['channels']) or payload['expires_in_seconds'] == 0):
                raise ValueError('invalid preview')
            return payload, 200
    else:
        if payload['request_id'] is not None and payload['request_id'] != data['request_id']:
            raise ValueError('wrong request')
        if status in ('queued', 'already_queued'):
            if (reason is not None or not payload['request_id'] or not payload['ip_count'] or
                    not payload['channels'] or payload['receipt_count'] != payload['ip_count'] * len(payload['channels'])):
                raise ValueError('invalid admission')
            return payload, 202 if status == 'queued' else 200
        if status == 'unknown':
            if reason != 'delivery_unknown':
                raise ValueError('invalid uncertainty')
            return payload, 503
        if payload['ip_count'] or payload['receipt_count']:
            raise ValueError('rejected admission has counts')
    if reason not in REASON_CODES or reason == 'delivery_unknown':
        raise ValueError('invalid refusal')
    return payload, REASON_CODES[reason]


def send_result(handler, payload, code):
    # Closed fields are not fed through generic secret substitution (which can
    # corrupt protocol enums). Provider bodies/URLs never enter this grammar.
    wire = json.dumps(payload, separators=(',', ':'), allow_nan=False).encode('utf-8')
    handler.send_response(code)
    handler.send_header('Content-Type', 'application/json; charset=utf-8')
    handler.send_header('Content-Length', str(len(wire)))
    if payload['retry_after'] is not None:
        handler.send_header('Retry-After', str(payload['retry_after']))
    handler.end_headers()
    handler.wfile.write(wire)


def handle_delivery_resend(ctx, handler, preview):
    raw, rejected = get_request_body(handler, max_length=min(handler.max_body_bytes, MAX_BODY))
    if rejected:
        return
    try:
        data = load_request(raw, preview)
    except (ValueError, KeyError, TypeError, UnicodeError, RecursionError):
        handler._resend_response = (_failure(preview, 'invalid_request'), 400)
        return
    runtime = getattr(ctx.config_service, 'delivery_runtime', None)
    method = getattr(runtime, 'preview_resend' if preview else 'resend_target', None)
    if not callable(method):
        payload, code = _failure(preview, 'runtime_unavailable', data.get('request_id')), 503
    else:
        try:
            actor_id = handler.principal['id']
            result = (method(data['target'], data['channels'], data['revision'], actor_id=actor_id)
                      if preview else method(data['request_id'], actor_id=actor_id))
            payload, code = _result(result, preview, data)
        except Exception:
            # Once confirm was invoked, absence of a valid result cannot prove
            # no commit. Never turn ambiguity into a safe-to-repeat refusal.
            payload = _failure(preview, 'runtime_unavailable' if preview else 'delivery_unknown',
                               data.get('request_id'), unknown=not preview)
            code = 503
    # The common boundary durably audits this result BEFORE exposing success.
    handler._resend_response = payload, code
