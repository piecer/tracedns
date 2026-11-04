"""Closed local health projection, shared with the generated OpenAPI contract."""
import json
from urllib.parse import parse_qs, urlsplit

from monitor.delivery_types import REASONS as DELIVERY_REASONS
from .utils import send_json


MAX_HEALTH_BYTES = 4096
MAX_COUNTER = (1 << 63) - 1
REASONS = tuple(sorted(DELIVERY_REASONS))
COUNT = {'type': 'integer', 'minimum': 0, 'maximum': MAX_COUNTER}
OPTIONAL_COUNT = {**COUNT, 'type': ['integer', 'null']}
FLAG = {'type': 'boolean'}
REASON = {'type': ['string', 'null'], 'enum': [None, *REASONS]}


def _closed(properties):
    return {'type': 'object', 'properties': properties,
            'required': list(properties), 'additionalProperties': False}


CHANNEL_SCHEMA = _closed({
    'enabled': FLAG, 'pending': COUNT, 'blocked': COUNT,
    'last_success_at': OPTIONAL_COUNT, 'last_error': REASON,
})
HEALTH_SCHEMA = _closed({
    'status': {'type': 'string', 'enum': ['disabled', 'ok', 'degraded', 'blocked']},
    'observation_policy': {'type': 'string', 'enum': ['continue']},
    'storage_ok': FLAG, 'worker_running': FLAG,
    'coverage': {'type': 'string', 'enum': ['covered', 'gap', 'rebaselining']},
    'accounting_complete': FLAG, 'missed_total': COUNT, 'missed_unpersisted': COUNT,
    'failed_total': COUNT, 'acked_total': COUNT, 'pending': COUNT, 'retry_wait': COUNT,
    'blocked': COUNT, 'oldest_pending_age_seconds': OPTIONAL_COUNT,
    'capacity': _closed({key: COUNT for key in (
        'used_receipts', 'max_receipts', 'used_payload_bytes', 'max_payload_bytes')}),
    'channels': _closed({'teams': CHANNEL_SCHEMA, 'misp': CHANNEL_SCHEMA}),
    'tracking_complete': FLAG, 'counts_stale': FLAG, 'last_error': REASON,
})


def _enum(values, nullable=False):
    return {'type': ['string', 'null'] if nullable else 'string',
            'enum': [None, *values] if nullable else values}


PROGRESS_CHANNEL_SCHEMA = _closed({
    'state': _enum(['disabled', 'idle', 'queued', 'retry_wait', 'blocked', 'active', 'stalled', 'unavailable']),
    'last_attempt_at': OPTIONAL_COUNT, 'in_flight_age_seconds': OPTIONAL_COUNT,
})
PROGRESS_SCHEMA = _closed({**HEALTH_SCHEMA['properties'],
    'progress_version': {**COUNT, 'enum': [1]}, 'counts_age_seconds': OPTIONAL_COUNT,
    'progress': _closed({
        'state': _enum(['not_started', 'idle', 'active', 'stalled', 'recovering', 'failed', 'stopping', 'stopped']),
        'operation': _enum(['recover_storage', 'seal_batches', 'claim', 'provider_step',
                            'finish_step', 'observation_hook', 'sightings_step'], True),
        'channel': _enum(['teams', 'misp'], True), 'last_progress_at': OPTIONAL_COUNT,
        'last_progress_age_seconds': OPTIONAL_COUNT, 'in_flight_age_seconds': OPTIONAL_COUNT,
        'stall_after_seconds': COUNT,
        'channels': _closed({'teams': PROGRESS_CHANNEL_SCHEMA, 'misp': PROGRESS_CHANNEL_SCHEMA}),
    }),
    'recovery': _closed({
        'state': _enum(['ready', 'recovering', 'backoff', 'uncertain', 'stopped', 'failed']),
        'retry_in_seconds': OPTIONAL_COUNT, 'targets_rebaselining': COUNT,
        'absence_state': _enum(['ready', 'awaiting_full', 'unknown']),
    }),
    'lookup': _closed({
        'last_attempt_at': OPTIONAL_COUNT, 'last_success_at': OPTIONAL_COUNT, 'in_flight': COUNT,
        'failed_targets': COUNT, 'uncertain_targets': COUNT, 'coverage': _enum(['complete', 'partial', 'unknown']),
        'counts_stale': FLAG,
    }),
})


def _project(value, schema, *, strict=False):
    kind = schema['type']
    if kind == 'object':
        if type(value) is not dict:
            raise ValueError('invalid cached health')
        if strict and value.keys() != schema['properties'].keys():
            raise ValueError('invalid cached shape')
        # Legacy projection retains its established private-field redaction.
        return {key: _project(value[key], child, strict=strict) for key, child in schema['properties'].items()}
    if type(kind) is list:
        if value is None:
            return None
        kind = kind[0]
    if kind == 'integer':
        if type(value) is not int or not 0 <= value <= MAX_COUNTER:
            raise ValueError('invalid cached counter')
        if 'enum' in schema and value not in schema['enum']:
            raise ValueError('invalid cached version')
    elif kind == 'boolean':
        if type(value) is not bool:
            raise ValueError('invalid cached flag')
    elif kind == 'string':
        if type(value) is not str:
            raise ValueError('invalid cached enum')
        if schema is REASON and not strict:
            return value if len(value) <= 64 and value in REASONS else 'delivery_unknown'
        if value not in schema['enum']:
            raise ValueError('invalid cached enum')
    return value


def handle_delivery_health(ctx, handler):
    query = parse_qs(urlsplit(handler.path).query, keep_blank_values=True)
    if 'progress' in query and query['progress'] != ['1']:
        return send_json(handler, {'error': 'invalid progress selector'}, 400)
    extended = 'progress' in query
    try:
        if ctx.delivery_health is None:
            raise ValueError('owner unavailable')
        value = ctx.delivery_health(include_progress=True) if extended else ctx.delivery_health()
        payload = _project(value, PROGRESS_SCHEMA if extended else HEALTH_SCHEMA, strict=extended)
        if len(json.dumps(payload, ensure_ascii=False).encode('utf-8')) > MAX_HEALTH_BYTES:
            raise ValueError('health byte limit')
    except Exception:
        return send_json(handler, {'error': 'delivery health unavailable'}, 503)
    return send_json(handler, payload)
