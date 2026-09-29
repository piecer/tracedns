"""Closed local health projection, shared with the generated OpenAPI contract."""
import json

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


def _project(value, schema):
    kind = schema['type']
    if kind == 'object':
        if type(value) is not dict:
            raise ValueError('invalid cached health')
        # Visit only fixed public fields, not arbitrary future internal payloads.
        return {key: _project(value[key], child) for key, child in schema['properties'].items()}
    if type(kind) is list:
        if value is None:
            return None
        kind = kind[0]
    if kind == 'integer':
        if type(value) is not int or not 0 <= value <= MAX_COUNTER:
            raise ValueError('invalid cached counter')
    elif kind == 'boolean':
        if type(value) is not bool:
            raise ValueError('invalid cached flag')
    elif kind == 'string':
        if type(value) is not str:
            raise ValueError('invalid cached enum')
        if schema is REASON:
            return value if len(value) <= 64 and value in REASONS else 'delivery_unknown'
        if value not in schema['enum']:
            raise ValueError('invalid cached enum')
    return value


def handle_delivery_health(ctx, handler):
    try:
        if ctx.delivery_health is None:
            raise ValueError('owner unavailable')
        payload = _project(ctx.delivery_health(), HEALTH_SCHEMA)
        if len(json.dumps(payload, ensure_ascii=False).encode('utf-8')) > MAX_HEALTH_BYTES:
            raise ValueError('health byte limit')
    except Exception:
        return send_json(handler, {'error': 'delivery health unavailable'}, 503)
    return send_json(handler, payload)
