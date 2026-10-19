"""Closed cached-only diagnostics projection; no provider or ledger I/O here."""
import json

from monitor.delivery_types import REASONS
from .utils import send_json

MAX_DIAGNOSTICS_BYTES = 32768
MAX_COUNTER = (1 << 63) - 1
STAGES = ('open_owner', 'open_db', 'open_validate', 'transaction_begin',
          'transaction_body', 'transaction_commit', 'transaction_readback',
          'health_refresh', 'worker')
CODES = ('sqlite_busy', 'sqlite_full', 'sqlite_readonly', 'sqlite_corrupt',
         'sqlite_io', 'sqlite_error', 'permission_denied', 'disk_full', 'owner_lock',
         'os_error', 'invalid_state', 'worker_exception', 'unknown')
OPERATIONS = ('unknown', 'teams_send', 'misp_read', 'misp_add', 'misp_delete',
              'misp_sighting_read', 'misp_sighting_add')


def _closed(properties):
    return {'type': 'object', 'properties': properties, 'required': list(properties),
            'additionalProperties': False}


def _enum(values):
    return {'type': 'string', 'enum': list(values)}


def _nullable(schema):
    return {**schema, 'type': [schema['type'], 'null'],
            **({'enum': [None, *schema['enum']]} if 'enum' in schema else {})}


COUNT = {'type': 'integer', 'minimum': 0, 'maximum': MAX_COUNTER}
FLAG = {'type': 'boolean'}
REASON = _enum(sorted(REASONS))
DETAIL_SCHEMA = _closed({
    'operation': _enum(OPERATIONS),
    'http_status': _nullable({'type': 'integer', 'minimum': 100, 'maximum': 599}),
    **{key: _nullable(COUNT) for key in ('response_bytes', 'response_limit',
                                       'attribute_count', 'attribute_limit')},
    'tls_kind': _nullable(_enum(('certificate_verify', 'ssl_failure'))),
    'tls_verify': _nullable(FLAG),
})
RECORD_SCHEMA = _closed({
    'at': COUNT, 'channel': _enum(('teams', 'misp')),
    'state': _enum(('acked', 'continue', 'retry', 'blocked', 'failed')),
    'reason': _nullable(REASON), 'attempt': COUNT, 'items': COUNT,
    'diagnostic': DETAIL_SCHEMA,
})
CHANNEL_SCHEMA = _closed({
    'latest_result': _nullable(RECORD_SCHEMA), 'latest_failure': _nullable(RECORD_SCHEMA),
    'blocked_by_reason': {'type': 'array', 'maxItems': 64,
                          'items': _closed({'reason': REASON, 'count': COUNT})},
})
DIAGNOSTICS_SCHEMA = _closed({
    'version': {'type': 'integer', 'const': 1, 'minimum': 1, 'maximum': 1},
    'observed_at': COUNT, 'counts_stale': FLAG, 'storage_ok': FLAG, 'worker_running': FLAG,
    'coverage': _enum(('covered', 'gap', 'rebaselining')),
    'storage_error': _nullable(_closed({'at': COUNT, 'stage': _enum(STAGES), 'code': _enum(CODES)})),
    'channels': _closed({'teams': CHANNEL_SCHEMA, 'misp': CHANNEL_SCHEMA}),
    'recent_failures': {'type': 'array', 'maxItems': 10, 'items': RECORD_SCHEMA},
})


def _project(value, schema):
    kind = schema['type']
    if type(kind) is list:
        if value is None:
            return None
        kind = kind[0]
    if kind == 'object':
        if type(value) is not dict:
            raise ValueError('invalid object')
        # Never traverse arbitrary internal keys, strings, or future payloads.
        return {key: _project(value[key], child) for key, child in schema['properties'].items()}
    if kind == 'array':
        if type(value) is not list or len(value) > schema['maxItems']:
            raise ValueError('invalid array')
        return [_project(item, schema['items']) for item in value]
    if kind == 'integer':
        valid = type(value) is int and schema['minimum'] <= value <= schema['maximum']
    elif kind == 'boolean':
        valid = type(value) is bool
    else:
        valid = type(value) is str and len(value) <= 64 and value in schema['enum']
    if not valid:
        raise ValueError('invalid diagnostic scalar')
    return value


def handle_delivery_diagnostics(ctx, handler):
    try:
        payload = _project(ctx.delivery_diagnostics(), DIAGNOSTICS_SCHEMA)
        wire = json.dumps(payload, separators=(',', ':'), allow_nan=False).encode('utf-8')
        if len(wire) > MAX_DIAGNOSTICS_BYTES:
            raise ValueError('diagnostics byte limit')
    except Exception:
        return send_json(handler, {'error': 'delivery diagnostics unavailable'}, 503)
    # This boundary has already reduced all strings to fixed protocol grammar.
    # Generic credential substitution can rename keys/enums and invalidate it;
    # do not traverse runtime configuration (or retained provider payloads) here.
    handler.send_response(200)
    handler.send_header('Content-Type', 'application/json; charset=utf-8')
    handler.send_header('Content-Length', str(len(wire)))
    handler.end_headers()
    handler.wfile.write(wire)
