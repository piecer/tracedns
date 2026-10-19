"""Explicit manual Teams send using only the saved configuration revision."""
import json

from monitor.delivery_diagnostics import normalize_diagnostic
from monitor.delivery_types import REASONS
from .delivery_diagnostics import DETAIL_SCHEMA, _closed, _enum, _nullable, _project
from .request_limits import get_request_body


TEST_REASONS = REASONS | {'test_in_progress', 'test_cooldown', 'configuration_changed', 'runtime_unavailable'}
CONFLICTS = {'configuration_changed', 'destination_disabled', 'destination_invalid',
             'adapter_unapplied', 'configuration_unavailable'}
RESULT_SCHEMA = _closed({
    'status': _enum(('accepted', 'failed', 'not_sent')),
    'reason': _nullable(_enum(sorted(TEST_REASONS))),
    'retry_after': _nullable({'type': 'integer', 'minimum': 0, 'maximum': 30}),
    'diagnostic': DETAIL_SCHEMA,
})
REQUEST_SCHEMA = _closed({'revision': {'type': 'integer', 'minimum': 0, 'maximum': 2**53 - 1}})


def _result(status, reason):
    return dict(status=status, reason=reason, retry_after=None, diagnostic=normalize_diagnostic())


def _status(payload):
    status, reason = payload['status'], payload['reason']
    if status == 'accepted' and reason is None:
        return 200
    if status == 'failed' and reason in REASONS:
        return 502
    if status == 'not_sent':
        if reason in ('test_in_progress', 'test_cooldown'):
            return 429
        if reason in CONFLICTS:
            return 409
        if reason == 'runtime_unavailable':
            return 503
    raise ValueError('invalid test result')


def _send(handler, payload, code):
    # Only closed, validated grammar may cross this boundary. Generic secret
    # substitution would corrupt enums (and erase useful 502 diagnostics).
    wire = json.dumps(payload, separators=(',', ':'), allow_nan=False).encode('utf-8')
    handler.send_response(code)
    handler.send_header('Content-Type', 'application/json; charset=utf-8')
    handler.send_header('Content-Length', str(len(wire)))
    if code == 429 and payload['retry_after'] is not None:
        handler.send_header('Retry-After', str(payload['retry_after']))
    handler.end_headers()
    handler.wfile.write(wire)


def _unique_object(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError('duplicate fields')
    return value


def handle_teams_test(ctx, handler):
    raw, rejected = get_request_body(handler, max_length=handler.max_body_bytes)
    if rejected:
        return
    try:
        data = json.loads(raw, object_pairs_hook=_unique_object)
        if (type(data) is not dict or set(data) != {'revision'} or
                type(data['revision']) is not int or not 0 <= data['revision'] <= 2**53 - 1):
            raise ValueError()
    except (ValueError, UnicodeError, RecursionError):
        return _send(handler, {'error': 'revision must be the only field and a nonnegative safe integer'}, 400)
    runtime = getattr(ctx.config_service, 'delivery_runtime', None)
    if runtime is None or not callable(getattr(runtime, 'test_teams', None)):
        return _send(handler, _result('not_sent', 'runtime_unavailable'), 503)
    try:
        payload = _project(runtime.test_teams(data['revision']), RESULT_SCHEMA)
        code = _status(payload)
    except Exception:
        # Once invoked, an exception or malformed result cannot prove no send.
        payload, code = _result('failed', 'delivery_unknown'), 502
    return _send(handler, payload, code)
