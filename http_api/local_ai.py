"""Thin local-AI HTTP adapter; the central security wrapper owns access/audit."""
import json
import re
import time
from urllib.parse import urlsplit

from local_ai.contracts import AIError, ERROR_STATUS, MAX_REQUEST_BYTES, load_request, parse_object
from local_ai.privacy import PrivacyError, require_secret_free
from .request_limits import get_request_body

JOB_PATH = re.compile(r'/ai/jobs/([a-f0-9]{32})(/cancel)?')
MAX_RESPONSE_BYTES = 32768


def _write(handler, wire, status):
    handler.send_response(status)
    handler.send_header('Content-Type', 'application/json; charset=utf-8')
    handler.send_header('Content-Length', str(len(wire)))
    handler.end_headers()
    handler.wfile.write(wire)


def send_error(handler, error):
    # Fixed grammar deliberately bypasses secret substitution of protocol enums.
    code = error.code if type(error.code) is str and error.code in ERROR_STATUS else 'source_unavailable'
    if code == 'audit_unavailable':
        handler._security_unavailable = True
    wire = json.dumps({'error': code, 'code': code,
                      'request_id': getattr(handler, 'request_id', '')}, separators=(',', ':')).encode()
    return _write(handler, wire, ERROR_STATUS[code])


def _body(handler):
    if hasattr(handler, '_ai_request_body'):
        return handler._ai_request_body
    raw, rejected = get_request_body(handler, max_length=MAX_REQUEST_BYTES)
    return None if rejected else raw


def _send(ctx, handler, payload, status, service):
    # Service envelopes are already bounded owned values; no raw provider data
    # enters this adapter. Recheck secret/source authority for retained results.
    if payload.get('result') is not None:
        try:
            wire = require_secret_free(payload, ctx.shared_config, ctx.config_lock, ctx.read_model,
                                       time.monotonic() + 1, max_bytes=MAX_RESPONSE_BYTES)
        except PrivacyError:
            raise AIError('privacy_unavailable') from None
        current = service.get(payload['job_id'], handler.principal)
        for key in ('cancellation_requested', 'cancellation_confirmed'):
            if key in payload:
                current[key] = payload[key]
        if json.loads(wire) != current:
            raise AIError('source_revoked')
    else:
        wire = json.dumps(payload, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
    if len(wire) > MAX_RESPONSE_BYTES:
        raise AIError('too_large')
    return _write(handler, wire, status)


def handle_local_ai(ctx, handler):
    parsed = urlsplit(handler.path)
    service = getattr(handler, 'local_ai', None)
    try:
        if parsed.query:
            raise AIError('invalid_request')
        if handler.command == 'GET' and parsed.path == '/ai/status':
            payload = ({'enabled': False, 'accepting': False, 'provider_state': 'disabled',
                        'queued': 0, 'active_job': None} if service is None else service.status(handler.principal))
            return _send(ctx, handler, payload, 200, service)
        if handler.command == 'POST' and parsed.path == '/ai/jobs':
            raw = _body(handler)
            if raw is None:
                return
            request = load_request(raw)
            if service is None:
                raise AIError('disabled')
            payload = service.submit(request, handler.principal,
                                     request_id=handler.request_id, source_ip=handler.source_ip)
            return _send(ctx, handler, payload, 202, service)
        match = JOB_PATH.fullmatch(parsed.path)
        if match is None or service is None:
            raise AIError('not_found')
        if handler.command == 'GET' and not match[2]:
            return _send(ctx, handler, service.get(match[1], handler.principal), 200, service)
        if handler.command == 'POST' and match[2]:
            raw = _body(handler)
            if raw is None:
                return
            if parse_object(raw):
                raise AIError('invalid_request')
            return _send(ctx, handler, service.cancel(match[1], handler.principal), 200, service)
        raise AIError('not_found')
    except AIError as error:
        return send_error(handler, error)
