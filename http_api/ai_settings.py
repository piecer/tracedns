"""Admin settings adapter. No provider traffic; never serialize private settings."""
import json
import time

from jsonschema import Draft202012Validator
from urllib.parse import urlsplit

from local_ai.contracts import AIError, parse_object
from local_ai.privacy import PrivacyError, require_secret_free
from local_ai.provider_settings import public_settings
from monitor.config_service import ConfigError, get_config_service
from .local_ai import _body, _write, send_error
from .ai_settings_schema import GET_SCHEMA, POST_SCHEMA


def encode_receipt(ctx, payload, *, post):
    schema = POST_SCHEMA if post else GET_SCHEMA
    if not Draft202012Validator(schema).is_valid(payload):
        raise AIError('privacy_unavailable')
    return require_secret_free(payload, ctx.shared_config, ctx.config_lock, ctx.read_model,
                               time.monotonic() + 1, max_bytes=16384)


def handle_ai_settings(ctx, handler):
    try:
        if urlsplit(handler.path).query or handler.command not in ('GET', 'POST'):
            raise AIError('invalid_request')
        if not getattr(handler, 'principal', None) or handler.principal.get('role') != 'admin':
            raise AIError('source_revoked')
        service = get_config_service(ctx)
        if handler.command == 'POST':
            if handler.headers.get('Content-Type', '').split(';')[0].strip().lower() != 'application/json':
                raise AIError('invalid_request')
            raw = _body(handler)
            if raw is None:
                return
            data = parse_object(raw)
            result = service.commit('ai_settings', data, expected_revision=data.get('revision'))
            handler._ai_settings_committed = True
            wire = result.get('ai_settings_wire')
            if type(wire) is not bytes or len(wire) > 16384:
                raise AIError('privacy_unavailable')
            # It was already checked against the exact committed secret set.
            # Also reject collisions introduced by an intervening writer.
            handler._ai_settings_response = encode_receipt(ctx, json.loads(wire), post=True)
            return
        else:
            snapshot = service.snapshot()
            payload = {'revision': snapshot['config_revision'],
                       'settings': public_settings(snapshot.get('local_ai')),
                       'runtime': handler.local_ai.runtime()}
        wire = encode_receipt(ctx, payload, post=False)
        with ctx.config_lock:
            service._require_storage()
            revision = ctx.shared_config.get('_config_revision', ctx.shared_config.get('config_revision', 0))
            if revision != payload['revision']:
                raise AIError('source_revoked')
        return _write(handler, wire, 200)
    except PrivacyError:
        return send_error(handler, AIError('privacy_unavailable'))
    except AIError as error:
        return send_error(handler, error)
    except ConfigError as error:
        # Config errors may originate in unrelated decoder validation. Never
        # serialize that prose or any submitted value through this route.
        code = ('config_revision_conflict' if error.status == 409 else
                error.payload.get('code', 'invalid_request' if error.status == 400 else 'config_save_failed'))
        if code not in {'config_revision_conflict', 'config_save_failed', 'invalid_request',
                        'config_storage_unavailable', 'config_revision_exhausted', 'stopped'}:
            code = 'config_save_failed'
        payload = {'error': 'config revision conflict' if code == 'config_revision_conflict' else code,
                   'code': code, 'request_id': handler.request_id}
        if error.status == 409:
            payload['revision'] = error.payload['revision']
        return _write(handler, json.dumps(payload).encode(), error.status)
