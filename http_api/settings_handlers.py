from __future__ import annotations

import json
import logging
from typing import Any, Dict

try:
    from vt_lookup import set_api_key, set_cache_ttl_days, get_cache_ttl_days
except Exception:
    set_api_key = None
    set_cache_ttl_days = None

    def get_cache_ttl_days():
        return 1

from .context import HttpContext
from .request_limits import get_request_body
from .utils import send_json

logger = logging.getLogger(__name__)


SECRET_FIELDS = frozenset(('vt_api_key', 'api_key', 'misp_key', 'misp_url', 'misp_ca_bundle', 'teams_webhook', 'ens_rpc_url',
                           'DEFAULT_SNS_PROXY_HOSTS', 'DEFAULT_SOLAR_PROXY_HOSTS'))


def redacted_config(value):
    if isinstance(value, list):
        return [redacted_config(v) for v in value]
    if not isinstance(value, dict):
        return value
    out = {k: redacted_config(v) for k, v in value.items() if not k.startswith('_')}
    configured = {}
    for key in SECRET_FIELDS.intersection(value):
        configured[key] = bool(value[key])
        out[key] = ''
    if configured:
        out['configured'] = configured
    return out


def validate_clear_fields(handler, data, allowed):
    fields = data.get('clear_fields', [])
    if not isinstance(fields, list) or any(not isinstance(k, str) or k not in allowed for k in fields):
        send_json(handler, {'error': 'invalid clear_fields'}, 400)
        return None
    if fields and (getattr(handler, 'principal', None) or {}).get('role') != 'admin':
        send_json(handler, {'error': 'admin required to clear secrets'}, 403)
        return None
    return fields


def handle_settings_get(ctx: HttpContext, handler) -> None:
    try:
        from monitor.config_service import get_config_service
        snapshot = get_config_service(ctx).snapshot()
        revision = snapshot['config_revision']
        alerts_out = snapshot.get('alerts') or {}
        ttl_days_current = get_cache_ttl_days()
        try:
            ttl_days_value = int(str(alerts_out.get('vt_cache_ttl_days')).strip())
            if ttl_days_value < 1:
                raise ValueError('invalid ttl')
        except Exception:
            ttl_days_value = int(ttl_days_current or 1)
        alerts_out['vt_cache_ttl_days'] = ttl_days_value

        raw_remove = alerts_out.get('misp_remove_on_absent', False)
        if isinstance(raw_remove, bool):
            alerts_out['misp_remove_on_absent'] = raw_remove
        else:
            alerts_out['misp_remove_on_absent'] = str(raw_remove).strip().lower() in ('1', 'true', 'yes', 'on', 'y')

        send_json(handler, {'settings': {'alerts': redacted_config(alerts_out)}, 'revision': revision})
    except Exception as e:
        send_json(handler, {'error': str(e)}, 500)


def handle_settings_post(ctx: HttpContext, handler) -> None:
    body, too_large = get_request_body(handler, max_length=ctx.max_body_bytes)
    if too_large:
        return
    try:
        data = json.loads(body.decode('utf-8')) if body else {}
    except Exception:
        return send_json(handler, {'error': 'invalid json'}, 400)
    if not isinstance(data, dict):
        return send_json(handler, {'error': 'json object required'}, 400)

    clear_fields = validate_clear_fields(handler, data, SECRET_FIELDS - {'ens_rpc_url'})
    if clear_fields is None:
        return
    from monitor.config_service import commit_request
    result = commit_request(ctx, handler, 'settings', data)
    if result is not None:
        return send_json(handler, {'status': 'ok', 'alerts': redacted_config(result['alerts']),
                                  'revision': result['revision'], 'warnings': result['warnings']})


def apply_runtime_settings(alerts):
    """Best effort, sanitized failures; caller owns writer order but no read lock."""
    try:
        from alerts import init_from_alerts
    except Exception:
        init_from_alerts = None
    warnings = []
    for adapter, value, warning in (
        (set_api_key, alerts.get('vt_api_key', ''), 'vt_api_key_apply_failed'),
        (set_cache_ttl_days, alerts['vt_cache_ttl_days'], 'vt_cache_ttl_apply_failed'),
        (init_from_alerts, alerts, 'alerts_runtime_apply_failed'),
    ):
        if adapter is None:
            warnings.append(warning)
            continue
        try:
            adapter(value)
            if warning == 'alerts_runtime_apply_failed' and alerts.get('misp_url') and alerts.get('api_key'):
                # The legacy alert adapter logs and swallows PyMISP failures.
                # Its boolean return also counts event IDs, so inspect the
                # actual client rather than equating truthy return with success.
                import mispupdate_code
                if getattr(mispupdate_code, 'misp', None) is None:
                    warnings.append(warning)
        except Exception:
            warnings.append(warning)
    return warnings
