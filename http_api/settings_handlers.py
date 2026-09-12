from __future__ import annotations

import json
import logging
from typing import Any, Dict

from config_manager import read_config, write_config

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


SECRET_FIELDS = frozenset(('vt_api_key', 'api_key', 'misp_key', 'misp_url', 'teams_webhook', 'ens_rpc_url',
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


def check_revision(ctx, handler, data):
    revision = ctx.shared_config.get('_config_revision', 0)
    if getattr(handler, 'principal', None) is not None and (
        type(data.get('revision')) is not int or data['revision'] != revision
    ):
        send_json(handler, {'error': 'config revision conflict', 'revision': revision}, 409)
        return False
    return True


def handle_settings_get(ctx: HttpContext, handler) -> None:
    try:
        with ctx.config_lock:
            alerts = ctx.shared_config.get('alerts', None)
            revision = ctx.shared_config.get('_config_revision', 0)
        if alerts is None and ctx.config_path:
            cfg = read_config(ctx.config_path) or {}
            alerts = cfg.get('alerts', {})
        alerts_out = dict(alerts or {})
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

    alerts = data.get('alerts')
    if alerts is None or not isinstance(alerts, dict):
        return send_json(handler, {'error': 'alerts object required'}, 400)

    clear_fields = validate_clear_fields(handler, data, SECRET_FIELDS - {'ens_rpc_url'})
    if clear_fields is None:
        return
    alerts = dict(alerts)
    alerts.pop('configured', None)

    # Validate VirusTotal API key if provided (basic checks)
    try:
        import re as _re

        vt = alerts.get('vt_api_key')
        if vt is not None and str(vt).strip() != '':
            vts = str(vt).strip()
            if _re.search(r"\s", vts) or len(vts) < 20 or len(vts) > 128:
                return send_json(handler, {'error': 'invalid vt_api_key (bad format or length)'}, 400)
            if not (_re.fullmatch(r'[A-Fa-f0-9]{64}', vts) or _re.fullmatch(r'[A-Za-z0-9\-_=]+', vts)):
                return send_json(handler, {'error': 'invalid vt_api_key (unexpected characters)'}, 400)
            alerts['vt_api_key'] = vts
    except Exception:
        return send_json(handler, {'error': 'vt_api_key validation error'}, 400)

    # Validate VT cache TTL (days)
    try:
        ttl_raw = alerts.get('vt_cache_ttl_days')
        ttl_days = get_cache_ttl_days() if ttl_raw in (None, '') else int(str(ttl_raw).strip())
        if ttl_days < 1 or ttl_days > 3650:
            return send_json(handler, {'error': 'vt_cache_ttl_days must be between 1 and 3650'}, 400)
        if 'vt_cache_ttl_days' in alerts:
            alerts['vt_cache_ttl_days'] = int(ttl_days)
    except Exception:
        return send_json(handler, {'error': 'invalid vt_cache_ttl_days'}, 400)

    if 'misp_remove_on_absent' in alerts:
        raw_remove = alerts['misp_remove_on_absent']
        alerts['misp_remove_on_absent'] = raw_remove if isinstance(raw_remove, bool) else str(raw_remove).strip().lower() in ('1', 'true', 'yes', 'on', 'y')

    with ctx.config_lock:
        if not check_revision(ctx, handler, data):
            return
        cfg = read_config(ctx.config_path) or {} if ctx.config_path else {}
        cfg.update({k: v for k, v in ctx.shared_config.items() if not k.startswith('_')})
        merged = dict(cfg.get('alerts') or {})
        merged.update({k: v for k, v in alerts.items() if k not in SECRET_FIELDS or str(v or '').strip()})
        for key in clear_fields:
            merged.pop(key, None)
        merged.setdefault('vt_cache_ttl_days', get_cache_ttl_days())
        alerts = merged
        cfg['config_revision'] = ctx.shared_config.get('_config_revision', 0) + 1
        cfg['alerts'] = alerts
        cfg = {k: v for k, v in cfg.items() if not k.startswith('_')}
        if ctx.config_path:
            try:
                write_config(ctx.config_path, cfg)
            except Exception as e:
                logger.warning('Failed to save settings to %s: %s', ctx.config_path, e)
                return send_json(handler, {'error': f'config save failed: {e}'}, 500)
            logger.debug('Settings saved to %s', ctx.config_path)
        ctx.shared_config['alerts'] = alerts
        revision = ctx.shared_config.get('_config_revision', 0) + 1
        ctx.shared_config['_config_revision'] = revision

        if set_api_key is not None:
            try:
                set_api_key(alerts.get('vt_api_key', ''))
            except Exception:
                pass
        if set_cache_ttl_days is not None:
            try:
                set_cache_ttl_days(alerts['vt_cache_ttl_days'])
            except Exception:
                pass

        # apply alert runtime immediately (best effort)
        try:
            from alerts import init_from_alerts as _init_alerts_runtime

            _init_alerts_runtime(alerts)
        except Exception as e:
            logger.warning('Failed to apply runtime alert settings: %s', e)

    return send_json(handler, {'status': 'ok', 'alerts': redacted_config(alerts), 'revision': revision})
