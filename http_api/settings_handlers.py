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
from .utils import send_json

logger = logging.getLogger(__name__)


def handle_settings_get(ctx: HttpContext, handler) -> None:
    try:
        with ctx.config_lock:
            alerts = ctx.shared_config.get('alerts', None)
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

        send_json(handler, {'settings': {'alerts': alerts_out}})
    except Exception as e:
        send_json(handler, {'error': str(e)}, 500)


def handle_settings_post(ctx: HttpContext, handler) -> None:
    length = int(handler.headers.get('Content-Length', '0'))
    body = handler.rfile.read(length) if length > 0 else b''
    try:
        data = json.loads(body.decode('utf-8')) if body else {}
    except Exception:
        return send_json(handler, {'error': 'invalid json'}, 400)

    alerts = data.get('alerts')
    if alerts is None or not isinstance(alerts, dict):
        return send_json(handler, {'error': 'alerts object required'}, 400)

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
            if set_api_key is not None:
                try:
                    set_api_key(vts)
                except Exception:
                    pass
    except Exception:
        return send_json(handler, {'error': 'vt_api_key validation error'}, 400)

    # Validate VT cache TTL (days)
    try:
        ttl_raw = alerts.get('vt_cache_ttl_days')
        ttl_days = get_cache_ttl_days() if ttl_raw in (None, '') else int(str(ttl_raw).strip())
        if ttl_days < 1 or ttl_days > 3650:
            return send_json(handler, {'error': 'vt_cache_ttl_days must be between 1 and 3650'}, 400)
        alerts['vt_cache_ttl_days'] = int(ttl_days)
        if set_cache_ttl_days is not None:
            try:
                set_cache_ttl_days(ttl_days)
            except Exception:
                pass
    except Exception:
        return send_json(handler, {'error': 'invalid vt_cache_ttl_days'}, 400)

    raw_remove = alerts.get('misp_remove_on_absent', False)
    if isinstance(raw_remove, bool):
        alerts['misp_remove_on_absent'] = raw_remove
    else:
        alerts['misp_remove_on_absent'] = str(raw_remove).strip().lower() in ('1', 'true', 'yes', 'on', 'y')

    with ctx.config_lock:
        ctx.shared_config['alerts'] = alerts
        if ctx.config_path:
            try:
                cfg = read_config(ctx.config_path) or {}
                cfg['alerts'] = alerts
                # keep existing domains/servers/interval/custom_decoders if present
                cfg.setdefault('domains', ctx.shared_config.get('domains', []))
                cfg.setdefault('servers', ctx.shared_config.get('servers', []))
                cfg.setdefault('interval', ctx.shared_config.get('interval'))
                cfg.setdefault('max_workers', ctx.shared_config.get('max_workers', 8))
                cfg.setdefault('custom_decoders', ctx.shared_config.get('custom_decoders', []))
                write_config(ctx.config_path, cfg)
                logger.debug('Settings saved to %s', ctx.config_path)
            except Exception as e:
                logger.warning('Failed to save settings to %s: %s', ctx.config_path, e)

    # apply alert runtime immediately (best effort)
    try:
        from alerts import init_from_alerts as _init_alerts_runtime

        _init_alerts_runtime(alerts)
    except Exception as e:
        logger.warning('Failed to apply runtime alert settings: %s', e)

    return send_json(handler, {'status': 'ok', 'alerts': alerts})
