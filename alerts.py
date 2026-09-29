#!/usr/bin/env python3
"""Alerting helpers: Teams webhook + MISP integration for new C2 IPs.

This module provides a small wrapper that can be initialized from:
- `config.ini` ([global] section), or
- `dns_config.json`'s `alerts` object
and exposes
`alert_new_ips(ip_tuples)` / `alert_removed_ips(ip_tuples)` where each
tuple is (ip, label).

It attempts to send a Teams webhook (if configured) and to add IPs to
the configured MISP event using functions in `mispupdate_code.py`.
"""
import logging
from datetime import datetime
from collections import Counter
from typing import List, Tuple
import requests
from monitor.delivery_adapters import validated_tls_verify

try:
    from pymisp import PyMISP
except Exception:
    PyMISP = None

try:
    # Package import (tests, module execution)
    from . import mispupdate_code
except Exception:
    # Script import (running from tracedns directory)
    import mispupdate_code


logger = logging.getLogger(__name__)

_initialized = False
_cfg = {}
_misp_event_id = None
_teams_webhook = None
_misp_remove_on_absent = False


def _sanitize_webhook(url):
    """Return a usable webhook URL or None."""
    s = str(url or '').strip()
    if not s:
        return None
    # reject obvious placeholder from legacy helper
    if s in ('https://X', 'http://X', 'X'):
        return None
    if not (s.startswith('http://') or s.startswith('https://')):
        return None
    return s


def _reset_runtime():
    global _misp_event_id, _teams_webhook, _misp_remove_on_absent
    _misp_event_id = None
    _teams_webhook = None
    _misp_remove_on_absent = False
    # Ensure downstream helper starts from a known state.
    try:
        mispupdate_code.misp = None
    except Exception:
        pass


def _to_bool(value, default=False):
    """Normalize loose bool-like config values."""
    if isinstance(value, bool):
        return value
    if value is None:
        return bool(default)
    s = str(value).strip().lower()
    if s in ('1', 'true', 'yes', 'on', 'y'):
        return True
    if s in ('0', 'false', 'no', 'off', 'n', ''):
        return False
    return bool(default)


def _apply_alert_values(
    misp_url=None,
    misp_key=None,
    push_event_id=None,
    teams_webhook=None,
    misp_remove_on_absent=None,
    misp_ca_bundle=None,
):
    """Apply alert settings to in-memory runtime (best effort)."""
    global _initialized, _misp_event_id, _teams_webhook, _misp_remove_on_absent

    _reset_runtime()

    _teams_webhook = _sanitize_webhook(teams_webhook)
    _misp_remove_on_absent = _to_bool(misp_remove_on_absent, default=False)

    try:
        pev = str(push_event_id or '').strip()
        _misp_event_id = int(pev) if pev else None
    except Exception:
        _misp_event_id = None

    murl = str(misp_url or '').strip()
    mkey = str(misp_key or '').strip()
    if murl and mkey:
        if PyMISP is None:
            logger.warning("PyMISP not installed; MISP alerts disabled.")
        else:
            try:
                misp_obj = PyMISP(murl, mkey, validated_tls_verify(misp_ca_bundle))
                mispupdate_code.misp = misp_obj
            except Exception:
                logger.warning("MISP client initialization failed: adapter_unapplied")

    _initialized = True


def select_alert_configuration(configuration, path='config.ini'):
    """Pure bootstrap selection for the registry; no PyMISP construction/I/O."""
    if isinstance(configuration, dict) and 'alerts' in configuration:
        value = configuration['alerts']
        return dict(value) if isinstance(value, dict) else {}
    try:
        cfg = mispupdate_code.load_ini_config(path)
        if not cfg.has_section('global'):
            return {}
        return {name: cfg.get('global', name, fallback='') for name in (
            'misp_url', 'api_key', 'push_event_id', 'teams_webhook',
            'misp_remove_on_absent', 'misp_ca_bundle')}
    except Exception:
        return {}


def init_from_configuration(configuration, path='config.ini'):
    """Select by provenance, never fall back on runtime readiness failure."""
    if isinstance(configuration, dict) and 'alerts' in configuration:
        return init_from_alerts(configuration['alerts'])
    return init_from_config(path)


def init_from_config(path='config.ini'):
    """Load configuration and initialize MISP client if possible.

    Expected `config.ini` [global] keys:
      - misp_url
      - api_key
      - push_event_id  (c2_event_id)
      - teams_webhook (optional)
    """
    global _initialized, _cfg
    try:
        cfg = mispupdate_code.load_ini_config(path)
    except Exception:
        cfg = None

    # ConfigParser object is truthy even if file/section is missing.
    if cfg is None or not hasattr(cfg, 'has_section') or not cfg.has_section('global'):
        _cfg = {}
        _reset_runtime()
        _initialized = True
        return False

    _cfg = {
        'misp_url': cfg.get('global', 'misp_url', fallback=''),
        'api_key': cfg.get('global', 'api_key', fallback=''),
        'push_event_id': cfg.get('global', 'push_event_id', fallback=''),
        'teams_webhook': cfg.get('global', 'teams_webhook', fallback=''),
        # Default false: keep MISP attributes even when domain-side IP disappears.
        'misp_remove_on_absent': cfg.get('global', 'misp_remove_on_absent', fallback='false'),
        'misp_ca_bundle': cfg.get('global', 'misp_ca_bundle', fallback=''),
    }

    _apply_alert_values(
        misp_url=_cfg.get('misp_url'),
        misp_key=_cfg.get('api_key'),
        push_event_id=_cfg.get('push_event_id'),
        teams_webhook=_cfg.get('teams_webhook'),
        misp_remove_on_absent=_cfg.get('misp_remove_on_absent'),
        misp_ca_bundle=_cfg.get('misp_ca_bundle'),
    )
    return bool(_teams_webhook or _misp_event_id or getattr(mispupdate_code, 'misp', None))


def init_from_alerts(alerts: dict):
    """Initialize alerting from `dns_config.json` alerts dict."""
    global _initialized, _cfg
    if not isinstance(alerts, dict):
        _cfg = {}
        _reset_runtime()
        _initialized = True
        return False

    _cfg = dict(alerts)
    _apply_alert_values(
        misp_url=alerts.get('misp_url'),
        misp_key=alerts.get('api_key'),
        push_event_id=alerts.get('push_event_id'),
        teams_webhook=alerts.get('teams_webhook'),
        misp_remove_on_absent=alerts.get('misp_remove_on_absent', False),
        misp_ca_bundle=alerts.get('misp_ca_bundle'),
    )
    return bool(_teams_webhook or _misp_event_id or getattr(mispupdate_code, 'misp', None))


def _send_teams(message: str, title: str = 'C2 TXT Alert'):
    if not _teams_webhook:
        return False
    payload = {
        'title': title,
        'text': message
    }
    response = None
    try:
        response = requests.post(_teams_webhook, json=payload, timeout=(3, 10),
                                 allow_redirects=False, stream=True, verify=True)
        if type(response.status_code) is not int or not 200 <= response.status_code < 300:
            return False
        size = 0
        for chunk in response.iter_content(chunk_size=65536):
            size += len(chunk)
            if size > 2 * 1024 * 1024:
                return False
        return True
    except Exception:
        logger.warning("Teams webhook send failed: transport_error")
        return False
    finally:
        if response is not None:
            response.close()


def _normalize_ip_tuples(ip_tuples):
    """Return deduplicated (ip, label, source_type) tuples."""
    out = []
    seen = set()
    allowed_types = {'TXT', 'A', 'ENS', 'SNS'}
    for item in ip_tuples or []:
        ip = ''
        label = 'unknown'
        source_type = 'TXT'
        if isinstance(item, (list, tuple)):
            if len(item) > 0:
                ip = str(item[0] or '').strip()
            if len(item) > 1:
                label = str(item[1] or '').strip() or 'unknown'
            if len(item) > 2:
                source_type = str(item[2] or '').strip().upper() or 'TXT'
        else:
            ip = str(item or '').strip()
        if not ip:
            continue
        if source_type not in allowed_types:
            source_type = 'TXT'
        key = (ip, label, source_type)
        if key in seen:
            continue
        seen.add(key)
        out.append((ip, label, source_type))
    return sorted(out, key=lambda x: (x[0], x[1], x[2]))


def _split_labels(label: str):
    text = str(label or '').strip()
    if not text:
        return ['unknown']
    parts = [x.strip() for x in text.split(',') if x and x.strip()]
    return parts or ['unknown']


def _format_local_timestamp(created=None):
    now = (datetime.now() if created is None else datetime.fromtimestamp(created)).astimezone()
    tz_name = str(now.tzname() or '').strip()
    ts = now.strftime('%Y-%m-%d %H:%M:%S')
    offset = now.strftime('%z')
    if tz_name:
        return f"{ts} {tz_name} ({offset})"
    return f"{ts} ({offset})"


def _build_alert_body(action: str, ip_tuples, context=None):
    """Build a structured Teams alert body with local-time operational summary."""
    entries = _normalize_ip_tuples(ip_tuples)
    created = context.get('created') if isinstance(context, dict) else None
    ts_local = _format_local_timestamp(created) if created is not None else _format_local_timestamp()

    unique_ips = sorted({ip for ip, _label, _stype in entries})
    source_counter = Counter()
    domain_counter = Counter()
    for _ip, label, source_type in entries:
        source_counter[str(source_type or 'TXT').upper()] += 1
        for dom in _split_labels(label):
            domain_counter[dom] += 1

    source_summary = ", ".join([f"{k}:{source_counter.get(k, 0)}" for k in ('TXT', 'A', 'ENS', 'SNS') if source_counter.get(k, 0) > 0]) or '-'
    domain_summary = ", ".join([f"{dom}({cnt})" for dom, cnt in domain_counter.most_common(5)]) or '-'
    unique_domain_count = len(domain_counter)

    lines = [
        f"Action: {action}",
        f"Time (Local): {ts_local}",
        f"Entries: {len(entries)}",
        f"Unique IPs: {len(unique_ips)}",
        f"Unique Domains: {unique_domain_count}",
        f"Source Types: {source_summary}",
        f"Top Domains: {domain_summary}",
    ]
    if isinstance(context, dict):
        scope = str(context.get('scan_scope') or '').strip()
        domain_targets = context.get('domain_targets')
        server_targets = context.get('server_targets')
        if scope or domain_targets is not None or server_targets is not None:
            lines.append(
                "Cycle Scope: "
                + (scope or 'unknown')
                + f" | domains={domain_targets if domain_targets is not None else '-'}"
                + f" | servers={server_targets if server_targets is not None else '-'}"
            )

    max_items = 60
    lines.append(f"Items (first {max_items}):")
    for ip, label, source_type in entries[:max_items]:
        lines.append(f"- [{source_type}] {ip} | source={label}")
    if len(entries) > max_items:
        lines.append(f"... +{len(entries) - max_items} more")
    return "\n".join(lines)


def render_teams_body(action, entries, context=None):
    """Render a complete chunk; optional context['created'] is persisted epoch time.

    Store glue remains render(entries, action, created), calling this function
    with (action, entries, {'created': created}). Persist the body for retries.
    """
    from monitor.delivery_types import TeamsPayloadTooLarge, encode_body
    if action not in ('Added', 'Removed'):
        raise ValueError('payload_invalid')
    if len(entries) > 60:
        raise TeamsPayloadTooLarge('payload_limit')
    body = {'title': 'C2 IOC Add Alert' if action == 'Added' else 'C2 IOC Remove Alert',
            'text': _build_alert_body(action, entries, context=context)}
    if len(encode_body(body)) > 24 * 1024:
        raise TeamsPayloadTooLarge('payload_limit')
    return body


def _legacy_alert(action, ip_tuples, context):
    if not _initialized:
        init_from_config()
    entries = _normalize_ip_tuples(ip_tuples)
    outcomes = {'teams': None, 'misp': None}
    if not entries:
        return outcomes
    if _teams_webhook:
        try:
            body = render_teams_body(action, entries, context=context)
            outcomes['teams'] = _send_teams(body['text'], title=body['title']) is True
        except Exception:
            outcomes['teams'] = False
            logger.warning('Teams send failed: payload_limit')
    if _misp_event_id and (action == 'Added' or _misp_remove_on_absent):
        if getattr(mispupdate_code, 'misp', None) is None:
            outcomes['misp'] = False
        else:
            operation = mispupdate_code.add_unique_ips if action == 'Added' else mispupdate_code.remove_ips
            try:
                outcomes['misp'] = operation(_misp_event_id, entries) is True
            except Exception:
                outcomes['misp'] = False
                logger.warning('MISP operation failed: provider_error')
    return outcomes


def alert_new_ips(ip_tuples: List[Tuple[str, str]], context=None):
    """Legacy caller-compatible helper; independent true/false/disabled results."""
    return _legacy_alert('Added', ip_tuples, context)


def alert_removed_ips(ip_tuples: List[Tuple[str, str]], context=None):
    """Legacy caller-compatible helper; a disabled channel is None, not ACK."""
    return _legacy_alert('Removed', ip_tuples, context)


__all__ = ['init_from_config', 'init_from_alerts', 'alert_new_ips', 'alert_removed_ips']
