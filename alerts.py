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
                misp_obj = PyMISP(murl, mkey, False)
                mispupdate_code.misp = misp_obj
            except Exception as e:
                logger.warning("Failed to initialize PyMISP client: %s", e)

    _initialized = True


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
    }

    _apply_alert_values(
        misp_url=_cfg.get('misp_url'),
        misp_key=_cfg.get('api_key'),
        push_event_id=_cfg.get('push_event_id'),
        teams_webhook=_cfg.get('teams_webhook'),
        misp_remove_on_absent=_cfg.get('misp_remove_on_absent'),
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
    )
    return bool(_teams_webhook or _misp_event_id or getattr(mispupdate_code, 'misp', None))


def _send_teams(message: str, title: str = 'C2 TXT Alert'):
    if not _teams_webhook:
        return False
    payload = {
        'title': title,
        'text': message
    }
    try:
        requests.post(_teams_webhook, json=payload, timeout=10)
        return True
    except Exception as e:
        logger.warning("Teams webhook send failed: %s", e)
        return False


def _normalize_ip_tuples(ip_tuples):
    """Return deduplicated (ip, label, source_type) tuples."""
    out = []
    seen = set()
    allowed_types = {'TXT', 'A', 'ENS'}
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


def _format_local_timestamp():
    now = datetime.now().astimezone()
    tz_name = str(now.tzname() or '').strip()
    ts = now.strftime('%Y-%m-%d %H:%M:%S')
    offset = now.strftime('%z')
    if tz_name:
        return f"{ts} {tz_name} ({offset})"
    return f"{ts} ({offset})"


def _build_alert_body(action: str, ip_tuples, context=None):
    """Build a structured Teams alert body with local-time operational summary."""
    entries = _normalize_ip_tuples(ip_tuples)
    ts_local = _format_local_timestamp()

    unique_ips = sorted({ip for ip, _label, _stype in entries})
    source_counter = Counter()
    domain_counter = Counter()
    for _ip, label, source_type in entries:
        source_counter[str(source_type or 'TXT').upper()] += 1
        for dom in _split_labels(label):
            domain_counter[dom] += 1

    source_summary = ", ".join([f"{k}:{source_counter.get(k, 0)}" for k in ('TXT', 'A', 'ENS') if source_counter.get(k, 0) > 0]) or '-'
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


def alert_new_ips(ip_tuples: List[Tuple[str, str]], context=None):
    """Alert about newly discovered C2 IPs.

    ip_tuples: list of (ip, label/domain[, source_type]) where source_type is TXT/A/ENS
    Behavior:
      - Sends a Teams webhook (best-effort)
      - Calls mispupdate_code.add_unique_ips(event_id, ip_tuples) if event configured
    """
    if not _initialized:
        init_from_config()
    entries = _normalize_ip_tuples(ip_tuples)
    if not entries:
        return

    body = _build_alert_body('Added', entries, context=context)

    # Teams alert (best effort)
    _send_teams(body, title='C2 IOC Add Alert')

    # Add to MISP event if configured
    if _misp_event_id and hasattr(mispupdate_code, 'add_unique_ips'):
        misp_client = getattr(mispupdate_code, 'misp', None)
        if misp_client is None:
            logger.warning("MISP event id is set but MISP client is not initialized; skipping MISP push.")
            return
        try:
            ok = mispupdate_code.add_unique_ips(_misp_event_id, entries)
            if ok is False:
                logger.warning("MISP push reported failure for event_id=%s", _misp_event_id)
        except Exception as e:
            logger.warning("MISP push failed: %s", e)


def alert_removed_ips(ip_tuples: List[Tuple[str, str]], context=None):
    """Alert about removed C2 IPs.

    ip_tuples: list of (ip, label/domain[, source_type]) where source_type is TXT/A/ENS
    Behavior:
      - Sends a Teams webhook (best-effort)
      - Calls mispupdate_code.remove_ips(event_id, ip_tuples) if event configured
    """
    if not _initialized:
        init_from_config()
    entries = _normalize_ip_tuples(ip_tuples)
    if not entries:
        return

    body = _build_alert_body('Removed', entries, context=context)

    _send_teams(body, title='C2 IOC Remove Alert')

    if not _misp_remove_on_absent:
        logger.info("MISP delete disabled by config; keeping existing attributes in event.")
        return

    if _misp_event_id and hasattr(mispupdate_code, 'remove_ips'):
        misp_client = getattr(mispupdate_code, 'misp', None)
        if misp_client is None:
            logger.warning("MISP event id is set but MISP client is not initialized; skipping MISP delete.")
            return
        try:
            ok = mispupdate_code.remove_ips(_misp_event_id, entries)
            if ok is False:
                logger.warning("MISP delete reported failure for event_id=%s", _misp_event_id)
        except Exception as e:
            logger.warning("MISP delete failed: %s", e)


__all__ = ['init_from_config', 'init_from_alerts', 'alert_new_ips', 'alert_removed_ips']
