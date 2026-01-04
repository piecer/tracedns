#!/usr/bin/env python3
"""Alerting helpers: Teams webhook + MISP integration for new C2 IPs.

This module provides a small wrapper that can be initialized from a
`config.ini` (same format used by existing scripts) and exposes
`alert_new_ips(ip_tuples)` where each tuple is (ip, label).

It attempts to send a Teams webhook (if configured) and to add IPs to
the configured MISP event using functions in `mispupdate_code.py`.
"""
import json
import requests
import os
from typing import List, Tuple

try:
    from pymisp import PyMISP
except Exception:
    PyMISP = None

import mispupdate_code

_initialized = False
_cfg = {}
_misp_event_id = None
_teams_webhook = None


def init_from_config(path='config.ini'):
    """Load configuration and initialize MISP client if possible.

    Expected `config.ini` [global] keys:
      - misp_url
      - api_key
      - push_event_id  (c2_event_id)
      - teams_webhook (optional)
    """
    global _initialized, _cfg, _misp_event_id, _teams_webhook
    try:
        cfg = mispupdate_code.load_ini_config(path)
    except Exception:
        cfg = None
    if not cfg:
        _initialized = True
        _cfg = {}
        return

    _cfg = cfg
    try:
        _teams_webhook = cfg.get('global', 'teams_webhook') if cfg.has_option('global', 'teams_webhook') else mispupdate_code.workflow_url
    except Exception:
        _teams_webhook = getattr(mispupdate_code, 'workflow_url', None)

    try:
        _misp_event_id = int(cfg.get('global', 'push_event_id')) if cfg.has_option('global', 'push_event_id') else None
    except Exception:
        _misp_event_id = None

    # initialize PyMISP if available and credentials present
    try:
        misp_url = cfg.get('global', 'misp_url') if cfg.has_option('global', 'misp_url') else None
        misp_key = cfg.get('global', 'api_key') if cfg.has_option('global', 'api_key') else None
        if misp_url and misp_key and PyMISP:
            misp_obj = PyMISP(misp_url, misp_key, False)
            # set into mispupdate_code so its helper functions can use it
            mispupdate_code.misp = misp_obj
    except Exception:
        # don't fail initialization on misp problems
        pass

    _initialized = True


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
    except Exception:
        return False


def alert_new_ips(ip_tuples: List[Tuple[str, str]]):
    """Alert about newly discovered C2 IPs.

    ip_tuples: list of (ip, label/domain)
    Behavior:
      - Sends a Teams webhook (best-effort)
      - Calls mispupdate_code.add_unique_ips(event_id, ip_tuples) if event configured
    """
    if not _initialized:
        init_from_config()
    if not ip_tuples:
        return

    # compose a concise message
    try:
        lines = [f"New C2 IP detected: {ip} (source: {label})" for ip, label in ip_tuples]
        body = "\n".join(lines)
    except Exception:
        body = str(ip_tuples)

    # Teams alert (best effort)
    _send_teams(body, title='C2 TXT Alert')

    # Add to MISP event if configured
    if _misp_event_id and hasattr(mispupdate_code, 'add_unique_ips'):
        try:
            mispupdate_code.add_unique_ips(_misp_event_id, ip_tuples)
        except Exception:
            pass


__all__ = ['init_from_config', 'alert_new_ips']
