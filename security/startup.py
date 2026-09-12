"""Fail-closed startup and bounded housekeeping for a single server instance."""
import ipaddress
import sqlite3
import threading

from .http import HttpSecurity
from .store import SecurityError, SecurityStore


def open_security(args):
    if args.allow_insecure_remote_http and not args.insecure_http:
        raise ValueError('--allow-insecure-remote-http requires --insecure-http')
    if args.allow_insecure_remote_http and not str(args.public_origin).startswith('http://'):
        raise ValueError('--allow-insecure-remote-http requires an http --public-origin')
    if args.insecure_http and not args.allow_insecure_remote_http and not ipaddress.ip_address(args.http_host).is_loopback:
        raise ValueError('Development HTTP requires a loopback bind address')
    if not 1 <= args.audit_retention_days <= 3650:
        raise ValueError('Audit retention must be 1..3650 days')
    if not 1 <= args.session_idle_minutes <= 1440 or not 1 <= args.session_hours <= 168:
        raise ValueError('Invalid session lifetime')
    try:
        store = SecurityStore(args.security_db, idle_seconds=args.session_idle_minutes * 60,
                              absolute_seconds=args.session_hours * 3600,
                              retention_days=args.audit_retention_days)
        if not store.has_admin():
            raise ValueError('Initialize an administrator with python -m security.cli first')
        HttpSecurity(store, args.public_origin, args.insecure_http, args.trusted_proxy,
                     args.allow_insecure_remote_http)
        store.reconcile_intents()
        store.prune_audit()
        return store
    except (SecurityError, sqlite3.Error) as exc:
        raise ValueError('Security database unavailable; initialize with python -m security.cli') from exc


def _new_stop_event():
    return threading.Event()


def start_housekeeping(store):
    stop = _new_stop_event()

    def maintain():
        while not stop.wait(3600):
            try:
                store.prune_audit()
            except Exception:
                import logging
                logging.getLogger(__name__).error('Audit retention maintenance failed')

    thread = threading.Thread(target=maintain, name='audit-retention', daemon=True)
    thread.start()
    return stop
