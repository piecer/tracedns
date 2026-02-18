#!/usr/bin/env python3
"""HTTP server bootstrap and shared-state wiring for TraceDNS UI/API."""

import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

from http_api_handlers import attach_api_handlers


def purge_removed_domains_state(current_results, history, history_dir, removed_domains):
    """Purge in-memory and on-disk history state for removed domains."""
    removed = [str(d or '').strip() for d in (removed_domains or []) if str(d or '').strip()]
    if not removed:
        return
    for domain in removed:
        try:
            if isinstance(current_results, dict):
                current_results.pop(domain, None)
        except Exception:
            pass
        try:
            if isinstance(history, dict):
                history.pop(domain, None)
        except Exception:
            pass
        try:
            if history_dir:
                fp = os.path.join(history_dir, f"{domain}.json")
                if os.path.isfile(fp):
                    os.remove(fp)
        except Exception:
            pass


def load_frontend_html():
    """Load primary frontend HTML; fallback to dashboard when unavailable."""
    base = os.path.dirname(__file__)
    dashboard_path = os.path.join(base, "dns_dashboard.html")
    frontend_path = os.path.join(base, "dns_frontend.html")
    for p in (frontend_path, dashboard_path):
        try:
            with open(p, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            continue
    return "<html><body>Frontend missing</body></html>"


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Threaded HTTP server (each request handled in its own thread)."""

    daemon_threads = True


def make_handler(shared_config, config_lock, config_path, history_dir, current_results, history):
    """Create configured HTTP request handler class bound to runtime state."""
    frontend_html = load_frontend_html()

    class ConfigHandler(BaseHTTPRequestHandler):
        pass

    return attach_api_handlers(
        ConfigHandler,
        frontend_html=frontend_html,
        shared_config=shared_config,
        config_lock=config_lock,
        config_path=config_path,
        history_dir=history_dir,
        current_results=current_results,
        history=history,
        purge_removed_domains_state=purge_removed_domains_state,
    )
