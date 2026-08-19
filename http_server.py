#!/usr/bin/env python3
"""HTTP server bootstrap and shared-state wiring for TraceDNS UI/API."""

import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

from http_api_handlers import attach_api_handlers
from history_manager import history_file_path
from monitor.runtime_state import bump_state_version, state_lock


def purge_removed_domains_state(current_results, history, history_dir, removed_domains):
    """Purge in-memory and on-disk history state for removed domains."""
    removed = [str(d or '').strip() for d in (removed_domains or []) if str(d or '').strip()]
    if not removed:
        return
    removed_any = False
    with state_lock():
        for domain in removed:
            try:
                if isinstance(current_results, dict) and current_results.pop(domain, None) is not None:
                    removed_any = True
            except Exception:
                pass
            try:
                if isinstance(history, dict) and history.pop(domain, None) is not None:
                    removed_any = True
            except Exception:
                pass
        if removed_any:
            bump_state_version()
    for domain in removed:
        try:
            if history_dir:
                fp = history_file_path(history_dir, domain)
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
    """Threaded HTTP server with a fixed upper bound on active handlers."""

    daemon_threads = True

    def __init__(self, *args, max_workers=64, request_timeout=15, **kwargs):
        super().__init__(*args, **kwargs)
        self._request_slots = threading.BoundedSemaphore(max(1, int(max_workers)))
        self.request_timeout = max(1.0, float(request_timeout))

    def process_request(self, request, client_address):
        request.settimeout(self.request_timeout)
        if not self._request_slots.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Connection: close\r\nContent-Length: 0\r\n\r\n"
                )
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


def make_handler(shared_config, config_lock, config_path, history_dir, current_results, history, max_body_bytes=None):
    """Create configured HTTP request handler class bound to runtime state.

    ``max_body_bytes`` defaults to ``resolve_max_body_length()`` when omitted.
    """
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
        max_body_bytes=max_body_bytes,
    )
