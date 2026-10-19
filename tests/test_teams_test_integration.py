"""Real authenticated HTTP -> immutable adapter -> local TLS webhook sink.

The sink is a test-owned HTTPS server, not Microsoft Teams. Requests performs
real certificate verification; only its fixture-local trusted CA is substituted.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer as SinkServer
from pathlib import Path
import ssl
import subprocess
import threading
from types import SimpleNamespace

import pytest
import requests.adapters

from http_server import ThreadingHTTPServer, make_handler
from security.store import SecurityStore
from test_http_auth_integration import Client
from test_stage3_core_runtime import app_factory, rows

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def tls_app(tmp_path, monkeypatch, request):
    cert, key = tmp_path / 'sink-cert.pem', tmp_path / 'sink-key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1',
                    '-keyout', str(key), '-out', str(cert)],
                   check=True, capture_output=True, timeout=15)
    if getattr(request, 'param', True):
        monkeypatch.setattr(requests.adapters, 'DEFAULT_CA_BUNDLE_PATH', str(cert))
        if hasattr(requests.adapters, '_preloaded_ssl_context'):
            monkeypatch.setattr(requests.adapters, '_preloaded_ssl_context', ssl.create_default_context(cafile=str(cert)))
    sink = SimpleNamespace(posts=[], status=200)

    class Webhook(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers['Content-Length'])
            assert 0 < length < 4096
            sink.posts.append({'path': self.path, 'body': json.loads(self.rfile.read(length)),
                               'content_type': self.headers['Content-Type']})
            self.send_response(sink.status)
            if sink.status == 302:
                self.send_header('Location', '/must-not-follow')
            self.send_header('Content-Length', '1')
            self.end_headers()
            self.wfile.write(b'1')

        def log_message(self, *_args):
            pass

    provider = SinkServer(('127.0.0.1', 0), Webhook)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    provider.socket = context.wrap_socket(provider.socket, server_side=True)
    provider_thread = threading.Thread(target=provider.serve_forever, daemon=True)
    provider_thread.start()
    app = None
    server = None
    handler = None
    thread = None
    try:
        app = app_factory(tmp_path / 'app', config={
            'domains': [], 'servers': [], 'interval': 60, 'config_revision': 0,
            'alerts': {'teams_webhook': f'https://127.0.0.1:{provider.server_port}/synthetic-hook'},
        })
        accounts = SecurityStore(tmp_path / 'auth' / 'auth.sqlite', create=True)
        accounts.bootstrap('root', 'test-password-123')
        handler = make_handler(app.cfg.raw, app.cfg.lock, str(tmp_path / 'app' / 'config'),
                               str(tmp_path / 'app'), app.current, app.history,
                               config_service=app.service, state_repository=app.repo,
                               security_store=accounts, insecure_http=True,
                               delivery_health=app.delivery.store.health_snapshot,
                               delivery_diagnostics=app.delivery.store.diagnostics_snapshot)
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        yield app, sink, Client(server.server_port)
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            assert not thread.is_alive()
        if handler is not None:
            for service in handler.background_services:
                service.close()
        if app is not None:
            assert app.delivery.stop()['closed']
        provider.shutdown()
        provider.server_close()
        provider_thread.join(timeout=5)
        assert not provider_thread.is_alive()


def test_runtime_uses_real_https_without_a_mock_transport(tls_app):
    app, sink, _ = tls_app
    outcome = app.delivery.test_teams(0)
    assert outcome['status'] == 'accepted'
    assert outcome['diagnostic']['tls_verify'] is True
    assert outcome['diagnostic']['http_status'] == 200
    assert len(sink.posts) == 1


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_http_sends_one_real_verified_tls_post_and_preserves_alert_ledger(tls_app, prefix):
    app, sink, client = tls_app
    assert client.login()[0] == 200
    before = {table: rows(app, table) for table in ('receipt', 'control', 'terminal', 'batch')}
    assert sink.posts == []
    code, outcome = client.call('POST', prefix + '/teams/test', {'revision': 0})
    assert code == 200 and outcome['status'] == 'accepted'
    assert outcome['diagnostic']['tls_verify'] is True
    assert outcome['diagnostic']['http_status'] == 200
    assert len(sink.posts) == 1
    assert sink.posts[0]['path'] == '/synthetic-hook'
    assert sink.posts[0]['content_type'] == 'application/json'
    assert sink.posts[0]['body']['title'] == 'TraceDNS Teams delivery test'
    assert client.call('POST', prefix + '/teams/test', {'revision': 0})[0] == 429
    assert len(sink.posts) == 1
    assert {table: rows(app, table) for table in before} == before


@pytest.mark.parametrize('tls_app', [False], indirect=True)
def test_untrusted_tls_is_rejected_without_any_webhook_post(tls_app):
    _, sink, client = tls_app
    assert client.login()[0] == 200
    code, outcome = client.call('POST', '/teams/test', {'revision': 0})
    assert code == 502 and outcome['status'] == 'failed' and outcome['reason'] == 'tls_error'
    assert outcome['diagnostic']['tls_kind'] == 'certificate_verify'
    assert outcome['diagnostic']['tls_verify'] is True
    assert sink.posts == []


def test_real_https_redirect_is_not_followed_or_claimed_accepted(tls_app):
    _, sink, client = tls_app
    sink.status = 302
    assert client.login()[0] == 200
    code, outcome = client.call('POST', '/api/v1/teams/test', {'revision': 0})
    assert code == 502 and outcome['status'] == 'failed' and outcome['reason'] == 'provider_http'
    assert outcome['diagnostic']['http_status'] == 302
    assert len(sink.posts) == 1


def test_browser_button_reaches_real_https_sink(tls_app, tmp_path):
    _, sink, client = tls_app
    preflight = subprocess.run(['node', '-e', "const {chromium}=require('@playwright/test');process.exit(require('fs').existsSync(chromium.executablePath())?0:1)"],
                               cwd=ROOT, capture_output=True, timeout=15)
    if preflight.returncode:
        pytest.skip('Playwright Chromium not installed; run npm ci and install Chromium')
    result = subprocess.run(['node', 'tests/test_teams_test_browser.js'], cwd=ROOT,
                            input=json.dumps({'port': client.port, 'out': str(tmp_path)}),
                            text=True, capture_output=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(sink.posts) == 1
    assert sink.posts[0]['body']['title'] == 'TraceDNS Teams delivery test'
    assert sink.posts[0]['path'] == '/synthetic-hook'
    print(result.stdout)
