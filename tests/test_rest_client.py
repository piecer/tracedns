"""External client integration uses real HTTP with isolated credentials/state."""
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from test_http_auth_integration import app as http_app

app = http_app


def client_class():
    path = Path(__file__).resolve().parents[1] / 'scripts' / 'tracedns_api.py'
    assert path.is_file(), 'Ship a standalone external AI client'
    spec = importlib.util.spec_from_file_location('tracedns_api_client', path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.TraceDNSClient


def test_client_authenticates_mutates_reads_back_and_revokes_session(app):
    store, http, _ = app
    cls = client_class()
    with cls(f'http://127.0.0.1:{http.port}', allow_loopback_http=True) as client:
        user = client.login('root', 'test-password-123')
        assert user['role'] == 'admin'
        config = client.request('GET', '/config')
        saved = client.request('PATCH', '/config', {
            'revision': config['revision'], 'domains': [{'name': 'example.net', 'type': 'TXT'}],
        })
        observed = client.request('GET', '/config')
        assert observed['revision'] == saved['revision']
        assert observed['domains'] == saved['config']['domains']
        assert client.request('GET', '/history', params={'domain': 'example.net'})['domain'] == 'example.net'
    assert store.sessions(user['id']) == []


def test_cli_runs_without_password_argument_or_token_output(app):
    store, http, _ = app
    path = Path(__file__).resolve().parents[1] / 'scripts' / 'tracedns_api.py'
    result = subprocess.run([
        sys.executable, str(path), '--base-url', f'http://127.0.0.1:{http.port}',
        '--allow-loopback-http', 'GET', '/auth/me',
    ], env={**os.environ, 'TRACEDNS_USERNAME': 'root', 'TRACEDNS_PASSWORD': 'test-password-123'},
        capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload['user']['username'] == 'root'
    assert 'csrf_token' not in payload
    assert 'test-password-123' not in result.stdout + result.stderr
    assert store.sessions(payload['user']['id']) == []


@pytest.mark.parametrize('url', [
    'http://example.org', 'http://127.0.0.1', 'https://user:secret@example.org',
    'https://example.org/api/v1', 'https://example.org?secret=1', 'https://example.org#fragment',
])
def test_client_rejects_unsafe_origin(url):
    with pytest.raises(ValueError):
        client_class()(url)


@pytest.mark.parametrize('path', ['https://evil.invalid', '//evil.invalid', '/../../x', '/x#fragment', '/x\\y'])
def test_client_rejects_escaping_paths(path):
    client = client_class()('https://example.org')
    with pytest.raises(ValueError):
        client.request('GET', path)


def test_client_surfaces_conflict_without_retry_or_sensitive_error(app):
    _, http, config = app
    with client_class()(f'http://127.0.0.1:{http.port}', allow_loopback_http=True) as client:
        client.login('root', 'test-password-123')
        with pytest.raises(RuntimeError, match='HTTP 409'):
            client.request('PATCH', '/config', {'revision': 999, 'domains': []})
        assert config.get('_config_revision', 0) == 0


def test_failed_login_body_processing_revokes_received_session(app, capsys):
    store, http, _ = app
    user = store.list_users()[0]
    client = client_class()(f'http://127.0.0.1:{http.port}', allow_loopback_http=True,
                            max_response_bytes=100)
    with pytest.raises(ValueError, match='Response exceeded'):
        with client:
            client.login('root', 'test-password-123')
    assert store.sessions(user['id']) == [], 'Set-Cookie login must be revoked even when JSON decoding fails'
    assert list(client.cookies) == []
    assert client.authenticated is False
    assert 'logout unconfirmed' not in capsys.readouterr().err


def test_audit_export_exposes_safe_pagination_headers(app):
    _, http, _ = app
    with client_class()(f'http://127.0.0.1:{http.port}', allow_loopback_http=True) as client:
        client.login('root', 'test-password-123')
        page = client.request('POST', '/admin/audit/export', {'limit': 1, 'offset': 0})
        assert len(page.splitlines()) == 1
        assert int(client.response_headers['X-Next-Offset']) == 1
        assert int(client.response_headers['X-Total-Count']) >= 1
        assert 'Set-Cookie' not in client.response_headers


def test_failed_partial_session_cleanup_warns_without_masking_login_error(app, capsys, monkeypatch):
    store, http, _ = app
    user = store.list_users()[0]
    client = client_class()(f'http://127.0.0.1:{http.port}', allow_loopback_http=True,
                            max_response_bytes=100)
    original = client._request

    def fail_recovery(method, path, *args, **kwargs):
        if path == '/auth/csrf' and any(c.name == 'td_session' for c in client.cookies):
            raise RuntimeError('synthetic recovery outage')
        return original(method, path, *args, **kwargs)

    monkeypatch.setattr(client, '_request', fail_recovery)
    with pytest.raises(ValueError, match='Response exceeded'):
        with client:
            client.login('root', 'test-password-123')
    assert 'logout unconfirmed' in capsys.readouterr().err
    assert len(store.sessions(user['id'])) == 1  # explicit uncertainty, not claimed cleanup
    store.revoke_sessions(user['id'], actor=user)
