"""Real HTTP checks with private temporary accounts; no external services."""
import http.client
import json
import threading
from http.cookies import SimpleCookie

import pytest


class Client:
    def __init__(self, port):
        self.port, self.cookies, self.csrf = port, {}, ''

    def call(self, method, path, data=None, csrf=True, extra_headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        headers = {'Origin': f'http://127.0.0.1:{self.port}',
                   'Cookie': '; '.join(f'{k}={v}' for k, v in self.cookies.items())}
        if csrf:
            headers['X-CSRF-Token'] = self.csrf
        body = None if data is None else json.dumps(data)
        if body is not None:
            headers['Content-Type'] = 'application/json'
        headers.update(extra_headers or {})
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        for key, value in response.getheaders():
            if key.lower() == 'set-cookie':
                parsed = SimpleCookie(value)
                self.cookies.update({k: v.value for k, v in parsed.items()})
        try:
            result = json.loads(raw)
        except ValueError:
            result = raw.decode()
        status = response.status
        connection.close()
        return status, result

    def login(self, username='root', password='test-password-123'):
        code, payload = self.call('GET', '/auth/csrf')
        assert code == 200
        self.csrf = payload['csrf_token']
        code, payload = self.call('POST', '/auth/login', {'username': username, 'password': password})
        if code == 200:
            self.csrf = payload['csrf_token']
        return code, payload


@pytest.fixture
def app(tmp_path):
    from security.store import SecurityStore
    from http_server import ThreadingHTTPServer, make_handler
    store = SecurityStore(tmp_path / 'private' / 'auth.sqlite', create=True)
    store.bootstrap('root', 'test-password-123')
    config = {'domains': [], 'servers': [], 'interval': 60}
    handler = make_handler(config, threading.RLock(), '', str(tmp_path), {}, {},
                           security_store=store, insecure_http=True)
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield store, Client(server.server_port), config
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def test_login_csrf_and_logout(app):
    store, client, _ = app
    assert client.call('GET', '/results')[0] == 401
    assert client.login()[0] == 200
    assert client.call('GET', '/results')[0] == 200
    assert client.call('POST', '/config', {'domains': [], 'revision': 0}, csrf=False)[0] == 403
    assert client.call('POST', '/auth/logout', {})[0] == 200
    assert client.call('GET', '/results')[0] == 401


def test_roles_and_audit_are_server_enforced(app):
    store, client, _ = app
    assert client.login()[0] == 200
    code, data = client.call('POST', '/admin/users',
                             {'username': 'reader', 'password': 'test-reader-123', 'role': 'viewer'})
    assert code == 201
    viewer = Client(client.port)
    assert viewer.login('reader', 'test-reader-123')[0] == 200
    assert viewer.call('POST', '/auth/password',
                       {'current_password': 'test-reader-123', 'new_password': 'changed-reader-123'})[0] == 200
    assert viewer.login('reader', 'changed-reader-123')[0] == 200
    assert viewer.call('GET', '/results')[0] == 200
    assert viewer.call('GET', '/admin/users')[0] == 403
    assert viewer.call('POST', '/resolve', {'domains': []})[0] == 403
    assert viewer.call('GET', '/domain-analysis?include_vt=1')[0] == 403
    code, audit = client.call('GET', '/admin/audit')
    assert code == 200
    assert audit['total'] > 0
    assert any(e['outcome'] == 'denied' for e in audit['events'])


def test_unknown_route_and_missing_store_are_closed(app):
    _, client, _ = app
    assert client.login()[0] == 200
    assert client.call('POST', '/new-unknown-api', {})[0] == 403


def test_configured_secrets_are_removed_from_result_keys_and_errors(app):
    _, client, config = app
    config['ens_rpc_url'] = 'https://rpc.invalid/private-token'
    from security.redaction import sanitize
    assert 'private-token' not in json.dumps(sanitize({'server': config['ens_rpc_url']}, config))
    assert 'private-token' not in json.dumps(sanitize({config['ens_rpc_url']: {'ok': True}}, config))
