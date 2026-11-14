"""Wire-level discriminator for security failures, not ordinary API outages."""
import http.client
import json
import threading
from types import SimpleNamespace

import pytest

from test_http_auth_integration import Client


HEADER = 'X-TraceDNS-Security-Error'


@pytest.fixture
def signal_app(tmp_path, request):
    from http_server import ThreadingHTTPServer, make_handler
    from security.store import SecurityStore

    store = None
    if getattr(request, 'param', True):
        store = SecurityStore(tmp_path / 'private' / 'auth.sqlite', create=True)
        store.bootstrap('root', 'test-password-123')
    config = {'domains': [], 'servers': [], 'interval': 60}
    handler = make_handler(config, threading.RLock(), str(tmp_path / 'config.json'),
                           str(tmp_path), {}, {}, security_store=store, insecure_http=True)
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = Client(server.server_port)
        if store is not None:
            assert client.login(password='test-password-123')[0] == 200
        yield SimpleNamespace(store=store, client=client, config=config, handler=handler)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def call(client, method, path, data=None, *, csrf=True):
    connection = http.client.HTTPConnection('127.0.0.1', client.port, timeout=5)
    headers = {'Origin': f'http://127.0.0.1:{client.port}',
               'Cookie': '; '.join(f'{key}={value}' for key, value in client.cookies.items())}
    if csrf:
        headers['X-CSRF-Token'] = client.csrf
    body = None if data is None else json.dumps(data)
    if body is not None:
        headers['Content-Type'] = 'application/json'
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read()), response.headers
    finally:
        connection.close()


def assert_unavailable(response, *, security):
    status, payload, headers = response
    assert status == 503
    assert payload == {'error': 'Service unavailable', 'request_id': headers['X-Request-ID']}
    assert headers['X-Request-ID']
    assert headers.get_all(HEADER) == (['security_unavailable'] if security else None)


def test_audit_failure_is_marked_before_mutation(signal_app, monkeypatch):
    app = signal_app
    original = app.handler.api_legacy_methods['POST']
    reached = []

    def observe_action(handler):
        reached.append(handler.path)
        return original(handler)

    monkeypatch.setitem(app.handler.api_legacy_methods, 'POST', observe_action)
    with app.store._db() as db:
        db.execute("CREATE TRIGGER audit_fail BEFORE INSERT ON audit_events "
                   "BEGIN SELECT RAISE(ABORT,'private storage detail'); END")
    data = {'revision': 0, 'domains': [{'name': 'blocked.test', 'type': 'A'}]}
    response = call(app.client, 'PATCH', '/api/v1/config', data)
    assert reached == []
    assert app.config['domains'] == []
    assert_unavailable(response, security=True)
    with app.store._db() as db:
        db.execute('DROP TRIGGER audit_fail')
    status, _, headers = call(app.client, 'PATCH', '/api/v1/config', data)
    assert status == 200
    assert headers.get_all(HEADER) is None
    assert reached == ['/config']
    assert app.config['domains'] == data['domains']


def test_unexpected_security_failure_is_marked(signal_app, monkeypatch):
    attempted = []

    def fail_authenticate(token):
        attempted.append(True)
        raise OSError('private storage detail\r\nX-Injected: never')

    monkeypatch.setattr(signal_app.store, 'authenticate', fail_authenticate)
    response = call(signal_app.client, 'GET', '/api/v1/config')
    assert attempted == [True]
    assert_unavailable(response, security=True)
    assert 'private storage detail' not in str(response[2])
    assert response[2]['X-Injected'] is None


@pytest.mark.parametrize('signal_app', [False], indirect=True)
def test_missing_store_is_marked(signal_app):
    assert_unavailable(call(signal_app.client, 'GET', '/api/v1/config'), security=True)


@pytest.mark.parametrize('path', ['/api/v1/delivery-health', '/api/v1/delivery-diagnostics'])
def test_handler_outage_is_not_marked(signal_app, path):
    assert_unavailable(call(signal_app.client, 'GET', path), security=False)


@pytest.mark.parametrize('preview', [True, False])
def test_prepared_resend_outage_is_not_marked(signal_app, preview):
    path = '/api/v1/delivery-resend' + ('/preview' if preview else '')
    data = ({'target': 'example.test', 'channels': ['teams'], 'revision': 0} if preview
            else {'request_id': 'a' * 32})
    status, payload, headers = call(signal_app.client, 'POST', path, data)
    assert status == 503
    assert headers.get_all(HEADER) is None
    expected = ({'status': 'not_ready', 'request_id': None, 'target': None,
                 'source_type': None, 'ips': [], 'observed_at': None, 'retained': True,
                 'expires_in_seconds': 0} if preview
                else {'status': 'not_queued', 'request_id': 'a' * 32,
                      'ip_count': 0, 'receipt_count': 0})
    assert payload == {**expected, 'reason': 'runtime_unavailable', 'channels': [], 'retry_after': None}


@pytest.mark.parametrize('reason', ['authentication', 'csrf', 'permission'])
def test_client_denials_are_not_marked(signal_app, reason):
    app = signal_app
    if reason == 'authentication':
        response = call(Client(app.client.port), 'GET', '/api/v1/config')
        expected_status, expected_error = 401, 'Authentication required'
    elif reason == 'csrf':
        response = call(app.client, 'PATCH', '/api/v1/config', {'revision': 0, 'domains': []}, csrf=False)
        expected_status, expected_error = 403, 'Invalid CSRF token'
    else:
        actor = app.client.call('GET', '/auth/me')[1]['user']
        app.store.create_user('reader', 'test-reader-123', 'viewer', actor=actor)
        viewer = Client(app.client.port)
        assert viewer.login('reader', 'test-reader-123')[0] == 200
        response = call(viewer, 'GET', '/api/v1/admin/users')
        expected_status, expected_error = 403, 'Permission denied'
    status, payload, headers = response
    assert status == expected_status
    assert payload == {'error': expected_error, 'request_id': headers['X-Request-ID']}
    assert headers.get_all(HEADER) is None
    assert app.config['domains'] == []


def test_failed_denial_audit_is_marked(signal_app):
    app = signal_app
    with app.store._db() as db:
        db.execute("CREATE TRIGGER audit_fail BEFORE INSERT ON audit_events "
                   "BEGIN SELECT RAISE(ABORT,'private storage detail'); END")
    response = call(app.client, 'PATCH', '/api/v1/config', {'revision': 0, 'domains': []}, csrf=False)
    assert_unavailable(response, security=True)
    assert app.config['domains'] == []


def test_marker_is_reset_on_reused_handler(signal_app, monkeypatch):
    from security.store import SecurityError

    app = signal_app
    authenticate = app.store.authenticate
    attempts = []

    def fail_once(token):
        attempts.append(True)
        if len(attempts) == 1:
            raise SecurityError('private storage detail', 503)
        return authenticate(token)

    monkeypatch.setattr(app.store, 'authenticate', fail_once)
    # Production closes each connection. Exercise request-local reset on the
    # same real handler by admitting explicit keep-alive only in this test.
    original = app.handler.handle_one_request
    handled = []
    completed = threading.Event()

    def keep_alive(handler):
        original(handler)
        if handler.raw_requestline:
            handled.append(handler)
            if handler.headers.get('Connection') == 'keep-alive':
                handler.close_connection = False
            if len(handled) == 2:
                completed.set()

    monkeypatch.setattr(app.handler, 'protocol_version', 'HTTP/1.1')
    monkeypatch.setattr(app.handler, 'handle_one_request', keep_alive)
    connection = http.client.HTTPConnection('127.0.0.1', app.client.port, timeout=5)
    headers = {'Cookie': '; '.join(f'{key}={value}' for key, value in app.client.cookies.items()),
               'Connection': 'keep-alive'}
    try:
        connection.request('GET', '/api/v1/config', headers=headers)
        response = connection.getresponse()
        first = response.status, json.loads(response.read()), response.headers
        assert_unavailable(first, security=True)
        connection.request('GET', '/api/v1/delivery-health', headers=headers)
        response = connection.getresponse()
        second = response.status, json.loads(response.read()), response.headers
        assert_unavailable(second, security=False)
        assert first[2]['X-Request-ID'] != second[2]['X-Request-ID']
        assert completed.wait(5)
        assert len(handled) == 2 and handled[0] is handled[1]
    finally:
        connection.close()


@pytest.mark.parametrize('failure', ['completion_audit', 'unexpected'])
def test_failure_after_headers_is_not_retroactively_marked(signal_app, monkeypatch, failure):
    app = signal_app
    failed = []
    if failure == 'completion_audit':
        method, data = 'PATCH', {'revision': 0, 'domains': [{'name': 'saved.test', 'type': 'A'}]}
        audit = app.store.audit

        def fail_completion(*args, **kwargs):
            if kwargs.get('outcome') == 'success':
                failed.append(True)
                raise OSError('private completion detail')
            return audit(*args, **kwargs)

        monkeypatch.setattr(app.store, 'audit', fail_completion)
    else:
        method, data = 'GET', None
        original = app.handler.api_legacy_methods['GET']

        def fail_after_response(handler):
            original(handler)
            failed.append(True)
            raise RuntimeError('private completion detail')

        monkeypatch.setitem(app.handler.api_legacy_methods, 'GET', fail_after_response)
    dispatch = getattr(app.handler, 'do_' + method)
    completed = threading.Event()
    marker_after_dispatch = []

    def observe_dispatch(handler):
        try:
            return dispatch(handler)
        finally:
            marker_after_dispatch.append(handler._security_unavailable)
            completed.set()

    monkeypatch.setattr(app.handler, 'do_' + method, observe_dispatch)
    status, payload, headers = call(app.client, method, '/api/v1/config', data)
    assert completed.wait(5)
    assert failed == [True]
    assert status == 200
    assert headers.get_all(HEADER) is None
    assert marker_after_dispatch == [False]
    assert 'error' not in payload
    if failure == 'completion_audit':
        assert app.config['domains'] == [{'name': 'saved.test', 'type': 'A'}]
