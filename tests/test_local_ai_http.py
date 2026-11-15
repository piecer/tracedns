"""Real central HTTP/REST security boundary; no model/provider calls."""
from contextlib import closing
import http.client
import json
import sqlite3
import threading

import pytest

from security.policy import allowed
from local_ai.contracts import AIError


@pytest.fixture
def ai_http_app(tmp_path):
    from test_http_auth_integration import app
    yield from app.__wrapped__(tmp_path)


@pytest.mark.parametrize('role', ['admin', 'operator', 'viewer'])
@pytest.mark.parametrize('kind', ['delivery', 'relationship_pair', 'decoder_suggest'])
def test_ai_admission_policy_is_field_sensitive(role, kind):
    expected = role == 'admin' or (role == 'operator' and kind != 'decoder_suggest')
    assert allowed(role, 'POST', '/ai/jobs', body={'kind': kind}) is expected
    assert allowed(role, 'GET', '/ai/status') is (role != 'viewer')
    assert allowed(role, 'GET', '/ai/jobs/' + 'a' * 32) is (role != 'viewer')
    assert allowed(role, 'POST', '/ai/jobs/' + 'a' * 32 + '/cancel', body={}) is (role != 'viewer')


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_disabled_status_and_submission_are_explicit(ai_http_app, prefix):
    _, client, _ = ai_http_app
    assert client.login()[0] == 200
    code, status = client.call('GET', prefix + '/ai/status')
    assert code == 200
    assert status == {'enabled': False, 'accepting': False, 'provider_state': 'disabled',
                      'queued': 0, 'active_job': None}
    code, error = client.call('POST', prefix + '/ai/jobs', {'kind': 'delivery', 'language': 'ko'})
    assert code == 503 and error['code'] == 'disabled'


def session_rows(store):
    with closing(sqlite3.connect(store.path.as_uri() + '?mode=ro', uri=True)) as db:
        return db.execute('SELECT id,last_seen,expires FROM sessions ORDER BY id').fetchall()


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_ai_reads_never_refresh_or_delete_sessions(ai_http_app, prefix):
    store, client, _ = ai_http_app
    assert client.login()[0] == 200
    now = [store.clock()]
    store.clock = lambda: now[0]
    store.idle_seconds = 10
    before = session_rows(store)
    now[0] += 3
    assert client.call('GET', prefix + '/ai/status')[0] == 200
    assert session_rows(store) == before
    assert client.call('GET', prefix + '/ai/jobs/' + 'a' * 32)[0] == 404
    assert session_rows(store) == before
    now[0] += 10
    assert client.call('GET', prefix + '/ai/status')[0] == 401
    assert session_rows(store) == before


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_ai_limit_precedes_central_body_read(ai_http_app, monkeypatch, prefix):
    from security import http
    _, client, _ = ai_http_app
    assert client.login()[0] == 200
    original = http.get_request_body
    reads = []

    def observe(handler, *, max_length):
        stream = handler.rfile
        class Observed:
            def read(self, count):
                reads.append(count)
                return stream.read(count)
        handler.rfile = Observed()
        try:
            return original(handler, max_length=max_length)
        finally:
            handler.rfile = stream

    monkeypatch.setattr(http, 'get_request_body', observe)
    code, _ = client.call('POST', prefix + '/ai/jobs', {'padding': 'x' * 16384})
    assert code == 413
    assert reads == [], 'oversized body must not enter the central JSON reader'


def test_ai_openapi_matches_mounted_routes_and_closed_requests(ai_http_app):
    from jsonschema import Draft202012Validator, ValidationError
    _, client, _ = ai_http_app
    assert client.login()[0] == 200
    code, document = client.call('GET', '/api/v1/openapi.json')
    assert code == 200
    paths = document['paths']
    assert set(paths['/ai/status']) == {'get'}
    assert paths['/ai/status']['get']['x-roles'] == ['operator', 'admin']
    operation = paths['/ai/jobs']['post']
    assert operation['x-max-body-bytes'] == 16384
    assert '202' in operation['responses']
    schema = operation['requestBody']['content']['application/json']['schema']
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    validator.validate({'kind': 'delivery', 'language': 'ko'})
    with pytest.raises(ValidationError):
        validator.validate({'kind': 'delivery', 'language': 'ko', 'endpoint': 'http://127.0.0.1:1'})
    validator.validate({'kind': 'decoder_suggest', 'language': 'en', 'decoder_type': 'TXT', 'generate': True,
                        'samples': [{'data': '192.0.2.1', 'expected_ips': ['192.0.2.1'],
                                     'usage': 'example', 'complete_expected': True}]})
    _, status = client.call('GET', '/ai/status')
    Draft202012Validator(paths['/ai/status']['get']['responses']['200']['content']['application/json']['schema']).validate(status)


@pytest.fixture
def capture_app(tmp_path):
    """Actual HTTP/security with a deliberately inert adapter-only service."""
    from test_http_auth_integration import Client
    from http_server import ThreadingHTTPServer, make_handler
    from security.store import SecurityStore
    store = SecurityStore(tmp_path / 'security' / 'db.sqlite', create=True)
    admin = store.bootstrap('fixture', 'local-ai-test-password')
    config = {'domains': [], 'servers': [], 'interval': 60}
    handler = make_handler(config, threading.RLock(), '', str(tmp_path), {}, {},
                           security_store=store, insecure_http=True)

    class CaptureService:
        def __init__(self):
            self.calls = []
            self.error = None
            self.request_audit_done = threading.Event()

        def submit(self, request, actor, **metadata):
            events = store.audit_list(action='post:/ai/jobs')['events']
            assert any(event['outcome'] == 'started' and event['request_id'] == metadata['request_id'] for event in events)
            self.calls.append((request, actor, metadata))
            if self.error:
                raise AIError(self.error)
            return {'job_id': 'a' * 32, 'kind': request['kind'], 'language': request['language'],
                    'status': 'queued', 'created_at': 1, 'deadline_at': 120001,
                    'audit_status': 'success', 'error': None, 'result': None, 'cancel_requested': False}

    service = CaptureService()
    original_audit = store.audit

    def observe_audit(actor, action, *args, **kwargs):
        result = original_audit(actor, action, *args, **kwargs)
        if action == 'post:/ai/jobs' and kwargs.get('outcome') in ('success', 'failure'):
            service.request_audit_done.set()
        return result

    store.audit = observe_audit
    handler.local_ai = service
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        client = Client(server.server_port)
        assert client.login('fixture', 'local-ai-test-password')[0] == 200
        yield store, admin, client, config, service
    finally:
        audit_retired = not service.calls or service.request_audit_done.wait(5)
        try:
            server.shutdown()
        finally:
            server.server_close()
            thread.join(5)
        assert audit_retired, 'post-response request audit must retire'
        assert not thread.is_alive()


def raw_request(client, path, raw, *, headers=None):
    with closing(http.client.HTTPConnection('127.0.0.1', client.port, timeout=5)) as connection:
        values = {'Origin': f'http://127.0.0.1:{client.port}',
                  'Cookie': '; '.join(f'{key}={value}' for key, value in client.cookies.items()),
                  'X-CSRF-Token': client.csrf, 'Content-Type': 'application/json'}
        values.update(headers or {})
        connection.request('POST', path, body=raw, headers=values)
        response = connection.getresponse()
        body = response.read()
        return response.status, dict(response.getheaders()), body


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_valid_create_passes_only_server_principal_after_durable_intent(capture_app, prefix):
    store, admin, client, _, service = capture_app
    code, body = client.call('POST', prefix + '/ai/jobs', {'kind': 'delivery', 'language': 'ko'})
    assert code == 202 and body['status'] == 'queued'
    assert len(service.calls) == 1
    request, actor, metadata = service.calls[0]
    assert request == {'kind': 'delivery', 'language': 'ko'}
    assert actor['id'] == admin['id'] and actor['session_id']
    assert set(actor) == {'id', 'username', 'role', 'active', 'must_change_password', 'session_id'}
    assert metadata['request_id'] and metadata['source_ip'] == '127.0.0.1'
    assert service.request_audit_done.wait(5)
    events = store.audit_list(action='post:/ai/jobs')['events']
    assert {event['outcome'] for event in events} == {'started', 'success'}
    from jsonschema import Draft202012Validator
    from http_api.local_ai_schema import JOB_SCHEMA
    Draft202012Validator(JOB_SCHEMA).validate(body)


@pytest.mark.parametrize('raw', [
    b'{"kind":"delivery","kind":"delivery","language":"ko"}',
    b'{"kind":"delivery","language":"ko","facts":{}}',
    b'{"kind":"delivery","language":"ko","value":NaN}',
    b'{"kind":[],"language":"ko"}',
])
@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_invalid_request_never_reaches_service(capture_app, raw, prefix):
    _, _, client, _, service = capture_app
    code, _, _ = raw_request(client, prefix + '/ai/jobs', raw)
    assert code == 400
    assert service.calls == []


@pytest.mark.parametrize('fault', ['csrf', 'origin', 'audit'])
@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_security_refusals_precede_service(capture_app, monkeypatch, fault, prefix):
    store, _, client, _, service = capture_app
    headers = {'X-CSRF-Token': 'wrong'} if fault == 'csrf' else {'Origin': 'http://other.invalid'} if fault == 'origin' else {}
    if fault == 'audit':
        def fail(*args, **kwargs):
            raise OSError('UNPUBLISHED-AUDIT-CANARY')
        monkeypatch.setattr(store, 'audit', fail)
    code, headers, raw = raw_request(client, prefix + '/ai/jobs', b'{"kind":"delivery","language":"ko"}', headers=headers)
    assert code == (503 if fault == 'audit' else 403)
    assert service.calls == []
    assert b'UNPUBLISHED-AUDIT-CANARY' not in raw
    if fault == 'audit':
        assert headers['X-TraceDNS-Security-Error'] == 'security_unavailable'


@pytest.mark.parametrize('code', ['disabled', 'provider_unsettled', 'audit_unavailable'])
def test_fixed_ai_errors_survive_protocol_enum_secret_collision(capture_app, code):
    _, _, client, config, service = capture_app
    service.error = code
    config['alerts'] = {'api_key': code}
    status, headers, raw = raw_request(client, '/ai/jobs', b'{"kind":"delivery","language":"ko"}')
    assert status == 503 and json.loads(raw)['code'] == code
    assert ('X-TraceDNS-Security-Error' in headers) is (code == 'audit_unavailable')


def test_http_ack_can_precede_request_completion_audit(capture_app, monkeypatch):
    store, _, client, _, service = capture_app
    reached, release = threading.Event(), threading.Event()
    original = store.audit

    def delayed(actor, action, *args, **kwargs):
        if action == 'post:/ai/jobs' and kwargs.get('outcome') == 'success':
            reached.set()
            assert release.wait(5)
        return original(actor, action, *args, **kwargs)

    monkeypatch.setattr(store, 'audit', delayed)
    try:
        code, _ = client.call('POST', '/ai/jobs', {'kind': 'delivery', 'language': 'ko'})
        assert code == 202 and reached.wait(1)
        assert not service.request_audit_done.is_set()
        assert len(service.calls) == 1
    finally:
        release.set()
    assert service.request_audit_done.wait(5)


@pytest.mark.parametrize('field,value', [('Content-Length', None), ('Transfer-Encoding', 'identity')])
def test_duplicate_ai_framing_is_rejected_before_body_read(capture_app, monkeypatch, field, value):
    from security import http as security_http
    _, _, client, _, service = capture_app
    reads = []
    original = security_http.get_request_body

    def observe(handler, **kwargs):
        reads.append(True)
        return original(handler, **kwargs)

    monkeypatch.setattr(security_http, 'get_request_body', observe)
    body = b'{"kind":"delivery","language":"ko"}'
    with closing(http.client.HTTPConnection('127.0.0.1', client.port, timeout=5)) as connection:
        connection.putrequest('POST', '/ai/jobs')
        connection.putheader('Origin', f'http://127.0.0.1:{client.port}')
        connection.putheader('Cookie', '; '.join(f'{key}={item}' for key, item in client.cookies.items()))
        connection.putheader('X-CSRF-Token', client.csrf)
        connection.putheader('Content-Length', str(len(body)))
        if field == 'Transfer-Encoding':
            connection.putheader(field, value)
        connection.putheader(field, value or str(len(body)))
        connection.endheaders(body)
        response = connection.getresponse()
        response.read()
        assert response.status == 400
    assert not reads and not service.calls


@pytest.mark.parametrize('extra', [0, 1])
def test_exact_ai_body_limit_is_distinct_from_task_projection_limit(capture_app, extra):
    _, _, client, _, service = capture_app
    raw = b'{"kind":"delivery","language":"ko"}'
    raw += b' ' * (16384 - len(raw) + extra)
    code, _, _ = raw_request(client, '/ai/jobs', raw)
    assert code == (413 if extra else 202)
    assert len(service.calls) == (0 if extra else 1)


@pytest.mark.parametrize('role', ['operator', 'viewer'])
def test_real_role_gate_denies_decoder_before_task_admission(capture_app, role):
    from test_http_auth_integration import Client
    store, admin, client, _, service = capture_app
    account = store.create_user(role, 'initial-ai-fixture-password', role, actor=admin)
    store.change_password(account['id'], 'initial-ai-fixture-password', 'changed-ai-fixture-password', actor=account)
    other = Client(client.port)
    assert other.login(role, 'changed-ai-fixture-password')[0] == 200
    code, _ = other.call('POST', '/ai/jobs', {'kind': 'decoder_suggest', 'language': 'ko',
                                           'decoder_type': 'TXT', 'generate': True, 'samples': []})
    assert code == 403 and not service.calls
    code, _ = other.call('POST', '/ai/jobs', {'kind': 'delivery', 'language': 'ko'})
    assert code == (202 if role == 'operator' else 403)
    assert len(service.calls) == (1 if role == 'operator' else 0)


@pytest.mark.parametrize('filename,mime', [('local_ai_frontend.js', 'javascript'), ('local_ai_frontend.css', 'text/css')])
def test_ai_assets_are_authenticated_and_serve_exact_current_bytes(ai_http_app, filename, mime):
    from pathlib import Path
    _, client, _ = ai_http_app
    assert client.call('GET', '/' + filename)[0] == 401
    assert client.login()[0] == 200
    with closing(http.client.HTTPConnection('127.0.0.1', client.port, timeout=5)) as connection:
        connection.request('GET', '/' + filename, headers={
            'Cookie': '; '.join(f'{k}={v}' for k, v in client.cookies.items())})
        response = connection.getresponse()
        body = response.read()
        assert response.status == 200
        assert mime in response.getheader('Content-Type')
        assert body == (Path(__file__).resolve().parents[1] / filename).read_bytes()
    for role in ('viewer', 'operator', 'admin'):
        assert allowed(role, 'GET', '/' + filename)
