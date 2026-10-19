"""Actual loopback HTTP boundary; runtime is injected, never a live webhook."""
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from http_server import ThreadingHTTPServer, make_handler
from monitor.delivery_diagnostics import normalize_diagnostic
from security.store import SecurityStore
from test_http_auth_integration import Client


def result(status='accepted', reason=None, retry_after=None):
    return dict(status=status, reason=reason, retry_after=retry_after,
                diagnostic=normalize_diagnostic())


@pytest.fixture
def teams_app(tmp_path):
    store = SecurityStore(tmp_path / 'private' / 'auth.sqlite', create=True)
    store.bootstrap('root', 'test-password-123')
    runtime = SimpleNamespace(test_teams=Mock(return_value=result()))
    service = SimpleNamespace(delivery_runtime=runtime)
    config = {'domains': [], 'servers': [], 'interval': 60}
    handler = make_handler(config, threading.RLock(), '', str(tmp_path), {}, {},
                           security_store=store, insecure_http=True, config_service=service)
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield Client(server.server_port), runtime.test_teams, service, config
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_teams_saved_revision_actual_http(teams_app, prefix):
    client, send, _, config = teams_app
    assert client.login()[0] == 200
    # A credential colliding with the closed protocol must not rename enums.
    config['api_key'] = 'accepted'
    code, payload = client.call('POST', prefix + '/teams/test', {'revision': 7})
    assert code == 200, payload
    assert payload == result()
    send.assert_called_once_with(7)


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_exact_revision_only_before_runtime(teams_app, prefix):
    client, send, _, _ = teams_app
    assert client.login()[0] == 200
    invalid = [{}, {'revision': True}, {'revision': -1}, {'revision': 1.5},
               {'revision': '7'}, {'revision': None}, {'revision': 2**53},
               {'revision': 7, 'webhook': 'PRIVATE-CANARY'},
               {'revision': 7, 'message': 'PRIVATE-CANARY'}, [], None]
    for data in invalid:
        code, payload = client.call('POST', prefix + '/teams/test', data)
        assert code == 400, (data, payload)
        assert 'PRIVATE-CANARY' not in str(payload)
    send.assert_not_called()
    for revision in (0, 2**53 - 1):
        assert client.call('POST', prefix + '/teams/test', {'revision': revision})[0] == 200
    assert [c.args for c in send.call_args_list] == [(0,), (2**53 - 1,)]


def test_closed_result_status_mapping_and_unavailable(teams_app):
    client, send, service, config = teams_app
    assert client.login()[0] == 200
    config['api_key'] = 'provider_tls'
    cases = [(result('failed', 'provider_tls'), 502),
             (result('not_sent', 'test_cooldown', 30), 429),
             (result('not_sent', 'test_in_progress', 1), 429),
             *[(result('not_sent', reason), 409) for reason in (
                 'configuration_changed', 'destination_disabled', 'destination_invalid',
                 'adapter_unapplied', 'configuration_unavailable')],
             (result('not_sent', 'runtime_unavailable'), 503)]
    for payload, expected in cases:
        send.return_value = payload
        code, actual = client.call('POST', '/teams/test', {'revision': 0})
        assert (code, actual) == (expected, payload)
    service.delivery_runtime = None
    code, actual = client.call('POST', '/teams/test', {'revision': 0})
    assert (code, actual) == (503, result('not_sent', 'runtime_unavailable'))


def test_bad_runtime_output_is_unknown_not_false_success(teams_app):
    client, send, _, _ = teams_app
    assert client.login()[0] == 200
    for payload in (None, {}, {**result(), 'status': 'PRIVATE-CANARY'},
                    {**result(), 'reason': []}, {**result(), 'retry_after': True},
                    {**result(), 'diagnostic': {'operation': 'PRIVATE-CANARY'}},
                    result('accepted', 'provider_tls'), result('not_sent', 'provider_tls')):
        send.return_value = payload
        assert client.call('POST', '/teams/test', {'revision': 1}) == (
            502, result('failed', 'delivery_unknown'))
    send.side_effect = RuntimeError('PRIVATE-CANARY')
    assert client.call('POST', '/teams/test', {'revision': 1}) == (
        502, result('failed', 'delivery_unknown'))
    send.side_effect = None
    send.return_value = {**result(), 'secret': 'PRIVATE-CANARY',
                         'diagnostic': {**normalize_diagnostic(), 'secret': 'PRIVATE-CANARY'}}
    assert client.call('POST', '/teams/test', {'revision': 1}) == (200, result())


def raw_post(client, path, body):
    import http.client
    import json
    connection = http.client.HTTPConnection('127.0.0.1', client.port, timeout=5)
    try:
        connection.request('POST', path, body=body, headers={
            'Origin': f'http://127.0.0.1:{client.port}', 'X-CSRF-Token': client.csrf,
            'Cookie': '; '.join(f'{k}={v}' for k, v in client.cookies.items()),
            'Content-Type': 'application/json'})
        response = connection.getresponse()
        return response.status, json.loads(response.read()), dict(response.getheaders())
    finally:
        connection.close()


def test_retry_after_header_and_duplicate_body_keys(teams_app):
    client, send, _, _ = teams_app
    assert client.login()[0] == 200
    send.return_value = result('not_sent', 'test_cooldown', 30)
    code, payload, headers = raw_post(client, '/api/v1/teams/test', '{"revision":0}')
    assert code == 429 and payload == send.return_value
    assert headers.get('Retry-After') == '30'
    assert 'no-store' in headers['Cache-Control']
    send.reset_mock()
    for raw in ('{"revision":0,"revision":1}', '{', 'null', '[1]', 'true', '[' * 1500 + '0' + ']' * 1500):
        code, payload, headers = raw_post(client, '/api/v1/teams/test', raw)
        assert code == 400
        assert 'Retry-After' not in headers
    send.assert_not_called()


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_teams_security_boundary(teams_app, prefix):
    client, send, _, _ = teams_app
    path = prefix + '/teams/test'
    assert client.call('POST', path, {'revision': 0})[0] == 401
    assert client.login()[0] == 200
    assert client.call('POST', path, {'revision': 0}, csrf=False)[0] == 403
    assert client.call('POST', path, {'revision': 0}, extra_headers={'Origin': 'https://other.invalid'})[0] == 403
    for method in ('GET', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE'):
        assert client.call(method, path, {'revision': 0})[0] in (403, 405)
    for role in ('viewer', 'operator'):
        assert client.call('POST', '/admin/users', {
            'username': role, 'password': 'initial-test-password', 'role': role})[0] == 201
        other = Client(client.port)
        assert other.login(role, 'initial-test-password')[0] == 200
        assert other.call('POST', '/auth/password', {
            'current_password': 'initial-test-password', 'new_password': 'changed-test-password'})[0] == 200
        assert other.login(role, 'changed-test-password')[0] == 200
        assert other.call('POST', path, {'revision': 0})[0] == 403
    send.assert_not_called()


def test_teams_test_openapi_and_static_asset(teams_app):
    import json
    from pathlib import Path
    from jsonschema import Draft7Validator
    from http_api.teams_test import REQUEST_SCHEMA, RESULT_SCHEMA
    client, _, _, _ = teams_app
    assert client.login()[0] == 200
    code, doc = client.call('GET', '/api/v1/openapi.json')
    assert code == 200, doc
    operation = doc['paths']['/teams/test']['post']
    assert operation['x-roles'] == ['admin']
    assert operation['requestBody']['content']['application/json']['schema'] == REQUEST_SCHEMA
    for status in ('200', '409', '429', '502', '503'):
        schema = operation['responses'][status]['content']['application/json']['schema']
        assert schema == RESULT_SCHEMA or RESULT_SCHEMA in schema.get('anyOf', [])
    assert operation['responses']['429']['headers']['Retry-After']['schema']['maximum'] == 30
    Draft7Validator(RESULT_SCHEMA).validate(result())
    for invalid in ({'revision': True}, {'revision': 2**53}, {'revision': 0, 'webhook': 'x'}):
        assert not Draft7Validator(REQUEST_SCHEMA).is_valid(invalid)
    assert json.loads((Path(__file__).resolve().parents[1] / 'docs/openapi.json').read_text()) == doc
    code, script = client.call('GET', '/teams_test.js')
    assert code == 200 and 'TraceTeamsTest' in script
