"""Real HTTP boundary tests; injected cache is not producer integration evidence."""
import json
import threading
from unittest.mock import Mock

import pytest

from http_server import ThreadingHTTPServer, make_handler
from security.store import SecurityStore
from test_http_auth_integration import Client


def diagnostics_payload():
    detail = dict(operation='misp_read', http_status=302, response_bytes=1025,
                  response_limit=1024, attribute_count=None, attribute_limit=4096,
                  tls_kind=None, tls_verify=True)
    record = dict(at=100, channel='misp', state='failed', reason='response_limit',
                  attempt=2, items=3, diagnostic=detail)
    return dict(version=1, observed_at=101, counts_stale=True, storage_ok=False,
                worker_running=False, coverage='gap',
                storage_error=dict(at=99, stage='transaction_commit', code='sqlite_full'),
                channels={name: dict(latest_result=record, latest_failure=record,
                                    blocked_by_reason=[dict(reason='provider_auth', count=4)])
                          for name in ('teams', 'misp')}, recent_failures=[record])


@pytest.fixture
def diagnostics_app(tmp_path):
    store = SecurityStore(tmp_path / 'private' / 'auth.sqlite', create=True)
    store.bootstrap('root', 'test-password-123')
    cached = Mock(return_value=diagnostics_payload())
    kwargs = {'delivery_diagnostics': cached}
    handler = make_handler({'domains': [], 'servers': [], 'interval': 60},
                           threading.RLock(), '', str(tmp_path), {}, {},
                           security_store=store, insecure_http=True, **kwargs)
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield Client(server.server_port), cached, handler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_cached_diagnostics_aliases(diagnostics_app, prefix):
    client, cached, _ = diagnostics_app
    assert client.login()[0] == 200
    code, payload = client.call('GET', prefix + '/delivery-diagnostics')
    assert code == 200, payload
    assert payload == diagnostics_payload()
    cached.assert_called_once_with()
    assert len(json.dumps(payload).encode()) <= 32768


def test_diagnostics_projects_only_closed_nested_fields(diagnostics_app):
    client, cached, _ = diagnostics_app
    payload = diagnostics_payload()
    def contaminate(value):
        if isinstance(value, dict):
            for child in list(value.values()):
                contaminate(child)
            value['private_extra'] = 'PRIVATE-CANARY'
        elif isinstance(value, list):
            for child in value:
                contaminate(child)
    contaminate(payload)
    cached.return_value = payload
    assert client.login()[0] == 200
    code, result = client.call('GET', '/delivery-diagnostics')
    assert code == 200
    assert result == diagnostics_payload()
    assert 'PRIVATE-CANARY' not in json.dumps(result)


def test_diagnostics_fixed_grammar_never_traverses_config_redactor(diagnostics_app):
    client, _, handler = diagnostics_app
    assert client.login()[0] == 200
    handler.shared_config['api_key'] = 'misp'
    code, payload = client.call('GET', '/delivery-diagnostics')
    assert code == 200
    assert payload == diagnostics_payload()


def test_diagnostics_openapi_closed_schema(diagnostics_app):
    from http_api.delivery_diagnostics import DIAGNOSTICS_SCHEMA
    from jsonschema import Draft7Validator
    client, _, _ = diagnostics_app
    assert client.login()[0] == 200
    code, document = client.call('GET', '/api/v1/openapi.json')
    assert code == 200
    operation = document['paths']['/delivery-diagnostics']['get']
    assert operation['x-roles'] == ['operator', 'admin']
    assert operation['responses']['200']['content']['application/json']['schema'] == DIAGNOSTICS_SCHEMA
    Draft7Validator(DIAGNOSTICS_SCHEMA).validate(diagnostics_payload())


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
@pytest.mark.parametrize('role,expected', [('viewer', 403), ('operator', 200)])
def test_diagnostics_auth_and_get_only(diagnostics_app, prefix, role, expected):
    admin, cached, _ = diagnostics_app
    assert admin.call('GET', prefix + '/delivery-diagnostics')[0] == 401
    cached.assert_not_called()
    assert admin.login()[0] == 200
    assert admin.call('POST', '/admin/users', {
        'username': role, 'password': 'initial-test-password', 'role': role})[0] == 201
    client = Client(admin.port)
    assert client.login(role, 'initial-test-password')[0] == 200
    assert client.call('POST', '/auth/password', {
        'current_password': 'initial-test-password', 'new_password': 'changed-test-password'})[0] == 200
    assert client.login(role, 'changed-test-password')[0] == 200
    assert client.call('GET', prefix + '/delivery-diagnostics', csrf=False)[0] == expected
    assert cached.call_count == (1 if expected == 200 else 0)
    cached.reset_mock()
    for method in ('POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE'):
        assert admin.call(method, prefix + '/delivery-diagnostics')[0] in (403, 405)
    cached.assert_not_called()


def test_invalid_nested_cache_is_unavailable_and_private(diagnostics_app):
    import copy
    from http_api.delivery_diagnostics import DIAGNOSTICS_SCHEMA
    client, cached, _ = diagnostics_app
    assert client.login()[0] == 200
    invalid = []
    base = diagnostics_payload()
    def mutate(trail, value, delete=False):
        candidate = copy.deepcopy(base)
        target = candidate
        for key in trail[:-1]:
            target = target[key]
        if delete:
            del target[trail[-1]]
        else:
            target[trail[-1]] = value
        invalid.append(candidate)
    def walk(schema, value, trail=()):
        kind = schema['type']
        if isinstance(kind, list):
            kind = kind[0]
        if kind == 'object':
            for key, child in schema['properties'].items():
                mutate((*trail, key), None, delete=True)
                walk(child, value[key], (*trail, key))
        elif kind == 'array':
            mutate(trail, [value[0]] * (schema['maxItems'] + 1))
            walk(schema['items'], value[0], (*trail, 0))
        else:
            choices = ['PRIVATE-CANARY']
            if kind == 'integer':
                choices += [True, -1, 2**63, 1.5]
            if 'enum' in schema:
                choices += [[], {}]
            for item in choices:
                mutate(trail, item)
    walk(DIAGNOSTICS_SCHEMA, base)
    for candidate in invalid:
        cached.return_value = candidate
        code, payload = client.call('GET', '/delivery-diagnostics')
        assert code == 503, candidate
        assert set(payload) == {'error', 'request_id'}
        assert 'PRIVATE-CANARY' not in json.dumps(payload)
    cached.side_effect = RuntimeError('PRIVATE-CANARY')
    assert client.call('GET', '/delivery-diagnostics')[0] == 503


def test_nonzero_array_caps_and_max_wire_budget(diagnostics_app):
    import copy
    import http.client
    from http_api.delivery_diagnostics import MAX_COUNTER
    from monitor.delivery_types import REASONS
    client, cached, _ = diagnostics_app
    longest = max(REASONS, key=len)
    def inflate(value):
        if isinstance(value, dict):
            return {k: (v if k in ('version', 'http_status') else inflate(v)) for k, v in value.items()}
        if type(value) is int:
            return MAX_COUNTER
        if value in REASONS if type(value) is str else False:
            return longest
        return value
    payload = inflate(diagnostics_payload())
    for c in payload['channels'].values():
        c['blocked_by_reason'] = [dict(reason=longest, count=MAX_COUNTER) for _ in range(64)]
    payload['recent_failures'] = [copy.deepcopy(payload['channels']['misp']['latest_failure']) for _ in range(10)]
    cached.return_value = payload
    assert client.login()[0] == 200
    connection = http.client.HTTPConnection('127.0.0.1', client.port, timeout=5)
    try:
        connection.request('GET', '/api/v1/delivery-diagnostics', headers={
            'Cookie': '; '.join(f'{k}={v}' for k, v in client.cookies.items())})
        response = connection.getresponse()
        wire = response.read()
        assert response.status == 200
        assert len(wire) == int(response.getheader('Content-Length')) <= 32768
        assert json.loads(wire) == payload
        assert 'no-store' in response.getheader('Cache-Control')
    finally:
        connection.close()


def test_diagnostics_ui_markup_and_static_asset(diagnostics_app):
    client, cached, _ = diagnostics_app
    assert client.login()[0] == 200
    code, html = client.call('GET', '/')
    assert code == 200
    assert 'id="deliveryDiagnostics"' in html
    assert 'src="/delivery_diagnostics.js"' in html
    for name in ('diagnosticsRead', 'diagnosticsCancel', 'diagnosticsDownload', 'diagnosticsStatus', 'diagnosticsDetails'):
        assert f'id="{name}"' in html
    code, source = client.call('GET', '/delivery_diagnostics.js')
    assert code == 200
    assert 'readDiagnostics' in source
    cached.assert_not_called()
