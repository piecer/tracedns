"""Real HTTP/security boundary with injected runtime protocol, not ledger proof."""
import http.client
import json
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from http_server import ThreadingHTTPServer, make_handler
from security.store import SecurityStore
from test_http_auth_integration import Client

TOKEN = 'a' * 32
PREVIEW = {'target': 'saved.example', 'channels': ['teams', 'misp'], 'revision': 7}


def preview_result(**changes):
    return dict(status='ready', reason=None, request_id=TOKEN, target='saved.example',
                source_type='RPC', ips=['192.0.2.1'], observed_at=1700000000,
                retained=True, channels=['teams', 'misp'], expires_in_seconds=300,
                retry_after=None, **{}) | changes


def confirm_result(**changes):
    return dict(status='queued', reason=None, request_id=TOKEN, ip_count=1,
                receipt_count=2, channels=['teams', 'misp'], retry_after=None) | changes


@pytest.fixture
def resend_app(tmp_path):
    store = SecurityStore(tmp_path / 'private' / 'auth.sqlite', create=True)
    store.bootstrap('root', 'test-password-123')
    runtime = SimpleNamespace(preview_resend=Mock(return_value=preview_result()),
                              resend_target=Mock(return_value=confirm_result()))
    service = SimpleNamespace(delivery_runtime=runtime)
    config = {'domains': [], 'servers': [], 'interval': 60}
    handler = make_handler(config, threading.RLock(), '', str(tmp_path), {}, {},
                           security_store=store, insecure_http=True, config_service=service)
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield Client(server.server_port), runtime, service, store, config
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def raw_post(client, path, body, headers=None):
    connection = http.client.HTTPConnection('127.0.0.1', client.port, timeout=5)
    try:
        connection.request('POST', path, body=body, headers={
            'Origin': f'http://127.0.0.1:{client.port}', 'X-CSRF-Token': client.csrf,
            'Cookie': '; '.join(f'{k}={v}' for k, v in client.cookies.items()),
            'Content-Type': 'application/json', **(headers or {})})
        response = connection.getresponse()
        raw = response.read()
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = raw.decode()
        return response.status, payload, dict(response.getheaders())
    finally:
        connection.close()


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_resend_routes_pass_exact_actor_and_saved_selection(resend_app, prefix):
    client, runtime, _, _, config = resend_app
    code, login = client.login()
    assert code == 200
    config['api_key'] = 'queued'  # closed enums are not generic redaction input
    assert client.call('POST', prefix + '/delivery-resend/preview', PREVIEW) == (200, preview_result())
    runtime.preview_resend.assert_called_once_with('saved.example', ['teams', 'misp'], 7,
                                                   actor_id=login['user']['id'])
    assert client.call('POST', prefix + '/delivery-resend', {'request_id': TOKEN}) == (202, confirm_result())
    runtime.resend_target.assert_called_once_with(TOKEN, actor_id=login['user']['id'])


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_closed_request_budget_and_unique_fields(resend_app, prefix):
    client, runtime, _, _, _ = resend_app
    assert client.login()[0] == 200
    bad_previews = [{}, {**PREVIEW, 'target': ''}, {**PREVIEW, 'target': 1},
                    *[{**PREVIEW, 'revision': v} for v in (True, -1, 1.5, '7', None, 2**53)],
                    *[{**PREVIEW, 'channels': v} for v in ([], ['teams', 'teams'], ['x'], 'teams', [None], [['teams']])],
                    {**PREVIEW, 'actor_id': 'other'}, {**PREVIEW, 'ips': ['192.0.2.2']},
                    {**PREVIEW, 'destination': 'PRIVATE-CANARY'}]
    for body in bad_previews:
        code, payload = client.call('POST', prefix + '/delivery-resend/preview', body)
        assert code == 400, (body, payload)
        assert 'PRIVATE-CANARY' not in str(payload)
    for body in ({}, {'request_id': TOKEN, 'target': 'x'}, {'request_id': 'A' * 32},
                 {'request_id': TOKEN + '\n'}, {'request_id': 1}, {'request_id': 'a' * 31}):
        assert client.call('POST', prefix + '/delivery-resend', body)[0] == 400
    for path, body in (('/delivery-resend', '{"request_id":"' + TOKEN + '","request_id":"' + TOKEN + '"}'),
                       ('/delivery-resend/preview', '{"target":"x","channels":["teams"],"revision":0,"revision":1}')):
        assert raw_post(client, prefix + path, body)[0] == 400
    for raw in ('null', '[]', '{', '[' * 1500 + '0' + ']' * 1500,
                '{"target":"x","channels":["teams"],"revision":NaN}'):
        assert raw_post(client, prefix + '/delivery-resend/preview', raw)[0] == 400
    assert raw_post(client, prefix + '/delivery-resend/preview', ' ' * 4097)[0] == 413
    assert raw_post(client, prefix + '/delivery-resend', '{}', {'Transfer-Encoding': 'chunked'})[0] == 400
    runtime.preview_resend.assert_not_called()
    runtime.resend_target.assert_not_called()
    padded = json.dumps(PREVIEW).encode().ljust(4096)
    assert raw_post(client, prefix + '/delivery-resend/preview', padded)[0] == 200


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_auth_csrf_roles_and_revocation_before_runtime(resend_app, prefix):
    client, runtime, _, _, _ = resend_app
    for path, body in (('/delivery-resend/preview', PREVIEW), ('/delivery-resend', {'request_id': TOKEN})):
        assert client.call('POST', prefix + path, body)[0] == 401
    assert client.login()[0] == 200
    for path, body in (('/delivery-resend/preview', PREVIEW), ('/delivery-resend', {'request_id': TOKEN})):
        assert client.call('POST', prefix + path, body, csrf=False)[0] == 403
        for headers in ({'Origin': 'https://other.invalid'}, {'Host': 'other.invalid'}):
            assert client.call('POST', prefix + path, body, extra_headers=headers)[0] == 403
        for method in ('GET', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE'):
            assert client.call(method, prefix + path, body)[0] in (403, 405)
    for role in ('viewer', 'operator', 'admin'):
        code, user = client.call('POST', '/admin/users', {
            'username': role, 'password': 'initial-test-password', 'role': role})
        assert code == 201
        other = Client(client.port)
        assert other.login(role, 'initial-test-password')[0] == 200
        assert other.call('POST', '/auth/password', {
            'current_password': 'initial-test-password', 'new_password': 'changed-test-password'})[0] == 200
        assert other.login(role, 'changed-test-password')[0] == 200
        if role == 'admin':
            assert client.call('POST', '/admin/users/' + user['user']['id'] + '/revoke', {})[0] == 200
        for path, body in (('/delivery-resend/preview', PREVIEW), ('/delivery-resend', {'request_id': TOKEN})):
            assert other.call('POST', prefix + path, body)[0] == (401 if role == 'admin' else 403)
    runtime.preview_resend.assert_not_called()
    runtime.resend_target.assert_not_called()


def test_closed_runtime_results_statuses_and_no_exception_prose(resend_app):
    client, runtime, service, _, _ = resend_app
    assert client.login()[0] == 200
    mapping = {400: ['invalid_request'], 404: ['target_not_found'],
               409: ['no_managed_ips', 'snapshot_changed', 'configuration_changed', 'preview_expired',
                     'delivery_pending', 'destination_unavailable'],
               429: ['preview_capacity', 'resend_cooldown'],
               503: ['delivery_capacity', 'delivery_storage', 'runtime_unavailable']}
    for expected, reasons in mapping.items():
        for reason in reasons:
            for preview in (True, False):
                method = runtime.preview_resend if preview else runtime.resend_target
                payload = (preview_result(status='not_ready', reason=reason, request_id=None, ips=[],
                                          expires_in_seconds=0) if preview else
                           confirm_result(status='not_queued', reason=reason, ip_count=0, receipt_count=0))
                method.return_value = payload
                path = '/delivery-resend' + ('/preview' if preview else '')
                body = PREVIEW if preview else {'request_id': TOKEN}
                assert client.call('POST', path, body) == (expected, payload)
    runtime.resend_target.return_value = confirm_result(status='already_queued')
    assert client.call('POST', '/delivery-resend', {'request_id': TOKEN}) == (200, confirm_result(status='already_queued'))
    runtime.resend_target.return_value = confirm_result(status='not_queued', reason='resend_cooldown',
                                                       retry_after=30, ip_count=0, receipt_count=0)
    code, payload, headers = raw_post(client, '/delivery-resend', json.dumps({'request_id': TOKEN}))
    assert code == 429 and headers['Retry-After'] == '30' and 'no-store' in headers['Cache-Control']
    for bad in (None, {}, confirm_result(reason='PRIVATE-CANARY'), confirm_result(request_id='x'),
                confirm_result(channels=['teams', 'teams']), confirm_result(ip_count=True),
                confirm_result(receipt_count=513), confirm_result(retry_after=31),
                confirm_result(status='unknown', reason=None), confirm_result(reason='delivery_storage')):
        runtime.resend_target.return_value = bad
        code, payload = client.call('POST', '/delivery-resend', {'request_id': TOKEN})
        assert code == 503 and payload['status'] == 'unknown' and payload['reason'] == 'delivery_unknown'
        assert 'PRIVATE-CANARY' not in str(payload)
    for bad in (None, {}, preview_result(ips=['bad']), preview_result(ips=['192.0.2.1'] * 257),
                preview_result(source_type='PRIVATE-CANARY'), preview_result(channels=['x']),
                preview_result(status='ready', reason='snapshot_changed'), preview_result(ips=[])):
        runtime.preview_resend.return_value = bad
        code, payload = client.call('POST', '/delivery-resend/preview', PREVIEW)
        assert code == 503 and payload['status'] == 'not_ready'
        assert 'PRIVATE-CANARY' not in str(payload)
    runtime.resend_target.side_effect = RuntimeError('PRIVATE-CANARY')
    code, payload = client.call('POST', '/delivery-resend', {'request_id': TOKEN})
    assert code == 503 and payload['status'] == 'unknown' and 'PRIVATE-CANARY' not in str(payload)
    service.delivery_runtime = None
    for path, body in (('/delivery-resend/preview', PREVIEW), ('/delivery-resend', {'request_id': TOKEN})):
        code, payload = client.call('POST', path, body)
        assert code == 503 and payload['reason'] == 'runtime_unavailable'


def test_durable_preaudit_and_truthful_correlated_outcomes(resend_app, monkeypatch):
    client, runtime, _, store, _ = resend_app
    _, login = client.login()
    original = store.audit
    seen = []
    def observe(actor, action, **kwargs):
        event_id = original(actor, action, **kwargs)
        seen.append((action, kwargs['outcome']))
        return event_id
    monkeypatch.setattr(store, 'audit', observe)
    def preview(*args, **kwargs):
        assert seen[-1] == ('post:/delivery-resend/preview', 'started')
        return preview_result()
    runtime.preview_resend.side_effect = preview
    assert client.call('POST', '/delivery-resend/preview', PREVIEW)[0] == 200
    assert client.call('POST', '/delivery-resend', {'request_id': TOKEN})[0] == 202
    events = store.audit_list(user_id=login['user']['id'], limit=100)['events']
    ready = next(e for e in events if e['action'] == 'post:/delivery-resend/preview' and e['outcome'] == 'ready')
    queued = next(e for e in events if e['action'] == 'post:/delivery-resend' and e['outcome'] == 'queued')
    assert ready['target'] == 'saved.example'
    assert ready['details']['resend_id'] == queued['details']['resend_id'] == TOKEN
    assert queued['job_id'] is None  # ledger request, not a fabricated security job
    assert ready['request_id'] and queued['request_id']
    def unavailable(*args, **kwargs):
        raise OSError('PRIVATE-CANARY')
    monkeypatch.setattr(store, 'audit', unavailable)
    runtime.preview_resend.reset_mock()
    runtime.resend_target.reset_mock()
    for path, body in (('/delivery-resend/preview', PREVIEW), ('/delivery-resend', {'request_id': TOKEN})):
        assert client.call('POST', path, body)[0] == 503
    runtime.preview_resend.assert_not_called()
    runtime.resend_target.assert_not_called()
    def terminal_unavailable(actor, action, **kwargs):
        if kwargs['outcome'] != 'started':
            raise OSError('PRIVATE-CANARY')
        return original(actor, action, **kwargs)
    monkeypatch.setattr(store, 'audit', terminal_unavailable)
    assert client.call('POST', '/delivery-resend', {'request_id': TOKEN})[0] == 503
    runtime.resend_target.assert_called_once()


def test_resend_openapi_exact_static_parity(resend_app):
    from pathlib import Path
    from jsonschema import Draft7Validator
    from http_api.delivery_resend import (PREVIEW_REQUEST_SCHEMA, PREVIEW_RESULT_SCHEMA,
                                         CONFIRM_REQUEST_SCHEMA, CONFIRM_RESULT_SCHEMA)
    client, _, _, _, _ = resend_app
    assert client.login()[0] == 200
    code, document = client.call('GET', '/api/v1/openapi.json')
    assert code == 200, document
    for path, request, result in (('/delivery-resend/preview', PREVIEW_REQUEST_SCHEMA, PREVIEW_RESULT_SCHEMA),
                                  ('/delivery-resend', CONFIRM_REQUEST_SCHEMA, CONFIRM_RESULT_SCHEMA)):
        op = document['paths'][path]['post']
        assert op['x-roles'] == ['admin']
        assert op['requestBody']['content']['application/json']['schema'] == request
        assert op['x-max-body-bytes'] == 4096
        for status in ('200', '400', '404', '409', '429', '503'):
            schema = op['responses'][status]['content']['application/json']['schema']
            assert result == schema or result in schema.get('anyOf', [])
        assert op['responses']['429']['headers']['Retry-After']['schema']['maximum'] == 30
    Draft7Validator(PREVIEW_RESULT_SCHEMA).validate(preview_result())
    Draft7Validator(CONFIRM_RESULT_SCHEMA).validate(confirm_result())
    assert not Draft7Validator(CONFIRM_REQUEST_SCHEMA).is_valid({'request_id': 'A' * 32})
    assert not Draft7Validator(PREVIEW_REQUEST_SCHEMA).is_valid({**PREVIEW, 'channels': ['teams', 'teams']})
    assert json.loads((Path(__file__).resolve().parents[1] / 'docs/openapi.json').read_text()) == document
    code, script = client.call('GET', '/delivery_resend.js')
    assert code == 200 and 'TraceDeliveryResend' in script


def test_resend_schema_discriminates_ready_queued_and_unknown():
    from jsonschema import Draft7Validator
    from http_api.delivery_resend import PREVIEW_RESULT_SCHEMA, CONFIRM_RESULT_SCHEMA
    for value in (preview_result(ips=[]), preview_result(request_id=None), preview_result(reason='snapshot_changed'),
                  preview_result(status='not_ready', reason=None)):
        assert not Draft7Validator(PREVIEW_RESULT_SCHEMA).is_valid(value)
    for value in (confirm_result(reason='delivery_storage'), confirm_result(request_id=None),
                  confirm_result(status='unknown', reason=None), confirm_result(status='not_queued', reason='delivery_pending')):
        assert not Draft7Validator(CONFIRM_RESULT_SCHEMA).is_valid(value)


def test_resend_audit_correlation_allowlist_is_action_and_format_bound(resend_app):
    _, _, _, store, _ = resend_app
    for action, token in (('post:/config', TOKEN), ('post:/delivery-resend', 'A' * 32),
                          ('post:/delivery-resend', TOKEN + '\n'), ('post:/delivery-resend', {'secret': 'x'})):
        store.audit(None, action, details={'resend_id': token, 'url': 'PRIVATE-CANARY'})
    events = store.audit_list(limit=100)['events']
    assert all(not event['details'] for event in events if event['action'].startswith('post:'))
