"""Authenticated cached delivery health; the real ledger is wired at integration."""
import json
import threading
from unittest.mock import Mock

import pytest

from http_server import ThreadingHTTPServer, make_handler
from security.store import SecurityStore
from test_http_auth_integration import Client


def health_payload():
    channel = {'enabled': True, 'pending': 1, 'blocked': 0,
               'last_success_at': None, 'last_error': 'delivery_storage'}
    return {
        'status': 'degraded', 'observation_policy': 'continue',
        'storage_ok': False, 'worker_running': True, 'coverage': 'gap',
        'accounting_complete': False, 'missed_total': 12, 'missed_unpersisted': 3,
        'failed_total': 2, 'acked_total': 40, 'pending': 2, 'retry_wait': 1,
        'blocked': 0, 'oldest_pending_age_seconds': 120,
        'capacity': {'used_receipts': 3, 'max_receipts': 4096,
                     'used_payload_bytes': 9000, 'max_payload_bytes': 8388608},
        'channels': {'teams': dict(channel), 'misp': dict(channel)},
        'tracking_complete': False, 'counts_stale': True, 'last_error': 'delivery_storage',
    }


@pytest.fixture
def delivery_app(tmp_path):
    store = SecurityStore(tmp_path / 'private' / 'auth.sqlite', create=True)
    store.bootstrap('root', 'test-password-123')
    cached = Mock(return_value=health_payload())
    handler = make_handler({'domains': [], 'servers': [], 'interval': 60},
                           threading.RLock(), '', str(tmp_path), {}, {},
                           security_store=store, insecure_http=True, delivery_health=cached)
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield Client(server.server_port), cached
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_delivery_health_degraded_cache_remains_available(delivery_app, prefix):
    client, cached = delivery_app
    assert client.login()[0] == 200
    code, result = client.call('GET', prefix + '/delivery-health')
    assert code == 200, result
    assert result == health_payload()
    assert len(json.dumps(result).encode()) <= 4096
    cached.assert_called_once_with()


def test_delivery_health_projects_only_closed_public_fields(delivery_app):
    client, cached = delivery_app
    payload = health_payload()
    payload['future_internal'] = {'endpoint': 'private-health-marker'}
    payload['capacity']['internal_token'] = 'private-health-marker'
    payload['channels']['teams']['api_key'] = 'private-health-marker'
    payload['channels']['teams']['last_error'] = 'private-health-marker'
    payload['channels']['future_destination'] = {'key': 'private-health-marker'}
    cached.return_value = payload
    assert client.login()[0] == 200
    code, result = client.call('GET', '/api/v1/delivery-health')
    assert code == 200
    expected = health_payload()
    expected['channels']['teams']['last_error'] = 'delivery_unknown'
    assert result == expected
    assert 'private-health-marker' not in json.dumps(result)


@pytest.mark.parametrize('field,value', [
    ('missed_total', True), ('missed_total', -1), ('missed_total', 2**63),
    ('missed_total', '12'), ('storage_ok', 'false'), ('status', 'sent'),
    ('observation_policy', 'stop'), ('coverage', 'everything_delivered'),
    ('oldest_pending_age_seconds', float('nan')), ('channels', []),
])
def test_delivery_health_invalid_cache_is_unknown_not_success(delivery_app, field, value):
    client, cached = delivery_app
    cached.return_value[field] = value
    assert client.login()[0] == 200
    code, result = client.call('GET', '/delivery-health')
    assert code == 503, result
    assert 'missed_total' not in result


def test_delivery_health_openapi_is_same_closed_projection(delivery_app):
    from http_api.delivery_health import HEALTH_SCHEMA
    client, _ = delivery_app
    assert client.login()[0] == 200
    code, document = client.call('GET', '/api/v1/openapi.json')
    assert code == 200
    operation = document['paths']['/delivery-health']['get']
    assert operation['responses']['200']['content']['application/json']['schema'] == HEALTH_SCHEMA
    assert operation['x-roles'] == ['operator', 'admin']
    from jsonschema import Draft7Validator
    code, health = client.call('GET', '/api/v1/delivery-health')
    assert code == 200
    Draft7Validator(HEALTH_SCHEMA).validate(health)


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
@pytest.mark.parametrize('role,status', [('viewer', 403), ('operator', 200)])
def test_delivery_health_auth_roles_and_cached_only_read(delivery_app, prefix, role, status):
    admin, cached = delivery_app
    assert admin.call('GET', prefix + '/delivery-health')[0] == 401
    cached.assert_not_called()
    assert admin.login()[0] == 200
    assert admin.call('POST', '/admin/users', {
        'username': role, 'password': 'initial-test-password', 'role': role})[0] == 201
    client = Client(admin.port)
    assert client.login(role, 'initial-test-password')[0] == 200
    assert client.call('POST', '/auth/password', {
        'current_password': 'initial-test-password', 'new_password': 'changed-test-password'})[0] == 200
    assert client.login(role, 'changed-test-password')[0] == 200
    assert client.call('GET', prefix + '/delivery-health', csrf=False)[0] == status
    assert cached.call_count == (1 if status == 200 else 0)


def test_delivery_health_broken_owner_never_reports_empty_success(delivery_app):
    client, cached = delivery_app
    assert client.login()[0] == 200
    cached.side_effect = RuntimeError('private-owner-marker')
    code, result = client.call('GET', '/api/v1/delivery-health')
    assert code == 503
    assert 'private-owner-marker' not in json.dumps(result)
    assert 'missed_total' not in result


def test_delivery_health_max_counters_fit_actual_wire_budget(delivery_app):
    import http.client
    from http_api.delivery_health import MAX_COUNTER, REASONS
    client, cached = delivery_app

    def inflate(value):
        if type(value) is dict:
            return {key: inflate(child) for key, child in value.items()}
        if type(value) is int:
            return MAX_COUNTER
        if value == 'delivery_storage':
            return max(REASONS, key=len)
        return value

    cached.return_value = inflate(health_payload())
    assert client.login()[0] == 200
    connection = http.client.HTTPConnection('127.0.0.1', client.port, timeout=5)
    try:
        connection.request('GET', '/api/v1/delivery-health', headers={
            'Cookie': '; '.join(f'{key}={value}' for key, value in client.cookies.items())})
        response = connection.getresponse()
        wire = response.read()
        assert response.status == 200
        length = response.getheader('Content-Length')
        assert length is not None
        assert len(wire) == int(length) <= 4096
        assert json.loads(wire) == cached.return_value
    finally:
        connection.close()
