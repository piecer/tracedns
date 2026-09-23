"""Versioned API traverses the same real HTTP security boundary as the UI."""
import json
import time
from pathlib import Path

import pytest

from test_http_auth_integration import Client, app as http_app

app = http_app


def test_versioned_login_read_and_mutation_share_legacy_state(app):
    _, client, config = app
    assert client.call('GET', '/api/v1/config')[0] == 401
    code, csrf = client.call('GET', '/api/v1/auth/csrf')
    assert code == 200
    client.csrf = csrf['csrf_token']
    code, login = client.call('POST', '/api/v1/auth/login', {
        'username': 'root', 'password': 'test-password-123',
    })
    assert code == 200
    client.csrf = login['csrf_token']
    code, before = client.call('GET', '/api/v1/config')
    assert code == 200
    code, saved = client.call('PATCH', '/api/v1/config', {
        'revision': before['revision'], 'domains': [{'name': 'example.org', 'type': 'A'}],
    })
    assert code == 200
    assert config['domains'][0]['name'] == 'example.org'
    code, legacy = client.call('GET', '/config')
    assert code == 200
    assert legacy['domains'] == saved['config']['domains']
    assert legacy['revision'] == saved['revision']
    assert client.call('PATCH', '/api/v1/config', {
        'revision': before['revision'], 'domains': [],
    })[0] == 409
    assert client.call('POST', '/api/v1/auth/logout', {})[0] == 200
    assert client.call('GET', '/api/v1/results')[0] == 401


def test_discovery_is_authenticated_and_describes_only_mounted_routes(app):
    _, client, _ = app
    assert client.call('GET', '/api/v1/openapi.json')[0] == 401
    assert client.login()[0] == 200
    code, info = client.call('GET', '/api/v1')
    assert code == 200
    assert info['openapi'] == '/api/v1/openapi.json'
    code, schema = client.call('GET', info['openapi'])
    assert code == 200
    assert schema['openapi'] == '3.1.0'
    assert schema['servers'] == [{'url': '/api/v1'}]
    assert '/ip-relationship-jobs/{job_id}' in schema['paths']
    assert '/admin/users/{user_id}/update' in schema['paths']
    assert '/settings' in schema['paths']
    assert '/verify' not in schema['paths']  # existing endpoint is a 501 stub
    assert schema['paths']['/config']['patch']['requestBody']['required']
    assert schema['components']['securitySchemes']['session']['name'] == 'td_session'
    from http_api.rest import resolve_route
    ids = []
    for path, methods in schema['paths'].items():
        concrete = path.replace('{job_id}', 'a' * 32).replace('{user_id}', 'test-user')
        for method, operation in methods.items():
            resolve_route('/api/v1' + concrete, method.upper())
            ids.append(operation['operationId'])
    assert len(ids) == len(set(ids))


def test_versioned_security_and_fail_closed_routes(app):
    store, client, config = app
    assert client.login()[0] == 200
    assert client.call('PATCH', '/api/v1/config', {'domains': [], 'revision': 0}, csrf=False)[0] == 403
    assert client.call('PATCH', '/api/v1/config', {'domains': [], 'revision': 0},
                       extra_headers={'Origin': 'https://wrong.invalid'})[0] == 403
    assert client.call('GET', '/api/v1/config', extra_headers={'Host': 'wrong.invalid'})[0] == 403
    for path in ('/api/v1/unknown', '/api/v2/config', '/api/v1/dns_config.json',
                 '/api/v1/login.html', '/api/v1/../config', '/api/v1/%63onfig', '/api/v1/verify'):
        assert client.call('GET', path)[0] == 404
    assert client.call('DELETE', '/api/v1/config', {})[0] == 405
    events = store.audit_list(limit=100)['events']
    assert any(e['action'] == 'access.denied' for e in events)


def account(app, role):
    store, admin, _ = app
    if admin.call('GET', '/auth/me')[0] != 200:
        assert admin.login()[0] == 200
    actor = admin.call('GET', '/auth/me')[1]['user']
    user = store.create_user(role, 'initial-password-123', role, actor=actor)
    store.change_password(user['id'], 'initial-password-123', 'changed-password-123', actor=user)
    client = Client(admin.port)
    assert client.login(role, 'changed-password-123')[0] == 200
    return client


@pytest.mark.parametrize('role', ['viewer', 'operator'])
def test_versioned_role_checks_cannot_be_bypassed_by_patch(app, role):
    client = account(app, role)
    assert client.call('GET', '/api/v1/openapi.json')[0] == 200
    assert client.call('GET', '/api/v1/domain-analysis?include_vt=0')[0] == 200
    assert client.call('GET', '/api/v1/settings')[0] == 403
    assert client.call('PATCH', '/api/v1/settings', {'revision': 0, 'alerts': {}})[0] == 403
    assert client.call('PATCH', '/api/v1/config', {'revision': 0, 'domains': [], 'interval': 120})[0] == 403
    assert client.call('PATCH', '/api/v1/config', {'revision': 0, 'domains': []})[0] == (200 if role == 'operator' else 403)
    if role == 'viewer':
        assert client.call('GET', '/api/v1/domain-analysis')[0] == 403
        assert client.call('GET', '/api/v1/ips?include_vt=1')[0] == 403
        assert client.call('POST', '/api/v1/ip-relationship-jobs', {'ips': ['192.0.2.1'], 'include_vt': False})[0] == 403


def test_versioned_mutation_stops_when_audit_fails(app, monkeypatch):
    store, client, config = app
    assert client.login()[0] == 200

    def fail(*args, **kwargs):
        raise OSError('private storage detail')

    monkeypatch.setattr(store, 'audit', fail)
    code, body = client.call('PATCH', '/api/v1/config', {'revision': 0, 'domains': ['example.org']})
    assert code == 503
    assert config['domains'] == []
    assert 'private storage detail' not in json.dumps(body)


def test_auth_body_limit_survives_version_prefix(app):
    _, client, _ = app
    assert client.login()[0] == 200
    code, body = client.call('POST', '/api/v1/auth/password', {'new_password': 'x' * 17000})
    assert code == 413
    assert isinstance(body, str)  # framing/body-limit errors remain text/plain


def test_actual_async_worker_via_versioned_http(app, monkeypatch):
    import http_api.relationship_handlers as jobs
    monkeypatch.setattr(jobs, '_IP_REL_JOBS', {})
    monkeypatch.setattr(jobs, '_IP_REL_JOB_EXECUTOR', None)
    _, client, _ = app
    assert client.login()[0] == 200
    try:
        code, accepted = client.call('POST', '/api/v1/ip-relationship-jobs', {
            'ips': ['192.0.2.1', '192.0.2.2'], 'include_vt': False,
        })
        assert code == 202
        deadline = time.monotonic() + 15
        while True:
            code, job = client.call('GET', '/api/v1/ip-relationship-jobs/' + accepted['job_id'] + '?result=1')
            assert code == 200
            if job['status'] not in ('queued', 'running'):
                break
            assert time.monotonic() < deadline, job
            time.sleep(0.05)
        assert job['status'] == 'completed', job
        assert isinstance(job['result'], dict)
        assert job['audit_status'] == 'recorded'
        other = account(app, 'operator')
        assert other.call('GET', '/api/v1/ip-relationship-jobs/' + accepted['job_id'])[0] == 404
        assert other.call('POST', '/api/v1/ip-relationship-jobs/' + accepted['job_id'] + '/cancel', {})[0] == 404
        assert client.call('POST', '/api/v1/ip-relationship-jobs/' + accepted['job_id'] + '/cancel', {})[0] == 409
    finally:
        jobs.shutdown_ip_relationship_jobs(wait=True)


def test_static_openapi_matches_live_producer():
    from http_api.openapi import openapi_document
    path = Path(__file__).resolve().parents[1] / 'docs' / 'openapi.json'
    assert path.exists(), 'Ship the offline contract alongside SKILL.md'
    assert json.loads(path.read_text()) == openapi_document()


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_misp_search_post_consumes_json_value_like_get(app, monkeypatch, prefix):
    from unittest.mock import Mock
    import requests
    _, client, config = app
    config['alerts'] = {'misp_url': 'https://misp.invalid', 'api_key': 'synthetic-test-key'}
    upstream = Mock()
    upstream.return_value.ok = True
    upstream.return_value.status_code = 200
    upstream.return_value.content = b'{}'
    upstream.return_value.json.return_value = {'response': {'Attribute': []}}
    monkeypatch.setattr(requests, 'post', upstream)
    assert client.login()[0] == 200
    code, result = client.call('POST', prefix + '/misp/search', {'value': '192.0.2.1'})
    assert code == 200, result
    assert result['query'] == '192.0.2.1'
    assert upstream.call_count == 1
    assert upstream.call_args.kwargs['json']['value'] == '192.0.2.1'
    code, get_result = client.call('GET', prefix + '/misp/search?value=192.0.2.1')
    assert code == 200 and get_result == result


def test_read_responses_match_documented_schemas(app):
    from jsonschema import Draft7Validator
    from http_api.openapi import READ_RESPONSES
    _, client, _ = app
    assert client.login()[0] == 200
    for path, schema in READ_RESPONSES.items():
        if '{job_id}' in path:
            continue  # exercised by the real worker test
        query = '?domain=example.org' if path == '/history' else '?ip=192.0.2.1' if path == '/ip' else ''
        status, body = client.call('GET', '/api/v1' + path + query)
        assert status == 200, (path, status, body)
        Draft7Validator.check_schema(schema)
        Draft7Validator(schema).validate(body)


def test_versioned_force_resolve_preserves_actor_and_acceptance_audit(app):
    store, client, config = app
    assert client.login()[0] == 200
    saved = client.call('PATCH', '/api/v1/config', {
        'revision': 0, 'domains': [{'name': 'example.org', 'type': 'A'}], 'servers': ['127.0.0.1'],
    })
    assert saved[0] == 200
    code, queued = client.call('POST', '/api/v1/resolve', {'domains': saved[1]['config']['domains']})
    assert code == 200 and queued['requested'] is True
    pending = config['_force_resolve_queue'][0]
    assert pending['job_id'] == queued['job_id']
    assert pending['actor']['username'] == 'root'
    events = store.audit_list(action='force.resolve', target=queued['job_id'])['events']
    assert [e['outcome'] for e in events] == ['started']  # no monitor worker here; never claim completion


def test_skill_bundle_has_portable_frontmatter_and_verified_references():
    root = Path(__file__).resolve().parents[1]
    text = (root / 'SKILL.md').read_text()
    assert text.startswith('---\n')
    header, body = text[4:].split('\n---\n', 1)
    fields = dict(line.split(': ', 1) for line in header.splitlines() if ': ' in line and not line.startswith(' '))
    assert fields['name'] == 'tracedns'
    assert len(fields['description']) <= 60
    assert fields['description'].endswith('.')
    assert fields['platforms'] == '[linux, macos, windows]'
    for section in ('When to Use', 'Prerequisites', 'Procedure', 'Pitfalls', 'Verification'):
        assert '## ' + section in body
    for path in ('scripts/tracedns_api.py', 'docs/API.md', 'docs/openapi.json', 'docs/security/deployment.md'):
        assert path in body
        assert (root / path).is_file()
    assert '/home/' not in text
