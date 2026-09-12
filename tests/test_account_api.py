"""Account lifecycle, denial paths and audit exports through real HTTP."""
import json
from unittest.mock import patch

import pytest
from tests.test_http_auth_integration import app as app, Client


def create_ready_user(store, role='operator'):
    admin = store.list_users()[0]
    user = store.create_user('member', 'temporary-password', role, actor=admin)
    store.change_password(user['id'], 'temporary-password', 'changed-password', actor=user)
    return user


def test_account_admin_session_reset_and_audit_export(app):
    store, admin, _ = app
    assert admin.login()[0] == 200
    member = create_ready_user(store)
    client = Client(admin.port)
    assert client.login('member', 'changed-password')[0] == 200
    code, sessions = client.call('GET', '/auth/sessions')
    assert code == 200 and sessions['sessions'][0]['current']
    assert client.call('POST', '/auth/sessions/revoke', {'session_id': sessions['sessions'][0]['id']})[0] == 200
    assert client.call('GET', '/auth/me')[0] == 401
    assert client.login('member', 'changed-password')[0] == 200
    prefix = '/admin/users/' + member['id']
    assert admin.call('POST', prefix + '/revoke', {})[0] == 200
    assert client.call('GET', '/auth/me')[0] == 401
    assert admin.call('POST', prefix + '/update', {'role':'viewer'})[0] == 200
    assert admin.call('POST', prefix + '/reset', {'password':'reset-test-password'})[0] == 200
    assert client.login('member', 'reset-test-password')[0] == 200
    assert client.call('GET', '/results')[0] == 403
    assert admin.call('POST', prefix + '/update', {'active':False})[0] == 200
    assert client.call('GET', '/auth/me')[0] == 401
    assert admin.call('GET', '/admin/users')[0] == 200
    assert admin.call('POST', prefix + '/update', {'unexpected':1})[0] == 400
    code, text = admin.call('POST', '/admin/audit/export', {'limit':2})
    assert code == 200 and len(text.strip().splitlines()) == 2
    assert 'reset-test-password' not in text
    code, own = admin.call('GET', '/auth/activity?user_id=' + member['id'])
    assert code == 200 and all(e['actor_id'] != member['id'] for e in own['events'])


@pytest.mark.parametrize('query', ['limit=0', 'limit=oops', 'offset=-1', 'since=bad', 'since=nan', 'since=20&until=10'])
def test_invalid_audit_filters(app, query):
    _, client, _ = app
    client.login()
    assert client.call('GET', '/admin/audit?' + query)[0] == 400


def test_audit_filtering_and_atomic_failure(app):
    store, client, cfg = app
    client.login()
    actor = store.list_users()[0]
    store.audit(actor, 'test.filter', target='safe-target', outcome='success', request_id='known')
    code, result = client.call('GET', '/admin/audit?action=test.filter&outcome=success&target=safe-target&since=0&until=99999999999')
    assert code == 200 and result['total'] == 1
    with patch.object(store, 'audit', side_effect=OSError('disk full')):
        assert client.call('POST', '/config', {'domains':[], 'revision':0})[0] == 503
    assert cfg.get('_config_revision', 0) == 0
    code, me = client.call('GET', '/auth/me')
    assert code == 200 and not me['audit_available']


def test_transport_and_bad_inputs(app):
    _, client, _ = app
    assert client.call('POST', '/auth/login', {'username':'root','password':'invalid'})[0] == 403
    client.cookies['td_pre'] = 'bad-cookie'
    assert client.call('POST', '/auth/login', {})[0] == 403
    assert client.call('POST', '/auth/login', []) [0] == 400
    assert client.login()[0] == 200
    assert client.call('POST', '/auth/logout', {}, extra_headers={'Origin':'https://other.invalid'})[0] == 403
    assert client.call('GET', '/results', extra_headers={'Host':'other.invalid'})[0] == 403
    assert client.call('OPTIONS', '/results')[0] == 403
    code, cfg = client.call('GET', '/config')
    assert client.call('POST', '/config', {'revision':cfg['revision'], 'domains':[]})[0] == 200
    assert client.call('POST', '/config', {'revision':cfg['revision'], 'domains':[]})[0] == 409
    for page in ('login.html', 'account.html', 'accounts.html', 'audit.html', 'auth_frontend.js', 'security_ui.js'):
        assert client.call('GET', '/' + page)[0] == 200
    assert 'password' not in json.dumps(client.call('GET', '/auth/sessions')[1])