"""Settings receipt publication is downstream of durable completion audit."""
import json
from pathlib import Path
import threading

import pytest

from test_ai_settings_api import app as app_fixture
from test_local_ai_live_settings import thread_call

app = app_fixture


def test_receipt_waits_for_completion_audit_and_fault_latches_admission(app, monkeypatch):
    entered, release, delivered = threading.Event(), threading.Event(), threading.Event()
    original = app.store.audit
    def audit(actor, action, **kwargs):
        if action == 'post:/ai/settings' and kwargs.get('outcome') == 'success':
            entered.set()
            assert release.wait(4)
            raise OSError('PRIVATE_AUDIT_PROSE')
        return original(actor, action, **kwargs)
    monkeypatch.setattr(app.store, 'audit', audit)
    def post():
        try:
            return app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': app.native})
        finally:
            delivered.set()
    thread, result = thread_call(post)
    try:
        assert entered.wait(2)
        assert not delivered.wait(.1), 'successful receipt escaped before completion audit'
        assert json.loads(Path(app.core.service.config_path).read_text())['config_revision'] == 1
    finally:
        release.set()
        thread.join(4)
    assert result.error is None
    assert result.value[0] == 503 and 'PRIVATE' not in json.dumps(result.value)
    code, readback = app.client.call('GET', '/api/v1/ai/settings')
    assert code == 200 and readback['revision'] == 1
    assert readback['runtime'] == {'applied': False, 'state': 'unavailable'}
    assert app.client.call('POST', '/ai/jobs', {'kind': 'delivery', 'language': 'en'})[0] == 503
    monkeypatch.setattr(app.store, 'audit', original)
    code, saved = app.client.call('POST', '/ai/settings', {'revision': 1, 'settings': {'enabled': True}})
    assert code == 200 and not saved['runtime']['applied']
    assert not app.handler.local_ai.status(app.store.authenticate(app.client.cookies['td_session']))['accepting']
    assert not app.native_requests, 'Save/audit failure must never infer or retry'


def test_audit_intent_failure_has_no_write_or_setup(app, monkeypatch):
    original = app.store.audit
    def audit(actor, action, **kwargs):
        if action == 'post:/ai/settings':
            raise OSError('PRIVATE_AUDIT_PROSE')
        return original(actor, action, **kwargs)
    monkeypatch.setattr(app.store, 'audit', audit)
    status, body = app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': app.native})
    assert status == 503 and 'PRIVATE' not in json.dumps(body)
    assert app.config['config_revision'] == 0
    assert not Path(app.core.service.config_path).exists()
    assert app.handler.local_ai._worker is None and not app.native_requests


@pytest.mark.parametrize('alias', ['/ai/settings', '/api/v1/ai/settings'])
def test_successful_settings_audit_contains_no_body_or_credential(app, alias):
    secret = 'fixture-Bearer-only-opaque-secret'
    patch = {'provider': 'openai_compatible', 'enabled': False, 'base_url': 'https://example.com/v1',
             'model': 'fixture', 'api_key': secret}
    code, response = app.client.call('POST', alias, {'revision': 0, 'settings': patch})
    assert code == 200, response
    events = app.store.audit_list(action='post:/ai/settings')['events']
    assert [e['outcome'] for e in reversed(events)] == ['started', 'success']
    assert secret not in json.dumps(events) and secret not in json.dumps(response)
    assert secret not in json.dumps(app.client.call('GET', alias))
    assert 'local_ai' not in app.client.call('GET', '/config')[1]
