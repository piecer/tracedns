"""Actual authenticated legacy/v1 settings -> ConfigService -> delivery ledger."""
import json
import threading
from pathlib import Path

import pytest

from http_server import ThreadingHTTPServer, make_handler
from security.store import SecurityStore
from test_http_auth_integration import Client
from test_delivery_auth_form_regressions import blocked_app, config, control, normal_form
from test_stage3_core_runtime import rows


@pytest.fixture
def http_delivery(tmp_path, monkeypatch):
    app = blocked_app(tmp_path, monkeypatch, 'teams misp')
    auth = SecurityStore(tmp_path / 'auth' / 'test.sqlite', create=True)
    auth.bootstrap('root', 'test-password-123')
    handler = make_handler(app.cfg.raw, app.cfg.lock, app.service.config_path,
        str(tmp_path), app.current, app.history, security_store=auth, insecure_http=True,
        state_repository=app.repo, config_service=app.service,
        delivery_health=app.delivery.store.health_snapshot)
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = Client(server.server_port)
    try:
        assert client.login()[0] == 200
        yield app, client
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)
        assert not thread.is_alive()
        for service in handler.background_services:
            service.close()
        app.delivery.stop()


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_http_normal_form_blank_clear_and_revision_are_same_delivery_path(http_delivery, prefix):
    app, client = http_delivery
    code, loaded = client.call('GET', prefix + '/settings')
    assert code == 200 and loaded['revision'] == 0
    public = loaded['settings']['alerts']
    assert all(public[k] == '' and public['configured'][k]
               for k in ('teams_webhook', 'misp_url', 'api_key'))
    form = normal_form(public)
    form['vt_cache_ttl_days'] = 2
    receipts = rows(app, 'receipt')
    epochs = control(app)
    payload = {'revision': loaded['revision'], 'alerts': form, 'clear_fields': []}
    code, result = client.call('POST', prefix + '/settings', payload)
    assert code == 200 and result['revision'] == 1
    assert result['warnings'] == []
    assert app.cfg.raw['_config_service'] is app.service
    app.delivery.worker.run_pass()
    assert rows(app, 'receipt') == receipts
    assert len(app.delivery._transport.calls) == 2
    disk = json.loads(Path(app.service.config_path).read_text())
    assert disk['config_revision'] == 1
    for key in ('teams_webhook', 'misp_url', 'api_key'):
        assert disk['alerts'][key] == config('teams misp')['alerts'][key]
    for channel in ('teams', 'misp'):
        assert control(app)['adapter_revision_' + channel] == epochs['adapter_revision_' + channel]
    # A stale full draft carrying genuine repair intent must not publish it.
    stale = {**payload, 'alerts': {**form, 'api_key': 'repair'}}
    assert client.call('POST', prefix + '/settings', stale)[0] == 409
    assert app.service.snapshot()['config_revision'] == 1
    app.delivery.worker.run_pass()
    assert rows(app, 'receipt') == receipts
    assert len(app.delivery._transport.calls) == 2
    # Admin clear dominates a nonblank field in the same normal form.
    clear = {**form, 'teams_webhook': config('teams')['alerts']['teams_webhook']}
    code, result = client.call('POST', prefix + '/settings',
        {'revision': 1, 'alerts': clear, 'clear_fields': ['teams_webhook']})
    assert code == 200 and result['revision'] == 2
    assert 'teams_webhook' not in app.cfg.raw['alerts']
    assert 'teams_webhook' not in json.loads(Path(app.service.config_path).read_text())['alerts']
    app.delivery.worker.run_pass()
    assert len(app.delivery._transport.calls) == 2
    assert all(row['attempt'] == 1 for row in rows(app, 'receipt'))
    assert control(app)['adapter_revision_teams'] == epochs['adapter_revision_teams'] + 1
    assert control(app)['adapter_revision_misp'] == epochs['adapter_revision_misp']
    # Re-enable exact binding; only Teams may retry, with the original receipt.
    code, result = client.call('POST', prefix + '/settings',
        {'revision': 2, 'alerts': clear, 'clear_fields': []})
    assert code == 200 and result['revision'] == 3
    app.delivery.worker.run_pass()
    app.delivery.worker.run_pass()
    assert len(app.delivery._transport.calls) == 3
    assert {r['id'] for r in rows(app, 'receipt')} == {r['id'] for r in receipts}
    assert {r['channel']: r['attempt'] for r in rows(app, 'receipt')} == {'teams': 2, 'misp': 1}
