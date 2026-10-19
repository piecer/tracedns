"""Manual Teams probes use the applied immutable adapter, never alert receipts."""
import json
import threading

import pytest
import requests

from test_delivery_adapters_steps import Response, Transport
from test_stage3_core_runtime import app_factory, rows


@pytest.mark.parametrize('revision', [1, -1, True, None, '0', 2**53])
def test_invalid_or_stale_revision_never_sends(tmp_path, revision):
    transport = Transport(Response(status=200))
    app = app_factory(tmp_path, transport=transport)
    try:
        outcome = app.delivery.test_teams(revision)
        assert outcome['status'] == 'not_sent'
        assert outcome['reason'] == 'configuration_changed'
        assert transport.calls == []
    finally:
        app.delivery.stop()


@pytest.mark.parametrize('mode,reason', [
    ('stopping', 'runtime_unavailable'), ('missing', 'runtime_unavailable'),
    ('pending', 'adapter_unapplied'), ('disabled', 'destination_disabled'),
    ('invalid', 'destination_invalid'),
])
def test_unavailable_or_unapplied_settings_never_send(tmp_path, mode, reason):
    transport = Transport(Response(status=200))
    app = app_factory(tmp_path, transport=transport)
    try:
        if mode == 'stopping':
            app.delivery.stopping = True
        elif mode == 'missing':
            app.delivery.registry = None
        elif mode == 'pending':
            app.delivery._pending_bindings = []
        else:
            app.service.commit('settings', {'alerts': {'teams_webhook': '' if mode == 'disabled' else 'http://teams.invalid/hook'},
                                           'clear_fields': ['teams_webhook'] if mode == 'disabled' else []}, expected_revision=0)
        outcome = app.delivery.test_teams(app.delivery.revision())
        assert outcome['status'] == 'not_sent'
        assert outcome['reason'] == reason
        assert transport.calls == []
    finally:
        app.delivery.stop()


def test_in_flight_guard_cooldown_and_unlocked_saved_adapter(tmp_path):
    entered, release = threading.Event(), threading.Event()
    class PausedTransport(Transport):
        def request(self, *args, **kwargs):
            entered.set()
            assert release.wait(3)
            return super().request(*args, **kwargs)
    transport = PausedTransport(Response(status=200), Response(status=200))
    app = app_factory(tmp_path, transport=transport)
    clock = [100.0]
    app.delivery._teams_test_clock = lambda: clock[0]
    outcomes = []
    thread = threading.Thread(target=lambda: outcomes.append(app.delivery.test_teams(0)))
    try:
        thread.start()
        assert entered.wait(2)
        busy = app.delivery.test_teams(0)
        assert busy['status'] == 'not_sent' and busy['reason'] == 'test_in_progress'
        assert app.cfg.lock.acquire(timeout=.5), 'outbound request held configuration lock'
        app.cfg.lock.release()
        app.service.commit('settings', {'alerts': {'teams_webhook': 'https://teams.invalid/changed'}}, expected_revision=0)
        release.set()
        thread.join(3)
        assert not thread.is_alive()
        assert outcomes[0]['status'] == 'accepted'
        assert transport.calls[0][1] == 'https://teams.invalid/hook'
        cooldown = app.delivery.test_teams(1)
        assert cooldown['reason'] == 'test_cooldown' and cooldown['retry_after'] == 30
        clock[0] = 130
        assert app.delivery.test_teams(1)['status'] == 'accepted'
        assert transport.calls[1][1] == 'https://teams.invalid/changed'
    finally:
        release.set()
        thread.join(3)
        app.delivery.stop()


@pytest.mark.parametrize('response,reason,status', [
    (Response(status=302), 'provider_http', 302),
    (Response(status=401), 'provider_auth', 401),
    (Response(status=500), 'provider_transient', 500),
    (requests.exceptions.SSLError('private-canary'), 'tls_error', None),
    (requests.exceptions.Timeout('private-canary'), 'transport_error', None),
])
def test_provider_failure_is_reported_without_retry_or_secret_text(tmp_path, response, reason, status):
    transport = Transport(response)
    app = app_factory(tmp_path, transport=transport)
    try:
        outcome = app.delivery.test_teams(0)
        assert outcome['status'] == 'failed' and outcome['reason'] == reason
        assert outcome['diagnostic']['http_status'] == status
        assert 'private-canary' not in json.dumps(outcome)
        assert len(transport.calls) == 1
        assert app.delivery.test_teams(0)['reason'] == 'test_cooldown'
        assert len(transport.calls) == 1
    finally:
        app.delivery.stop()


def test_shutdown_does_not_report_closed_while_manual_send_is_active(tmp_path):
    entered, release = threading.Event(), threading.Event()
    class PausedTransport(Transport):
        def request(self, *args, **kwargs):
            entered.set()
            assert release.wait(3)
            return super().request(*args, **kwargs)
    transport = PausedTransport(Response(status=200))
    app = app_factory(tmp_path, transport=transport)
    thread = threading.Thread(target=lambda: app.delivery.test_teams(0))
    try:
        thread.start()
        assert entered.wait(2)
        stopped = app.delivery.stop(join_seconds=0)
        assert stopped['stopped'] is False and stopped['closed'] is False
        assert stopped['in_flight_preserved'] is True
        release.set()
        thread.join(3)
        assert not thread.is_alive()
        assert app.delivery.test_teams(0)['reason'] == 'runtime_unavailable'
        assert len(transport.calls) == 1
        assert app.delivery.stop()['closed'] is True
    finally:
        release.set()
        thread.join(3)
        app.delivery.stop()


def test_manual_teams_posts_fixed_message_once_without_ledger_changes(tmp_path):
    transport = Transport(Response(status=200, raw=b'1'))
    app = app_factory(tmp_path, transport=transport)
    try:
        before = {table: rows(app, table) for table in ('receipt', 'control', 'terminal', 'batch')}
        outcome = app.delivery.test_teams(0)
        assert outcome['status'] == 'accepted'
        assert outcome['reason'] is None
        assert outcome['diagnostic']['operation'] == 'teams_send'
        assert outcome['diagnostic']['http_status'] == 200
        assert len(transport.calls) == 1
        method, url, kwargs = transport.calls[0]
        assert method == 'POST' and url == 'https://teams.invalid/hook'
        assert kwargs['verify'] is True and kwargs['allow_redirects'] is False
        body = json.loads(kwargs['data'])
        assert set(body) == {'title', 'text'}
        assert 'test' in body['title'].lower() and 'TraceDNS' in body['title']
        assert 'test.example' not in json.dumps(body)
        assert {table: rows(app, table) for table in before} == before
    finally:
        app.delivery.stop()
