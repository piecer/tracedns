"""Real worker/store -> authenticated HTTP -> shipped Chromium UI.

Provider transport is synthetic; no claim about remote MISP connectivity.
"""
import json
from pathlib import Path
import subprocess
import threading

import pytest
import requests

from http_server import ThreadingHTTPServer, make_handler
from monitor.delivery_adapters import DestinationRegistry, MAX_RESPONSE_BYTES
from monitor.delivery_worker import DeliveryWorker
from security.store import SecurityStore
from test_delivery_adapters_steps import Response, Transport
from test_delivery_store_atomic import AUTH, obs, store_at
from test_http_auth_integration import Client

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def producer_app(tmp_path):
    transport = Transport(
        requests.exceptions.SSLError('private-error-canary'),
        Response(raw=b'x' * (MAX_RESPONSE_BYTES + 1)),
        Response({'Event': {'id': '12', 'Attribute': [{}] * 2001}}),
        Response({'Event': {'id': '12', 'Attribute': [
            {'id': '1', 'event_id': '12', 'type': 'ip-src', 'value': '1.1.1.4'}]}}),
    )
    registry = DestinationRegistry(b'k' * 32, transport=transport)
    registry.apply({'misp_url': 'https://misp.invalid', 'api_key': 'private-key-canary',
                    'push_event_id': '12'}, revision=1)
    binding = registry.descriptors()['misp']
    store = store_at(tmp_path / 'delivery', clock=lambda: 100)
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(['1.1.1.1', '1.1.1.2', '1.1.1.3', '1.1.1.4'], label='private-label'),
                        AUTH, [binding])

    def admit(now):
        claim = store.claim_next(binding, now)
        return (claim, registry.capture('misp', claim['binding_id'], claim['action'])) if claim else None

    worker = DeliveryWorker(store, claim_admission=admit, clock=lambda: 100)
    result = worker.run_pass()
    assert result['provider_calls'] == 4
    snapshot = store.diagnostics_snapshot()
    assert snapshot['channels']['misp']['latest_result']['state'] == 'acked'
    assert [r['reason'] for r in snapshot['recent_failures']] == ['attribute_limit', 'response_limit']
    assert snapshot['channels']['misp']['blocked_by_reason'] == [{'reason': 'tls_error', 'count': 1}]
    accounts = SecurityStore(tmp_path / 'auth' / 'auth.sqlite', create=True)
    accounts.bootstrap('root', 'test-password-123')
    handler = make_handler({'domains': [], 'servers': [], 'interval': 60}, threading.RLock(), '',
                           str(tmp_path), {}, {}, security_store=accounts, insecure_http=True,
                           delivery_health=store.health_snapshot, delivery_diagnostics=store.diagnostics_snapshot)
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield store, transport, Client(server.server_port), snapshot
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        for service in handler.background_services:
            service.close()
        worker.stop()
        store.close(clean=False)


def test_real_producer_diagnostics_http_is_cached_and_secret_free(producer_app):
    store, transport, client, expected = producer_app
    assert client.login()[0] == 200
    original = store._one
    def no_db(*args, **kwargs):
        raise AssertionError('HTTP touched delivery SQL')
    store._one = no_db
    try:
        for prefix in ('', '/api/v1'):
            code, body = client.call('GET', prefix + '/delivery-diagnostics')
            assert code == 200 and body == expected
            wire = json.dumps(body)
            assert 'private-' not in wire
            assert '1.1.1.4' not in wire and 'misp.invalid' not in wire
        assert len(transport.calls) == 4
        store.worker_failed(RuntimeError('private-exception-canary'))
        code, body = client.call('GET', '/delivery-diagnostics')
        assert code == 200
        assert body['storage_error']['code'] == 'worker_exception'
        assert body['counts_stale'] is True and body['coverage'] == 'gap'
        assert body['recent_failures'] == expected['recent_failures']
    finally:
        store._one = original


def test_real_producer_browser_render_and_download(producer_app, tmp_path):
    _, transport, client, snapshot = producer_app
    preflight = subprocess.run(['node', '-e', "const {chromium}=require('@playwright/test');process.exit(require('fs').existsSync(chromium.executablePath())?0:1)"],
                               cwd=ROOT, capture_output=True, timeout=15)
    if preflight.returncode:
        pytest.skip('Playwright Chromium not installed; run npm ci and install Chromium')
    result = subprocess.run(['node', 'tests/test_delivery_diagnostics_browser.js'], cwd=ROOT,
                            input=json.dumps({'port': client.port, 'expected': snapshot, 'out': str(tmp_path)}),
                            text=True, capture_output=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(transport.calls) == 4
    print(result.stdout)
