"""Browser enrichment mode must never invoke synchronous VT lookups."""
import io
import json
import threading
import time
from unittest.mock import Mock, patch

import pytest

from http_api_handlers import attach_api_handlers


def handler(service=None, ip='8.8.8.8'):
    class Handler:
        def __init__(self):
            self.wfile = io.BytesIO()
            self.status = None
            self.principal = {'id': 'test-operator', 'role': 'operator'}

        def send_response(self, status):
            self.status = status

        def send_header(self, *args):
            pass

        def end_headers(self):
            pass

    return attach_api_handlers(
        Handler, frontend_html='', shared_config={}, config_lock=threading.RLock(),
        config_path='', history_dir='', current_results={
            'example.test': {'resolver': {'type': 'A', 'values': [ip], 'ts': 1}},
        }, history={}, purge_removed_domains_state=lambda *args: None,
        background_enrichment=service,
    )()


def test_background_domain_analysis_uses_published_reports_not_sync_vt():
    service = Mock()
    service.request.return_value = ({'8.8.8.8': {'asn': 15169, 'malicious': 0}}, {'status': 'ready'})
    h = handler(service)
    with patch('http_api_handlers.get_ip_report', side_effect=AssertionError('interactive VT lookup')):
        h._handle_domain_analysis({'include_vt': ['1'], 'vt_mode': ['background']})
    assert h.status == 200
    body = json.loads(h.wfile.getvalue())
    assert body['domains'][0]['ip_rows'][0]['vt']['asn'] == 15169
    assert body['enrichment']['status'] == 'ready'
    assert service.request.call_args.kwargs['owner'] == 'test-operator'


def test_background_ips_uses_visible_page_and_respects_include_vt_zero():
    service = Mock()
    service.request.return_value = ({}, {'status': 'pending'})
    h = handler(service)
    with patch('http_api_handlers.get_ip_report', side_effect=AssertionError('interactive VT lookup')):
        h._handle_ips({'include_vt': ['1'], 'vt_mode': ['background'], 'limit': ['1']})
    assert h.status == 200
    assert service.request.call_args.args[0] == ['8.8.8.8']
    assert json.loads(h.wfile.getvalue())['enrichment']['status'] == 'pending'
    service.reset_mock()
    h = handler(service)
    h._handle_domain_analysis({'include_vt': ['0'], 'vt_mode': ['background']})
    assert h.status == 200
    service.request.assert_not_called()
    assert json.loads(h.wfile.getvalue())['enrichment']['status'] == 'disabled'


def test_missing_background_service_never_falls_back_to_sync_lookup():
    h = handler()
    with patch('http_api_handlers.get_ip_report', side_effect=AssertionError('interactive VT lookup')):
        h._handle_ips({'include_vt': ['1'], 'vt_mode': ['background']})
    assert h.status == 200
    assert json.loads(h.wfile.getvalue())['enrichment']['status'] == 'unavailable'


@pytest.mark.parametrize('method', ['_handle_ips', '_handle_domain_analysis'])
def test_background_reports_use_canonical_lookup_without_rewriting_evidence(method):
    raw = '2001:4860:4860:0:0:0:0:8888'
    service = Mock()
    service.request.return_value = ({'2001:4860:4860::8888': {'asn': 15169}}, {'status': 'ready'})
    h = handler(service, raw)
    getattr(h, method)({'include_vt': ['1'], 'vt_mode': ['background']})
    body = json.loads(h.wfile.getvalue())
    rows = body['ips'] if method == '_handle_ips' else body['domains'][0]['ip_rows']
    assert rows[0]['ip'] == raw
    assert rows[0]['vt']['asn'] == 15169


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_real_http_background_mode_keeps_reads_live_and_enforces_csrf(tmp_path, prefix):
    from http_server import ThreadingHTTPServer, make_handler
    from security.store import SecurityStore
    from tests.test_http_auth_integration import Client

    entered, release = threading.Event(), threading.Event()
    calls = []

    def lookup(ip):
        calls.append(ip)
        entered.set()
        release.wait(5)
        return {'asn': 15169, 'malicious': 0}

    store = SecurityStore(tmp_path / 'private' / 'auth.sqlite', create=True)
    store.bootstrap('root', 'test-password-123')
    with patch('http_api_handlers.get_ip_report', side_effect=lookup):
        cls = make_handler({}, threading.RLock(), '', str(tmp_path), {
            'example.test': {'r': {'type': 'A', 'values': ['8.8.8.8'], 'ts': 1}}
        }, {}, security_store=store, insecure_http=True)
        assert getattr(cls, 'background_services', ()), 'factory must own the enrichment service'
        server = ThreadingHTTPServer(('127.0.0.1', 0), cls)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        client = Client(server.server_port)
        try:
            assert client.login()[0] == 200
            path = prefix + '/ips?include_vt=1&vt_mode=background'
            assert client.call('GET', path, csrf=False)[0] == 403
            assert calls == []
            code, first = client.call('GET', path)
            assert code == 200 and first['enrichment']['pending'] == 1
            assert entered.wait(1)
            assert client.call('GET', prefix + '/results?aggregate=1')[0] == 200
            assert client.call('GET', path)[1]['enrichment']['pending'] == 1
            assert calls == ['8.8.8.8']
            release.set()
            until = time.monotonic() + 2
            while time.monotonic() < until:
                code, result = client.call('GET', path)
                if result['enrichment']['cached']:
                    break
                time.sleep(0.01)
            assert code == 200 and result['ips'][0]['vt']['asn'] == 15169
        finally:
            release.set()
            server.shutdown()
            server.server_close()
            thread.join(2)
