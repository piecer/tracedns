"""Prepared browser reads must not traverse mutable source state."""
import io
import json
import threading
import time
from unittest.mock import Mock, patch

import pytest

from http_api_handlers import attach_api_handlers


def request(model, current=None, history=None, enrichment=None):
    class Handler:
        def __init__(self):
            self.wfile = io.BytesIO()
            self.status = None
            self.response_headers = {}
        def send_response(self, status):
            self.status = status
        def send_header(self, *args):
            self.response_headers[args[0]] = args[1]
        def end_headers(self):
            pass
    return attach_api_handlers(
        Handler, frontend_html='', shared_config={}, config_lock=threading.RLock(),
        config_path='', history_dir='', current_results=current or {}, history=history or {},
        purge_removed_domains_state=lambda *args: None, read_model=model, background_enrichment=enrichment,
    )()


@pytest.mark.parametrize('method', ['_handle_results', '_handle_ips', '_handle_domain_analysis'])
def test_cold_background_read_is_explicit_and_does_not_claim_empty_success(method):
    model = Mock()
    model.read.return_value = (None, {'ready': False, 'status': 'building', 'stale': True})
    h = request(model)
    getattr(h, method)({'read_mode': ['background'], 'include_vt': ['0']})
    assert h.status == 202
    body = json.loads(h.wfile.getvalue())
    assert body['snapshot']['ready'] is False
    assert not any(key in body for key in ('ips', 'results_agg', 'domains'))


@pytest.mark.parametrize('method', ['_handle_results', '_handle_ips', '_handle_domain_analysis'])
def test_prepared_reads_only_consult_publication_not_source_or_global_lock(method):
    model = Mock()
    model.read.return_value = ({'results': {'results': {}, 'results_agg': {}, 'domain_meta': {}},
                               'ips': [], 'domains': []},
                              {'ready': True, 'stale': True, 'source_version': [1, 0]})
    h = request(model)
    with patch('http_api_handlers.get_state_version', side_effect=AssertionError('source lock on request')):
        getattr(h, method)({'read_mode': ['background'], 'include_vt': ['0']})
    assert h.status == 200
    assert json.loads(h.wfile.getvalue())['snapshot']['stale'] is True
    model.read.assert_called_once_with()


def test_successful_domain_mutation_fences_previous_publications():
    from http_api.config_post import handle_config_post
    from http_api.context import HttpContext
    model = Mock()
    config = {'domains': ['removed.test']}
    h = request(model)
    body = json.dumps({'domains': []}).encode()
    h.rfile = io.BytesIO(body)
    h.headers = {'Content-Length': str(len(body))}
    ctx = HttpContext('', config, threading.RLock(), '', '', {}, {}, lambda *args: None)
    ctx.read_model = model
    handle_config_post(ctx, h)
    assert h.status == 200
    assert model.invalidate.call_count >= 1
    assert all(call.kwargs == {'hard': True} for call in model.invalidate.call_args_list)


@pytest.mark.parametrize('kind,method', [('results', '_handle_results'), ('ips', '_handle_ips'), ('domains', '_handle_domain_analysis')])
def test_prepared_pages_are_bounded_and_unchanged_reads_omit_rows(kind, method):
    from http_api.read_source import build_read_views
    current = {f'{i:04}.test': {'r': {'type': 'A', 'values': ['8.8.8.8'], 'ts': 1}} for i in range(250)}
    data = build_read_views((current, {}, []))
    # Use distinct IP observations so the IP list also exceeds the row ceiling.
    data['ips'] = [{'ip': f'11.0.{i // 250}.{i % 250 + 1}', 'valid': True, 'last_ts': 1, 'count': 1, 'domains': []} for i in range(250)]
    model = Mock()
    model.read.return_value = (data, {'ready': True, 'stale': False, 'version': 1})
    qs = {'read_mode': ['background'], 'include_vt': ['0'], 'aggregate': ['1'], 'limit': ['99999']}
    h = request(model)
    getattr(h, method)(qs)
    first = json.loads(h.wfile.getvalue())
    assert first['page']['displayed'] <= 200
    assert first['page']['total'] == 250
    assert first['page']['next_offset'] == first['page']['displayed']
    qs['if_version'] = [first['view_version']]
    h = request(model)
    getattr(h, method)(qs)
    same = json.loads(h.wfile.getvalue())
    assert same['unchanged'] is True
    assert not any(key in same for key in ('ips', 'domains', 'results_agg'))
    qs['offset'] = [str(first['page']['next_offset'])]
    h = request(model)
    getattr(h, method)(qs)
    last = json.loads(h.wfile.getvalue())
    assert not last.get('unchanged')
    assert last['page']['next_offset'] is None
    assert first['page']['displayed'] + last['page']['displayed'] == 250


def test_exact_byte_budget_reduces_whole_units_before_enrichment_admission():
    from copy import deepcopy
    from http_api import prepared_reads
    rows = [{'ip': f'11.0.0.{i + 1}', 'valid': True, 'last_ts': 1, 'count': 1,
             'domains': ['x' * 12000]} for i in range(200)]
    data = {'ips': rows}
    before = deepcopy(data)
    model, enrichment = Mock(), Mock()
    model.read.return_value = (data, {'ready': True, 'version': 1})
    enrichment.request.return_value = ({}, {'status': 'pending'})
    h = request(model, enrichment=enrichment)
    with patch.object(prepared_reads, '_encode', wraps=prepared_reads._encode) as encodes:
        h._handle_ips({'read_mode': ['background'], 'limit': ['200'], 'include_vt': ['1']})
    assert h.status == 200
    body = h.wfile.getvalue()
    assert len(body) <= 1024 * 1024
    assert int(h.response_headers['Content-Length']) == len(body)
    page = json.loads(body)
    count = page['page']['displayed']
    assert 0 < count < 200
    assert page['page']['next_offset'] == count
    assert len(enrichment.request.call_args.args[0]) == count
    enrichment.request.assert_called_once()
    assert encodes.call_count <= 12, 'prefix selection must not encode each removed row'
    assert data == before


def test_irreducible_entry_fails_before_success_headers():
    model = Mock()
    model.read.return_value = ({'ips': [{'ip': '8.8.8.8', 'valid': True, 'last_ts': 1,
                                       'domains': ['x' * (2 * 1024 * 1024)]}]}, {'ready': True})
    h = request(model)
    h._handle_ips({'read_mode': ['background'], 'include_vt': ['0']})
    assert h.status == 422
    assert len(h.wfile.getvalue()) < 1024


def test_flattened_domain_pages_preserve_every_role_and_empty_domain():
    from http_api.read_source import build_read_views
    addresses = [f'11.0.0.{i + 1}' for i in range(220)]
    data = build_read_views(({'a.test': {'r': {'type': 'A', 'values': addresses, 'decoded_ips': addresses, 'ts': 1}}}, {}, ['empty.test']))
    model = Mock()
    model.read.return_value = (data, {'ready': True, 'version': 1})
    before = json.dumps(data, sort_keys=True)
    seen, offset, empty = [], 0, 0
    while offset is not None:
        h = request(model)
        h._handle_domain_analysis({'read_mode': ['background'], 'include_vt': ['0'], 'limit': ['37'], 'offset': [str(offset)]})
        body = json.loads(h.wfile.getvalue())
        assert body['page']['total'] == 441
        assert body['page']['displayed'] <= 37
        for row in body['domains']:
            if row['domain'] == 'empty.test':
                empty += 1
            else:
                assert row['ip_rows_total'] == 440
                assert row['resolving']
                assert len(row['resolved_ips']) + len(row['decoded_ips']) == len(row['ip_rows'])
            seen.extend((row['domain'], item['role'], item['ip']) for item in row['ip_rows'])
        offset = body['page']['next_offset']
    assert len(set(seen)) == len(seen) == 440
    assert empty == 1
    assert json.dumps(data, sort_keys=True) == before


def test_conditional_version_tracks_zero_threat_report_presence_and_redaction():
    data = {'ips': [{'ip': '8.8.8.8', 'valid': True, 'last_ts': 1, 'domains': []}]}
    model, enrichment = Mock(), Mock()
    model.read.return_value = (data, {'ready': True, 'version': 1})
    enrichment.request.return_value = ({}, {'status': 'pending'})
    qs = {'read_mode': ['background'], 'include_vt': ['1']}
    h = request(model, enrichment=enrichment)
    h._handle_ips(qs)
    first = json.loads(h.wfile.getvalue())
    qs['if_version'] = [first['view_version']]
    enrichment.request.return_value = ({'8.8.8.8': {'malicious': 0, 'asn': 15169}}, {'status': 'ready'})
    h = request(model, enrichment=enrichment)
    h._handle_ips(qs)
    second = json.loads(h.wfile.getvalue())
    assert not second.get('unchanged')
    assert second['ips'][0]['vt']['asn'] == 15169
    # A different sanitized representation must never reuse a previous token.
    qs['if_version'] = [second['view_version']]
    h = request(model, enrichment=enrichment)
    h.sanitize_response = lambda body, code: {**body, 'redaction_policy': 'different'}
    h._handle_ips(qs)
    assert not json.loads(h.wfile.getvalue()).get('unchanged')


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_real_http_cold_and_stale_publications_do_not_wait_for_builder(tmp_path, prefix):
    from http_api.read_source import build_read_views
    from http_server import ThreadingHTTPServer, make_handler
    from monitor.runtime_state import bump_state_version, state_lock
    from security.store import SecurityStore
    from tests.test_http_auth_integration import Client

    entered, release = threading.Event(), threading.Event()
    def blocked_build(inputs):
        entered.set()
        assert release.wait(5)
        return build_read_views(inputs)

    current = {'a.test': {'r': {'type': 'A', 'values': ['8.8.8.8'], 'ts': 1}}}
    store = SecurityStore(tmp_path / 'private' / 'auth.sqlite', create=True)
    store.bootstrap('root', 'test-password-123')
    with patch('http_api.read_source.build_read_views', side_effect=blocked_build):
        cls = make_handler({'domains': ['a.test']}, threading.RLock(), '', str(tmp_path),
                           current, {}, security_store=store, insecure_http=True)
        server = ThreadingHTTPServer(('127.0.0.1', 0), cls)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        client = Client(server.server_port)
        try:
            assert entered.wait(1), 'server must start the read builder'
            assert client.login()[0] == 200
            path = prefix + '/ips?read_mode=background&include_vt=0'
            assert client.call('GET', path)[0] == 202
            release.set()
            until = time.monotonic() + 2
            while time.monotonic() < until:
                code, result = client.call('GET', path)
                if code == 200:
                    break
                time.sleep(.01)
            assert code == 200 and result['ips'][0]['ip'] == '8.8.8.8'
            release.clear()
            entered.clear()
            with state_lock():
                current['a.test']['r']['values'] = ['1.1.1.1']
                bump_state_version()
            assert entered.wait(2)
            code, result = client.call('GET', path)
            assert code == 200 and result['ips'][0]['ip'] == '8.8.8.8'
            assert result['snapshot']['stale'] is True
        finally:
            release.set()
            server.shutdown()
            server.server_close()
            thread.join(2)
