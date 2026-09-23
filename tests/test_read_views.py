"""Pure read projections preserve the legacy observation and history contract."""
import importlib.util
import io
import json
import threading

from http_api_handlers import attach_api_handlers


def test_pure_read_views_match_legacy_source_semantics():
    assert importlib.util.find_spec('http_api.read_views') is not None, 'pure read builders missing'
    from http_api.read_views import build_domain_rows, build_ip_rows
    current = {'a.test': {'r': {'type': 'A', 'values': ['8.8.8.8'], 'decoded_ips': ['8.8.8.8'], 'ts': 7}},
               'b.test': {'r': {'type': 'TXT', 'values': ['raw'], 'decoded_ips': ['1.1.1.1'],
                                'txt_decode': 'custom', 'ts': 8}}}
    history = {'a.test': {'meta': {'nxdomain_active': True, 'nxdomain_since': 9}, 'events': [
        {'type': 'A', 'ts': 5, 'old': {'values': ['8.8.8.8']}, 'new': {'values': ['8.8.8.8']}},
        {'type': 'A', 'ts': 4, 'values': ['9.9.9.9']},
    ]}}
    config = {'domains': ['a.test', 'configured-only.test']}

    class Handler:
        def __init__(self):
            self.wfile = io.BytesIO()
        def send_response(self, status):
            assert status == 200
        def send_header(self, *args):
            pass
        def end_headers(self):
            pass

    attach_api_handlers(Handler, frontend_html='', shared_config=config, config_lock=threading.RLock(),
                        config_path='', history_dir='', current_results=current, history=history,
                        purge_removed_domains_state=lambda *args: None)
    h = Handler()
    expected_ips = h._gather_ip_rows()
    h._handle_domain_analysis({'include_vt': ['0']})
    expected_domains = json.loads(h.wfile.getvalue())['domains']
    actual_ips = build_ip_rows(current, history)
    assert actual_ips == expected_ips
    assert next(row for row in actual_ips if row['ip'] == '8.8.8.8')['count'] == 4
    assert build_domain_rows(current, {d: entry['meta'] for d, entry in history.items()}, config['domains']) == expected_domains


def test_source_capture_rebuilds_config_only_changes_and_keeps_owned_inputs():
    assert importlib.util.find_spec('http_api.read_source') is not None
    from http_api.read_source import capture_read_inputs, build_read_views
    config = {'domains': ['only.test'], '_config_revision': 0}
    lock = threading.RLock()
    current = {'a.test': {'r': {'type': 'A', 'values': ['8.8.8.8'], 'ts': 1}}}
    token, inputs = capture_read_inputs(config, lock, current, {}, None)
    assert capture_read_inputs(config, lock, current, {}, token) is None
    config['domains'].append('new.test')
    config['_config_revision'] += 1
    updated, inputs2 = capture_read_inputs(config, lock, current, {}, token)
    assert updated != token
    assert [row['domain'] for row in build_read_views(inputs)['domains']] == ['a.test', 'only.test']
    assert [row['domain'] for row in build_read_views(inputs2)['domains']] == ['a.test', 'new.test', 'only.test']
