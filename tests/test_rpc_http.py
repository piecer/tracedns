"""Authenticated legacy/v1 RPC registration/precheck; no live services."""
import json
from unittest.mock import patch

import pytest

from test_http_auth_integration import app as http_app
from test_rpc_monitor import DOMAIN, rpc_response
from rpc_query import PROFILE

app = http_app


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_rpc_config_force_roundtrip_and_invalid_profile_no_effect(app, tmp_path, prefix):
    _, client, config = app
    assert client.login()[0] == 200
    service = config['_config_service']
    service.config_path = str(tmp_path / 'rpc-config.json')
    before = client.call('GET', prefix + '/config')[1]
    with patch('rpc_query._post_rpc', side_effect=AssertionError('registration is offline')):
        code, saved = client.call('POST', prefix + '/config', {
            'revision': before['revision'], 'domains': [DOMAIN], 'servers': []})
        assert code == 200, saved
        persisted = json.loads((tmp_path / 'rpc-config.json').read_text())
        assert persisted['domains'] == [DOMAIN]
        code, loaded = client.call('GET', prefix + '/config')
        assert loaded['domains'] == [DOMAIN]
        for bad in [{**DOMAIN, 'rpc_profile': PROFILE + ' '}, {**DOMAIN, 'rpc_profile': None},
                    {**DOMAIN, 'rpc_profile': {}}, {**DOMAIN, 'name': ''},
                    {**DOMAIN, 'name': '한' * 100}, {**DOMAIN, 'rpc_url': 'http://127.0.0.1/'}]:
            code, result = client.call('POST', prefix + '/config', {
                'revision': loaded['revision'], 'domains': [bad]})
            assert code == 400, result
            assert json.loads((tmp_path / 'rpc-config.json').read_text()) == persisted
        code, queued = client.call('POST', prefix + '/resolve', {'domains': [DOMAIN], 'servers': []})
        assert code == 200 and queued['requested'] is True
        queue = len(config['_force_resolve_queue'])
        code, _ = client.call('POST', prefix + '/resolve', {
            'domains': [{**DOMAIN, 'rpc_profile': PROFILE + ' '}], 'servers': []})
        assert code == 400
        assert len(config['_force_resolve_queue']) == queue


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_rpc_precheck_authenticates_without_dns_or_enrichment(app, prefix):
    _, client, config = app
    assert client.login()[0] == 200
    with patch('rpc_query._post_rpc', return_value=rpc_response()) as fetch, \
         patch('http_api_handlers.query_dns', side_effect=AssertionError('not DNS')):
        code, result = client.call('POST', prefix + '/domain-precheck', {
            **DOMAIN, 'domain': DOMAIN['name'], 'include_vt': True})
    assert code == 200, result
    assert fetch.call_count == 1
    assert result['managed_ips'] == ['192.0.2.10']
    assert result['decoded_endpoints'] == ['192.0.2.10:18082']
    assert result['resolved_ips'] == []
    assert result['rpc_record']['roles']['relay'] == ['203.0.113.1:443']
    assert result['domain_object'] == DOMAIN
    assert result['include_vt'] is False
    assert result['can_add'] is True
    assert config['domains'] == []


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_rpc_precheck_failure_is_not_verified_empty_success(app, prefix):
    _, client, _ = app
    assert client.login()[0] == 200
    with patch('rpc_query._post_rpc', return_value={'jsonrpc': '2.0', 'id': 1, 'result': '0x'}):
        code, result = client.call('POST', prefix + '/domain-precheck', {**DOMAIN, 'domain': DOMAIN['name']})
    assert code == 200, result
    assert result['can_add'] is True
    assert result['managed_ips'] == []
    assert result['rpc_record'] is None
    assert result['by_server'][0]['status'] == 'error'
    assert result['by_server'][0]['error'] == 'rpc_invalid_abi'


def test_invalid_startup_profile_fails_closed():
    import threading
    from monitor.config_service import ConfigService, ConfigError
    cfg = {'domains': [{**DOMAIN, 'rpc_profile': 'unknown'}]}
    service = ConfigService(cfg, threading.RLock(), '')
    with pytest.raises(ConfigError, match='rpc_invalid_profile'):
        service.initialize_decoders()
