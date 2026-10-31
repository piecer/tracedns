"""Authenticated legacy/v1 DHT contracts; only signed synthetic lookup fixtures."""
import json
from unittest.mock import patch

import pytest

from test_http_auth_integration import app as http_app
from test_dht_monitor import observation, target

app = http_app


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_dht_config_roundtrip_force_admission_and_invalid_request_no_effect(app, tmp_path, prefix):
    _, client, config = app
    assert client.login()[0] == 200
    service = config['_config_service']
    service.config_path = str(tmp_path / 'dht-config.json')
    _, key = observation()
    domain = target(key)
    with patch('dht_query.fetch_dht_records', side_effect=AssertionError('config must not query')):
        before = client.call('GET', prefix + '/config')[1]
        code, result = client.call('POST', prefix + '/config', {
            'revision': before['revision'], 'domains': [domain], 'servers': []})
        assert code == 200, result
        persisted = json.loads((tmp_path / 'dht-config.json').read_text())
        assert persisted['domains'] == [domain]
        code, loaded = client.call('GET', prefix + '/config')
        assert code == 200 and loaded['domains'] == [domain]
        for bad in [{**domain, 'dht_public_key': ' ' + key},
                    {**domain, 'dht_options': {'bootstraps': ['127.0.0.1:6881']}},
                    {**domain, 'dht_options': {'duration': 61}},
                    {**domain, 'name': ''}, {**domain, 'name': '한' * 100}]:
            code, invalid = client.call('POST', prefix + '/config', {
                'revision': loaded['revision'], 'domains': [bad]})
            assert code == 400, invalid
            assert json.loads((tmp_path / 'dht-config.json').read_text()) == persisted
        code, queued = client.call('POST', prefix + '/resolve', {'domains': [domain], 'servers': []})
        assert code == 200 and queued['requested'] is True
        queue_length = len(config['_force_resolve_queue'])
        code, invalid = client.call('POST', prefix + '/resolve', {
            'domains': [{**domain, 'dht_public_key': key + '\n'}], 'servers': []})
        assert code == 400, invalid
        assert len(config['_force_resolve_queue']) == queue_length


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_dht_precheck_verifies_signed_payload_without_dns_or_enrichment(app, prefix):
    _, client, config = app
    assert client.login()[0] == 200
    obs, key = observation(2**53 + 1)
    domain = target(key)
    with patch('dht_query.fetch_dht_records', return_value=obs) as fetch, \
         patch('http_api_handlers.query_dns', side_effect=AssertionError('not DNS')), \
         patch('http_api_handlers.report_for', side_effect=AssertionError('no external enrichment'), create=True):
        code, result = client.call('POST', prefix + '/domain-precheck', {
            **domain, 'domain': domain['name'], 'include_vt': True})
    assert code == 200, result
    assert fetch.call_count == 1
    assert result['managed_ips'] == ['192.0.2.123']
    assert result['dht_record']['seq'] == str(2**53 + 1)
    assert result['dht_record']['signature_valid'] is True
    assert result['dht_observation']['status'] == 'initial'
    assert result['domain_object'] == domain
    assert result['include_vt'] is False
    assert config['domains'] == []  # precheck never registers implicitly


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_dht_precheck_miss_is_registerable_not_verified(app, prefix):
    _, client, _ = app
    assert client.login()[0] == 200
    _, key = observation()
    domain = target(key)
    with patch('dht_query.fetch_dht_records', return_value={'records': [], 'coverage': {}}):
        code, result = client.call('POST', prefix + '/domain-precheck', {**domain, 'domain': domain['name']})
    assert code == 200, result
    assert result['can_add'] is True
    assert result['managed_ips'] == []
    assert result['dht_observation']['status'] == 'no_verified_record'
    assert result['by_server'][0]['status'] == 'error'


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_invalid_precheck_never_starts_dht_lookup(app, prefix):
    _, client, _ = app
    assert client.login()[0] == 200
    _, key = observation()
    with patch('dht_query.fetch_dht_records') as fetch:
        code, _ = client.call('POST', prefix + '/domain-precheck', {
            'domain': 'invalid', 'type': 'DHT', 'dht_public_key': key + ' ',
            'dht_options': {'duration': float('nan')}})
    assert code == 400
    fetch.assert_not_called()
