"""Real decoder through collector and authenticated legacy/v1 HTTP adapters."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from models import DomainSpec
from monitor.collect import collect_snapshot
from test_http_auth_integration import app as http_app
from test_ens_sha256_hmac_xor import synthetic_record

app = http_app
CORPUS = json.loads((Path(__file__).resolve().parents[1] / 'docs/ens/sha256-hmac-xor-decoder.json').read_text())
DOMAIN = {
    'name': CORPUS['ens_name'], 'type': 'ENS', 'ens_text_key': CORPUS['text_key'],
    'ens_decode': CORPUS['runtime_method_name'], 'ens_options': CORPUS['decoder_options'],
}


def test_collector_keeps_authenticated_endpoint_and_raw_record():
    with patch('monitor.collect.fetch_ens_text_record', return_value=CORPUS['raw_record']) as fetch:
        collected = collect_snapshot(DomainSpec(**DOMAIN), 'https://rpc.example')
    fetch.assert_called_once_with('https://rpc.example', DOMAIN['name'], 'name', ens_node=None, resolver_address=None)
    assert collected.query.status == 'ok'
    snapshot = collected.snapshot
    assert snapshot is not None
    assert snapshot.values == [CORPUS['raw_record']]
    assert snapshot.managed_ips() == {CORPUS['decoded_ipv4']}
    assert snapshot.decoded_endpoints == [CORPUS['decoded_endpoint']]


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_authenticated_precheck_keeps_endpoint(app, prefix):
    _, client, _ = app
    assert client.login()[0] == 200
    request = {**DOMAIN, 'domain': DOMAIN['name'], 'ens_rpc_url': 'https://rpc.example', 'include_vt': False}
    with patch('http_api_handlers.fetch_ens_text_record', return_value=CORPUS['raw_record']) as fetch:
        code, result = client.call('POST', prefix + '/domain-precheck', request)
    assert code == 200, result
    fetch.assert_called_once_with('https://rpc.example', DOMAIN['name'], 'name', ens_node=None, resolver_address=None)
    assert result['managed_ips'] == [CORPUS['decoded_ipv4']]
    assert result['decoded_endpoints'] == [CORPUS['decoded_endpoint']]
    assert result['by_server'][0]['values'] == [CORPUS['raw_record']]
    assert result['by_server'][0]['decoded_endpoints'] == [CORPUS['decoded_endpoint']]


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_builtin_catalog_and_config_roundtrip_expose_decoder_options(app, tmp_path, prefix):
    _, client, config = app
    assert client.login()[0] == 200
    config['_config_service'].config_path = str(tmp_path / 'configured.json')
    code, catalog = client.call('GET', prefix + '/decoders')
    assert code == 200
    assert DOMAIN['ens_decode'] in catalog['ens_decoders']
    code, saved = client.call('POST', prefix + '/config', {'revision': catalog['revision'], 'domains': [DOMAIN]})
    assert code == 200, saved
    code, restored = client.call('GET', prefix + '/config')
    assert code == 200
    assert restored['domains'][0]['ens_decode'] == DOMAIN['ens_decode']
    assert restored['domains'][0]['ens_options'] == DOMAIN['ens_options']
    assert restored['domains'][0]['ens_text_key'] == 'name'
    persisted = json.loads((tmp_path / 'configured.json').read_text())
    assert persisted['domains'][0]['ens_options'] == DOMAIN['ens_options']


def test_monitor_history_restart_and_results_keep_ip_port_rotation(tmp_path):
    from config_manager import domain_storage_name
    from dns_monitor import restore_current_results
    from history_manager import load_history_files
    from http_api.basic_handlers import _build_results_payload
    from monitor.engine import run_domain_cycle

    current, history = {}, {}
    server = 'https://rpc.example'
    key = domain_storage_name(DOMAIN)
    replacement = synthetic_record(CORPUS['decoded_ipv4'] + ':8443')
    for record in [CORPUS['raw_record'], replacement]:
        with patch('monitor.collect.fetch_ens_text_record', return_value=record):
            run_domain_cycle(domain=DomainSpec(**DOMAIN), servers=[server], current_results=current,
                             history=history, history_dir=str(tmp_path), query_fail_counts={}, max_workers=1)
    event = history[key]['events'][-1]
    assert event['old']['decoded_endpoints'] == [CORPUS['decoded_endpoint']]
    assert event['new']['decoded_endpoints'] == [CORPUS['decoded_ipv4'] + ':8443']
    assert event['old']['decoded_ips'] == event['new']['decoded_ips'] == [CORPUS['decoded_ipv4']]
    persisted = load_history_files(str(tmp_path))
    assert persisted[key]['current'][server]['values'] == [replacement]
    restored = restore_current_results(persisted)
    assert restored[key][server]['ens_options'] == CORPUS['decoder_options']
    payload = _build_results_payload(restored, persisted, include_raw=True)
    assert payload['results'][key][server]['decoded_endpoints'] == [CORPUS['decoded_ipv4'] + ':8443']
    assert payload['results_agg'][key]['decoded_endpoints'] == [CORPUS['decoded_ipv4'] + ':8443']


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_failed_auth_keeps_raw_record_without_promoting_outer_ips_or_ports(app, prefix):
    _, client, _ = app
    assert client.login()[0] == 200
    record = CORPUS['raw_record'][:-2] + '00' + ' 198.51.100.99 "]:80'
    with patch('monitor.collect.fetch_ens_text_record', return_value=record):
        collected = collect_snapshot(DomainSpec(**DOMAIN), 'https://rpc.example')
    assert collected.snapshot is not None
    assert collected.snapshot.values == [record]
    assert collected.snapshot.managed_ips() == set()
    assert collected.snapshot.decoded_endpoints == []
    request = {**DOMAIN, 'domain': DOMAIN['name'], 'ens_rpc_url': 'https://rpc.example', 'include_vt': False}
    with patch('http_api_handlers.fetch_ens_text_record', return_value=record):
        code, result = client.call('POST', prefix + '/domain-precheck', request)
    assert code == 200
    assert result['managed_ips'] == []
    assert result['decoded_endpoints'] == []
    assert result['by_server'][0]['values'] == [record]
