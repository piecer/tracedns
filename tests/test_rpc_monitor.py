"""RPC ciphertext through the collector, managed IOC, history and delivery path."""
from unittest.mock import patch

from config_manager import domain_identity, domain_storage_name, normalize_domains
from models import DomainSpec, coerce_domains
from monitor.collect import collect_snapshot
from monitor.engine import run_domain_cycle, run_full_cycle
from rpc_query import PROFILE, PROVIDER, RpcQueryError
from test_rpc_query import encrypted_result

DOMAIN = {'name': 'Polygon config', 'type': 'RPC', 'rpc_profile': PROFILE}


def rpc_response(plaintext='192.0.2.10:18082\nj 192.0.2.10:18082\nr 203.0.113.1:443'):
    return {'jsonrpc': '2.0', 'id': 1, 'result': encrypted_result(plaintext)}


def test_config_identity_coercion_and_no_dns_provider():
    from monitor.targets import providers_for
    assert normalize_domains([DOMAIN]) == [DOMAIN]
    assert domain_identity(DOMAIN) == 'polygon config|RPC|' + PROFILE
    assert domain_storage_name(DOMAIN) == 'Polygon config [RPC:' + PROFILE + ']'
    spec = coerce_domains(normalize_domains([DOMAIN]))[0]
    assert spec.rpc_profile == PROFILE
    assert providers_for(spec, ['8.8.8.8']) == (PROVIDER,)
    assert domain_identity(DOMAIN) != domain_identity({**DOMAIN, 'type': 'A'})


def test_collector_uses_authenticated_c2_not_provider_or_auxiliary_ips():
    with patch('rpc_query._post_rpc', return_value=rpc_response()) as request, \
         patch('monitor.collect.query_dns', side_effect=AssertionError('RPC is not DNS')):
        result = collect_snapshot(DomainSpec(**DOMAIN), PROVIDER)
    assert request.call_count == 1
    assert result.query.status == 'ok'
    assert result.snapshot.managed_ips() == {'192.0.2.10'}
    assert result.snapshot.decoded_endpoints == ['192.0.2.10:18082']
    assert result.snapshot.rpc_record['roles']['relay'] == ['203.0.113.1:443']
    assert result.snapshot.values == [rpc_response()['result']]


def test_monitor_rotations_survive_history_restart_and_result_projection(tmp_path):
    from dns_monitor import restore_current_results
    from history_manager import load_history_files
    from http_api.basic_handlers import _build_results_payload
    current, history = {}, {}
    name = domain_storage_name(DOMAIN)
    for port in (18082, 443):
        with patch('rpc_query._post_rpc', return_value=rpc_response(f'192.0.2.10:{port}')):
            run_domain_cycle(domain=DomainSpec(**DOMAIN), servers=[PROVIDER],
                             current_results=current, history=history, history_dir=str(tmp_path),
                             query_fail_counts={}, max_workers=1)
    event = history[name]['events'][-1]
    assert event['old']['decoded_endpoints'] == ['192.0.2.10:18082']
    assert event['new']['decoded_endpoints'] == ['192.0.2.10:443']
    assert event['new']['rpc_profile'] == PROFILE
    loaded = load_history_files(str(tmp_path))
    restored = restore_current_results(loaded)
    assert restored[name][PROVIDER]['rpc_record']['plaintext'] == '192.0.2.10:443'
    payload = _build_results_payload(restored, {}, include_raw=True)
    assert payload['results'][name][PROVIDER]['rpc_profile'] == PROFILE
    assert payload['results_agg'][name]['decoded_ips'] == ['192.0.2.10']
    assert payload['results_agg'][name]['decoded_endpoints'] == ['192.0.2.10:443']
    assert payload['results_agg'][name]['rpc_record']['authentication'] == 'aes-128-gcm'
    assert 'Polygon' in payload['results_agg'][name]['method_summary']


def test_full_cycle_uses_one_logical_provider_and_existing_alert_path(tmp_path):
    current, history = {}, {}
    name = domain_storage_name(DOMAIN)
    with patch('rpc_query._post_rpc', return_value=rpc_response()) as request, \
         patch('monitor.engine.alert_new_ips') as alert, \
         patch('monitor.collect.query_dns', side_effect=AssertionError('not DNS')):
        result = run_full_cycle(domains_raw=[DOMAIN], servers=['8.8.8.8', '1.1.1.1'],
                                current_results=current, history=history, history_dir=str(tmp_path),
                                query_fail_counts={})
    assert request.call_count == 1
    assert result == {'192.0.2.10': {name}}
    assert result.complete is True
    assert alert.call_args.args[0] == [('192.0.2.10', name, 'RPC')]


def test_repeated_auth_failures_keep_last_good_and_mark_failed(tmp_path):
    from test_stage3_core_runtime import app_factory, rows
    from monitor.engine import reconcile_scan
    app = app_factory(tmp_path, config={'domains': [DOMAIN], 'servers': [],
        'alerts': {'teams_webhook': 'https://teams.invalid/hook'}, 'config_revision': 0})
    name = domain_storage_name(DOMAIN)
    try:
        for index in range(5):
            snapshot = app.cfg.snapshot()
            response = rpc_response() if index == 0 else {'jsonrpc': '2.0', 'id': 1, 'result': '0x'}
            with patch('rpc_query._post_rpc', return_value=response), \
                 patch('monitor.engine.alert_new_ips', side_effect=AssertionError('no legacy delivery')):
                result = run_full_cycle(domains_raw=snapshot.domains, servers=snapshot.servers,
                    current_results=app.current, history=app.history, history_dir=app.repo.history_dir,
                    query_fail_counts={}, state_repository=app.repo, target_leases=snapshot.target_leases)
            accepted, _ = reconcile_scan(app.cfg, snapshot, {}, result, None)
            assert accepted is True
            assert result.complete is (index == 0)
            assert app.current[name][PROVIDER]['decoded_ips'] == ['192.0.2.10']
        attempt = app.history[name]['meta']['rpc_observation']
        assert attempt['status'] == 'error'
        assert attempt['reason'] == 'rpc_invalid_abi'
        from http_api.basic_handlers import _build_results_payload
        projected = _build_results_payload(app.current, {name: app.history[name]['meta']}, include_raw=False)
        assert projected['domain_meta'][name]['rpc_observation'] == attempt
        assert len(rows(app, 'receipt')) == 1
        assert rows(app, 'receipt')[0]['action'] == 'Added'
        assert rows(app, 'grace') == []
    finally:
        app.delivery.stop()


def test_invalid_rpc_auth_is_query_error_not_empty_success():
    with patch('rpc_query._post_rpc', side_effect=RpcQueryError('rpc_auth_failed')):
        result = collect_snapshot(DomainSpec(**DOMAIN), PROVIDER)
    assert result.query.status == 'error'
    assert result.query.error == 'rpc_auth_failed'
    assert result.snapshot is None


def test_rpc_history_ips_keep_type_and_profile_provenance():
    from http_api.read_views import build_ip_rows
    name = domain_storage_name(DOMAIN)
    history = {name: {'events': [{'type': 'RPC', 'ts': 123,
        'old': {'decoded_ips': ['192.0.2.1'], 'rpc_profile': PROFILE},
        'new': {'decoded_ips': ['192.0.2.2'], 'rpc_profile': PROFILE}}]}}
    rows = build_ip_rows({}, history)
    assert {row['ip'] for row in rows} == {'192.0.2.1', '192.0.2.2'}
    assert all(row['record_types'] == ['RPC'] and row['decoders'] == ['RPC:' + PROFILE] for row in rows)


def test_direct_default_profile_identity_matches_normalized_target():
    from monitor.engine import _domain_storage_name
    from monitor.repository import normalized_domain_specs
    spec = DomainSpec(name=DOMAIN['name'], type='RPC')
    assert _domain_storage_name(spec) == domain_storage_name(DOMAIN)
    assert normalized_domain_specs([spec])[0].rpc_profile == PROFILE


def test_rpc_openapi_describes_fixed_read_only_profile():
    from http_api.openapi import openapi_document
    doc = openapi_document()
    assert doc['components']['schemas']['Domain']['properties']['rpc_profile']['enum'] == [PROFILE]
    schema = doc['paths']['/domain-precheck']['post']['requestBody']['content']['application/json']['schema']
    assert 'RPC' in schema['properties']['type']['enum']


def test_rpc_teams_and_misp_accept_original_source_type():
    import alerts
    from test_delivery_adapters_steps import Response, Transport, setup, event, attribute
    entries = [('192.0.2.10', domain_storage_name(DOMAIN), 'RPC')]
    assert alerts._normalize_ip_tuples(entries) == entries
    for channel in ('teams', 'misp'):
        transport = Transport(Response(status=200)) if channel == 'teams' else Transport(
            Response(event()), Response({'Attribute': attribute(ip='192.0.2.10')}))
        adapter, claim = setup(transport, channel)
        claim['payload']['entries'] = entries
        result = adapter.execute_step(claim)
        if channel == 'misp':
            assert result['state'] == 'continue'
            claim['progress'] = result['progress']
            result = adapter.execute_step(claim)
        assert result['state'] == 'acked'
