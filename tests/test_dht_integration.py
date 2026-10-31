"""DHT target identity and managed snapshot integration, without network access."""
from config_manager import domain_identity, domain_storage_name, normalize_domains
from models import Snapshot, coerce_domains
from monitor.runtime_state import clone_snapshot
from monitor.state_utils import collect_active_ip_map, collect_domain_managed_ips
from monitor.targets import active_target_projection, providers_for

KEY = '15' * 32
TARGET = {'name': 'tracked-dht', 'type': 'DHT', 'dht_public_key': KEY,
          'dht_options': {'duration': 10, 'max_queries': 16}}


def test_dht_normalization_identity_and_provider_do_not_depend_on_dns():
    changed_key = {**TARGET, 'dht_public_key': '16' * 32}
    normalized = normalize_domains([TARGET, changed_key])
    assert normalized == [TARGET, changed_key]
    assert domain_identity(TARGET) == 'tracked-dht|DHT|' + KEY
    assert domain_storage_name(TARGET) == 'tracked-dht [DHT:' + KEY + ']'
    specs = coerce_domains(normalized)
    assert len(specs) == 2
    assert specs[0].dht_public_key == KEY
    assert specs[0].dht_options == TARGET['dht_options']
    assert providers_for(specs[0], ['1.1.1.1', '8.8.8.8']) == ('DHT',)
    assert providers_for(specs[0], []) == ('DHT',)
    assert active_target_projection(normalized, []) == {
        domain_storage_name(item): frozenset({'DHT'}) for item in normalized}


def test_dht_snapshot_roundtrip_clone_and_managed_ip_projection():
    record = {'seq': '9223372036854775807', 'ips': ['192.0.2.15'],
              'signature_valid': True, 'value_hex': '0102'}
    raw = {'type': 'DHT', 'values': ['0102'], 'decoded_ips': ['192.0.2.15'],
           'ts': 100, 'dht_public_key': KEY, 'dht_options': {'duration': 10},
           'dht_record': record}
    snapshot = Snapshot.from_legacy(raw)
    assert snapshot.managed_ips() == {'192.0.2.15'}
    serialized = snapshot.to_dict()
    assert serialized['dht_record']['seq'] == '9223372036854775807'
    assert serialized['dht_public_key'] == KEY
    cloned = clone_snapshot(serialized)
    cloned['dht_record']['ips'].append('198.51.100.99')
    assert serialized['dht_record']['ips'] == ['192.0.2.15']
    name = domain_storage_name(TARGET)
    state = {name: {'DHT': serialized}}
    assert collect_domain_managed_ips(state, name, rtype='DHT') == {'192.0.2.15'}
    assert collect_active_ip_map(state) == {'192.0.2.15': {name}}


def test_results_history_meta_and_ip_rows_keep_dht_provenance():
    from http_api.basic_handlers import _build_results_payload
    from http_api.read_views import build_ip_rows
    from monitor.runtime_state import clone_history_entry, clone_history_meta
    name = domain_storage_name(TARGET)
    record = {'seq': '9223372036854775807', 'target': 'ab' * 20, 'signature_valid': True}
    snapshot = {'type': 'DHT', 'values': ['abcd'], 'decoded_ips': ['192.0.2.15'],
                'ts': 100, 'dht_public_key': KEY, 'dht_record': record}
    meta = {'dht_state': {'highest_seq': record['seq'], 'variants': [record]},
            'dht_observation': {'status': 'no_verified_record', 'observed_at': 101,
                                'coverage': {'globally_complete': False}}}
    history = {name: {'meta': meta, 'current': {'DHT': snapshot}, 'events': [
        {'type': 'DHT', 'ts': 100, 'old': {'decoded_ips': ['192.0.2.14']},
         'new': {'decoded_ips': ['192.0.2.15']}}]}}
    cloned = clone_history_entry(history[name])
    cloned['meta']['dht_state']['variants'][0]['seq'] = '1'
    assert record['seq'] == '9223372036854775807'
    metadata = clone_history_meta(history)
    result = _build_results_payload({name: {'DHT': snapshot}}, metadata, include_raw=True)
    assert result['results'][name]['DHT']['dht_record'] == record
    assert result['results_agg'][name]['dht_public_keys'] == [KEY]
    assert result['results_agg'][name]['dht_sequences'] == ['9223372036854775807']
    assert result['domain_meta'][name]['dht_observation']['status'] == 'no_verified_record'
    assert {r['ip'] for r in build_ip_rows({}, history)} == {'192.0.2.14', '192.0.2.15'}


def test_dht_delivery_type_reaches_existing_teams_and_misp_adapters():
    from alerts import _normalize_ip_tuples, _build_alert_body
    from test_delivery_adapters_steps import Response, Transport, setup, event
    entries = [('1.2.3.4', 'target', 'DHT')]
    assert _normalize_ip_tuples(entries) == entries
    assert 'DHT:1' in _build_alert_body('Added', entries)
    for channel, response in [('teams', Response()), ('misp', Response(event()))]:
        adapter, claim = setup(Transport(response), channel)
        claim['payload']['entries'] = entries
        result = adapter.execute_step(claim)
        assert result['state'] != 'failed', result
        assert result['provider_calls'] == 1


def test_engine_storage_key_and_signed_sequence_changes_survive_history():
    from monitor.engine import _domain_storage_name, _snapshot_changed, _history_snapshot
    from models import SnapshotChange
    spec = coerce_domains([TARGET])[0]
    assert _domain_storage_name(spec) == domain_storage_name(TARGET)
    old = {'type': 'DHT', 'values': ['abcd'], 'decoded_ips': ['192.0.2.15'],
           'dht_public_key': KEY, 'dht_record': {'seq': '1', 'value_hex': 'abcd'}}
    new = Snapshot.from_legacy({**old, 'dht_record': {'seq': '2', 'value_hex': 'abcd'}})
    assert _snapshot_changed(old, new)
    assert _history_snapshot(new)['dht_record']['seq'] == '2'
    assert SnapshotChange('dht', 'DHT', 'DHT', Snapshot.from_legacy(old), new, 1).is_changed()


def test_openapi_describes_public_key_and_read_only_dht_options():
    from http_api.openapi import openapi_document
    document = openapi_document()
    schema = document['paths']['/domain-precheck']['post']['requestBody']['content']['application/json']['schema']
    assert 'DHT' in schema['properties']['type']['enum']
    target = document['components']['schemas']['Domain']
    assert target['properties']['dht_public_key']['pattern'] == '^[0-9A-Fa-f]{64}$'
    options = target['properties']['dht_options']
    assert options['additionalProperties'] is False
    assert options['properties']['max_queries']['maximum'] == 128
    assert options['properties']['duration']['maximum'] == 60


def test_never_confirmed_dht_targets_are_typed_and_paginated_with_metadata():
    from http_api.read_source import build_read_views
    from http_api.prepared_reads import _project_page
    second = {**TARGET, 'name': 'other'}
    history = {domain_storage_name(d): {'meta': {
        'dht_state': {'public_key': KEY},
        'dht_observation': {'status': 'no_verified_record', 'observed_at': 100}},
        'current': {}, 'events': []} for d in [TARGET, second]}
    data = build_read_views(({}, history, [TARGET, second]))
    assert len(data['result_keys']) == 2
    for entry in data['results']['results_agg'].values():
        assert entry['type'] == 'DHT'
        assert entry['dht_public_keys'] == [KEY]
        assert entry['decoded_ips'] == []
    first = _project_page(data, {}, 'results', {}, 0, 1)
    assert first['page']['total'] == 2 and first['page']['next_offset'] == 1
    assert set(first['domain_meta']) == set(first['results_agg'])
    assert len(first['domain_meta']) == 1
