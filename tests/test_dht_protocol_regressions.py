"""Offline regressions from independent protocol review; no public endpoints."""
import copy
import ipaddress
import json
import socket
import struct
import threading
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import dht_query as d
from config_manager import validate_dht_domain
from models import DomainSpec
from monitor.collect import collect_snapshot
from test_http_auth_integration import app as http_app

app = http_app


@pytest.fixture(autouse=True)
def loopback_only(monkeypatch):
    original_connect = socket.socket.connect
    original_sendto = socket.socket.sendto
    original_resolve = socket.getaddrinfo

    def allowed(address):
        if isinstance(address, tuple):
            assert ipaddress.ip_address(address[0]).is_loopback, address

    def connect(sock, address):
        allowed(address)
        return original_connect(sock, address)

    def sendto(sock, data, *args):
        allowed(args[-1])
        return original_sendto(sock, data, *args)

    def resolve(host, *args, **kwargs):
        assert host in ('localhost', '127.0.0.1', '::1'), host
        return original_resolve(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, 'connect', connect)
    monkeypatch.setattr(socket.socket, 'sendto', sendto)
    monkeypatch.setattr(socket, 'getaddrinfo', resolve)


def dns_value(ip='192.0.2.123'):
    return (struct.pack('!6H', 0, 0, 0, 1, 0, 0) + b'\0' +
            struct.pack('!HHIH', 1, 1, 300, 4) + ipaddress.IPv4Address(ip).packed)


def evidence(seq=7, value=None):
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    value = dns_value() if value is None else value
    # Independent formatter from the reviewer, not the product's serializer.
    transcript = b'3:seqi%d e1:v%d:' % (seq, len(value))
    transcript = transcript.replace(b' e1:', b'e1:') + value
    return {b'k': public, b'seq': seq, b'v': value, b'sig': private.sign(transcript)}, public


def serialized(raw):
    return {'public_key': raw[b'k'].hex(), 'seq': str(raw[b'seq']),
            'signature': raw[b'sig'].hex(), 'value_hex': raw[b'v'].hex()}


def obs(seq=7, value=None):
    raw, public = evidence(seq, value)
    return {'records': [serialized(raw)], 'coverage': {}}, public.hex()


def target(key):
    return {'name': 'independent review', 'type': 'DHT', 'dht_public_key': key,
            'dht_options': {'duration': .05, 'max_queries': 1}}


def test_identity_key_forgery_must_not_be_verified():
    # Preserve the reviewer's exact schedule: register the shape-valid identity
    # key and reconcile two distinct messages signed with R=identity, S=0.
    public = b'\x01' + bytes(31)
    signature = public + bytes(32)
    results = []
    for seq, value in [(1, dns_value()), (2**63 - 1, dns_value('198.51.100.9'))]:
        raw = {b'k': public, b'seq': seq, b'v': value, b'sig': signature}
        validate_dht_domain(target(public.hex()))
        outcome = d.reconcile_dht(None, {'records': [serialized(raw)]}, public.hex())
        results.append(outcome)
    assert all(r['record'] is None and r['state']['highest_seq'] is None for r in results)


@pytest.mark.parametrize('seq,value', [(1, dns_value()), (2**63 - 1, dns_value('198.51.100.9'))])
def test_weak_key_rejected_on_wire_reverify_and_persisted_evidence(seq, value):
    public = b'\x01' + bytes(31)
    raw = {b'k': public, b'seq': seq, b'v': value, b'sig': public + bytes(32)}
    record = serialized(raw)
    with pytest.raises(ValueError):
        d._verify_record(raw, public)
    with pytest.raises(ValueError):
        d._reverify(record, public)
    previous = {'version': 1, 'public_key': public.hex(), 'highest_seq': str(seq),
                'variants': [record], 'conflict': False, 'conflict_count': 0, 'last_confirmed': record}
    with pytest.raises(d.DHTQueryError) as error:
        d.reconcile_dht(json.loads(json.dumps(previous)), {'records': []}, public.hex())
    assert error.value.code == 'invalid_state'


def test_normal_independent_signatures_and_tampering_stay_strict():
    raw, public = evidence(2**63 - 1)
    assert d._verify_record(raw, public)['ips'] == ['192.0.2.123']
    for field, value in [(b'seq', 0), (b'v', dns_value('198.51.100.9')), (b'sig', bytes(64))]:
        with pytest.raises(ValueError):
            d._verify_record({**raw, field: value}, public)
    result = d.reconcile_dht(None, {'records': [serialized(raw)]}, public.hex())
    restart = d.reconcile_dht(json.loads(json.dumps(result['state'])),
                              {'records': [serialized(raw)]}, public.hex())
    assert restart['record']['signature_valid'] is True
    assert restart['state']['highest_seq'] == '9223372036854775807'


def test_collector_cancellation_during_reverification_must_not_publish():
    observation, key = obs()
    cancelled = threading.Event()
    original = d._reverify

    def verify(*args):
        record = original(*args)
        cancelled.set()
        return record

    with patch.object(d, 'fetch_dht_records', return_value=observation), \
         patch.object(d, '_reverify', side_effect=verify):
        collected = collect_snapshot(DomainSpec(**target(key)), 'DHT', cancelled=cancelled.is_set)
    assert cancelled.is_set()
    assert collected.snapshot is None and collected.query.status == 'error'
    assert collected.query.values == []
    assert collected.dht_observation['records'] == []
    assert collected.dht_observation['status'] == 'cancelled'
    assert collected.dht_observation['coverage']['termination'] == 'cancelled'
    assert len(observation['records']) == 1  # Never mutate the provider's evidence.


@pytest.mark.parametrize('stop_at', [1, 3, 4])
def test_http_stop_during_signature_reverification_must_not_publish(app, stop_at):
    _, client, config = app
    assert client.login()[0] == 200
    observation, key = obs()
    domain = target(key)
    original = d._reverify
    verifies = []

    def verify(*args):
        record = original(*args)
        verifies.append(True)
        if len(verifies) == stop_at:
            config['_monitor_stopped'] = True
        return record

    with patch.object(d, 'fetch_dht_records', return_value=observation), \
         patch.object(d, '_reverify', side_effect=verify):
        code, result = client.call('POST', '/api/v1/domain-precheck',
                                  {**domain, 'domain': domain['name']})
    assert config['_monitor_stopped'] is True and len(verifies) >= stop_at
    assert code == 200
    assert result['dht_record'] is None
    assert result['dht_observation']['status'] == 'cancelled'
    assert result['dht_observation']['confirmed_in_this_run'] is False
    assert result['dht_observation']['highest_seen_seq'] is None
    assert result['dht_observation']['observed_seq'] is None
    assert result['managed_ips'] == result['ip_rows'] == result['detected_types'] == []
    assert result['by_server'][0]['values'] == []
    assert result['by_server'][0]['status'] == 'error'


def test_collector_cancel_during_snapshot_projection_is_fenced():
    import monitor.dht_support as support
    observation, key = obs()
    cancelled = threading.Event()
    original = support.record_snapshot

    def project(*args):
        snapshot = original(*args)
        cancelled.set()
        return snapshot

    with patch.object(d, 'fetch_dht_records', return_value=observation), \
         patch.object(support, 'record_snapshot', side_effect=project):
        collected = collect_snapshot(DomainSpec(**target(key)), 'DHT', cancelled=cancelled.is_set)
    assert cancelled.is_set()
    assert collected.snapshot is None and collected.query.status == 'error'
    assert collected.dht_observation['records'] == []


def test_http_cancel_during_metadata_projection_is_fenced(app):
    import http_api.dht_handlers as handlers
    _, client, config = app
    assert client.login()[0] == 200
    observation, key = obs()
    original = handlers.attempt_metadata

    def project(*args):
        result = original(*args)
        config['_monitor_stopped'] = True
        return result

    with patch.object(d, 'fetch_dht_records', return_value=observation), \
         patch.object(handlers, 'attempt_metadata', side_effect=project):
        code, result = client.call('POST', '/api/v1/domain-precheck',
                                  {**target(key), 'domain': target(key)['name']})
    assert code == 200 and config['_monitor_stopped'] is True
    assert result['dht_record'] is None
    assert result['dht_observation']['status'] == 'cancelled'
    assert result['dht_observation']['confirmed_in_this_run'] is False
    assert result['managed_ips'] == result['ip_rows'] == result['detected_types'] == []


def test_source_node_is_preserved_as_unsigned_evidence_across_restart(tmp_path):
    from config_manager import domain_storage_name
    from dns_monitor import restore_current_results
    from history_manager import load_history_files
    from test_dht_monitor import cycle
    observation, key = obs()
    source = ['8.8.8.8', 6881]  # Metadata only; loopback guard forbids contacting it.
    observation['records'][0].update(source_node=source, source_node_signed=True,
                                     ips=['8.8.8.8'], arbitrary_peer_data='not retained')
    original = copy.deepcopy(observation)
    first = d.reconcile_dht(None, observation, key)
    for record in [first['record'], first['state']['variants'][0], first['state']['last_confirmed']]:
        assert record['source_node'] == source
        assert record['source_node_signed'] is False
        assert 'arbitrary_peer_data' not in record
    assert first['record']['ips'] == ['192.0.2.123']
    state = json.loads(json.dumps(first['state']))
    restarted = d.reconcile_dht(state, observation, key)
    assert restarted['record']['source_node'] == source
    assert restarted['state'] == state
    assert d.reconcile_dht(state, {'records': []}, key)['state'] == state
    # Metadata is not signed: replacing the public source does not affect the
    # signed value or candidates, and cannot forge signature coverage for it.
    alternate = {**observation['records'][0], 'source_node': ['1.1.1.1', 65535]}
    checked = d._reverify(alternate, bytes.fromhex(key))
    assert checked['signature'] == first['record']['signature']
    assert checked['source_node'] == ['1.1.1.1', 65535]
    assert checked['source_node_signed'] is False
    assert checked['ips'] == ['192.0.2.123']
    first['record']['source_node'][0] = '9.9.9.9'
    assert observation == original and first['state']['variants'][0]['source_node'] == source

    domain = target(key)
    name = domain_storage_name(domain)
    current, history = {}, {}
    cycle(tmp_path, domain, observation, current, history, {})
    loaded = load_history_files(str(tmp_path))
    restored = restore_current_results(loaded)
    assert loaded[name]['meta']['dht_state']['variants'][0]['source_node'] == source
    assert restored[name]['DHT']['dht_record']['source_node'] == source
    assert restored[name]['DHT']['dht_record']['source_node_signed'] is False
    assert restored[name]['DHT']['decoded_ips'] == ['192.0.2.123']


@pytest.mark.parametrize('source', [None, '8.8.8.8:6881', [], ['8.8.8.8'],
    ['8.8.8.8', 6881, 'extra'], {'host': '8.8.8.8', 'port': 6881},
    ['127.0.0.1', 6881], ['10.0.0.1', 6881], ['192.0.2.1', 6881],
    ['224.0.0.1', 6881], ['::1', 6881], ['2606:4700:4700::1111', 6881],
    ['dns.example', 6881], ['8.8.8.8\n', 6881], ['08.8.8.8', 6881],
    ['x' * 10000, 6881], [123, 6881], ['8.8.8.8', True], ['8.8.8.8', '6881'],
    ['8.8.8.8', 0], ['8.8.8.8', -1], ['8.8.8.8', 65536]])
def test_invalid_unsigned_source_is_dropped_without_losing_signed_value(source):
    observation, key = obs()
    observation['records'][0].update(source_node=source, source_node_signed=True)
    result = d.reconcile_dht(None, observation, key)
    for record in [result['record'], result['state']['variants'][0], result['state']['last_confirmed']]:
        assert 'source_node' not in record and 'source_node_signed' not in record
    assert result['record']['signature_valid'] is True
    assert result['record']['ips'] == ['192.0.2.123']


def test_precheck_source_peer_never_becomes_a_managed_ip(app):
    _, client, _ = app
    assert client.login()[0] == 200
    observation, key = obs()
    observation['records'][0]['source_node'] = ['8.8.8.8', 6881]
    with patch.object(d, 'fetch_dht_records', return_value=observation):
        code, result = client.call('POST', '/api/v1/domain-precheck',
                                  {**target(key), 'domain': target(key)['name']})
    assert code == 200
    assert result['dht_record']['source_node'] == ['8.8.8.8', 6881]
    assert result['dht_record']['source_node_signed'] is False
    assert result['managed_ips'] == result['by_server'][0]['managed_ips'] == ['192.0.2.123']
    assert result['ip_rows'] == [{'ip': '192.0.2.123', 'role': 'managed', 'vt': None}]


def test_wire_source_endpoint_is_explicitly_unsigned():
    from test_dht_query import test_real_loopback_udp_correlates_peer_transaction_id_and_never_writes
    original = d.fetch_dht_records
    fetched = []

    def fetch(*args, **kwargs):
        result = original(*args, **kwargs)
        fetched.append(result)
        return result

    # Exercise the existing real UDP correlation fixture unchanged, including
    # its read-only methods, spoof-reply rejection and public-policy controls.
    with patch.object(d, 'fetch_dht_records', side_effect=fetch):
        test_real_loopback_udp_correlates_peer_transaction_id_and_never_writes()
    assert len(fetched) == 1
    record = fetched[0]['records'][0]
    assert record['source_node'][0] == '127.0.0.1'  # Only the fixture overrides public-peer policy.
    assert record['source_node_signed'] is False


def test_null_options_rejected_by_domain_schema_but_python_defaults_remain():
    from http_api.openapi import DHT_OPTIONS
    _, key = obs()
    domain = target(key)
    del domain['dht_options']
    assert DHT_OPTIONS['type'] == 'object'
    assert not DHT_OPTIONS.get('nullable', False)
    validate_dht_domain(domain)
    validate_dht_domain({**domain, 'dht_options': {}})
    assert d.validate_dht_config(key)[1] == d.validate_dht_config(key, None)[1]
    assert d.validate_dht_config(key)[1] == d.validate_dht_config(key, {})[1]
    with pytest.raises(ValueError, match='invalid_options'):
        validate_dht_domain({**domain, 'dht_options': None})


def test_default_domainspec_collection_does_not_turn_absence_into_explicit_null():
    observation, key = obs()
    domain = target(key)
    del domain['dht_options']
    spec = DomainSpec(**domain)
    with patch.object(d, 'fetch_dht_records', return_value=observation) as fetch:
        collected = collect_snapshot(spec, 'DHT')
    fetch.assert_called_once_with(key, None, cancelled=None)
    assert spec.dht_options is None
    assert collected.query.status == 'ok'
    assert collected.snapshot.managed_ips() == {'192.0.2.123'}


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_null_options_http_rejected_before_side_effects_and_missing_defaults_work(app, tmp_path, prefix):
    _, client, config = app
    assert client.login()[0] == 200
    service = config['_config_service']
    service.config_path = str(tmp_path / 'config.json')
    observation, key = obs()
    domain = target(key)
    del domain['dht_options']
    revision = client.call('GET', prefix + '/config')[1]['revision']
    with patch.object(d, 'fetch_dht_records', side_effect=AssertionError('no lookup on registration')):
        code, registered = client.call('POST', prefix + '/config', {'revision': revision, 'domains': [domain]})
    assert code == 200, registered
    persisted = (tmp_path / 'config.json').read_bytes()
    before = client.call('GET', prefix + '/config')[1]
    null_domain = {**domain, 'dht_options': None}
    queue_before = copy.deepcopy(config.get('_force_resolve_queue', []))
    with patch.object(d, 'fetch_dht_records', side_effect=AssertionError('no lookup for null')):
        code, result = client.call('POST', prefix + '/config',
                                  {'revision': before['revision'], 'domains': [null_domain]})
        assert code == 400, result
        code, result = client.call('POST', prefix + '/domain-precheck',
                                  {**null_domain, 'domain': domain['name']})
        assert code == 400, result
        code, result = client.call('POST', prefix + '/resolve', {'domains': [null_domain], 'servers': []})
        assert code == 400, result
    assert (tmp_path / 'config.json').read_bytes() == persisted
    assert client.call('GET', prefix + '/config')[1] == before
    assert config.get('_force_resolve_queue', []) == queue_before
    for options in ({}, {'dht_options': {}}):
        with patch.object(d, 'fetch_dht_records', return_value=observation):
            code, result = client.call('POST', prefix + '/domain-precheck',
                                      {**domain, **options, 'domain': domain['name']})
        assert code == 200 and result['dht_record']['signature_valid'] is True


@pytest.mark.parametrize('unavailable', ['missing', 'minimal'])
def test_point_validation_dependency_is_required_before_network(unavailable):
    import sys
    import nacl.bindings as bindings
    _, key = obs()
    blocker = (patch.dict(sys.modules, {'nacl.bindings': None}) if unavailable == 'missing' else
               patch.object(bindings, 'has_crypto_core_ed25519', False))
    with blocker, patch.object(d, '_resolve_bootstraps', return_value=[]) as resolve:
        with pytest.raises(d.DHTQueryError) as error:
            d.fetch_dht_records(key)
    assert error.value.code == 'crypto_unavailable'
    resolve.assert_not_called()
    assert d._LOOKUP_SLOTS.acquire(blocking=False)
    try:
        assert d._LOOKUP_SLOTS.acquire(blocking=False)
        d._LOOKUP_SLOTS.release()
    finally:
        d._LOOKUP_SLOTS.release()


@pytest.mark.parametrize('public', [bytes(32), b'\x01' + bytes(31),
                                   b'\xec' + b'\xff' * 30 + b'\x7f', bytes(31) + b'\x80'])
def test_low_order_point_policy_is_enforced_before_signature_acceptance(public):
    assert d._ed25519_public_key_valid(public) is False
    raw = {b'k': public, b'seq': 7, b'v': dns_value(), b'sig': b'\x01' + bytes(63)}
    with pytest.raises(ValueError):
        d._verify_record(raw, public)
