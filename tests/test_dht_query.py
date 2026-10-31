"""Offline-only signed DNS fixtures; all UDP is owned loopback."""
import importlib
from unittest.mock import patch

import pytest


def module():
    return importlib.import_module('dht_query')


def test_config_exact_key_closed_options_and_literal_policy():
    d = module()
    key, options = d.validate_dht_config('AB' * 32)
    assert key == 'ab' * 32
    assert options == {
        'duration': 30.0, 'max_queries': 128, 'timeout': 2.5,
        'rate': 4.0, 'concurrency': 4, 'max_nodes': 512,
        'bootstraps': ['dht.transmissionbt.com:6881', 'router.bittorrent.com:6881',
                       'router.utorrent.com:6881', 'dht.libtorrent.org:25401'],
    }
    for bad in [' ' + key, key + '\n', key[:-1], 'gg' * 32, None, bytes(32)]:
        with pytest.raises(d.DHTQueryError) as error:
            d.validate_dht_config(bad)
        assert error.value.code == 'invalid_public_key'
    for bad in [{'wat': 1}, {'duration': True}, {'duration': float('nan')},
                {'rate': float('inf')}, {'duration': 61}, {'timeout': 6},
                {'max_queries': 129}, {'max_queries': 1.0}, {'concurrency': 5},
                {'max_nodes': 513}, {'rate': 6}, {'bootstraps': []},
                {'bootstraps': ['example.com:80'] * 9}, {'bootstraps': 'example.com:80'},
                [], {'duration': 0}]:
        with pytest.raises(d.DHTQueryError) as error:
            d.validate_dht_config(key, bad)
        assert error.value.code == 'invalid_options'
    with patch('socket.getaddrinfo', side_effect=AssertionError('DNS')), \
         patch('socket.socket', side_effect=AssertionError('socket')):
        for host in ['127.0.0.1', '10.0.0.1', '169.254.169.254', '100.64.0.1',
                     '192.0.2.1', '192.0.0.9', '224.0.0.1', '240.0.0.1',
                     '0.0.0.0', '127.1', '2130706433', '0x7f000001', '0177.0.0.1',
                     '::1', 'http://example.com']:
            with pytest.raises(d.DHTQueryError):
                d.validate_dht_config(key, {'bootstraps': ['example.com:80', host + ':6881']})
    custom = {'duration': .05, 'timeout': .02, 'rate': .1, 'max_nodes': 1,
              'bootstraps': ['1.1.1.1:6881']}
    _, normalized = d.validate_dht_config(key, custom)
    assert normalized['duration'] == .05
    normalized['bootstraps'].append('8.8.8.8:6881')
    assert len(custom['bootstraps']) == 1


def dns_fixture(ips=('192.0.2.123',)):
    import ipaddress
    import struct
    return (struct.pack('!6H', 0, 0, 0, len(ips), 0, 0) + b''.join(
        b'\0' + struct.pack('!HHIH', 1, 1, 300, 4) + ipaddress.IPv4Address(ip).packed
        for ip in ips))


def signed_fixture(seq=7, ips=('192.0.2.123',), value=None):
    import hashlib
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b'TraceDNS synthetic test key').digest())
    pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    value = dns_fixture(ips) if value is None else value
    transcript = b'3:seqi' + str(seq).encode() + b'e1:v' + str(len(value)).encode() + b':' + value
    return {b'k': pk, b'seq': seq, b'v': value, b'sig': sk.sign(transcript)}, pk


def test_verified_record_is_json_safe_strict_and_not_xored():
    import json
    d = module()
    for seq in [0, 7, 2**53 + 1, 2**63 - 1]:
        raw, pk = signed_fixture(seq)
        record = d._verify_record(raw, pk)
        assert record['seq'] == str(seq)
        assert json.loads(json.dumps(record)) == record
        assert record['ips'] == ['192.0.2.123']
        assert record['signature_valid'] is True
        assert record['dns_valid'] is True
        assert record['xor_applied'] is False
        for field, value in [(b'k', bytes(32)), (b'seq', seq + 1), (b'seq', True),
                             (b'seq', -1), (b'seq', 2**63), (b'seq', str(seq)),
                             (b'sig', bytes(64)), (b'v', b'tampered'), (b'salt', b'salted')]:
            with pytest.raises(ValueError):
                d._verify_record({**raw, field: value}, pk)
    raw, pk = signed_fixture(value=b'bad DNS')
    record = d._verify_record(raw, pk)
    assert record['signature_valid'] is True
    assert record['dns_valid'] is False
    assert record['dns_error']


def observation(seq=7, ips=('192.0.2.123',), value=None):
    raw, pk = signed_fixture(seq, ips, value)
    return {'records': [module()._verify_record(raw, pk)], 'coverage': {}}, pk.hex()


def test_reconcile_survives_json_restart_preserves_highwater_conflicts_and_last_good():
    import json
    d = module()
    obs, key = observation(2**53 + 1)
    first = d.reconcile_dht(None, obs, key)
    assert first['status'] == 'initial'
    assert first['record']['seq'] == str(2**53 + 1)
    state = json.loads(json.dumps(first['state']))
    assert state['highest_seq'] == str(2**53 + 1)
    assert d.reconcile_dht(state, obs, key)['status'] == 'unchanged'
    miss = d.reconcile_dht(state, {'records': [], 'coverage': {}}, key)
    assert miss['status'] == 'no_verified_record' and miss['record'] is None
    assert miss['state'] == state
    old, _ = observation(2**53)
    stale = d.reconcile_dht(state, old, key)
    assert stale['status'] == 'stale_only' and stale['record'] is None
    bad, _ = observation(2**53 + 2, value=b'bad')
    invalid = d.reconcile_dht(state, bad, key)
    assert invalid['status'] == 'signed_dns_invalid' and invalid['record'] is None
    state = json.loads(json.dumps(invalid['state']))
    assert state['highest_seq'] == str(2**53 + 2)
    assert d.reconcile_dht(state, obs, key)['status'] == 'stale_only'
    same_seq, _ = observation(2**53 + 2)
    conflict = d.reconcile_dht(state, same_seq, key)
    assert conflict['status'] == 'same_seq_conflict' and conflict['record'] is None
    state = json.loads(json.dumps(conflict['state']))
    assert state['conflict'] is True
    assert len(state['variants']) == 2
    assert d.reconcile_dht(state, bad, key)['status'] == 'same_seq_conflict'
    for index in range(12):
        variant, _ = observation(2**53 + 2, (f'192.0.2.{index + 1}',))
        state = d.reconcile_dht(state, variant, key)['state']
    assert len(state['variants']) == 2
    assert len(json.dumps(state)) < 15000
    empty, _ = observation(2**53 + 3, ())
    updated = d.reconcile_dht(state, empty, key)
    assert updated['status'] == 'updated' and updated['record']['ips'] == []
    assert updated['state']['conflict'] is False
    assert d.reconcile_dht(updated['state'], empty, key)['status'] == 'unchanged'


def test_reconcile_reverifies_state_and_never_trusts_derived_metadata():
    import copy
    d = module()
    obs, key = observation()
    obs['records'][0].update(ips=['8.8.8.8'], signature_valid=False, value_sha256='lie')
    first = d.reconcile_dht(None, obs, key)
    assert first['record']['ips'] == ['192.0.2.123']
    bad_state = copy.deepcopy(first['state'])
    bad_state['variants'][0]['signature'] = '00' * 64
    with pytest.raises(d.DHTQueryError) as error:
        d.reconcile_dht(bad_state, obs, key)
    assert error.value.code == 'invalid_state'
    for seq in [7, True, '07', '+7', '-1', '9223372036854775808', '7\n']:
        tampered = copy.deepcopy(obs)
        tampered['records'][0]['seq'] = seq
        with pytest.raises(d.DHTQueryError) as error:
            d.reconcile_dht(None, tampered, key)
        assert error.value.code == 'invalid_observation'
    higher, _ = observation(8)
    higher['coverage'] = {'termination': 'cancelled'}
    cancelled = d.reconcile_dht(first['state'], higher, key)
    assert cancelled['status'] == 'cancelled' and cancelled['record'] is None
    assert cancelled['state'] == first['state']


def test_bounded_bencode_and_read_only_query_builder():
    d = module()
    for method in ('find_node', 'get'):
        wire = d._make_query(method, b'abcd', bytes(20), bytes([1]) * 20)
        query = d._bdecode(wire)
        assert query[b'ro'] == 1 and query[b'q'] == method.encode()
        assert query[b'a'][b'target'] == bytes([1]) * 20
        assert query[b'a'][b'want'] == [b'n4']
    for method in ('put', 'announce_peer', 'get_peers', 'ping'):
        with pytest.raises(ValueError):
            d._make_query(method, b'abcd', bytes(20), bytes(20))
    for wire in [b'i-0e', b'i01e', b'i+1e', b'02:hi', b'd1:ai1e1:ai2ee',
                 b'i1ee', b'l' * 30 + b'e' * 30, b'9:short', b'x' * 8193,
                 b'i9223372036854775808e', b'l' + b'0:' * 1025 + b'e']:
        with pytest.raises(ValueError):
            d._bdecode(wire)
    value = {b'nodes': b'\x00\xff', b'r': [1, b'v']}
    assert d._bdecode(d._bencode(value)) == value


def test_dns_sample_first_64_answers_any_class_long_rdata_no_authority():
    import struct
    d = module()
    rr = b'\0' + struct.pack('!HHIH', 1, 255, 1, 5) + bytes([1, 2, 3, 4, 99])
    wire = struct.pack('!6H', 0, 0, 0, 65, 1, 1) + rr * 64 + b'ignored tail'
    records, limited = d._dns_addresses(wire)
    assert len(records) == 64 and limited is True
    assert {r['ip'] for r in records} == {'1.2.3.4'}
    assert records[0]['class'] == 255 and records[0]['rdlength'] == 5
    assert d._dns_addresses(struct.pack('!6H', 0, 0, 0, 0, 1, 1) + rr)[0] == []
    header = struct.pack('!6H', 0, 0, 0, 1, 0, 0)
    for tail in [b'\xc0\x0c', b'\xc0\xff', b'\x40', b'\x3fabc', b'\0', rr[:-1]]:
        with pytest.raises(ValueError):
            d._dns_addresses(header + tail)


@pytest.mark.parametrize('payload,admitted', [
    ('["1.1.1.1", "8.8.8.8"]', 2), ('["1.1.1.1", "127.0.0.1"]', 0),
    ('["1.1.1.1"]' , 1), ('["1.1.1.1"] * 9', 0), ('{}', 0),
])
def test_resolver_admits_entire_numeric_snapshot(payload, admitted):
    import time
    d = module()
    code = f'import json; print(json.dumps({payload}))'
    with patch.object(d, '_RESOLVER_CODE', code):
        coverage = d._coverage()
        peers = d._resolve_bootstraps([('router.example', 6881)], time.monotonic() + 2,
                                      None, coverage)
    assert len(peers) == admitted
    assert all(d._public_peer(peer) for peer in peers)


@pytest.mark.parametrize('kind', ['timeout', 'cancel', 'stdout', 'stderr'])
def test_resolver_children_are_bounded_killed_and_reaped(kind):
    import subprocess
    import time
    d = module()
    spawned = []
    original = subprocess.Popen

    def launch(*args, **kwargs):
        child = original(*args, **kwargs)
        spawned.append(child)
        return child

    code = ('import time; time.sleep(20)' if kind in ('timeout', 'cancel') else
            'import os,time; os.write(%s, b"x" * 100000); time.sleep(20)' %
            (1 if kind == 'stdout' else 2))
    start = time.monotonic()
    callback = (lambda: time.monotonic() - start > .08) if kind == 'cancel' else None
    coverage = d._coverage()
    with patch.object(d, '_RESOLVER_CODE', code), patch.object(d.subprocess, 'Popen', launch):
        peers = d._resolve_bootstraps([('router.example', 6881)], start + .25, callback, coverage)
    assert peers == [] and len(spawned) == 1
    assert time.monotonic() - start < 1.5
    assert spawned[0].poll() is not None
    assert spawned[0].stdout.closed and spawned[0].stderr.closed
    if kind == 'cancel':
        assert coverage['termination'] == 'cancelled'
    elif kind == 'timeout':
        assert coverage['termination'] == 'duration_budget'
    else:
        assert coverage['bootstrap_failures'] == 1


def test_fetch_capacity_and_early_cancellation_precede_network():
    import threading
    d = module()
    release = threading.Event()
    admitted = threading.Barrier(3)
    results, errors = [], []

    def resolving(*args):
        admitted.wait(timeout=2)
        release.wait(timeout=2)
        return []

    def fetch():
        try:
            results.append(d.fetch_dht_records('ab' * 32))
        except Exception as exc:
            errors.append(exc)

    with patch.object(d, '_resolve_bootstraps', side_effect=resolving) as dns, \
         patch.object(d.socket, 'socket', side_effect=AssertionError('socket')):
        workers = [threading.Thread(target=fetch) for _ in range(2)]
        for worker in workers:
            worker.start()
        try:
            admitted.wait(timeout=2)
            with pytest.raises(d.DHTQueryError) as error:
                d.fetch_dht_records('ab' * 32)
            assert error.value.code == 'capacity'
            assert dns.call_count == 2
        finally:
            release.set()
            for worker in workers:
                worker.join(3)
    assert not errors and len(results) == 2
    with patch.object(d, '_resolve_bootstraps', side_effect=AssertionError('DNS')):
        cancelled = d.fetch_dht_records('ab' * 32, cancelled=lambda: True)
    assert cancelled['status'] == 'cancelled' and cancelled['records'] == []
    # Both tokens were returned, including early cancellation's token.
    with patch.object(d, '_resolve_bootstraps', return_value=[]):
        assert d.fetch_dht_records('ab' * 32)['coverage']['termination'] == 'no_bootstrap'


def test_real_loopback_udp_correlates_peer_transaction_id_and_never_writes():
    import socket
    import struct
    import threading
    d = module()
    raw, pk = signed_fixture()
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(('127.0.0.1', 0))
    server.settimeout(2)
    spoof = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    spoof.bind(('127.0.0.1', 0))
    peer = server.getsockname()
    identity = bytes([1]) * 20
    messages, errors = [], []
    spoof_received = threading.Event()
    original_decode = d._bdecode

    def decode(data):
        message = original_decode(data)
        if isinstance(message, dict) and message.get(b'x') == b'spoof':
            spoof_received.set()
        return message

    def serve():
        try:
            data, addr = server.recvfrom(8192)
            query = d._bdecode(data)
            messages.append(query)
            nodes = identity + socket.inet_aton(peer[0]) + struct.pack('!H', peer[1])
            nodes += bytes([2]) * 20 + socket.inet_aton('10.0.0.1') + struct.pack('!H', 6881)
            server.sendto(d._bencode({b't': query[b't'], b'y': b'r',
                                     b'r': {b'id': identity, b'nodes': nodes}}), addr)
            data, addr = server.recvfrom(8192)
            query = d._bdecode(data)
            messages.append(query)
            body = {b'id': identity, **raw}
            response = {b't': query[b't'], b'y': b'r', b'r': body}
            server.sendto(d._bencode({**response, b't': b'wrong'}), addr)
            spoof.sendto(d._bencode({**response, b'x': b'spoof'}), addr)
            # Cross-socket UDP arrival order is unspecified. Observe the actual
            # spoof decode before sending the success that may end the lookup.
            assert spoof_received.wait(1)
            server.sendto(d._make_query('get', b'inbound', identity, bytes(20)), addr)
            server.sendto(d._bencode({**response, b'r': {**body, b'id': bytes(20)}}), addr)
            server.sendto(d._bencode(response), addr)
            server.settimeout(.1)
            with pytest.raises(socket.timeout):
                server.recvfrom(8192)
        except Exception as exc:
            errors.append(exc)

    worker = threading.Thread(target=serve)
    worker.start()
    try:
        # Test-only policy monkeypatch, not a production override or option.
        with patch.object(d, '_public_peer', side_effect=lambda p: p == peer), \
             patch.object(d, '_bdecode', side_effect=decode):
            result = d.fetch_dht_records(pk.hex(), {
                'bootstraps': [f'{peer[0]}:{peer[1]}'], 'duration': 1,
                'timeout': .3, 'rate': 5, 'max_queries': 2,
            })
    finally:
        worker.join(3)
        server.close()
        spoof.close()
    assert not worker.is_alive() and not errors
    assert [q[b'q'] for q in messages] == [b'find_node', b'get']
    assert all(q[b'ro'] == 1 and q[b'y'] == b'q' for q in messages)
    assert len(result['records']) == 1 and result['records'][0]['ips'] == ['192.0.2.123']
    assert result['records'][0]['seq'] == '7'
    assert result['coverage']['ignored_datagrams'] == 4
    assert result['coverage']['blocked_peers'] == 1
    assert result['coverage']['decoded_endpoint_contacts'] == 0
    assert result['coverage']['globally_complete'] is False


@pytest.mark.parametrize('stop', ['cancel_preparation', 'deadline_preparation', 'dns_deadline'])
def test_no_send_after_preparation_cancellation_or_shared_dns_deadline(stop):
    import socket
    import time
    d = module()
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(('127.0.0.1', 0))
    server.settimeout(.03)
    peer = server.getsockname()
    flag = [False]
    original = d._make_query

    def prepare(*args):
        if stop == 'cancel_preparation':
            flag[0] = True
        else:
            time.sleep(.07)
        return original(*args)

    def resolve(*args):
        if stop == 'dns_deadline':
            time.sleep(.07)
        return [peer]

    try:
        with patch.object(d, '_public_peer', side_effect=lambda p: p == peer), \
             patch.object(d, '_make_query', side_effect=prepare), \
             patch.object(d, '_resolve_bootstraps', side_effect=resolve):
            result = d.fetch_dht_records('ab' * 32, {'duration': .05}, cancelled=lambda: flag[0])
        assert result['records'] == [] and result['coverage']['queries_sent'] == 0
        assert result['coverage']['termination'] == ('cancelled' if flag[0] else 'duration_budget')
        with pytest.raises(socket.timeout):
            server.recvfrom(8192)
    finally:
        server.close()


def test_exact_receive_cap_oversized_packets_and_seed_queue_cap():
    import socket
    import threading
    d = module()
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(('127.0.0.1', 0))
    server.settimeout(2)
    peer = server.getsockname()
    errors = []

    def flood():
        try:
            _, addr = server.recvfrom(8192)
            for _ in range(16):
                server.sendto(b'x' * 100, addr)
        except Exception as exc:
            errors.append(exc)

    worker = threading.Thread(target=flood)
    worker.start()
    try:
        # This host drops large UDP datagrams; lower the test-only parser cap
        # to exercise real recvfrom truncation. The actual 8192 cap is tested
        # independently in test_bounded_bencode_and_read_only_query_builder.
        with patch.object(d, '_public_peer', side_effect=lambda p: p == peer), \
             patch.object(d, '_MAX_PACKET', 64):
            result = d.fetch_dht_records('ab' * 32, {'bootstraps': [f'{peer[0]}:{peer[1]}'],
                'duration': 1, 'max_queries': 1, 'timeout': .5})
        assert result['coverage']['received_packets'] == 4
        assert result['coverage']['received_bytes'] == 4 * 65
        assert result['coverage']['malformed_datagrams'] == 4
        assert result['coverage']['termination'] == 'receive_budget'
    finally:
        worker.join(3)
        server.close()
    assert not worker.is_alive() and not errors
    servers = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(10)]
    try:
        for server in servers:
            server.bind(('127.0.0.1', 0))
        peers = [server.getsockname() for server in servers]
        with patch.object(d, '_public_peer', side_effect=lambda p: p in peers), \
             patch.object(d, '_resolve_bootstraps', return_value=peers):
            result = d.fetch_dht_records('ab' * 32, {'duration': .2, 'max_queries': 1,
                                                   'max_nodes': 3, 'timeout': .02})
        assert result['coverage']['initial_queued'] == 3
        assert result['coverage']['seed_limit_drops'] == 7
        assert result['coverage']['queued_at_stop'] <= 3
    finally:
        for server in servers:
            server.close()


def test_rate_measured_from_actual_send_after_slow_preparation():
    import socket
    import threading
    import time
    d = module()
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(('127.0.0.1', 0))
    server.settimeout(2)
    peer = server.getsockname()
    received, errors = [], []
    original = d._make_query
    prepared = []

    def prepare(*args):
        if not prepared:
            time.sleep(.12)
        prepared.append(True)
        return original(*args)

    def serve():
        try:
            for _ in range(2):
                data, addr = server.recvfrom(8192)
                received.append(time.monotonic())
                query = d._bdecode(data)
                server.sendto(d._bencode({b't': query[b't'], b'y': b'r',
                                         b'r': {b'id': bytes(20)}}), addr)
        except Exception as exc:
            errors.append(exc)

    worker = threading.Thread(target=serve)
    worker.start()
    try:
        with patch.object(d, '_public_peer', side_effect=lambda p: p == peer), \
             patch.object(d, '_make_query', side_effect=prepare):
            d.fetch_dht_records('ab' * 32, {'bootstraps': [f'{peer[0]}:{peer[1]}'],
                'duration': 1, 'rate': 5, 'max_queries': 2})
    finally:
        worker.join(3)
        server.close()
    assert not errors and len(received) == 2
    assert received[1] - received[0] >= .19


@pytest.mark.parametrize('stop', ['during_verify', 'after_lookup', 'udp_wait', 'expiry'])
def test_cancel_or_expiry_never_publishes_late_signed_success(stop):
    import socket
    import threading
    import time
    d = module()
    raw, pk = signed_fixture()
    flag = [False]
    original = d._verify_record
    original_lookup = d._lookup
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(('127.0.0.1', 0))
    server.settimeout(2)
    peer = server.getsockname()
    errors = []

    def verify(*args):
        result = original(*args)
        if stop == 'during_verify':
            flag[0] = True
        elif stop == 'expiry':
            time.sleep(.13)
        return result

    def lookup(*args):
        result = original_lookup(*args)
        if stop == 'after_lookup':
            assert len(result) == 1
            flag[0] = True
        return result

    def serve():
        try:
            for index in range(2):
                data, addr = server.recvfrom(8192)
                query = d._bdecode(data)
                if stop == 'udp_wait' and index == 1:
                    flag[0] = True
                    break
                body = {b'id': bytes(20), **(raw if index else {})}
                server.sendto(d._bencode({b't': query[b't'], b'y': b'r', b'r': body}), addr)
        except Exception as exc:
            errors.append(exc)

    worker = threading.Thread(target=serve)
    worker.start()
    try:
        with patch.object(d, '_public_peer', side_effect=lambda p: p == peer), \
             patch.object(d, '_verify_record', side_effect=verify), \
             patch.object(d, '_lookup', side_effect=lookup):
            result = d.fetch_dht_records(pk.hex(), {'bootstraps': [f'{peer[0]}:{peer[1]}'],
                'duration': 1, 'timeout': .1, 'rate': 5, 'max_queries': 2}, cancelled=lambda: flag[0])
    finally:
        worker.join(3)
        server.close()
    assert not worker.is_alive() and not errors
    assert result['records'] == []
    reconciled = d.reconcile_dht(None, result, pk.hex())
    assert reconciled['record'] is None
    assert reconciled['status'] == ('no_verified_record' if stop == 'expiry' else 'cancelled')


def test_coverage_is_closed_bounded_and_robust_to_untrusted_fields():
    d = module()
    obs, key = observation()
    obs['coverage'] = {'termination': [], 'globally_complete': True, 'decoded_endpoint_contacts': 10,
                       'unknown': 'x' * 10000, 'elapsed_seconds': float('nan'),
                       'methods': {'put': 99999, 'get': True}, 'replies': 2**200}
    result = d.reconcile_dht(None, obs, key)
    assert result['status'] == 'initial'
    assert result['coverage']['globally_complete'] is False
    assert 'unknown' not in result['coverage']
    assert result['coverage']['replies'] == 0


def test_public_fetch_invalid_input_and_mixed_dns_have_zero_socket_effects():
    d = module()
    with patch.object(d.subprocess, 'Popen', side_effect=AssertionError('child')), \
         patch.object(d.socket, 'socket', side_effect=AssertionError('socket')):
        for key, options in [('00' * 32 + ' ', None), ('00' * 32, {'max_queries': 129}),
                             ('00' * 32, {'bootstraps': ['example.com:80', '127.0.0.1:80']}),
                             ('00' * 32, {'allow_private': True})]:
            with pytest.raises(d.DHTQueryError):
                d.fetch_dht_records(key, options)
    with patch.object(d, '_RESOLVER_CODE', 'print(\'["1.1.1.1", "127.0.0.1"]\')'), \
         patch.object(d.socket, 'socket', side_effect=AssertionError('socket')):
        result = d.fetch_dht_records('00' * 32, {'bootstraps': ['router.example:6881']})
    assert result['coverage']['bootstrap_rejections'] == 1
    assert result['records'] == []


def test_slot_released_after_unexpected_callback_or_resolver_exception():
    d = module()

    def broken():
        raise RuntimeError('test cancellation callback failure')

    with pytest.raises(RuntimeError):
        d.fetch_dht_records('00' * 32, cancelled=broken)
    with patch.object(d, '_resolve_bootstraps', side_effect=RuntimeError('test resolver failure')):
        with pytest.raises(RuntimeError):
            d.fetch_dht_records('00' * 32)
    # Acquire the exact shared semaphore: neither failed call retained a slot.
    assert d._LOOKUP_SLOTS.acquire(blocking=False)
    try:
        assert d._LOOKUP_SLOTS.acquire(blocking=False)
        d._LOOKUP_SLOTS.release()
    finally:
        d._LOOKUP_SLOTS.release()


def test_strict_ed25519_noncanonical_s_value_and_record_bounds():
    d = module()
    raw, pk = signed_fixture()
    order = 2**252 + 27742317777372353535851937790883648493
    noncanonical = raw[b'sig'][:32] + (int.from_bytes(raw[b'sig'][32:], 'little') + order).to_bytes(32, 'little')
    for field, value in [(b'sig', noncanonical), (b'sig', b'x' * 63),
                         (b'v', b''), (b'v', b'x' * 2049), (b'k', pk[:-1]),
                         (b'salt', None), (b'seq', 1.0)]:
        with pytest.raises(ValueError):
            d._verify_record({**raw, field: value}, pk)


def test_persistent_state_bound_and_evidence_mismatch_fail_closed():
    import copy
    import json
    d = module()
    obs, key = observation(2**63 - 1, value=b'x' * 2048)
    first = d.reconcile_dht(None, obs, key)
    second, _ = observation(2**63 - 1, value=b'y' * 2048)
    conflicted = d.reconcile_dht(first['state'], second, key)
    state = conflicted['state']
    assert len(state['variants']) == 2 and len(json.dumps(state)) < 15000
    for alteration in [{'highest_seq': '9223372036854775806'}, {'public_key': '00' * 32},
                       {'variants': state['variants'] * 2}, {'version': True},
                       {'highest_seq': None}, {'variants': []}]:
        with pytest.raises(d.DHTQueryError) as error:
            d.reconcile_dht({**state, **alteration}, obs, key)
        assert error.value.code == 'invalid_state'
    cleared = copy.deepcopy(state)
    cleared['conflict'] = False
    cleared['conflict_count'] = 0
    assert d.reconcile_dht(cleared, obs, key)['status'] == 'same_seq_conflict'
    with pytest.raises(d.DHTQueryError):
        d.reconcile_dht(None, {'records': obs['records'] * 513}, key)
