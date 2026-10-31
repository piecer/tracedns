"""Bounded, read-only IPv4 BEP44 signed-DNS observation.

No CLI, filesystem state, mutable DHT writes, or decoded-endpoint connections.
Only the three public entrypoints and DHTQueryError form the integration API.
"""
import hashlib
import ipaddress
import math
import json
import os
import re
import secrets
import select
import socket
import struct
import subprocess
import sys
import threading
import time
from collections.abc import Mapping


class DHTQueryError(ValueError):
    """Stable, non-wire-derived error code (also exposed as reason)."""

    def __init__(self, code):
        self.code = self.reason = code
        super().__init__(code)


_DEFAULT_BOOTSTRAPS = (
    'dht.transmissionbt.com:6881', 'router.bittorrent.com:6881',
    'router.utorrent.com:6881', 'dht.libtorrent.org:25401',
)
_DEFAULTS = dict(duration=30.0, max_queries=128, timeout=2.5,
                 rate=4.0, concurrency=4, max_nodes=512)


def _public_peer(peer):
    try:
        host, port = peer
        ip = ipaddress.IPv4Address(host)
        return (type(host) is str and str(ip) == host and type(port) is int and
                1 <= port <= 65535 and ip.is_global and not (
                    ip.is_multicast or ip.is_reserved or ip.is_loopback or
                    ip.is_link_local or ip.is_unspecified) and
                ip not in ipaddress.IPv4Network('192.0.0.0/24'))
    except (ValueError, TypeError):
        return False


def _parse_bootstrap(text):
    if type(text) is not str or len(text) > 260 or text.count(':') != 1:
        raise DHTQueryError('invalid_options')
    host, port = text.rsplit(':', 1)
    if (not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535 or
            not host or len(host) > 253 or any(not re.fullmatch(
                r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                for label in host.split('.'))):
        raise DHTQueryError('invalid_options')
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        if re.fullmatch(r'[0-9.]+', host):
            raise DHTQueryError('invalid_options') from None
        try:
            socket.inet_aton(host)  # Numeric-only parser, never a DNS lookup.
        except OSError:
            pass
        else:
            raise DHTQueryError('invalid_options') from None
    else:
        if not _public_peer((host, int(port))):
            raise DHTQueryError('invalid_options')
    return host, int(port)


def validate_dht_config(public_key: str, options=None) -> tuple[str, dict]:
    """Validate without side effects; return exact key lowercased and fresh options.

    Options are closed: duration .05..60, timeout .02..5, rate .1..5,
    max_queries 1..128, concurrency 1..4, max_nodes 1..512 and 1..8
    bootstrap host:port strings. Public peers only; no private-peer override.
    """
    if type(public_key) is not str or not re.fullmatch(r'[0-9A-Fa-f]{64}', public_key):
        raise DHTQueryError('invalid_public_key')
    if options is None:
        options = {}
    if not isinstance(options, Mapping) or set(options) - (_DEFAULTS.keys() | {'bootstraps'}):
        raise DHTQueryError('invalid_options')
    normalized = {**_DEFAULTS, **options}
    for name, low, high in [('duration', .05, 60), ('timeout', .02, 5), ('rate', .1, 5)]:
        value = normalized[name]
        if (type(value) not in (int, float) or not low <= value <= high or
                not math.isfinite(value)):
            raise DHTQueryError('invalid_options')
        normalized[name] = float(value)
    for name, high in [('max_queries', 128), ('concurrency', 4), ('max_nodes', 512)]:
        if type(normalized[name]) is not int or not 1 <= normalized[name] <= high:
            raise DHTQueryError('invalid_options')
    bootstraps = normalized.get('bootstraps', list(_DEFAULT_BOOTSTRAPS))
    if type(bootstraps) is not list or not 1 <= len(bootstraps) <= 8:
        raise DHTQueryError('invalid_options')
    for bootstrap in bootstraps:
        _parse_bootstrap(bootstrap)
    normalized['bootstraps'] = list(bootstraps)
    return public_key.lower(), normalized


_MAX_VALUE = 2048
_MAX_PACKET = 8192


def _dns_addresses(data):
    """First 64 answer RRs, A/any class/RDLENGTH >= 4; never XOR."""
    import struct
    if not 12 <= len(data) <= _MAX_VALUE:
        raise ValueError('DNS packet size')
    _, _, questions, answers, _, _ = struct.unpack_from('!6H', data)
    if questions > 64:
        raise ValueError('DNS question count')

    def name(pos):
        end, labels, visited, expanded = None, [], set(), 1
        for _ in range(128):
            if pos in visited or pos >= len(data):
                raise ValueError('DNS pointer cycle/bounds')
            visited.add(pos)
            length = data[pos]
            if length & 0xc0 == 0xc0:
                if pos + 1 >= len(data):
                    raise ValueError('DNS pointer bounds')
                target = ((length & 63) << 8) | data[pos + 1]
                if target >= pos:
                    raise ValueError('DNS non-backward pointer')
                if end is None:
                    end = pos + 2
                pos = target
                continue
            if length & 0xc0:
                raise ValueError('DNS label type')
            pos += 1
            if length == 0:
                return (pos if end is None else end), '.'.join(labels) or '.'
            if pos + length > len(data) or expanded + length + 1 > 255:
                raise ValueError('DNS label bounds')
            labels.append(''.join(chr(x) if 33 <= x <= 126 and x not in (46, 92)
                                  else '\\%03d' % x for x in data[pos:pos + length]))
            expanded += length + 1
            pos += length
        raise ValueError('DNS name work limit')

    pos = 12
    for _ in range(questions):
        pos, _ = name(pos)
        if pos + 4 > len(data):
            raise ValueError('DNS question bounds')
        pos += 4
    records = []
    for _ in range(min(answers, 64)):
        pos, owner = name(pos)
        if pos + 10 > len(data):
            raise ValueError('DNS RR bounds')
        typ, cls, ttl, length = struct.unpack_from('!HHIH', data, pos)
        pos += 10
        if pos + length > len(data):
            raise ValueError('DNS RDATA bounds')
        if typ == 1 and length >= 4:
            records.append({'name': owner, 'ip': str(ipaddress.IPv4Address(data[pos:pos + 4])),
                            'ttl': ttl, 'class': cls, 'rdlength': length})
        pos += length
    return records, answers > 64


class _UnauthenticatingKey(ValueError):
    """A shape-valid configured key cannot authenticate signed observations."""


def _ed25519_public_key_valid(key):
    # Use libsodium's vetted point check, not locally implemented curve math.
    # In particular this rejects low-order keys for which verify alone can
    # succeed without proving possession of any private signing key.
    try:
        from nacl.bindings import crypto_core_ed25519_is_valid_point, has_crypto_core_ed25519
    except ImportError as exc:
        raise DHTQueryError('crypto_unavailable') from exc
    if not has_crypto_core_ed25519:
        raise DHTQueryError('crypto_unavailable')
    return crypto_core_ed25519_is_valid_point(key)


def _verify_record(record, public_key):
    import hashlib
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if type(record) is not dict or type(public_key) is not bytes or len(public_key) != 32:
        raise ValueError('record/key type')
    key, seq, sig, value = (record.get(k) for k in (b'k', b'seq', b'sig', b'v'))
    if type(key) is not bytes or key != public_key or record.get(b'salt', b'') != b'':
        raise ValueError('public key or salt mismatch')
    if type(seq) is not int or not 0 <= seq < 1 << 63:
        raise ValueError('seq must be nonnegative signed-int64')
    if type(sig) is not bytes or len(sig) != 64:
        raise ValueError('signature size/type')
    if type(value) is not bytes or not 0 < len(value) <= _MAX_VALUE:
        raise ValueError('value size/type')
    if not _ed25519_public_key_valid(key):
        raise _UnauthenticatingKey('invalid Ed25519 public key')
    transcript = b'3:seqi' + str(seq).encode() + b'e1:v' + str(len(value)).encode() + b':' + value
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(sig, transcript)
    except InvalidSignature as exc:
        raise ValueError('invalid Ed25519 signature') from exc
    result = dict(public_key=key.hex(), target=hashlib.sha1(key).hexdigest(), seq=str(seq),
                  signature=sig.hex(), signature_valid=True, value_hex=value.hex(),
                  value_sha256=hashlib.sha256(value).hexdigest(), xor_applied=False,
                  dns_valid=True, dns_error=None, ips=[], a_records=[])
    try:
        records, limited = _dns_addresses(value)
        result.update(a_records=records, sample_answer_limit_applied=limited,
                      ips=sorted({r['ip'] for r in records}, key=ipaddress.IPv4Address))
    except ValueError as exc:
        result.update(dns_valid=False, dns_error=str(exc))
    return result


def _seq(text):
    if (type(text) is not str or not re.fullmatch(r'(0|[1-9][0-9]{0,18})', text) or
            int(text) >= 1 << 63):
        raise ValueError('noncanonical sequence')
    return int(text)


def _source_provenance(record):
    """One bounded public numeric IPv4 endpoint; never covered by the signature.

    Invalid optional provenance is omitted, not promoted to decoded addresses
    and not used to invalidate otherwise authenticated signed evidence.
    """
    source = record.get('source_node')
    if (type(source) not in (list, tuple) or len(source) != 2 or
            type(source[0]) is not str or not 1 <= len(source[0]) <= 15 or
            type(source[1]) is not int or not _public_peer(source)):
        return {}
    return {'source_node': list(source), 'source_node_signed': False}


def _reverify(record, public_key):
    if type(record) is not dict:
        raise ValueError('record type')
    for field, low, high in [('public_key', 64, 64), ('signature', 128, 128),
                             ('value_hex', 2, _MAX_VALUE * 2)]:
        text = record.get(field)
        if (type(text) is not str or not low <= len(text) <= high or len(text) % 2 or
                not re.fullmatch('[0-9a-f]+', text)):
            raise ValueError('record hex encoding')
    verified = _verify_record({b'k': bytes.fromhex(record['public_key']),
                               b'seq': _seq(record.get('seq')),
                               b'sig': bytes.fromhex(record['signature']),
                               b'v': bytes.fromhex(record['value_hex'])}, public_key)
    verified.update(_source_provenance(record))
    return verified


def _evidence(record):
    return {**{key: record[key] for key in ('public_key', 'seq', 'signature', 'value_hex')},
            **_source_provenance(record)}


_COUNTERS = ('query_attempts', 'queries_sent', 'replies', 'timeouts', 'ignored_datagrams',
             'malformed_datagrams', 'rpc_errors', 'signature_rejections', 'discovered_nodes',
             'blocked_peers', 'node_limit_drops', 'seed_limit_drops', 'initial_queued',
             'received_packets', 'received_bytes', 'send_errors', 'pending_at_stop',
             'queued_at_stop', 'bootstrap_failures', 'bootstrap_rejections', 'bootstrap_peers')
_TERMINATIONS = {'queue_exhausted', 'query_budget', 'duration_budget', 'receive_budget',
                 'cancelled', 'socket_error', 'no_bootstrap', 'not_started'}


def _coverage(source=None):
    """Bounded JSON projection, never carry arbitrary input/peer data downstream."""
    result = {key: 0 for key in _COUNTERS}
    result.update(termination='not_started', decoded_endpoint_contacts=0, ipv4_only=True,
                  globally_complete=False, globally_latest_proven=False,
                  methods={'get': 0, 'find_node': 0}, elapsed_seconds=0.0)
    if type(source) is not dict:
        return result
    for key in _COUNTERS:
        value = source.get(key)
        if type(value) is int and 0 <= value <= 2**31 - 1:
            result[key] = value
    if type(source.get('termination')) is str and source['termination'] in _TERMINATIONS:
        result['termination'] = source['termination']
    elapsed = source.get('elapsed_seconds')
    if type(elapsed) in (int, float) and 0 <= elapsed <= 86400:
        result['elapsed_seconds'] = round(float(elapsed), 3)
    methods = source.get('methods')
    if type(methods) is dict:
        for method in result['methods']:
            count = methods.get(method)
            if type(count) is int and 0 <= count <= 128:
                result['methods'][method] = count
    limits = source.get('limits')
    if type(limits) is dict:
        try:
            _, checked = validate_dht_config('00' * 32, limits)
        except DHTQueryError:
            pass
        else:
            result['limits'] = {key: checked[key] for key in _DEFAULTS}
    return result


def _load_state(previous, public_key):
    key = public_key.hex()
    empty = dict(version=1, public_key=key, highest_seq=None, variants=[],
                 conflict=False, conflict_count=0, last_confirmed=None)
    if previous is None:
        return empty
    try:
        if (type(previous) is not dict or type(previous.get('version')) is not int or
                previous['version'] != 1 or previous.get('public_key') != key or
                type(previous.get('variants')) is not list or len(previous['variants']) > 2):
            raise ValueError('state shape')
        variants = [_reverify(r, public_key) for r in previous['variants']]
        high = previous.get('highest_seq')
        if high is None:
            if variants or previous.get('last_confirmed') is not None or previous.get('conflict'):
                raise ValueError('empty state mismatch')
            return empty
        high_int = _seq(high)
        if (not variants or any(int(r['seq']) != high_int for r in variants) or
                len({r['value_hex'] for r in variants}) != len(variants)):
            raise ValueError('high water evidence mismatch')
        conflict = len(variants) == 2
        if previous.get('conflict') is True and not conflict:
            raise ValueError('missing conflict evidence')
        last = previous.get('last_confirmed')
        if last is not None:
            last = _reverify(last, public_key)
            if not last['dns_valid'] or int(last['seq']) > high_int:
                raise ValueError('last confirmed mismatch')
            if (last['seq'] == high and not conflict and
                    last['value_hex'] != variants[0]['value_hex']):
                raise ValueError('missing conflict evidence')
        return dict(version=1, public_key=key, highest_seq=high,
                    variants=[_evidence(r) for r in variants], conflict=conflict,
                    conflict_count=2 if conflict else 0,
                    last_confirmed=_evidence(last) if last else None)
    except (ValueError, TypeError, KeyError) as exc:
        raise DHTQueryError('invalid_state') from exc


def reconcile_dht(previous_state, observation, public_key):
    """Return {state, status, record, coverage}; None never means authoritative empty.

    Persist the returned state even on stale/conflict/signed_dns_invalid results.
    It contains at most two distinct highest-sequence signed values plus the last
    confirmed signed value. conflict_count is saturated at 2 (two or more distinct
    values), NOT a lifetime count. All signatures and derived metadata are
    reverified/recomputed on every call. Sequences are canonical decimal strings.
    No observation proves the globally latest value. Cancelled observations do
    not advance state or publish success. Invalid serialized evidence fails closed.
    """
    canonical, _ = validate_dht_config(public_key)
    public_key_bytes = bytes.fromhex(canonical)
    state = _load_state(previous_state, public_key_bytes)
    if type(observation) is not dict:
        raise DHTQueryError('invalid_observation')
    coverage = _coverage(observation.get('coverage'))
    result = dict(state=state, status='no_verified_record', record=None, coverage=coverage)
    if observation.get('status') == 'cancelled' or coverage['termination'] == 'cancelled':
        coverage['termination'] = 'cancelled'
        result['status'] = 'cancelled'
        return result
    records = observation.get('records')
    if type(records) is not list or len(records) > 512:
        raise DHTQueryError('invalid_observation')
    try:
        checked = [_reverify(record, public_key_bytes) for record in records]
    except _UnauthenticatingKey:
        # Keep shape-only registration compatible, but never authenticate a
        # weak configured key or advance its high-water mark. Stored evidence
        # takes the separate _load_state fail-closed path above.
        result['error_code'] = 'invalid_public_key'
        return result
    except (ValueError, TypeError, KeyError) as exc:
        raise DHTQueryError('invalid_observation') from exc
    if not checked:
        return result
    current = max(int(record['seq']) for record in checked)
    old_high = int(state['highest_seq']) if state['highest_seq'] is not None else -1
    if current < old_high:
        result['status'] = 'stale_only'
        return result
    if current > old_high:
        state.update(highest_seq=str(current), variants=[], conflict=False, conflict_count=0)
    variants = state['variants']
    for record in checked:
        if (int(record['seq']) == current and len(variants) < 2 and
                all(record['value_hex'] != existing['value_hex'] for existing in variants)):
            variants.append(_evidence(record))
    state['conflict'] = len(variants) == 2
    state['conflict_count'] = 2 if state['conflict'] else 0
    if state['conflict']:
        result['status'] = 'same_seq_conflict'
        return result
    selected = _reverify(variants[0], public_key_bytes)
    if not selected['dns_valid']:
        result['status'] = 'signed_dns_invalid'
        return result
    last = state['last_confirmed']
    result['status'] = ('initial' if last is None else 'unchanged' if
                        last['seq'] == selected['seq'] and last['value_hex'] == selected['value_hex']
                        else 'updated')
    state['last_confirmed'] = _evidence(selected)
    result['record'] = selected
    return result


def _bencode(value):
    if type(value) is bytes:
        return str(len(value)).encode() + b':' + value
    if type(value) is int:
        return b'i' + str(value).encode() + b'e'
    if type(value) is dict and all(type(key) is bytes for key in value):
        return b'd' + b''.join(_bencode(k) + _bencode(value[k]) for k in sorted(value)) + b'e'
    if type(value) is list:
        return b'l' + b''.join(map(_bencode, value)) + b'e'
    raise ValueError('unsupported bencode type')


def _bdecode(data):
    if type(data) is not bytes or not 1 <= len(data) <= _MAX_PACKET:
        raise ValueError('bencode packet bound')
    items = 0

    def parse(pos, depth):
        nonlocal items
        items += 1
        if items > 1024 or depth > 12 or pos >= len(data):
            raise ValueError('bencode work/depth/bounds')
        tag = data[pos:pos + 1]
        if tag == b'i':
            end = data.find(b'e', pos + 1, pos + 23)
            if end < 0 or not re.fullmatch(rb'(0|-?[1-9][0-9]{0,18})', data[pos + 1:end]):
                raise ValueError('bencode integer')
            value = int(data[pos + 1:end])
            if not -(1 << 63) <= value < 1 << 63:
                raise ValueError('bencode int64')
            return value, end + 1
        if tag in (b'd', b'l'):
            value = {} if tag == b'd' else []
            pos += 1
            while pos < len(data) and data[pos:pos + 1] != b'e':
                item, pos = parse(pos, depth + 1)
                if type(value) is dict:
                    if type(item) is not bytes or len(item) > 128 or item in value:
                        raise ValueError('bencode dictionary key')
                    value[item], pos = parse(pos, depth + 1)
                else:
                    value.append(item)
            if pos >= len(data):
                raise ValueError('unterminated bencode')
            return value, pos + 1
        end = data.find(b':', pos, pos + 7)
        if end < 0 or not re.fullmatch(rb'(0|[1-9][0-9]{0,4})', data[pos:end]):
            raise ValueError('bencode byte length')
        size = int(data[pos:end])
        start = end + 1
        if size > _MAX_PACKET or start + size > len(data):
            raise ValueError('bencode byte bounds')
        return data[start:start + size], start + size

    value, end = parse(0, 0)
    if end != len(data):
        raise ValueError('trailing bencode')
    return value


def _make_query(method, transaction, node_id, target):
    if method not in ('get', 'find_node'):
        raise ValueError('only read-only get/find_node queries are permitted')
    if type(transaction) is not bytes or not 1 <= len(transaction) <= 8:
        raise ValueError('transaction size')
    if not all(type(value) is bytes and len(value) == 20 for value in (node_id, target)):
        raise ValueError('node/target size')
    return _bencode({b't': transaction, b'y': b'q', b'q': method.encode(), b'ro': 1,
                     b'a': {b'id': node_id, b'target': target, b'want': [b'n4']}})


_RESOLVER_CODE = '''import socket,sys,json
try:
    rows=socket.getaddrinfo(sys.argv[1],int(sys.argv[2]),socket.AF_INET,socket.SOCK_DGRAM)
    print(json.dumps(list(dict.fromkeys(r[4][0] for r in rows))[:9]))
except OSError:
    print('[]')
'''


class _Stopped(Exception):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def _checkpoint(deadline, cancelled):
    if cancelled is not None and cancelled():
        raise _Stopped('cancelled')
    if time.monotonic() >= deadline:
        raise _Stopped('duration_budget')


def _resolve_addresses(host, port, deadline, cancelled):
    """Own a killable resolver, cap each pipe at 4096 bytes, and always reap it."""
    argv = [sys.executable, '-I', '-c', _RESOLVER_CODE, host, str(port)]
    env = {'PATH': os.defpath, 'LANG': 'C'}
    _checkpoint(deadline, cancelled)
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=env, close_fds=True)
    try:
        child_deadline = min(deadline, time.monotonic() + 5)
        streams = {process.stdout: bytearray(), process.stderr: bytearray()}
        active = set(streams)
        for stream in active:
            os.set_blocking(stream.fileno(), False)
        while active or process.poll() is None:
            _checkpoint(deadline, cancelled)
            remaining = child_deadline - time.monotonic()
            if remaining <= 0:
                raise DHTQueryError('resolver_timeout')
            ready, _, _ = select.select(list(active), [], [], min(.025, remaining))
            for stream in ready:
                buffer = streams[stream]
                chunk = os.read(stream.fileno(), 4097 - len(buffer))
                if not chunk:
                    active.remove(stream)
                    continue
                buffer.extend(chunk)
                if len(buffer) > 4096:
                    raise DHTQueryError('resolver_output_limit')
        _checkpoint(deadline, cancelled)
        if process.returncode:
            raise DHTQueryError('resolver_failed')
        return json.loads(bytes(streams[process.stdout]))
    finally:
        if process.poll() is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        process.wait()
        process.stdout.close()
        process.stderr.close()


def _resolve_bootstraps(bootstraps, deadline, cancelled, coverage):
    peers = []
    try:
        for host, port in bootstraps:
            _checkpoint(deadline, cancelled)
            try:
                ipaddress.IPv4Address(host)
            except ValueError:
                try:
                    addresses = _resolve_addresses(host, port, deadline, cancelled)
                except (OSError, ValueError):
                    coverage['bootstrap_failures'] += 1
                    continue
            else:
                addresses = [host]
            _checkpoint(deadline, cancelled)
            if (type(addresses) is not list or not 1 <= len(addresses) <= 8 or
                    not all(type(ip) is str and _public_peer((ip, port)) for ip in addresses)):
                coverage['bootstrap_rejections'] += 1
                continue
            for ip in addresses:
                if (ip, port) not in peers:
                    peers.append((ip, port))
    except _Stopped as exc:
        coverage['termination'] = exc.reason
        return []
    coverage['bootstrap_peers'] = len(peers)
    return peers


_LOOKUP_SLOTS = threading.BoundedSemaphore(2)


def fetch_dht_records(public_key, options=None, *, cancelled=None):
    """Observe bounded DHT evidence, never connect to decoded DNS addresses.

    Returns {records, coverage}; cancellation additionally sets status='cancelled'
    and clears records. DNS and UDP share one absolute duration deadline. A
    process-wide, nonblocking two-slot admission bound precedes all DNS/socket
    effects. DHTQueryError.code is stable: invalid_public_key, invalid_options,
    invalid_cancelled, crypto_unavailable, capacity. Transport misses/errors are
    described by bounded coverage rather than an authoritative empty record.
    """
    canonical, limits = validate_dht_config(public_key, options)
    if cancelled is not None and not callable(cancelled):
        raise DHTQueryError('invalid_cancelled')
    if not _LOOKUP_SLOTS.acquire(blocking=False):
        raise DHTQueryError('capacity')
    try:
        start = time.monotonic()
        deadline = start + limits['duration']
        coverage = _coverage()
        coverage['limits'] = {key: limits[key] for key in _DEFAULTS}
        records = []
        try:
            _checkpoint(deadline, cancelled)
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(canonical))
            except ImportError as exc:
                raise DHTQueryError('crypto_unavailable') from exc
            # Preflight the point-validation dependency before DNS/UDP. Lookup
            # configuration stays shape-only; record acceptance enforces the
            # returned key policy on every wire and persisted signature.
            _ed25519_public_key_valid(bytes.fromhex(canonical))
            seeds = _resolve_bootstraps([_parse_bootstrap(b) for b in limits['bootstraps']],
                                        deadline, cancelled, coverage)
            if coverage['termination'] in ('cancelled', 'duration_budget'):
                raise _Stopped(coverage['termination'])
            _checkpoint(deadline, cancelled)
            if seeds:
                records = _lookup(bytes.fromhex(canonical), seeds, limits, deadline, cancelled, coverage)
            else:
                coverage['termination'] = 'no_bootstrap'
        except _Stopped as exc:
            coverage['termination'] = exc.reason
        except OSError:
            coverage['termination'] = 'socket_error'
        coverage['elapsed_seconds'] = round(time.monotonic() - start, 3)
        result = {'records': records, 'coverage': coverage}
        # Cancellation stays authoritative even if it arrived during cleanup or
        # after the final receive. The reconciler also fences cancelled evidence.
        if coverage['termination'] == 'cancelled' or (cancelled is not None and cancelled()):
            coverage['termination'] = 'cancelled'
            result.update(status='cancelled', records=[])
        return result
    finally:
        _LOOKUP_SLOTS.release()


def _lookup(public_key, seeds, limits, deadline, cancelled, coverage):
    if (type(seeds) is not list or len(seeds) > 64 or
            any(not _public_peer(peer) for peer in seeds)):
        raise DHTQueryError('invalid_seeds')
    target = hashlib.sha1(public_key).digest()
    target_int = int.from_bytes(target, 'big')
    node_id, prefix = secrets.token_bytes(20), secrets.token_bytes(2)
    unique_seeds = list(dict.fromkeys(seeds))
    seed_drops = max(0, len(unique_seeds) - limits['max_nodes'])
    queue = {(peer, 'find_node'): (-1, None) for peer in unique_seeds[:limits['max_nodes']]}
    attempted, pending, records = set(), {}, []
    coverage.update(initial_queued=len(queue), seed_limit_drops=seed_drops,
                    node_limit_drops=seed_drops, termination='queue_exhausted')
    next_send = time.monotonic()

    def offer(peer, identity, method='get'):
        key = (peer, method)
        if key in attempted or key in queue:
            return
        if not _public_peer(peer):
            coverage['blocked_peers'] += 1
            return
        distance = int.from_bytes(identity, 'big') ^ target_int
        if len(queue) >= limits['max_nodes']:
            worst = max(queue, key=lambda item: queue[item][0])
            coverage['node_limit_drops'] += 1
            if queue[worst][0] <= distance:
                return
            del queue[worst]
        queue[key] = (distance, identity)

    try:
        _checkpoint(deadline, cancelled)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('0.0.0.0', 0))
            sock.setblocking(False)
            while True:
                _checkpoint(deadline, cancelled)
                now = time.monotonic()
                if (coverage['received_packets'] >= limits['max_queries'] * 4 or
                        coverage['received_bytes'] + _MAX_PACKET + 1 > 2097152):
                    coverage['termination'] = 'receive_budget'
                    break
                for key, request in list(pending.items()):
                    if now >= request['expires']:
                        del pending[key]
                        coverage['timeouts'] += 1
                may_send = (queue and len(pending) < limits['concurrency'] and
                            coverage['query_attempts'] < limits['max_queries'])
                if may_send and now >= next_send:
                    item = min(queue, key=lambda key: (queue[key][0], key))
                    _, expected_id = queue.pop(item)
                    peer, method = item
                    attempted.add(item)
                    coverage['query_attempts'] += 1
                    tx = prefix + coverage['query_attempts'].to_bytes(2, 'big')
                    wire = _make_query(method, tx, node_id, target)
                    _checkpoint(deadline, cancelled)
                    send_at = time.monotonic()
                    try:
                        # Numeric vetted snapshot only; sendto cannot re-resolve DNS.
                        sock.sendto(wire, peer)
                    except OSError:
                        coverage['send_errors'] += 1
                    else:
                        pending[(peer, tx)] = dict(expires=min(send_at + limits['timeout'], deadline),
                                                   identity=expected_id, method=method)
                        coverage['queries_sent'] += 1
                        coverage['methods'][method] += 1
                    # Slow preparation or slow send never creates a burst.
                    next_send = time.monotonic() + 1 / limits['rate']
                if not pending and (not queue or coverage['query_attempts'] >= limits['max_queries']):
                    coverage['termination'] = 'query_budget' if queue else 'queue_exhausted'
                    break
                wake = min([deadline, time.monotonic() + .025] + [r['expires'] for r in pending.values()])
                if (queue and len(pending) < limits['concurrency'] and
                        coverage['query_attempts'] < limits['max_queries']):
                    wake = min(wake, next_send)
                ready, _, _ = select.select([sock], [], [], max(0, wake - time.monotonic()))
                _checkpoint(deadline, cancelled)
                if not ready:
                    continue
                try:
                    data, peer = sock.recvfrom(_MAX_PACKET + 1)
                except BlockingIOError:
                    continue
                coverage['received_packets'] += 1
                coverage['received_bytes'] += len(data)
                try:
                    message = _bdecode(data)
                except ValueError:
                    coverage['malformed_datagrams'] += 1
                    continue
                if type(message) is not dict or type(message.get(b't')) is not bytes:
                    coverage['malformed_datagrams'] += 1
                    continue
                match = (peer, message[b't'])
                request = pending.get(match)
                _checkpoint(deadline, cancelled)
                if (request is None or time.monotonic() >= request['expires'] or
                        message.get(b'y') not in (b'r', b'e')):
                    coverage['ignored_datagrams'] += 1
                    continue
                if message[b'y'] == b'e':
                    del pending[match]
                    coverage['replies'] += 1
                    coverage['rpc_errors'] += 1
                    if request['method'] == 'get':
                        offer(peer, request['identity'] or bytes(20), 'find_node')
                    continue
                reply = message.get(b'r')
                if type(reply) is not dict or type(reply.get(b'id')) is not bytes or len(reply[b'id']) != 20:
                    coverage['malformed_datagrams'] += 1
                    continue
                if request['identity'] is not None and reply[b'id'] != request['identity']:
                    coverage['ignored_datagrams'] += 1
                    continue
                del pending[match]
                coverage['replies'] += 1
                if request['method'] == 'get' and b'v' in reply:
                    try:
                        record = _verify_record(reply, public_key)
                    except ValueError:
                        coverage['signature_rejections'] += 1
                    else:
                        _checkpoint(deadline, cancelled)
                        if time.monotonic() < request['expires']:
                            record['source_node'] = list(peer)
                            record['source_node_signed'] = False
                            records.append(record)
                        else:
                            coverage['ignored_datagrams'] += 1
                if request['method'] == 'find_node':
                    offer(peer, reply[b'id'])
                nodes = reply.get(b'nodes', b'')
                if type(nodes) is not bytes or len(nodes) % 26:
                    coverage['malformed_datagrams'] += 1
                    continue
                for pos in range(0, len(nodes), 26):
                    identity = nodes[pos:pos + 20]
                    endpoint = (socket.inet_ntoa(nodes[pos + 20:pos + 24]),
                                struct.unpack_from('!H', nodes, pos + 24)[0])
                    coverage['discovered_nodes'] += 1
                    offer(endpoint, identity)
    except _Stopped as exc:
        coverage['termination'] = exc.reason
    except OSError:
        coverage['termination'] = 'socket_error'
    finally:
        coverage.update(pending_at_stop=len(pending), queued_at_stop=len(queue))
    return records
