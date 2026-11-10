"""Read-only Polygon contract C2 profile recovered in rpc.txt.

RPC infrastructure is not C2. Only authenticated configuration endpoints are
promoted; no discovered endpoint, URL, relay or mining pool is ever contacted.
"""
from __future__ import annotations

import ipaddress
import json
import re
import time

import requests

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from lookup_context import checkpoint, transport_timeout

PROFILE = 'polygon_aes_gcm_v1'
PROVIDER = 'RPC:' + PROFILE
CONTRACT = '0x5D5abC33a4e5C602a002815d93806b204324D1a1'
SELECTOR = '0x6d4ce63c'
# Public sample configuration key, not a service credential.
_CONFIG_KEY = bytes.fromhex('805c5098c496b1e3ee6b2f8a00adf088')
RPC_URLS = (
    'https://1rpc.io/matic',
    'https://polygon.gateway.tenderly.co/',
    'https://polygon-bor.publicnode.com/',
    'https://polygon.drpc.org/',
)


class RpcQueryError(ValueError):
    """Closed reason codes: never include response bodies or exception text."""

    def __init__(self, code):
        self.code = code
        self.attempts = []
        super().__init__(code)


def _endpoint(value):
    match = re.fullmatch(r'([0-9]+(?:\.[0-9]+){3}):([0-9]{1,5})', value)
    if match is None:
        return None
    try:
        ip = ipaddress.IPv4Address(match[1])
    except ipaddress.AddressValueError:
        return None
    port = int(match[2])
    if int(ip) in (0, 0xffffffff) or not 1 <= port <= 65535:
        return None
    return f'{ip}:{port}'


def _parse_settings(plaintext):
    endpoints = []
    roles = {key: [] for key in ('relay', 'download', 'download_alt', 'wallet', 'pool', 'pool_alt', 'ignored')}
    prefixes = {'r': 'relay', 'm': 'download', 'ma': 'download_alt',
                'w': 'wallet', 'p': 'pool', 'p2': 'pool_alt'}
    for line in re.split(r'[\r\n,]', plaintext):
        line = line.strip()
        if not line or line.startswith(('#', ';', '//')):
            continue
        parts = line.split(None, 1)
        prefix = parts[0].lower()
        if prefix in prefixes and len(parts) == 2:
            roles[prefixes[prefix]].append(parts[1])
            continue
        value = parts[1] if prefix == 'j' and len(parts) == 2 else line
        endpoint = _endpoint(value)
        if endpoint is not None:
            if endpoint not in endpoints and len(endpoints) < 24:
                endpoints.append(endpoint)
        else:
            roles['ignored'].append(line)
    return endpoints, roles


def decode_polygon_result(result):
    """Validate canonical ABI bytes, authenticate GCM, then parse C2 roles."""
    if (type(result) is not str or not result.startswith('0x') or len(result) > 4098
            or not re.fullmatch(r'0x(?:[0-9a-fA-F]{2})+', result)):
        raise RpcQueryError('rpc_invalid_abi')
    raw = bytes.fromhex(result[2:])
    if len(raw) < 64 or int.from_bytes(raw[:32], 'big') != 32:
        raise RpcQueryError('rpc_invalid_abi')
    length = int.from_bytes(raw[32:64], 'big')
    padded = (length + 31) // 32 * 32
    if not 29 <= length <= 1428 or len(raw) != 64 + padded or any(raw[64 + length:]):
        raise RpcQueryError('rpc_invalid_abi')
    blob = raw[64:64 + length]
    try:
        plaintext = AESGCM(_CONFIG_KEY).decrypt(blob[:12], blob[12:], None).decode('utf-8')
    except InvalidTag:
        raise RpcQueryError('rpc_auth_failed') from None
    except UnicodeDecodeError:
        raise RpcQueryError('rpc_invalid_plaintext') from None
    endpoints, roles = _parse_settings(plaintext)
    return {
        'profile': PROFILE, 'chain_id': 137, 'contract': CONTRACT,
        'selector': SELECTOR, 'block': 'latest', 'authentication': 'aes-128-gcm',
        'raw_result': result, 'plaintext': plaintext,
        'decoded_ips': list(dict.fromkeys(ep.split(':')[0] for ep in endpoints)),
        'decoded_endpoints': endpoints, 'roles': roles,
    }


class _RpcSession(requests.Session):
    def resolve_redirects(self, *args, **kwargs):
        # Requests would otherwise consume even a refused redirect's body while
        # preparing Response.next, bypassing the streaming byte/deadline cap.
        return iter(())


def _remaining(deadline):
    remaining = transport_timeout(deadline - time.monotonic())
    if remaining <= 0:
        raise RpcQueryError('rpc_timeout')
    return remaining


def _post_rpc(url, payload, timeout):
    deadline = time.monotonic() + transport_timeout(timeout)
    with _RpcSession() as session:
        session.trust_env = False
        response = session.post(url, json=payload, timeout=_remaining(deadline),
                                verify=True, stream=True, allow_redirects=False,
                                headers={'Accept-Encoding': 'identity', 'Accept': 'application/json',
                                         'User-Agent': 'tracedns-rpc/1.0'})
        try:
            _remaining(deadline)
            if not 200 <= response.status_code < 300:
                raise RpcQueryError('rpc_http_status')
            if response.headers.get('Content-Encoding', '').strip().lower() not in ('', 'identity'):
                raise RpcQueryError('rpc_content_encoding')
            body = bytearray()
            raw = response.raw
            while True:
                remaining = _remaining(deadline)
                sock = getattr(getattr(raw, '_connection', None), 'sock', None)
                if sock is None:
                    fp = getattr(getattr(raw, '_fp', None), 'fp', None)
                    sock = getattr(getattr(fp, 'raw', None), '_sock', None)
                if sock is not None:
                    sock.settimeout(remaining)
                elif not raw.closed:
                    raise RpcQueryError('rpc_read_timeout_unavailable')
                chunk = raw.read1(1024, decode_content=False)
                _remaining(deadline)
                if len(body) + len(chunk) > 8192:
                    raise RpcQueryError('rpc_body_limit')
                if not chunk:
                    break
                body.extend(chunk)
            try:
                result = json.loads(body)
            except (ValueError, RecursionError):
                raise RpcQueryError('rpc_invalid_json') from None
            _remaining(deadline)
            return result
        finally:
            response.close()


def fetch_rpc_config(profile=PROFILE):
    """Read the fixed profile, trying public providers in sample order.

    Each attempt has an 8-second cooperative budget; the enclosing monitor's
    original cancellation/deadline is checked before/after all work. Native DNS
    and socket calls retain the owning lookup worker until they actually return.
    """
    if type(profile) is not str or profile != PROFILE:
        raise RpcQueryError('rpc_invalid_profile')
    payload = {'jsonrpc': '2.0', 'method': 'eth_call',
               'params': [{'to': CONTRACT, 'data': SELECTOR}, 'latest'], 'id': 1}
    attempts = []
    for slot, url in enumerate(RPC_URLS, 1):
        checkpoint()
        try:
            response = _post_rpc(url, payload, transport_timeout(8))
            checkpoint()
            if (type(response) is not dict or response.get('jsonrpc') != '2.0'
                    or type(response.get('id')) is not int or response['id'] != 1
                    or 'error' in response or 'result' not in response):
                raise RpcQueryError('rpc_response_error')
            record = decode_polygon_result(response['result'])
            checkpoint()
            if not record['decoded_endpoints']:
                raise RpcQueryError('rpc_no_c2')
            attempts.append({'provider': slot, 'status': 'ok'})
            return {**record, 'source_rpc': url, 'attempts': attempts}
        except Exception as error:
            checkpoint()  # Cancellation/owner expiry never starts a fallback.
            if isinstance(error, RpcQueryError):
                reason = error.code
            elif isinstance(error, requests.exceptions.SSLError):
                reason = 'query_tls'
            elif isinstance(error, (requests.exceptions.Timeout, TimeoutError)):
                reason = 'rpc_timeout'
            else:
                reason = 'query_transport'
            attempts.append({'provider': slot, 'status': reason})
    error = RpcQueryError(attempts[-1]['status'])
    error.attempts = attempts
    raise error


def main(argv=None):
    """Print decoded endpoints, or full JSON; --input is strictly offline."""
    import argparse
    import sys
    parser = argparse.ArgumentParser(description='Read-only Polygon RPC C2 configuration decoder (no C2 contact)')
    parser.add_argument('--input', help='Offline JSON-RPC response or captured raw_result JSON file')
    parser.add_argument('--json', action='store_true', help='Include authenticated plaintext and separate auxiliary roles')
    args = parser.parse_args(argv)
    try:
        if args.input:
            with open(args.input, 'rb') as stream:
                data = stream.read(8193)
            if len(data) > 8192:
                raise RpcQueryError('rpc_body_limit')
            payload = json.loads(data)
            if not isinstance(payload, dict):
                raise RpcQueryError('rpc_invalid_json')
            record = decode_polygon_result(payload.get('result', payload.get('raw_result')))
        else:
            record = fetch_rpc_config()
    except (OSError, ValueError, RecursionError) as error:
        code = error.code if isinstance(error, RpcQueryError) else 'rpc_input_error'
        print(code, file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(record, indent=2, ensure_ascii=False))
    else:
        print('\n'.join(record['decoded_endpoints']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
