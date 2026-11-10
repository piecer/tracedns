"""Polygon contract C2 profile: synthetic encrypted inputs, never C2 contact."""
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY = bytes.fromhex('805c5098c496b1e3ee6b2f8a00adf088')
PLAINTEXT = (
    '# synthetic configuration\r\n192.0.2.10:18082\n'
    'j 192.0.2.10:18082, J 198.51.100.20:443\n'
    'r 203.0.113.30:443\nm http://203.0.113.40/d/m\n'
    'ma http://203.0.113.41/d/a\nw wallet-example\n'
    'p 203.0.113.50:3333\np2 203.0.113.51:3333\n'
    'l http://203.0.113.60\n'
)


def abi_blob(blob):
    return '0x' + ((32).to_bytes(32, 'big') + len(blob).to_bytes(32, 'big')
                   + blob + bytes((-len(blob)) % 32)).hex()


def encrypted_result(plaintext=PLAINTEXT, nonce=bytes(range(12))):
    # Test-only deterministic nonce. No application encryption functionality.
    raw = plaintext.encode() if isinstance(plaintext, str) else plaintext
    return abi_blob(nonce + AESGCM(KEY).encrypt(nonce, raw, None))


def test_authenticated_c2_extraction_keeps_roles_and_raw_evidence_separate():
    from rpc_query import decode_polygon_result
    result = encrypted_result()
    record = decode_polygon_result(result)
    assert record['raw_result'] == result
    assert record['plaintext'] == PLAINTEXT
    assert record['authentication'] == 'aes-128-gcm'
    assert record['decoded_endpoints'] == ['192.0.2.10:18082', '198.51.100.20:443']
    assert record['decoded_ips'] == ['192.0.2.10', '198.51.100.20']
    assert record['roles'] == {
        'relay': ['203.0.113.30:443'],
        'download': ['http://203.0.113.40/d/m'],
        'download_alt': ['http://203.0.113.41/d/a'],
        'wallet': ['wallet-example'],
        'pool': ['203.0.113.50:3333'],
        'pool_alt': ['203.0.113.51:3333'],
        'ignored': ['l http://203.0.113.60'],
    }


def test_captured_public_rpc_matches_report_known_answer():
    import json
    from pathlib import Path
    from rpc_query import decode_polygon_result
    corpus = json.loads((Path(__file__).resolve().parents[1] / 'docs/rpc/polygon-aes-gcm-observation.json').read_text())
    record = decode_polygon_result(corpus['raw_result'])
    assert len(bytes.fromhex(corpus['raw_result'][2:])) == 608
    assert len(record['plaintext'].encode()) == 515
    assert record['decoded_endpoints'] == corpus['decoded_endpoints']
    assert record['decoded_ips'] == corpus['decoded_ips']
    assert record['roles']['relay'] == ['185.100.87.214:443']


def test_cli_decodes_saved_json_without_network(tmp_path):
    import json
    from pathlib import Path
    import subprocess
    import sys
    root = Path(__file__).resolve().parents[1]
    saved = tmp_path / 'rpc-response.json'
    saved.write_text(json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': encrypted_result()}))
    process = subprocess.run([sys.executable, str(root / 'rpc_query.py'), '--input', str(saved), '--json'],
                             text=True, capture_output=True, timeout=10)
    assert process.returncode == 0, process.stderr
    assert process.stdout.strip(), 'CLI produced no decoded result'
    record = json.loads(process.stdout)
    assert record['decoded_endpoints'] == ['192.0.2.10:18082', '198.51.100.20:443']
    saved.write_text('{"result":"0x"}')
    process = subprocess.run([sys.executable, str(root / 'rpc_query.py'), '--input', str(saved)],
                             text=True, capture_output=True, timeout=10)
    assert process.returncode != 0
    assert process.stdout == ''
    assert 'rpc_invalid_abi' in process.stderr


@pytest.mark.parametrize('part', ['nonce', 'ciphertext', 'tag'])
def test_authentication_failure_never_parses_plaintext(monkeypatch, part):
    import rpc_query
    raw = bytearray.fromhex(encrypted_result()[2:])
    length = int.from_bytes(raw[32:64], 'big')
    index = {'nonce': 64, 'ciphertext': 76, 'tag': 64 + length - 1}[part]
    raw[index] ^= 1
    monkeypatch.setattr(rpc_query, '_parse_settings', lambda _: pytest.fail('unauthenticated parse'))
    with pytest.raises(rpc_query.RpcQueryError, match='rpc_auth_failed'):
        rpc_query.decode_polygon_result('0x' + raw.hex())


@pytest.mark.parametrize('variant', ['offset', 'length', 'overflow', 'padding', 'truncated',
                                     'trailing', 'odd', 'whitespace', 'nonhex', 'oversize'])
def test_malformed_abi_is_rejected(variant):
    from rpc_query import decode_polygon_result, RpcQueryError
    raw = bytearray.fromhex(encrypted_result()[2:])
    if variant == 'offset':
        raw[31] = 64
    elif variant == 'length':
        raw[32:64] = (1429).to_bytes(32, 'big')
    elif variant == 'overflow':
        raw[32] = 1
    elif variant == 'padding':
        raw[-1] = 1
    elif variant == 'truncated':
        raw = raw[:-1]
    elif variant == 'trailing':
        raw += bytes(32)
    result = '0x' + raw.hex()
    result = {'odd': result[:-1], 'whitespace': result + ' ', 'nonhex': '0xgg',
              'oversize': '0x' + '00' * 2049}.get(variant, result)
    with pytest.raises(RpcQueryError, match='rpc_invalid_abi'):
        decode_polygon_result(result)


def test_endpoint_validation_port_identity_and_cap():
    from rpc_query import decode_polygon_result
    invalid = ['0.0.0.0:1', '255.255.255.255:1', '192.0.2.1:0', '192.0.2.1:65536',
               '999.1.1.1:80', '192.0.2.01:80', '192.0.2.1:+80', '[::1]:80',
               'm http://198.51.100.2:8080/download']
    valid = ['192.0.2.1:1', 'j 192.0.2.1:65535'] + [f'192.0.2.{i}:80' for i in range(2, 30)]
    result = decode_polygon_result(encrypted_result('\n'.join(invalid + valid)))
    assert len(result['decoded_endpoints']) == 24
    assert result['decoded_endpoints'][:2] == ['192.0.2.1:1', '192.0.2.1:65535']
    assert len(result['decoded_ips']) == 23
    assert '198.51.100.2' not in result['decoded_ips']


def test_authenticated_non_text_is_rejected():
    from rpc_query import decode_polygon_result, RpcQueryError
    with pytest.raises(RpcQueryError, match='rpc_invalid_plaintext'):
        decode_polygon_result(encrypted_result(b'\xff'))


def test_rpc_fallback_requires_authenticated_c2_and_exact_request(monkeypatch):
    import rpc_query
    calls = []
    responses = iter([
        {'jsonrpc': '2.0', 'id': 1, 'error': {'message': 'untrusted'}},
        {'jsonrpc': '2.0', 'id': 1, 'result': abi_blob(bytes(29))},
        {'jsonrpc': '2.0', 'id': 1, 'result': encrypted_result('r 203.0.113.1:443')},
        {'jsonrpc': '2.0', 'id': 1, 'result': encrypted_result()},
    ])

    def post(url, payload, timeout):
        calls.append((url, payload, timeout))
        return next(responses)

    monkeypatch.setattr(rpc_query, '_post_rpc', post, raising=False)
    result = rpc_query.fetch_rpc_config()
    assert [call[0] for call in calls] == list(rpc_query.RPC_URLS)
    assert all(call[1] == {
        'jsonrpc': '2.0', 'method': 'eth_call',
        'params': [{'to': '0x5D5abC33a4e5C602a002815d93806b204324D1a1', 'data': '0x6d4ce63c'}, 'latest'],
        'id': 1,
    } for call in calls)
    assert result['source_rpc'] == rpc_query.RPC_URLS[-1]
    assert result['decoded_endpoints'] == ['192.0.2.10:18082', '198.51.100.20:443']
    assert result['attempts'] == [
        {'provider': 1, 'status': 'rpc_response_error'},
        {'provider': 2, 'status': 'rpc_auth_failed'},
        {'provider': 3, 'status': 'rpc_no_c2'},
        {'provider': 4, 'status': 'ok'},
    ]


@pytest.mark.parametrize('response', [[], {}, {'jsonrpc': '1.0', 'id': 1, 'result': '0x'},
                                    {'jsonrpc': '2.0', 'id': True, 'result': '0x'},
                                    {'jsonrpc': '2.0', 'id': 2, 'result': '0x'}])
def test_invalid_envelope_cannot_be_accepted(monkeypatch, response):
    import rpc_query
    monkeypatch.setattr(rpc_query, '_post_rpc', lambda *args: response, raising=False)
    with pytest.raises(rpc_query.RpcQueryError, match='rpc_response_error'):
        rpc_query.fetch_rpc_config()


def test_cancelled_lookup_stops_before_any_request(monkeypatch):
    import rpc_query
    from lookup_context import lookup_scope
    monkeypatch.setattr(rpc_query, '_post_rpc', lambda *args: pytest.fail('cancelled request'), raising=False)
    with lookup_scope(lambda: True, lambda: 20):
        with pytest.raises(TimeoutError):
            rpc_query.fetch_rpc_config()


def test_unknown_profile_is_refused_before_network(monkeypatch):
    import rpc_query
    monkeypatch.setattr(rpc_query, '_post_rpc', lambda *args: pytest.fail('invalid profile'), raising=False)
    with pytest.raises(rpc_query.RpcQueryError, match='rpc_invalid_profile'):
        rpc_query.fetch_rpc_config('polygon_aes_gcm_v1 ')


@pytest.mark.parametrize('status, encoding, body, expected', [
    (200, '', b'{"jsonrpc":"2.0","id":1,"result":"0x"}', None),
    (302, '', b'x' * 20000, 'rpc_http_status'),
    (500, '', b'sensitive-body', 'rpc_http_status'),
    (200, 'gzip', b'sensitive-body', 'rpc_content_encoding'),
    (200, '', b'x' * 8193, 'rpc_body_limit'),
    (200, '', b'sensitive-body', 'rpc_invalid_json'),
], ids=['ok', 'redirect', 'server_error', 'compressed', 'oversize', 'invalid_json'])
def test_real_session_transport_bounds_and_closes(monkeypatch, status, encoding, body, expected):
    import io
    import requests
    import rpc_query

    class Raw:
        closed = True  # Fully buffered adapter body; no live socket needed.

        def __init__(self):
            self.body = io.BytesIO(body)
            self.reads = []
            self.did_close = False

        def read1(self, amount, decode_content=False):
            self.reads.append(amount)
            return self.body.read(amount)

        def close(self):
            self.did_close = True

        def release_conn(self):
            pass

    raw = Raw()
    seen = []

    class Adapter(requests.adapters.BaseAdapter):
        def send(self, request, **kwargs):
            seen.append((request, kwargs))
            response = requests.Response()
            response.status_code = status
            response.headers = {'Content-Encoding': encoding, 'Location': 'http://127.0.0.1/private'}
            response.raw = raw
            response.request = request
            response.url = request.url
            return response

        def close(self):
            pass

    monkeypatch.setattr(requests.Session, 'get_adapter', lambda *args, **kwargs: Adapter())
    if expected:
        with pytest.raises(rpc_query.RpcQueryError, match=expected):
            rpc_query._post_rpc(rpc_query.RPC_URLS[0], {'id': 1}, 2)
    else:
        assert rpc_query._post_rpc(rpc_query.RPC_URLS[0], {'id': 1}, 2)['id'] == 1
    assert len(seen) == 1
    assert seen[0][1]['verify'] is True
    assert seen[0][1]['stream'] is True
    assert seen[0][1]['proxies'] == {}
    assert 0 < seen[0][1]['timeout'] <= 2
    assert raw.did_close
    if status != 200 or encoding:
        assert raw.reads == []
    assert all(amount <= 1024 for amount in raw.reads)
