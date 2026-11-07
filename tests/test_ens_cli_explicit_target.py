"""CLI target admission and real, loopback-only JSON-RPC compatibility."""
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import ens_ipv6_decoder as cli


def test_rpc_alone_refuses_before_fetch(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(cli, 'fetch_ens_text_record', lambda *a, **k: calls.append((a, k)) or '')
    monkeypatch.setattr(sys, 'argv', ['ens_ipv6_decoder.py', '--rpc', 'http://127.0.0.1:1'])
    with pytest.raises(SystemExit) as caught:
        cli.main()
    assert caught.value.code == 2
    assert calls == []
    assert 'ens_name or --ens-node' in capsys.readouterr().err


@pytest.fixture
def rpc_server():
    calls = []
    raw = '192.0.2.42'
    resolver = '0x' + '12' * 20

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            req = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            calls.append(req)
            method = req['method']
            if method == 'web3_clientVersion':
                result = 'TraceDNS-local-fixture'
            elif method == 'eth_chainId':
                result = '0x1'
            elif method == 'eth_getCode':
                result = '0x01'
            elif method == 'eth_call':
                data = req['params'][0]['data']
                if data[:10] == '0x0178b8bf':  # resolver(bytes32)
                    result = '0x' + '00' * 12 + resolver[2:]
                else:
                    assert data[:10] == '0x59d1d43c'  # text(bytes32,string)
                    encoded = raw.encode()
                    result = '0x' + ((32).to_bytes(32, 'big') + len(encoded).to_bytes(32, 'big')
                                     + encoded.ljust(32, b'\0')).hex()
            else:
                self.send_error(400, 'Unexpected fixture method')
                return
            body = json.dumps({'jsonrpc': '2.0', 'id': req['id'], 'result': result}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}', calls, raw, resolver
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        assert not worker.is_alive()


def invoke(*args):
    env = dict(os.environ, NO_PROXY='127.0.0.1,localhost', no_proxy='127.0.0.1,localhost')
    return subprocess.run([sys.executable, str(ROOT / 'ens_ipv6_decoder.py'), *args],
                          capture_output=True, text=True, timeout=20, cwd=ROOT, env=env)


def test_rpc_alone_emits_no_http_requests(rpc_server):
    url, calls, _, _ = rpc_server
    result = invoke('--rpc', url)
    assert result.returncode == 2, result.stderr
    assert calls == []


@pytest.mark.parametrize('kind', ['name', 'node', 'name-and-node', 'direct-resolver'])
def test_explicit_target_reads_exact_node_and_key(rpc_server, kind):
    web3 = pytest.importorskip('web3')
    url, calls, raw, resolver = rpc_server
    name = 'fixture.example'
    node = b'\x34' * 32
    args = ['--rpc', url, '--key', 'Host', '--decode-method', 'ipv4_literals']
    if kind in ('name', 'name-and-node'):
        args.append(name)
    if kind != 'name':
        args += ['--ens-node', '0x' + node.hex()]
    else:
        node = b'\0' * 32
        for label in reversed(name.split('.')):
            node = web3.Web3.keccak(node + web3.Web3.keccak(text=label))
    if kind == 'direct-resolver':
        args += ['--ens-resolver', resolver]
    result = invoke(*args)
    assert result.returncode == 0, result.stderr
    assert raw in result.stdout
    text_calls = [r for r in calls if r['method'] == 'eth_call'
                  and r['params'][0]['data'].startswith('0x59d1d43c')]
    assert len(text_calls) == 1
    call = text_calls[0]['params'][0]
    data = bytes.fromhex(call['data'][10:])
    assert data[:32] == node
    offset = int.from_bytes(data[32:64], 'big')
    size = int.from_bytes(data[offset:offset + 32], 'big')
    assert data[offset + 32:offset + 32 + size] == b'Host'
    assert call['to'].lower() == resolver
    registry_calls = [r for r in calls if r['method'] == 'eth_call'
                      and r['params'][0]['data'].startswith('0x0178b8bf')]
    assert len(registry_calls) == (0 if kind == 'direct-resolver' else 1)


def test_same_process_ens_then_misp_attribute_and_sighting(rpc_server, monkeypatch):
    pytest.importorskip('web3')
    from pymisp import MISPAttribute, MISPSighting, PyMISP
    from ens_query import fetch_ens_text_record
    monkeypatch.setenv('NO_PROXY', '127.0.0.1,localhost')
    monkeypatch.setenv('no_proxy', '127.0.0.1,localhost')
    url, rpc_calls, expected, resolver = rpc_server
    value = fetch_ens_text_record(url, 'fixture.example', 'Host', resolver_address=resolver)
    assert value == expected
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path == '/servers/getVersion':
                body = {'version': '2.4.198', 'pymisp_recommended_version': '2.4.198'}
            elif self.path == '/servers/getPyMISPVersion.json':
                body = {'version': '2.4.198'}
            elif self.path == '/users/view/me':
                body = {'User': {'id': '1', 'email': 'fixture@example.invalid'},
                        'Role': {'id': '1', 'name': 'admin'}, 'UserSetting': {}}
            elif self.path == '/attributes/describeTypes.json':
                body = {'result': {'categories': ['Network activity'], 'types': ['ip-dst'],
                                  'category_type_mappings': {'Network activity': ['ip-dst']},
                                  'sane_defaults': {'ip-dst': {'default_category': 'Network activity',
                                                             'to_ids': 1}}}}
            else:
                self.send_error(404)
                return
            self.respond(body)

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            requests.append((self.path, body))
            if self.path == '/attributes/add/1':
                self.respond({'Attribute': dict(body, id='42', event_id='1')})
            elif self.path == '/sightings/add/42':
                self.respond({'Sighting': dict(body, id='7', attribute_id='42')})
            else:
                self.send_error(404)

        def respond(self, body):
            wire = json.dumps(body).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(wire)))
            self.end_headers()
            self.wfile.write(wire)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = PyMISP(f'http://127.0.0.1:{server.server_port}', 'synthetic-fixture-key', timeout=2)
        attribute = MISPAttribute()
        attribute.from_dict(type='ip-dst', value=value, category='Network activity', to_ids=True)
        added = client.add_attribute(1, attribute)
        assert added['Attribute']['value'] == expected
        sighting = MISPSighting()
        sighting.from_dict(value=value, type=0, source='local-regression')
        result = client.add_sighting(sighting, attribute=42)
        assert result['Sighting']['attribute_id'] == '42'
        assert [path for path, _ in requests] == ['/attributes/add/1', '/sightings/add/42']
        assert all(body['value'] == expected for _, body in requests)
        assert any(r['method'] == 'eth_call' for r in rpc_calls)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()
