"""Subprocess-only real main canaries; no external network or credentials."""
import json
import logging
import os
from pathlib import Path
import socket
import sys

SOURCE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(SOURCE), str(SOURCE / 'tests')]

import dns_monitor
import history_manager
from monitor import collect, delivery_runtime, engine
from security.store import SecurityStore
from test_delivery_adapters_steps import Transport
from test_http_auth_integration import Client

SECRET = 'SYNTHETIC_DIAGNOSTIC_CANARY_715'
ENDPOINT = 'https://user:' + SECRET + '@provider.invalid/' + SECRET + '?key=' + SECRET
RAW = 'raw-observation-' + SECRET
rtype, mode, directory = sys.argv[1:]
work = Path(directory)
work.mkdir(parents=True, exist_ok=True)
original_connect = socket.socket.connect


def connect(sock, address):
    if isinstance(address, tuple) and address[0] not in ('127.0.0.1', '::1'):
        raise AssertionError('external network forbidden')
    return original_connect(sock, address)


socket.socket.connect = connect
socket.socket.connect_ex = lambda *_: (_ for _ in ()).throw(AssertionError('connect_ex forbidden'))
security = SecurityStore(work / 'auth' / 'auth.sqlite', create=True)
security.bootstrap('root', 'test-password-123')
config = {'domains': [{'name': 'fixture.example', 'type': rtype,
                      'ens_decode': 'ipv4_literals', 'sns_decode': 'ipv4_literals'}],
          'servers': [ENDPOINT], 'ens_rpc_url': ENDPOINT,
          'DEFAULT_SNS_PROXY_HOSTS': [ENDPOINT], 'DEFAULT_SOLAR_PROXY_HOSTS': [ENDPOINT],
          'interval': 1, 'alerts': {}}
config_path = work / 'cfg.json'
config_path.write_text(json.dumps(config))
sys.argv = ['dns_monitor.py', '--config', str(config_path), '--security-db',
            str(work / 'auth' / 'auth.sqlite'), '--insecure-http', '--http-port', '0']
os.environ['TRACEDNS_LOG_LEVEL'] = 'DEBUG'
captured = {}
original_runtime = delivery_runtime.DeliveryRuntime
original_server = dns_monitor.ThreadingHTTPServer


def runtime(*args, **kw):
    captured['runtime'] = original_runtime(*args, **kw, transport=Transport())
    return captured['runtime']


def server(*args, **kw):
    captured['server'] = original_server(*args, **kw)
    return captured['server']


delivery_runtime.DeliveryRuntime = runtime
dns_monitor.ThreadingHTTPServer = server
phase = ['init']


def fetch(*args, **kw):
    if phase[0] == 'error':
        if rtype == 'A':
            return {'status': 'error', 'values': [], 'error': ENDPOINT + ' /private/' + SECRET}
        if rtype == 'ENS':
            from ens_query import EnsQueryError
            raise EnsQueryError('rpc_not_connected', SECRET, rpc_url=ENDPOINT,
                                cause=OSError('/private/CA/' + SECRET))
        raise TimeoutError('URL=' + ENDPOINT + ' CA=/private/' + SECRET)
    ip = '192.0.2.12' if phase[0] == 'change' else '192.0.2.11'
    if rtype == 'A':
        return {'status': 'nxdomain' if phase[0] == 'nxdomain' else 'ok',
                'values': [] if phase[0] == 'nxdomain' else [ip, RAW]}
    return ip + ' ' + RAW


collect.fetch_sns_record = fetch
collect.fetch_ens_text_record = fetch
collect.query_dns = fetch
if mode == 'worker':
    def worker_fault(*args, **kw):
        raise RuntimeError('URL=' + ENDPOINT + ' CA=/private/' + SECRET)
    engine.collect_snapshot = worker_fault

original_cycle = dns_monitor.run_full_cycle
original_makedirs = history_manager.os.makedirs
snapshots = []


def cycle(**kw):
    if mode == 'history':
        def makedirs(path, *args, **kwargs):
            if str(path) == kw['history_dir']:
                raise OSError('private path /' + SECRET)
            return original_makedirs(path, *args, **kwargs)
        history_manager.os.makedirs = makedirs
        def failed_tempfile(*args, **kwargs):
            raise OSError('private file /' + SECRET)
        history_manager.tempfile.NamedTemporaryFile = failed_tempfile
    phases = ['init', 'same', 'change', 'error', 'error', 'error', 'nxdomain'] if mode == 'cycles' else ['init']
    for value in phases:
        phase[0] = value
        result = original_cycle(**kw)
        snapshots.append(json.loads(json.dumps({'current': kw['current_results'], 'history': kw['history']})))
        if mode == 'cycles':
            assert history_manager.load_history_files(kw['history_dir']) == snapshots[-1]['history']
    owner = captured['runtime']
    client = Client(captured['server'].server_port)
    assert client.login()[0] == 200
    diagnostics = []
    for route in ('/delivery-health', '/api/v1/delivery-health'):
        status, payload = client.call('GET', route)
        assert status == 200
        assert SECRET not in json.dumps(payload)
        if mode == 'history':
            assert payload['last_error'] == 'history_persistence'
        diagnostics.append(payload)
    captured['diagnostics'] = diagnostics
    owner.config.raw['_monitor_stopped'] = True
    return result


dns_monitor.run_full_cycle = cycle
if mode == 'security':
    import security.startup
    def security_fault(_):
        raise OSError('security path /private/' + SECRET)
    security.startup.open_security = security_fault
    try:
        dns_monitor.main()
    except SystemExit as exc:
        assert exc.code == 2
elif mode == 'cli_start':
    import runpy
    import threading
    original_start = threading.Thread.start
    def failed_start(thread):
        if thread.name == 'delivery-worker':
            raise RuntimeError('startup URL=' + ENDPOINT + ' /private/' + SECRET)
        return original_start(thread)
    threading.Thread.start = failed_start
    try:
        runpy.run_module('dns_monitor', run_name='__main__')
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError('CLI must fail closed')
    assert captured['runtime'].store._closed
else:
    dns_monitor.main()
    assert captured['runtime'].store._closed
    assert captured['server'].socket.fileno() == -1
    if mode in ('cycles', 'history'):
        first = snapshots[0]
        target = next(iter(first['current']))
        raw = first['current'][target][ENDPOINT]['values']
        assert raw == (['192.0.2.11', RAW] if rtype == 'A' else ['192.0.2.11 ' + RAW])
        assert first['history'][target]['current'][ENDPOINT]['values'] == raw
        decoded = first['current'][target][ENDPOINT]['decoded_ips']
        assert decoded == ([] if rtype == 'A' else ['192.0.2.11'])
        # Provider keys and canonical raw facts are not diagnostic strings.
        if mode == 'cycles':
            changed = snapshots[2]['history'][target]
            assert changed['events'][-1]['server'] == ENDPOINT
            assert changed['events'][-1]['old']['values'] == raw
            assert RAW in str(changed['events'][-1]['new']['values'])
            assert ENDPOINT not in snapshots[5]['current'][target]
    history_manager.os.makedirs = original_makedirs
logging.shutdown()
(work / 'evidence.json').write_text(json.dumps({'type': rtype, 'mode': mode, 'snapshots': snapshots,
    'http_diagnostics': captured.get('diagnostics'), 'completed': True}, indent=2))
print('real_main_completed')
