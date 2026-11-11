"""Actual app and delivery worker with offline RPC/provider transports only."""
import json
import os
from pathlib import Path
import sys
import threading
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import dns_monitor
import rpc_query
from models import DomainSpec
from monitor.engine import run_domain_cycle
from monitor.delivery_adapters import DestinationRegistry
from security.store import SecurityStore


class Response:
    status_code = 200
    headers = {}

    def __init__(self, body=None):
        self.body = json.dumps(body).encode()

    def iter_content(self, chunk_size):
        for start in range(0, len(self.body), chunk_size):
            yield self.body[start:start + chunk_size]

    def close(self):
        pass


class OfflineProvider:
    def __init__(self, state):
        self.state = state
        self.lock = threading.Lock()
        self.attributes_path = state / 'provider-attributes.json'
        self.attributes = (json.loads(self.attributes_path.read_text())
                           if self.attributes_path.exists() else [])

    def request(self, method, url, **kwargs):
        with self.lock:
            data = json.loads(kwargs['data']) if kwargs.get('data') else None
            if url == 'https://teams.invalid/offline-resend' and method == 'POST':
                record = {'channel': 'teams', 'operation': 'send', 'body': data}
                reply = None
            elif url == 'https://misp.invalid/events/view/12' and method == 'GET':
                record = {'channel': 'misp', 'operation': 'read'}
                reply = {'Event': {'id': '12', 'Attribute': list(self.attributes)}}
            elif url == 'https://misp.invalid/attributes/add/12' and method == 'POST':
                assert data['type'] == 'ip-src'
                assert not any(a['value'] == data['value'] for a in self.attributes)
                item = dict(data, id=str(len(self.attributes) + 1), event_id='12')
                self.attributes.append(item)
                self.attributes_path.write_text(json.dumps(self.attributes))
                record = {'channel': 'misp', 'operation': 'add', 'ip': data['value']}
                reply = {'Attribute': item}
            elif url.startswith('https://misp.invalid/sightings/add/') and method == 'POST':
                identifier = url.rsplit('/', 1)[-1]
                assert any(a['id'] == identifier for a in self.attributes)
                record = {'channel': 'misp', 'operation': 'sighting'}
                reply = {'Sighting': {'id': '1', 'event_id': '12', 'attribute_id': identifier, 'type': '0'}}
            else:
                raise AssertionError('Unexpected outbound fixture operation')
            with (self.state / 'provider-calls.jsonl').open('a') as output:
                output.write(json.dumps(record) + '\n')
            return Response(reply)


def main():
    state = Path(sys.argv[1]).resolve()
    state.mkdir(parents=True, exist_ok=True)
    os.chdir(state)
    os.environ['MISP_SIGHTING_BATCH_FILE'] = str(state / 'fixture-sightings.json')
    blocked = []

    def audit(event, args):
        if event == 'open' and isinstance(args[0], (str, bytes)):
            opened = Path(os.fsdecode(args[0])).absolute()
            if opened in (ROOT / 'misp_sighting_batch.json', ROOT / 'misp_sighting_batch.json.tmp'):
                blocked.append('default_sightings_access')
                raise AssertionError('Repository sightings state is outside this fixture')
        if event in ('socket.connect', 'socket.sendto'):
            address = args[-1]
            if isinstance(address, tuple) and address[0] not in ('127.0.0.1', '::1'):
                blocked.append(event)
                raise AssertionError('No external traffic in resend acceptance')

    sys.addaudithook(audit)
    corpus = json.loads((ROOT / 'docs/rpc/polygon-aes-gcm-observation.json').read_text())

    def replay(url, payload, timeout):
        assert url in rpc_query.RPC_URLS
        assert payload['method'] == 'eth_call'
        assert payload['params'][0] == {'to': rpc_query.CONTRACT, 'data': rpc_query.SELECTOR}
        return {'jsonrpc': '2.0', 'id': 1, 'result': corpus['raw_result']}

    rpc_query._post_rpc = replay
    db = state / 'auth.sqlite'
    first = not db.exists()
    security = SecurityStore(db, create=first)
    if first:
        admin = security.bootstrap('admin', 'test-admin-password')
        for role in ('operator', 'viewer'):
            user = security.create_user(role, 'temporary-role-password', role, actor=admin)
            security.change_password(user['id'], 'temporary-role-password', 'test-role-password', actor=user)
    config = state / 'config.json'
    if not config.exists():
        domains = [{'name': name, 'type': 'RPC', 'rpc_profile': rpc_query.PROFILE}
                   for name in ('Resend RPC', 'Other RPC')]
        config.write_text(json.dumps({'domains': domains, 'servers': [], 'interval': 3600,
            'alerts': {'teams_webhook': 'https://teams.invalid/offline-resend',
                       'misp_url': 'https://misp.invalid', 'api_key': 'offline-fixture-only',
                       'push_event_id': 12}}))
        # Produce genuine saved evidence before delivery bootstrap; no automatic
        # Added notifications should disguise the manual resend under test.
        current, history = {}, {}
        with patch('monitor.engine.alert_new_ips'):
            for domain in domains:
                run_domain_cycle(domain=DomainSpec(**domain), servers=[rpc_query.PROVIDER],
                    current_results=current, history=history, history_dir=str(config) + '.history',
                    query_fail_counts={}, max_workers=1)

    provider = OfflineProvider(state)

    class OfflineRegistry(DestinationRegistry):
        def __init__(self, key, *, transport=None):
            super().__init__(key, transport=provider)

    server_type = dns_monitor.ThreadingHTTPServer

    class AnnouncedServer(server_type):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            print(json.dumps({'port': self.server_address[1]}), flush=True)

    sys.argv = ['dns_monitor.py', '--config', str(config), '--security-db', str(db),
                '--http-host', '127.0.0.1', '--http-port', '0', '--insecure-http']
    with patch('monitor.delivery_runtime.DestinationRegistry', OfflineRegistry), \
         patch.object(dns_monitor, 'ThreadingHTTPServer', AnnouncedServer):
        try:
            dns_monitor.main()
        finally:
            assert not blocked


if __name__ == '__main__':
    main()
