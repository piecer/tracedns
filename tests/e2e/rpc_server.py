"""Real application/worker/API, replaying a captured RPC response offline."""
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from security.store import SecurityStore
import dns_monitor
import rpc_query


def main():
    state = Path(sys.argv[1]).resolve()
    state.mkdir(parents=True, exist_ok=True)
    os.chdir(state)
    db = state / 'auth.sqlite'
    first = not db.exists()
    store = SecurityStore(db, create=first)
    if first:
        store.bootstrap('admin', 'test-admin-password')
    config = state / 'config.json'
    if not config.exists():
        config.write_text(json.dumps({'domains': [], 'servers': [], 'interval': 3600, 'alerts': {}}))
    corpus = json.loads((ROOT / 'docs/rpc/polygon-aes-gcm-observation.json').read_text())

    def replay(url, payload, timeout):
        assert url in rpc_query.RPC_URLS
        assert payload['method'] == 'eth_call'
        assert payload['params'][0] == {'to': rpc_query.CONTRACT, 'data': rpc_query.SELECTOR}
        miss = (state / 'miss').exists()
        return {'jsonrpc': '2.0', 'id': 1, 'result': '0x' if miss else corpus['raw_result']}

    blocked = []

    def audit(event, args):
        if event in ('socket.connect', 'socket.sendto'):
            address = args[-1]
            if isinstance(address, tuple) and address[0] not in ('127.0.0.1', '::1'):
                blocked.append(event)
                raise AssertionError('external traffic forbidden in RPC replay fixture')

    sys.addaudithook(audit)
    rpc_query._post_rpc = replay
    server_type = dns_monitor.ThreadingHTTPServer

    class AnnouncedServer(server_type):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            print(json.dumps({'port': self.server_address[1]}), flush=True)

    dns_monitor.ThreadingHTTPServer = AnnouncedServer
    sys.argv = ['dns_monitor.py', '--config', str(config), '--security-db', str(db),
                '--http-host', '127.0.0.1', '--http-port', '0', '--insecure-http']
    try:
        dns_monitor.main()
    finally:
        assert not blocked


if __name__ == '__main__':
    main()
