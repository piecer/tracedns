"""Actual application main/worker/API; ONLY the DHT network source is synthetic."""
import copy
import json
import os
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))
from test_dht_query import signed_fixture
from security.store import SecurityStore
import dht_query
import dns_monitor


def main():
    state = Path(sys.argv[1]).resolve()
    state.mkdir(parents=True, exist_ok=True)
    os.chdir(state)  # Never load a production config.ini or write into the checkout.
    db = state / 'auth.sqlite'
    first = not db.exists()
    store = SecurityStore(db, create=first)
    if first:
        store.bootstrap('admin', 'test-admin-password')
    config = state / 'config.json'
    if not config.exists():
        config.write_text(json.dumps({'domains': [], 'servers': [], 'interval': 3600, 'alerts': {}}))
    raw, key = signed_fixture(9007199254740993, ('192.0.2.123',))
    record = {'public_key': key.hex(), 'seq': str(raw[b'seq']),
              'signature': raw[b'sig'].hex(), 'value_hex': raw[b'v'].hex()}

    def synthetic(public_key, options=None, *, cancelled=None):
        checked, _ = dht_query.validate_dht_config(public_key, options)
        assert checked == key.hex()
        mode = (state / 'mode').read_text().strip() if (state / 'mode').exists() else 'record'
        records = [] if mode == 'miss' or (cancelled is not None and cancelled()) else [copy.deepcopy(record)]
        return {'records': records, 'coverage': {'termination': 'queue_exhausted', 'queries_sent': 0}}

    # Fail closed if any unrelated application path attempts external traffic.
    blocked = []
    def audit(event, args):
        if event in ('socket.connect', 'socket.sendto'):
            address = args[-1]
            if isinstance(address, tuple) and address[0] not in ('127.0.0.1', '::1'):
                blocked.append(event)
                raise AssertionError('external network forbidden in synthetic browser fixture')
    sys.addaudithook(audit)
    dht_query.fetch_dht_records = synthetic
    real_server = dns_monitor.ThreadingHTTPServer

    class AnnouncedServer(real_server):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            print(json.dumps({'port': self.server_address[1], 'key': key.hex()}), flush=True)

    dns_monitor.ThreadingHTTPServer = AnnouncedServer
    sys.argv = ['dns_monitor.py', '--config', str(config), '--security-db', str(db),
                '--http-host', '127.0.0.1', '--http-port', '0', '--insecure-http']
    try:
        dns_monitor.main()
    finally:
        assert not blocked, 'application attempted external traffic in synthetic fixture'


if __name__ == '__main__':
    main()
