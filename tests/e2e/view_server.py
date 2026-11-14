"""Owned synthetic targets + real prepared reads/delivery store; no providers."""
import argparse
import json
import signal
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from http_server import ThreadingHTTPServer, make_handler
from security.store import SecurityStore
from monitor.delivery_store import DeliveryStore

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_delivery_frontend_fixture import delivery_fixture


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--delivery', choices=['acked', 'disabled', 'noowner', 'degraded', 'overflow'], default='acked')
    parser.add_argument('--rows', type=int, default=12)
    parser.add_argument('--documentation', action='store_true')
    args = parser.parse_args()
    if args.documentation and not 1 <= args.rows <= 250:
        parser.error('documentation fixture requires 1..250 reserved example IPs')
    with tempfile.TemporaryDirectory(prefix='tracedns-view-e2e-') as temp:
        root = Path(temp)
        auth = SecurityStore(root / 'private' / 'auth.db', create=True)
        auth.bootstrap('admin', 'test-admin-password')
        if args.delivery == 'disabled':
            delivery = DeliveryStore(root / 'delivery')
            assert delivery.bootstrap({}, {}, {'valid': True, 'revision': 1, 'signature': 'fixture'})['ready']
        else:
            delivery = delivery_fixture(root / 'delivery', args.delivery)
        current = {f'target-{i:03}.test': {'fixture': {
            'type': 'A', 'values': [f'192.0.2.{i + 1}' if args.documentation else f'11.0.{i // 250}.{i % 250 + 1}'], 'ts': int(time.time())}}
            for i in range(args.rows)}
        config = {'domains': list(current), 'servers': ['127.0.0.1'], 'interval': 60, 'alerts': {}}
        handler = make_handler(config, threading.RLock(), '', str(root), current, {},
                               security_store=auth, insecure_http=True,
                               delivery_health=(lambda **kwargs: delivery.health_snapshot()) if delivery else None)
        class LegacyHealthHandler(handler):
            def do_GET(self):
                # The real store exposes legacy health; explicitly emulate that
                # server's ignored selector, not an impossible extended DTO.
                path = urlsplit(self.path).path
                if path == '/delivery-health':
                    self.path = path
                super().do_GET()
        server = ThreadingHTTPServer(('127.0.0.1', 0), LegacyHealthHandler)
        signal.signal(signal.SIGTERM, lambda *args: threading.Thread(target=server.shutdown).start())
        print(json.dumps({'port': server.server_port}), flush=True)
        try:
            server.serve_forever()
        finally:
            server.server_close()
            if delivery:
                delivery.close(clean=True)


if __name__ == '__main__':
    main()
