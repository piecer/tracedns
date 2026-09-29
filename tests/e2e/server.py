"""Disposable E2E server; synthetic accounts, no external traffic."""
import argparse
import json
import signal
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from http_server import ThreadingHTTPServer, make_handler
from security.store import SecurityStore


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=18765)
    parser.add_argument('--delivery', choices=['noowner', 'backlog', 'acked', 'overflow', 'degraded'], default='acked')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='tracedns-e2e-') as temp:
        store = SecurityStore(Path(temp) / 'private' / 'auth.db', create=True)
        store.bootstrap('admin', 'test-admin-password')
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from test_delivery_frontend_fixture import delivery_fixture
        delivery = delivery_fixture(Path(temp) / 'delivery', args.delivery)
        cfg = {'domains': [], 'servers': ['127.0.0.1'], 'interval': 60, 'alerts': {}}
        handler = make_handler(cfg, threading.RLock(), '', temp, {}, {},
                               security_store=store, insecure_http=True,
                               delivery_health=delivery.health_snapshot if delivery else None)
        server = ThreadingHTTPServer(('127.0.0.1', args.port), handler)
        print(json.dumps({'port': server.server_address[1]}), flush=True)
        signal.signal(signal.SIGTERM, lambda *args: threading.Thread(target=server.shutdown).start())
        try:
            server.serve_forever()
        finally:
            server.server_close()
            if delivery:
                delivery.close(clean=True)


if __name__ == '__main__':
    main()
