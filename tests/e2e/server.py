"""Disposable E2E server; synthetic accounts, no external traffic."""
import signal
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from http_server import ThreadingHTTPServer, make_handler
from security.store import SecurityStore


def main():
    with tempfile.TemporaryDirectory(prefix='tracedns-e2e-') as temp:
        store = SecurityStore(Path(temp) / 'private' / 'auth.db', create=True)
        store.bootstrap('admin', 'test-admin-password')
        cfg = {'domains': [], 'servers': ['127.0.0.1'], 'interval': 60, 'alerts': {}}
        handler = make_handler(cfg, threading.RLock(), '', temp, {}, {},
                               security_store=store, insecure_http=True)
        server = ThreadingHTTPServer(('127.0.0.1', 18765), handler)
        signal.signal(signal.SIGTERM, lambda *args: threading.Thread(target=server.shutdown).start())
        try:
            server.serve_forever()
        finally:
            server.server_close()


if __name__ == '__main__':
    main()
