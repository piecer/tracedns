"""Disposable real HTTP read-path fixture; no DNS or external VT traffic."""
import signal
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from http_server import ThreadingHTTPServer, make_handler
from monitor.runtime_state import bump_state_version, state_lock
from security.store import SecurityStore


def main():
    with tempfile.TemporaryDirectory(prefix='tracedns-read-e2e-') as temp:
        store = SecurityStore(Path(temp) / 'private' / 'auth.db', create=True)
        store.bootstrap('admin', 'test-admin-password')
        current = {f'a{i:03}.test': {'r': {'type': 'A', 'values': [f'11.0.0.{i + 1}'], 'ts': int(time.time())}}
                   for i in range(250)}
        current['a000.test']['r']['values'] = [f'11.1.{i // 250}.{i % 250 + 1}' for i in range(450)]
        config = {'domains': list(current), 'servers': ['127.0.0.1'], 'interval': 60, 'alerts': {}}
        with patch('http_api_handlers.get_ip_report', return_value={'asn': 15169, 'malicious': 0, 'country': 'US'}):
            handler = make_handler(config, threading.RLock(), '', temp, current, {},
                                   security_store=store, insecure_http=True)
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
        signal.signal(signal.SIGTERM, lambda *args: threading.Thread(target=server.shutdown).start())

        def commands():
            for command in sys.stdin:
                if command.strip() == 'tick':
                    with state_lock():
                        current['a000.test']['r']['ts'] += 100
                        bump_state_version()
        threading.Thread(target=commands, daemon=True).start()
        print(f'PORT={server.server_port}', flush=True)
        try:
            server.serve_forever()
        finally:
            server.server_close()


if __name__ == '__main__':
    main()
