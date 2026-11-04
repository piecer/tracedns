"""Real runtime/SQLite/worker -> authenticated health, synthetic transport only."""
import json
from pathlib import Path
import subprocess
import threading

from http_server import ThreadingHTTPServer, make_handler
from security.store import SecurityStore
from test_http_auth_integration import Client
from test_stage3_core_runtime import app_factory, scan


class BlockedTransport:
    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()
        self.calls = 0

    def request(self, *args, **kwargs):
        self.calls += 1
        self.entered.set()
        assert self.release.wait(15), 'fixture transport release missing'
        return {'status': 200, 'body': b'1', 'headers': {}}


def test_blocked_actual_callback_age_and_stall_over_authenticated_http(tmp_path, monkeypatch):
    from contextlib import ExitStack
    from monitor.lookup_runtime import LookupRuntime
    transport = BlockedTransport()
    app = app_factory(tmp_path / 'ledger', transport=transport)
    mono = [100.0]
    app.delivery.store._monotonic = lambda: mono[0]
    app.delivery.worker._monotonic = lambda: mono[0]
    auth = SecurityStore(tmp_path / 'auth.sqlite', create=True)
    auth.bootstrap('root', 'test-password-123')
    # Bind the actual owner at request time, so baseline failure is an HTTP
    # behavioral assertion rather than a missing-method collection error.
    handler = make_handler(app.cfg.raw, app.cfg.lock, '', str(tmp_path), app.current, app.history,
        security_store=auth, insecure_http=True,
        delivery_health=lambda **kwargs: app.delivery.health_snapshot(**kwargs))
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert scan(app, monkeypatch, ['192.0.2.1'])[0]
        assert app.delivery.worker.start()
        assert transport.entered.wait(3)
        client = Client(server.server_port)
        assert client.login()[0] == 200
        code, first = client.call('GET', '/delivery-health?progress=1')
        assert code == 200, first
        assert first['progress']['state'] == 'active'
        assert first['worker_running'] and first['acked_total'] == 0
        mono[0] += 59.999
        assert client.call('GET', '/delivery-health?progress=1')[1]['progress']['state'] == 'active'
        mono[0] = 160
        lookup = LookupRuntime(app.repo)
        locked, unlocked = threading.Event(), threading.Event()
        def hold():
            with ExitStack() as stack:
                for lock in (app.cfg.lock, app.repo._coord, app.delivery.store._lock,
                             lookup.condition, lookup.audit.condition):
                    stack.enter_context(lock)
                locked.set()
                assert unlocked.wait(15)
        holder = threading.Thread(target=hold)
        holder.start()
        assert locked.wait(2)
        with monkeypatch.context() as poison:
            poison.setattr(app.delivery.store, '_one', lambda *a: (_ for _ in ()).throw(AssertionError('HTTP SQL')))
            for owner, method in ((app.repo, 'capture'), (app.delivery.store, '_open'),
                                  (lookup, 'status'), (lookup.audit, 'status')):
                poison.setattr(owner, method, lambda *a: (_ for _ in ()).throw(AssertionError('HTTP owner read')))
            code, stalled = client.call('GET', '/api/v1/delivery-health?progress=1')
            assert code == 200, stalled
            assert stalled['progress']['state'] == 'stalled'
            assert stalled['progress']['operation'] == 'provider_step'
            assert stalled['oldest_pending_age_seconds'] >= first['oldest_pending_age_seconds'] + 60
            assert stalled['counts_age_seconds'] >= 60
            assert stalled['worker_running'] and stalled['acked_total'] == 0
            code, legacy = client.call('GET', '/delivery-health')
            assert code == 200 and legacy['status'] == 'degraded'
            assert 'progress' not in legacy
            corpus = [
                {'wire': json.dumps(stalled), 'accept': True,
                 'contains': ['stalled', 'provider step', '60 seconds', 'Source coverage: unknown', 'ACKed: 0']},
                {'wire': json.dumps(legacy), 'accept': True, 'contains': ['progress unavailable on this server']},
            ]
            for key in ('progress', 'recovery', 'lookup'):
                mutated = json.loads(json.dumps(stalled))
                mutated[key]['foreign'] = 'PRIVATE-CANARY'
                corpus.append({'wire': json.dumps(mutated), 'accept': False})
            parsed = subprocess.run(['node', 'tests/test_delivery_progress_frontend.js'],
                cwd=Path(__file__).resolve().parents[1], input=json.dumps(corpus),
                capture_output=True, text=True, timeout=10)
            assert parsed.returncode == 0, parsed.stderr
    finally:
        if 'unlocked' in locals():
            unlocked.set()
            holder.join(5)
            lookup.stop()
        transport.release.set()
        app.delivery.stop()
        server.shutdown()
        server.server_close()
        thread.join(5)
        assert not thread.is_alive()
