"""Real browser uses the real authenticated handler and producer-owned state."""
import json
import os
from pathlib import Path
import subprocess
import threading
from urllib.parse import urlsplit

from http_server import ThreadingHTTPServer, make_handler
from monitor import engine
from monitor.lookup_runtime import LookupRuntime
from security.store import SecurityStore
from test_delivery_review_components import MISP, TEAMS, Transport
from test_lookup_liveness import owned_scan
from test_stage3_core_runtime import app_factory, scan


class BrowserTransport(Transport):
    def __init__(self):
        super().__init__()
        self.entered = threading.Event()
        self.release = threading.Event()

    def request(self, method, url, **kwargs):
        if 'teams.invalid' in url:
            self.entered.set()
            assert self.release.wait(100), 'browser fixture rescue deadline'
        return super().request(method, url, **kwargs)


def test_actual_browser_progress_path(tmp_path, monkeypatch):
    transport = BrowserTransport()
    app = app_factory(tmp_path / 'ledger', transport=transport, config={
        'domains': ['test.example'], 'servers': ['fixture'], 'alerts': {**TEAMS, **MISP}})
    mono = [100.0]
    app.delivery.store._monotonic = lambda: mono[0]
    app.delivery.worker._monotonic = lambda: mono[0]
    app.delivery.worker._observation_hook = lambda _: None
    app.delivery.worker._sightings_step = lambda: {'provider_calls': 0, 'has_more': False}
    assert scan(app, monkeypatch, ['192.0.2.1'])[0]
    app.lookup = LookupRuntime(app.repo)
    app.delivery.store.enter_gap('delivery_storage', {})
    assert app.delivery.maintain_delivery(app.clock())['state'] == 'ready'
    def failed_lookup(*args):
        raise RuntimeError('PRIVATE-CANARY')
    monkeypatch.setattr(engine, 'collect_snapshot', failed_lookup)
    assert not owned_scan(app).complete
    auth = SecurityStore(tmp_path / 'auth.sqlite', create=True)
    auth.bootstrap('admin', 'test-admin-password')
    legacy = [False]
    produced = []
    def health(**kwargs):
        snapshot = app.delivery.health_snapshot(include_progress=kwargs.get('include_progress', False) and not legacy[0])
        produced.append(snapshot)
        return snapshot
    base = make_handler(app.cfg.raw, app.cfg.lock, '', str(tmp_path), app.current, app.history,
        security_store=auth, insecure_http=True, delivery_health=health)
    # Explicit fixture-only clock/release controls. These are never shipped in
    # the production handler and authorize no external operation.
    token = os.urandom(24).hex()
    class FixtureHandler(base):
        def do_GET(self):
            path = urlsplit(self.path).path
            if legacy[0] and path in ('/delivery-health', '/api/v1/delivery-health'):
                self.path = path  # explicit old-server selector policy fixture
            super().do_GET()

        def do_POST(self):
            if self.path.startswith('/__fixture/') and self.headers.get('X-Fixture-Token') == token:
                if self.path == '/__fixture/advance':
                    mono[0] += 60
                elif self.path == '/__fixture/release':
                    transport.release.set()
                elif self.path == '/__fixture/legacy':
                    legacy[0] = True
                elif self.path == '/__fixture/failed':
                    legacy[0] = False
                    def fail(*args):
                        raise RuntimeError('PRIVATE-CANARY')
                    app.delivery.worker._claim_admission = fail
                    app.delivery.worker.wake()
                else:
                    self.send_error(404)
                    return
                self.send_response(204)
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            super().do_POST()
    server = ThreadingHTTPServer(('127.0.0.1', 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert app.delivery.worker.start()
        assert transport.entered.wait(3)
        env = dict(os.environ, STAGE4_PORT=str(server.server_port), STAGE4_TOKEN=token,
                   STAGE4_BROWSER_OUTPUT=os.environ.get('STAGE4_BROWSER_OUTPUT', str(tmp_path / 'browser')))
        result = subprocess.run(['node', 'tests/test_delivery_progress_browser.js'],
            cwd=Path(__file__).resolve().parents[1], env=env, text=True, capture_output=True, timeout=120)
        proof = Path(env['STAGE4_BROWSER_OUTPUT'])
        proof.mkdir(parents=True, exist_ok=True)
        (proof / 'producer-snapshots.json').write_text(json.dumps(produced, indent=2) + '\n')
        assert result.returncode == 0, result.stdout + result.stderr
        states = [s.get('progress', {}).get('state', 'legacy') for s in produced]
        assert states[:3] == ['active', 'stalled', 'stalled']
        assert states[3] in ('idle', 'active')  # a legitimate idle-loop boundary may be sampled
        assert states[4:] == ['legacy', 'failed']
        assert app.delivery.health_snapshot()['acked_total'] == 2
        assert len([c for c in transport.calls if 'teams.invalid' in c['url']]) == 1
    finally:
        transport.release.set()
        app.lookup.stop()
        app.delivery.stop()
        server.shutdown()
        server.server_close()
        thread.join(5)
        assert not thread.is_alive()
