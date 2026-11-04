"""Terminal delivery failure must not masquerade as successful suppression."""
import pytest

from test_delivery_review_components import MISP, TEAMS, Response, Transport
from test_reappearance_suppression import IP, NEW_IP, PEER, PEER_IP, TARGET, scan
from test_stage3_core_runtime import app_factory, rows


@pytest.mark.parametrize('failed_channels', [('teams',), ('misp',), ('teams', 'misp')])
def test_terminal_failed_return_retries_only_failed_destination(tmp_path, monkeypatch, failed_channels):
    failures = set(failed_channels)

    def respond(method, url, kwargs):
        channel = 'teams' if 'teams.invalid' in url else 'misp'
        return Response(status=400) if channel in failures else None

    transport = Transport(callback=respond)
    config = {'domains': [{'name': TARGET, 'type': 'A'}, {'name': PEER, 'type': 'A'}],
              'servers': ['fake'], 'alerts': {**MISP, **TEAMS}, 'config_revision': 0}
    app = app_factory(tmp_path, config=config, transport=transport,
                      current={PEER: {'fake': {'type': 'A', 'values': [PEER_IP]}}})
    try:
        scan(app, monkeypatch, [IP])
        app.delivery.worker.run_pass()
        assert rows(app, 'receipt') == []
        assert app.delivery.store.health_snapshot()['failed_total'] == len(failures)
        assert app.delivery.store.health_snapshot()['acked_total'] == 2 - len(failures)
        failures.clear()

        # Repairing transport alone must not resurrect terminal work.
        app.clock.now += 120
        scan(app, monkeypatch, [IP], peer_error=True)
        assert rows(app, 'receipt') == []
        scan(app, monkeypatch, [], peer_error=True)
        assert rows(app, 'grace') == []
        app.clock.now += 120
        scan(app, monkeypatch, [IP, NEW_IP], peer_error=True)
        receipts = rows(app, 'receipt')
        assert {r['channel'] for r in receipts if r['ip'] == IP} == set(failed_channels)
        assert {r['channel'] for r in receipts if r['ip'] == NEW_IP} == {'teams', 'misp'}
        assert len(receipts) == len(failed_channels) + 2
        app.delivery.worker.run_pass()
        assert rows(app, 'receipt') == []
        assert app.delivery.store.health_snapshot()['acked_total'] == 4
        assert app.delivery.store.health_snapshot()['failed_total'] == len(failed_channels)
        assert app.delivery.store.health_snapshot()['missed_total'] == 0

        # After durable success, the usual non-sliding suppression applies.
        app.clock.now += 120
        scan(app, monkeypatch, [], peer_error=True)
        app.clock.now += 120
        scan(app, monkeypatch, [IP, NEW_IP], peer_error=True)
        assert rows(app, 'receipt') == []
    finally:
        assert app.delivery.stop()['closed']
