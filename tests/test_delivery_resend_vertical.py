"""Manual resend composes the actual source, ledger, worker and adapters."""
from copy import deepcopy
import json

from config_manager import domain_storage_name, domain_identity
from monitor.engine import run_full_cycle, reconcile_scan
from test_delivery_review_components import MISP, TEAMS, Transport, rows
from test_rpc_monitor import DOMAIN, rpc_response
from test_stage3_core_runtime import app_factory


STORAGE_TARGET = domain_storage_name(DOMAIN)


AUTOMATIC_TABLES = ('cursor', 'recent', 'reappearance', 'failed_addition', 'baseline', 'grace')


def preserved(app):
    return {'current': deepcopy(app.current), 'history': deepcopy(app.history),
            'automatic': {table: rows(app.delivery.store, table) for table in AUTOMATIC_TABLES},
            'history_files': {p.name: p.read_bytes() for p in app.delivery.store.path.parent.glob('*.json')}}


def rpc_app(tmp_path, monkeypatch, *, limits=None, transport=None):
    side_stream = tmp_path / 'side-stream'
    side_stream.mkdir(exist_ok=True)
    monkeypatch.setenv('MISP_SIGHTING_BATCH_FILE', str(side_stream / 'sightings.json'))
    transport = transport or Transport()
    app = app_factory(tmp_path, config={'domains': [DOMAIN], 'servers': [],
        'alerts': {**MISP, **TEAMS}, 'config_revision': 0}, limits=limits, transport=transport)
    monkeypatch.setattr('rpc_query._post_rpc', lambda *a, **k: rpc_response())
    snapshot = app.cfg.snapshot()
    result = run_full_cycle(domains_raw=snapshot.domains, servers=snapshot.servers,
        current_results=app.current, history=app.history, history_dir=app.repo.history_dir,
        query_fail_counts={}, state_repository=app.repo, target_leases=snapshot.target_leases)
    assert reconcile_scan(app.cfg, snapshot, {}, result, None)[0]
    app.delivery.worker.run_pass()
    assert not rows(app.delivery.store, 'receipt')
    transport.calls.clear()
    return app, transport, domain_identity(DOMAIN)


def test_rpc_saved_source_preview_confirm_real_worker_both_ack(tmp_path, monkeypatch):
    app, transport, target = rpc_app(tmp_path, monkeypatch)
    try:
        before = preserved(app)
        acked = app.delivery.store.health_snapshot()['acked_total']
        preview = app.delivery.preview_resend(target, ['teams', 'misp'], 0, actor_id='admin-fixture')
        assert preview['status'] == 'ready', preview
        assert preview['ips'] == ['192.0.2.10']  # Neither relay nor ciphertext.
        assert preview['source_type'] == 'RPC'
        assert type(preview['observed_at']) is int
        assert len(preview['request_id']) == 32
        assert transport.calls == []
        assert preserved(app) == before
        result = app.delivery.resend_target(preview['request_id'], actor_id='admin-fixture')
        assert result == {'status': 'queued', 'reason': None, 'request_id': preview['request_id'],
                          'ip_count': 1, 'receipt_count': 2, 'channels': ['teams', 'misp'],
                          'retry_after': None}
        receipts = rows(app.delivery.store, 'receipt')
        assert len(receipts) == 2 and {r['action'] for r in receipts} == {'Added'}
        marker = rows(app.delivery.store, 'manual_resend')[0]
        assert marker['request_id'] == preview['request_id']
        assert marker['target'] == STORAGE_TARGET and marker['actor_id'] == 'admin-fixture'
        assert json.loads(marker['channels']) == ['teams', 'misp']
        assert marker['ip_count'] == 1 and marker['receipt_count'] == 2
        assert preserved(app) == before and transport.calls == []
        app.delivery.worker.run_pass()
        assert not rows(app.delivery.store, 'receipt')
        assert app.delivery.store.health_snapshot()['acked_total'] == acked + 2
        assert any('teams.invalid' in c['url'] for c in transport.calls)
        assert any('/events/view/' in c['url'] for c in transport.calls)
        assert not any('/attributes/add/' in c['url'] for c in transport.calls)  # Existing MISP attribute.
        assert preserved(app) == before
    finally:
        app.delivery.stop()
