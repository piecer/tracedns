"""Required composition gates owned by core, repaired by component owner.

These are deliberately not xfailed: a component defect remains a blocking gate.
"""
from test_stage3_core_runtime import app_factory, rows, scan
from test_delivery_adapters_steps import Response, Transport


def test_first_other_channel_descriptor_is_not_a_credential_repair(tmp_path, monkeypatch):
    transport = Transport(Response(status=401), Response(status=200))
    app = app_factory(tmp_path, transport=transport)
    try:
        scan(app, monkeypatch, ['1.2.3.4'])
        app.delivery.worker.run_pass()
        assert len(transport.calls) == 1, 'discovering disabled MISP must not release Teams auth block'
        assert rows(app, 'receipt')[0]['state'] == 'blocked_config'
        assert app.delivery.store.health_snapshot()['acked_total'] == 0
    finally:
        app.delivery.stop()


def test_history_failure_reaches_real_store_diagnostic_without_delivery_gap(tmp_path, monkeypatch):
    from monitor import engine
    app = app_factory(tmp_path)
    monkeypatch.setattr(engine, 'persist_history_entry', lambda *a, **k: False)
    try:
        scan(app, monkeypatch, ['1.2.3.4'])
        health = app.delivery.store.health_snapshot()
        assert health['last_error'] == 'history_persistence'
        assert health['coverage'] == 'covered'
        assert len(rows(app, 'receipt')) == 1
    finally:
        app.delivery.stop()
