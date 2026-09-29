import json
import threading

from monitor import delivery_runtime
from test_stage3_core_runtime import app_factory, rows, scan
from test_delivery_adapters_steps import Response, Transport


def test_false_stop_keeps_store_claim_and_refuses_late_ack(tmp_path, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    class Blocking(Transport):
        def request(self, *args, **kwargs):
            entered.set()
            assert release.wait(2)
            return Response()
    app = app_factory(tmp_path, transport=Blocking())
    scan(app, monkeypatch, ['1.2.3.4'])
    running = threading.Thread(target=app.delivery.worker.run_pass)
    try:
        running.start()
        assert entered.wait(2)
        result = app.delivery.stop(join_seconds=.01)
        assert not result['stopped'] and not result['closed']
        assert not app.delivery.store._closed
        assert rows(app, 'receipt')[0]['state'] == 'in_flight'
        release.set()
        running.join(2)
        assert app.delivery.store.health_snapshot()['acked_total'] == 0
        assert rows(app, 'receipt')[0]['state'] == 'in_flight'
    finally:
        release.set()
        running.join(2)
        app.delivery.store.close(clean=False)


def test_bootstrap_selects_ini_once_and_reuses_exact_values_on_repair(tmp_path, monkeypatch):
    ini = tmp_path / 'local.ini'
    ini.write_text('[global]\nteams_webhook=https://teams.invalid/initial\n')
    selected = []
    original = delivery_runtime.select_alert_configuration
    def select(config, path):
        selected.append(1)
        return original(config, str(ini))
    monkeypatch.setattr(delivery_runtime, 'select_alert_configuration', select)
    app = app_factory(tmp_path, config={'domains': [], 'servers': [], 'config_revision': 0})
    try:
        binding = app.delivery.bindings()[0]['binding_id']
        ini.write_text('[global]\nteams_webhook=https://teams.invalid/CHANGED\n')
        app.service.commit('config', {'interval': 20}, expected_revision=0)
        assert selected == [1]
        assert app.delivery.bindings()[0]['binding_id'] == binding
        app.service.commit('settings', {'alerts': {'vt_cache_ttl_days': 3}}, expected_revision=1)
        assert selected == [1]
        assert app.delivery.bindings()[0]['binding_id'] == binding
        persisted = json.loads((tmp_path / 'config').read_text())
        assert persisted['alerts']['teams_webhook'] == 'https://teams.invalid/initial'
    finally:
        app.delivery.stop()


def test_failed_apply_disables_old_destination_without_legacy_globals(tmp_path, monkeypatch):
    app = app_factory(tmp_path, transport=Transport(Response()))
    scan(app, monkeypatch, ['1.2.3.4'])
    apply = app.delivery.registry.apply
    def failing(config, **kwargs):
        if kwargs.get('applied', True):
            raise RuntimeError('private credential detail')
        return apply(config, **kwargs)
    monkeypatch.setattr(app.delivery.registry, 'apply', failing)
    try:
        result = app.service.commit('settings', {'alerts': {'teams_webhook': 'https://teams.invalid/new'}}, expected_revision=0)
        assert result['warnings'] == ['alerts_runtime_apply_failed']
        assert not app.delivery.bindings()[0]['ready']
        assert app.delivery.worker.run_pass()['provider_calls'] == 0
        assert rows(app, 'receipt')[0]['state'] == 'blocked_config'
        assert 'private credential' not in json.dumps(app.delivery.store.health_snapshot())
    finally:
        app.delivery.stop()
