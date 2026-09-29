import json
import threading

import pytest

from test_stage3_core_runtime import app_factory, rows, scan
from test_delivery_adapters_steps import Response, Transport


def test_real_settings_rotation_fences_old_binding_and_repairs_same_binding(tmp_path, monkeypatch):
    transport = Transport(Response(status=401), Response(status=200))
    app = app_factory(tmp_path, transport=transport)
    try:
        scan(app, monkeypatch, ['1.2.3.4'])
        app.delivery.worker.run_pass()
        assert rows(app, 'receipt')[0]['state'] == 'blocked_config'
        monkeypatch.setattr('http_api.settings_handlers.apply_runtime_settings',
                            lambda *a: pytest.fail('production must not initialize legacy PyMISP'))
        apply = app.delivery.registry.apply
        # Registry preparation must permit a concurrent config reader.
        def unlocked_apply(*args, **kwargs):
            finished = threading.Event()
            thread = threading.Thread(target=lambda: (app.service.snapshot(), finished.set()))
            thread.start()
            assert finished.wait(1), 'adapter apply held config ownership'
            thread.join()
            return apply(*args, **kwargs)
        monkeypatch.setattr(app.delivery.registry, 'apply', unlocked_apply)
        result = app.service.commit('settings', {'alerts': {'teams_webhook': 'https://teams.invalid/hook'}}, expected_revision=0)
        assert not result['warnings']
        app.delivery.worker.run_pass()
        assert app.delivery.store.health_snapshot()['acked_total'] == 1
        assert len(transport.calls) == 2
    finally:
        app.delivery.stop()


def test_committed_new_destination_is_admission_authority_during_apply(tmp_path, monkeypatch):
    app = app_factory(tmp_path)
    applying, release = threading.Event(), threading.Event()
    original = app.delivery.apply_configuration
    def apply(candidate):
        applying.set()
        assert release.wait(2)
        return original(candidate)
    monkeypatch.setattr(app.delivery, 'apply_configuration', apply)
    old_binding = app.delivery.bindings()[0]['binding_id']
    writer = threading.Thread(target=lambda: app.service.commit('settings', {
        'alerts': {'teams_webhook': 'https://teams.invalid/new'}}, expected_revision=0))
    try:
        writer.start()
        assert applying.wait(2)
        binding = app.delivery.bindings()[0]
        assert binding['binding_id'] != old_binding
        assert not binding['ready']
        scan(app, monkeypatch, ['1.2.3.4'])
        assert rows(app, 'receipt')[0]['binding'] == binding['binding_id']
        release.set()
        writer.join(2)
        assert app.delivery.bindings()[0]['ready']
    finally:
        release.set()
        writer.join(2)
        app.delivery.stop()


def test_configuration_repair_wakes_only_after_store_notification(tmp_path, monkeypatch):
    app = app_factory(tmp_path)
    calls = []
    original = app.delivery.store.configuration_applied
    def applied(*args, **kwargs):
        calls.append('persisted')
        return original(*args, **kwargs)
    monkeypatch.setattr(app.delivery.store, 'configuration_applied', applied)
    original_wake = app.delivery.worker.wake
    def wake():
        calls.append('wake')
        original_wake()
    monkeypatch.setattr(app.delivery.worker, 'wake', wake)
    try:
        app.service.commit('settings', {'alerts': {}}, expected_revision=0)
        assert calls == ['persisted', 'wake']
    finally:
        app.delivery.stop()


def test_delete_readd_revokes_old_lease_but_retains_receipt(tmp_path, monkeypatch):
    app = app_factory(tmp_path, transport=Transport(Response(status=200)))
    try:
        original = app.repo.capture()['test.example']
        scan(app, monkeypatch, ['1.2.3.4'])
        old_cursor = rows(app, 'cursor')[0]['incarnation']
        app.service.commit('config', {'domains': []}, expected_revision=0)
        assert not app.repo.valid(original)
        assert rows(app, 'cursor') == []
        assert not (tmp_path / 'test.example.json').exists()
        assert len(rows(app, 'receipt')) == 1
        app.delivery.worker.run_pass()
        assert app.delivery.store.health_snapshot()['acked_total'] == 1
        app.service.commit('config', {'domains': [{'name': 'test.example', 'type': 'A'}]}, expected_revision=1)
        scan(app, monkeypatch, ['2.3.4.5'])
        assert rows(app, 'cursor')[0]['incarnation'] != old_cursor
        assert not app.repo.valid(original)
        assert json.loads(rows(app, 'receipt')[0]['payload'])['entries'][0][0] == '2.3.4.5'
    finally:
        app.delivery.stop()
