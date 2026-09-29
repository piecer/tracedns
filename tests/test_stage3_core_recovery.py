import threading

from monitor import delivery_runtime
from test_stage3_core_runtime import app_factory, scan


def test_storage_unavailable_at_start_still_collects_then_attaches_real_key(tmp_path, monkeypatch):
    # A path which cannot initially be a directory forces real constructor failure.
    root = tmp_path / 'blocked'
    root.write_text('fixture')
    app = app_factory(root)
    try:
        assert app.delivery.registry is None
        accepted, _ = scan(app, monkeypatch, ['1.2.3.4'])
        assert accepted
        assert app.current['test.example']['fake']['values'] == ['1.2.3.4']
        assert app.delivery.store.health_snapshot()['coverage'] == 'gap'
        # Move the owned fixture, don't delete it; collection is still running.
        root.rename(tmp_path / 'old-blocker')
        root.mkdir()
        app.service.commit('settings', {'alerts': {'teams_webhook': 'https://teams.invalid/repaired'}}, expected_revision=0)
        scan(app, monkeypatch, ['2.3.4.5'])
        assert app.delivery.registry is not None
        assert app.delivery.registry.capture('teams', app.delivery.bindings()[0]['binding_id'],
                                            'Added', revision=1).ready
        assert app.delivery.store.health_snapshot()['missed_total'] == 0
        assert not app.delivery.store.health_snapshot()['accounting_complete']
    finally:
        app.delivery.stop()


def test_recovery_registry_attachment_cannot_overwrite_later_config(tmp_path, monkeypatch):
    app = app_factory(tmp_path)
    entered, release = threading.Event(), threading.Event()
    original = delivery_runtime.DestinationRegistry.apply
    def apply(self, values, **kwargs):
        if threading.current_thread().name == 'recover' and values:
            entered.set()
            assert release.wait(2)
        return original(self, values, **kwargs)
    monkeypatch.setattr(delivery_runtime.DestinationRegistry, 'apply', apply)
    recovering = threading.Thread(target=app.delivery._attach_registry, name='recover')
    try:
        recovering.start()
        assert entered.wait(2)
        app.service.commit('settings', {'alerts': {'teams_webhook': 'https://teams.invalid/new'}}, expected_revision=0)
        release.set()
        recovering.join(2)
        assert app.delivery.registry.revision == 1
        assert app.delivery.bindings()[0]['ready']
    finally:
        release.set()
        recovering.join(2)
        app.delivery.stop()
