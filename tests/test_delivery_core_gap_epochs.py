import threading

import pytest

from test_stage3_core_runtime import app_factory, rows, scan
from test_delivery_adapters_steps import Response, Transport


@pytest.mark.parametrize('channel', ['teams', 'misp'])
def test_other_channel_settings_do_not_authorize_auth_retry(tmp_path, monkeypatch, channel):
    alerts = ({'teams_webhook': 'https://teams.invalid/hook'} if channel == 'teams' else
              {'misp_url': 'https://misp.invalid', 'api_key': 'old', 'push_event_id': '7'})
    config = {'domains': [{'name': 'test.example', 'type': 'A'}], 'servers': ['fake'],
              'alerts': alerts, 'config_revision': 0}
    transport = Transport(Response(status=401), Response(status=401))
    app = app_factory(tmp_path, config=config, transport=transport)
    try:
        app.delivery._channel = 1 if channel == 'misp' else 0
        scan(app, monkeypatch, ['1.2.3.4'])
        app.delivery.worker.run_pass()
        assert len(transport.calls) == 1
        receipt = rows(app, 'receipt')[0]
        other = {'api_key': 'unrelated'} if channel == 'teams' else {'teams_webhook': ''}
        app.service.commit('settings', {'alerts': other}, expected_revision=0)
        app.delivery.worker.run_pass()
        assert len(transport.calls) == 1, 'other channel settings are not credential repair'
        assert rows(app, 'receipt')[0]['attempt'] == receipt['attempt'] == 1
        repair = {'teams_webhook': alerts['teams_webhook']} if channel == 'teams' else {'api_key': 'repaired'}
        app.service.commit('settings', {'alerts': repair}, expected_revision=1)
        app.delivery.worker.run_pass()
        app.delivery.worker.run_pass()
        assert len(transport.calls) == 2
        assert rows(app, 'receipt')[0]['attempt'] == 2
        assert rows(app, 'receipt')[0]['state'] == 'blocked_config'
    finally:
        app.delivery.stop()


def test_old_immutable_auth_finish_after_real_same_binding_repair(tmp_path, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    class PausedTransport(Transport):
        def request(self, *args, **kwargs):
            if not self.calls:
                entered.set()
                assert release.wait(3)
            return super().request(*args, **kwargs)
    transport = PausedTransport(Response(status=401), Response(status=200))
    app = app_factory(tmp_path, transport=transport)
    thread = threading.Thread(target=app.delivery.worker.run_pass)
    try:
        scan(app, monkeypatch, ['1.2.3.4'])
        thread.start()
        assert entered.wait(2)
        old = rows(app, 'receipt')[0]
        app.service.commit('settings', {'alerts': {'teams_webhook': 'https://teams.invalid/hook'}}, expected_revision=0)
        release.set()
        thread.join(3)
        assert not thread.is_alive()
        app.delivery.worker.run_pass()
        assert len(transport.calls) == 2
        assert app.delivery.store.health_snapshot()['acked_total'] == 1
        assert old['attempt'] == 1
    finally:
        release.set()
        thread.join(3)
        app.delivery.stop()


def test_endpoint_rotation_never_rebinds_blocked_receipt(tmp_path, monkeypatch):
    transport = Transport(Response(status=401))
    app = app_factory(tmp_path, transport=transport)
    try:
        scan(app, monkeypatch, ['1.2.3.4'])
        app.delivery.worker.run_pass()
        old = rows(app, 'receipt')[0]
        app.service.commit('settings', {'alerts': {'teams_webhook': 'https://teams.invalid/rotated'}}, expected_revision=0)
        app.delivery.worker.run_pass()
        receipt = rows(app, 'receipt')[0]
        assert receipt['error'] == 'old_binding_blocked'
        assert receipt['binding'] == old['binding']
        assert receipt['attempt'] == 1
        assert len(transport.calls) == 1
    finally:
        app.delivery.stop()


def test_pending_other_channel_apply_does_not_erase_or_release_auth_block(tmp_path, monkeypatch):
    app = app_factory(tmp_path, transport=Transport(Response(status=401), Response(status=200)))
    applying, release = threading.Event(), threading.Event()
    apply = app.delivery.apply_configuration
    def paused(candidate):
        applying.set()
        assert release.wait(3)
        return apply(candidate)
    monkeypatch.setattr(app.delivery, 'apply_configuration', paused)
    writer = threading.Thread(target=lambda: app.service.commit('settings',
        {'alerts': {'api_key': 'unrelated'}}, expected_revision=0))
    try:
        scan(app, monkeypatch, ['1.2.3.4'])
        app.delivery.worker.run_pass()
        writer.start()
        assert applying.wait(2)
        app.delivery.worker.run_pass()
        assert rows(app, 'receipt')[0]['error'] == 'provider_auth'
        release.set()
        writer.join(3)
        app.delivery.worker.run_pass()
        assert len(app.delivery._transport.calls) == 1
        assert rows(app, 'receipt')[0]['attempt'] == 1
    finally:
        release.set()
        writer.join(3)
        app.delivery.stop()


@pytest.mark.parametrize('channel', ['teams', 'misp'])
def test_auth_block_survives_clean_restart_until_own_repair(tmp_path, monkeypatch, channel):
    config = {'domains': [{'name': 'test.example', 'type': 'A'}], 'servers': ['fake'],
        'alerts': ({'teams_webhook': 'https://teams.invalid/hook'} if channel == 'teams' else
                   {'misp_url': 'https://misp.invalid', 'api_key': 'old', 'push_event_id': '7'}),
        'config_revision': 0}
    transport = Transport(Response(status=401), Response(status=401))
    app = app_factory(tmp_path, config=config, transport=transport)
    scan(app, monkeypatch, ['1.2.3.4'])
    app.delivery.worker.run_pass()
    old = rows(app, 'receipt')[0]
    saved = app.service.snapshot()
    app.delivery.stop()
    app = app_factory(tmp_path, config=saved, transport=transport)
    try:
        app.delivery.worker.run_pass()
        assert len(transport.calls) == 1
        assert rows(app, 'receipt')[0]['attempt'] == old['attempt']
        fields = {'teams_webhook': 'https://teams.invalid/hook'} if channel == 'teams' else {'api_key': 'repaired'}
        app.service.commit('settings', {'alerts': fields}, expected_revision=0)
        app.delivery.worker.run_pass()
        app.delivery.worker.run_pass()
        assert len(transport.calls) == 2
        assert rows(app, 'receipt')[0]['attempt'] == 2
        assert rows(app, 'receipt')[0]['provider_calls'] == 2
    finally:
        app.delivery.stop()


def test_legacy_shared_discovery_epoch_does_not_authorize_retry_on_upgrade(tmp_path, monkeypatch):
    import json
    import sqlite3
    transport = Transport(Response(status=401), Response(status=401))
    app = app_factory(tmp_path, transport=transport)
    scan(app, monkeypatch, ['1.2.3.4'])
    app.delivery.worker.run_pass()
    app.delivery.stop()
    # Reconstruct the predecessor schema-1 control epoch after an unrelated
    # descriptor discovery. No secrets, extra schema, or new receipt identities.
    with sqlite3.connect(tmp_path / 'delivery.sqlite') as db:
        control = json.loads(db.execute('SELECT data FROM control').fetchone()[0])
        control.pop('adapter_revision_teams', None)
        control.pop('adapter_revision_misp', None)
        control['adapter_revision'] = 9
        db.execute('UPDATE control SET data=?', (json.dumps(control),))
        db.execute('UPDATE receipt SET block_revision=7,claim_revision=7')
    app = app_factory(tmp_path, transport=transport)
    try:
        app.delivery.worker.run_pass()
        assert len(transport.calls) == 1, 'legacy discovery epoch is not proof of repair'
        assert rows(app, 'receipt')[0]['attempt'] == 1
        app.service.commit('settings', {'alerts': {'teams_webhook': 'https://teams.invalid/hook'}}, expected_revision=0)
        app.delivery.worker.run_pass()
        assert len(transport.calls) == 2
        assert rows(app, 'receipt')[0]['attempt'] == 2
    finally:
        app.delivery.stop()


def test_same_binding_repair_during_storage_failure_retries_once_after_recovery(tmp_path, monkeypatch):
    transport = Transport(Response(status=401), Response(status=401))
    app = app_factory(tmp_path, transport=transport)
    try:
        scan(app, monkeypatch, ['1.2.3.4'])
        app.delivery.worker.run_pass()
        with app.delivery.store._lock:
            app.delivery.store._execute('PRAGMA query_only=ON')
        app.service.commit('settings', {'alerts': {'teams_webhook': 'https://teams.invalid/hook'}}, expected_revision=0)
        # A later unrelated commit cannot erase the bounded outstanding repair.
        app.service.commit('config', {'interval': 78}, expected_revision=1)
        with app.delivery.store._lock:
            app.delivery.store._execute('PRAGMA query_only=OFF')
        scan(app, monkeypatch, ['1.2.3.4'])
        app.delivery.worker.run_pass()
        assert len(transport.calls) == 2
        assert rows(app, 'receipt')[0]['attempt'] == 2
        scan(app, monkeypatch, ['1.2.3.4'])
        app.delivery.worker.run_pass()
        assert len(transport.calls) == 2
        assert rows(app, 'receipt')[0]['provider_calls'] == 2
    finally:
        app.delivery.stop()


@pytest.mark.parametrize('later_config', [False, True])
def test_unknown_repair_commit_readback_cannot_mint_second_authorization_epoch(tmp_path, monkeypatch, later_config):
    import json
    import sqlite3
    transport = Transport(Response(status=401), Response(status=401))
    app = app_factory(tmp_path, transport=transport)
    try:
        scan(app, monkeypatch, ['1.2.3.4'])
        app.delivery.worker.run_pass()
        store = app.delivery.store
        applied = store.configuration_applied
        def uncertain(*args, **kwargs):
            def fail(point):
                if point == 'after_commit':
                    raise sqlite3.OperationalError('fixture commit return')
            with monkeypatch.context() as mp:
                mp.setattr(store, '_fault', fail)
                mp.setattr(store, '_read_control', lambda: (_ for _ in ()).throw(sqlite3.OperationalError('fixture read')))
                return applied(*args, **kwargs)
        with monkeypatch.context() as mp:
            mp.setattr(store, 'configuration_applied', uncertain)
            result = app.service.commit('settings', {'alerts': {'teams_webhook': 'https://teams.invalid/hook'}}, expected_revision=0)
        assert result['warnings'] == ['delivery_configuration_apply_failed']
        epoch = json.loads(rows(app, 'control')[0]['data'])['adapter_revision_teams']
        assert store._unresolved is not None
        if later_config:
            app.service.commit('config', {'interval': 78}, expected_revision=1)
        scan(app, monkeypatch, ['1.2.3.4'])
        assert store._unresolved is None
        assert json.loads(rows(app, 'control')[0]['data'])['adapter_revision_teams'] == epoch
        app.delivery.worker.run_pass()
        app.delivery.worker.run_pass()
        assert len(transport.calls) == 2
        assert rows(app, 'receipt')[0]['attempt'] == 2
    finally:
        app.delivery.stop()
