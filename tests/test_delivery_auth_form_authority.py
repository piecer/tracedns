"""Normal-form repair classification must preserve runtime/store authority."""
import sqlite3

import pytest

from test_delivery_auth_form_regressions import blocked_app, config, control, normal_form, save
from test_stage3_core_runtime import rows, scan


@pytest.mark.parametrize('channel', ['teams', 'misp'])
def test_failed_apply_stays_unready_then_uses_original_repair_revision(tmp_path, monkeypatch, channel):
    app = blocked_app(tmp_path, monkeypatch, channel)
    try:
        apply = app.delivery.registry.apply
        key = 'teams_webhook' if channel == 'teams' else 'api_key'
        def fail(alerts, *, revision, applied=True):
            if applied:
                raise OSError('fixture registry apply')
            return apply(alerts, revision=revision, applied=False)
        form = normal_form(config(channel)['alerts'])
        form[key] = config(channel)['alerts'][key]
        with monkeypatch.context() as patch:
            patch.setattr(app.delivery.registry, 'apply', fail)
            result = save(app, form)
        assert 'alerts_runtime_apply_failed' in result['warnings']
        app.delivery.worker.run_pass()
        assert len(app.delivery._transport.calls) == 1
        assert rows(app, 'receipt')[0]['attempt'] == 1
        assert not next(b for b in app.delivery.bindings() if b['channel'] == channel)['ready']
        epoch = control(app)['adapter_revision_' + channel]
        assert control(app)['applied_config_' + channel] == 1
        # Successful apply after an unrelated full form can consume the original
        # repair authorization, but may not create one at revision 2 or later.
        for _ in range(2):
            save(app, normal_form(config(channel)['alerts']))
            app.delivery.worker.run_pass()
        assert control(app)['adapter_revision_' + channel] == epoch
        assert control(app)['applied_config_' + channel] == 1
        assert rows(app, 'receipt')[0]['attempt'] == len(app.delivery._transport.calls) == 2
    finally:
        app.delivery.stop()


@pytest.mark.parametrize('channel', ['teams', 'misp'])
def test_unknown_repair_commit_full_form_saves_keep_origin_epoch(tmp_path, monkeypatch, channel):
    app = blocked_app(tmp_path, monkeypatch, channel)
    try:
        store = app.delivery.store
        original = store.configuration_applied
        def uncertain(*args, **kwargs):
            def fault(where):
                if where == 'after_commit':
                    raise sqlite3.OperationalError('fixture unknown commit')
            def readback():
                raise sqlite3.OperationalError('fixture readback unavailable')
            with monkeypatch.context() as patch:
                patch.setattr(store, '_fault', fault)
                patch.setattr(store, '_read_control', readback)
                return original(*args, **kwargs)
        form = normal_form(config(channel)['alerts'])
        key = 'teams_webhook' if channel == 'teams' else 'api_key'
        form[key] = config(channel)['alerts'][key]
        with monkeypatch.context() as patch:
            patch.setattr(store, 'configuration_applied', uncertain)
            result = save(app, form)
        assert 'delivery_configuration_apply_failed' in result['warnings']
        assert store._unresolved is not None
        epoch = control(app)['adapter_revision_' + channel]
        assert control(app)['applied_config_' + channel] == 1
        for index in range(2):
            form = normal_form(config(channel)['alerts'])
            form['vt_cache_ttl_days'] = index + 2
            save(app, form)
            scan(app, monkeypatch, ['192.0.2.10'])
            app.delivery.worker.run_pass()
            assert store._unresolved is None
            assert control(app)['adapter_revision_' + channel] == epoch
            assert control(app)['applied_config_' + channel] == 1
            assert rows(app, 'receipt')[0]['attempt'] == len(app.delivery._transport.calls) == 2
    finally:
        app.delivery.stop()
