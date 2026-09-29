"""Repair intent controls through the real producer/store/worker composition."""
import json
from pathlib import Path

import pytest
from requests.certs import where

from monitor.config_service import ConfigError
from test_delivery_auth_form_regressions import (
    AuthWire, blocked_app, config, control, normal_form, save,
)
from test_stage3_core_runtime import app_factory, rows, scan


@pytest.mark.parametrize('change', ['unchanged', 'ttl', 'teams', 'misp'])
def test_full_form_authorizes_only_actual_channel_repair(tmp_path, monkeypatch, change):
    app = blocked_app(tmp_path, monkeypatch, 'teams misp')
    try:
        before = {r['channel']: r for r in rows(app, 'receipt')}
        epochs = control(app)
        form = normal_form(config('teams misp')['alerts'])
        if change == 'ttl':
            form['vt_cache_ttl_days'] = 3
        elif change == 'teams':
            form['teams_webhook'] = config('teams')['alerts']['teams_webhook']
        elif change == 'misp':
            form['api_key'] = 'rotated-key'
        save(app, form)
        app.delivery.worker.run_pass()
        app.delivery.worker.run_pass()
        for receipt in rows(app, 'receipt'):
            channel = receipt['channel']
            assert receipt['id'] == before[channel]['id']
            assert receipt['attempt'] == receipt['provider_calls'] == (2 if channel == change else 1)
            assert control(app)['adapter_revision_' + channel] == epochs['adapter_revision_' + channel] + (channel == change)
        assert len(app.delivery._transport.calls) == (3 if change in ('teams', 'misp') else 2)
    finally:
        app.delivery.stop()


@pytest.mark.parametrize('key', ['teams_webhook', 'misp_url', 'api_key', 'misp_ca_bundle'])
def test_explicit_nonblank_same_binding_reapply_remains_repair(tmp_path, monkeypatch, key):
    channel = 'teams' if key == 'teams_webhook' else 'misp'
    cfg = config(channel)
    if key == 'misp_ca_bundle':
        bundle = tmp_path / 'ca.pem'
        bundle.write_bytes(Path(where()).read_bytes())
        cfg['alerts'][key] = str(bundle)
    app = app_factory(tmp_path, config=cfg, transport=AuthWire())
    try:
        scan(app, monkeypatch, ['192.0.2.10'])
        app.delivery.worker.run_pass()
        receipt = rows(app, 'receipt')[0]
        before = control(app)
        form = normal_form(cfg['alerts'])
        form[key] = cfg['alerts'][key]
        save(app, form)
        app.delivery.worker.run_pass()
        app.delivery.worker.run_pass()
        new = rows(app, 'receipt')[0]
        assert (new['id'], new['binding']) == (receipt['id'], receipt['binding'])
        assert new['attempt'] == new['provider_calls'] == len(app.delivery._transport.calls) == 2
        assert control(app)['adapter_revision_' + channel] == before['adapter_revision_' + channel] + 1
    finally:
        app.delivery.stop()


@pytest.mark.parametrize('blank', ['', ' \t\n', None])
@pytest.mark.parametrize('channel', ['teams', 'misp'])
def test_preserve_blank_secret_variants_never_authorize(tmp_path, monkeypatch, channel, blank):
    app = blocked_app(tmp_path, monkeypatch, channel)
    try:
        before = rows(app, 'receipt')
        epoch = control(app)['adapter_revision_' + channel]
        form = normal_form(config(channel)['alerts'])
        for key in ('teams_webhook', 'misp_url', 'api_key'):
            form[key] = blank
        save(app, form)
        app.delivery.worker.run_pass()
        assert rows(app, 'receipt') == before
        assert control(app)['adapter_revision_' + channel] == epoch
        assert len(app.delivery._transport.calls) == 1
    finally:
        app.delivery.stop()


@pytest.mark.parametrize('key,value,blocked', [
    ('push_event_id', '10', True),
    ('misp_url', 'https://misp.invalid/changed', True),
    ('teams_webhook', 'https://teams.invalid/changed', True),
    ('api_key', 'rotated', False),
    ('misp_remove_on_absent', False, False),
])
def test_changed_relevant_setting_keeps_binding_fence(tmp_path, monkeypatch, key, value, blocked):
    channel = 'teams' if key == 'teams_webhook' else 'misp'
    app = blocked_app(tmp_path, monkeypatch, channel)
    try:
        before = rows(app, 'receipt')[0]
        epoch = control(app)['adapter_revision_' + channel]
        form = normal_form(config(channel)['alerts'])
        form[key] = value
        save(app, form)
        app.delivery.worker.run_pass()
        new = rows(app, 'receipt')[0]
        assert (new['id'], new['binding']) == (before['id'], before['binding'])
        assert control(app)['adapter_revision_' + channel] == epoch + 1
        assert len(app.delivery._transport.calls) == new['attempt'] == (1 if blocked else 2)
        assert new['error'] == ('old_binding_blocked' if blocked else 'provider_auth')
    finally:
        app.delivery.stop()


@pytest.mark.parametrize('key', ['teams_webhook', 'misp_url', 'api_key'])
def test_clear_overrides_nonblank_reapply_then_same_binding_restore(tmp_path, monkeypatch, key):
    channel = 'teams' if key == 'teams_webhook' else 'misp'
    app = blocked_app(tmp_path, monkeypatch, channel)
    try:
        original = config(channel)['alerts'][key]
        receipt = rows(app, 'receipt')[0]
        epoch = control(app)['adapter_revision_' + channel]
        save(app, {key: original}, clear_fields=[key])
        assert key not in app.cfg.raw['alerts']
        assert key not in json.loads(Path(app.service.config_path).read_text())['alerts']
        assert key not in app.delivery.selected_alerts
        app.delivery.worker.run_pass()
        assert rows(app, 'receipt')[0]['attempt'] == len(app.delivery._transport.calls) == 1
        assert control(app)['adapter_revision_' + channel] == epoch + 1
        # Clearing an already absent field dominates a submitted nonblank value.
        save(app, {key: original}, clear_fields=[key])
        app.delivery.worker.run_pass()
        assert control(app)['adapter_revision_' + channel] == epoch + 1
        assert len(app.delivery._transport.calls) == 1
        save(app, {key: original})
        app.delivery.worker.run_pass()
        assert rows(app, 'receipt')[0]['id'] == receipt['id']
        assert rows(app, 'receipt')[0]['attempt'] == len(app.delivery._transport.calls) == 2
    finally:
        app.delivery.stop()


def test_absent_ca_clear_beats_nonblank_reapply_without_authorizing(tmp_path, monkeypatch):
    app = blocked_app(tmp_path, monkeypatch, 'misp')
    try:
        bundle = tmp_path / 'ca.pem'
        bundle.write_bytes(Path(where()).read_bytes())
        before = rows(app, 'receipt')
        epoch = control(app)['adapter_revision_misp']
        save(app, {'misp_ca_bundle': str(bundle)}, clear_fields=['misp_ca_bundle'])
        app.delivery.worker.run_pass()
        assert 'misp_ca_bundle' not in app.cfg.raw['alerts']
        assert rows(app, 'receipt') == before
        assert control(app)['adapter_revision_misp'] == epoch
        assert len(app.delivery._transport.calls) == 1
    finally:
        app.delivery.stop()


@pytest.mark.parametrize('failure', ['revision', 'write', 'validation'])
def test_rejected_candidate_never_publishes_repair(tmp_path, monkeypatch, failure):
    app = blocked_app(tmp_path, monkeypatch, 'teams misp')
    try:
        before = app.service.snapshot()
        receipts = rows(app, 'receipt')
        epochs = control(app)
        form = normal_form(config('teams misp')['alerts'])
        form['api_key'] = 'repair'
        if failure == 'validation':
            form['vt_cache_ttl_days'] = 0
        with monkeypatch.context() as patch:
            if failure == 'write':
                def fail(*args):
                    raise OSError('fixture write failure')
                patch.setattr('config_manager.write_config', fail)
            with pytest.raises(ConfigError):
                app.service.commit('settings', {'alerts': form}, expected_revision=-1 if failure == 'revision' else 0)
        assert app.service.snapshot() == before
        assert control(app) == epochs
        app.delivery.worker.run_pass()
        assert rows(app, 'receipt') == receipts
        # A no-claim pass still commits discovery/last_transaction, not repair.
        for channel in ('teams', 'misp'):
            assert control(app)['adapter_revision_' + channel] == epochs['adapter_revision_' + channel]
        assert len(app.delivery._transport.calls) == 2
    finally:
        app.delivery.stop()


@pytest.mark.parametrize('json_alerts', [False, True])
def test_actual_ini_selected_configuration_is_merge_and_comparison_baseline(tmp_path, monkeypatch, json_alerts):
    monkeypatch.chdir(tmp_path)
    (tmp_path / 'config.ini').write_text('[global]\nteams_webhook=https://teams.invalid/hook\n'
        'misp_url=https://misp.invalid\napi_key=fixture-key\npush_event_id=9\nmisp_remove_on_absent=true\n')
    cfg = config('teams misp')
    if json_alerts:
        cfg['alerts'] = {}
    else:
        cfg.pop('alerts')
    app = app_factory(tmp_path, config=cfg, transport=AuthWire())
    try:
        selected = dict(app.delivery.selected_alerts)
        assert bool(selected) != json_alerts
        scan(app, monkeypatch, ['192.0.2.10'])
        app.delivery.worker.run_pass()
        before = rows(app, 'receipt')
        epochs = control(app)
        # Sparse first save must materialize actual selected INI without minting
        # repair. An explicit empty JSON object must never revive INI settings.
        save(app, {'vt_cache_ttl_days': 2})
        app.delivery.worker.run_pass()
        assert rows(app, 'receipt') == before
        for channel in ('teams', 'misp'):
            assert control(app)['adapter_revision_' + channel] == epochs['adapter_revision_' + channel]
        assert app.cfg.raw['alerts'] == {**selected, 'vt_cache_ttl_days': 2}
        assert len(app.delivery._transport.calls) == (0 if json_alerts else 2)
        if not json_alerts:
            form = normal_form(app.cfg.raw['alerts'])
            form['misp_remove_on_absent'] = True
            save(app, form)
            app.delivery.worker.run_pass()
            assert rows(app, 'receipt') == before
            assert len(app.delivery._transport.calls) == 2
    finally:
        app.delivery.stop()
