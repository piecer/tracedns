"""F-AUTH-01: real producer, repository, ledger, adapters and worker.

Only collection and provider HTTP are fixtures; SQL assertions use a separate
connection. Normal form values match saveAlertSettings's redacted fields.
"""
import json

import pytest

from test_stage3_core_runtime import app_factory, rows, scan
from test_delivery_adapters_steps import Response


class AuthWire:
    def __init__(self):
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url))
        return Response(status=401)


def config(channel='teams'):
    alerts = {'vt_cache_ttl_days': 1}
    if 'teams' in channel:
        alerts['teams_webhook'] = 'https://teams.invalid/hook'
    if 'misp' in channel:
        alerts.update(misp_url='https://misp.invalid', api_key='fixture-key',
                      push_event_id='9', misp_remove_on_absent=True)
    return {'domains': [{'name': 'test.example', 'type': 'A'}],
            'servers': ['fake'], 'alerts': alerts, 'config_revision': 0}


def normal_form(alerts):
    return {'teams_webhook': '', 'misp_url': '', 'api_key': '', 'misp_ca_bundle': '',
            'push_event_id': str(alerts.get('push_event_id') or ''),
            'misp_remove_on_absent': alerts.get('misp_remove_on_absent', False),
            'vt_api_key': '', 'vt_cache_ttl_days': alerts.get('vt_cache_ttl_days', 1)}


def control(app):
    return json.loads(rows(app, 'control')[0]['data'])


def save(app, alerts, **extra):
    return app.service.commit('settings', {'alerts': alerts, **extra},
                              expected_revision=app.service.snapshot()['config_revision'])


def blocked_app(tmp_path, monkeypatch, channel):
    app = app_factory(tmp_path, config=config(channel), transport=AuthWire())
    scan(app, monkeypatch, ['192.0.2.10'])
    app.delivery.worker.run_pass()
    receipts = rows(app, 'receipt')
    assert receipts and all(r['attempt'] == 1 and r['error'] == 'provider_auth' for r in receipts)
    return app


@pytest.mark.parametrize('channel', ['teams', 'misp'])
def test_blank_preserving_normal_settings_form_is_not_credential_repair(tmp_path, monkeypatch, channel):
    """Persist both channel variants of the independent reviewer's normal-form RED."""
    app = blocked_app(tmp_path, monkeypatch, channel)
    try:
        before = rows(app, 'receipt')
        epoch = control(app)['adapter_revision_' + channel]
        form = normal_form(config(channel)['alerts'])
        form['vt_cache_ttl_days'] = 2
        save(app, form)
        for _ in range(2):
            app.delivery.worker.run_pass()
        assert len(app.delivery._transport.calls) == 1, 'blank-preserve is not auth repair'
        assert rows(app, 'receipt') == before
        assert control(app)['adapter_revision_' + channel] == epoch
        assert app.cfg.raw['alerts'] == {**config(channel)['alerts'], **{
            k: v for k, v in form.items() if k not in ('teams_webhook', 'misp_url', 'api_key', 'vt_api_key', 'misp_ca_bundle')}}
    finally:
        app.delivery.stop()


@pytest.mark.parametrize('channel', ['teams', 'misp', 'teams misp'])
def test_blank_saves_do_not_exhaust_retained_auth_obligation(tmp_path, monkeypatch, channel):
    """Reviewer exhaustion RED, extended to both channels and every intermediate save."""
    app = blocked_app(tmp_path, monkeypatch, channel)
    try:
        receipts = rows(app, 'receipt')
        batches = rows(app, 'batch')
        before = control(app)
        for index in range(8):
            form = normal_form(config(channel)['alerts'])
            form['vt_cache_ttl_days'] = index + 2
            save(app, form)
            app.delivery.worker.run_pass()
            assert rows(app, 'receipt') == receipts
            assert rows(app, 'batch') == batches
            assert len(app.delivery._transport.calls) == len(receipts)
            assert control(app)['failed_total'] == 0
            for name in ('teams', 'misp'):
                assert control(app)['adapter_revision_' + name] == before['adapter_revision_' + name]
        assert control(app)['failed_total'] == 0, 'unrelated saves exhausted admitted work'
        assert rows(app, 'receipt') == receipts
        assert rows(app, 'batch') == batches
        assert rows(app, 'terminal') == []
        assert len(app.delivery._transport.calls) == len(receipts)
        for name in ('teams', 'misp'):
            assert control(app)['adapter_revision_' + name] == before['adapter_revision_' + name]
        repair = {k: v for k, v in config(channel)['alerts'].items()
                  if k in ('teams_webhook', 'api_key')}
        save(app, repair)
        app.delivery.worker.run_pass()
        app.delivery.worker.run_pass()
        assert len(app.delivery._transport.calls) == 2 * len(receipts)
        assert {r['id'] for r in rows(app, 'receipt')} == {r['id'] for r in receipts}
        assert all(r['attempt'] == r['provider_calls'] == 2 for r in rows(app, 'receipt'))
    finally:
        app.delivery.stop()


@pytest.mark.parametrize('prior,submitted', [
    ({'push_event_id': 9}, {'push_event_id': '9'}),
    ({'misp_remove_on_absent': 'true'}, {'misp_remove_on_absent': True}),
    ({'misp_remove_on_absent': '1'}, {'misp_remove_on_absent': ' YES '}),
    ({'misp_remove_on_absent': False}, {'misp_remove_on_absent': 'off'}),
])
def test_normalized_unchanged_nonsecret_is_not_repair(tmp_path, monkeypatch, prior, submitted):
    cfg = config('misp')
    cfg['alerts'].update(prior)
    app = app_factory(tmp_path, config=cfg, transport=AuthWire())
    try:
        scan(app, monkeypatch, ['192.0.2.10'])
        app.delivery.worker.run_pass()
        before = rows(app, 'receipt')
        epoch = control(app)['adapter_revision_misp']
        save(app, submitted)
        app.delivery.worker.run_pass()
        assert len(app.delivery._transport.calls) == 1
        assert rows(app, 'receipt') == before
        assert control(app)['adapter_revision_misp'] == epoch
    finally:
        app.delivery.stop()
