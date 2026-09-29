from datetime import datetime
import json

from monitor.delivery_runtime import render_batch
from test_stage3_core_runtime import app_factory, scan
from test_delivery_adapters_steps import Response, Transport


def test_teams_seal_uses_observation_timestamp_not_renderer_wall_clock():
    created = 100000
    body = render_batch([['1.2.3.4', 'label', 'A']], 'Added', created)
    expected = datetime.fromtimestamp(created).astimezone().strftime('%Y-%m-%d %H:%M:%S %Z (%z)')
    assert 'Time (Local): ' + expected in body['text']


def test_renderer_bridge_validates_final_timestamp_inside_actual_renderer(monkeypatch):
    from monitor import delivery_runtime
    original = delivery_runtime.render_teams_body
    def renderer(action, entries, context=None):
        assert context == {'created': 0}, 'timestamp must participate in renderer byte validation'
        return original(action, entries, context)
    monkeypatch.setattr(delivery_runtime, 'render_teams_body', renderer)
    result = render_batch([['1.2.3.4', 'label', 'A']], 'Added', 0)
    assert '1970-' in result['text']


def test_sighting_progress_survives_pass_boundary_and_rotation(tmp_path, monkeypatch):
    import mispupdate_code
    monkeypatch.setenv('MISP_SIGHTING_BATCH_FILE', str(tmp_path / 'sightings'))
    cfg = {'domains': [{'name': 'test.example', 'type': 'A'}], 'servers': ['fake'],
           'alerts': {'misp_url': 'https://misp.invalid', 'api_key': 'secret', 'push_event_id': '12'},
           'config_revision': 0}
    event = {'Event': {'id': '12', 'Attribute': [{'id': '7', 'event_id': '12', 'type': 'ip-src', 'value': '1.2.3.4'}]}}
    transport = Transport(Response(event), Response(event),
                          Response({'Sighting': {'id': '9', 'event_id': '12', 'attribute_id': '7', 'type': '0'}}))
    app = app_factory(tmp_path, config=cfg, transport=transport)
    try:
        scan(app, monkeypatch, ['1.2.3.4'])
        app.delivery.worker.run_pass(max_provider_calls=1)
        pending = mispupdate_code._load_sighting_batch_state()['events']['12']['pending']
        assert pending == ['1.2.3.4'], 'first authoritative existing-IP observation hook must attach'
        app.delivery.worker.run_pass(max_provider_calls=1)
        assert len(transport.calls) == 2
        app.delivery.worker.run_pass(max_provider_calls=1)
        assert len(transport.calls) == 3
        assert transport.calls[-1][1].endswith('/sightings/add/7')
        assert mispupdate_code._load_sighting_batch_state()['events']['12']['pending'] == []
        # Independently exercise binding change between read and sighting POST.
        calls = []
        def step(adapter, progress=None, **kwargs):
            calls.append((adapter.binding_id, dict(progress or {})))
            return {'state': 'continue', 'reason': None, 'progress': {'phase': 'sighting', 'ip': '1.2.3.4',
                    'attribute_id': '7', 'binding_id': adapter.binding_id},
                    'provider_calls': 1, 'retry_after': None, 'observation_hook': None}
        monkeypatch.setattr(mispupdate_code, 'flush_sightings_step', step)
        app.delivery.sightings_step()
        app.service.commit('settings', {'alerts': {'push_event_id': '13'}}, expected_revision=0)
        app.delivery.sightings_step()
        assert calls[-1][1] == {}
        assert calls[-1][0] != calls[0][0]
    finally:
        app.delivery.stop()


def test_zero_call_sighting_failure_ends_pass(tmp_path, monkeypatch):
    import mispupdate_code
    cfg = {'domains': [], 'servers': [], 'alerts': {'misp_url': 'https://misp.invalid',
           'api_key': 'secret', 'push_event_id': '12'}, 'config_revision': 0}
    app = app_factory(tmp_path, config=cfg)
    calls = []
    def step(*a, **k):
        calls.append(1)
        return {'state': 'failed', 'reason': 'payload_invalid', 'progress': {},
                'provider_calls': 0, 'retry_after': None, 'observation_hook': None}
    monkeypatch.setattr(mispupdate_code, 'flush_sightings_step', step)
    try:
        app.delivery.worker.run_pass()
        assert calls == [1]
        assert 'secret' not in json.dumps(app.delivery.store.health_snapshot())
    finally:
        app.delivery.stop()
