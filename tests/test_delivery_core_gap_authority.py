import json

from test_stage3_core_runtime import Clock, app_factory, rows, scan


def control(app):
    return json.loads(rows(app, 'control')[0]['data'])


def assert_exact_authority(app):
    actual = control(app)
    authority = app.delivery.authority()
    assert actual['revision'] == authority['revision']
    assert actual['signature'] == authority['signature']


def test_committed_authority_refresh_preserves_unchanged_detector_enrolls_empty(tmp_path, monkeypatch):
    app = app_factory(tmp_path)
    try:
        scan(app, monkeypatch, ['1.2.3.4'])
        cursor, baseline, receipt = rows(app, 'cursor'), rows(app, 'baseline'), rows(app, 'receipt')
        app.service.commit('config', {'interval': 77}, expected_revision=0)
        assert_exact_authority(app)
        assert rows(app, 'cursor') == cursor
        assert rows(app, 'baseline') == baseline
        assert rows(app, 'receipt') == receipt
        result = app.service.commit('config', {'domains': [
            {'name': 'test.example', 'type': 'A'}, {'name': 'empty.example', 'type': 'A'}]}, expected_revision=1)
        assert not result['warnings']
        assert_exact_authority(app)
        cursors = {r['target']: r for r in rows(app, 'cursor')}
        assert cursors['test.example'] == cursor[0]
        assert json.loads(cursors['empty.example']['ips']) == []
        assert rows(app, 'baseline') == baseline
        assert rows(app, 'grace') == []
        app.service.commit('config', {'domains': []}, expected_revision=2)
        assert_exact_authority(app)
        assert rows(app, 'cursor') == []
        assert rows(app, 'receipt') == receipt
        assert rows(app, 'baseline') == baseline
        assert rows(app, 'grace') == [], 'configuration alone is not absence'
    finally:
        app.delivery.stop()


def test_provider_change_baselines_current_configured_union_not_history(tmp_path, monkeypatch):
    current = {'test.example': {'fake': {'values': ['1.2.3.4']}, 'new': {'values': ['2.3.4.5']}}}
    app = app_factory(tmp_path, current=current)
    try:
        old = rows(app, 'cursor')[0]
        baseline = rows(app, 'baseline')
        app.service.commit('config', {'servers': ['new']}, expected_revision=0)
        assert_exact_authority(app)
        cursor = rows(app, 'cursor')[0]
        assert cursor['incarnation'] != old['incarnation']
        assert json.loads(cursor['ips']) == ['2.3.4.5']
        assert rows(app, 'baseline') == baseline
        assert rows(app, 'grace') == []
        scan(app, monkeypatch, ['2.3.4.5'])
        assert rows(app, 'receipt') == []
        assert rows(app, 'grace')[0]['ip'] == '1.2.3.4'
        scan(app, monkeypatch, ['2.3.4.5', '3.4.5.6'])
        assert json.loads(rows(app, 'receipt')[0]['payload'])['entries'][0][0] == '3.4.5.6'
    finally:
        app.delivery.stop()


def test_clean_config_change_restart_preserves_eligible_grace_time(tmp_path, monkeypatch):
    clock = Clock()
    app = app_factory(tmp_path, current={'test.example': {'fake': {'values': ['1.2.3.4']}}}, clock=clock)
    scan(app, monkeypatch, [])
    grace = rows(app, 'grace')
    app.service.commit('config', {'interval': 77}, expected_revision=0)
    config = app.service.snapshot()
    app.delivery.stop()
    clock.now += 86399
    app = app_factory(tmp_path, config=config, clock=clock)
    try:
        assert app.delivery.store.health_snapshot()['coverage'] == 'covered'
        assert rows(app, 'grace') == grace
        scan(app, monkeypatch, [])
        assert rows(app, 'grace') == grace
        clock.now += 1
        scan(app, monkeypatch, [])
        assert rows(app, 'grace') == []
        assert rows(app, 'receipt')[0]['action'] == 'Removed'
    finally:
        app.delivery.stop()
