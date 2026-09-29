import json

import pytest

from test_stage3_core_runtime import app_factory, rows, scan
from test_delivery_core_gap_authority import control, assert_exact_authority


@pytest.mark.parametrize('restart', [False, True])
def test_failed_retirement_identical_readd_cannot_attach_old_incarnation(tmp_path, monkeypatch, restart):
    app = app_factory(tmp_path)
    scan(app, monkeypatch, ['1.2.3.4'])
    old = rows(app, 'cursor')[0]
    receipt = rows(app, 'receipt')
    original_lease = app.repo.capture()['test.example']
    with app.delivery.store._lock:
        app.delivery.store._execute('PRAGMA query_only=ON')
    result = app.service.commit('config', {'domains': []}, expected_revision=0)
    assert result['warnings'] == ['delivery_configuration_refresh_failed']
    assert not app.repo.valid(original_lease)
    assert app.current == {} and app.history == {}
    assert not (tmp_path / 'test.example.json').exists()
    assert rows(app, 'receipt') == receipt
    assert control(app)['revision'] == 0
    assert app.delivery.store.health_snapshot()['coverage'] == 'gap'
    result = app.service.commit('config', {'domains': [{'name': 'test.example', 'type': 'A'}]}, expected_revision=1)
    assert result['warnings'] == ['delivery_configuration_refresh_failed']
    scan(app, monkeypatch, ['2.3.4.5'])
    assert app.current['test.example']['fake']['values'] == ['2.3.4.5']
    assert json.loads((tmp_path / 'test.example.json').read_text())['current']['fake']['values'] == ['2.3.4.5']
    assert rows(app, 'receipt') == receipt
    config = app.service.snapshot()
    if restart:
        app.delivery.stop()  # cannot overwrite the persisted nonclean marker
        app = app_factory(tmp_path, config=config,
            current={'test.example': json.loads((tmp_path / 'test.example.json').read_text())['current']})
        assert app.delivery.store.health_snapshot()['coverage'] == 'rebaselining'
        assert rows(app, 'cursor')[0]['incarnation'] != old['incarnation']
        assert control(app)['revision'] != 2, 'bootstrap cannot certify stale projection authority'
    else:
        with app.delivery.store._lock:
            app.delivery.store._execute('PRAGMA query_only=OFF')
    try:
        scan(app, monkeypatch, ['2.3.4.5'])
        assert rows(app, 'cursor')[0]['incarnation'] != old['incarnation']
        assert rows(app, 'receipt') == receipt
        assert_exact_authority(app)
        assert app.delivery.store.health_snapshot()['coverage'] == 'covered'
        assert not app.delivery.store.health_snapshot()['accounting_complete']
        scan(app, monkeypatch, ['2.3.4.5', '3.4.5.6'])
        assert len(rows(app, 'receipt')) == 2
    finally:
        app.delivery.stop()
