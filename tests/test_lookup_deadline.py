"""Deadline eligibility follows the original ticket through reduction."""
import threading

import pytest

from monitor import engine
from test_lookup_liveness import owned_app, background_scan, MonotonicClock, success
from test_stage3_core_runtime import rows


@pytest.mark.parametrize('boundary', ['candidate', 'admission'])
def test_ready_result_expiring_during_parent_reduction_cannot_publish(tmp_path, monkeypatch, boundary):
    clock = MonotonicClock()
    app = owned_app(tmp_path, servers=['healthy'], clock=clock)
    entered, release = threading.Event(), threading.Event()
    name = 'observation_candidate' if boundary == 'candidate' else 'accept_observation'
    original = getattr(app.repo, name)
    fired = []
    def delayed(*args, **kwargs):
        if not fired:
            fired.append(True)
            entered.set()
            assert release.wait(10)
        return original(*args, **kwargs)
    monkeypatch.setattr(app.repo, name, delayed)
    monkeypatch.setattr(engine, 'collect_snapshot', success)
    thread, results, errors = background_scan(app)
    try:
        assert entered.wait(2)
        clock.now = 5
        release.set()
        thread.join(2)
        assert not thread.is_alive() and not errors
        assert app.current['test.example'] == {}, 'expired acquired result crossed source admission'
        assert rows(app, 'receipt') == []
        assert not results[0].complete and results[0].positive == {}
    finally:
        release.set()
        thread.join(3)
        app.lookup.stop()
        app.delivery.stop()


def test_native_collection_checks_budget_before_decoding(tmp_path, monkeypatch):
    from monitor import collect
    clock = MonotonicClock()
    app = owned_app(tmp_path, domains=[{'name': 'test.example', 'type': 'TXT'}],
                    servers=['healthy'], clock=clock)
    calls = []
    def query(*args, **kwargs):
        calls.append('query')
        assert kwargs.get('timeout', 2) <= 2
        clock.now = 5
        return {'status': 'ok', 'values': ['synthetic']}
    def decode(*args, **kwargs):
        calls.append('decode')
        return ['192.0.2.2']
    monkeypatch.setattr(collect, 'query_dns', query)
    monkeypatch.setattr(collect, 'decode_txt_hidden_ips', decode)
    try:
        from test_lookup_liveness import owned_scan
        result = owned_scan(app)
        assert calls == ['query'], 'expired transport return must not begin decoder work'
        assert not result.complete and app.current['test.example'] == {}
    finally:
        app.lookup.stop()
        app.delivery.stop()
