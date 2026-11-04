"""Owned DHT lookup authority and cooperative cancellation regressions."""
import threading

import pytest

from monitor import engine
from test_dht_monitor import observation, target
from test_lookup_liveness import owned_app, background_scan, MonotonicClock, wait_for
from test_stage3_core_runtime import rows


@pytest.mark.parametrize('acknowledge,abort_failure', [(False, False), (True, False), (True, True)])
def test_dht_token_precedes_fetch_and_uncertain_timeout_retains_it(tmp_path, monkeypatch, acknowledge, abort_failure):
    clock = MonotonicClock()
    obs, key = observation(7)
    domain = target(key)
    domain['dht_options'] = {'duration': .05}
    app = owned_app(tmp_path, domains=[domain], clock=clock)
    aborts = []
    if abort_failure:
        def fail_abort(*args):
            aborts.append(args)
            raise OSError('synthetic token cleanup failure')
        monkeypatch.setattr(app.delivery.store, 'abort_dht', fail_abort)
    entered, release = threading.Event(), threading.Event()
    seen = []
    def fetch(*args, cancelled=None, **kwargs):
        seen.append((rows(app, 'dht_state'), cancelled))
        entered.set()
        assert release.wait(10)
        if acknowledge and cancelled():
            return {'records': [], 'status': 'cancelled', 'coverage': {'termination': 'cancelled'}}
        return obs
    # Explicit injected collector preserves potentially acquired evidence on late return.
    from monitor.collect import Collected
    from models import QueryResult
    def collect(ds, server, *, cancelled=None):
        value = fetch(cancelled=cancelled)
        return Collected(QueryResult(server='DHT', domain=ds.name, rtype='DHT',
                                     status='error', values=[]), None, value)
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    thread, results, errors = background_scan(app)
    try:
        assert entered.wait(2)
        assert seen[0][0] and seen[0][0][0]['pending'], 'durable begin must precede fetch'
        token = seen[0][0][0]['pending']
        assert callable(seen[0][1])
        clock.now = 5.05
        thread.join(2)
        assert not thread.is_alive() and not errors and not results[0].complete
        assert rows(app, 'dht_state')[0]['pending'] == token
        release.set()
        assert wait_for(lambda: app.lookup.status()['active'] == 0)
        assert bool(rows(app, 'dht_state')[0]['pending']) == (not acknowledge or abort_failure)
        assert bool(aborts) == abort_failure
        assert not any(app.current.values())
    finally:
        release.set()
        thread.join(3)
        app.lookup.stop()
        app.delivery.stop()


def test_owned_dht_invalid_highwater_survives_history_failure_and_reopen(tmp_path, monkeypatch):
    from copy import deepcopy
    from dht_state_helpers import application
    from config_manager import domain_storage_name
    from monitor.lookup_runtime import LookupRuntime
    from test_lookup_liveness import owned_scan
    first, key = observation(5)
    domain = target(key)
    name = domain_storage_name(domain)
    app = application(tmp_path / 'owned', [domain])
    app.lookup = LookupRuntime(app.repo)
    try:
        monkeypatch.setattr('dht_query.fetch_dht_records', lambda *a, **k: first)
        assert owned_scan(app).complete
        invalid, _ = observation(7, value=b'not DNS')
        monkeypatch.setattr('dht_query.fetch_dht_records', lambda *a, **k: invalid)
        failed = []
        def fail(*args, **kwargs):
            failed.append(True)
            raise OSError('synthetic history failure')
        with monkeypatch.context() as change:
            change.setattr(app.repo, 'commit_history', fail)
            result = owned_scan(app)
        assert failed and not result.complete
        expected = deepcopy(app.history[name]['meta']['dht_state'])
        assert expected['highest_seq'] == '7'
    finally:
        app.lookup.stop()
        app.delivery.stop()
    app = application(tmp_path / 'owned', [domain], restart=True)
    app.lookup = LookupRuntime(app.repo)
    try:
        assert app.history[name]['meta']['dht_state'] == expected
        lower, _ = observation(6, ips=())
        monkeypatch.setattr('dht_query.fetch_dht_records', lambda *a, **k: lower)
        result = owned_scan(app)
        assert not result.complete and set(result) == {'192.0.2.123'}
        assert app.history[name]['meta']['dht_state'] == expected
        assert not rows(app, 'grace')
    finally:
        app.lookup.stop()
        app.delivery.stop()
