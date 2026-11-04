"""Delivery-only recovery through real SQLite and the production pass gate."""
import sqlite3

import pytest

from monitor import engine
from test_delivery_adapters_steps import Response, Transport
from test_stage3_core_runtime import app_factory, rows, scan
from test_delivery_store_atomic import AUTH, BINDINGS, obs, rows as ledger_rows, store_at
from test_delivery_store_claims import result


def fail_at(point):
    def fault(actual):
        if actual == point:
            raise sqlite3.OperationalError('fixture transaction fault')
    return fault


def unreadable():
    raise sqlite3.OperationalError('fixture readback fault')


def test_real_worker_recovers_ack_without_full_completion(tmp_path, monkeypatch):
    class AckFault(Transport):
        def request(self, *args, **kwargs):
            response = super().request(*args, **kwargs)
            if len(self.calls) == 1:
                app.delivery.store._execute('PRAGMA query_only=ON')
            return response

    transport = AckFault(Response(status=200), Response(status=200))
    config = {'domains': [{'name': name, 'type': 'A'} for name in ('test.example', 'failed.example')],
              'servers': ['fake'], 'alerts': {'teams_webhook': 'https://teams.invalid/hook'},
              'config_revision': 0}
    app = app_factory(tmp_path, transport=transport, config=config)
    store = app.delivery.store
    try:
        from types import SimpleNamespace
        from models import Snapshot
        def collect(domain, server):
            failed = domain.name == 'failed.example'
            return SimpleNamespace(query=SimpleNamespace(server=server,
                status='error' if failed else 'ok', error='fixture'),
                snapshot=None if failed else Snapshot(type='A', values=['192.0.2.1'],
                                                       decoded_ips=[], ts=int(app.clock())))
        monkeypatch.setattr(engine, 'collect_snapshot', collect)
        snap = app.cfg.snapshot()
        initial = engine.run_full_cycle(domains_raw=snap.domains, servers=snap.servers,
            current_results=app.current, history=app.history, history_dir=app.repo.history_dir,
            query_fail_counts={}, state_repository=app.repo, target_leases=snap.target_leases)
        assert not initial.complete
        store.seal_cycle(None)
        preserved = {t: rows(app, t) for t in ('cursor', 'baseline', 'grace', 'dht_state', 'batch')}
        app.delivery.worker.run_pass()
        original = rows(app, 'receipt')[0]
        assert original['state'] == 'in_flight'
        assert original['attempt'] == original['provider_calls'] == 1
        assert not store.dispatch_available()
        assert not store._gap and not store._rebaseline, 'ACK failure is not lost source evidence'
        store._execute('PRAGMA query_only=OFF')
        # A subsequent real failed provider result cannot certify full absence.
        monkeypatch.setattr(app.delivery, 'complete', lambda *a: (_ for _ in ()).throw(
            AssertionError('delivery recovery must not need complete')))
        monkeypatch.setattr(engine, 'collect_snapshot', lambda d, s: SimpleNamespace(
            query=SimpleNamespace(server=s, status='error', error='fixture'), snapshot=None))
        snap = app.cfg.snapshot()
        failed = engine.run_full_cycle(domains_raw=snap.domains, servers=snap.servers,
            current_results=app.current, history=app.history, history_dir=app.repo.history_dir,
            query_fail_counts={}, state_repository=app.repo, target_leases=snap.target_leases)
        assert not failed.complete
        app.delivery.worker.run_pass(max_provider_calls=0)
        retry = rows(app, 'receipt')[0]
        assert retry['state'] == 'retry_wait'
        assert retry['attempt'] == retry['provider_calls'] == 1
        assert retry['binding'] == original['binding']
        assert {t: rows(app, t) for t in preserved} == preserved
        app.clock.now = retry['due']
        app.delivery.worker.run_pass()
        assert len(transport.calls) == 2
        assert not rows(app, 'receipt')
        assert store.health_snapshot()['acked_total'] == 1
        assert rows(app, 'terminal')[0]['state'] == 'acked'
    finally:
        store._execute('PRAGMA query_only=OFF')
        app.delivery.stop()


@pytest.mark.parametrize('operation', ['source', 'claim', 'ack'])
@pytest.mark.parametrize('point', ['before_commit', 'after_commit'])
def test_exact_unknown_outcome_resolved_before_new_write(tmp_path, monkeypatch, operation, point):
    store = store_at(tmp_path, clock=lambda: 100)
    store.bootstrap({}, {}, AUTH)
    try:
        if operation != 'source':
            store.record_domain(obs(['192.0.2.1']), AUTH, BINDINGS)
        claim = store.claim_next(BINDINGS[0], 100) if operation == 'ack' else None
        with monkeypatch.context() as mp:
            mp.setattr(store, '_fault', fail_at(point))
            mp.setattr(store, '_read_control', unreadable)
            if operation == 'source':
                candidate = obs(['192.0.2.1'])
                assert not store.record_domain(candidate, AUTH, BINDINGS)['ledger_committed']
                assert not store.record_domain(candidate, AUTH, BINDINGS)['ledger_committed']
            elif operation == 'claim':
                assert store.claim_next(BINDINGS[0], 100) is None
            else:
                assert not store.finish_step(claim, result(), 100)['applied']
        unresolved = store._unresolved.copy()
        assert unresolved['kind'] == operation
        before = ledger_rows(tmp_path, 'control')
        with monkeypatch.context() as mp:
            read = store._read_control
            mp.setattr(store, '_read_control', lambda: {**read(), 'epoch': 'wrong-ledger'})
            assert store.recover_delivery(100)['state'] == 'uncertain'
        assert store._unresolved == unresolved
        assert ledger_rows(tmp_path, 'control') == before
        assert not store.dispatch_available()
        deadline = store._recovery_next
        monkeypatch.setattr(store, '_monotonic', lambda: deadline)
        recovered = store.recover_delivery(100)
        assert recovered['state'] == 'ready'
        assert store._unresolved is None
        committed = point == 'after_commit'
        receipts = ledger_rows(tmp_path, 'receipt')
        if operation == 'ack' and committed:
            assert receipts == []
            assert store.health_snapshot()['acked_total'] == 1
        elif operation == 'source':
            assert len(receipts) == int(committed)
            assert store.health_snapshot()['missed_total'] == int(not committed)
        else:
            assert len(receipts) == 1
            reserved = operation == 'ack' or committed
            assert receipts[0]['attempt'] == receipts[0]['provider_calls'] == int(reserved)
            assert receipts[0]['state'] == ('retry_wait' if reserved else 'pending')
    finally:
        store.close(clean=False)


@pytest.mark.parametrize('operation', ['begin', 'finish'])
@pytest.mark.parametrize('point', ['before_commit', 'after_commit'])
def test_checkpoint_uncertainty_recovery_never_edits_dht_evidence(tmp_path, monkeypatch, operation, point):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    try:
        original = {'highwater': 7}
        token = store.begin_dht('signed.example', original, lambda: False) if operation == 'finish' else None
        with monkeypatch.context() as mp:
            mp.setattr(store, '_fault', fail_at(point))
            mp.setattr(store, '_read_control', unreadable)
            if operation == 'begin':
                assert store.begin_dht('signed.example', original, lambda: False) is None
            else:
                assert not store.finish_dht('signed.example', token, {'highwater': 8}, lambda: False)
        saved = ledger_rows(tmp_path, 'dht_state')
        assert store._unresolved['kind'] == 'checkpoint'
        assert store.recover_delivery(100)['state'] == 'ready'
        assert ledger_rows(tmp_path, 'dht_state') == saved
        assert store._gap
        assert store._unresolved is None
    finally:
        store.close(clean=False)


@pytest.mark.parametrize('channel', ['teams', 'misp'])
def test_stale_maintenance_apply_cannot_overwrite_new_channel_epoch(tmp_path, monkeypatch, channel):
    import json
    import threading
    from monitor.delivery_adapters import DestinationRegistry
    app = app_factory(tmp_path, transport=Transport(Response(status=401)))
    entered, release = threading.Event(), threading.Event()
    thread = None
    apply = DestinationRegistry.apply
    try:
        scan(app, monkeypatch, ['192.0.2.1'])
        app.delivery.worker.run_pass()
        fields = ({'teams_webhook': 'https://teams.invalid/hook'} if channel == 'teams'
                  else {'misp_url': 'https://misp.invalid', 'api_key': 'new', 'push_event_id': '7'})
        with monkeypatch.context() as mp:
            mp.setattr(DestinationRegistry, 'apply', lambda *a, **k: (_ for _ in ()).throw(
                OSError('fixture local adapter unavailable')))
            app.service.commit('settings', {'alerts': fields}, expected_revision=0)
        assert app.delivery._repair_channels == {channel: 1}
        assert app.delivery._pending_bindings is not None
        def paused(registry, selected, *, revision, **kwargs):
            if revision == 1:
                assert not app.cfg.lock._is_owned()
                assert not app.repo._coord._is_owned()
                entered.set()
                assert release.wait(3)
            return apply(registry, selected, revision=revision, **kwargs)
        monkeypatch.setattr(DestinationRegistry, 'apply', paused)
        thread = threading.Thread(target=lambda: app.delivery.worker.run_pass(max_provider_calls=0))
        thread.start()
        assert entered.wait(2)
        newer = dict(fields)
        if channel == 'teams':
            newer['teams_webhook'] = 'https://teams.invalid/new'
        else:
            newer['api_key'] = 'newer'
        app.service.commit('settings', {'alerts': newer}, expected_revision=1)
        selected = app.delivery.selected_alerts.copy()
        release.set()
        thread.join(3)
        assert not thread.is_alive()
        assert app.delivery.registry.revision == 2
        assert app.delivery.selected_alerts == selected
        assert app.delivery._pending_bindings is None
        assert app.delivery._repair_channels == {}
        control = json.loads(rows(app, 'control')[0]['data'])
        assert control['applied_config_' + channel] == 2
        assert control['adapter_revision_' + channel] == 1
    finally:
        release.set()
        if thread is not None:
            thread.join(3)
        app.delivery.stop()


@pytest.mark.parametrize('channel', ['teams', 'misp'])
def test_pending_repair_epoch_retries_without_complete(tmp_path, monkeypatch, channel):
    import json
    alerts = ({'teams_webhook': 'https://teams.invalid/hook'} if channel == 'teams' else
              {'misp_url': 'https://misp.invalid', 'api_key': 'old', 'push_event_id': '7'})
    config = {'domains': [{'name': 'test.example', 'type': 'A'}], 'servers': ['fake'],
              'alerts': alerts, 'config_revision': 0}
    transport = Transport(Response(status=401), Response(status=401))
    app = app_factory(tmp_path, config=config, transport=transport)
    try:
        scan(app, monkeypatch, ['192.0.2.1'])
        app.delivery.worker.run_pass()
        assert rows(app, 'receipt')[0]['error'] == 'provider_auth'
        app.delivery.store._execute('PRAGMA query_only=ON')
        repair = {'teams_webhook': alerts['teams_webhook']} if channel == 'teams' else {'api_key': 'new'}
        app.service.commit('settings', {'alerts': repair}, expected_revision=0)
        app.service.commit('config', {'interval': 78}, expected_revision=1)
        assert app.delivery._repair_channels == {channel: 1}
        app.delivery.store._execute('PRAGMA query_only=OFF')
        monkeypatch.setattr(app.delivery, 'projection', lambda: pytest.fail('idle reprojects sources'))
        app.delivery.worker.run_pass()
        assert len(transport.calls) == 2
        assert rows(app, 'receipt')[0]['attempt'] == 2
        assert app.delivery._repair_channels == {}
        control = json.loads(rows(app, 'control')[0]['data'])
        assert control['applied_config_' + channel] == 1
        app.delivery.worker.run_pass()
        assert len(transport.calls) == 2
        assert app.delivery.store._gap
    finally:
        app.delivery.store._execute('PRAGMA query_only=OFF')
        app.delivery.stop()


@pytest.mark.parametrize('established', [False, True])
def test_initial_open_retry_attaches_actual_registry_without_scan(tmp_path, monkeypatch, established):
    transport = Transport(Response(status=200))
    if established:
        seed = app_factory(tmp_path, transport=transport)
        scan(seed, monkeypatch, ['192.0.2.1'])
        before = {t: rows(seed, t) for t in ('receipt', 'batch', 'cursor', 'baseline', 'grace')}
        key = seed.delivery.store.binding_key()
        seed.delivery.stop()
    connect = sqlite3.connect
    attempts = []
    def fail_open(path, *args, **kwargs):
        if str(path).endswith('delivery.sqlite'):
            attempts.append(path)
            raise sqlite3.OperationalError('fixture open failure')
        return connect(path, *args, **kwargs)
    with monkeypatch.context() as mp:
        mp.setattr(sqlite3, 'connect', fail_open)
        app = app_factory(tmp_path, transport=transport)
    try:
        assert attempts
        assert app.delivery.registry is None
        assert app.delivery.store._db is None
        app.delivery.worker.run_pass(max_provider_calls=0)
        assert app.delivery.registry is not None
        assert app.delivery.store.dispatch_available()
        if established:
            assert app.delivery.store.binding_key() == key
            assert {t: rows(app, t) for t in before} == before
            app.delivery.worker.run_pass()
            assert len(transport.calls) == 1
            assert rows(app, 'receipt') == []
        else:
            assert app.delivery.store.binding_key() is not None
            assert len(rows(app, 'cursor')) == 1
        assert app.delivery.store._gap, 'registry readiness is not detector recovery'
    finally:
        app.delivery.stop()


@pytest.mark.parametrize('point', ['before_commit', 'after_commit'])
def test_stop_racing_recovery_never_waits_for_sql_or_authorizes_callback(tmp_path, monkeypatch, point):
    import threading
    entered, release = threading.Event(), threading.Event()
    app = app_factory(tmp_path, transport=Transport(Response(status=200)))
    store = app.delivery.store
    thread = stopper = None
    stopped = []
    try:
        scan(app, monkeypatch, ['192.0.2.1'])
        claim = store.claim_next(app.delivery.bindings()[0], app.clock())
        with monkeypatch.context() as mp:
            mp.setattr(store, '_fault', fail_at('before_commit'))
            assert not store.finish_step(claim, result(), app.clock())['applied']
        def paused(actual):
            if actual == point:
                entered.set()
                assert release.wait(3)
        monkeypatch.setattr(store, '_fault', paused)
        thread = threading.Thread(target=app.delivery.worker.run_pass)
        thread.start()
        assert entered.wait(2)
        stopper = threading.Thread(target=lambda: stopped.append(app.delivery.stop(join_seconds=0)))
        stopper.start()
        stopper.join(.5)
        assert not stopper.is_alive(), 'stop must fence before waiting for recovery SQL'
        assert not stopped[0]['stopped']
        assert store._db is not None
        release.set()
        thread.join(3)
        assert not thread.is_alive()
        assert not app.delivery._transport.calls
        assert not store.dispatch_available()
        assert store.recover_delivery(app.clock())['state'] == 'stopped'
    finally:
        release.set()
        if thread is not None:
            thread.join(3)
        if stopper is not None:
            stopper.join(3)
        monkeypatch.setattr(store, '_fault', lambda _: None)
        app.delivery.stop()


def test_zero_loss_storage_incident_requires_proof_before_dispatch(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    try:
        store.enter_gap('delivery_storage', {})
        store._execute('PRAGMA query_only=ON')
        assert store.recover_delivery(100)['state'] == 'failed'
        assert not store.dispatch_available()
        store._execute('PRAGMA query_only=OFF')
        store._monotonic = lambda: store._recovery_next
        assert store.recover_delivery(100)['state'] == 'ready'
        assert store._gap
        assert store.health_snapshot()['storage_ok']
        assert store.dispatch_available()
    finally:
        store._execute('PRAGMA query_only=OFF')
        store.close(clean=False)


def test_runtime_pass_yields_when_source_owns_store(tmp_path):
    import threading
    app = app_factory(tmp_path)
    entered, release = threading.Event(), threading.Event()
    reports = []
    def own():
        with app.cfg.lock, app.repo._coord, app.delivery.store._lock:
            entered.set()
            release.wait(3)
    owner = threading.Thread(target=own)
    worker = threading.Thread(target=lambda: reports.append(app.delivery.worker.run_pass(max_provider_calls=0)))
    try:
        owner.start()
        assert entered.wait(2)
        worker.start()
        worker.join(.5)
        assert not worker.is_alive(), 'maintenance must not re-enter a busy lock through runtime/worker'
        assert reports[0]['provider_calls'] == 0
    finally:
        release.set()
        owner.join(3)
        worker.join(3)
        app.delivery.stop()


def test_recovery_busy_store_lock_is_nonblocking(tmp_path):
    import threading
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    entered, release = threading.Event(), threading.Event()
    def own():
        with store._lock:
            entered.set()
            release.wait(3)
    thread = threading.Thread(target=own)
    thread.start()
    try:
        assert entered.wait(2)
        assert store.recover_delivery(100)['state'] == 'recovering'
        assert thread.is_alive()
    finally:
        release.set()
        thread.join(3)
        store.close(clean=True)


def test_recovery_refuses_active_callback_and_full_recovery(tmp_path, monkeypatch):
    import threading
    entered, release = threading.Event(), threading.Event()
    class Paused(Transport):
        def request(self, *args, **kwargs):
            entered.set()
            assert release.wait(3)
            return super().request(*args, **kwargs)
    app = app_factory(tmp_path, transport=Paused(Response(status=200)))
    thread = threading.Thread(target=app.delivery.worker.run_pass)
    try:
        scan(app, monkeypatch, ['192.0.2.1'])
        thread.start()
        assert entered.wait(2)
        store = app.delivery.store
        store.enter_gap('delivery_storage', {})
        before = {t: rows(app, t) for t in ('receipt', 'cursor', 'baseline', 'grace')}
        assert store.recover_delivery(app.clock())['state'] == 'stopped'
        assert not store.recover_gap(app.delivery.authority(), app.delivery.projection(),
            {'active_map': {}, 'completed_at': app.clock(), 'bindings': []})['ready']
        assert {t: rows(app, t) for t in before} == before
        assert app.delivery.worker.run_pass()['provider_calls'] == 0
    finally:
        release.set()
        thread.join(3)
        app.delivery.stop()


def test_failed_startup_bootstrap_backs_off_without_reprojection(tmp_path, monkeypatch):
    from monitor.delivery_store import DeliveryStore
    opening = DeliveryStore._open
    def readonly(store):
        opening(store)
        store._execute('PRAGMA query_only=ON')
    with monkeypatch.context() as mp:
        mp.setattr(DeliveryStore, '_open', readonly)
        app = app_factory(tmp_path)
    try:
        assert not app.delivery.store._ready
        with monkeypatch.context() as mp:
            mp.setattr(app.delivery, 'projection', lambda: pytest.fail('bootstrap retry ignored backoff'))
            app.delivery.worker.run_pass(max_provider_calls=0)
        store = app.delivery.store
        store._execute('PRAGMA query_only=OFF')
        store._monotonic = lambda: store._recovery_next
        app.delivery.worker.run_pass(max_provider_calls=0)
        assert store.dispatch_available()
        assert app.delivery.registry is not None
        assert store._gap
    finally:
        app.delivery.store._execute('PRAGMA query_only=OFF')
        app.delivery.stop()


def test_recovery_failures_use_monotonic_capped_backoff(tmp_path, monkeypatch):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    monotonic = [10.0]
    monkeypatch.setattr(store, '_monotonic', lambda: monotonic[0], raising=False)
    store.enter_gap('delivery_storage', {'teams': 1})
    try:
        store._execute('PRAGMA query_only=ON')
        for delay in (1, 2, 4, 8, 16, 30, 30):
            assert store.recover_delivery(100)['state'] == 'failed'
            statements = []
            store._db.set_trace_callback(statements.append)
            monotonic[0] += delay - .001
            assert store.recover_delivery(10**9)['state'] == 'backoff'
            assert statements == [], 'wall-clock jumps must not bypass retry scheduling'
            monotonic[0] += .001
            store._db.set_trace_callback(None)
        store._execute('PRAGMA query_only=OFF')
        assert store.recover_delivery(100)['state'] == 'ready'
        assert store.health_snapshot()['missed_total'] == 1
    finally:
        store._execute('PRAGMA query_only=OFF')
        store.close(clean=False)


@pytest.mark.parametrize('restart', [False, True])
def test_recovery_pages_cap_leaders_and_idle_does_no_sql(tmp_path, monkeypatch, restart):
    store = store_at(tmp_path, clock=lambda: 100)
    store.bootstrap({}, {}, AUTH)
    try:
        store.record_domain(obs(['192.0.2.' + str(i) for i in range(1, 18)]), AUTH, BINDINGS)
        claims = [store.claim_next(BINDINGS[0], 100) for _ in range(17)]
        old = ledger_rows(tmp_path, 'receipt')
        if restart:
            store.close(clean=False)
            store = store_at(tmp_path, clock=lambda: 100)
            assert store.bootstrap({}, {}, AUTH)['ready']
            assert sum(r['state'] == 'retry_wait' for r in ledger_rows(tmp_path, 'receipt')) <= 8
        else:
            with monkeypatch.context() as mp:
                mp.setattr(store, '_fault', fail_at('before_commit'))
                assert not store.finish_step(claims[0], result(), 100)['applied']
        assert not store.dispatch_available()
        page = store.recover_delivery(100, max_claims=1000)
        assert page['recovered_claims'] == 8
        assert page['has_more']
        assert not store.dispatch_available()
        while page['has_more']:
            page = store.recover_delivery(100)
            assert page['recovered_claims'] <= 8
        assert page['state'] == 'ready'
        assert store.dispatch_available()
        for prior, new in zip(old, ledger_rows(tmp_path, 'receipt')):
            assert new['attempt'] == prior['attempt'] == 1
            assert new['provider_calls'] == prior['provider_calls'] == 1
            assert new['payload'] == prior['payload']
            assert new['binding'] == prior['binding']
            assert new['due'] == 130
        statements = []
        store._db.set_trace_callback(statements.append)
        for _ in range(5):
            assert store.recover_delivery(100)['state'] == 'ready'
        assert statements == [], 'healthy maintenance must not scan or write'
    finally:
        store.close(clean=False)


@pytest.mark.parametrize('field', ['schema', 'loss_checkpoint'])
def test_invalid_recovery_proof_stays_fenced(tmp_path, monkeypatch, field):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    try:
        store.enter_gap('delivery_storage', {'teams': 1})
        with monkeypatch.context() as mp:
            mp.setattr(store, '_fault', fail_at('after_commit'))
            mp.setattr(store, '_read_control', unreadable)
            store.recover_delivery(100)
        pending = store._unresolved.copy()
        before = ledger_rows(tmp_path, 'control')
        store._monotonic = lambda: store._recovery_next
        read = store._read_control
        with monkeypatch.context() as mp:
            mp.setattr(store, '_read_control', lambda: {**read(), field: True if field == 'schema' else {}})
            assert store.recover_delivery(100)['state'] == 'uncertain'
        assert store._unresolved == pending
        assert ledger_rows(tmp_path, 'control') == before
        assert store._volatile['teams'] == 1
        assert not store.dispatch_available()
    finally:
        store.close(clean=False)


def test_loss_checkpoint_saturates_without_erasing_later_losses(tmp_path, monkeypatch):
    from monitor.delivery_types import MAX_COUNTER
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    try:
        store.enter_gap('delivery_storage', {'teams': MAX_COUNTER})
        assert store.recover_delivery(100)['state'] == 'ready'
        store.enter_gap('delivery_storage', {'teams': 2})
        with monkeypatch.context() as mp:
            mp.setattr(store, '_fault', fail_at('after_commit'))
            mp.setattr(store, '_read_control', unreadable)
            assert store.recover_delivery(100)['state'] != 'ready'
        store.enter_gap('delivery_storage', {'teams': 3})
        store._monotonic = lambda: store._recovery_next
        store._execute('PRAGMA query_only=ON')
        assert store.recover_delivery(100)['state'] == 'failed'
        assert store._checkpoint['teams'] == MAX_COUNTER
        assert store._volatile['teams'] == 3
        assert not store.health_snapshot()['accounting_complete']
    finally:
        store._execute('PRAGMA query_only=OFF')
        store.close(clean=False)


@pytest.mark.parametrize('point', ['before_commit', 'after_commit'])
def test_unknown_recovery_adopts_only_captured_losses(tmp_path, monkeypatch, point):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    try:
        store.enter_gap('delivery_storage', {'teams': 3})
        with monkeypatch.context() as mp:
            mp.setattr(store, '_fault', fail_at(point))
            mp.setattr(store, '_read_control', unreadable)
            assert store.recover_delivery(100)['state'] != 'ready'
        assert store._unresolved is not None
        store.enter_gap('delivery_storage', {'teams': 5, 'misp': 2})
        deadline = store._recovery_next
        monkeypatch.setattr(store, '_monotonic', lambda: deadline)
        store._execute('PRAGMA query_only=ON')
        assert store.recover_delivery(100)['state'] != 'ready'
        committed = point == 'after_commit'
        assert store._checkpoint['teams'] == (3 if committed else 0)
        assert store._volatile == {'teams': 5 if committed else 8, 'misp': 2}
        assert store.health_snapshot()['missed_unpersisted'] == (7 if committed else 10)
        store._execute('PRAGMA query_only=OFF')
        deadline = store._recovery_next
        assert store.recover_delivery(100)['state'] == 'ready'
        assert store.health_snapshot()['missed_total'] == 10
        assert store.health_snapshot()['missed_unpersisted'] == 0
        assert store._gap
        before = ledger_rows(tmp_path, 'control')
        assert store.recover_delivery(100)['state'] == 'ready'
        assert ledger_rows(tmp_path, 'control') == before
    finally:
        store._execute('PRAGMA query_only=OFF')
        store.close(clean=False)
