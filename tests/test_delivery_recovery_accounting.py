"""Finite independent probes; immutable candidate, real SQLite/worker paths."""
import json
import sqlite3
import threading
from types import SimpleNamespace

import pytest

from monitor import engine
from monitor.delivery_types import MAX_COUNTER
from models import Snapshot
from test_delivery_adapters_steps import Response, Transport
from test_delivery_store_atomic import AUTH, BINDINGS, obs, rows as ledger_rows, store_at
from test_delivery_store_claims import result
from test_stage3_core_runtime import app_factory, rows, scan


def unknown_fault(store, monkeypatch, point, hits):
    def fault(actual):
        if actual == point:
            hits.append(actual)
            raise sqlite3.OperationalError('owned review commit boundary')
    def unreadable():
        raise sqlite3.OperationalError('owned review readback boundary')
    monkeypatch.setattr(store, '_fault', fault)
    monkeypatch.setattr(store, '_read_control', unreadable)


@pytest.mark.parametrize('captured', [3, MAX_COUNTER], ids=['ordinary-control', 'volatile-saturation'])
@pytest.mark.parametrize('point', ['before_commit', 'after_commit'])
def test_new_real_source_loss_survives_unknown_recovery(tmp_path, monkeypatch, captured, point):
    store = store_at(tmp_path, clock=lambda: 100)
    assert store.bootstrap({}, {}, AUTH)['ready']
    hits = []
    try:
        # Boundary fixture seeds the supported saturating counter; the later
        # one-item loss enters through real source admission, not direct edits.
        store.enter_gap('delivery_storage', {'misp': captured})
        with monkeypatch.context() as mp:
            unknown_fault(store, mp, point, hits)
            initial = store.recover_delivery(100)
        assert hits == [point]
        assert not initial['ledger_committed']
        pending = dict(store._unresolved)
        assert pending['kind'] == 'recovery'
        assert pending['captured']['misp'] == captured
        durable = json.loads(ledger_rows(tmp_path, 'control')[0]['data'])
        assert (durable['last_transaction'] == pending['operation']) == (point == 'after_commit')
        admission = store.record_domain(obs(['192.0.2.37']), AUTH, BINDINGS)
        assert admission['outcome'] == 'gap'
        assert store._volatile['misp'] == min(MAX_COUNTER, captured + 1)
        # A persistent failure of the *next* write must not erase the newly
        # accumulated loss when adopting the proven previous COMMIT.
        store._execute('PRAGMA query_only=ON')
        monkeypatch.setattr(store, '_monotonic', lambda: store._recovery_next)
        followup = store.recover_delivery(100)
        assert followup['state'] == 'failed'
        expected = 1 if point == 'after_commit' else min(MAX_COUNTER, captured + 1)
        assert store._unresolved is None
        assert store._volatile['misp'] == expected, (
            'adopting the captured checkpoint erased a newer real source loss',
            {'captured': captured, 'expected_new_loss': expected, 'actual': store._volatile['misp']})
        assert store.health_snapshot()['missed_unpersisted'] == expected
    finally:
        store._execute('PRAGMA query_only=OFF')
        store.close(clean=False)


@pytest.mark.parametrize('uncertain', [False, True], ids=['definite-control', 'unknown-recovery'])
def test_new_source_gap_keeps_incomplete_accounting_after_ack_recovery(tmp_path, monkeypatch, uncertain):
    class AckFault(Transport):
        def request(self, *args, **kwargs):
            response = super().request(*args, **kwargs)
            app.delivery.store._execute('PRAGMA query_only=ON')
            return response
    app = app_factory(tmp_path, transport=AckFault(Response(status=200)))
    store = app.delivery.store
    hits = []
    try:
        scan(app, monkeypatch, ['192.0.2.60'])
        app.delivery.worker.run_pass()
        assert store._claims_halted and not store._gap
        assert store.health_snapshot()['accounting_complete']
        if uncertain:
            store._execute('PRAGMA query_only=OFF')
            with monkeypatch.context() as mp:
                unknown_fault(store, mp, 'after_commit', hits)
                app.delivery.worker.run_pass(max_provider_calls=0)
            assert hits == ['after_commit'] and store._unresolved['kind'] == 'recovery'
        else:
            app.delivery.worker.run_pass(max_provider_calls=0)
            assert store._unresolved is None
        # Genuine next source observation while the delivery ledger remains
        # fenced. No full-result reconciliation is called or fabricated.
        def collect(domain, server):
            return SimpleNamespace(query=SimpleNamespace(server=server, status='ok'),
                snapshot=Snapshot(type='A', values=['192.0.2.60', '192.0.2.61'],
                                  decoded_ips=[], ts=int(app.clock())))
        monkeypatch.setattr(engine, 'collect_snapshot', collect)
        snap = app.cfg.snapshot()
        engine.run_full_cycle(domains_raw=snap.domains, servers=snap.servers,
            current_results=app.current, history=app.history, history_dir=app.repo.history_dir,
            query_fail_counts={}, state_repository=app.repo, target_leases=snap.target_leases)
        assert store._gap and store._volatile['teams'] == 1
        assert not store.health_snapshot()['accounting_complete']
        # Prove the exact earlier COMMIT, but refuse the next write. The newer
        # obligation must survive adoption itself, before any fresh persistence.
        if uncertain:
            pending = dict(store._unresolved)
            durable = json.loads(rows(app, 'control')[0]['data'])
            assert durable['last_transaction'] == pending['operation']
            assert durable['epoch'] == pending['epoch']
            assert durable['accounting_complete']
        store._execute('PRAGMA query_only=ON')
        monkeypatch.setattr(store, '_monotonic', lambda: store._recovery_next)
        app.delivery.worker.run_pass(max_provider_calls=0)
        assert store._unresolved is None
        assert store._volatile['teams'] == 1
        assert not store._control['accounting_complete']
        assert not store.health_snapshot()['accounting_complete']
        store._execute('PRAGMA query_only=OFF')
        monkeypatch.setattr(store, '_monotonic', lambda: store._recovery_next)
        app.delivery.worker.run_pass(max_provider_calls=0)
        assert store._unresolved is None and store.dispatch_available()
        assert store._gap and store.health_snapshot()['coverage'] == 'gap'
        assert store.health_snapshot()['missed_total'] == 1
        assert not store.health_snapshot()['accounting_complete'], 'unknown recovery erased a newer source-gap incompleteness marker'
        assert not json.loads(rows(app, 'control')[0]['data'])['accounting_complete']
    finally:
        store._execute('PRAGMA query_only=OFF')
        app.delivery.stop()


@pytest.mark.parametrize('kind', ['claim', 'ack'])
def test_wrong_epoch_initial_readback_fences_all_writes_then_recovers(tmp_path, monkeypatch, kind):
    store = store_at(tmp_path, clock=lambda: 100)
    assert store.bootstrap({}, {}, AUTH)['ready']
    assert store.record_domain(obs(['192.0.2.40']), AUTH, BINDINGS)['ledger_committed']
    claim = store.claim_next(BINDINGS[0], 100) if kind == 'ack' else None
    read = store._read_control
    hits = []
    def fault(point):
        if point == 'after_commit':
            hits.append(point)
            raise sqlite3.OperationalError('owned review committed write')
    try:
        with monkeypatch.context() as mp:
            mp.setattr(store, '_fault', fault)
            mp.setattr(store, '_read_control', lambda: {**read(), 'epoch': 'different-owned-fixture-epoch'})
            if kind == 'claim':
                assert store.claim_next(BINDINGS[0], 100) is None
            else:
                assert not store.finish_step(claim, result(), 100)['applied']
            assert hits == ['after_commit']
            assert store._unresolved['kind'] == kind
            before = ledger_rows(tmp_path, 'control')
            statements = []
            store._db.set_trace_callback(statements.append)
            assert not store.seal_cycle(None)['ledger_committed']
            assert not store.configuration_applied(['misp'], apply_epochs={'misp': 7})['ledger_committed']
            assert store.claim_next(BINDINGS[0], 100) is None
            assert store.recover_delivery(100)['state'] == 'uncertain'
            assert not statements
            assert ledger_rows(tmp_path, 'control') == before
            store._db.set_trace_callback(None)
        monkeypatch.setattr(store, '_monotonic', lambda: store._recovery_next)
        assert store.recover_delivery(100)['state'] == 'ready'
        remaining = ledger_rows(tmp_path, 'receipt')
        if kind == 'ack':
            assert remaining == []
            assert store.health_snapshot()['acked_total'] == 1
        else:
            assert remaining[0]['state'] == 'retry_wait'
            assert remaining[0]['attempt'] == remaining[0]['provider_calls'] == 1
    finally:
        store.close(clean=False)


@pytest.mark.parametrize('producers_stopped', [True, False])
def test_runtime_shutdown_preserves_and_seals_stage1_tail(tmp_path, monkeypatch, producers_stopped):
    app = app_factory(tmp_path, transport=Transport())
    def collect(domain, server):
        return SimpleNamespace(query=SimpleNamespace(server=server, status='ok'),
            snapshot=Snapshot(type='A', values=['192.0.2.48'], decoded_ips=[], ts=int(app.clock())))
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    snap = app.cfg.snapshot()
    engine.run_full_cycle(domains_raw=snap.domains, servers=snap.servers,
        current_results=app.current, history=app.history, history_dir=app.repo.history_dir,
        query_fail_counts={}, state_repository=app.repo, target_leases=snap.target_leases)
    original = rows(app, 'receipt')
    assert len(original) == 1 and original[0]['state'] == 'unsealed'
    try:
        stopped = app.delivery.stop(join_seconds=0, producers_stopped=producers_stopped)
        if not producers_stopped:
            assert not stopped['closed'] and not stopped['stopped']
            assert rows(app, 'receipt') == original
            assert app.delivery.store._db is not None
            stopped = app.delivery.stop(join_seconds=0, producers_stopped=True)
        assert stopped['closed'] and stopped['stopped']
        saved = rows(app, 'receipt')
        assert saved[0]['state'] == 'pending'
        for field in ('operation', 'binding', 'payload', 'attempt', 'provider_calls', 'reserved'):
            assert saved[0][field] == original[0][field]
        assert len(rows(app, 'batch')) == 1
        assert not app.delivery._transport.calls
    finally:
        app.delivery.stop()


@pytest.mark.parametrize('owner', ['observation_hook', 'sightings'])
def test_active_nonprovider_callbacks_reject_recovery_and_keep_stop_ownership(tmp_path, monkeypatch, owner):
    entered, release = threading.Event(), threading.Event()
    app = app_factory(tmp_path, transport=Transport(Response(status=200)))
    errors = []
    def callback(*args):
        entered.set()
        assert release.wait(5)
        return {'provider_calls': 0, 'has_more': False}
    if owner == 'sightings':
        monkeypatch.setattr(app.delivery.worker, '_sightings_step', callback)
    else:
        # The worker owns the hook after a real durable ACK. Supply a small
        # synthetic local-hook result; no provider or OS side effect is invoked.
        scan(app, monkeypatch, ['192.0.2.51'])
        finish = app.delivery.store.finish_step
        def finished(*args):
            value = finish(*args)
            assert value['applied']
            return {**value, 'observation_hook': {'owned_review': True}}
        monkeypatch.setattr(app.delivery.store, 'finish_step', finished)
        monkeypatch.setattr(app.delivery.worker, '_observation_hook', callback)
    def run():
        try:
            app.delivery.worker.run_pass()
        except BaseException as error:
            errors.append(repr(error))
    thread = threading.Thread(target=run)
    thread.start()
    try:
        assert entered.wait(3)
        store = app.delivery.store
        assert store._worker_active
        before = rows(app, 'control')
        assert store.recover_delivery(app.clock())['state'] == 'stopped'
        assert rows(app, 'control') == before
        assert app.delivery.worker.run_pass()['provider_calls'] == 0
        stop = app.delivery.stop(join_seconds=0)
        assert not stop['stopped'] and not stop['closed']
        assert store._db is not None and store._owner is not None
    finally:
        release.set()
        thread.join(3)
        assert not thread.is_alive()
        app.delivery.stop()
    assert not errors


@pytest.mark.parametrize('cumulative', [0, MAX_COUNTER], ids=['ordinary', 'cumulative-max'])
@pytest.mark.parametrize('outcome', ['on-time', 'definite-rollback', 'unknown-rollback', 'unknown-commit'])
def test_checkpoint_loss_ownership_is_adopted_once(tmp_path, monkeypatch, cumulative, outcome):
    store = store_at(tmp_path, clock=lambda: 100)
    assert store.bootstrap({}, {}, AUTH)['ready']
    hits = []
    try:
        if cumulative:
            store.enter_gap('delivery_storage', {'misp': cumulative})
            assert store.recover_delivery(100)['ledger_committed']
        store.enter_gap('delivery_storage', {'misp': 3})
        with monkeypatch.context() as mp:
            if outcome.startswith('unknown'):
                point = 'after_commit' if outcome == 'unknown-commit' else 'before_commit'
                unknown_fault(store, mp, point, hits)
            elif outcome == 'definite-rollback':
                def fault(point):
                    if point == 'before_commit':
                        hits.append(point)
                        raise sqlite3.OperationalError('owned definite rollback')
                mp.setattr(store, '_fault', fault)
            recovered = store.recover_delivery(100)
        committed = outcome in ('on-time', 'unknown-commit')
        assert recovered['ledger_committed'] == (outcome == 'on-time')
        assert hits == ([] if outcome == 'on-time' else [
            'after_commit' if outcome == 'unknown-commit' else 'before_commit'])
        if outcome.startswith('unknown'):
            pending = dict(store._unresolved)
            durable = json.loads(ledger_rows(tmp_path, 'control')[0]['data'])
            assert durable['epoch'] == pending['epoch']
            assert (durable['last_transaction'] == pending['operation']) == committed
        else:
            assert store._unresolved is None
        assert store.record_domain(obs(['192.0.2.71']), AUTH, BINDINGS)['outcome'] == 'gap'
        expected = 1 if committed else 4
        store._execute('PRAGMA query_only=ON')
        monkeypatch.setattr(store, '_monotonic', lambda: store._recovery_next)
        for _ in range(2):
            assert store.recover_delivery(100)['state'] == 'failed'
            assert store._unresolved is None
            assert store._volatile['misp'] == expected
            assert store._checkpoint['misp'] == min(MAX_COUNTER, cumulative + (3 if committed else 0))
            assert store.health_snapshot()['missed_unpersisted'] == expected
        store._execute('PRAGMA query_only=OFF')
        assert store.recover_delivery(100)['state'] == 'ready'
        assert store._volatile['misp'] == 0
        assert store._checkpoint['misp'] == min(MAX_COUNTER, cumulative + 4)
        assert store.health_snapshot()['missed_unpersisted'] == 0
        assert store.health_snapshot()['missed_total'] == min(MAX_COUNTER, cumulative + 4)
        durable = ledger_rows(tmp_path, 'control')
        assert json.loads(durable[0]['data'])['missed_total'] == min(MAX_COUNTER, cumulative + 4)
        statements = []
        store._db.set_trace_callback(statements.append)
        assert store.recover_delivery(100)['state'] == 'ready'
        assert not statements
        assert ledger_rows(tmp_path, 'control') == durable
    finally:
        store._execute('PRAGMA query_only=OFF')
        store.close(clean=False)


@pytest.mark.parametrize('point', ['before_commit', 'after_commit'])
@pytest.mark.parametrize('new_gap', [False, True], ids=['no-source-gap', 'source-gap'])
def test_readback_preserves_only_existing_completeness_obligations(tmp_path, monkeypatch, point, new_gap):
    store = store_at(tmp_path, clock=lambda: 100)
    assert store.bootstrap({}, {}, AUTH)['ready']
    hits = []
    try:
        # Delivery-only halt is not permission to invent a source gap.
        store._halt_delivery()
        with monkeypatch.context() as mp:
            unknown_fault(store, mp, point, hits)
            assert not store.recover_delivery(100)['ledger_committed']
        assert hits == [point]
        pending = dict(store._unresolved)
        durable = json.loads(ledger_rows(tmp_path, 'control')[0]['data'])
        assert durable['epoch'] == pending['epoch']
        assert (durable['last_transaction'] == pending['operation']) == (point == 'after_commit')
        if new_gap:
            assert store.record_domain(obs(['192.0.2.72']), AUTH, BINDINGS)['outcome'] == 'gap'
        store._execute('PRAGMA query_only=ON')
        monkeypatch.setattr(store, '_monotonic', lambda: store._recovery_next)
        assert store.recover_delivery(100)['state'] == 'failed'
        assert store._unresolved is None
        assert store._control['accounting_complete'] == (not new_gap)
        assert store._control['tracking_complete']
        assert store.health_snapshot()['accounting_complete'] == (not new_gap)
        assert store._gap == new_gap
        store._execute('PRAGMA query_only=OFF')
        assert store.recover_delivery(100)['state'] == 'ready'
        assert store._gap == new_gap
        durable = json.loads(ledger_rows(tmp_path, 'control')[0]['data'])
        assert durable['accounting_complete'] == (not new_gap)
        assert durable['tracking_complete']
        assert durable['missed_total'] == int(new_gap)
    finally:
        store._execute('PRAGMA query_only=OFF')
        store.close(clean=False)
