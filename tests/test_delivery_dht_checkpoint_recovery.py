"""Reconcile durable signed evidence, never late collector memory or tickets."""
import json
import sqlite3
import threading

import pytest

from config_manager import domain_storage_name
from monitor.lookup_runtime import LookupRuntime
from test_dht_monitor import observation, target
from dht_state_helpers import application
from test_lookup_liveness import owned_scan
from test_stage3_core_runtime import rows


@pytest.mark.parametrize('point', ['before_commit', 'after_commit'])
@pytest.mark.parametrize('seed_empty', [False, True])
def test_unknown_finish_restores_exact_committed_checkpoint_before_next_fetch(tmp_path, monkeypatch, point, seed_empty):
    first, key = observation(7)
    domain = target(key)
    name = domain_storage_name(domain)
    app = application(tmp_path / 'ledger', [domain])
    app.lookup = LookupRuntime(app.repo)
    store = app.delivery.store
    if seed_empty:
        monkeypatch.setattr('dht_query.fetch_dht_records', lambda *a, **k: {'records': [], 'coverage': {}})
        assert not owned_scan(app).complete
    hits, calls = [], []
    finish = store.finish_dht
    read = store._read_control
    def unreadable():
        raise sqlite3.OperationalError('owned readback unavailable')
    def fault(actual):
        if actual == point:
            hits.append(actual)
            raise sqlite3.OperationalError('owned finish uncertainty')
    def uncertain(*args, **kwargs):
        store._fault = fault
        store._read_control = unreadable
        try:
            return finish(*args, **kwargs)
        finally:
            store._fault = lambda point: None
    def fetch(*args, **kwargs):
        calls.append(True)
        return first
    monkeypatch.setattr('dht_query.fetch_dht_records', fetch)
    monkeypatch.setattr(store, 'finish_dht', uncertain)
    try:
        assert not owned_scan(app).complete
        assert hits == [point] and len(calls) == 1
        saved = rows(app, 'dht_state')
        assert not app.current[name]
        assert store._unresolved is not None
        for _ in range(2):
            store._monotonic = lambda: store._recovery_next
            app.delivery.worker.run_pass(max_provider_calls=0)
            assert store._unresolved is not None
            assert rows(app, 'dht_state') == saved
        store._read_control = read
        monkeypatch.setattr(store, 'finish_dht', finish)
        store._monotonic = lambda: store._recovery_next
        app.delivery.worker.run_pass(max_provider_calls=0)
        assert store._unresolved is None
        assert rows(app, 'dht_state') == saved
        # Restoration itself is not a fresh observation: the next collector is
        # empty and cannot complete a pending addition cursor or prove absence.
        def next_fetch(*args, **kwargs):
            calls.append(True)
            assert app.history[name]['meta']['dht_state']['highest_seq'] == '7'
            assert app.current[name]['DHT']['decoded_ips'] == ['192.0.2.123']
            return {'records': [], 'coverage': {'globally_complete': False}}
        monkeypatch.setattr('dht_query.fetch_dht_records', next_fetch)
        assert not owned_scan(app).complete
        if point == 'before_commit':
            assert len(calls) == 1
            assert rows(app, 'dht_state') == saved
            assert saved[0]['pending']
        else:
            assert len(calls) == 2, 'resolved durable finish must unblock the real next collector'
            assert rows(app, 'dht_state')[0]['pending'] is None
            state = json.loads(rows(app, 'dht_state')[0]['data'])['state']
            assert state['highest_seq'] == '7'
            assert rows(app, 'receipt') == []
            assert rows(app, 'cursor')[0]['addition_epoch'] != store._read_control()['addition_epoch']
            newer, _ = observation(8, ips=('192.0.2.123', '192.0.2.124'))
            monkeypatch.setattr('dht_query.fetch_dht_records', lambda *a, **k: newer)
            assert owned_scan(app).complete
            assert rows(app, 'receipt') == [], 'first fresh verified result rebases without outage replay'
            assert rows(app, 'cursor')[0]['addition_epoch'] == store._read_control()['addition_epoch']
            latest, _ = observation(9, ips=('192.0.2.123', '192.0.2.124', '192.0.2.125'))
            monkeypatch.setattr('dht_query.fetch_dht_records', lambda *a, **k: latest)
            assert owned_scan(app).complete
            assert [row['ip'] for row in rows(app, 'receipt')] == ['192.0.2.125']
            assert app.history[name]['meta']['dht_observation']['coverage']['globally_complete'] is False
    finally:
        store._fault = lambda point: None
        store._read_control = read
        app.lookup.stop()
        app.delivery.stop()


@pytest.mark.parametrize('newer', ['higher', 'conflict'])
def test_startup_checkpoint_never_rolls_back_newer_signed_history(tmp_path, monkeypatch, newer):
    first, key = observation(7)
    domain = target(key)
    name = domain_storage_name(domain)
    path = tmp_path / 'ledger'
    app = application(path, [domain])
    app.lookup = LookupRuntime(app.repo)
    monkeypatch.setattr('dht_query.fetch_dht_records', lambda *a, **k: first)
    assert owned_scan(app).complete
    older = rows(app, 'dht_state')[0]
    next_record, _ = observation(8 if newer == 'higher' else 7, ips=('192.0.2.124',))
    monkeypatch.setattr('dht_query.fetch_dht_records', lambda *a, **k: next_record)
    result = owned_scan(app)
    assert result.complete == (newer == 'higher')
    expected = app.history[name]['meta']['dht_state']
    app.lookup.stop()
    app.delivery.stop()
    # Owned local volume-rollback fixture: retain valid higher history, restore
    # the independently signed older checkpoint without changing ledger identity.
    with sqlite3.connect(path / 'delivery.sqlite') as db:
        db.execute('UPDATE dht_state SET data=?,bytes=? WHERE target=?',
                   (older['data'], older['bytes'], name))
    app = application(path, [domain], restart=True)
    app.lookup = LookupRuntime(app.repo)
    try:
        assert app.history[name]['meta']['dht_state'] == expected
        calls = []
        monkeypatch.setattr('dht_query.fetch_dht_records', lambda *a, **k: calls.append(True))
        assert not owned_scan(app).complete
        assert calls == []
        assert app.history[name]['meta']['dht_state'] == expected
        assert rows(app, 'dht_state')[0]['data'] == older['data']
    finally:
        app.lookup.stop()
        app.delivery.stop()


@pytest.mark.parametrize('interference', ['retire', 'stop', 'ticket', 'admission-stop'])
def test_checkpoint_restore_revalidates_authority_and_pending_before_publication(tmp_path, monkeypatch, interference):
    from monitor import dht_support
    first, key = observation(7)
    domain = target(key)
    name = domain_storage_name(domain)
    app = application(tmp_path / 'ledger', [domain])
    app.lookup = LookupRuntime(app.repo)
    store, finish = app.delivery.store, app.delivery.store.finish_dht
    fetched = []
    def fetch(*args, **kwargs):
        fetched.append(True)
        return first
    def unpublished(*args, **kwargs):
        assert finish(*args, **kwargs)
        store.enter_gap('delivery_storage', {})
        return False
    monkeypatch.setattr('dht_query.fetch_dht_records', fetch)
    monkeypatch.setattr(store, 'finish_dht', unpublished)
    stopped, ticket = [], []
    try:
        assert not owned_scan(app).complete
        assert fetched == [True] and not app.current[name]
        durable = json.loads(rows(app, 'dht_state')[0]['data'])
        app.delivery.worker.run_pass(max_provider_calls=0)
        restore = dht_support.restore_checkpoint
        def interrupted(*args, **kwargs):
            value = restore(*args, **kwargs)
            assert not app.cfg.lock._is_owned() and not app.repo._coord._is_owned()
            if interference == 'retire':
                app.service.commit('config', {'domains': []}, expected_revision=0)
            elif interference == 'stop':
                stopped.append(app.delivery.stop(join_seconds=0, producers_stopped=False))
            elif interference == 'admission-stop':
                valid = app.repo.valid
                owner = threading.get_ident()
                def stop_after_valid(lease):
                    accepted = valid(lease)
                    if accepted and threading.get_ident() == owner and not stopped:
                        stopped.append(app.delivery.stop(join_seconds=0, producers_stopped=False))
                    return accepted
                monkeypatch.setattr(app.repo, 'valid', stop_after_valid)
            else:
                ticket.append(store.begin_dht(name, durable, lambda: False))
                assert ticket[0]
            return value
        monkeypatch.setattr(dht_support, 'restore_checkpoint', interrupted)
        assert not owned_scan(app).complete
        assert fetched == [True], 'invalid restoration cannot authorize a fresh collector'
        if interference == 'retire':
            assert name not in app.current and rows(app, 'dht_state') == []
        else:
            assert not app.current[name]
            if interference == 'ticket':
                assert rows(app, 'dht_state')[0]['pending'] == ticket[0]
            else:
                assert stopped and not stopped[0]['closed'] and not store._closed
    finally:
        monkeypatch.setattr(store, 'finish_dht', finish)
        app.lookup.stop()
        app.delivery.stop()
