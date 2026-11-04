"""Original admission cancellation is not a storage failure."""
import copy
import sqlite3
import threading

import pytest

from monitor import engine
from test_lookup_liveness import background_scan, success
from test_s2_accept_runtime_boundaries import Clock, app_at, cleanup
from test_stage3_core_runtime import rows


@pytest.mark.parametrize('boundary', ['ownership', 'begin', 'precommit'])
def test_cancelled_admission_rolls_back_all_detector_state(tmp_path, monkeypatch, boundary):
    clock = Clock()
    app = app_at(tmp_path, clock=clock)
    store = app.delivery.store
    entered, release = threading.Event(), threading.Event()
    before = {t: rows(app, t) for t in ('receipt', 'cursor', 'recent', 'reappearance')}
    control = copy.deepcopy(store._control)
    original_execute, original_fault = store._execute, store._fault
    fired = []

    def delay():
        if not fired:
            fired.append(True)
            entered.set()
            assert release.wait(12)

    def execute(sql, *args):
        if boundary == 'begin' and sql == 'BEGIN IMMEDIATE':
            delay()
        return original_execute(sql, *args)

    def fault(stage):
        if boundary == 'precommit' and stage == 'before_commit':
            delay()
        return original_fault(stage)

    monkeypatch.setattr(store, '_execute', execute)
    monkeypatch.setattr(store, '_fault', fault)
    monkeypatch.setattr(engine, 'collect_snapshot', success)
    if boundary == 'ownership':
        record = store.record_domain

        def record_wait(*args, **kwargs):
            entered.set()
            return record(*args, **kwargs)

        monkeypatch.setattr(store, 'record_domain', record_wait)
        store._lock.acquire()
    thread, results, errors = background_scan(app)
    try:
        if boundary == 'ownership':
            # Observe actual admission entry before releasing store ownership.
            assert entered.wait(2)
        else:
            assert entered.wait(2)
        clock.now = 105
        if boundary == 'ownership':
            store._lock.release()
        release.set()
        thread.join(3)
        assert not errors and not thread.is_alive()
        assert not results[0].complete
        assert {t: rows(app, t) for t in before} == before
        assert store._control == control
        assert not store._gap and store._unresolved is None
    finally:
        cleanup(app, thread, release)


@pytest.mark.parametrize('operation', ['begin_dht', 'finish_dht'])
def test_dht_storage_failure_is_not_reclassified_as_cancellation(tmp_path, monkeypatch, operation):
    app = app_at(tmp_path)
    store = app.delivery.store
    expired = []
    token = store.begin_dht('fixture', {}, lambda: False)
    original = store._execute
    def execute(sql, *args):
        if sql == 'BEGIN IMMEDIATE' and not expired:
            expired.append(True)
            raise sqlite3.OperationalError('storage failed at expiry')
        return original(sql, *args)
    monkeypatch.setattr(store, '_execute', execute)
    try:
        if operation == 'begin_dht':
            assert store.begin_dht('other', {}, lambda: bool(expired)) is None
        else:
            assert not store.finish_dht('fixture', token, {}, lambda: bool(expired))
        assert expired and store._gap
    finally:
        cleanup(app)


@pytest.mark.parametrize('fault', ['begin', 'uncertain', 'commit_then_raise'])
def test_storage_fault_is_not_hidden_by_expiry(tmp_path, monkeypatch, fault):
    clock = Clock()
    app = app_at(tmp_path, clock=clock)
    store = app.delivery.store
    monkeypatch.setattr(engine, 'collect_snapshot', success)
    execute, read_control, db = store._execute, store._read_control, store._db
    fired = []

    def fail_begin(sql, *args):
        if sql == 'BEGIN IMMEDIATE' and not fired:
            fired.append(True)
            clock.now = 105
            raise sqlite3.OperationalError('injected storage refusal')
        return execute(sql, *args)

    class CommitBoundary:
        def __getattr__(self, name):
            return getattr(db, name)

        def commit(self):
            db.commit()
            fired.append(True)
            clock.now = 105
            raise sqlite3.OperationalError('commit result unavailable')

    def unreadable():
        if fired:
            raise sqlite3.OperationalError('readback unavailable')
        return read_control()

    if fault == 'begin':
        monkeypatch.setattr(store, '_execute', fail_begin)
    else:
        monkeypatch.setattr(store, '_db', CommitBoundary())
        if fault == 'uncertain':
            monkeypatch.setattr(store, '_read_control', unreadable)
    thread, results, errors = background_scan(app)
    try:
        thread.join(3)
        assert not errors and not thread.is_alive() and fired
        if fault == 'commit_then_raise':
            assert rows(app, 'receipt') and store._unresolved is None
        else:
            assert store._gap
            if fault == 'uncertain':
                assert store._unresolved is not None and store._claims_halted
            else:
                assert not rows(app, 'receipt')
    finally:
        monkeypatch.setattr(store, '_db', db)
        monkeypatch.setattr(store, '_read_control', read_control)
        cleanup(app, thread)
