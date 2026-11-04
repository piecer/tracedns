"""Five-minute Teams flush is independent of source-cycle completion."""
import sqlite3
import threading
from types import SimpleNamespace

import pytest

from monitor.delivery_worker import DeliveryWorker
from test_delivery_store_atomic import AUTH, BINDINGS, obs, rows, store_at
from test_delivery_store_claims import result


TEAMS = {**BINDINGS[0], 'channel': 'teams', 'binding_id': 'b' * 64}


def worker_for_teams(store, clock, sent):
    class Adapter:
        def execute_step(self, claim):
            sent.append(claim)
            return result()

    def admit(now):
        claim = store.claim_next(TEAMS, now)
        return (claim, Adapter()) if claim else None

    return DeliveryWorker(store, claim_admission=admit, clock=lambda: clock[0])


def test_teams_tail_dispatches_at_300_seconds_without_scan_completion(tmp_path):
    clock, sent = [100.0], []
    store = store_at(tmp_path, clock=lambda: clock[0])
    assert store.bootstrap({}, {}, AUTH)['ready']
    worker = worker_for_teams(store, clock, sent)
    try:
        store.record_domain(obs(['192.0.2.1'], observed_at=clock[0]), AUTH, [TEAMS])
        clock[0] = 399.999
        worker.run_pass()
        assert sent == []
        assert rows(tmp_path, 'receipt')[0]['state'] == 'unsealed'
        clock[0] = 400.0
        worker.run_pass()
        assert len(sent) == 1, 'Teams tail must become claimable at age 300 without full scan completion'
        assert sent[0]['payload']['entries'] == [['192.0.2.1', 'example.test', 'A']]
        assert store.health_snapshot()['acked_total'] == 1
        worker.run_pass()
        assert len(sent) == 1
    finally:
        worker.stop()
        store.close(clean=True)


def test_younger_append_does_not_restart_oldest_batch_age(tmp_path):
    clock, sent = [100.0], []
    store = store_at(tmp_path, clock=lambda: clock[0])
    store.bootstrap({}, {}, AUTH)
    worker = worker_for_teams(store, clock, sent)
    try:
        store.record_domain(obs(['192.0.2.1']), AUTH, [TEAMS])
        clock[0] = 399.0
        store.record_domain(obs(['192.0.2.2'], target='second.test', observed_at=399), AUTH, [TEAMS])
        worker.run_pass()
        assert not sent
        clock[0] = 400.0
        worker.run_pass()
        assert len(sent) == 1
        assert {row[0] for row in sent[0]['payload']['entries']} == {'192.0.2.1', '192.0.2.2'}
    finally:
        worker.stop()
        store.close(clean=True)


def test_due_maintenance_bounds_backlog_and_does_not_write_when_idle(tmp_path, monkeypatch):
    store = store_at(tmp_path, clock=lambda: 100)
    store.bootstrap({}, {}, AUTH)
    try:
        for i in range(10):
            store.record_domain(obs([f'192.0.2.{i + 1}'], target=f'{i}.test', cycle=f'cycle-{i}'), AUTH, [TEAMS])
        with monkeypatch.context() as m:
            m.setattr(store, '_transaction', lambda *a, **k: pytest.fail('no-due maintenance wrote SQL'))
            assert store.seal_due_batches(399.999)['sealed_batches'] == 0
        assert store.seal_due_batches(400)['sealed_batches'] == 8
        assert len([r for r in rows(tmp_path, 'receipt') if r['state'] == 'unsealed']) == 2
        assert store.seal_due_batches(400)['sealed_batches'] == 2
        with monkeypatch.context() as m:
            m.setattr(store, '_transaction', lambda *a, **k: pytest.fail('idle maintenance wrote SQL'))
            assert store.seal_due_batches(400)['sealed_batches'] == 0
    finally:
        store.close(clean=True)


@pytest.mark.parametrize('fault', ['render', 'commit'])
def test_due_flush_failure_retains_receipt_and_retries_safely(tmp_path, monkeypatch, fault):
    clock, sent = [100.0], []
    store = store_at(tmp_path, clock=lambda: clock[0])
    store.bootstrap({}, {}, AUTH)
    worker = worker_for_teams(store, clock, sent)
    try:
        store.record_domain(obs(['192.0.2.3']), AUTH, [TEAMS])
        clock[0] = 400
        def broken(*args):
            raise ValueError('controlled render failure')
        def commit_failure(point):
            if point == 'before_commit':
                raise sqlite3.OperationalError('controlled storage failure')
        with monkeypatch.context() as m:
            m.setattr(store, '_render' if fault == 'render' else '_fault', broken if fault == 'render' else commit_failure)
            assert not store.seal_due_batches(clock[0])['ledger_committed']
        assert rows(tmp_path, 'receipt')[0]['state'] == 'unsealed'
        assert rows(tmp_path, 'batch') == []
        worker.run_pass()
        assert len(sent) == 1 and store.health_snapshot()['acked_total'] == 1
        worker.run_pass()
        assert len(sent) == 1
    finally:
        worker.stop()
        store.close(clean=True)


def test_stopped_owner_cannot_age_flush_and_normal_cycle_can_flush_early(tmp_path):
    store = store_at(tmp_path, clock=lambda: 100)
    store.bootstrap({}, {}, AUTH)
    try:
        store.record_domain(obs(['192.0.2.4']), AUTH, [TEAMS])
        assert store.seal_cycle(None)['sealed_batches'] == 1
        store.record_domain(obs(['192.0.2.5'], target='later.test'), AUTH, [TEAMS])
        store.fence_claims()
        assert not store.seal_due_batches(1000)['ledger_committed']
        assert any(r['state'] == 'unsealed' for r in rows(tmp_path, 'receipt'))
    finally:
        store.close(clean=True)


def test_daemon_flushes_real_admission_while_next_source_is_blocked(tmp_path, monkeypatch):
    from monitor import engine
    from models import Snapshot
    from test_stage3_core_runtime import app_factory
    from test_delivery_review_components import Transport

    blocked, release, acked = threading.Event(), threading.Event(), threading.Event()
    transport = Transport()
    app = app_factory(tmp_path, transport=transport, config={
        'domains': [{'name': 'healthy.test', 'type': 'A'}, {'name': 'slow.test', 'type': 'A'}],
        'servers': ['fixture'], 'alerts': {'teams_webhook': 'https://teams.invalid/hook'}, 'config_revision': 0})
    errors = []
    def collect(domain, server):
        if domain.name == 'slow.test':
            blocked.set()
            assert release.wait(5)
            return SimpleNamespace(query=SimpleNamespace(server=server, status='error', error='fixture'), snapshot=None)
        return SimpleNamespace(query=SimpleNamespace(server=server, status='ok'),
                               snapshot=Snapshot(type='A', values=['192.0.2.6'], ts=int(app.clock())))
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    finish = app.delivery.store.finish_step
    def finish_step(*args):
        value = finish(*args)
        if app.delivery.store.health_snapshot()['acked_total'] == 1:
            acked.set()
        return value
    monkeypatch.setattr(app.delivery.store, 'finish_step', finish_step)
    def scan():
        try:
            snap = app.cfg.snapshot()
            engine.run_full_cycle(domains_raw=snap.domains, servers=snap.servers, current_results=app.current,
                history=app.history, history_dir=app.repo.history_dir, query_fail_counts={},
                state_repository=app.repo, target_leases=snap.target_leases)
        except BaseException as error:
            errors.append(error)
    thread = threading.Thread(target=scan)
    thread.start()
    try:
        assert blocked.wait(2)
        assert rows(tmp_path, 'receipt')[0]['state'] == 'unsealed'
        app.clock.now += 300
        assert app.delivery.worker.start()
        assert acked.wait(2), 'independent dispatcher did not flush while source scan was blocked'
        assert thread.is_alive() and not release.is_set()
        assert len(transport.calls) == 1
    finally:
        release.set()
        thread.join(3)
        app.delivery.stop()
    assert not thread.is_alive() and not errors
