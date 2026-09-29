import json
import sqlite3
import threading

import pytest

from monitor.runtime_state import state_lock
from test_stage3_core_runtime import app_factory, rows, scan
from test_delivery_adapters_steps import Response, Transport


def test_capacity_loss_consumes_without_stopping_observations_or_replay(tmp_path, monkeypatch):
    app = app_factory(tmp_path, limits={'receipts': 1}, transport=Transport(Response()))
    try:
        scan(app, monkeypatch, ['1.2.3.4'])
        scan(app, monkeypatch, ['2.3.4.5'])
        assert app.current['test.example']['fake']['values'] == ['2.3.4.5']
        assert app.delivery.store.health_snapshot()['missed_total'] == 1
        app.delivery.worker.run_pass()
        app.clock.now += 61
        scan(app, monkeypatch, ['2.3.4.5'])
        assert rows(app, 'receipt') == []
        assert app.delivery.store.health_snapshot()['missed_total'] == 1
        assert json.loads((tmp_path / 'test.example.json').read_text())['current']['fake']['values'] == ['2.3.4.5']
    finally:
        app.delivery.stop()


@pytest.mark.parametrize('failure', ['readonly', 'busy', 'ack'])
def test_real_storage_failure_keeps_observations_and_gap_recovery_no_replay(tmp_path, monkeypatch, failure):
    transport = Transport(Response())
    app = app_factory(tmp_path, transport=transport)
    blocker = None
    try:
        scan(app, monkeypatch, ['1.2.3.4'])
        if failure == 'busy':
            blocker = sqlite3.connect(app.delivery.store.path)
            blocker.execute('BEGIN IMMEDIATE')
        elif failure == 'readonly':
            app.delivery.store._db.execute('PRAGMA query_only=ON')
        else:
            original = transport.request
            def request(*a, **k):
                app.delivery.store._db.execute('PRAGMA query_only=ON')
                return original(*a, **k)
            monkeypatch.setattr(transport, 'request', request)
            app.delivery.worker.run_pass()
        for ip in ['2.3.4.5', '3.4.5.6']:
            accepted, _ = scan(app, monkeypatch, [ip])
            assert accepted
            assert app.current['test.example']['fake']['values'] == [ip]
        health = app.delivery.store.health_snapshot()
        assert health['coverage'] == 'gap'
        assert health['missed_unpersisted'] == 2
        if blocker is not None:
            blocker.rollback()
        app.delivery.store._db.execute('PRAGMA query_only=OFF')
        scan(app, monkeypatch, ['3.4.5.6'])
        assert app.delivery.store.health_snapshot()['coverage'] == 'covered'
        assert app.delivery.store.health_snapshot()['missed_total'] == 2
        assert len(rows(app, 'receipt')) == 1
        assert json.loads(rows(app, 'receipt')[0]['payload'])['entries'][0][0] == '1.2.3.4'
    finally:
        if blocker is not None:
            blocker.close()
        app.delivery.store._db.execute('PRAGMA query_only=OFF')
        app.delivery.stop()


def test_target_delete_before_admission_drops_original_candidate(tmp_path, monkeypatch):
    app = app_factory(tmp_path)
    collected, release = threading.Event(), threading.Event()
    original = app.repo.accept_observation
    def accept(*args, **kwargs):
        collected.set()
        assert release.wait(2)
        return original(*args, **kwargs)
    monkeypatch.setattr(app.repo, 'accept_observation', accept)
    done = []
    thread = threading.Thread(target=lambda: done.append(scan(app, monkeypatch, ['1.2.3.4'])))
    try:
        thread.start()
        assert collected.wait(2)
        app.service.commit('config', {'domains': []}, expected_revision=0)
        app.service.commit('config', {'domains': [{'name': 'test.example', 'type': 'A'}]}, expected_revision=1)
        release.set()
        thread.join(2)
        assert not thread.is_alive()
        assert rows(app, 'receipt') == []
        assert app.current.get('test.example', {}) == {}
        assert not done[0][0]
    finally:
        release.set()
        thread.join(2)
        app.delivery.stop()


def test_admission_holds_original_authority_but_not_state_lock(tmp_path, monkeypatch):
    app = app_factory(tmp_path)
    admitted, release, deleted, read = (threading.Event() for _ in range(4))
    original = app.delivery.store.record_domain
    def record(*args):
        result = original(*args)
        admitted.set()
        assert release.wait(2)
        return result
    monkeypatch.setattr(app.delivery.store, 'record_domain', record)
    collector = threading.Thread(target=lambda: scan(app, monkeypatch, ['1.2.3.4']))
    def delete():
        app.service.commit('config', {'domains': []}, expected_revision=0)
        deleted.set()
    writer = threading.Thread(target=delete)
    def read_state():
        with state_lock():
            assert app.current['test.example'] == {}
            read.set()
    reader = threading.Thread(target=read_state)
    try:
        collector.start()
        assert admitted.wait(2)
        assert len(rows(app, 'receipt')) == 1
        reader.start()
        assert read.wait(1), 'SQLite must not hold shared state lock'
        writer.start()
        assert not deleted.wait(.05), 'deletion interleaved admission and publication'
        release.set()
        collector.join(2)
        writer.join(2)
        reader.join(2)
        assert deleted.is_set()
        assert app.current == {}
        assert len(rows(app, 'receipt')) == 1
    finally:
        release.set()
        collector.join(2)
        if writer.ident:
            writer.join(2)
        app.delivery.stop()
