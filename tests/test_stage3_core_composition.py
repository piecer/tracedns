import json
import sqlite3
import threading

from monitor.runtime_state import state_lock
from test_stage3_core_runtime import app_factory, rows, scan
from test_delivery_adapters_steps import Response, Transport


def test_small_full_cycle_is_one_frozen_team_batch_outside_every_shared_lock(tmp_path, monkeypatch):
    cfg = {'domains': [{'name': 'one.example', 'type': 'A'}, {'name': 'two.example', 'type': 'A'}],
           'servers': ['fake'], 'alerts': {'teams_webhook': 'https://teams.invalid/hook'}, 'config_revision': 0}
    transport = Transport(Response())
    app = app_factory(tmp_path, config=cfg, transport=transport)
    original = transport.request
    checks = []
    def request(*args, **kwargs):
        def check():
            with app.cfg.lock, app.repo._coord, state_lock():
                with sqlite3.connect(app.delivery.store.path, timeout=.1) as db:
                    db.execute('BEGIN IMMEDIATE')
                    db.rollback()
                checks.append(True)
        thread = threading.Thread(target=check)
        thread.start()
        thread.join(1)
        assert not thread.is_alive(), 'provider called under shared ownership'
        return original(*args, **kwargs)
    monkeypatch.setattr(transport, 'request', request)
    try:
        scan(app, monkeypatch, ['1.2.3.4'])
        assert len(rows(app, 'receipt')) == 2
        assert len(rows(app, 'batch')) == 1
        body = json.loads(rows(app, 'batch')[0]['payload'])['body']
        assert 'one.example' in body['text'] and 'two.example' in body['text']
        app.delivery.worker.run_pass()
        assert checks == [True]
        assert len(transport.calls) == 1
        assert json.loads(transport.calls[0][2]['data']) == body
        assert app.delivery.store.health_snapshot()['acked_total'] == 2
    finally:
        app.delivery.stop()


def test_default_oversized_unit_consumes_all_without_truncating_raw_evidence(tmp_path, monkeypatch):
    app = app_factory(tmp_path)
    ips = [f'10.0.{index // 256}.{index % 256}' for index in range(257)]
    try:
        accepted, _ = scan(app, monkeypatch, ips)
        assert accepted
        assert rows(app, 'receipt') == []
        assert app.delivery.store.health_snapshot()['missed_total'] == 257
        assert app.current['test.example']['fake']['values'] == ips
        assert json.loads((tmp_path / 'test.example.json').read_text())['current']['fake']['values'] == ips
        app.clock.now += 61
        scan(app, monkeypatch, ips)
        assert app.delivery.store.health_snapshot()['missed_total'] == 257
    finally:
        app.delivery.stop()


def test_real_engine_splits_sixty_one_items_without_omission(tmp_path, monkeypatch):
    transport = Transport(Response(), Response())
    app = app_factory(tmp_path, transport=transport)
    ips = [f'10.0.0.{index}' for index in range(1, 62)]
    try:
        scan(app, monkeypatch, ips)
        assert len(rows(app, 'receipt')) == 61
        batches = rows(app, 'batch')
        entries = [entry for row in batches for entry in json.loads(row['payload'])['entries']]
        assert {entry[0] for entry in entries} == set(ips)
        assert sorted(len(json.loads(row['payload'])['entries']) for row in batches) == [1, 60]
        app.delivery.worker.run_pass()
        assert len(transport.calls) == 2
        assert app.delivery.store.health_snapshot()['acked_total'] == 61
        assert app.current['test.example']['fake']['values'] == ips
    finally:
        app.delivery.stop()


def test_seal_failure_retains_old_partial_and_later_observations_keep_advancing(tmp_path, monkeypatch):
    app = app_factory(tmp_path)
    original = app.delivery.store._render
    def fail(*args):
        raise ValueError('fixture renderer unavailable')
    monkeypatch.setattr(app.delivery.store, '_render', fail)
    try:
        scan(app, monkeypatch, ['1.2.3.4'])
        scan(app, monkeypatch, ['2.3.4.5'])
        assert app.current['test.example']['fake']['values'] == ['2.3.4.5']
        assert len(rows(app, 'receipt')) == 2
        assert rows(app, 'batch') == []
        monkeypatch.setattr(app.delivery.store, '_render', original)
        scan(app, monkeypatch, ['2.3.4.5'])
        assert len(rows(app, 'receipt')) == 2
        assert len(rows(app, 'batch')) == 2
    finally:
        app.delivery.stop()
