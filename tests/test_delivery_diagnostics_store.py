"""Troubleshooting evidence must survive degraded storage without leaking data."""
import errno
import json

import pytest
import sqlite3
import threading

from test_delivery_store_atomic import AUTH, BINDINGS, obs, store_at


def test_latest_failure_is_separate_from_old_block_and_success_and_survives_restart(tmp_path):
    from test_delivery_store_claims import result
    store = store_at(tmp_path, clock=lambda: 100)
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(['1.1.1.1', '2.2.2.2', '3.3.3.3'], label='private-label'), AUTH, BINDINGS)
    first = store.claim_next(BINDINGS[0], 100)
    store.finish_step(first, result('blocked', reason='tls_error'), 100)
    second = store.claim_next(BINDINGS[0], 101)
    from monitor.delivery_diagnostics import normalize_diagnostic
    detail = dict(normalize_diagnostic(), operation='misp_read', http_status=200,
                  response_bytes=2097153, response_limit=2097152)
    store.finish_step(second, result('failed', reason='response_limit', diagnostic=detail), 101)
    third = store.claim_next(BINDINGS[0], 102)
    store.finish_step(third, result('acked'), 102)
    snapshot = store.diagnostics_snapshot()
    misp = snapshot['channels']['misp']
    assert misp['latest_result']['state'] == 'acked'
    assert misp['latest_failure']['reason'] == 'response_limit'
    assert misp['latest_failure']['at'] == 101
    assert misp['latest_failure']['diagnostic']['response_bytes'] == 2097153
    assert misp['blocked_by_reason'] == [{'reason': 'tls_error', 'count': 1}]
    assert len(snapshot['recent_failures']) == 1
    assert store.health_snapshot()['channels']['misp']['last_error'] == 'tls_error'
    wire = json.dumps(snapshot)
    assert 'private-label' not in wire
    assert '1.1.1.1' not in wire and BINDINGS[0]['binding_id'] not in wire
    store.close(clean=True)
    reopened = store_at(tmp_path, clock=lambda: 103)
    try:
        reopened.bootstrap({}, {}, AUTH)
        again = reopened.diagnostics_snapshot()
        assert again['channels']['misp']['latest_failure'] == misp['latest_failure']
        assert again['recent_failures'] == snapshot['recent_failures']
    finally:
        reopened.close(clean=True)


def test_failure_history_is_bounded_and_counted_as_terminal_groups(tmp_path):
    from test_delivery_store_claims import result
    store = store_at(tmp_path, clock=lambda: 100)
    store.bootstrap({}, {}, AUTH)
    try:
        store.record_domain(obs([f'1.1.1.{i}' for i in range(1, 13)]), AUTH, BINDINGS)
        for now in range(100, 112):
            claim = store.claim_next(BINDINGS[0], now)
            store.finish_step(claim, result('failed', reason='provider_http'), now)
        snapshot = store.diagnostics_snapshot()
        assert len(snapshot['recent_failures']) == 10
        assert [r['at'] for r in snapshot['recent_failures']] == list(range(111, 101, -1))
        assert all(r['items'] == 1 for r in snapshot['recent_failures'])
        assert store.health_snapshot()['failed_total'] == 12
        snapshot['recent_failures'][0]['reason'] = 'private-mutation'
        assert store.diagnostics_snapshot()['recent_failures'][0]['reason'] == 'provider_http'
    finally:
        store.close(clean=True)


@pytest.mark.parametrize('point,committed', [('before_commit', False), ('after_commit', True)])
def test_failed_commit_does_not_publish_uncommitted_terminal_evidence(tmp_path, point, committed):
    from test_delivery_store_claims import result
    store = store_at(tmp_path, clock=lambda: 100)
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(['1.1.1.1']), AUTH, BINDINGS)
    claim = store.claim_next(BINDINGS[0], 100)
    def fail(stage):
        if stage == point:
            raise OSError(errno.ENOSPC, 'private-path-canary')
    store._fault = fail
    try:
        outcome = store.finish_step(claim, result('failed', reason='response_limit'), 100)
        assert bool(outcome['applied']) is committed
        snapshot = store.diagnostics_snapshot()
        if committed:
            assert snapshot['recent_failures'][0]['reason'] == 'response_limit'
            with sqlite3.connect(tmp_path / 'delivery.sqlite') as reader:
                saved = json.loads(reader.execute('SELECT data FROM control').fetchone()[0])
                assert saved['delivery_diagnostics']['recent_failures'] == snapshot['recent_failures']
        else:
            assert snapshot['recent_failures'] == []
            assert snapshot['channels']['misp']['latest_result'] is None
            assert snapshot['counts_stale'] is True
        assert snapshot['storage_error']['code'] == 'disk_full'
        assert 'private-path-canary' not in json.dumps(snapshot)
    finally:
        store._fault = lambda _: None
        store.close(clean=False)


@pytest.mark.parametrize('error,expected', [
    (PermissionError(errno.EACCES, 'private-path'), 'permission_denied'),
    (sqlite3.OperationalError('database or disk is full'), 'sqlite_full'),
    (sqlite3.OperationalError('attempt to write a readonly database'), 'sqlite_readonly'),
    (sqlite3.DatabaseError('database disk image is malformed'), 'sqlite_corrupt'),
    (sqlite3.OperationalError('disk I/O error'), 'sqlite_io'),
    (sqlite3.OperationalError('private-query-canary'), 'sqlite_error'),
])
def test_transaction_error_classification_never_publishes_exception_text(tmp_path, error, expected):
    store = store_at(tmp_path, clock=lambda: 100)
    store.bootstrap({}, {}, AUTH)
    def fail(point):
        if point == 'before_commit':
            raise error
    store._fault = fail
    try:
        result = store.record_domain(obs(['1.1.1.1']), AUTH, BINDINGS)
        assert not result['ledger_committed']
        snapshot = store.diagnostics_snapshot()
        assert snapshot['storage_error']['code'] == expected
        assert 'private-' not in json.dumps(snapshot)
    finally:
        store._fault = lambda _: None
        store.close(clean=False)


def test_snapshot_does_not_wait_for_writer_lock_or_query_database(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    store = store_at(tmp_path, clock=lambda: 100)
    store.bootstrap({}, {}, AUTH)
    expected = store.diagnostics_snapshot()
    original = store._db
    class NoDatabase:
        def __getattr__(self, name):
            raise AssertionError('diagnostic read queried SQLite')
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            with store._lock:
                store._db = NoDatabase()
                future = pool.submit(store.diagnostics_snapshot)
                assert future.result(timeout=1) == expected
    finally:
        store._db = original
        store.close(clean=True)


def test_teams_terminal_group_reports_items_not_one_delivery(tmp_path):
    from test_delivery_store_claims import result
    store = store_at(tmp_path, clock=lambda: 100)
    teams = [{**BINDINGS[0], 'channel': 'teams'}]
    store.bootstrap({}, {}, AUTH)
    try:
        store.record_domain(obs(['1.1.1.1', '2.2.2.2', '3.3.3.3']), AUTH, teams)
        store.seal_cycle(None)
        claim = store.claim_next(teams[0], 100)
        assert len(claim['payload']['entries']) == 3
        store.finish_step(claim, result('failed', reason='provider_http'), 100)
        snapshot = store.diagnostics_snapshot()
        assert len(snapshot['recent_failures']) == 1
        assert snapshot['recent_failures'][0]['items'] == 3
        assert store.health_snapshot()['failed_total'] == 3
    finally:
        store.close(clean=True)


def test_worker_exception_is_distinct_from_sqlite_failure(tmp_path):
    from monitor.delivery_worker import DeliveryWorker
    store = store_at(tmp_path, clock=lambda: 100)
    store.bootstrap({}, {}, AUTH)
    finished = threading.Event()
    original = store.set_worker_thread_running
    def running(value):
        original(value)
        if not value:
            finished.set()
    store.set_worker_thread_running = running
    def fail(_):
        raise RuntimeError('secret-worker-marker')
    worker = DeliveryWorker(store, claim_admission=fail)
    try:
        assert worker.start()
        assert finished.wait(3)
        snapshot = store.diagnostics_snapshot()
        assert snapshot['storage_error'] == {'at': 100, 'stage': 'worker', 'code': 'worker_exception'}
        assert snapshot['worker_running'] is False
        assert snapshot['coverage'] == 'gap'
        assert 'secret-worker-marker' not in json.dumps(snapshot)
    finally:
        worker.stop()
        store.close(clean=False)


def test_owner_lock_failure_has_cached_safe_diagnostics(tmp_path):
    owner = store_at(tmp_path, clock=lambda: 100)
    other = store_at(tmp_path, clock=lambda: 101)
    try:
        snapshot = other.diagnostics_snapshot()
        assert snapshot['storage_error'] == {'at': 101, 'stage': 'open_owner', 'code': 'owner_lock'}
        assert snapshot['storage_ok'] is False
        assert snapshot['counts_stale'] is True
        assert str(tmp_path) not in json.dumps(snapshot)
        assert snapshot['channels']['misp']['latest_result'] is None
        snapshot['storage_error']['code'] = 'mutated'
        assert other.diagnostics_snapshot()['storage_error']['code'] == 'owner_lock'
    finally:
        other.close(clean=False)
        owner.close(clean=True)


def test_real_sqlite_busy_preserves_stage_without_reading_db_on_snapshot(tmp_path):
    store = store_at(tmp_path, clock=lambda: 100)
    store.bootstrap({}, {}, AUTH)
    external = sqlite3.connect(tmp_path / 'delivery.sqlite', isolation_level=None)
    try:
        external.execute('BEGIN IMMEDIATE')
        result = store.record_domain(obs(['1.1.1.1']), AUTH, BINDINGS)
        assert not result['ledger_committed']
        snapshot = store.diagnostics_snapshot()
        assert snapshot['storage_error']['code'] == 'sqlite_busy'
        assert snapshot['storage_error']['stage'] == 'transaction_begin'
        assert snapshot['coverage'] == 'gap'
        assert snapshot['counts_stale'] is True
        original = store._one
        try:
            store._one = lambda *a, **k: (_ for _ in ()).throw(AssertionError('snapshot read SQLite'))
            assert store.diagnostics_snapshot() == snapshot
        finally:
            store._one = original
    finally:
        external.rollback()
        external.close()
        store.close(clean=False)
