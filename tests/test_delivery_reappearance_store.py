"""Transactional, bounded reappearance state independent of removal evidence."""
import json
import sqlite3

import pytest

from monitor.delivery_store import DeliveryStore
from test_delivery_store_atomic import AUTH, BINDINGS, obs, rows, store_at
from test_delivery_store_tracking import projection


IP = '192.0.2.9'
OTHER = '192.0.2.10'


def test_return_frees_capacity_before_next_disappearance(tmp_path):
    store = store_at(tmp_path, limits={'reappearance_items': 1})
    try:
        store.bootstrap(projection([IP, OTHER]), {}, AUTH)
        store.record_domain(obs([OTHER], observed_at=100), AUTH, BINDINGS)
        assert rows(tmp_path, 'reappearance')[0]['ip'] == IP
        result = store.record_domain(obs([IP], observed_at=200), AUTH, BINDINGS)
        assert result['admitted_receipts'] == 0
        assert [r['ip'] for r in rows(tmp_path, 'reappearance')] == [OTHER]
        assert store.health_snapshot()['tracking_complete']
        assert store.record_domain(obs([IP, OTHER], observed_at=300), AUTH, BINDINGS)['admitted_receipts'] == 0
    finally:
        store.close(clean=True)


@pytest.mark.parametrize('limit', [{'reappearance_items': 1}, {'reappearance_bytes': 1}])
def test_suppression_overflow_is_bounded_and_visible_without_removals(tmp_path, limit):
    store = store_at(tmp_path, limits=limit)
    try:
        store.bootstrap(projection([IP, OTHER]), {}, AUTH)
        result = store.record_domain(obs([]), AUTH, BINDINGS)
        holds = rows(tmp_path, 'reappearance')
        assert len(holds) <= store.limits['reappearance_items']
        assert sum(row['bytes'] for row in holds) <= store.limits['reappearance_bytes']
        assert result['ledger_committed']
        assert result['missed_receipts'] == 0
        assert not store.health_snapshot()['tracking_complete']
        assert not store.health_snapshot()['accounting_complete']
        assert store.health_snapshot()['status'] == 'degraded'
        assert rows(tmp_path, 'grace') == rows(tmp_path, 'receipt') == []
        assert json.loads(rows(tmp_path, 'cursor')[0]['ips']) == []
    finally:
        store.close(clean=True)


def test_hold_expiry_reclaims_capacity_before_admission(tmp_path):
    store = store_at(tmp_path, limits={'reappearance_items': 1})
    try:
        store.bootstrap(projection([IP, OTHER]), {}, AUTH)
        store.record_domain(obs([OTHER], observed_at=100), AUTH, BINDINGS)
        store.record_domain(obs([], observed_at=86500), AUTH, BINDINGS)
        assert [row['ip'] for row in rows(tmp_path, 'reappearance')] == [OTHER]
        assert store.health_snapshot()['tracking_complete']
    finally:
        store.close(clean=True)


def test_gap_does_not_count_suppressed_return_as_lost_delivery(tmp_path):
    store = store_at(tmp_path)
    try:
        store.bootstrap(projection([IP]), {}, AUTH)
        store.record_domain(obs([], observed_at=100), AUTH, BINDINGS)
        store.enter_gap('delivery_storage', {})
        result = store.record_domain(obs([IP], observed_at=200), AUTH, BINDINGS)
        assert result['outcome'] == 'gap'
        assert store.health_snapshot()['missed_unpersisted'] == 0
        assert rows(tmp_path, 'receipt') == []
    finally:
        store.close(clean=False)


@pytest.mark.parametrize('operation', ['disappear', 'return'])
def test_suppression_and_cursor_rollback_together(tmp_path, operation):
    store = store_at(tmp_path)
    try:
        store.bootstrap(projection([IP]), {}, AUTH)
        if operation == 'return':
            store.record_domain(obs([], observed_at=100), AUTH, BINDINGS)
        before = {table: rows(tmp_path, table) for table in ('cursor', 'reappearance', 'receipt')}
        fired = []

        def fail(point):
            if point == 'before_commit':
                fired.append(point)
                raise sqlite3.OperationalError('injected write failure')

        store._fault = fail
        result = store.record_domain(obs([IP] if operation == 'return' else [], observed_at=200), AUTH, BINDINGS)
        assert fired == ['before_commit']
        assert not result['ledger_committed']
        assert {table: rows(tmp_path, table) for table in before} == before
        assert store.health_snapshot()['missed_unpersisted'] == 0
    finally:
        store._fault = lambda _: None
        store.close(clean=False)


@pytest.mark.parametrize('change', ['signature', 'remove', 'retire'])
def test_retired_configuration_cannot_suppress_fresh_addition(tmp_path, change):
    store = store_at(tmp_path)
    try:
        store.bootstrap(projection([IP]), {}, AUTH)
        store.record_domain(obs([], observed_at=100), AUTH, BINDINGS)
        signature = 'dns-v1'
        if change == 'signature':
            signature = 'dns-v2'
            new_projection = projection([])
            new_projection['example.test']['signature'] = signature
            assert store.refresh_configuration(AUTH, new_projection)['ledger_committed']
        elif change == 'remove':
            assert store.refresh_configuration(AUTH, {})['ledger_committed']
            assert store.refresh_configuration(AUTH, projection([]))['ledger_committed']
        else:
            incarnation = store.cursor_incarnation('example.test')
            assert store.retire_target_cursor(incarnation)['ledger_committed']
        assert rows(tmp_path, 'reappearance') == []
        assert store.record_domain(obs([IP], observed_at=200, projection_signature=signature),
                                   AUTH, BINDINGS)['admitted_receipts'] == 1
    finally:
        store.close(clean=True)


def test_hold_is_scoped_to_target_and_not_all_mentions_of_an_ip(tmp_path):
    store = store_at(tmp_path)
    try:
        store.bootstrap(projection([IP]), {}, AUTH)
        store.record_domain(obs([], observed_at=100), AUTH, BINDINGS)
        assert store.record_domain(obs([IP], target='new.example', observed_at=200),
                                   AUTH, BINDINGS)['admitted_receipts'] == 1
        assert store.record_domain(obs([IP], observed_at=200), AUTH, BINDINGS)['admitted_receipts'] == 0
    finally:
        store.close(clean=True)


def test_stale_source_does_not_create_or_consume_hold(tmp_path):
    store = store_at(tmp_path)
    try:
        store.bootstrap(projection([IP]), {}, AUTH)
        assert store.record_domain(obs([]), {**AUTH, 'valid': False}, BINDINGS)['outcome'] == 'stale'
        assert rows(tmp_path, 'reappearance') == []
        observation = obs([], observed_at=100)
        store.record_domain(observation, AUTH, BINDINGS)
        before = rows(tmp_path, 'reappearance')
        assert store.record_domain(observation, AUTH, BINDINGS)['admitted_receipts'] == 0
        assert rows(tmp_path, 'reappearance') == before
        assert store.record_domain(obs([IP], observed_at=200, expected_operation_id='stale'),
                                   AUTH, BINDINGS)['outcome'] == 'stale'
        assert rows(tmp_path, 'reappearance') == before
    finally:
        store.close(clean=True)


def test_schema_one_upgrade_preserves_existing_delivery_and_grace(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap(projection([IP]), {OTHER: {'labels': ['old'], 'missing_since': 10}}, AUTH)
    store.record_domain(obs([IP, '192.0.2.11']), AUTH, BINDINGS)
    preserved = {table: rows(tmp_path, table) for table in ('cursor', 'baseline', 'grace', 'receipt')}
    store.close(clean=True)
    # Fixture is the previous schema-1 database, lacking only the additive table.
    with sqlite3.connect(tmp_path / 'delivery.sqlite') as db:
        db.execute('DROP TABLE reappearance')
    sentinel = (tmp_path / 'delivery.initialized').read_bytes()
    store = DeliveryStore(tmp_path, clock=lambda: 200)
    try:
        assert store.bootstrap(projection([IP, '192.0.2.11']), {}, AUTH)['ready']
        assert rows(tmp_path, 'reappearance') == []
        assert {table: rows(tmp_path, table) for table in preserved} == preserved
        assert (tmp_path / 'delivery.initialized').read_bytes() == sentinel
        store.record_domain(obs(['192.0.2.11'], observed_at=200), AUTH, BINDINGS)
        assert store.record_domain(obs([IP, '192.0.2.11'], observed_at=300), AUTH, BINDINGS)['admitted_receipts'] == 0
    finally:
        store.close(clean=True)
