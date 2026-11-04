"""Resource/terminal paths for the bounded failed-Added exception."""
import json
import sqlite3

import pytest

from monitor.delivery_types import size
from test_delivery_review_components import (
    AUTH, MISP, TEAMS, bindings, close, make_components, observation, rows, worker,
)
from test_failed_addition_boundaries import IP, NEW, disappear, failed, return_ips, no_network as no_network
from test_failed_addition_integrity import result

pytestmark = pytest.mark.usefixtures('no_network')


@pytest.mark.parametrize('budget,limit,expected', [
    ('receipts', 2, 0), ('receipts', 3, 3), ('unit_items', 1, 0), ('unit_items', 2, 3),
    ('payload_bytes', -1, 0), ('payload_bytes', 0, 3),
])
def test_selected_plan_is_one_atomic_budget_with_unique_entry_units(tmp_path, budget, limit, expected):
    store, reg, transport, clock = failed(tmp_path, channels=('teams',))
    try:
        disappear(store, reg, clock)
        cursor = rows(store, 'cursor')[0]
        context = [cursor['target'], cursor['incarnation'], cursor['signature']]
        required = sum(size({'entries': [[ip, 'example.test', 'A']]}) + 4096 + size(context) +
                       (store.limits['batch_bytes'] if channel == 'teams' else 0)
                       for ip, channel in ((IP, 'teams'), (NEW, 'teams'), (NEW, 'misp')))
        store.limits[budget] = required + limit if budget == 'payload_bytes' else limit
        candidate = observation([IP, NEW], now=clock[0] + 120)
        outcome = store.record_domain(candidate, AUTH, bindings(reg))
        assert outcome['admitted_receipts'] == expected
        assert outcome['missed_receipts'] == (0 if expected else 3)
        assert len(rows(store, 'receipt')) == expected
        assert rows(store, 'failed_addition') == []
        if expected:
            assert sum(r['reserved'] for r in rows(store, 'receipt')) == required
            assert {(r['ip'], r['channel']) for r in rows(store, 'receipt')} == {
                (IP, 'teams'), (NEW, 'teams'), (NEW, 'misp')}
        else:
            assert json.loads(rows(store, 'control')[0]['data'])['missed_by_reason']['delivery_capacity'] == {
                'teams': 2, 'misp': 1}
        # An identical consumed operation must never create a prefix or recount loss.
        assert store.record_domain(candidate, AUTH, bindings(reg))['admitted_receipts'] == 0
        assert store.health_snapshot()['missed_total'] == (0 if expected else 3)
    finally:
        close(store)


@pytest.mark.parametrize('terminal', ['payload', 'attempts', 'provider_calls'])
def test_common_terminal_path_records_explicit_local_failure(tmp_path, terminal):
    store, reg, transport, clock = make_components(tmp_path, config=TEAMS if terminal == 'payload' else MISP)
    try:
        assert store.record_domain(observation([IP]), AUTH, bindings(reg))['admitted_receipts'] == 1
        if terminal == 'payload':
            store.limits['batch_bytes'] = 1
            assert store.seal_cycle(None)['ledger_committed']
            reason = 'payload_limit'
        else:
            field, value = ('attempt', 8) if terminal == 'attempts' else ('provider_calls', 4096)
            with sqlite3.connect(store.path) as db:
                db.execute('UPDATE receipt SET ' + field + '=?', (value,))
            worker(store, reg, clock).run_pass()
            reason = 'attempts_exhausted' if terminal == 'attempts' else 'provider_work_limit'
        assert rows(store, 'receipt') == []
        assert len(rows(store, 'failed_addition')) == 1
        assert rows(store, 'terminal')[0]['reason'] == reason
        assert transport.calls == []
        assert store.health_snapshot()['failed_total'] == 1
    finally:
        close(store)


def test_ack_rollback_keeps_existing_failure_proof_and_exact_claim(tmp_path):
    store, reg, transport, clock = make_components(tmp_path)
    try:
        store.record_domain(observation([IP]), AUTH, bindings(reg))
        claim = store.claim_next(reg.descriptors()['misp'], clock[0])
        row = rows(store, 'receipt')[0]
        identity = [row['source_target'], row['source_incarnation'], row['source_signature'],
                    IP, row['channel'], row['binding']]
        with sqlite3.connect(store.path) as db:
            db.execute('INSERT INTO failed_addition VALUES(?,?,?,?,?,?,?,?)', (*identity, row['id'], size([*identity, row['id']])))
        before = {t: rows(store, t) for t in ('receipt', 'failed_addition', 'terminal', 'control')}
        fired = []

        def fail(point):
            if point == 'before_commit':
                fired.append(point)
                raise sqlite3.OperationalError('fixture ACK fault')

        store._fault = fail
        assert not store.finish_step(claim, result('acked'), clock[0])['applied']
        assert fired == ['before_commit']
        assert {t: rows(store, t) for t in before} == before
        store._fault = lambda _: None
        assert store.finish_step(claim, result('acked'), clock[0])['applied']
        assert rows(store, 'failed_addition') == rows(store, 'receipt') == []
    finally:
        store._fault = lambda _: None
        close(store)


def test_metadata_capacity_reclaimed_by_return_before_later_failure(tmp_path):
    store, reg, transport, clock = failed(tmp_path, limits={'failed_addition_items': 1}, channels=('teams',))
    try:
        disappear(store, reg, clock)
        assert return_ips(store, reg, clock, [IP, NEW])['admitted_receipts'] == 3
        assert rows(store, 'failed_addition') == []
        # ACK the new return, then fail a later fresh item; consumed proof owns no slot.
        assert store.seal_cycle(None)['ledger_committed']
        worker(store, reg, clock).run_pass()
        assert rows(store, 'receipt') == []
        store.record_domain(observation([IP, NEW, '192.0.2.12'], now=clock[0] + 120), AUTH, bindings(reg))
        claim = store.claim_next(reg.descriptors()['misp'], clock[0] + 120)
        assert store.finish_step(claim, result('failed'), clock[0] + 120)['applied']
        assert [r['ip'] for r in rows(store, 'failed_addition')] == ['192.0.2.12']
        assert store.health_snapshot()['tracking_complete']
    finally:
        close(store)


def test_full_metadata_table_has_indexed_lookup_and_bounded_vm_work(tmp_path, record_property):
    store, reg, transport, clock = make_components(tmp_path)
    try:
        # Own synthetic near-cap fixture; identities are exact current source context.
        cursor = rows(store, 'cursor')[0]
        descriptor = reg.descriptors()['misp']
        count = store.limits['failed_addition_items']
        metadata = []
        for i in range(count):
            identity = [cursor['target'], cursor['incarnation'], cursor['signature'],
                        '198.18.' + str(i // 256) + '.' + str(i % 256), 'misp', descriptor['binding_id']]
            metadata.append((*identity, i + 1, size([*identity, i + 1])))
        before_bytes = store.path.stat().st_size
        with sqlite3.connect(store.path) as db:
            db.executemany('INSERT INTO failed_addition VALUES(?,?,?,?,?,?,?,?)', metadata)
            pages = db.execute('PRAGMA page_count').fetchone()[0]
            page_size = db.execute('PRAGMA page_size').fetchone()[0]
            plan = db.execute('EXPLAIN QUERY PLAN SELECT 1 FROM failed_addition WHERE target=? AND incarnation=? '
                              'AND signature=? AND ip=? AND channel=? AND binding=?', metadata[0][:6]).fetchall()
        assert len(rows(store, 'failed_addition')) == count == 4096
        assert any('SEARCH failed_addition USING COVERING INDEX' in p[3] for p in plan)
        assert pages * page_size < store.limits['pages'] * page_size
        assert sum(r[-1] for r in metadata) <= store.limits['failed_addition_bytes']
        ticks = []
        store._db.set_progress_handler(lambda: ticks.append(1) or 0, 1000)
        outcome = store.record_domain(observation([IP]), AUTH, bindings(reg))
        claim = store.claim_next(descriptor, clock[0])
        assert claim
        assert store.finish_step(claim, result('failed'), clock[0])['applied']
        store._db.set_progress_handler(None, 0)
        assert outcome['admitted_receipts'] == 1
        assert len(ticks) * 1000 < 1000000  # bounded complete admit/claim/terminal path, not lookup only
        assert len(rows(store, 'failed_addition')) == count
        assert not store.health_snapshot()['tracking_complete']
        record_property('failed_addition_count', count)
        record_property('logical_bytes', sum(r[-1] for r in metadata))
        record_property('physical_added_bytes', pages * page_size - before_bytes)
        record_property('sql_vm_upper_bound', (len(ticks) + 1) * 1000)
        record_property('lookup_plan', str(plan))
    finally:
        store._db.set_progress_handler(None, 0)
        close(store)
