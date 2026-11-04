"""Failure metadata never replaces authority, transactions or delivery ownership."""
import json
import sqlite3

import pytest

from monitor.delivery_types import DEFAULT_LIMITS, size
from test_delivery_review_components import (
    AUTH, MISP, TEAMS, Response, Transport, bindings, close, make_components,
    observation, projection, rows, worker,
)
from test_failed_addition_boundaries import IP, NEW, disappear, failed, return_ips, no_network as no_network

pytestmark = pytest.mark.usefixtures('no_network')


def result(state):
    return {'state': state, 'reason': None if state == 'acked' else 'provider_http',
            'progress': {}, 'retry_after': None, 'provider_calls': 1, 'observation_hook': None}


@pytest.mark.parametrize('limit,expected', [({'failed_addition_items': 1}, 1),
                                           ({'failed_addition_bytes': 1}, 0)])
def test_optional_metadata_overflow_does_not_block_terminal_outcome(tmp_path, limit, expected):
    store, reg, transport, clock = failed(tmp_path, limits=limit)
    try:
        proof = rows(store, 'failed_addition')
        assert len(proof) == expected
        assert sum(r['bytes'] for r in proof) <= store.limits['failed_addition_bytes']
        health = store.health_snapshot()
        assert health['failed_total'] == 2
        assert not health['tracking_complete']
        assert not health['accounting_complete']
        assert health['status'] == 'degraded'
        assert health['capacity']['max_receipts'] == DEFAULT_LIMITS['receipts'] == 4096
        assert len(json.dumps(health).encode()) <= 4096
        disappear(store, reg, clock)
        assert return_ips(store, reg, clock)['admitted_receipts'] == expected
        assert rows(store, 'failed_addition') == []
    finally:
        close(store)


def test_multitarget_teams_batch_carries_every_immutable_source_and_reserved_byte(tmp_path):
    transport = Transport(callback=lambda *a: Response(status=400))
    store, reg, transport, clock = make_components(tmp_path, config=TEAMS, transport=transport)
    try:
        for target in ('example.test', 'other.test'):
            assert store.record_domain(observation([IP, NEW], target=target), AUTH, bindings(reg))['admitted_receipts'] == 2
        admitted = rows(store, 'receipt')
        for row in admitted:
            context = [row[k] for k in ('source_target', 'source_incarnation', 'source_signature')]
            assert context[0] in ('example.test', 'other.test')
            assert context[1] == store.cursor_incarnation(context[0])
            assert context[2] == 'dns-v1'
            assert row['reserved'] == len(row['payload'].encode()) + 4096 + store.limits['batch_bytes'] + size(context)
        assert store.seal_cycle(None)['sealed_batches'] == 1
        assert worker(store, reg, clock).run_pass()['provider_calls'] == 1
        assert len(transport.calls) == 1
        proof = rows(store, 'failed_addition')
        assert {(r['target'], r['ip'], r['receipt_id']) for r in proof} == {
            (r['source_target'], r['ip'], r['id']) for r in admitted}
        for row in proof:
            assert row['bytes'] == size([row[k] for k in (
                'target', 'incarnation', 'signature', 'ip', 'channel', 'binding', 'receipt_id')])
        assert store.health_snapshot()['failed_total'] == 4
        assert rows(store, 'receipt') == rows(store, 'batch') == []
    finally:
        close(store)


@pytest.mark.parametrize('fault,readable', [('before_commit', True), ('after_commit', True), ('after_commit', False)])
@pytest.mark.parametrize('operation', ['finish', 'return'])
def test_marker_and_source_or_terminal_share_exact_transaction_readback(tmp_path, monkeypatch, fault, readable, operation):
    if operation == 'return':
        store, reg, transport, clock = failed(tmp_path, channels=('teams',))
        disappear(store, reg, clock)
        claim = None
    else:
        store, reg, transport, clock = make_components(tmp_path)
        assert store.record_domain(observation([IP]), AUTH, bindings(reg))['admitted_receipts'] == 1
        claim = store.claim_next(reg.descriptors()['misp'], clock[0])
        assert claim
    tables = ('receipt', 'failed_addition', 'cursor', 'reappearance', 'control')
    before = {t: rows(store, t) for t in tables}
    fired = []
    saved_read = store._read_control

    def inject(point):
        if point == fault and not fired:
            fired.append(point)
            raise sqlite3.OperationalError('fixture fault')

    def unavailable():
        raise sqlite3.OperationalError('fixture readback unavailable')

    store._fault = inject
    if not readable:
        monkeypatch.setattr(store, '_read_control', unavailable)
    try:
        outcome = (store.finish_step(claim, result('failed'), clock[0]) if claim else
                   return_ips(store, reg, clock, [IP, NEW]))
        assert fired == [fault]
        after = {t: rows(store, t) for t in tables}  # independent connection, not speculative memory
        committed = fault == 'after_commit'
        assert (outcome.get('applied', outcome.get('ledger_committed'))) == (committed and readable)
        if not committed:
            assert after == before
        elif operation == 'finish':
            assert after['receipt'] == []
            assert len(after['failed_addition']) == 1
        else:
            assert after['failed_addition'] == []
            assert len(after['receipt']) == 3
        if not readable:
            assert store._unresolved is not None
            assert store.claim_next(reg.descriptors()['misp'], clock[0]) is None
            assert not store.record_domain(observation([NEW], now=clock[0]), AUTH, bindings(reg))['ledger_committed']
            assert {t: rows(store, t) for t in tables} == after
            monkeypatch.setattr(store, '_read_control', saved_read)
            store._fault = lambda _: None
            assert store.recover_delivery(clock[0])['ledger_committed']
            assert store._unresolved is None
            assert rows(store, 'failed_addition') == after['failed_addition']
    finally:
        store._fault = lambda _: None
        monkeypatch.setattr(store, '_read_control', saved_read)
        close(store)


@pytest.mark.parametrize('mode', ['gap', 'busy', 'tracking'])
def test_loss_lower_bound_is_per_channel_and_counts_new_ip_once_each(tmp_path, mode):
    store, reg, transport, clock = failed(tmp_path, channels=('teams',))
    writer = None
    try:
        disappear(store, reg, clock)
        proof = rows(store, 'failed_addition')
        if mode == 'gap':
            store.enter_gap('delivery_storage', {})
        elif mode == 'tracking':
            store.limits['target_ips'] = 1
        else:
            writer = sqlite3.connect(store.path)
            writer.execute('BEGIN IMMEDIATE')
        outcome = return_ips(store, reg, clock, [IP, NEW])
        if mode == 'tracking':
            assert outcome['outcome'] == 'missed'
            assert outcome['missed_receipts'] == 3
            control = json.loads(rows(store, 'control')[0]['data'])
            assert control['missed_by_reason']['tracking_overflow'] == {'teams': 2, 'misp': 1}
            assert rows(store, 'failed_addition') == []
        else:
            assert outcome['outcome'] == 'gap'
            assert store._volatile == {'teams': 2, 'misp': 1}
            assert rows(store, 'failed_addition') == proof
        assert rows(store, 'receipt') == []
    finally:
        if writer:
            writer.rollback()
            writer.close()
        close(store)


@pytest.mark.parametrize('state', ['unsealed', 'pending', 'in_flight', 'retry_wait', 'blocked_config'])
def test_nonterminal_exact_obligation_fences_even_explicit_stale_proof(tmp_path, state):
    config = TEAMS if state == 'unsealed' else MISP
    store, reg, transport, clock = make_components(tmp_path, config=config)
    try:
        assert store.record_domain(observation([IP]), AUTH, bindings(reg))['admitted_receipts'] == 1
        channel = 'teams' if state == 'unsealed' else 'misp'
        if state not in ('unsealed', 'pending'):
            claim = store.claim_next(reg.descriptors()[channel], clock[0])
            if state != 'in_flight':
                assert store.finish_step(claim, result('retry' if state == 'retry_wait' else 'blocked'), clock[0])['applied']
        original = rows(store, 'receipt')
        assert original[0]['state'] == state
        # Synthetic retained old proof: even this cannot bypass an existing owner.
        row = original[0]
        identity = [row['source_target'], row['source_incarnation'], row['source_signature'],
                    IP, channel, row['binding']]
        with sqlite3.connect(store.path) as db:
            db.execute('INSERT INTO failed_addition VALUES(?,?,?,?,?,?,?,?)', (*identity, row['id'], size([*identity, row['id']])))
        disappear(store, reg, clock)
        assert return_ips(store, reg, clock)['admitted_receipts'] == 0
        assert rows(store, 'receipt') == original
        assert rows(store, 'failed_addition') == []
        assert transport.calls == []
        assert store.health_snapshot()['missed_total'] == 0
    finally:
        close(store)


@pytest.mark.parametrize('when', ['absent', 'returned'])
def test_failure_completed_after_disappearance_or_consumed_pending_return(tmp_path, when):
    store, reg, transport, clock = make_components(tmp_path, transport=Transport(callback=lambda *a: Response(status=400)))
    try:
        store.record_domain(observation([IP]), AUTH, bindings(reg))
        disappear(store, reg, clock)
        if when == 'returned':
            assert return_ips(store, reg, clock)['admitted_receipts'] == 0
        worker(store, reg, clock).run_pass()
        assert len(rows(store, 'failed_addition')) == 1
        if when == 'returned':
            assert return_ips(store, reg, clock)['admitted_receipts'] == 0  # unchanged, not a retry loop
            disappear(store, reg, clock)
        assert return_ips(store, reg, clock)['admitted_receipts'] == 1
    finally:
        close(store)


@pytest.mark.parametrize('boundary', ['binding', 'target'])
def test_foreign_identity_cannot_borrow_failure_proof(tmp_path, boundary):
    store, reg, transport, clock = failed(tmp_path)
    try:
        disappear(store, reg, clock)
        if boundary == 'binding':
            reg.apply({**MISP, 'push_event_id': '2', 'teams_webhook': 'https://teams.invalid/changed'}, revision=2)
            assert return_ips(store, reg, clock)['admitted_receipts'] == 0
        else:
            # A second target's observation-only hold has no failed delivery.
            store.record_domain(observation([IP], target='other.test', now=clock[0]), AUTH, [])
            store.record_domain(observation([], target='other.test', now=clock[0] + 120), AUTH, bindings(reg))
            assert store.record_domain(observation([IP], target='other.test', now=clock[0] + 240),
                                       AUTH, bindings(reg))['admitted_receipts'] == 0
            assert return_ips(store, reg, clock)['admitted_receipts'] == 2
        assert rows(store, 'failed_addition') == []
    finally:
        close(store)


@pytest.mark.parametrize('state', ['failed', 'acked'])
def test_older_terminal_completion_cannot_replace_or_erase_newer_proof(tmp_path, state):
    store, reg, transport, clock = make_components(tmp_path)
    try:
        store.record_domain(observation([IP]), AUTH, bindings(reg))
        claim = store.claim_next(reg.descriptors()['misp'], clock[0])
        row = rows(store, 'receipt')[0]
        identity = [row['source_target'], row['source_incarnation'], row['source_signature'],
                    IP, row['channel'], row['binding']]
        with sqlite3.connect(store.path) as db:
            db.execute('INSERT INTO failed_addition VALUES(?,?,?,?,?,?,?,?)', (*identity, row['id'] + 100, size([*identity, row['id'] + 100])))
        proof = rows(store, 'failed_addition')
        assert store.finish_step(claim, result(state), clock[0])['applied']
        assert rows(store, 'failed_addition') == proof
        assert not store.finish_step(claim, result('failed'), clock[0])['applied']
        assert rows(store, 'failed_addition') == proof
    finally:
        close(store)


def test_late_real_worker_failure_after_delete_readd_cannot_recreate_proof(tmp_path):
    store, reg, transport, clock = make_components(tmp_path)
    try:
        store.record_domain(observation([IP]), AUTH, bindings(reg))
        original = rows(store, 'receipt')[0]

        def retire_during_http(*args):
            assert store.retire_target_cursor(original['source_incarnation'])['ledger_committed']
            assert store.refresh_configuration(AUTH, projection([IP]))['ledger_committed']
            return Response(status=400)

        transport.callback = retire_during_http
        assert worker(store, reg, clock).run_pass()['provider_calls'] == 1
        assert rows(store, 'receipt') == []
        assert rows(store, 'failed_addition') == []
        assert store.cursor_incarnation('example.test') != original['source_incarnation']
        assert store.health_snapshot()['failed_total'] == 1
    finally:
        close(store)


@pytest.mark.parametrize('expired', [False, True])
def test_expiry_is_not_a_retry_and_still_present_failure_has_no_ttl(tmp_path, expired):
    store, reg, transport, clock = failed(tmp_path)
    try:
        proof = rows(store, 'failed_addition')
        clock[0] += 10 * 86400
        assert store.record_domain(observation([IP], now=clock[0]), AUTH, bindings(reg))['admitted_receipts'] == 0
        assert rows(store, 'failed_addition') == proof
        disappear(store, reg, clock)
        expiry = rows(store, 'reappearance')[0]['expires']
        clock[0] = expiry - (0 if expired else 1)
        # No maintenance action enqueues anything, including exact expiry.
        assert store.record_domain(observation([], now=clock[0]), AUTH, bindings(reg))['admitted_receipts'] == 0
        assert rows(store, 'receipt') == []
        assert rows(store, 'failed_addition') == proof  # conservative bounded retention until transition
        assert store.record_domain(observation([IP], now=clock[0]), AUTH, bindings(reg))['admitted_receipts'] == 2
        assert rows(store, 'failed_addition') == []
    finally:
        close(store)


def test_schema_one_legacy_receipts_and_summaries_never_infer_failures(tmp_path):
    store, reg, transport, clock = make_components(tmp_path, transport=Transport(callback=lambda *a: Response(status=400)))
    store.record_domain(observation([IP]), AUTH, bindings(reg))
    epoch = json.loads(rows(store, 'control')[0]['data'])['epoch']
    sentinel = (tmp_path / 'delivery.initialized').read_bytes()
    assert store.close(clean=True)
    with sqlite3.connect(tmp_path / 'delivery.sqlite') as db:
        db.execute('DROP TABLE failed_addition')
        for column in ('source_target', 'source_incarnation', 'source_signature'):
            db.execute('ALTER TABLE receipt DROP COLUMN ' + column)
        db.execute("INSERT INTO terminal(channel,state,reason,at,bytes) VALUES('misp','failed','provider_http',100,20)")
    store = type(store)(tmp_path, clock=lambda: clock[0])
    try:
        assert store.bootstrap(projection([IP]), {}, AUTH)['ready']
        legacy = rows(store, 'receipt')[0]
        assert all(legacy[k] is None for k in ('source_target', 'source_incarnation', 'source_signature'))
        assert rows(store, 'failed_addition') == []
        assert worker(store, reg, clock).run_pass()['provider_calls'] == 1
        assert rows(store, 'failed_addition') == rows(store, 'receipt') == []
        assert len(rows(store, 'terminal')) == 2
        assert json.loads(rows(store, 'control')[0]['data'])['schema'] == 1
        assert json.loads(rows(store, 'control')[0]['data'])['epoch'] == epoch
        assert (tmp_path / 'delivery.initialized').read_bytes() == sentinel
        disappear(store, reg, clock)
        assert return_ips(store, reg, clock)['admitted_receipts'] == 0
    finally:
        close(store)
