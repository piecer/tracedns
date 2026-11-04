"""Due group age must not replace the actual FIFO batch leader.

Regressions promoted from the three blocking stage1 independent probes.
"""
import json

from monitor.delivery_types import TeamsPayloadTooLarge, encode_body
from test_delivery_batch_deadline import TEAMS
from test_delivery_store_atomic import AUTH, obs, rows, store_at
from test_delivery_store_claims import result


def broken_render(*args):
    raise ValueError('controlled renderer outage')


def fitting_render(entries, action, created):
    return {'title': action, 'text': json.dumps(entries)}


def assert_batch_leaders(tmp_path):
    receipts = rows(tmp_path, 'receipt')
    for batch in rows(tmp_path, 'batch'):
        members = [r for r in receipts if r['batch_id'] == batch['id']]
        assert members, 'committed batch has no members'
        leader = min(members, key=lambda r: r['id'])
        assert leader['id'] == batch['id'], 'batch ID must identify its actual FIFO leader'
        assert leader['state'] == 'pending'
        assert batch['created'] == leader['created']
        expected = [entry for r in sorted(members, key=lambda r: r['id'])
                    for entry in json.loads(r['payload'])['entries']]
        assert json.loads(batch['payload'])['entries'] == expected


def ack_all(store, tmp_path, expected_ips):
    delivered = []
    while True:
        claim = store.claim_next(TEAMS, 400)
        if claim is None:
            break
        assert claim['binding_id'] == TEAMS['binding_id']
        assert len(claim['payload']['entries']) <= 60
        assert len(encode_body(claim['payload']['body'])) <= 24 * 1024
        delivered.extend(entry[0] for entry in claim['payload']['entries'])
        assert store.finish_step(claim, result(), 400)['applied']
    assert sorted(delivered) == sorted(expected_ips)
    assert rows(tmp_path, 'receipt') == []
    assert rows(tmp_path, 'batch') == []
    assert store.health_snapshot()['acked_total'] == len(expected_ips)


def test_clock_rollback_due_member_after_fitting_prefix_must_progress(tmp_path):
    clock = [1000]
    store = store_at(tmp_path, clock=lambda: clock[0], render=broken_render)
    try:
        assert store.bootstrap({}, {}, AUTH)['ready']
        prefix = [f'192.0.2.{i}' for i in range(1, 61)]
        assert store.record_domain(obs(prefix, observed_at=clock[0]), AUTH, [TEAMS])['admitted_receipts'] == 60
        clock[0] = 100
        assert store.record_domain(obs(['192.0.2.61'], target='later', observed_at=clock[0]),
                                   AUTH, [TEAMS])['admitted_receipts'] == 1
        clock[0] = 400
        store._render = fitting_render
        outcome = store.seal_due_batches(clock[0])
        assert outcome['ledger_committed'], 'due member behind a full prefix must not collide with its own batch ID'
        assert outcome['sealed_batches'] == 2
        assert_batch_leaders(tmp_path)
        assert len(rows(tmp_path, 'receipt')) == 61
        assert store.health_snapshot()['failed_total'] == 0
        ack_all(store, tmp_path, prefix + ['192.0.2.61'])
    finally:
        store.close(clean=True)


def test_clock_rollback_oversized_prefix_must_not_fail_valid_due_member(tmp_path):
    clock = [1000]
    store = store_at(tmp_path, clock=lambda: clock[0], render=broken_render)
    try:
        assert store.bootstrap({}, {}, AUTH)['ready']
        store.record_domain(obs(['192.0.2.1'], target='oversized', observed_at=clock[0]), AUTH, [TEAMS])
        clock[0] = 100
        store.record_domain(obs(['192.0.2.2'], target='valid', observed_at=clock[0]), AUTH, [TEAMS])
        clock[0] = 400

        def render(entries, action, created):
            if entries[0][1] == 'oversized':
                raise TeamsPayloadTooLarge('payload_limit')
            return fitting_render(entries, action, created)

        store._render = render
        outcome = store.seal_due_batches(clock[0])
        remaining = rows(tmp_path, 'receipt')
        assert any(r['ip'] == '192.0.2.2' for r in remaining), 'size failure must not delete a different valid receipt'
        assert outcome == {'ledger_committed': True, 'sealed_batches': 1}
        assert [r['ip'] for r in remaining] == ['192.0.2.2']
        assert store.health_snapshot()['failed_total'] == 1
        assert_batch_leaders(tmp_path)
        ack_all(store, tmp_path, ['192.0.2.2'])
    finally:
        store.close(clean=True)


def test_eighth_batch_keeps_its_actual_leader_in_membership(tmp_path):
    clock = [100]
    store = store_at(tmp_path, clock=lambda: clock[0], render=broken_render)
    try:
        assert store.bootstrap({}, {}, AUTH)['ready']
        old_ips = [f'198.51.100.{n + 1}' for n in range(7)]
        for n, ip in enumerate(old_ips):
            assert store.record_domain(obs([ip], target=f'old{n}', cycle=f'old{n}', observed_at=clock[0]),
                                       AUTH, [TEAMS])['admitted_receipts'] == 1
        clock[0] = 1000
        prefix = [f'192.0.2.{i}' for i in range(1, 61)]
        assert store.record_domain(obs(prefix, observed_at=clock[0]), AUTH, [TEAMS])['admitted_receipts'] == 60
        clock[0] = 100
        assert store.record_domain(obs(['192.0.2.61'], target='late', observed_at=clock[0]),
                                   AUTH, [TEAMS])['admitted_receipts'] == 1
        clock[0] = 400
        store._render = fitting_render
        assert store.seal_due_batches(clock[0]) == {'ledger_committed': True, 'sealed_batches': 8}
        batches, receipts = rows(tmp_path, 'batch'), rows(tmp_path, 'receipt')
        leaders = {r['id'] for r in receipts if r['state'] == 'pending' and r['id'] == r['batch_id']}
        assert not [b['id'] for b in batches if b['id'] not in leaders], 'eighth candidate must not commit an orphan batch'
        assert_batch_leaders(tmp_path)
        assert len(receipts) == 68
        assert [r['ip'] for r in receipts if r['state'] == 'unsealed'] == ['192.0.2.61']
        assert store.seal_due_batches(clock[0]) == {'ledger_committed': True, 'sealed_batches': 1}
        assert_batch_leaders(tmp_path)
        assert store.health_snapshot()['failed_total'] == 0
        ack_all(store, tmp_path, old_ips + prefix + ['192.0.2.61'])
    finally:
        store.close(clean=True)
