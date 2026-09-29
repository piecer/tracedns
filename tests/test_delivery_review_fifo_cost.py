"""Freeze full-claim SQL VM budget before repair; no latency SLO assertion.

200*N + 10,000 opcodes accommodates metadata/health scans and indexed claim
maintenance with a conservative constant allowance, but rejects quadratic
membership scanning. The ratio gates allow SQLite plan/version variation.
Actual default-budget admission builds every fixture (no inflated budgets).
"""
import json
import statistics
import sqlite3
import time

from test_delivery_review_components import (
    AUTH, TEAMS, Response, Transport, bindings, close, make_components, observation,
)


def measure_claims(path, count, *, config=None):
    transport = Transport(callback=lambda *args: Response({}, 503))
    store, reg, _, _ = make_components(path, transport=transport, config=config)
    admission_seconds = []
    try:
        for offset in range(0, count, 250):
            ips = ['198.18.' + str(i // 250) + '.' + str(i % 250 + 1)
                   for i in range(offset, min(count, offset + 250))]
            start = time.perf_counter()
            result = store.record_domain(observation(ips, target='target' + str(offset)), AUTH, bindings(reg))
            admission_seconds.append(time.perf_counter() - start)
            assert result['admitted_receipts'] == len(ips)
        if config == TEAMS:
            assert store.seal_cycle(None)['ledger_committed']
        capacity = store.health_snapshot()['capacity']
        assert capacity['used_receipts'] == count
        assert capacity['used_payload_bytes'] <= capacity['max_payload_bytes'] == 8 * 1024 * 1024
        channel = 'teams' if config == TEAMS else 'misp'
        descriptor = reg.descriptors()[channel]
        adapter = reg.capture(channel, descriptor['binding_id'], 'Added', revision=1)
        traces = []
        vm = [0]

        def progress():
            vm[0] += 100
            return 0

        store._db.set_trace_callback(traces.append)
        store._db.set_progress_handler(progress, 100)
        claim = store.claim_next(descriptor, 100)
        store._db.set_progress_handler(None, 0)
        store._db.set_trace_callback(None)
        assert claim
        query = next(q for q in traces if q.startswith('SELECT r.* FROM receipt r'))
        plan = [list(row) for row in store._db.execute('EXPLAIN QUERY PLAN ' + query)]
        assert store.finish_step(claim, adapter.execute_step(claim), 100)['applied']
        # Uninstrumented full-claim timings. Remote 503 keeps the admitted row;
        # clock advance respects real finite attempts/backoff (six total).
        samples = []
        for attempt in range(5):
            now = 10000 * (attempt + 1)
            start = time.perf_counter()
            claim = store.claim_next(descriptor, now)
            samples.append(time.perf_counter() - start)
            assert claim
            assert store.finish_step(claim, adapter.execute_step(claim), now)['applied']
        return {'receipts': count, 'capacity': capacity, 'vm_instructions_approx': vm[0],
                'main_db_bytes': store.path.stat().st_size, 'sqlite_version': sqlite3.sqlite_version,
                'query_plan': plan, 'claim_seconds_samples': samples,
                'claim_seconds_median': statistics.median(samples),
                'admission_seconds': admission_seconds}
    finally:
        close(store)


def test_full_claim_vm_budget_and_indexed_membership_scaling(tmp_path):
    measures = [measure_claims(tmp_path / str(n), n) for n in (1, 10, 250, 1000, 1999)]
    print('CLAIM_MEASUREMENTS=' + json.dumps(measures), flush=True)
    for row in measures:
        assert row['vm_instructions_approx'] <= 200 * row['receipts'] + 10000
    for row in measures:
        assert not any('SCAN m' in entry[-1] for entry in row['query_plan'])
        assert not any('TEMP B-TREE FOR ORDER BY' in entry[-1] for entry in row['query_plan'])
    large = measures[2:]
    assert large[1]['vm_instructions_approx'] <= 6 * large[0]['vm_instructions_approx']
    assert large[2]['vm_instructions_approx'] <= 3 * large[1]['vm_instructions_approx']


def test_teams_all_member_claim_has_bounded_vm_work(tmp_path):
    measured = measure_claims(tmp_path, 250, config=TEAMS)
    print('TEAMS_CLAIM_MEASUREMENT=' + json.dumps(measured), flush=True)
    assert measured['vm_instructions_approx'] <= 200 * 250 + 10000
    assert not any('SCAN m' in entry[-1] for entry in measured['query_plan'])


def test_many_retry_predecessors_do_not_make_correlated_range_scan_quadratic(tmp_path):
    store, reg, _, _ = make_components(tmp_path)
    try:
        for generation in range(2):
            for group in range(4):
                ips = ['198.19.' + str(group) + '.' + str(i) for i in range(1, 251)]
                assert store.record_domain(observation(ips, target=f'g{generation}-t{group}'),
                                           AUTH, bindings(reg))['admitted_receipts'] == 250
        with sqlite3.connect(store.path) as db:
            db.execute("UPDATE receipt SET state='retry_wait',due=200 WHERE id<=1000")
        vm = [0]

        def progress():
            vm[0] += 100
            return 0

        store._db.set_progress_handler(progress, 100)
        assert store.claim_next(reg.descriptors()['misp'], 100) is None
        store._db.set_progress_handler(None, 0)
        print('BLOCKED_PREDECESSOR_VM=' + str(vm[0]), flush=True)
        assert vm[0] <= 200 * 2000 + 10000
        assert store.health_snapshot()['capacity']['used_receipts'] == 2000
    finally:
        close(store)
