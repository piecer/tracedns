"""Interrupted real-adapter mutations must resume with authoritative evidence."""
import json
import multiprocessing
import os
import sqlite3

import pytest

from monitor.delivery_store import DeliveryStore
from test_delivery_review_components import (
    AUTH, MISP, Transport, attr, bindings, close, make_components,
    observation, projection, registry, rows, worker,
)

IP = '192.0.2.1'


def mutation_fixture(path, action):
    grace = {IP: {'labels': ['x'], 'missing_since': 0}} if action == 'Removed' else {}
    store, reg, _, _ = make_components(path, grace=grace, now=86400)
    if action == 'Removed':
        assert store.reconcile_full(AUTH, {}, 86400, bindings(reg))['admitted_receipts'] == 1
    else:
        assert store.record_domain(observation([IP], now=86400), AUTH, bindings(reg))['admitted_receipts'] == 1
    return store, reg


def crash_in_mutation(path, action, after):
    store = DeliveryStore(path, clock=lambda: 86400)
    assert store.bootstrap(projection(), {}, AUTH)['ready']
    initial = [attr(IP)] if action == 'Removed' else []

    class CrashTransport(Transport):
        def request(self, method, url, **kwargs):
            mutation = '/attributes/' in url
            if mutation and not after:
                (path / 'fake-remote.json').write_text(json.dumps(self.attrs))
                os._exit(23)
            response = super().request(method, url, **kwargs)
            if mutation:
                # Persist the fake provider's actual add/delete result, then
                # die before adapter validation or durable finish can run.
                (path / 'fake-remote.json').write_text(json.dumps(self.attrs))
                os._exit(23)
            return response

    transport = CrashTransport(initial)
    reg = registry(store, transport, MISP)
    value = worker(store, reg, [86400])
    value.run_pass(max_provider_calls=1)
    value.run_pass(max_provider_calls=1)
    os._exit(99)


@pytest.mark.parametrize('action', ['Added', 'Removed'])
@pytest.mark.parametrize('after', [False, True], ids=['before-side-effect', 'after-side-effect'])
def test_child_death_during_mutation_rereads_before_truthful_ack(tmp_path, action, after):
    store, _ = mutation_fixture(tmp_path, action)
    close(store)
    child = multiprocessing.get_context('fork').Process(target=crash_in_mutation, args=(tmp_path, action, after))
    child.start()
    child.join(10)
    assert not child.is_alive() and child.exitcode == 23
    before = rows(tmp_path, 'receipt')[0]
    assert before['state'] == 'in_flight'
    assert json.loads(before['progress'])['phase'] == ('add' if action == 'Added' else 'delete')
    assert before['attempt'] == 1 and before['provider_calls'] == 2
    store = DeliveryStore(tmp_path, clock=lambda: 86400)
    assert store.bootstrap(projection(), {}, AUTH)['ready']
    try:
        recovered = rows(store, 'receipt')[0]
        assert json.loads(recovered['progress']) == {}
        assert recovered['attempt'] == 1 and recovered['provider_calls'] == 2
        assert recovered['state'] == 'retry_wait' and recovered['due'] == 86430
        remote = json.loads((tmp_path / 'fake-remote.json').read_text())
        transport = Transport(remote)
        reg = registry(store, transport, MISP)
        value = worker(store, reg, [86430])
        result = value.run_pass()
        assert transport.calls[0]['method'] == 'GET'
        assert store.health_snapshot()['acked_total'] == 1
        assert store.health_snapshot()['failed_total'] == 0
        assert result['provider_calls'] == (1 if after else (2 if action == 'Added' else 3))
        assert bool(transport.attrs) == (action == 'Added')
        assert value.stop()['stopped']
    finally:
        close(store)


@pytest.mark.parametrize('action', ['Added', 'Removed'])
def test_same_process_failed_finish_atomically_resets_mutation_and_rejects_stale_token(tmp_path, action):
    store, reg = mutation_fixture(tmp_path, action)
    transport = Transport([attr(IP)] if action == 'Removed' else [])
    reg = registry(store, transport, MISP)
    descriptor = reg.descriptors()['misp']
    adapter = reg.capture('misp', descriptor['binding_id'], action, revision=1)
    try:
        first = store.claim_next(descriptor, 86400)
        assert store.finish_step(first, adapter.execute_step(first), 86400)['applied']
        claim = store.claim_next(descriptor, 86400)
        outcome = adapter.execute_step(claim)

        def fail(point):
            if point == 'before_commit':
                raise sqlite3.OperationalError('injected durable finish failure')

        store._fault = fail
        assert not store.finish_step(claim, outcome, 86400)['applied']
        assert not store.dispatch_available()
        # Recovery itself cannot partially clear progress if its COMMIT fails.
        full = {'active_map': {}, 'completed_at': 86400, 'bindings': bindings(reg)}
        assert not store.recover_gap(AUTH, projection(), full)['ready']
        unchanged = rows(store, 'receipt')[0]
        assert unchanged['state'] == 'in_flight' and unchanged['token'] == claim['attempt_token']
        assert json.loads(unchanged['progress']) == claim['progress']
        store._fault = lambda _: None
        assert store.recover_gap(AUTH, projection(), full)['ready']
        recovered = rows(store, 'receipt')[0]
        assert json.loads(recovered['progress']) == {}
        assert recovered['attempt'] == 1 and recovered['provider_calls'] == 2
        assert not store.finish_step(claim, outcome, 86400)['applied']
        next_claim = store.claim_next(descriptor, 86430)
        assert next_claim['attempt'] == 2 and next_claim['provider_calls'] == 3
        assert not store.finish_step(claim, outcome, 86430)['applied']
        next_outcome = adapter.execute_step(next_claim)
        assert transport.calls[-1]['method'] == 'GET'
        assert next_outcome['state'] == 'acked'
        assert store.finish_step(next_claim, next_outcome, 86430)['applied']
        assert store.health_snapshot()['acked_total'] == 1
    finally:
        close(store)
