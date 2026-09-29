"""FIFO checks every Teams member, including nonleaders across domains."""
import json

import pytest

from test_delivery_review_components import (
    AUTH, TEAMS, Response, bindings, close, make_components,
    observation, rows, worker,
)


@pytest.mark.parametrize('status', [401, 503], ids=['blocked', 'retry'])
@pytest.mark.parametrize('action', ['Added', 'Removed'])
def test_old_predecessor_holds_nonleader_but_not_unrelated_ip(tmp_path, status, action):
    grace = {'192.0.2.9': {'labels': ['old'], 'missing_since': 0}} if action == 'Removed' else {}
    store, reg, transport, clock = make_components(tmp_path, config=TEAMS, grace=grace, now=86400)
    if action == 'Removed':
        assert store.reconcile_full(AUTH, {}, 86400, bindings(reg))['admitted_receipts'] == 1
    else:
        store.record_domain(observation(['192.0.2.9'], label='old', now=86400, cycle_id='old'), AUTH, bindings(reg))
    store.seal_cycle(None)
    value = worker(store, reg, clock)
    try:
        transport.callback = lambda *args: Response({}, status)
        assert value.run_pass(max_provider_calls=1)['provider_calls'] == 1
        # The conflict belongs to a nonleader, not the candidate's own IP.
        store.record_domain(observation(['192.0.2.1', '192.0.2.9'], target='new-domain',
                            label='new', now=86401, cycle_id='new'), AUTH, bindings(reg))
        store.seal_cycle(None)
        store.record_domain(observation(['192.0.2.2'], target='unrelated',
                            label='unrelated', now=86401, cycle_id='other'), AUTH, bindings(reg))
        store.seal_cycle(None)
        transport.callback = None
        result = value.run_pass()
        assert result['provider_calls'] == 1
        assert 'source=unrelated' in json.loads(transport.calls[-1]['data'])['text']
        assert len(rows(store, 'receipt')) == 3
        clock[0] = 86430
        if status == 401:
            store.configuration_applied()
        result = value.run_pass()
        assert result['provider_calls'] == 2
        assert 'source=old' in json.loads(transport.calls[-2]['data'])['text']
        assert 'source=new' in json.loads(transport.calls[-1]['data'])['text']
        assert store.health_snapshot()['acked_total'] == 4
        assert not rows(store, 'receipt')
    finally:
        close(store, value)


def test_same_ip_within_one_batch_does_not_self_block(tmp_path):
    store, reg, _, clock = make_components(tmp_path, config=TEAMS)
    for target in ('first', 'second'):
        store.record_domain(observation(['192.0.2.1'], target=target, label=target), AUTH, bindings(reg))
    store.seal_cycle(None)
    value = worker(store, reg, clock)
    try:
        assert value.run_pass()['provider_calls'] == 1
        assert store.health_snapshot()['acked_total'] == 2
    finally:
        close(store, value)
