"""Complete batch membership, seal failure and retry/restart boundary coverage."""
import json

import pytest

from monitor.delivery_store import DeliveryStore
from test_delivery_review_components import (
    AUTH, TEAMS, Response, Transport, bindings, close, make_components,
    observation, projection, registry, render, rows, worker,
)


def test_real_renderer_has_typed_size_error_separate_from_genuine_value_error():
    from alerts import render_teams_body
    from monitor.delivery_types import TeamsPayloadTooLarge
    with pytest.raises(TeamsPayloadTooLarge, match='payload_limit'):
        render_teams_body('Added', [['192.0.2.1', '雪' * 9000, 'A']])
    with pytest.raises(ValueError, match='payload_invalid') as fault:
        render_teams_body('invalid', [['192.0.2.1', 'label', 'A']])
    assert not isinstance(fault.value, TeamsPayloadTooLarge)


def test_single_item_over_wire_limit_is_explicit_failure_not_queue_poison(tmp_path):
    store, reg, transport, clock = make_components(tmp_path, config=TEAMS, limits={'batch_bytes': 600})
    try:
        store.record_domain(observation(['192.0.2.1'], label='a' * 1000), AUTH, bindings(reg))
        store.record_domain(observation(['192.0.2.2'], target='other', label='short'), AUTH, bindings(reg))
        assert store.seal_cycle(None)['ledger_committed']
        value = worker(store, reg, clock)
        value.run_pass()
        assert store.health_snapshot()['failed_total'] == 1
        assert store.health_snapshot()['acked_total'] == 1
        assert store.health_snapshot()['missed_total'] == 0
        assert [r['reason'] for r in rows(store, 'terminal') if r['state'] == 'failed'] == ['payload_limit']
        assert len(transport.calls) == 1
        assert '192.0.2.2' in json.loads(transport.calls[0]['data'])['text']
        assert value.stop()['stopped']
    finally:
        close(store)


@pytest.mark.parametrize('count,label', [(61, 'short'), (121, 'short'), (61, 'a' * 1000)])
def test_chunks_restart_partial_and_retry_exact_frozen_bytes(tmp_path, count, label):
    transport = Transport(callback=lambda method, url, kw: Response({}, 503))
    store, reg, _, clock = make_components(tmp_path, config=TEAMS, transport=transport)
    ips = ['198.51.100.' + str(i) for i in range(1, count + 1)]
    # Long labels require <=64KiB per admission; same cycle remains shared.
    for offset in range(0, count, 30):
        batch = ips[offset:offset + 30]
        assert store.record_domain(observation(batch, target='target' + str(offset), label=label),
                                   AUTH, bindings(reg))['admitted_receipts'] == len(batch)
    assert any(row['state'] == 'unsealed' for row in rows(store, 'receipt'))
    close(store)
    store = DeliveryStore(tmp_path, clock=lambda: 100, render=render)
    assert store.bootstrap(projection(), {}, AUTH)['ready']
    try:
        batches = [json.loads(r['payload']) for r in rows(store, 'batch')]
        assert sorted(e[0] for b in batches for e in b['entries']) == sorted(ips)
        assert all(len(b['entries']) <= 60 for b in batches)
        reg = registry(store, transport, TEAMS)
        value = worker(store, reg, clock)
        value.run_pass()
        original = [call['data'] for call in transport.calls]
        assert len(original) == len(batches)
        assert all(len(body) <= 24 * 1024 for body in original)
        assert all(row['state'] == 'retry_wait' for row in rows(store, 'receipt'))
        close(store, value)
        store = DeliveryStore(tmp_path, clock=lambda: 130, render=lambda *args: pytest.fail('sealed retry re-rendered'))
        assert store.bootstrap(projection(), {}, AUTH)['ready']
        transport.callback = None
        reg = registry(store, transport, TEAMS)
        value = worker(store, reg, [130])
        value.run_pass()
        assert [call['data'] for call in transport.calls[len(original):]] == original
        assert store.health_snapshot()['acked_total'] == count
        assert not rows(store, 'receipt')
        assert value.stop()['stopped']
    finally:
        close(store)


@pytest.mark.parametrize('fault', [RuntimeError('renderer offline'), ValueError('payload_limit')])
def test_genuine_fault_including_untyped_size_text_retains_work(tmp_path, fault):
    def broken(*args):
        raise fault
    store, reg, transport, clock = make_components(tmp_path, config=TEAMS, renderer=broken)
    store.record_domain(observation(['192.0.2.1']), AUTH, bindings(reg))
    assert not store.seal_cycle(None)['ledger_committed']
    assert rows(store, 'receipt')[0]['state'] == 'unsealed'
    assert store.health_snapshot()['failed_total'] == 0
    value = worker(store, reg, clock)
    assert value.run_pass()['provider_calls'] == 0
    assert not transport.calls
    close(store, value)
    store = DeliveryStore(tmp_path, clock=lambda: 100, render=render)
    assert store.bootstrap(projection(), {}, AUTH)['ready']
    reg = registry(store, transport, TEAMS)
    value = worker(store, reg, clock)
    value.run_pass()
    assert store.health_snapshot()['acked_total'] == 1
    close(store, value)
