"""Fair best-effort sightings share, never extend, the receipt call budget."""
import json
import sqlite3

import pytest

import mispupdate_code as sightings
from test_delivery_review_components import (
    AUTH, TEAMS, Transport, attr, bindings, close, make_components,
    observation, worker,
)


def sighting_bridge(reg):
    # Core owns this bridge: retain actual two-step progress, recapture binding.
    progress = {}

    def step():
        nonlocal progress
        descriptor = reg.descriptors()['misp']
        adapter = reg.capture('misp', descriptor['binding_id'], 'Added', revision=reg.revision)
        if progress.get('binding_id', descriptor['binding_id']) != descriptor['binding_id']:
            progress = {}
        result = sightings.flush_sightings_step(adapter, progress, today='2026-09-24')
        progress = result['progress'] if result['state'] == 'continue' else {}
        return {'provider_calls': result['provider_calls'], 'has_more': result['provider_calls'] > 0}

    return step


@pytest.mark.parametrize('budget', [1, 2, 3, 32, 100])
def test_sustained_receipts_and_sightings_both_progress_within_four_passes(tmp_path, monkeypatch, budget):
    queue = tmp_path / 'sightings.json'
    monkeypatch.setenv('MISP_SIGHTING_BATCH_FILE', str(queue))
    ips = ['198.51.100.' + str(i) for i in range(1, 201)]
    transport = Transport([attr(ip, str(i + 1)) for i, ip in enumerate(ips)])
    store, reg, _, clock = make_components(tmp_path / 'ledger', transport=transport)
    assert store.record_domain(observation(ips), AUTH, bindings(reg))['admitted_receipts'] == 200
    sightings.enqueue_sightings('1', [ips[0]])
    value = worker(store, reg, clock, sightings_step=sighting_bridge(reg))
    try:
        for _ in range(4):
            before = len(transport.calls)
            result = value.run_pass(max_provider_calls=budget)
            assert result['provider_calls'] == len(transport.calls) - before
            assert result['provider_calls'] <= min(32, budget)
            assert result['steps'] <= 256
            assert store.health_snapshot()['capacity']['used_receipts'] > 0
        assert any('/sightings/add/' in call['url'] for call in transport.calls)
        assert json.loads(queue.read_text())['events']['1']['pending'] == []
        assert store.health_snapshot()['acked_total'] >= 2
    finally:
        close(store, value)


def test_ack_persistence_failure_fences_sightings_even_when_fair_turn_due(tmp_path):
    store, reg, transport, clock = make_components(tmp_path, config=TEAMS)
    store.record_domain(observation(['192.0.2.1']), AUTH, bindings(reg))
    store.seal_cycle(None)
    sight_calls = []

    def fail(point):
        if point == 'before_commit':
            raise sqlite3.OperationalError('ACK unavailable')

    def transport_hook(*args):
        store._fault = fail

    transport.callback = transport_hook
    value = worker(store, reg, clock, sightings_step=lambda: sight_calls.append(1) or {'provider_calls': 1, 'has_more': True})
    try:
        assert value.run_pass()['provider_calls'] == 1
        assert not sight_calls
        assert value.run_pass()['provider_calls'] == 0
        assert not sight_calls
        assert store.health_snapshot()['acked_total'] == 0
    finally:
        store._fault = lambda _: None
        close(store, value)


def test_stop_during_actual_sighting_post_prevents_next_provider_call(tmp_path, monkeypatch):
    monkeypatch.setenv('MISP_SIGHTING_BATCH_FILE', str(tmp_path / 'sightings.json'))
    ips = ['192.0.2.' + str(i) for i in range(1, 11)]
    transport = Transport([attr(ip, str(i + 1)) for i, ip in enumerate(ips)])
    store, reg, _, clock = make_components(tmp_path / 'ledger', transport=transport)
    store.record_domain(observation(ips), AUTH, bindings(reg))
    sightings.enqueue_sightings('1', [ips[0]])
    value = worker(store, reg, clock, sightings_step=sighting_bridge(reg))
    stopped_at = []

    def during_post(method, url, kw):
        if '/sightings/add/' in url:
            stopped_at.append(len(transport.calls))
            assert not value.stop(join_seconds=0)['stopped']

    transport.callback = during_post
    try:
        result = value.run_pass()
        assert result['stopped']
        assert stopped_at == [len(transport.calls)]
        assert store.health_snapshot()['capacity']['used_receipts'] > 0
        assert value.run_pass()['provider_calls'] == 0
        assert stopped_at == [len(transport.calls)]
    finally:
        close(store, value)


def test_zero_call_sightings_step_cap_zero_budget_and_stop(tmp_path):
    store, reg, _, clock = make_components(tmp_path)
    local = []
    value = worker(store, reg, clock, sightings_step=lambda: local.append(1) or {'provider_calls': 0, 'has_more': True})
    assert value.run_pass(max_provider_calls=0)['steps'] == 0
    assert not local
    result = value.run_pass(max_provider_calls=1)
    assert result['provider_calls'] == 0 and result['steps'] == 256
    assert len(local) == 256
    assert value.stop()['stopped']
    assert value.run_pass()['provider_calls'] == 0
    assert len(local) == 256
    close(store)
