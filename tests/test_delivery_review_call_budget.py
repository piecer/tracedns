"""The adapter count includes the current durable provider-call reservation."""
import multiprocessing
import os
import sqlite3

import pytest

from monitor.delivery_store import DeliveryStore
from test_delivery_review_components import (
    AUTH, MISP, Transport, attr, bindings, close, make_components,
    observation, projection, registry, rows, worker,
)


@pytest.mark.parametrize('previous,expected', [(4094, 1), (4095, 1), (4096, 0)])
def test_inclusive_current_reservation_can_issue_last_permitted_read(tmp_path, previous, expected):
    store, reg, transport, clock = make_components(tmp_path, transport=Transport([attr('192.0.2.1')]))
    try:
        store.record_domain(observation(['192.0.2.1']), AUTH, bindings(reg))
        with sqlite3.connect(store.path) as db:
            db.execute('UPDATE receipt SET provider_calls=?,attempt=1,resume=1', (previous,))
        value = worker(store, reg, clock)
        result = value.run_pass()
        assert result['provider_calls'] == len(transport.calls) == expected
        assert store.health_snapshot()['acked_total'] == expected
        assert store.health_snapshot()['failed_total'] == 1 - expected
        if not expected:
            assert rows(store, 'terminal')[0]['reason'] == 'provider_work_limit'
        assert value.stop()['stopped']
    finally:
        close(store)


def die_on_call(path):
    store = DeliveryStore(path, clock=lambda: 100)
    assert store.bootstrap(projection(), {}, AUTH)['ready']
    transport = Transport(callback=lambda *args: os._exit(24))
    reg = registry(store, transport, MISP)
    worker(store, reg, [100]).run_pass(max_provider_calls=1)
    os._exit(99)


@pytest.mark.parametrize('previous,expected', [(4094, 1), (4095, 0)])
def test_crashed_last_reservations_are_never_refunded_on_reopen(tmp_path, previous, expected):
    store, reg, _, _ = make_components(tmp_path)
    store.record_domain(observation(['192.0.2.1']), AUTH, bindings(reg))
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE receipt SET provider_calls=?,attempt=1,resume=1', (previous,))
    close(store)
    child = multiprocessing.get_context('fork').Process(target=die_on_call, args=(tmp_path,))
    child.start()
    child.join(10)
    assert not child.is_alive() and child.exitcode == 24
    assert rows(tmp_path, 'receipt')[0]['provider_calls'] == previous + 1
    store = DeliveryStore(tmp_path, clock=lambda: 100)
    assert store.bootstrap(projection(), {}, AUTH)['ready']
    transport = Transport([attr('192.0.2.1')])
    reg = registry(store, transport, MISP)
    value = worker(store, reg, [130])
    try:
        result = value.run_pass()
        assert result['provider_calls'] == len(transport.calls) == expected
        assert store.health_snapshot()['acked_total'] == expected
        assert store.health_snapshot()['failed_total'] == 1 - expected
    finally:
        close(store, value)
