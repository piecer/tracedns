"""Established schema-1 ledgers acquire indexes without changing admitted work."""
import sqlite3

from monitor.delivery_store import DeliveryStore
from test_delivery_review_components import (
    AUTH, MISP, Transport, attr, bindings, close, observation, projection, registry, rows, worker,
)


class LegacyIndexStore(DeliveryStore):
    def _execute(self, sql, args=()):
        # Only fixture schema construction omits the additive indexes. Existing
        # baseline table layout and all real admission methods are unchanged.
        if sql.startswith(('CREATE INDEX IF NOT EXISTS receipt_claim ',
                           'CREATE INDEX IF NOT EXISTS receipt_members ')):
            return 0
        return super()._execute(sql, args)


def test_reopen_adds_indexes_to_legacy_schema_preserving_receipts(tmp_path):
    store = LegacyIndexStore(tmp_path, clock=lambda: 100)
    assert store.bootstrap(projection(), {}, AUTH)['ready']
    transport = Transport([attr('192.0.2.1')])
    reg = registry(store, transport, MISP)
    store.record_domain(observation(['192.0.2.1']), AUTH, bindings(reg))
    original = rows(store, 'receipt')
    close(store)
    with sqlite3.connect(tmp_path / 'delivery.sqlite') as db:
        old_indexes = {row[1] for row in db.execute('PRAGMA index_list(receipt)')}
    assert old_indexes == {'receipt_fifo'}
    store = DeliveryStore(tmp_path, clock=lambda: 100)
    assert store.bootstrap(projection(['192.0.2.1']), {}, AUTH)['ready']
    try:
        assert rows(store, 'receipt') == original
        with sqlite3.connect(store.path) as db:
            assert {row[1] for row in db.execute('PRAGMA index_list(receipt)')} == {
                'receipt_fifo', 'receipt_claim', 'receipt_members'}
            assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        reg = registry(store, transport, MISP)
        value = worker(store, reg, [100])
        assert value.run_pass()['provider_calls'] == 1
        assert store.health_snapshot()['acked_total'] == 1
        assert value.stop()['stopped']
    finally:
        close(store)
