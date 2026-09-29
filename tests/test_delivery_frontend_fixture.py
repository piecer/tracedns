"""Real store states for the disposable browser owner, never production wiring."""
from monitor.delivery_store import DeliveryStore


def delivery_fixture(path, scenario):
    if scenario == 'noowner':
        return None
    store = DeliveryStore(path, limits={'receipts': 4}, clock=lambda: 100)
    authority = {'valid': True, 'revision': 1, 'signature': 'fixture'}
    assert store.bootstrap({}, {}, authority)['ready']
    bindings = [{'channel': channel, 'binding_id': letter * 64, 'enabled': True,
                 'ready': True, 'allow_removed': True, 'error': None}
                for channel, letter in [('misp', 'a'), ('teams', 'b')]]
    # Real worker admission publishes channel configuration even on an idle pass.
    for binding in bindings:
        assert store.claim_next(binding, 100) is None

    def observe(ips):
        return store.record_domain({'target': 'private-canary.test', 'managed_ips': ips,
            'before_ips': [], 'projection_signature': 'fixture',
            'source_operation_id': str(len(ips)), 'cycle_id': 'fixture',
            'observed_at': 100, 'label': 'PRIVATE-CANARY', 'source_type': 'A'},
            authority, bindings)

    observe(['192.0.2.1'])
    store.seal_cycle('fixture')
    if scenario == 'acked':
        # Fake transport outcomes through actual claim/finish, not health DTOs.
        for binding in bindings:
            claim = store.claim_next(binding, 100)
            assert claim
            assert store.finish_step(claim, {'state': 'acked', 'reason': None,
                'progress': {}, 'retry_after': None, 'provider_calls': 1,
                'observation_hook': None}, 100)['applied']
    if scenario == 'overflow':
        assert observe(['192.0.2.1', '192.0.2.2', '192.0.2.3'])['missed_receipts'] == 4
    if scenario == 'degraded':
        store.enter_gap('delivery_storage', {'misp': 3})
    return store


def test_delivery_browser_fixture_states(tmp_path):
    for scenario in ('backlog', 'acked', 'overflow', 'degraded'):
        store = delivery_fixture(tmp_path / scenario, scenario)
        try:
            health = store.health_snapshot()
            assert health['pending'] == (0 if scenario == 'acked' else 2)
            assert health['acked_total'] == (2 if scenario == 'acked' else 0)
            assert health['missed_total'] == (4 if scenario == 'overflow' else 0)
            if scenario == 'degraded':
                assert health['counts_stale'] and not health['accounting_complete']
                assert health['missed_unpersisted'] == 3
        finally:
            store.close(clean=True)
