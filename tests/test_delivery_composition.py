"""Composition of the actual store and destination registry, no providers."""
from monitor.delivery_adapters import DestinationRegistry
from monitor.delivery_store import DeliveryStore
from tests.test_delivery_store_atomic import AUTH, obs


def test_real_registry_disabled_channel_does_not_poison_enabled_admission(tmp_path):
    store = DeliveryStore(tmp_path)
    try:
        boot = store.bootstrap({'example.test': {'ips': [], 'signature': 'dns-v1'}}, {}, AUTH)
        assert boot is not None and boot['ready']
        registry = DestinationRegistry(store.binding_key())
        registry.apply({'teams_webhook': 'https://teams.invalid/fixture'}, revision=1)
        result = store.record_domain(obs(['192.0.2.1']), AUTH, list(registry.descriptors().values()))
        assert result['outcome'] == 'admitted', result
        assert result['admitted_receipts'] == 1
        assert store.health_snapshot()['coverage'] == 'covered'
    finally:
        store.close(clean=True)
