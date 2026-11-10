"""Canonical target identity and managed-only source projections."""
import pytest

from config_manager import domain_identity, domain_storage_name
from test_delivery_review_components import MISP, TEAMS, Transport, rows
from test_stage3_core_runtime import app_factory


@pytest.mark.parametrize('kind,definition,provider', [
    ('A', {'name': 'example.test', 'type': 'A'}, 'fake'),
    ('TXT', {'name': 'example.test', 'type': 'TXT'}, 'fake'),
    ('ENS', {'name': 'example.eth', 'type': 'ENS', 'ens_text_key': 'ipv6'}, 'fixture-ens'),
    ('SNS', {'name': 'example.sol', 'type': 'SNS', 'ens_text_key': 'IPFS'}, 'fixture-sns'),
    ('DHT', {'name': 'signed config', 'type': 'DHT', 'dht_public_key': 'a' * 64}, 'DHT'),
])
def test_all_source_types_use_canonical_identity_and_configured_provider_only(tmp_path, monkeypatch, kind, definition, provider):
    side_stream = tmp_path / 'side-stream'
    side_stream.mkdir()
    monkeypatch.setenv('MISP_SIGHTING_BATCH_FILE', str(side_stream / 'sightings.json'))
    storage, identity = domain_storage_name(definition), domain_identity(definition)
    snapshot = {'type': kind, 'values': ['192.0.2.1'] if kind == 'A' else ['ciphertext'],
                'decoded_ips': [] if kind == 'A' else ['192.0.2.1'], 'ts': 123}
    config = {'domains': [definition], 'servers': ['fake'], 'ens_rpc_url': 'fixture-ens',
              'DEFAULT_SNS_PROXY_HOSTS': ['fixture-sns'], 'alerts': {**TEAMS, **MISP}, 'config_revision': 0}
    current = {storage: {provider: snapshot, 'retired-provider': {'type': kind,
                          'values': ['203.0.113.2'], 'decoded_ips': ['203.0.113.2'], 'ts': 124}}}
    transport = Transport()
    app = app_factory(tmp_path, config=config, current=current, transport=transport)
    try:
        preview = app.delivery.preview_resend(identity, ['teams', 'misp'], 0, actor_id='actor')
        assert preview['status'] == 'ready', preview
        assert preview['target'] == identity
        assert preview['ips'] == ['192.0.2.1'] and preview['observed_at'] == 123
        assert preview['source_type'] == kind and preview['retained'] is True
        if storage != identity:
            assert app.delivery.preview_resend(storage, ['teams'], 0, actor_id='actor')['reason'] == 'target_not_found'
        result = app.delivery.resend_target(preview['request_id'], actor_id='actor')
        assert result['status'] == 'queued'
        assert rows(app.delivery.store, 'manual_resend')[0]['target'] == storage
        app.delivery.worker.run_pass()
        assert app.delivery.store.health_snapshot()['acked_total'] == 2
        assert any('/attributes/add/' in call['url'] for call in transport.calls)
    finally:
        app.delivery.stop()
