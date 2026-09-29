import dataclasses
import importlib
import importlib.util
import json


def module():
    assert importlib.util.find_spec('monitor.delivery_adapters'), 'delivery adapter missing'
    return importlib.import_module('monitor.delivery_adapters')


def test_registry_malformed_committed_replacement_revokes_old_readiness():
    m = module()
    registry = m.DestinationRegistry(b'k' * 32)
    registry.apply({'teams_webhook': 'https://teams.invalid/SECRET'}, revision=1)
    binding = registry.descriptors()['teams']['binding_id']
    registry.apply(None, revision=2)
    assert registry.capture('teams', binding, 'Added').error is not None
    registry.apply({'teams_webhook': 'https://teams.invalid/SECRET'}, revision=3)
    assert registry.capture('teams', binding, 'Added', revision=2).error == 'adapter_unapplied'


def test_registry_binding_rotation_disable_failed_apply_and_immutable_snapshot():
    m = module()
    registry = m.DestinationRegistry(b'k' * 32)
    cfg = {'misp_url': 'https://misp.invalid', 'api_key': 'CANARY_KEY',
           'push_event_id': 12, 'misp_remove_on_absent': True,
           'teams_webhook': 'https://teams.invalid/CANARY_WEBHOOK'}
    registry.apply(cfg, revision=1)
    descriptors = registry.descriptors()
    assert set(descriptors) == {'teams', 'misp'}
    for d in descriptors.values():
        assert set(d) == {'channel', 'binding_id', 'enabled', 'ready', 'allow_removed', 'error'}
        assert d['enabled'] and d['ready']
    assert 'CANARY' not in json.dumps(descriptors)
    old = registry.capture('misp', descriptors['misp']['binding_id'], 'Removed')
    assert 'CANARY' not in repr(old)
    try:
        old.binding_id = 'changed'
        assert False, 'adapter is mutable'
    except dataclasses.FrozenInstanceError:
        pass
    registry.apply(dict(cfg, api_key='ROTATED'), revision=2)
    assert registry.descriptors() == descriptors
    assert registry.capture('misp', old.binding_id, 'Added') is not old
    registry.apply(dict(cfg, push_event_id=13), revision=3)
    assert registry.capture('misp', old.binding_id, 'Added').error == 'old_binding_blocked'
    registry.apply(cfg, revision=4, applied=False)
    assert registry.capture('misp', old.binding_id, 'Added').error == 'adapter_unapplied'
    registry.apply({}, revision=5)
    assert registry.capture('misp', old.binding_id, 'Added').error == 'destination_disabled'
    registry.apply(dict(cfg, misp_remove_on_absent=False), revision=6)
    assert registry.capture('misp', old.binding_id, 'Removed').error == 'removal_disabled'
    assert old.error is None  # already admitted snapshot is not revoked
    assert m.DestinationRegistry(b'x' * 32).descriptors()['misp']['enabled'] is False
