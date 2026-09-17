import json
from datetime import datetime

from config_manager import domain_identity, read_config
from http_api.basic_handlers import handle_config
from http_api.config_post import handle_config_post
from tests.test_config_revision import context, request


def save(ctx, domains, **extra):
    h = request({'revision': ctx.shared_config.get('_config_revision', 0),
                 'domains': domains, **extra})
    handle_config_post(ctx, h)
    return h


def test_registration_metadata_is_server_owned_persisted_and_exposed(tmp_path):
    ctx = context(domains=[])
    ctx.config_path = str(tmp_path / 'config.json')
    domain = {'name': 'example.test', 'type': 'A'}
    key = domain_identity(domain)
    h = save(ctx, [domain], domain_metadata={key: {'created_at': 'forged'}})
    assert h.status == 200
    metadata = ctx.shared_config['domain_metadata'][key]
    assert datetime.fromisoformat(metadata['created_at']).tzinfo is not None
    assert metadata['updated_at'] == metadata['created_at']
    assert read_config(ctx.config_path)['domain_metadata'][key] == metadata
    assert json.loads(h.wfile.getvalue())['config']['domain_metadata'][key] == metadata
    h = request({})
    handle_config(ctx, h)
    assert json.loads(h.wfile.getvalue())['domain_metadata'][key] == metadata


def test_noop_reorder_and_unrelated_settings_keep_dates(tmp_path):
    from copy import deepcopy

    ctx = context(domains=[])
    domains = [{'name': 'one.test', 'type': 'A'}, {'name': 'two.test', 'type': 'TXT'}]
    save(ctx, domains)
    original = deepcopy(ctx.shared_config['domain_metadata'])
    save(ctx, list(reversed(domains)), interval=120)
    assert ctx.shared_config['domain_metadata'] == original
    h = request({'revision': ctx.shared_config['_config_revision'], 'servers': ['1.1.1.1']})
    handle_config_post(ctx, h)
    assert ctx.shared_config['domain_metadata'] == original


def test_edit_preserves_registration_and_legacy_registration_stays_unknown():
    dates = {'created_at': '2020-01-01T00:00:00+00:00', 'updated_at': '2020-01-01T00:00:00+00:00'}
    ctx = context(domains=[{'name': 'one.test', 'type': 'A'}, 'legacy.test'],
                  domain_metadata={'one.test': dates})
    save(ctx, [{'name': 'one.test', 'type': 'AAAA'}, {'name': 'legacy.test', 'type': 'TXT'}])
    known = ctx.shared_config['domain_metadata']['one.test']
    assert known['created_at'] == dates['created_at']
    assert known['updated_at'] != dates['updated_at']
    legacy = ctx.shared_config['domain_metadata']['legacy.test']
    assert 'created_at' not in legacy
    assert datetime.fromisoformat(legacy['updated_at']).tzinfo is not None


def test_legacy_noop_does_not_invent_dates_and_removal_discards_metadata():
    ctx = context(domains=['legacy.test'])
    save(ctx, [{'name': 'legacy.test', 'type': 'A'}])
    assert ctx.shared_config['domain_metadata']['legacy.test'] == {}
    save(ctx, [])
    assert ctx.shared_config['domain_metadata'] == {}
    save(ctx, [{'name': 'legacy.test', 'type': 'A'}])
    assert ctx.shared_config['domain_metadata']['legacy.test']['created_at']


def test_ens_sns_identities_get_independent_dates():
    domains = [
        {'name': 'node.eth', 'type': 'ENS', 'ens_text_key': 'Host'},
        {'name': 'node.eth', 'type': 'ENS', 'ens_text_key': 'host'},
        {'name': 'node.eth', 'type': 'ENS', 'ens_text_key': 'host', 'ens_node': '0x' + 'a' * 64},
        {'name': 'node.sol', 'type': 'SNS', 'ens_text_key': 'TXT'},
        {'name': 'node.sol', 'type': 'SNS', 'ens_text_key': 'url'},
    ]
    ctx = context(domains=[])
    save(ctx, domains)
    before = dict(ctx.shared_config['domain_metadata'])
    edited = [dict(d) for d in domains]
    edited[1]['ens_decode'] = 'none'
    save(ctx, edited)
    after = ctx.shared_config['domain_metadata']
    assert len(after) == len(domains)
    for index, domain in enumerate(domains):
        key = domain_identity(domain)
        assert after[key]['created_at'] == before[key]['created_at']
        assert (after[key] == before[key]) is (index != 1)


def test_failed_save_and_stale_revision_do_not_change_metadata(tmp_path):
    from copy import deepcopy
    from unittest.mock import patch

    ctx = context(domains=[])
    save(ctx, [{'name': 'one.test', 'type': 'A'}])
    before = deepcopy(ctx.shared_config)
    h = request({'revision': 0, 'domains': []})
    handle_config_post(ctx, h)
    assert h.status == 409
    assert ctx.shared_config == before
    ctx.config_path = str(tmp_path / 'config.json')
    with patch('config_manager.write_config', side_effect=OSError('disk full')):
        h = save(ctx, [{'name': 'one.test', 'type': 'AAAA'}])
    assert h.status == 500
    assert ctx.shared_config == before


def test_reload_of_persisted_configuration_keeps_dates(tmp_path):
    ctx = context(domains=[])
    ctx.config_path = str(tmp_path / 'config.json')
    save(ctx, [{'name': 'one.test', 'type': 'A'}])
    stored = read_config(ctx.config_path)
    restarted = context(**stored)
    save(restarted, stored['domains'])
    assert restarted.shared_config['domain_metadata'] == stored['domain_metadata']
