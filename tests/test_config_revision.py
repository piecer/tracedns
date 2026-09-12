import json
import threading
from types import SimpleNamespace
from unittest.mock import patch
from tests.test_settings_handlers import FakeHandler
from http_api.config_post import handle_config_post
from http_api.settings_handlers import handle_settings_post


def context(**cfg):
    return SimpleNamespace(shared_config=cfg, config_lock=threading.RLock(),
        config_path='', max_body_bytes=10000, current_results={}, history={},
        history_dir='', purge_removed_domains_state=None)


def request(payload, role='admin'):
    h = FakeHandler(json.dumps(payload).encode())
    h.principal = {'id': 1, 'username': 'alice', 'role': role}
    return h


def test_revision_is_shared_and_stale_write_does_not_mutate():
    ctx = context(domains=[], alerts={})
    h = request({'domains': [], 'revision': 0})
    handle_config_post(ctx, h)
    assert json.loads(h.wfile.getvalue())['revision'] == 1
    h = request({'alerts': {}, 'revision': 0})
    handle_settings_post(ctx, h)
    assert h.status == 409
    assert ctx.shared_config['_config_revision'] == 1


def test_secrets_preserved_redacted_and_explicitly_cleared():
    from http_api.settings_handlers import handle_settings_get
    from http_api.basic_handlers import handle_config
    ctx = context(alerts={'vt_api_key': 'a' * 64, 'api_key': 'hidden',
                          'teams_webhook': 'https://secret'}, ens_rpc_url='https://secret-rpc')
    for func in (handle_config, handle_settings_get):
        h = request({})
        func(ctx, h)
        text = h.wfile.getvalue().decode()
        assert 'hidden' not in text and 'https://secret' not in text
        assert json.loads(text)['revision'] == 0
    h = request({'revision': 0, 'alerts': {'api_key': '', 'vt_cache_ttl_days': 2}})
    with patch('alerts.init_from_alerts'), patch('http_api.settings_handlers.set_api_key'):
        handle_settings_post(ctx, h)
    assert ctx.shared_config['alerts']['api_key'] == 'hidden'
    assert 'hidden' not in h.wfile.getvalue().decode()
    h = request({'revision': 1, 'alerts': {}, 'clear_fields': ['vt_api_key']})
    with patch('alerts.init_from_alerts'), patch('http_api.settings_handlers.set_api_key') as setter:
        handle_settings_post(ctx, h)
    assert 'vt_api_key' not in ctx.shared_config['alerts']
    setter.assert_called_once_with('')


def test_internal_fields_not_persisted(tmp_path):
    ctx = context(domains=[], _force_resolve_queue=[{'actor': object()}])
    from pathlib import Path
    ctx.config_path = str(tmp_path / 'config.json')
    h = request({'revision': 0, 'domains': []})
    handle_config_post(ctx, h)
    assert h.status == 200
    assert not any(k.startswith('_') for k in json.loads(Path(ctx.config_path).read_text()))
