"""Atomic configuration commit contracts through the shipped handlers."""
import copy
import json
from pathlib import Path
from unittest.mock import patch

import pytest
import decoder_registry
import txt_decoder
from http_api.decoder_crud import handle_decoders_custom_post, handle_decoders_custom_put
from tests.test_config_revision import context, request


@pytest.fixture(autouse=True)
def restore_registry():
    view = decoder_registry.snapshot_registry()
    yield
    decoder_registry.publish(view)


def call(ctx, fn, data):
    handler = request(data)
    fn(ctx, handler)
    return handler.status, json.loads(handler.wfile.getvalue())


def test_decoder_replace_failure_retains_disk_revision_and_callable(tmp_path):
    ctx = context(domains=[], custom_decoders=[], unknown_public={'keep': [1]})
    ctx.config_path = str(tmp_path / 'config.json')
    data = {'revision': 0, 'name': 'atomic_test', 'steps': [{'op': 'ascii'}]}
    code, result = call(ctx, handle_decoders_custom_post, data)
    assert code == 200
    assert result.get('revision') == 1, 'decoder commit must share the config revision'
    original = Path(ctx.config_path).read_bytes()
    previous = copy.deepcopy({k: v for k, v in ctx.shared_config.items() if not k.startswith('_')})
    with patch('config_manager.os.replace', side_effect=OSError('secret disk path')):
        code, result = call(ctx, handle_decoders_custom_put, {**data, 'revision': 1, 'steps': [{'op': 'base64'}]})
    assert code == 500 and 'secret disk path' not in json.dumps(result)
    assert Path(ctx.config_path).read_bytes() == original
    assert {k: v for k, v in ctx.shared_config.items() if not k.startswith('_')} == previous
    assert ctx.shared_config['_config_revision'] == 1
    assert txt_decoder.decode_txt_hidden_ips(['1.2.3.4'], 'atomic_test') == ['1.2.3.4']


def test_bulk_config_compiles_before_write_and_publishes_catalog(tmp_path):
    from http_api.config_post import handle_config_post
    from http_api.basic_handlers import handle_decoders
    ctx = context(domains=[], custom_decoders=[], unknown_public={'keep': [1]})
    ctx.config_path = str(tmp_path / 'config.json')
    code, result = call(ctx, handle_config_post, {'revision': 0, 'custom_decoders': [
        {'name': 'bulk', 'steps': [{'op': 'not_an_op'}]},
    ]})
    assert code == 400, 'bulk decoder definitions must be compiled before committing'
    assert not Path(ctx.config_path).exists()
    definition = {'name': 'bulk', 'steps': [{'op': 'ascii'}]}
    code, result = call(ctx, handle_config_post, {'revision': 0, 'custom_decoders': [definition]})
    assert code == 200 and result['revision'] == 1
    assert txt_decoder.decode_txt_hidden_ips(['1.2.3.4'], 'bulk') == ['1.2.3.4']
    assert json.loads(Path(ctx.config_path).read_text())['unknown_public'] == {'keep': [1]}
    code, result = call(ctx, handle_decoders, {})
    assert result['revision'] == 1 and result['custom'] == [definition]


def test_settings_effects_are_unlocked_ordered_and_failure_acknowledges_commit(tmp_path):
    import threading
    from http_api.settings_handlers import handle_settings_post
    from http_api.config_post import handle_config_post
    from monitor.config_service import get_config_service
    ctx = context(domains=[], alerts={}, unknown_public={'keep': [1]})
    ctx.config_path = str(tmp_path / 'config.json')
    entered, release, read_done, second_done = (threading.Event() for _ in range(4))
    results = []

    def apply(alerts):
        entered.set()
        assert release.wait(3)
        raise RuntimeError('secret adapter URL')

    def read():
        with ctx.config_lock:
            assert ctx.shared_config['_config_revision'] == 1
        read_done.set()

    def second():
        results.append(call(ctx, handle_config_post, {'revision': 1, 'interval': 22}))
        second_done.set()

    with patch('alerts.init_from_alerts', side_effect=apply), patch('http_api.settings_handlers.set_api_key'):
        first = threading.Thread(target=lambda: results.append(call(ctx, handle_settings_post,
            {'revision': 0, 'alerts': {'vt_cache_ttl_days': 9}})))
        first.start()
        assert entered.wait(2)
        reader = threading.Thread(target=read)
        writer = threading.Thread(target=second)
        reader.start()
        writer.start()
        try:
            assert read_done.wait(1), 'adapter must not own config lock'
            assert not second_done.is_set(), 'writer order extends through optional effects'
        finally:
            release.set()
            first.join(3)
            reader.join(3)
            writer.join(3)
    committed = next(payload for code, payload in results if payload['revision'] == 1)
    assert committed['warnings'] == ['alerts_runtime_apply_failed']
    assert 'secret adapter URL' not in json.dumps(committed)
    assert committed['alerts']['vt_cache_ttl_days'] == 9
    snapshot = get_config_service(ctx).snapshot()
    assert snapshot['config_revision'] == 2 and snapshot['unknown_public'] == {'keep': [1]}
    assert json.loads(Path(ctx.config_path).read_text()) == snapshot



@pytest.mark.parametrize('kind,key,field', [('TXT', 'custom_decoders', 'txt_decode'), ('A', 'custom_a_decoders', 'a_decode')])
def test_referenced_decoder_cannot_be_deleted_by_crud_or_bulk(kind, key, field):
    from http_api.decoder_crud import handle_decoders_custom_delete
    from http_api.config_post import handle_config_post
    ctx = context(domains=[{'name': 'in.use', 'type': kind, field: 'used'}])
    code, _ = call(ctx, handle_decoders_custom_post,
        {'revision': 0, 'name': 'used', 'decoder_type': kind, 'steps': [{'op': 'ascii'}]})
    assert code == 200
    for fn, data in ((handle_decoders_custom_delete, {'name': 'used', 'decoder_type': kind}),
                     (handle_config_post, {key: []})):
        code, result = call(ctx, fn, {'revision': 1, **data})
        assert code == 400, 'referenced decoder deletion must fail before publication'
        assert 'referenced' in result['error']
        assert ctx.shared_config['_config_revision'] == 1
    # Removing the target and its decoder in one config commit is valid.
    code, _ = call(ctx, handle_config_post, {'revision': 1, 'domains': [], key: []})
    assert code == 200


@pytest.mark.parametrize('kind', ['TXT', 'A'])
def test_decoder_success_never_returns_persistent_secrets(kind):
    ctx = context(domains=[], ens_rpc_url='private-rpc', alerts={'vt_api_key': 'private-api-key'},
                  unknown_public={'opaque_secret': 'not-an-api-field'})
    code, result = call(ctx, handle_decoders_custom_post,
        {'revision': 0, 'name': 'safe', 'decoder_type': kind, 'steps': [{'op': 'ascii'}]})
    assert code == 200
    text = json.dumps(result)
    assert 'private-rpc' not in text and 'private-api-key' not in text
    assert 'not-an-api-field' not in text



def test_config_and_settings_reads_use_complete_memory_snapshot_not_live_disk(tmp_path):
    from http_api.basic_handlers import handle_config
    from http_api.config_post import handle_config_post
    from http_api.settings_handlers import handle_settings_get
    ctx = context(domains=[], config_revision=7, unknown_public={'opaque': 'persist-not-project'})
    ctx.config_path = str(tmp_path / 'config.json')
    Path(ctx.config_path).write_text(json.dumps({'alerts': {'vt_cache_ttl_days': 99}}))
    code, settings = call(ctx, handle_settings_get, {})
    assert code == 200 and settings['revision'] == 7
    assert settings['settings']['alerts']['vt_cache_ttl_days'] != 99
    code, config = call(ctx, handle_config, {})
    assert config['revision'] == 7 and 'unknown_public' not in config
    code, result = call(ctx, handle_config_post, {'revision': 7, 'interval': 42})
    assert code == 200 and result['revision'] == 8
    assert 'unknown_public' not in result['config']
    persisted = json.loads(Path(ctx.config_path).read_text())
    assert persisted['unknown_public']['opaque'] == 'persist-not-project'
    assert 'alerts' not in persisted



def test_http_bootstrap_accepts_explicit_shared_service(tmp_path):
    import threading
    from http_server import make_handler
    from monitor.config_service import ConfigService
    ctx = context(domains=[], alerts={})
    service = ConfigService(ctx.shared_config, ctx.config_lock, '')
    try:
        handler = make_handler(ctx.shared_config, ctx.config_lock, '', str(tmp_path), {}, {}, config_service=service)
    except TypeError as exc:
        pytest.fail(f'bootstrap must accept the app service: {exc}')
    assert ctx.shared_config['_config_service'] is service
    assert service.read_model is not None and service.state_repository is not None
    assert handler is not None
    # First access from separate helper contexts must select this same writer.
    from monitor.config_service import get_config_service
    other = context()
    other.shared_config = ctx.shared_config
    other.config_lock = ctx.config_lock
    chosen = []
    threads = [threading.Thread(target=lambda c=c: chosen.append(get_config_service(c))) for c in (ctx, other)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(2)
    assert chosen == [service, service]



def test_swallowed_misp_initialization_failure_is_a_committed_warning():
    from http_api.settings_handlers import handle_settings_post
    ctx = context(domains=[], alerts={})
    with patch('alerts.PyMISP', side_effect=OSError('private upstream error')):
        code, result = call(ctx, handle_settings_post, {'revision': 0, 'alerts': {
            'misp_url': 'https://synthetic.invalid', 'api_key': 'synthetic-key', 'push_event_id': '1',
        }})
    assert code == 200 and result['revision'] == 1
    assert result['warnings'] == ['alerts_runtime_apply_failed']
    assert 'private upstream error' not in json.dumps(result)



def test_config_commit_preserves_configured_secret_flags():
    from http_api.config_post import handle_config_post
    ctx = context(domains=[], ens_rpc_url='https://private.invalid/token', alerts={'api_key': 'private-key'})
    code, result = call(ctx, handle_config_post, {'revision': 0, 'interval': 31})
    assert code == 200
    assert result['config']['configured']['ens_rpc_url'] is True
    assert result['config']['alerts']['configured']['api_key'] is True
    assert 'private' not in json.dumps(result)
