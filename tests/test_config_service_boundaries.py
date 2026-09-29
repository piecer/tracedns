"""Fault injection at the durable boundary and deterministic writer races."""
import copy
import json
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

import a_decoder
import txt_decoder
from http_api.config_post import handle_config_post
from http_api.decoder_crud import handle_decoders_custom_delete, handle_decoders_custom_post, handle_decoders_custom_put
from http_api.settings_handlers import handle_settings_post
from monitor.config_service import ConfigError, ConfigService, get_config_service
from tests.test_config_revision import context
from tests.test_config_service import call, restore_registry  # noqa: F401


@pytest.mark.parametrize('kind,key,decode', [
    ('TXT', 'custom_decoders', txt_decoder.decode_txt_hidden_ips),
    ('A', 'custom_a_decoders', a_decoder.decode_a_hidden_ips),
])
@pytest.mark.parametrize('command', ['create', 'put', 'delete', 'bulk', 'settings'])
@pytest.mark.parametrize('fault', ['config_manager.os.replace', 'config_manager.os.fsync', 'config_manager.tempfile.NamedTemporaryFile'])
def test_all_writers_preserve_previous_generation_on_durable_failure(tmp_path, kind, key, decode, command, fault):
    ctx = context(domains=[], _force_resolve_queue=[{'opaque': object()}], unknown_public={'x': [1]})
    ctx.config_path = str(tmp_path / 'config.json')
    data = {'name': 'durable', 'decoder_type': kind, 'steps': [{'op': 'ascii'}], 'revision': 0}
    assert call(ctx, handle_decoders_custom_post, data)[0] == 200
    previous = get_config_service(ctx).snapshot()
    raw = Path(ctx.config_path).read_bytes()
    queue = ctx.shared_config['_force_resolve_queue']
    handler, body = {
        'create': (handle_decoders_custom_post, {**data, 'name': 'other'}),
        'put': (handle_decoders_custom_put, {**data, 'steps': [{'op': 'base64'}]}),
        'delete': (handle_decoders_custom_delete, data),
        'bulk': (handle_config_post, {key: []}),
        'settings': (handle_settings_post, {'alerts': {'vt_cache_ttl_days': 12}}),
    }[command]
    with patch(fault, side_effect=OSError('private fault')), patch('alerts.init_from_alerts') as adapter:
        code, result = call(ctx, handler, {**body, 'revision': 1})
    assert code == 500 and 'private fault' not in json.dumps(result)
    adapter.assert_not_called()
    assert Path(ctx.config_path).read_bytes() == raw
    assert get_config_service(ctx).snapshot() == previous
    assert ctx.shared_config['_force_resolve_queue'] is queue
    assert decode(['1.2.3.4'], 'durable') == ['1.2.3.4']
    assert list(tmp_path.glob('.tracedns-*')) == []


@pytest.mark.parametrize('kind,key,factory,decode', [
    ('TXT', 'custom_decoders', 'txt_decoder.create_custom_decoder', txt_decoder.decode_txt_hidden_ips),
    ('A', 'custom_a_decoders', 'a_decoder.create_custom_a_decoder', a_decoder.decode_a_hidden_ips),
])
@pytest.mark.parametrize('steps', [[{'op': 'invalid'}], [{'op': 'regex', 'pattern': '(a+)+$'}], 'factory_failure'])
def test_compilation_failure_preserves_callable_and_file(tmp_path, kind, key, factory, decode, steps):
    ctx = context(domains=[])
    ctx.config_path = str(tmp_path / 'config.json')
    data = {'name': 'compile', 'decoder_type': kind, 'steps': [{'op': 'ascii'}], 'revision': 0}
    assert call(ctx, handle_decoders_custom_post, data)[0] == 200
    raw = Path(ctx.config_path).read_bytes()
    if steps == 'factory_failure':
        with patch(factory, side_effect=RuntimeError('private compiler error')):
            result = call(ctx, handle_decoders_custom_put, {**data, 'revision': 1})
    else:
        result = call(ctx, handle_decoders_custom_put, {**data, 'revision': 1, 'steps': steps})
    assert result[0] == 400
    assert Path(ctx.config_path).read_bytes() == raw
    assert decode(['1.2.3.4'], 'compile') == ['1.2.3.4']


def test_three_context_writers_have_one_cas_winner(tmp_path):
    contexts = [context(domains=[], config_revision=7) for _ in range(3)]
    shared, lock = contexts[0].shared_config, contexts[0].config_lock
    for ctx in contexts:
        ctx.shared_config, ctx.config_lock, ctx.config_path = shared, lock, str(tmp_path / 'config.json')
    barrier = threading.Barrier(3)
    results = []
    commands = [(handle_config_post, {'interval': 22}), (handle_settings_post, {'alerts': {}}),
                (handle_decoders_custom_post, {'name': 'race', 'steps': [{'op': 'ascii'}]})]

    def write(ctx, fn, data):
        barrier.wait(2)
        results.append(call(ctx, fn, {'revision': 7, **data}))

    with patch('alerts.init_from_alerts'):
        threads = [threading.Thread(target=write, args=(ctx, fn, data)) for ctx, (fn, data) in zip(contexts, commands)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(3)
    assert sorted(code for code, _ in results) == [200, 409, 409]
    assert all(result['revision'] == 8 for _, result in results)
    assert all(ctx.config_service is contexts[0].config_service for ctx in contexts)
    assert json.loads(Path(contexts[0].config_path).read_text()) == contexts[0].config_service.snapshot()


def test_restart_from_complete_file_and_detached_results(tmp_path):
    ctx = context(domains=[], unknown_public={'nested': [1]}, _runtime_object=object())
    ctx.config_path = str(tmp_path / 'config.json')
    service = get_config_service(ctx)
    steps = [{'op': 'ascii'}]
    saved = service.commit('decoder_create', {'name': 'restart', 'steps': steps}, expected_revision=0)
    steps[0]['op'] = 'base64'
    saved['config']['custom_decoders'][0]['steps'][0]['op'] = 'base64'
    saved['catalog']['custom'][0]['steps'][0]['op'] = 'base64'
    stored = json.loads(Path(ctx.config_path).read_text())
    assert not any(k.startswith('_') for k in stored)
    assert stored['unknown_public'] == {'nested': [1]}
    restarted = ConfigService(stored, threading.Lock(), ctx.config_path)
    restarted.initialize_decoders()
    assert restarted.snapshot() == service.snapshot()
    assert txt_decoder.decode_txt_hidden_ips(['1.2.3.4'], 'restart') == ['1.2.3.4']
    bad = copy.deepcopy(stored)
    bad['custom_decoders'][0]['steps'] = [{'op': 'invalid'}]
    with pytest.raises(ConfigError):
        ConfigService(bad, threading.Lock(), '').initialize_decoders()
    assert txt_decoder.decode_txt_hidden_ips(['1.2.3.4'], 'restart') == ['1.2.3.4']


def test_repository_prevalidation_and_committed_cleanup_warning(tmp_path):
    from types import SimpleNamespace
    ctx = context(domains=[])
    ctx.config_path = str(tmp_path / 'config.json')
    events = []

    def validate(candidate):
        assert not Path(ctx.config_path).exists()
        events.append('validate')
        if candidate['domains']:
            raise ValueError('private pending path')

    def configure(candidate, removed):
        assert json.loads(Path(ctx.config_path).read_text()) == candidate
        events.append('configure')
        return ['history_cleanup_pending']

    ctx.state_repository = SimpleNamespace(validate_config=validate, configure=configure)
    code, result = call(ctx, handle_config_post, {'revision': 0, 'domains': ['blocked.example']})
    assert code == 400 and 'private pending path' not in result['error']
    assert events == ['validate']
    assert not Path(ctx.config_path).exists()
    code, result = call(ctx, handle_config_post, {'revision': 0, 'domains': []})
    assert code == 200 and result['warnings'] == ['history_cleanup_pending']
    assert result['revision'] == 1 and events == ['validate', 'validate', 'configure']


def test_committed_response_is_not_reread_after_another_writer():
    ctx = context(domains=[])
    first_ready, second_done = threading.Event(), threading.Event()
    responses = []
    import http_api.config_post as config_post

    def send(handler, result, code=200):
        if result.get('revision') == 1:
            first_ready.set()
            assert second_done.wait(2)
        responses.append(result)

    with patch.object(config_post, 'send_json', side_effect=send):
        from tests.test_config_revision import request
        thread = threading.Thread(target=lambda: handle_config_post(ctx, request({'revision': 0, 'interval': 10})))
        thread.start()
        assert first_ready.wait(2)
        handle_config_post(ctx, request({'revision': 1, 'interval': 20}))
        second_done.set()
        thread.join(2)
    assert {(r['revision'], r['config']['interval']) for r in responses} == {(1, 10), (2, 20)}



def test_scheduler_notification_uses_existing_nonreentrant_config_lock():
    ctx = context(domains=[])
    ctx.config_lock = threading.Lock()
    condition = threading.Condition(ctx.config_lock)
    ctx.shared_config['_monitor_condition'] = condition
    with patch.object(condition, 'notify_all', wraps=condition.notify_all) as notify:
        code, result = call(ctx, handle_config_post, {'revision': 0, 'interval': 10})
    assert code == 200 and result['revision'] == 1
    notify.assert_called_once_with()



def test_nested_domain_command_input_cannot_mutate_committed_configuration():
    ctx = context(domains=[])
    service = get_config_service(ctx)
    options = {'nested': {'values': [1]}}
    command = {'domains': [{'name': 'local.eth', 'type': 'ENS', 'ens_options': options}]}
    result = service.commit('config', command, expected_revision=0)
    options['nested']['values'].append(2)
    assert service.snapshot()['domains'][0]['ens_options'] == {'nested': {'values': [1]}}
    result['config']['domains'][0]['ens_options']['nested']['values'].append(3)
    assert service.snapshot()['domains'][0]['ens_options'] == {'nested': {'values': [1]}}
