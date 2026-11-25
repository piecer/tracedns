"""Source-bound authenticated HTTP settings -> real controlled native job.

The peer speaks native HTTP, not a live model. Compatible contract injections
in the lifecycle tests are deliberately NOT compatible transport acceptance.
"""
import json
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from test_http_auth_integration import Client
from test_local_ai_application import wait_job
from test_local_ai_provider import DIGEST, MODEL, envelope, http_response, peer
from test_stage3_core_runtime import app_factory


@pytest.fixture
def app(tmp_path, monkeypatch):
    from http_server import ThreadingHTTPServer, make_handler
    from security.store import SecurityStore

    def reply(sock, stop):
        request = json.loads(requests[-1]['body'])
        schema = request['format']
        props = schema.get('oneOf', [schema])[0]['properties']
        value = {k: props[k]['const'] for k in ('version', 'kind', 'language', 'snapshot_digest')}
        value.update(summary=[{'text': 'Inspect retained evidence.', 'evidence_ids': ['e1']}],
                     counterpoints=[], limitations=[], next_checks=[])
        sock.sendall(http_response(envelope(json.dumps(value))))

    with peer(chat=reply) as (origin, requests, _):
        monkeypatch.setenv('MISP_SIGHTING_BATCH_FILE', str(tmp_path / 'sightings.json'))
        config = {'domains': [], 'servers': [], 'interval': 60, 'config_revision': 0, 'alerts': {}}
        core = app_factory(tmp_path / 'ledger', config=config)
        store = SecurityStore(tmp_path / 'security' / 'auth.db', create=True)
        store.bootstrap('fixture', 'fixture-only-password')
        server = thread = None
        try:
            handler = make_handler(config, core.cfg.lock, core.service.config_path, str(tmp_path / 'history'),
                                   core.current, core.history, security_store=store, insecure_http=True,
                                   state_repository=core.repo, config_service=core.service,
                                   delivery_diagnostics=core.delivery.store.diagnostics_snapshot,
                                   delivery_health=core.delivery.health_snapshot)
            import importlib
            checkout = Path(__file__).resolve().parents[1]
            for name in ('http_server', 'http_api_handlers', 'local_ai.service', 'local_ai.engine',
                         'local_ai.provider_factory', 'local_ai.provider_settings', 'monitor.config_service',
                         'security.http', 'security.store'):
                assert Path(importlib.import_module(name).__file__).resolve() == checkout / (name.replace('.', '/') + '.py')
            server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            client = Client(server.server_port)
            assert client.login('fixture', 'fixture-only-password')[0] == 200
            yield SimpleNamespace(client=client, handler=handler, core=core, store=store, config=config,
                                  native_requests=requests,
                                  native={'enabled': True, 'provider': 'ollama', 'base_url': origin,
                                          'model': MODEL, 'model_digest': DIGEST})
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()
            if thread is not None:
                thread.join(5)
                assert not thread.is_alive()
                assert all(not isinstance(r, dict) or r.get('complete', True) for r in server.background_shutdown)
            core.delivery.stop()


def test_absent_startup_enable_then_real_native_job_same_owner(app):
    import local_ai.service
    assert Path(local_ai.service.__file__).resolve() == Path(__file__).resolve().parents[1] / 'local_ai/service.py'
    owner = app.handler.local_ai
    assert owner is not None, 'disabled startup must retain a live-configurable owner'
    assert owner._worker is None and owner._maintenance_worker is None
    code, loaded = app.client.call('GET', '/ai/settings')
    assert code == 200, loaded
    assert loaded['revision'] == 0
    assert loaded['settings']['enabled'] is False
    assert loaded['runtime'] == {'applied': True, 'state': 'disabled'}
    assert not Path(app.core.service.config_path).exists(), 'GET/startup cannot save'
    code, saved = app.client.call('POST', '/api/v1/ai/settings', {'revision': 0, 'settings': app.native})
    assert code == 200, saved
    assert saved == {'status': 'ok', 'revision': 1,
                     'settings': {**app.native, 'configured': {'api_key': False}},
                     'runtime': {'applied': True, 'state': 'ready'}, 'warnings': []}
    assert app.handler.local_ai is owner and app.core.service.local_ai is owner
    workers = (owner._worker, owner._maintenance_worker)
    assert all(t.is_alive() for t in workers)
    assert app.native_requests == [], 'Save is not discovery or inference'
    disk = json.loads(Path(app.core.service.config_path).read_text())
    assert disk['local_ai'] == app.native and disk['config_revision'] == 1
    assert Path(app.core.service.config_path).stat().st_mode & 0o777 == 0o600
    assert 'local_ai' not in app.client.call('GET', '/config')[1]
    code, admitted = app.client.call('POST', '/ai/jobs', {'kind': 'delivery', 'language': 'en'})
    assert code == 202, admitted
    result = wait_job(app.client, '/ai/jobs/' + admitted['job_id'])
    assert result['status'] == 'completed' and result['audit_status'] == 'success'
    assert result['result']['model']['model_digest'] == DIGEST
    assert [r['path'] for r in app.native_requests] == ['/api/tags', '/api/chat']
    assert app.store.llm_provider_state()['outcome'] == 'settled'
    assert (owner._worker, owner._maintenance_worker) == workers


@pytest.mark.parametrize('body', [
    {}, {'revision': True, 'settings': {'enabled': False}},
    {'revision': -1, 'settings': {'enabled': False}},
    {'revision': 1.0, 'settings': {'enabled': False}},
    {'revision': '0', 'settings': {'enabled': False}},
    {'revision': 9007199254740992, 'settings': {'enabled': False}},
    {'revision': 0, 'settings': {}}, {'revision': 0, 'settings': None},
    {'revision': 0, 'settings': {'enabled': False}, 'extra': 'private-canary'},
    {'revision': 0, 'settings': {'enabled': False}, 'clear_fields': ['api_key', 'api_key']},
    {'revision': 0, 'settings': {'origin': 'http://127.0.0.1:9'}},
    {'revision': 0, 'settings': {'configured': {'api_key': True}}},
])
def test_closed_request_and_revision_are_refused_without_save(app, body):
    code, response = app.client.call('POST', '/ai/settings', body)
    assert code == 400 and response['code'] == 'invalid_request', response
    assert app.config['config_revision'] == 0
    assert not Path(app.core.service.config_path).exists()
    assert not app.native_requests and app.handler.local_ai._worker is None


def test_malformed_stored_revision_is_not_reflected_in_conflict(app):
    app.config['config_revision'] = 'fixture-only-private-revision'
    code, response = app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': {'enabled': False}})
    assert code == 503 and response['code'] == 'config_revision_exhausted'
    assert 'fixture-only-private-revision' not in json.dumps(response)
    assert not Path(app.core.service.config_path).exists()


def test_no_storage_and_exhaustion_are_fail_closed(app):
    path = app.core.service.config_path
    app.core.service.config_path = ''
    code, response = app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': app.native})
    assert (code, response['code']) == (503, 'config_storage_unavailable')
    assert app.config['config_revision'] == 0 and not app.native_requests
    app.core.service.config_path = path
    app.config['config_revision'] = 9007199254740991
    code, response = app.client.call('POST', '/ai/settings', {
        'revision': 9007199254740991, 'settings': app.native})
    assert (code, response['code']) == (503, 'config_revision_exhausted')
    assert not Path(path).exists()


def test_precommit_write_fault_preserves_config_and_runtime(app, monkeypatch):
    import config_manager
    def fail(*args):
        raise OSError('PRIVATE_WRITE_EXCEPTION')
    monkeypatch.setattr(config_manager, 'write_config', fail)
    code, response = app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': app.native})
    assert (code, response['code']) == (500, 'config_save_failed')
    assert 'PRIVATE' not in json.dumps(response)
    assert app.config['config_revision'] == 0
    assert app.handler.local_ai.runtime() == {'applied': True, 'state': 'disabled'}
    assert not Path(app.core.service.config_path).exists()


def test_postcommit_apply_fault_is_committed_unavailable_not_rollback(app, monkeypatch):
    def fail(*args):
        raise OSError('PRIVATE_SETUP_EXCEPTION')
    monkeypatch.setattr(app.handler.local_ai, 'apply_configuration', fail)
    code, response = app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': app.native})
    assert code == 200, response
    assert response['revision'] == 1 and response['runtime'] == {'applied': False, 'state': 'unavailable'}
    assert response['warnings'] == ['ai_runtime_apply_failed']
    assert json.loads(Path(app.core.service.config_path).read_text())['local_ai'] == app.native
    assert app.client.call('GET', '/ai/settings')[1]['runtime'] == response['runtime']
    assert not app.native_requests


@pytest.mark.parametrize('owner_name,method', [('read_model', 'invalidate'), ('state_repository', 'configure'),
                                              ('delivery_runtime', 'configuration_committed'),
                                              ('delivery_runtime', 'apply_configuration')])
def test_postcommit_effect_fault_keeps_truthful_persisted_read_and_fences_ai(app, monkeypatch, owner_name, method):
    target = getattr(app.core.service, owner_name)
    def fail(*args, **kwargs):
        raise OSError('PRIVATE_EFFECT_PROSE')
    monkeypatch.setattr(target, method, fail)
    code, body = app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': app.native})
    assert code == 200, body
    assert body['revision'] == 1
    assert body['runtime'] == {'applied': False, 'state': 'unavailable'}
    assert body['warnings'] == ['ai_runtime_apply_failed']
    assert app.config['config_revision'] == 1
    assert json.loads(Path(app.core.service.config_path).read_text())['local_ai'] == app.native
    status, loaded = app.client.call('GET', '/ai/settings')
    assert status == 200 and loaded['revision'] == 1 and loaded['runtime'] == body['runtime']
    assert not app.native_requests
    assert not app.handler.local_ai.source_admission_enabled()


def test_rotated_secret_cannot_escape_delayed_committed_receipt(app, monkeypatch):
    from test_local_ai_live_settings import thread_call
    entered, release = threading.Event(), threading.Event()
    original = app.core.service.commit
    def commit(*args, **kwargs):
        result = original(*args, **kwargs)
        if args[0] == 'ai_settings' and kwargs['expected_revision'] == 0:
            entered.set()
            assert release.wait(4)
        return result
    monkeypatch.setattr(app.core.service, 'commit', commit)
    secret = 'fixture-prior-secret-canary'
    patch = {'enabled': False, 'provider': 'openai_compatible', 'base_url': 'https://example.com/v1',
             'model': secret, 'api_key': secret}
    thread, first = thread_call(lambda: app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': patch}))
    try:
        assert entered.wait(2)
        assert app.client.call('POST', '/ai/settings', {
            'revision': 1, 'settings': {'model': 'fixture', 'api_key': 'fixture-new-key'}})[0] == 200
    finally:
        release.set()
        thread.join(4)
    assert first.error is None
    assert first.value[0] == 503 and secret not in json.dumps(first.value)
    assert app.client.call('GET', '/ai/settings')[1]['revision'] == 2


def test_get_runtime_and_config_snapshot_cannot_cross_save(app, monkeypatch):
    from test_local_ai_live_settings import thread_call
    entered, release = threading.Event(), threading.Event()
    original = app.handler.local_ai.runtime
    def get():
        return app.client.call('GET', '/ai/settings')
    # The runtime callback is in a server-owned handler; gate only its first call.
    first = [True]
    def gate():
        if first[0]:
            first[0] = False
            entered.set()
            assert release.wait(4)
        return original()
    monkeypatch.setattr(app.handler.local_ai, 'runtime', gate)
    thread, loaded = thread_call(get)
    try:
        assert entered.wait(2)
        assert app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': app.native})[0] == 200
    finally:
        release.set()
        thread.join(4)
    assert loaded.error is None
    assert loaded.value[0] == 409 and loaded.value[1]['code'] == 'source_revoked'


def test_dedicated_schema_and_secret_projection_contract(app):
    from jsonschema import Draft202012Validator
    from http_api.ai_settings_schema import GET_SCHEMA, POST_SCHEMA, REQUEST_SCHEMA, ERROR_SCHEMA
    code, loaded = app.client.call('GET', '/ai/settings')
    assert code == 200
    Draft202012Validator(GET_SCHEMA).validate(loaded)
    request = {'revision': 0, 'settings': {'enabled': False}}
    Draft202012Validator(REQUEST_SCHEMA).validate(request)
    code, saved = app.client.call('POST', '/ai/settings', request)
    assert code == 200
    Draft202012Validator(POST_SCHEMA).validate(saved)
    code, conflict = app.client.call('POST', '/ai/settings', request)
    assert code == 409
    Draft202012Validator(ERROR_SCHEMA).validate(conflict)
    for invalid in ({**saved, 'unexpected': 'x'}, {**saved, 'warnings': ['ai_runtime_apply_failed'] * 2},
                    {**saved, 'runtime': {'applied': True, 'state': 'connected'}}):
        assert not Draft202012Validator(POST_SCHEMA).is_valid(invalid)


@pytest.mark.parametrize('alias', ['/ai/settings', '/api/v1/ai/settings'])
def test_admin_only_routes_preserve_csrf_origin_and_no_patch(app, alias):
    anonymous = Client(app.client.port)
    assert anonymous.call('GET', alias)[0] == 401
    assert anonymous.call('POST', alias, {'revision': 0, 'settings': app.native})[0] == 401
    assert app.client.call('POST', alias, {'revision': 0, 'settings': app.native}, csrf=False)[0] == 403
    assert app.client.call('POST', alias, {'revision': 0, 'settings': app.native},
                           extra_headers={'Origin': 'http://invalid.example'})[0] == 403
    assert app.client.call('PATCH', alias, {'revision': 0, 'settings': app.native})[0] in (403, 405)
    assert app.client.call('GET', alias + '?extra=private')[0] == 400
    for role in ('operator', 'viewer'):
        user = role + 'fixture'
        assert app.client.call('POST', '/admin/users', {
            'username': user, 'password': 'fixture-role-password', 'role': role})[0] == 201
        client = Client(app.client.port)
        assert client.login(user, 'fixture-role-password')[0] == 200
        assert client.call('POST', '/auth/password', {
            'current_password': 'fixture-role-password', 'new_password': 'changed-fixture-role-password'})[0] == 200
        assert client.login(user, 'changed-fixture-role-password')[0] == 200
        assert client.call('GET', alias)[0] == 403
        assert client.call('POST', alias, {'revision': 0, 'settings': app.native})[0] == 403
    assert app.config['config_revision'] == 0 and not app.native_requests


def test_settings_json_content_type_is_required(app):
    code, response = app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': app.native},
                                      extra_headers={'Content-Type': 'text/plain'})
    assert code == 400 and response['code'] == 'invalid_request'
    assert app.config['config_revision'] == 0


@pytest.mark.parametrize('collision', ['model', 'base_url', 'protocol'])
def test_public_secret_collision_fails_closed_without_reflection(app, collision):
    secret = 'fixture-secret-canary'
    patch = {'provider': 'openai_compatible', 'enabled': False, 'base_url': 'https://example.com/v1',
             'model': 'fixture', 'api_key': secret}
    if collision == 'protocol':
        patch['api_key'] = secret = 'disabled'
    else:
        patch[collision] = secret if collision == 'model' else 'https://example.com/' + secret
    status, response = app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': patch})
    assert status == 503 and response['code'] == 'privacy_unavailable'
    assert secret not in json.dumps(response)
    status, response = app.client.call('GET', '/ai/settings')
    assert status == 503 and secret not in json.dumps(response)
    assert secret not in json.dumps(app.client.call('GET', '/admin/audit'))


def test_endpoint_bound_secret_keep_clear_and_replacement_use_private_candidate(app):
    patch = {'provider': 'openai_compatible', 'enabled': False, 'base_url': 'https://example.com/v1',
             'model': 'fixture', 'api_key': 'fixture-secret-A'}
    assert app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': patch})[0] == 200
    for blank in ('', '   '):
        revision = app.config['config_revision']
        assert app.client.call('POST', '/ai/settings', {
            'revision': revision, 'settings': {'model': 'fixture2', 'api_key': blank}})[0] == 200
        assert app.config['local_ai']['api_key'] == 'fixture-secret-A'
    revision = app.config['config_revision']
    code, response = app.client.call('POST', '/ai/settings', {
        'revision': revision, 'settings': {'base_url': 'https://example.org/v1'}})
    assert code == 400 and response['code'] == 'invalid_request'
    assert app.config['config_revision'] == revision
    assert app.client.call('POST', '/ai/settings', {
        'revision': revision, 'settings': {'base_url': 'https://example.org/v1', 'api_key': 'fixture-secret-B'}})[0] == 200
    assert app.config['local_ai']['api_key'] == 'fixture-secret-B'
    assert app.client.call('POST', '/ai/settings', {
        'revision': revision + 1, 'settings': {'enabled': False}, 'clear_fields': ['api_key']})[0] == 200
    assert 'api_key' not in app.config['local_ai']
    assert app.client.call('GET', '/ai/settings')[1]['settings']['configured'] == {'api_key': False}
    assert not app.native_requests


def test_enabling_stamps_only_new_original_relationship_producers(app, monkeypatch):
    from test_local_ai_application import original_relationship
    old_selector, _ = original_relationship(app, monkeypatch)
    assert app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': app.native})[0] == 200
    code, old = app.client.call('POST', '/ai/jobs', {
        'kind': 'relationship_pair', 'language': 'en', 'source': old_selector})
    assert code == 409 and old['code'] == 'source_unavailable'  # Never stamped, not a revoked lease.
    new_selector, _ = original_relationship(app, monkeypatch)
    code, job = app.client.call('POST', '/ai/jobs', {
        'kind': 'relationship_pair', 'language': 'en', 'source': new_selector})
    assert code == 202, job
    assert wait_job(app.client, '/ai/jobs/' + job['job_id'])['status'] == 'completed'
    assert [r['path'] for r in app.native_requests] == ['/api/tags', '/api/chat']


def test_simultaneous_alias_saves_have_one_global_cas_winner(app):
    from test_local_ai_live_settings import thread_call
    barrier = threading.Barrier(2)
    def post(alias, model):
        barrier.wait(3)
        return app.client.call('POST', alias, {'revision': 0, 'settings': {'provider': 'ollama', 'model': model}})
    a, first = thread_call(lambda: post('/ai/settings', 'fixture:first'))
    b, second = thread_call(lambda: post('/api/v1/ai/settings', 'fixture:second'))
    a.join(4)
    b.join(4)
    assert not a.is_alive() and not b.is_alive() and first.error is None and second.error is None
    assert sorted([first.value[0], second.value[0]]) == [200, 409]
    winner = first.value if first.value[0] == 200 else second.value
    assert winner[1]['revision'] == app.config['config_revision'] == 1
    assert app.config['local_ai']['model'] == winner[1]['settings']['model']
    assert not app.native_requests


def test_global_cas_rejects_stale_ai_and_alert_drafts(app):
    assert app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': {'enabled': False}})[0] == 200
    code, response = app.client.call('POST', '/api/v1/ai/settings', {'revision': 0, 'settings': app.native})
    assert code == 409 and response['revision'] == 1
    assert response['code'] == 'config_revision_conflict'
    assert app.client.call('POST', '/settings', {'revision': 0, 'alerts': {}})[0] == 409
    assert app.client.call('POST', '/config', {'revision': 1, 'interval': 61})[0] == 200
    assert app.client.call('POST', '/ai/settings', {'revision': 1, 'settings': app.native})[0] == 409
    assert not app.native_requests
