"""Real HTTP -> service -> engine -> owned native peer, not real-model acceptance."""
import json
import secrets
import threading
import time
from types import SimpleNamespace

import pytest

from test_http_auth_integration import Client
from test_local_ai_provider import DIGEST, MODEL, envelope, http_response, peer
from test_stage3_core_runtime import app_factory


@pytest.fixture
def application(tmp_path, monkeypatch):
    from http_server import ThreadingHTTPServer, make_handler
    from security.store import SecurityStore
    from security import http as security_http
    import sys
    import traceback
    unexpected = []
    log_error = security_http.LOGGER.error
    def observe_error(*args, **kwargs):
        error = sys.exc_info()[1]
        if error is not None:
            unexpected.append((type(error).__name__, [
                (frame.f_code.co_name, line) for frame, line in traceback.walk_tb(error.__traceback__)]))
        return log_error(*args, **kwargs)
    monkeypatch.setattr(security_http.LOGGER, 'error', observe_error)

    def reply(sock, stop):
        request = json.loads(native_requests[-1]['body'])
        schema = request['format']
        props = schema.get('oneOf', [schema])[0]['properties']
        value = {key: props[key]['const'] for key in ('version', 'kind', 'language', 'snapshot_digest')}
        if value['kind'] == 'decoder_suggest':
            value.update(candidates=[{'steps': [{'op': 'base64'}, {'op': 'ascii'}]}],
                         insufficient_reason=None)
        else:
            value.update(summary=[{'text': 'Inspect the retained evidence, not attribution.',
                                   'evidence_ids': ['e1']}], counterpoints=[], limitations=[], next_checks=[])
        sock.sendall(http_response(envelope(json.dumps(value))))

    with peer(chat=reply) as (origin, native_requests, native_routes):
        settings = {'enabled': True, 'origin': origin, 'model': MODEL, 'model_digest': DIGEST}
        config = {'domains': [], 'servers': [], 'interval': 60, 'config_revision': 0,
                  'local_ai': settings}
        core = app_factory(tmp_path / 'ledger', config=config)
        server = thread = None
        try:
            store = SecurityStore(tmp_path / 'security' / 'db.sqlite', create=True)
            password = secrets.token_urlsafe(24)
            store.bootstrap('fixture', password)
            handler = make_handler(config, core.cfg.lock, '', str(tmp_path / 'history'), {}, {},
                                   security_store=store, insecure_http=True,
                                   state_repository=core.repo, config_service=core.service,
                                   delivery_diagnostics=core.delivery.store.diagnostics_snapshot,
                                   delivery_health=core.delivery.health_snapshot)
            assert native_requests == [], 'handler construction cannot contact the model'
            server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            client = Client(server.server_port)
            assert client.login('fixture', password)[0] == 200
            assert native_requests == [], 'startup and authentication cannot contact the model'
            yield SimpleNamespace(client=client, handler=handler, store=store, config=config,
                                  core=core, native_requests=native_requests, native_routes=native_routes)
            assert not unexpected, unexpected
        finally:
            try:
                if server is not None:
                    server.shutdown()
                    server.server_close()
            finally:
                if thread is not None:
                    thread.join(5)
                    assert not thread.is_alive()
                core.delivery.stop()


def wait_job(client, path):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        status, value = client.call('GET', path)
        assert status == 200, value
        if value['status'] in ('completed', 'failed', 'cancelled') and value.get('audit_status') != 'pending':
            return value
        time.sleep(.01)
    pytest.fail('real HTTP job did not retire within the fixture deadline')


def test_enabled_http_uses_real_cached_producer_service_engine_and_native_adapter(application):
    from jsonschema import Draft202012Validator
    from http_api.local_ai_schema import JOB_SCHEMA, STATUS_SCHEMA

    app = application
    status, state = app.client.call('GET', '/api/v1/ai/status')
    assert status == 200 and state['enabled'] is True
    Draft202012Validator(STATUS_SCHEMA).validate(state)
    assert state['accepting'] is True and app.native_requests == []
    status, admitted = app.client.call('POST', '/api/v1/ai/jobs', {'kind': 'delivery', 'language': 'en'})
    assert status == 202, admitted
    result = wait_job(app.client, '/api/v1/ai/jobs/' + admitted['job_id'])
    Draft202012Validator(JOB_SCHEMA).validate(result)
    assert result['status'] == 'completed' and result['audit_status'] == 'success'
    output = result['result']
    assert output['snapshot']['kind'] == 'delivery'
    assert 'snapshots_not_atomic' in output['snapshot']['warnings']
    assert output['interpretation']['snapshot_digest'] == output['snapshot_digest']
    assert output['model']['model_digest'] == DIGEST
    assert [r['path'] for r in app.native_requests] == ['/api/tags', '/api/chat']
    assert app.store.llm_provider_state()['outcome'] == 'settled'
    events = app.store.audit_list(action='llm.lifecycle')['events']
    assert [e['outcome'] for e in reversed(events)] == ['started', 'completed']


def original_relationship(app, monkeypatch):
    from http_api import relationship_handlers as rh
    from test_local_ai_sources import InlineExecutor
    class SynchronousProducer(InlineExecutor):
        def __init__(self):
            self._processes = {}
        def shutdown(self, **kwargs):
            pass  # No thread/process was created by this inline test executor.
    app.handler.relationship_jobs.executor = SynchronousProducer()
    for name in ('begin_cache_batch', 'end_cache_batch', 'get_vt_runtime_config'):
        monkeypatch.setattr(rh, name, None)
    monkeypatch.setattr(rh, '_load_geoip_reader', lambda path: None)
    monkeypatch.setattr(rh, 'get_ip_report', lambda *a, **k: pytest.fail('unexpected intelligence request'))
    status, admitted = app.client.call('POST', '/ip-relationship-jobs', {
        'ips': ['192.0.2.1', '192.0.2.2'], 'include_vt': False,
        'min_score': 1, 'pair_gate_enabled': False})
    assert status == 202, admitted
    completed = wait_job(app.client, '/ip-relationship-jobs/' + admitted['job_id'] + '?result=1')
    assert completed['status'] == 'completed' and completed['result']['pairs']
    pair = completed['result']['pairs'][0]
    return {'job_id': admitted['job_id'], 'a': pair['a'], 'b': pair['b']}, completed


def test_original_http_relationship_is_stamped_then_only_selected_pair_is_explained(application, monkeypatch):
    app = application
    selector, before = original_relationship(app, monkeypatch)
    assert app.native_requests == []
    status, admitted = app.client.call('POST', '/ai/jobs',
        {'kind': 'relationship_pair', 'language': 'en', 'source': selector})
    assert status == 202, admitted
    result = wait_job(app.client, '/ai/jobs/' + admitted['job_id'])
    assert result['status'] == 'completed' and result['audit_status'] == 'success'
    assert result['result']['snapshot']['kind'] == 'relationship_pair'
    assert result['result']['snapshot']['source']['job_id'] == selector['job_id']
    after = app.client.call('GET', '/ip-relationship-jobs/' + selector['job_id'] + '?result=1')[1]
    assert after == before, 'AI cannot mutate the deterministic producer result'
    assert [r['path'] for r in app.native_requests] == ['/api/tags', '/api/chat']


def test_pending_terminal_audit_remains_discoverable_with_documented_status(application, monkeypatch):
    from http_api.local_ai_schema import STATUS_SCHEMA
    from jsonschema import Draft202012Validator
    app = application
    reached, release = threading.Event(), threading.Event()
    original = app.store.audit_llm_lifecycle
    def gated(*args, **kwargs):
        if kwargs['outcome'] == 'completed':
            reached.set()
            assert release.wait(5), 'test must release the real terminal audit'
        return original(*args, **kwargs)
    monkeypatch.setattr(app.store, 'audit_llm_lifecycle', gated)
    try:
        code, admitted = app.client.call('POST', '/ai/jobs', {'kind': 'delivery', 'language': 'en'})
        assert code == 202 and reached.wait(4)
        code, public = app.client.call('GET', '/ai/status')
        assert code == 200 and public['active_job']['job_id'] == admitted['job_id']
        Draft202012Validator(STATUS_SCHEMA).validate(public)
        code, pending = app.client.call('GET', '/ai/jobs/' + admitted['job_id'])
        assert code == 200 and pending['status'] == 'completed'
        assert pending['audit_status'] == 'pending' and pending['result'] is None
    finally:
        release.set()
    assert wait_job(app.client, '/ai/jobs/' + admitted['job_id'])['audit_status'] == 'success'


@pytest.mark.parametrize('fault', ['capture-unavailable', 'hard-epoch-during-context'])
def test_missing_original_proof_preserves_analysis_but_never_backfills_ai(application, monkeypatch, fault):
    from local_ai import sources
    from local_ai.contracts import AIError
    app = application
    captured = []
    contexts = []
    original_capture = sources.capture_relationship_stamp
    def capture(*args):
        captured.append(True)
        contexts.append(args[0])
        if fault == 'capture-unavailable':
            raise AIError('source_unavailable')
        return original_capture(*args)
    monkeypatch.setattr(sources, 'capture_relationship_stamp', capture)
    gather = app.handler._gather_ip_map
    def gather_after_capture(handler):
        assert captured == [True], 'original proof must precede any context gathering'
        if fault == 'hard-epoch-during-context':
            contexts[0].read_model.invalidate(hard=True)
        return gather(handler)
    monkeypatch.setattr(app.handler, '_gather_ip_map', gather_after_capture)
    selector, original = original_relationship(app, monkeypatch)
    assert original['status'] == 'completed'
    assert app.handler.relationship_jobs.jobs[selector['job_id']]['_ai_source_stamp'] is None
    code, refused = app.client.call('POST', '/ai/jobs',
        {'kind': 'relationship_pair', 'language': 'en', 'source': selector})
    assert code == 409 and refused['code'] == 'source_unavailable'
    assert captured == [True] and app.native_requests == []


@pytest.mark.parametrize('kind', ['TXT', 'A'])
@pytest.mark.parametrize('generate', [False, True])
def test_real_http_decoder_verifies_holdout_without_registration_or_prompt_disclosure(application, kind, generate):
    import base64
    import copy
    app = application
    before_config = copy.deepcopy({k: v for k, v in app.config.items() if not k.startswith('_')})
    code, before_registry = app.client.call('GET', '/decoders/custom')
    assert code == 200
    samples = [{'data': base64.b64encode(ip.encode()).decode(), 'expected_ips': [ip],
                'usage': usage, 'complete_expected': True}
               for ip, usage in [('192.0.2.1', 'example'), ('198.51.100.17', 'validation')]]
    code, admitted = app.client.call('POST', '/ai/jobs', {'kind': 'decoder_suggest', 'language': 'en',
        'decoder_type': kind, 'generate': generate, 'samples': samples})
    assert code == 202, admitted
    result = wait_job(app.client, '/ai/jobs/' + admitted['job_id'])
    assert result['status'] == 'completed' and result['audit_status'] == 'success', result['error']
    output = result['result']
    assert output['catalog']['complete'] is True
    if generate:
        candidate = output['generated']['candidates'][0]
        assert candidate['examples']['results'][0]['matched_ips'] == ['192.0.2.1']
        assert candidate['validation']['results'][0]['matched_ips'] == ['198.51.100.17']
        native = next(r for r in app.native_requests if r['path'] == '/api/chat')
        messages = json.loads(native['body'])['messages']
        assert '198.51.100.17' not in json.dumps(messages)
        assert samples[1]['data'] not in json.dumps(messages)
        assert [r['path'] for r in app.native_requests] == ['/api/tags', '/api/chat']
    else:
        assert output['generated'] is None and output['model'] is None and app.native_requests == []
    assert {k: v for k, v in app.config.items() if not k.startswith('_')} == before_config
    assert app.client.call('GET', '/decoders/custom') == (200, before_registry)
