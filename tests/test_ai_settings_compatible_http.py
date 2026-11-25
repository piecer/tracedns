"""Actual authenticated settings -> compatible transport -> job, synthetic peers."""
import json

import jsonschema
import pytest

from http_api.local_ai_schema import JOB_SCHEMA
from test_ai_settings_api import app as app_fixture
from test_local_ai_application import wait_job
from test_local_ai_openai_provider import (
    KEY, envelope, no_proxy as no_proxy, peer, response, settings,
)

app = app_fixture


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
@pytest.mark.parametrize('upstream,expected', [
    (200, None), (400, 'provider_request_rejected'), (401, 'provider_auth_failed'),
    (429, 'provider_rate_limited'), (500, 'provider_failed'),
])
def test_real_settings_to_compatible_job_and_durable_outcome(app, prefix, upstream, expected):
    def answer(sock, stop):
        body = json.loads(requests[0]['body'])
        assert [m['role'] for m in body['messages']] == ['system', 'user']
        assert body['stream'] is False and body['n'] == 1 and body['store'] is False
        assert body['response_format'] == {'type': 'json_object'}
        schema = json.loads(body['messages'][0]['content'].split('\nRequired JSON Schema: ', 1)[1])
        props = schema['properties']
        value = {key: props[key]['const'] for key in ('version', 'kind', 'language', 'snapshot_digest')}
        value.update(summary=[{'text': 'Inspect retained evidence.', 'evidence_ids': ['e1']}],
                     counterpoints=[], limitations=[], next_checks=[])
        completion = envelope(json.dumps(value))
        completion['choices'][0]['message'].update(annotations=[], audio=None, tool_calls=[], function_call=None)
        sock.sendall(response(completion if upstream == 200 else b'SYNTHETIC upstream body', upstream))

    owner = app.handler.local_ai
    assert owner._worker is None
    with peer(answer) as (url, requests):
        code, before = app.client.call('GET', prefix + '/ai/settings')
        assert code == 200
        config = settings(url + '/v1', token_limit_field='max_tokens')
        code, saved = app.client.call('POST', prefix + '/ai/settings',
                                      {'revision': before['revision'], 'settings': config})
        assert code == 200, saved
        assert saved['runtime'] == {'applied': True, 'state': 'ready'}
        assert saved['settings']['configured'] == {'api_key': True}
        assert 'api_key' not in saved['settings'] and KEY not in json.dumps(saved)
        assert requests == [] and app.native_requests == [], 'Save must not contact either provider'
        assert app.handler.local_ai is owner and app.core.service.local_ai is owner
        workers = (owner._worker, owner._maintenance_worker)
        assert owner._resolver is not None
        code, job = app.client.call('POST', prefix + '/ai/jobs', {'kind': 'delivery', 'language': 'en'})
        assert code == 202, job
        result = wait_job(app.client, prefix + '/ai/jobs/' + job['job_id'])
        assert result['audit_status'] == 'success' and result['error'] == expected
        assert result['status'] == ('completed' if expected is None else 'failed')
        jsonschema.Draft202012Validator(JOB_SCHEMA).validate(result)
        assert len(requests) == 1 and app.native_requests == []
        assert requests[0]['headers']['Authorization'] == 'Bearer ' + KEY
        packet = json.loads(requests[0]['body'])
        assert packet['max_tokens'] == 512 and 'max_completion_tokens' not in packet
        assert KEY not in requests[0]['body'].decode() and KEY not in json.dumps(result)
        state = app.store.llm_provider_state()
        assert state['blocked'] is (upstream == 500)
        if upstream == 200:
            assert state['outcome'] == 'settled'
            metadata = result['result']['model']
            assert metadata['provider'] == 'openai_compatible'
            assert metadata['requested_model'] == config['model']
            assert metadata['reported_model'] == 'reported/alias-2026'
            assert 'model_digest' not in metadata
        else:
            assert result['result'] is None
            if upstream != 500:
                assert state['outcome'] == 'http_rejected'
        assert app.client.call('GET', '/auth/me')[0] == 200, 'provider auth failure is not logout'
        assert KEY not in json.dumps(app.client.call('GET', prefix + '/ai/settings')[1])
        assert KEY not in json.dumps(app.store.audit_list(limit=1000))
        code, disabled = app.client.call('POST', prefix + '/ai/settings',
                                         {'revision': saved['revision'], 'settings': {'enabled': False}})
        assert code == 200, disabled
        assert app.store.llm_provider_state()['blocked'] is (upstream == 500)
        assert (owner._worker, owner._maintenance_worker) == workers
        assert len(requests) == 1
