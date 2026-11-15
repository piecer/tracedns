"""Independent finding B1: typed native failures must survive the real engine."""
import time

import pytest

from local_ai.contracts import AIError, ERROR_STATUS
from local_ai.engine import generate_once
from local_ai.provider import ProviderError
import test_local_ai_application as application_support
from test_local_ai_application import original_relationship, wait_job
from test_local_ai_provider import catalog, http_response

application = application_support.application


@pytest.mark.parametrize('kind', ['delivery', 'decoder_suggest', 'relationship_pair'])
def test_real_http_catalog_drift_preserves_model_unavailable(application, monkeypatch, kind):
    app = application
    wrong = catalog()
    wrong['models'][0]['digest'] = '0' * 64
    app.native_routes['/api/tags'] = http_response(wrong)
    request = {'kind': kind, 'language': 'en'}
    if kind == 'decoder_suggest':
        request.update(decoder_type='TXT', generate=True, samples=[{
            'data': '192.0.2.1', 'expected_ips': ['192.0.2.1'],
            'usage': 'example', 'complete_expected': True}])
    elif kind == 'relationship_pair':
        request['source'], _ = original_relationship(app, monkeypatch)
    code, admitted = app.client.call('POST', '/api/v1/ai/jobs', request)
    assert code == 202
    terminal = wait_job(app.client, '/api/v1/ai/jobs/' + admitted['job_id'])
    assert terminal['status'] == 'failed' and terminal['result'] is None
    assert terminal['audit_status'] == 'success'
    assert [r['path'] for r in app.native_requests] == ['/api/tags']
    assert app.store.llm_provider_state() == {'blocked': False, 'job_id': None, 'outcome': 'absent'}
    assert terminal['error'] == 'model_unavailable'
    events = app.store.audit_list(action='llm.lifecycle')['events']
    assert [(event['outcome'], event['status']) for event in reversed(events)] == [
        ('started', None), ('failed', 503)]


@pytest.mark.parametrize('code', ['invalid_request', 'too_large', 'model_unavailable',
                                 'provider_failed', 'deadline_exceeded'])
def test_engine_preserves_all_closed_native_failure_codes(code):
    def generate(*args):
        raise ProviderError(code, sent=True)
    with pytest.raises(AIError) as caught:
        generate_once(generate, [], {}, time.monotonic() + 10)
    assert caught.value.code == code and caught.value.status == ERROR_STATUS[code]


def test_unknown_callback_prose_remains_fixed_and_nonreflecting():
    def generate(*args):
        raise RuntimeError('SYNTHETIC_PRIVATE_PROVIDER_PROSE')
    with pytest.raises(AIError) as caught:
        generate_once(generate, [], {}, time.monotonic() + 10)
    assert caught.value.code == 'provider_failed'
    assert str(caught.value) == 'provider_failed'
