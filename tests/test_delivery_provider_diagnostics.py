"""Safe provider metadata: no provider text is part of this contract."""
import importlib
import importlib.util
import json

import requests

import pytest

from monitor.delivery_adapters import result
from monitor.delivery_types import provider_result


DEFAULT = {
    'operation': 'unknown', 'http_status': None, 'response_bytes': None,
    'response_limit': None, 'attribute_count': None, 'attribute_limit': None,
    'tls_kind': None, 'tls_verify': None,
}


def test_normalize_diagnostic_default_is_exact_and_fresh():
    assert importlib.util.find_spec('monitor.delivery_diagnostics'), 'diagnostic normalizer missing'
    module = importlib.import_module('monitor.delivery_diagnostics')
    first = module.normalize_diagnostic()
    assert first == DEFAULT
    first['operation'] = 'teams_send'
    assert module.normalize_diagnostic() == DEFAULT
    assert module.normalize_diagnostic(None) == DEFAULT


def test_optional_diagnostic_preserves_legacy_and_safe_ack():
    from monitor.delivery_diagnostics import normalize_diagnostic
    legacy = result('acked', calls=1)
    assert len(legacy) == 6
    assert provider_result(legacy) == legacy
    detail = dict(DEFAULT, operation='misp_read', http_status=200,
                  response_bytes=42, response_limit=2097152, tls_verify=True)
    assert normalize_diagnostic(detail) == detail
    accepted = provider_result(dict(legacy, diagnostic=detail))
    assert accepted['state'] == 'acked'
    assert accepted['diagnostic'] == detail
    assert accepted['diagnostic'] is not detail


@pytest.mark.parametrize('invalid', [
    None, [], 'SECRET', {}, dict(DEFAULT, extra='SECRET'),
    dict(DEFAULT, operation='https://SECRET'), dict(DEFAULT, operation=[]),
    dict(DEFAULT, http_status=True), dict(DEFAULT, http_status=600),
    dict(DEFAULT, http_status=99), dict(DEFAULT, http_status=200.0),
    dict(DEFAULT, response_bytes=-1), dict(DEFAULT, response_limit=2**63),
    dict(DEFAULT, attribute_count=True), dict(DEFAULT, attribute_limit='SECRET'),
    dict(DEFAULT, tls_kind='SECRET'), dict(DEFAULT, tls_kind=[]),
    dict(DEFAULT, tls_verify=1),
])
def test_invalid_metadata_cannot_authorize_ack_or_leak(invalid):
    from monitor.delivery_diagnostics import normalize_diagnostic
    assert normalize_diagnostic(invalid) == DEFAULT
    outcome = provider_result(dict(result('acked', calls=1), diagnostic=invalid))
    assert outcome['state'] == 'failed'
    assert outcome['reason'] == 'invalid_payload'
    assert 'SECRET' not in repr(outcome)
    assert set(outcome) <= set(result('failed')) | {'diagnostic'}


@pytest.mark.parametrize('value', [0, 2**53, 2**63 - 1])
def test_exact_counter_boundaries_are_retained(value):
    from monitor.delivery_diagnostics import normalize_diagnostic
    detail = dict(DEFAULT, response_bytes=value, response_limit=value,
                  attribute_count=value, attribute_limit=value)
    assert normalize_diagnostic(detail) == detail
    assert provider_result(dict(result('acked'), diagnostic=detail))['state'] == 'acked'


class Response:
    def __init__(self, body=None, *, status=200, raw=None, headers=None):
        self.status_code = status
        self.headers = headers or {}
        self.raw = json.dumps(body).encode() if raw is None else raw
        self.closed = False
        self.reads = 0

    def iter_content(self, chunk_size):
        for start in range(0, len(self.raw), chunk_size):
            self.reads += 1
            yield self.raw[start:start + chunk_size]

    def close(self):
        self.closed = True


class Transport:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def configured(transport, channel='teams'):
    from monitor.delivery_adapters import DestinationRegistry
    registry = DestinationRegistry(b'k' * 32, transport=transport)
    registry.apply({'teams_webhook': 'https://teams.invalid/SECRET',
                    'misp_url': 'https://misp.invalid/SECRET', 'api_key': 'SECRET',
                    'push_event_id': 12, 'misp_remove_on_absent': True}, revision=1)
    binding = registry.descriptors()[channel]['binding_id']
    adapter = registry.capture(channel, binding, 'Added')
    claim = {'claim_id': 'c', 'attempt_token': 't', 'channel': channel,
             'binding_id': binding, 'action': 'Added', 'attempt': 1,
             'provider_calls': 0, 'progress': {}, 'observation_hook_consumed': False,
             'payload': {'entries': [['1.2.3.4', 'label', 'A']],
                         'body': {'title': 'fixed', 'text': 'fixed'}}}
    return adapter, claim


@pytest.mark.parametrize('status,state,reason,observed', [
    (200, 'acked', None, 6), (204, 'acked', None, 6),
    (302, 'failed', 'provider_http', 0), (400, 'failed', 'provider_http', 0),
    (401, 'blocked', 'provider_auth', 0), (403, 'blocked', 'provider_auth', 0),
    (429, 'retry', 'provider_transient', 0), (500, 'retry', 'provider_transient', 0),
    (True, 'retry', 'provider_protocol', 0), (999, 'failed', 'provider_http', 0),
])
def test_teams_http_diagnostic_preserves_classification_and_read_budget(status, state, reason, observed):
    response = Response(status=status, raw=b'SECRET', headers={'Retry-After': '999999'})
    transport = Transport(response)
    adapter, claim = configured(transport)
    outcome = adapter.execute_step(claim)
    assert (outcome['state'], outcome['reason']) == (state, reason)
    expected_status = status if type(status) is int and 100 <= status <= 599 else None
    assert outcome.get('diagnostic') == dict(
        DEFAULT, operation='teams_send', http_status=expected_status,
        response_bytes=observed, response_limit=2097152, tls_verify=True)
    assert provider_result(outcome)['state'] == state
    assert 'SECRET' not in json.dumps(outcome)
    assert response.closed
    assert response.reads == (1 if observed else 0)
    assert len(transport.calls) == 1
    kwargs = transport.calls[0][2]
    assert kwargs['verify'] is True
    assert kwargs['stream'] is True and kwargs['allow_redirects'] is False
    assert kwargs['timeout'] == (3, 10)
    if status in (429, 500):
        assert outcome['retry_after'] == 3600


def test_rejected_body_records_first_excess_chunk_without_draining(monkeypatch):
    from monitor import delivery_adapters
    monkeypatch.setattr(delivery_adapters, 'MAX_RESPONSE_BYTES', 65536)
    response = Response(raw=b'x' * 200000)
    adapter, claim = configured(Transport(response))
    outcome = adapter.execute_step(claim)
    assert outcome['state'] == 'failed' and outcome['reason'] == 'response_limit'
    assert outcome.get('diagnostic') == dict(
        DEFAULT, operation='teams_send', http_status=200,
        response_bytes=131072, response_limit=65536, tls_verify=True)
    assert response.closed and response.reads == 2


def test_truncated_response_retains_bytes_and_status():
    response = Response(raw=b'SECRET', headers={'Content-Length': '100'})
    adapter, claim = configured(Transport(response))
    outcome = adapter.execute_step(claim)
    assert outcome['state'] == 'retry' and outcome['reason'] == 'provider_protocol'
    assert outcome.get('diagnostic') == dict(
        DEFAULT, operation='teams_send', http_status=200,
        response_bytes=6, response_limit=2097152, tls_verify=True)


def test_transport_exception_retains_only_known_metrics():
    adapter, claim = configured(Transport(requests.exceptions.Timeout('https://SECRET')))
    outcome = adapter.execute_step(claim)
    assert outcome['state'] == 'retry' and outcome['reason'] == 'transport_error'
    assert outcome.get('diagnostic') == dict(
        DEFAULT, operation='teams_send', response_limit=2097152, tls_verify=True)
    assert 'SECRET' not in json.dumps(outcome)


@pytest.mark.parametrize('kind', ['certificate', 'other', 'text_only', 'cycle'])
@pytest.mark.parametrize('verify', [True, '/private/SECRET-ca.pem'])
def test_tls_diagnostic_uses_exception_types_not_raw_text(kind, verify):
    import dataclasses
    import ssl
    from urllib3.exceptions import MaxRetryError, SSLError
    if kind == 'certificate':
        error = requests.exceptions.SSLError(MaxRetryError(
            None, 'https://SECRET', SSLError(ssl.SSLCertVerificationError(1, 'SECRET'))))
    elif kind == 'other':
        error = requests.exceptions.SSLError(ssl.SSLError(1, 'SECRET'))
    else:
        error = requests.exceptions.SSLError('CERTIFICATE_VERIFY_FAILED https://SECRET')
        if kind == 'cycle':
            error.__cause__ = error
    transport = Transport(error)
    adapter, claim = configured(transport)
    adapter = dataclasses.replace(adapter, _verify=verify)
    outcome = adapter.execute_step(claim)
    assert (outcome['state'], outcome['reason']) == ('blocked', 'tls_error')
    assert outcome.get('diagnostic') == dict(
        DEFAULT, operation='teams_send', response_limit=2097152, tls_verify=True,
        tls_kind='certificate_verify' if kind == 'certificate' else 'ssl_failure')
    assert transport.calls[0][2]['verify'] == verify
    assert 'SECRET' not in json.dumps(outcome)


def attribute():
    return {'id': '1', 'event_id': '12', 'type': 'ip-src', 'value': '1.2.3.4'}


def event(*attributes):
    return {'Event': {'id': '12', 'Attribute': list(attributes)}}


def run_phase(adapter, claim, operation):
    if operation == 'misp_sighting_read':
        return adapter.sighting_step('1.2.3.4')
    if operation == 'misp_sighting_add':
        return adapter.sighting_step('1.2.3.4', {
            'phase': 'sighting', 'ip': '1.2.3.4', 'attribute_id': '1',
            'binding_id': adapter.binding_id})
    if operation == 'misp_add':
        claim['progress'] = {'phase': 'add'}
    elif operation == 'misp_delete':
        claim.update(action='Removed', progress={'phase': 'delete', 'attribute_id': '1'})
    return adapter.execute_step(claim)


@pytest.mark.parametrize('operation,body,state', [
    ('misp_read', event(), 'continue'),
    ('misp_read', event(attribute()), 'acked'),
    ('misp_add', {'Attribute': attribute()}, 'acked'),
    ('misp_add', {}, 'retry'),
    ('misp_delete', {'success': True}, 'continue'),
    ('misp_delete', {}, 'retry'),
    ('misp_sighting_read', event(attribute()), 'continue'),
    ('misp_sighting_read', event(), 'failed'),
    ('misp_sighting_add', {'Sighting': {'id': '2', 'event_id': '12',
                                      'attribute_id': '1', 'type': '0'}}, 'acked'),
    ('misp_sighting_add', {}, 'retry'),
])
def test_all_misp_phases_retain_http_metrics_including_success(operation, body, state):
    response = Response(body)
    transport = Transport(response)
    adapter, claim = configured(transport, 'misp')
    outcome = run_phase(adapter, claim, operation)
    assert outcome['state'] == state
    assert outcome.get('diagnostic') == dict(
        DEFAULT, operation=operation, http_status=200, response_bytes=len(response.raw),
        response_limit=2097152, tls_verify=True)
    assert provider_result(outcome)['state'] == state
    assert response.closed and len(transport.calls) == 1
    assert 'SECRET' not in json.dumps(outcome['diagnostic'])


@pytest.mark.parametrize('operation', ['misp_read', 'misp_add', 'misp_delete',
                                       'misp_sighting_read', 'misp_sighting_add'])
@pytest.mark.parametrize('status,raw,reason', [(403, b'SECRET', 'provider_auth'),
                                             (200, b'SECRET', 'provider_protocol')])
def test_all_misp_phase_errors_retain_operation_and_http(operation, status, raw, reason):
    response = Response(status=status, raw=raw)
    adapter, claim = configured(Transport(response), 'misp')
    outcome = run_phase(adapter, claim, operation)
    assert outcome['reason'] == reason
    assert outcome.get('diagnostic') == dict(
        DEFAULT, operation=operation, http_status=status,
        response_bytes=len(raw) if status == 200 else 0,
        response_limit=2097152, tls_verify=True)


@pytest.mark.parametrize('body,state', [(event(), 'acked'), (event(attribute()), 'continue')])
def test_authoritative_removal_read_retains_diagnostic(body, state):
    response = Response(body)
    adapter, claim = configured(Transport(response), 'misp')
    claim['action'] = 'Removed'
    outcome = adapter.execute_step(claim)
    assert outcome['state'] == state
    assert outcome.get('diagnostic') == dict(
        DEFAULT, operation='misp_read', http_status=200,
        response_bytes=len(response.raw), response_limit=2097152, tls_verify=True)


@pytest.mark.parametrize('shape,observed', [('top', 2001), ('nested', 2001), ('objects', 0)])
@pytest.mark.parametrize('operation', ['misp_read', 'misp_sighting_read'])
def test_attribute_limit_retains_observed_lower_bound_and_http(shape, observed, operation):
    from monitor.delivery_adapters import event_attributes
    body = event()
    if shape == 'top':
        body['Event']['Attribute'] = [attribute()] * 2001
    elif shape == 'nested':
        body['Event']['Attribute'] = [attribute()] * 1999
        body['Event']['Object'] = [{'id': '2', 'event_id': '12', 'Attribute': [attribute()] * 2},
                                   {'DO_NOT_TRAVERSE': 'SECRET'}]
    else:
        # Object count is not an attribute count; no extra traversal for diagnostics.
        body['Event']['Object'] = [{'Attribute': []}] * 2001
    with pytest.raises(ValueError, match='^attribute_limit$') as caught:
        event_attributes(body, '12')
    assert getattr(caught.value, 'diagnostic', None) == dict(
        DEFAULT, attribute_count=observed, attribute_limit=2000)
    response = Response(body)
    adapter, claim = configured(Transport(response), 'misp')
    outcome = run_phase(adapter, claim, operation)
    expected = ('failed', 'attribute_limit') if operation == 'misp_read' else ('retry', 'provider_protocol')
    assert (outcome['state'], outcome['reason']) == expected
    assert outcome.get('diagnostic') == dict(
        DEFAULT, operation=operation, http_status=200, response_bytes=len(response.raw),
        response_limit=2097152, tls_verify=True, attribute_count=observed, attribute_limit=2000)
    assert 'SECRET' not in json.dumps(outcome)


@pytest.mark.parametrize('invalid', [{}, {'SECRET': 'SECRET'}, dict(DEFAULT, http_status=True)])
def test_result_helper_does_not_launder_invalid_metadata_into_ack(invalid):
    outcome = result('acked', calls=1, diagnostic=invalid)
    assert outcome['state'] == 'failed' and outcome['reason'] == 'invalid_payload'
    assert provider_result(outcome)['state'] == 'failed'
    assert 'SECRET' not in json.dumps(outcome)


def test_stream_failure_retains_observed_prefix_without_exception_text():
    class Interrupted(Response):
        def iter_content(self, chunk_size):
            yield b'prefix'
            raise requests.exceptions.ConnectionError('SECRET')
    response = Interrupted()
    adapter, claim = configured(Transport(response))
    outcome = adapter.execute_step(claim)
    assert (outcome['state'], outcome['reason']) == ('retry', 'transport_error')
    assert outcome['diagnostic'] == dict(
        DEFAULT, operation='teams_send', http_status=200,
        response_bytes=6, response_limit=2097152, tls_verify=True)
    assert response.closed


def test_rejected_chunk_counter_is_bounded_without_copying_chunk():
    class HugeChunk:
        def __len__(self):
            return 2**63 - 1
    class HugeResponse(Response):
        def iter_content(self, chunk_size):
            yield b'prefix'
            yield HugeChunk()
            raise AssertionError('must stop at the first rejected chunk')
    response = HugeResponse()
    adapter, claim = configured(Transport(response))
    outcome = adapter.execute_step(claim)
    assert (outcome['state'], outcome['reason']) == ('failed', 'response_limit')
    assert outcome['diagnostic']['response_bytes'] == 2**63 - 1
    assert provider_result(outcome)['reason'] == 'response_limit'
    assert response.closed


@pytest.mark.parametrize('length,state,observed', [(65536, 'acked', 65536),
                                                  (200000, 'failed', 131072)])
def test_requests_decoded_bytes_not_compressed_length(monkeypatch, length, state, observed):
    import gzip
    import io
    import urllib3
    from monitor import delivery_adapters
    monkeypatch.setattr(delivery_adapters, 'MAX_RESPONSE_BYTES', 65536)
    wire = gzip.compress(b'x' * length)
    sent = []
    responses = []

    def send(self, request, **kwargs):
        sent.append((kwargs, self.max_retries.total))
        response = requests.Response()
        response.status_code = 200
        response.headers.update({'Content-Encoding': 'gzip', 'Content-Length': str(len(wire))})
        response.raw = urllib3.response.HTTPResponse(
            body=io.BytesIO(wire), headers=response.headers,
            preload_content=False, decode_content=False)
        response.request = request
        responses.append(response)
        return response

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    adapter, claim = configured(delivery_adapters.RequestsTransport())
    outcome = adapter.execute_step(claim)
    assert outcome['state'] == state
    assert outcome['diagnostic'] == dict(
        DEFAULT, operation='teams_send', http_status=200,
        response_bytes=observed, response_limit=65536, tls_verify=True)
    assert len(sent) == 1
    assert sent[0][0]['proxies'] == {} and sent[0][0]['verify'] is True
    assert sent[0][1] == 0
    assert responses[0].raw.closed
