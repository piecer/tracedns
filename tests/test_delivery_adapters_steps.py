import json

import pytest
import requests

from monitor.delivery_adapters import DestinationRegistry


class Response:
    def __init__(self, body=None, status=200, raw=None, headers=None):
        self.status_code = status
        self.headers = headers or {}
        self.raw = raw if raw is not None else json.dumps(body).encode()
        self.closed = False

    def iter_content(self, chunk_size):
        for n in range(0, len(self.raw), chunk_size):
            yield self.raw[n:n + chunk_size]

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


def setup(transport, channel='teams'):
    registry = DestinationRegistry(b'k' * 32, transport=transport)
    registry.apply({'teams_webhook': 'https://teams.invalid/SECRET',
                    'misp_url': 'https://misp.invalid', 'api_key': 'SECRET',
                    'push_event_id': 12, 'misp_remove_on_absent': True}, revision=1)
    descriptor = registry.descriptors()[channel]
    adapter = registry.capture(channel, descriptor['binding_id'], 'Added')
    claim = {'claim_id': 'c', 'attempt_token': 't', 'channel': channel,
             'binding_id': adapter.binding_id, 'action': 'Added', 'attempt': 1,
             'provider_calls': 0, 'progress': {}, 'observation_hook_consumed': False,
             'payload': {'entries': [['1.2.3.4', 'label', 'A']],
                         'body': {'title': 'fixed title', 'text': 'fixed time 한글'}}}
    return adapter, claim


def closed(result):
    assert set(result) == {'state', 'reason', 'progress', 'retry_after', 'provider_calls', 'observation_hook'}
    assert result['provider_calls'] in (0, 1)
    assert 'SECRET' not in json.dumps(result)


@pytest.mark.parametrize('status,state', [(200, 'acked'), (202, 'acked'), (204, 'acked'),
                                          (302, 'failed'), (401, 'blocked'), (403, 'blocked'),
                                          (429, 'retry'), (500, 'retry'), (400, 'failed')])
def test_teams_status_explicit_and_exact_persisted_body(status, state):
    response = Response(status=status)
    transport = Transport(response)
    adapter, claim = setup(transport)
    result = adapter.execute_step(claim)
    closed(result)
    assert result['state'] == state
    assert result['provider_calls'] == 1
    assert len(transport.calls) == 1
    _, _, kwargs = transport.calls[0]
    assert json.loads(kwargs['data']) == claim['payload']['body']
    assert kwargs['timeout'] == (3, 10)
    assert kwargs['allow_redirects'] is False and kwargs['stream'] is True
    assert kwargs['verify'] is True
    assert response.closed


@pytest.mark.parametrize('response,state,reason', [
    (Response(raw=b'x' * (2 * 1024 * 1024 + 1)), 'failed', 'response_limit'),
    (requests.exceptions.SSLError('SECRET'), 'blocked', 'tls_error'),
    (requests.exceptions.Timeout('SECRET'), 'retry', 'transport_error')])
def test_teams_response_cap_errors_are_sanitized(response, state, reason):
    adapter, claim = setup(Transport(response))
    result = adapter.execute_step(claim)
    closed(result)
    assert (result['state'], result['reason'], result['provider_calls']) == (state, reason, 1)


def test_teams_byte_budget_binding_and_work_cap_before_io():
    transport = Transport()
    adapter, claim = setup(transport)
    claim['payload']['body']['text'] = '한' * 9000
    assert adapter.execute_step(claim)['reason'] == 'payload_limit'
    claim['payload']['body']['text'] = 'ok'
    claim['binding_id'] = 'different'
    assert adapter.execute_step(claim)['reason'] == 'old_binding_blocked'
    claim['binding_id'] = adapter.binding_id
    # Count includes current reservation; 4096 is the last permitted call.
    claim['provider_calls'] = 4097
    assert adapter.execute_step(claim)['reason'] == 'provider_work_limit'
    assert transport.calls == []


def attribute(id='1', ip='1.2.3.4', event='12'):
    return {'id': id, 'type': 'ip-src', 'value': ip, 'event_id': event}


def event(*attributes):
    return {'Event': {'id': '12', 'Attribute': list(attributes)}}


def test_misp_add_read_then_validate_add_and_never_observe_retry():
    transport = Transport(Response(event()), Response({'Attribute': attribute()}))
    adapter, claim = setup(transport, 'misp')
    claim['payload'].pop('body')
    read = adapter.execute_step(claim)
    assert (read['state'], read['progress'], read['provider_calls']) == ('continue', {'phase': 'add'}, 1)
    assert read['observation_hook'] is None
    claim['progress'] = read['progress']
    added = adapter.execute_step(claim)
    closed(added)
    assert added['state'] == 'acked' and added['observation_hook'] is None
    assert transport.calls[0][0:2] == ('GET', 'https://misp.invalid/events/view/12')
    assert transport.calls[1][0:2] == ('POST', 'https://misp.invalid/attributes/add/12')
    assert transport.calls[1][2]['headers']['Authorization'] == 'SECRET'
    assert json.loads(transport.calls[1][2]['data'])['comment'] == 'NST-2-1 label'


@pytest.mark.parametrize('bad', [{}, {'Event': {}}, {'Event': {'id': '99', 'Attribute': []}},
                               {'Event': {'id': '12', 'Attribute': None}},
                               event({'type': 'ip-src', 'value': '1.2.3.4'}),
                               dict(event(), errors=['SECRET']),
                               {'Event': {'id': '12', 'Attribute': [], 'attribute_count': '1'}},
                               {'Event': {'id': '12', 'Attribute': [], 'Object': [{'Attribute': []}]}}])
def test_malformed_event_never_proves_removal_absence(bad):
    transport = Transport(Response(bad))
    adapter, claim = setup(transport, 'misp')
    claim['action'] = 'Removed'
    result = adapter.execute_step(claim)
    closed(result)
    assert result['state'] == 'retry' and result['reason'] == 'provider_protocol'
    assert result['provider_calls'] == 1


def test_misp_removal_one_delete_then_authoritative_read_only_ack():
    transport = Transport(Response(event(attribute('1'), attribute('2'))),
                          Response({'saved': True, 'success': True}),
                          Response(event(attribute('2'))),
                          Response({'saved': True, 'success': True}), Response(event()))
    adapter, claim = setup(transport, 'misp')
    claim['action'] = 'Removed'
    for expected in ('continue', 'continue', 'continue', 'continue', 'acked'):
        before = len(transport.calls)
        result = adapter.execute_step(claim)
        closed(result)
        assert result['state'] == expected
        assert len(transport.calls) == before + 1
        claim['progress'] = result['progress']
    assert [call[1] for call in transport.calls if call[0] == 'POST'] == [
        'https://misp.invalid/attributes/delete/1', 'https://misp.invalid/attributes/delete/2']
    assert result['observation_hook']['kind'] == 'remove_queued_sightings'


@pytest.mark.parametrize('envelope', [{}, {'errors': ['SECRET']}, {'Attribute': attribute(ip='2.3.4.5')},
                                     {'Attribute': attribute(event='99')}, {'Attribute': [attribute()]},
                                     {'Attribute': attribute(), 'errors': ['SECRET']}])
def test_bad_add_envelope_cannot_ack_or_cache_existing(envelope):
    adapter, claim = setup(Transport(Response(envelope)), 'misp')
    claim['progress'] = {'phase': 'add'}
    result = adapter.execute_step(claim)
    assert result['state'] == 'retry' and result['progress'] == {}
    closed(result)


def test_misp_attribute_limit_and_truncated_json():
    for response, reason in [(Response(event(*[attribute(str(i + 1)) for i in range(2001)])), 'attribute_limit'),
                             (Response(raw=b'{"Event":'), 'provider_protocol')]:
        adapter, claim = setup(Transport(response), 'misp')
        claim['action'] = 'Removed'
        result = adapter.execute_step(claim)
        assert result['state'] != 'acked' and result['reason'] == reason


@pytest.mark.parametrize('attempt,consumed,hook', [(1, False, True), (1, True, False), (2, False, False)])
def test_first_existing_observation_hook_not_retry(attempt, consumed, hook):
    adapter, claim = setup(Transport(Response(event(attribute()))), 'misp')
    claim.update(attempt=attempt, observation_hook_consumed=consumed)
    result = adapter.execute_step(claim)
    assert result['state'] == 'acked'
    assert bool(result['observation_hook']) is hook
    if hook:
        assert result['observation_hook'] == {'kind': 'enqueue_sightings', 'event_id': '12', 'ip': '1.2.3.4'}


@pytest.mark.parametrize('change', [{'action': 'Unexpected'}, {'channel': 'unknown'}, {'attempt': True},
                                    {'provider_calls': -1}, {'provider_calls': '0'},
                                    {'observation_hook_consumed': 0}, {'progress': {'evil': 'SECRET'}},
                                    {'extra': 'SECRET'}, {'progress': None}])
def test_invalid_claim_closed_before_network(change):
    transport = Transport()
    adapter, claim = setup(transport, 'misp')
    claim.update(change)
    outcome = adapter.execute_step(claim)
    assert outcome['state'] == 'failed' and outcome['reason'] == 'payload_invalid'
    assert outcome['provider_calls'] == 0 and not transport.calls


@pytest.mark.parametrize('raw', [b'{"Event":{"id":"12","Attribute":[]},"Event":{"id":"12","Attribute":[]}}',
                                 b'[' * 1500 + b']' * 1500,
                                 b'{"Event":{"id":"12","Attribute":[]},"x":NaN}'])
def test_invalid_json_cannot_ack_or_escape(raw):
    adapter, claim = setup(Transport(Response(raw=raw)), 'misp')
    claim['action'] = 'Removed'
    outcome = adapter.execute_step(claim)
    assert outcome['state'] == 'retry' and outcome['reason'] == 'provider_protocol'


def test_truncated_content_length_no_absence():
    adapter, claim = setup(Transport(Response(event(), headers={'Content-Length': '999'})), 'misp')
    claim['action'] = 'Removed'
    assert adapter.execute_step(claim)['state'] == 'retry'


def test_nested_misp_ip_participates_and_combined_attribute_budget():
    body = event()
    body['Event']['Object'] = [{'id': '8', 'event_id': '12', 'Attribute': [attribute('9')]}]
    body['Event']['attribute_count'] = '1'
    adapter, claim = setup(Transport(Response(body)), 'misp')
    claim['action'] = 'Removed'
    outcome = adapter.execute_step(claim)
    assert outcome['state'] == 'continue' and outcome['progress']['attribute_id'] == '9'
    body['Event']['Attribute'] = [attribute(str(n + 10)) for n in range(2000)]
    adapter, claim = setup(Transport(Response(body)), 'misp')
    assert adapter.execute_step(claim)['reason'] == 'attribute_limit'


@pytest.mark.parametrize('bad_attribute', [dict(attribute(), value='invalid'),
                                          dict(attribute(), value='1.2.3.4%zone'),
                                          dict(attribute(), event_id=True),
                                          dict(attribute(), deleted='1')])
def test_invalid_ip_attribute_never_proves_absence(bad_attribute):
    adapter, claim = setup(Transport(Response(event(bad_attribute))), 'misp')
    claim['action'] = 'Removed'
    assert adapter.execute_step(claim)['state'] == 'retry'


def test_requests_transport_no_redirect_hidden_retry_or_environment(monkeypatch):
    import io
    from monitor.delivery_adapters import RequestsTransport
    calls = []

    def send(self, request, **kwargs):
        calls.append((request, kwargs, self.max_retries.total))
        response = requests.Response()
        response.status_code = 307
        response.headers['Location'] = 'https://exfil.invalid/SECRET'
        response.raw = io.BytesIO(b'')
        response.request = request
        response.url = request.url
        return response

    monkeypatch.setenv('HTTPS_PROXY', 'http://proxy.invalid')
    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    adapter, claim = setup(RequestsTransport())
    result = adapter.execute_step(claim)
    assert result['state'] == 'failed' and result['provider_calls'] == 1
    assert len(calls) == 1
    assert calls[0][1]['proxies'] == {} and calls[0][1]['verify'] is True
    assert calls[0][2] == 0


def test_redirect_body_is_never_eagerly_drained_by_requests(monkeypatch):
    import io
    from monitor.delivery_adapters import RequestsTransport
    reads = []

    class GuardedBody(io.BytesIO):
        def read(self, *args, **kwargs):
            reads.append(args)
            raise AssertionError('redirect body must not be consumed')

    def send(self, request, **kwargs):
        response = requests.Response()
        response.status_code = 302
        response.headers['Location'] = 'https://exfil.invalid/SECRET'
        response.raw = GuardedBody(b'')
        response.request = request
        response.url = request.url
        return response

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    adapter, claim = setup(RequestsTransport())
    result = adapter.execute_step(claim)
    assert result['state'] == 'failed' and result['reason'] == 'provider_http'
    assert reads == []


def test_close_failure_does_not_escape_closed_result():
    class BadClose(Response):
        def close(self):
            raise RuntimeError('SECRET')
    adapter, claim = setup(Transport(BadClose()))
    outcome = adapter.execute_step(claim)
    closed(outcome)
    assert outcome['state'] == 'acked'


@pytest.mark.parametrize('channel,payload', [
    ('teams', {'entries': [['1.2.3.4', 'label', 'A']], 'body': ['title', 'text']}),
    ('teams', {'entries': [], 'body': {'title': 't', 'text': 'x'}}),
    ('teams', {'entries': [['invalid', 'label', 'A']], 'body': {'title': 't', 'text': 'x'}}),
    ('misp', {'entries': [[16909060, 'label', 'A']]}),
    ('misp', {'entries': [['fe80::1%zone', 'label', 'A']]}),
])
def test_invalid_entries_or_body_never_escape_or_send(channel, payload):
    transport = Transport()
    adapter, claim = setup(transport, channel)
    claim['payload'] = payload
    outcome = adapter.execute_step(claim)
    assert outcome['state'] == 'failed' and outcome['reason'] == 'payload_invalid'
    assert outcome['provider_calls'] == 0 and transport.calls == []


def test_retry_after_clamped_and_no_automatic_retry():
    transport = Transport(Response(status=429, headers={'Retry-After': '999999'}))
    adapter, claim = setup(transport)
    assert adapter.execute_step(claim)['retry_after'] == 3600
    assert len(transport.calls) == 1
