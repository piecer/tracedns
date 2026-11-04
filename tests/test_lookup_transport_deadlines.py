"""Real collector/fetch boundaries with synthetic providers; no provider traffic."""
import json
import gzip
import zlib
import threading
import io
from types import SimpleNamespace
from dataclasses import replace

import pytest
import requests

import ens_query
import sns_query
from models import DomainSpec
from monitor import collect


class Clock:
    now = 0.0
    stopped = False

    def remaining(self, budget):
        return max(0, budget - self.now)


def ens_fixture(monkeypatch, clock, *, times=(8, 16, 24, 29.5), fail_at=(), decode=None,
                require_redirect_guard=False, on_send=None):
    """Mirror installed Web3 7.16 HTTPProvider session/retry/decode boundaries."""
    calls, decoded, responses = [], [], []

    def send(session, request, **kwargs):
        index = len(calls)
        calls.append((json.loads(request.body)['method'], kwargs['timeout']))
        if on_send:
            on_send()
        if require_redirect_guard:
            assert kwargs.get('allow_redirects') is False
        clock.now = times[index]
        if index in fail_at:
            raise requests.Timeout('synthetic transport timeout')
        response = requests.Response()
        response.status_code = 200
        response._content = b'{"result":"synthetic"}'
        response.closed = False
        response.close = lambda: setattr(response, 'closed', True)
        responses.append(response)
        return response

    monkeypatch.setattr(requests.Session, 'send', send)

    class Provider:
        def __init__(self, url, request_kwargs, session=None):
            self.url, self.kwargs = url, request_kwargs
            self.session = session or requests.Session()

        def get_request_kwargs(self):
            return self.kwargs.copy()

        def decode_rpc_response(self, raw):
            decoded.append(True)
            if decode:
                decode()
            return json.loads(raw)

        def make_request(self, method, params):
            for attempt in range(2):
                try:
                    with self.session.post(self.url, json={'method': method},
                                           **self.get_request_kwargs()) as response:
                        response.raise_for_status()
                        raw = response.content
                    break
                except requests.Timeout:
                    if attempt:
                        raise
            return self.decode_rpc_response(raw)

    class Web3:
        HTTPProvider = Provider
        to_checksum_address = staticmethod(lambda value: value)

        def __init__(self, provider):
            self.provider = provider
            self.eth = SimpleNamespace(contract=self.contract)

        def is_connected(self):
            self.provider.make_request('web3_clientVersion', [])
            return True

        def contract(self, *, address, abi):
            def call():
                self.provider.make_request('eth_chainId', [])  # nested middleware RPC
                self.provider.make_request('eth_call', [])
                self.provider.make_request('eth_getCode', [])  # nested Web3 RPC
                return '192.0.2.1'
            return SimpleNamespace(functions=SimpleNamespace(text=lambda *args: SimpleNamespace(call=call)))

    monkeypatch.setattr(ens_query, 'Web3', Web3)
    return calls, decoded, responses


def ens_domain():
    return DomainSpec(name='fixture.eth', type='ENS', ens_decode='ipv4_literals',
                      ens_node='0x' + '07' * 32, ens_resolver='0x' + 'ab' * 20)


def test_owned_ens_rebinds_nested_rpc_to_original_remaining_budget(monkeypatch):
    clock = Clock()
    calls, decoded, responses = ens_fixture(monkeypatch, clock)
    with collect.lookup_scope(lambda: clock.stopped, lambda: clock.remaining(30)):
        result = collect.collect_snapshot(ens_domain(), 'https://rpc.invalid')
    assert result.snapshot is not None
    assert [timeout for _, timeout in calls] == [8, 8, 8, 6]
    assert len(decoded) == 4
    assert all(response.closed for response in responses)


@pytest.mark.parametrize('completion', [29.999, 30, 30.001])
@pytest.mark.parametrize('boundary', ['transport', 'rpc_decode'])
def test_owned_ens_checks_transport_and_rpc_decode_deadlines(monkeypatch, completion, boundary):
    clock = Clock()
    def decode():
        if clock.now == 24:
            clock.now = completion
    calls, decoded, responses = ens_fixture(monkeypatch, clock,
        times=(8, 16, completion if boundary == 'transport' else 24, max(completion, 29.999)),
        decode=decode if boundary == 'rpc_decode' else None)
    with collect.lookup_scope(lambda: clock.stopped, lambda: clock.remaining(30)):
        if completion < 30:
            assert collect.collect_snapshot(ens_domain(), 'https://rpc.invalid').snapshot
        else:
            with pytest.raises(TimeoutError):
                collect.collect_snapshot(ens_domain(), 'https://rpc.invalid')
    assert len(calls) == (4 if completion < 30 else 3)
    assert len(decoded) == (4 if completion < 30 else 2 if boundary == 'transport' else 3)
    assert all(response.closed for response in responses)


def test_owned_ens_cancellation_between_rpc_decode_and_next_rpc(monkeypatch):
    clock = Clock()
    calls, decoded, responses = ens_fixture(monkeypatch, clock,
        decode=lambda: setattr(clock, 'stopped', True))
    with collect.lookup_scope(lambda: clock.stopped, lambda: clock.remaining(30)):
        with pytest.raises(TimeoutError):
            collect.collect_snapshot(ens_domain(), 'https://rpc.invalid')
    assert len(calls) == len(decoded) == 1
    assert all(response.closed for response in responses)


@pytest.mark.parametrize('expired', [False, True])
def test_owned_ens_retry_budget_and_session_retirement(monkeypatch, expired):
    clock = Clock()
    closed = []
    monkeypatch.setattr(requests.Session, 'close', lambda self: closed.append(self))
    calls, decoded, responses = ens_fixture(monkeypatch, clock,
        times=(8, 30 if expired else 24, 29, 29.5, 29.75), fail_at=(1,), require_redirect_guard=True)
    with collect.lookup_scope(lambda: clock.stopped, lambda: clock.remaining(30)):
        if expired:
            with pytest.raises(TimeoutError):
                collect.collect_snapshot(ens_domain(), 'https://rpc.invalid')
        else:
            assert collect.collect_snapshot(ens_domain(), 'https://rpc.invalid').snapshot
    assert [timeout for _, timeout in calls] == ([8, 8] if expired else [8, 8, 6, 1, .5])
    assert len(closed) == 1
    assert all(response.closed for response in responses)


@pytest.mark.parametrize('completion', [29.999, 30, 30.001])
def test_ens_decoder_expiry_prevents_endpoint_decode(monkeypatch, completion):
    clock = Clock()
    ens_fixture(monkeypatch, clock)
    endpoints = []
    def decode(*args, **kwargs):
        clock.now = completion
        return ['192.0.2.1']
    monkeypatch.setattr(collect, 'decode_ens_hidden_ips', decode)
    monkeypatch.setattr(collect, 'decode_ens_endpoints', lambda *a, **k: endpoints.append(True))
    with collect.lookup_scope(lambda: clock.stopped, lambda: clock.remaining(30)):
        if completion < 30:
            assert collect.collect_snapshot(ens_domain(), 'https://rpc.invalid').snapshot
        else:
            with pytest.raises(TimeoutError):
                collect.collect_snapshot(ens_domain(), 'https://rpc.invalid')
    assert endpoints == ([True] if completion < 30 else [])


def sns_domain():
    return DomainSpec(name='fixture.sol', type='SNS', sns_decode='ipv4_literals')


def sns_fixture(monkeypatch, clock, *, chunks=(b'192.', b'0.2.1'),
                times=(10, 19, 19.5), header_time=3, status=200, encoding='', fail_read=None):
    calls, reads, socket_timeouts, decoded = [], [], [], []

    class Raw:
        closed = False
        _connection = SimpleNamespace(sock=SimpleNamespace(settimeout=socket_timeouts.append))

        def read1(self, size, decode_content=False):
            assert not decode_content, 'compressed output must be bounded before accumulation'
            index = len(reads)
            reads.append(size)
            clock.now = times[min(index, len(times) - 1)]
            if fail_read:
                fail_read(index)
            return chunks[index] if index < len(chunks) else b''

        def close(self):
            self.closed = True

        def release_conn(self):
            pass

    raw = Raw()
    response = requests.Response()
    response.status_code, response.raw, response.encoding = status, raw, 'utf-8'
    response.headers['Content-Encoding'] = encoding
    # This legacy path remains available to make the missing stream observable.
    response._content = b''.join(chunks)
    response._content_consumed = False
    def get(*args, **kwargs):
        calls.append(kwargs)
        clock.now = header_time
        return response
    monkeypatch.setattr(sns_query.requests, 'get', get)
    monkeypatch.setattr(requests.Session, 'get', get)
    def decode(raw_value, **kwargs):
        decoded.append(raw_value)
        return ['192.0.2.1']
    monkeypatch.setattr(collect, 'decode_ens_hidden_ips', decode)
    return calls, reads, socket_timeouts, decoded, raw


def test_owned_sns_streams_with_original_budget_at_each_read(monkeypatch):
    clock = Clock()
    calls, reads, timeouts, decoded, raw = sns_fixture(monkeypatch, clock)
    with collect.lookup_scope(lambda: clock.stopped, lambda: clock.remaining(20)):
        result = collect.collect_snapshot(sns_domain(), 'https://proxy.invalid')
    assert result.snapshot is not None
    assert calls[0].get('stream') is True and calls[0].get('allow_redirects') is False
    assert calls[0]['timeout'] == 15 and calls[0]['verify'] is True
    assert reads == [8192, 8192, 8192]
    assert timeouts == [15, 10, 1]
    assert decoded == ['192.0.2.1'] and raw.closed


@pytest.mark.parametrize('size', [1048575, 1048576, 1048577])
def test_owned_sns_body_cap_before_decode(monkeypatch, size):
    clock = Clock()
    body = b'x' * size
    chunks = tuple(body[i:i + 8192] for i in range(0, len(body), 8192))
    calls, reads, timeouts, decoded, raw = sns_fixture(monkeypatch, clock,
        chunks=chunks, times=(4,))
    with collect.lookup_scope(lambda: clock.stopped, lambda: clock.remaining(20)):
        result = collect.collect_snapshot(sns_domain(), 'https://proxy.invalid')
    assert bool(result.snapshot) == (size <= 1048576)
    assert bool(decoded) == (size <= 1048576)
    if decoded:
        assert len(decoded[0]) == size
    assert raw.closed
    assert all(size == 8192 for size in reads)


@pytest.mark.parametrize('size', [1048576, 1048577])
@pytest.mark.parametrize('encoding', ['gzip', 'deflate', 'gzip-members'])
def test_owned_sns_cap_counts_decompressed_bytes(monkeypatch, size, encoding):
    clock = Clock()
    body = b'x' * size
    wire = (gzip.compress(body, mtime=0) if encoding == 'gzip' else zlib.compress(body)
            if encoding == 'deflate' else gzip.compress(body[:100], mtime=0) + gzip.compress(body[100:], mtime=0))
    chunks = tuple(wire[i:i + 8192] for i in range(0, len(wire), 8192))
    calls, reads, timeouts, decoded, raw = sns_fixture(monkeypatch, clock,
        chunks=chunks, times=(4,), encoding=encoding.replace('-members', ''))
    with collect.lookup_scope(lambda: clock.stopped, lambda: clock.remaining(20)):
        result = collect.collect_snapshot(sns_domain(), 'https://proxy.invalid')
    assert bool(result.snapshot) == (size <= 1048576)
    assert bool(decoded) == (size <= 1048576)
    if decoded:
        assert len(decoded[0]) == size
    assert raw.closed


@pytest.mark.parametrize('encoding, wire', [('gzip', b'invalid'),
    ('gzip', gzip.compress(b'fixture', mtime=0)[:-1]), ('br', b'unsupported')],
    ids=['invalid-gzip', 'truncated-gzip', 'unsupported-br'])
def test_owned_sns_bad_content_encoding_never_decodes(monkeypatch, encoding, wire):
    clock = Clock()
    calls, reads, timeouts, decoded, raw = sns_fixture(monkeypatch, clock,
        chunks=(wire,), times=(4,), encoding=encoding)
    with collect.lookup_scope(lambda: clock.stopped, lambda: clock.remaining(20)):
        result = collect.collect_snapshot(sns_domain(), 'https://proxy.invalid')
    assert result.snapshot is None and not decoded
    assert raw.closed


@pytest.mark.parametrize('status', [301, 302, 307, 308, 500])
def test_owned_sns_real_requests_does_not_prefetch_redirect_body(monkeypatch, status):
    clock = Clock()
    activity = []
    class Raw:
        closed = False
        def read(self, *args, **kwargs):
            activity.append('body')
            self.closed = True
            return b''
        def close(self):
            self.closed = True
        def release_conn(self):
            pass
    raw = Raw()
    def send(adapter, request, **kwargs):
        activity.append('send')
        assert kwargs['stream'] is True
        response = requests.Response()
        response.raw, response.status_code = raw, status
        response.headers['Location'] = 'https://redirect.invalid'
        response.url, response.request = request.url, request
        return response
    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    with collect.lookup_scope(lambda: clock.stopped, lambda: clock.remaining(20)):
        result = collect.collect_snapshot(sns_domain(), 'https://proxy.invalid')
    assert result.snapshot is None
    assert activity == ['send'], 'even allow_redirects=False must not prefetch a redirect body'
    assert raw.closed


def test_installed_web3_real_contract_rpc_and_retry_boundary(monkeypatch):
    web3 = pytest.importorskip('web3')
    clock = Clock()
    clock.now = 23
    calls, closed, offchain = [], [], []
    failed_once = False
    codec = web3.Web3().codec
    def send(adapter, request, **kwargs):
        nonlocal failed_once
        rpc = json.loads(request.body)
        calls.append((rpc['method'], clock.now, kwargs['timeout']))
        clock.now += .25
        if rpc['method'] == 'eth_chainId' and not failed_once:
            failed_once = True
            raise requests.Timeout('synthetic retry')
        if rpc['method'] == 'web3_clientVersion':
            result = 'synthetic/client'
        elif rpc['method'] == 'eth_chainId':
            result = '0x1'
        elif rpc['method'] == 'eth_call':
            registry = rpc['params'][0]['to'].lower() == ens_query.ENS_REGISTRY_ADDRESS.lower()
            result = '0x' + codec.encode(['address'] if registry else ['string'],
                ['0x' + 'ab' * 20] if registry else ['192.0.2.1']).hex()
        else:
            raise AssertionError('unexpected synthetic RPC: ' + rpc['method'])
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps({'jsonrpc': '2.0', 'id': rpc['id'], 'result': result}).encode()
        response.close = lambda: closed.append(True)
        return response
    def forbidden_offchain(*args, **kwargs):
        offchain.append(True)
        raise AssertionError('unowned CCIP gateway path must be disabled')
    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    monkeypatch.setattr(web3.eth.Eth, '_durin_call', forbidden_offchain)
    monkeypatch.setattr(ens_query, 'Web3', web3.Web3)
    domain = replace(ens_domain(), ens_resolver=None)  # actual registry + resolver ABI calls
    with collect.lookup_scope(lambda: clock.stopped, lambda: clock.remaining(30)):
        result = collect.collect_snapshot(domain, 'https://rpc.invalid')
    assert not offchain, 'real Web3 selected an unowned gateway transport'
    assert result.snapshot is not None
    assert result.snapshot.decoded_ips == ['192.0.2.1']
    assert failed_once and not offchain
    assert len([method for method, _, _ in calls if method == 'eth_call']) == 2
    assert all(timeout == min(8, 30 - started) for _, started, timeout in calls)
    assert len(closed) == len(calls) - 1


@pytest.mark.parametrize('completion', [19.999, 20, 20.001])
@pytest.mark.parametrize('boundary', ['headers', 'read', 'decoder'])
def test_sns_before_exact_after_original_deadline(monkeypatch, completion, boundary):
    clock = Clock()
    calls, reads, timeouts, decoded, raw = sns_fixture(monkeypatch, clock,
        header_time=completion if boundary == 'headers' else 3,
        times=(completion,) if boundary != 'decoder' else (4,))
    if boundary == 'decoder':
        def decode(*args, **kwargs):
            decoded.append(True)
            clock.now = completion
            return ['192.0.2.1']
        monkeypatch.setattr(collect, 'decode_ens_hidden_ips', decode)
    with collect.lookup_scope(lambda: clock.stopped, lambda: clock.remaining(20)):
        if completion < 20:
            assert collect.collect_snapshot(sns_domain(), 'https://proxy.invalid').snapshot
        else:
            with pytest.raises(TimeoutError):
                collect.collect_snapshot(sns_domain(), 'https://proxy.invalid')
    assert raw.closed
    if completion >= 20 and boundary != 'decoder':
        assert not decoded
        assert len(reads) == (0 if boundary == 'headers' else 1)


@pytest.mark.parametrize('fault', ['cancel', 'read_error', 'socket_error', 'missing_socket', 'oversized_chunk'])
def test_sns_failure_closes_response_before_decoder(monkeypatch, fault):
    clock = Clock()
    def fail(index):
        if index == 1:
            if fault == 'cancel':
                clock.stopped = True
            elif fault == 'read_error':
                raise requests.ConnectionError('synthetic read failure')
    calls, reads, timeouts, decoded, raw = sns_fixture(monkeypatch, clock,
        fail_read=fail, chunks=(b'x' * 8193,) if fault == 'oversized_chunk' else (b'a', b'b'))
    if fault == 'missing_socket':
        raw._connection = None
    if fault == 'socket_error':
        def settimeout(value):
            raise OSError('synthetic socket failure')
        raw._connection.sock.settimeout = settimeout
    with collect.lookup_scope(lambda: clock.stopped, lambda: clock.remaining(20)):
        if fault == 'cancel':
            with pytest.raises(TimeoutError):
                collect.collect_snapshot(sns_domain(), 'https://proxy.invalid')
        else:
            assert collect.collect_snapshot(sns_domain(), 'https://proxy.invalid').snapshot is None
    assert raw.closed and not decoded


@pytest.mark.parametrize('kind, budget', [('ENS', 30), ('SNS', 20)])
@pytest.mark.parametrize('expired', [False, True])
def test_expired_or_cancelled_scope_starts_no_transport(monkeypatch, kind, budget, expired):
    clock = Clock()
    if expired:
        clock.now = budget
    else:
        clock.stopped = True
    ens_calls, _, _ = ens_fixture(monkeypatch, clock)
    sns_calls, _, _, _, _ = sns_fixture(monkeypatch, clock)
    with collect.lookup_scope(lambda: clock.stopped, lambda: clock.remaining(budget)):
        with pytest.raises(TimeoutError):
            collect.collect_snapshot(ens_domain() if kind == 'ENS' else sns_domain(), 'https://fixture.invalid')
    assert not ens_calls and not sns_calls


@pytest.mark.parametrize('kind, budget', [('ENS', 30), ('SNS', 20)])
def test_real_owner_keeps_native_transport_slot_until_return(tmp_path, monkeypatch, kind, budget):
    from monitor.lookup_runtime import LookupRuntime
    from test_stage3_core_runtime import app_factory
    from test_lookup_liveness import background_scan, wait_for
    clock = Clock()
    entered, release = threading.Event(), threading.Event()
    domain = ens_domain() if kind == 'ENS' else sns_domain()
    app = app_factory(tmp_path, config={'domains': [vars(domain)], 'servers': [],
        'max_workers': 1, 'ens_rpc_url': 'https://rpc.invalid',
        'DEFAULT_SNS_PROXY_HOSTS': ['https://proxy.invalid'], 'alerts': {}})
    app.lookup = LookupRuntime(app.repo, clock=lambda: clock.now)
    def block(*args):
        entered.set()
        assert release.wait(5), 'test rescue only after observed production state'
    if kind == 'ENS':
        calls, decoded, responses = ens_fixture(monkeypatch, clock, times=(budget,), on_send=block)
    else:
        calls, reads, timeouts, decoded, raw = sns_fixture(monkeypatch, clock,
            times=(budget,), fail_read=block)
    thread, results, errors = background_scan(app)
    try:
        assert entered.wait(2)
        clock.now = budget
        thread.join(2)
        assert not thread.is_alive() and not errors
        assert not results[0].complete and not results[0].positive
        status = app.lookup.status()
        assert status['active'] == status['overdue'] == 1
        assert all(not providers for providers in app.current.values())
        assert not release.is_set()
        release.set()
        assert wait_for(lambda: app.lookup.status()['active'] == 0)
        assert not decoded
        if kind == 'SNS':
            assert raw.closed
        else:
            assert all(response.closed for response in responses)
    finally:
        release.set()
        thread.join(3)
        app.lookup.stop()
        app.delivery.stop()


@pytest.mark.parametrize('preparation', ['remaining', 'expired', 'cancelled'])
def test_sns_request_preparation_cannot_reset_or_escape_budget(monkeypatch, preparation):
    from urllib3.response import HTTPResponse
    clock = Clock()
    clock.now = 19
    sends, reads = [], []
    prepare = requests.Session.prepare_request
    def delayed_prepare(session, request):
        result = prepare(session, request)
        clock.now = 20 if preparation == 'expired' else 19.75
        clock.stopped = preparation == 'cancelled'
        return result
    raw = HTTPResponse(body=io.BytesIO(b'192.0.2.1'), preload_content=False,
        connection=SimpleNamespace(sock=SimpleNamespace(settimeout=reads.append), close=lambda: None))
    def send(adapter, request, **kwargs):
        sends.append(kwargs['timeout'])
        response = requests.Response()
        response.raw, response.status_code, response.encoding = raw, 200, 'utf-8'
        return response
    monkeypatch.setattr(requests.Session, 'prepare_request', delayed_prepare)
    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    with collect.lookup_scope(lambda: clock.stopped, lambda: clock.remaining(20)):
        if preparation == 'remaining':
            assert collect.collect_snapshot(sns_domain(), 'https://proxy.invalid').snapshot
        else:
            with pytest.raises(TimeoutError):
                collect.collect_snapshot(sns_domain(), 'https://proxy.invalid')
    assert sends == ([.25] if preparation == 'remaining' else [])
    if sends:
        assert raw.closed and all(timeout == .25 for timeout in reads)


@pytest.mark.parametrize('outcome', ['on_time', 'expired', 'cancelled'])
def test_sns_bounded_native_decompression_observes_original_deadline(monkeypatch, outcome):
    clock = Clock()
    wire = gzip.compress(b'x' * 1048576, mtime=0)
    calls, reads, timeouts, decoded, raw = sns_fixture(monkeypatch, clock,
        chunks=(wire,), times=(4,), encoding='gzip')
    native = zlib.decompressobj
    sizes = []
    class Decoder:
        def __init__(self, *args):
            self.native = native(*args)
        def __getattr__(self, name):
            return getattr(self.native, name)
        def decompress(self, value, max_length):
            assert 0 < max_length <= 8192
            output = self.native.decompress(value, max_length)
            sizes.append(len(output))
            if outcome == 'expired':
                clock.now = 20
            if outcome == 'cancelled':
                clock.stopped = True
            return output
    monkeypatch.setattr(zlib, 'decompressobj', Decoder)
    with collect.lookup_scope(lambda: clock.stopped, lambda: clock.remaining(20)):
        if outcome == 'on_time':
            assert collect.collect_snapshot(sns_domain(), 'https://proxy.invalid').snapshot
        else:
            with pytest.raises(TimeoutError):
                collect.collect_snapshot(sns_domain(), 'https://proxy.invalid')
    assert sizes and max(sizes) <= 8192 and raw.closed
    assert bool(decoded) == (outcome == 'on_time')


def test_sns_real_urllib3_raw_reads_use_buffered_socket_fallback(monkeypatch):
    from urllib3.response import HTTPResponse
    clock = Clock()
    timeouts, reads = [], []
    wire = gzip.compress(b'x' * 1048576, mtime=0)
    class Body(io.BytesIO):
        @property
        def fp(self):
            return None if self.closed else self
        raw = SimpleNamespace(_sock=SimpleNamespace(settimeout=timeouts.append))
        def read1(self, size):
            reads.append(size)
            clock.now += 1
            return super().read1(size)
    raw = HTTPResponse(body=Body(wire), preload_content=False,
                       headers={'Content-Encoding': 'gzip'})
    def send(adapter, request, **kwargs):
        response = requests.Response()
        response.raw, response.status_code, response.encoding = raw, 200, 'utf-8'
        response.headers['Content-Encoding'] = 'gzip'
        return response
    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    with collect.lookup_scope(lambda: clock.stopped, lambda: clock.remaining(20)):
        value = sns_query.fetch_sns_record('https://proxy.invalid', 'fixture.sol', 'TXT')
    assert len(value) == 1048576
    assert raw.closed and reads == [8192, 8192]
    assert timeouts == [15, 15]


def test_ens_submillisecond_remainder_is_not_rounded_up(monkeypatch):
    clock = Clock()
    clock.now = 29.9999
    calls, _, _ = ens_fixture(monkeypatch, clock, times=(clock.now,) * 4)
    with collect.lookup_scope(lambda: clock.stopped, lambda: clock.remaining(30)):
        assert collect.collect_snapshot(ens_domain(), 'https://rpc.invalid').snapshot
    assert all(timeout == pytest.approx(.0001) for _, timeout in calls)


def test_scope_restoration_preserves_legacy_sns_fetch(monkeypatch):
    clock = Clock()
    calls, reads, timeouts, decoded, raw = sns_fixture(monkeypatch, clock)
    with collect.lookup_scope(lambda: False, lambda: 2):
        with collect.lookup_scope(lambda: True, lambda: 0):
            with pytest.raises(TimeoutError):
                collect.checkpoint()
        assert collect.transport_timeout(15) == 2
    assert sns_query.fetch_sns_record('https://proxy.invalid', 'fixture.sol', 'TXT') == '192.0.2.1'
    assert calls[0]['timeout'] == 15 and 'stream' not in calls[0]
    assert not reads and not timeouts
