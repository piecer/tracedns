"""Parent acceptance probes against the frozen transport, controlled peers only."""
import importlib
from pathlib import Path
import socket
import sys
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))
from test_local_ai_openai_provider import (
    MESSAGES, SCHEMA, NoDNS, envelope, no_proxy as no_proxy, peer, response, settings,
)
from local_ai.contracts import AIError


def module():
    value = importlib.import_module('local_ai.openai_provider')
    assert value.__file__ is not None
    assert Path(value.__file__).resolve() == ROOT / 'local_ai/openai_provider.py'
    return value


def test_documented_empty_annotations_is_a_usable_non_tool_completion():
    value = envelope('{"ok":true}')
    value['choices'][0]['message'].update(refusal=None, annotations=[])
    with peer(response(value)) as (url, requests):
        adapter = module().OpenAICompatibleProvider(settings(url), resolver=NoDNS())
        reply = adapter.generate(MESSAGES, SCHEMA, time.monotonic() + 3)
        assert reply.content == '{"ok":true}' and reply.content_error is None
        assert len(requests) == 1 and requests[0]['headers']['Authorization'].startswith('Bearer ')
        assert 'annotations' not in reply.metadata


@pytest.mark.parametrize('optional', [
    {'annotations': None},
    {'annotations': [{'type': 'url_citation', 'url_citation': {
        'start_index': 0, 'end_index': 1, 'title': 'SYNTHETIC annotation', 'url': 'https://example.invalid/'}}]},
    {'audio': None, 'function_call': None, 'tool_calls': []},
    {'tool_calls': None, 'reasoning': None, 'reasoning_content': None},
    {'reasoning': 'SYNTHETIC ignored reasoning'},
    {'reasoning_content': 'SYNTHETIC ignored reasoning'},
])
def test_bounded_optional_metadata_and_inactive_actions_are_not_published(optional):
    value = envelope()
    value['choices'][0]['message'].update(optional)
    with peer(response(value)) as (url, requests):
        reply = module().OpenAICompatibleProvider(settings(url), resolver=NoDNS()).generate(
            MESSAGES, SCHEMA, time.monotonic() + 3)
        assert reply.content == '{"ok":true}' and reply.content_error is None
        assert not (set(optional) & set(reply.metadata))
        assert len(requests) == 1


@pytest.mark.parametrize('optional', [
    {'annotations': {}}, {'annotations': 'invalid'}, {'audio': {}},
    {'function_call': {'name': 'never_call', 'arguments': '{}'}},
    {'tool_calls': [{'type': 'function', 'function': {'name': 'never_call', 'arguments': '{}'}}]},
    {'tool_calls': {}}, {'reasoning': {}}, {'reasoning_content': []}, {'unknown': None},
])
def test_malformed_metadata_and_active_actions_remain_uncertain(optional):
    from local_ai.provider import ProviderError
    value = envelope()
    value['choices'][0]['message'].update(optional)
    with peer(response(value)) as (url, requests):
        with pytest.raises(ProviderError) as caught:
            module().OpenAICompatibleProvider(settings(url), resolver=NoDNS()).generate(
                MESSAGES, SCHEMA, time.monotonic() + 3)
        assert caught.value.code == 'provider_failed' and caught.value.sent
        assert len(requests) == 1


@pytest.mark.parametrize('kind', ['ai', 'provider', 'os', 'timeout'])
def test_callback_primary_survives_one_owned_socket_close_failure(monkeypatch, kind):
    from local_ai.provider import ProviderError
    actual_socket = socket.socket
    closes = []
    primary = {'ai': AIError('source_revoked'), 'provider': ProviderError('provider_failed'),
               'os': OSError('SYNTHETIC callback'), 'timeout': TimeoutError('SYNTHETIC callback')}[kind]

    class Client:
        def __init__(self, *args, **kwargs):
            self.inner = actual_socket(*args, **kwargs)

        def __getattr__(self, name):
            return getattr(self.inner, name)

        def close(self):
            self.inner.close()
            closes.append(True)
            raise OSError('SYNTHETIC close diagnostic')

    def refuse():
        raise primary

    # Only the adapter client constructor is replaced; server accepts use real
    # sockets so the fixture is not the source of the cleanup failure.
    class SocketModule:
        AF_INET = socket.AF_INET
        SOCK_STREAM = socket.SOCK_STREAM
        socket = Client

    with peer() as (url, requests):
        target = module()
        monkeypatch.setattr(target, 'socket', SocketModule)
        adapter = target.OpenAICompatibleProvider(settings(url), resolver=NoDNS())
        with pytest.raises(Exception) as caught:
            adapter.generate(MESSAGES, SCHEMA, time.monotonic() + 3, before_send=refuse)
        assert closes == [True] and requests == []
        assert caught.value is primary


@pytest.mark.parametrize('status', [200, 401])
def test_cleanup_only_failure_is_fixed_uncertainty_even_in_an_outer_except(monkeypatch, status):
    from local_ai.provider import ProviderError
    actual_socket, closes = socket.socket, []

    class Client:
        def __init__(self, *args, **kwargs):
            self.inner = actual_socket(*args, **kwargs)

        def __getattr__(self, name):
            return getattr(self.inner, name)

        def close(self):
            self.inner.close()
            closes.append(self.inner.fileno())
            raise OSError('SYNTHETIC close diagnostic')

    class SocketModule:
        AF_INET = socket.AF_INET
        SOCK_STREAM = socket.SOCK_STREAM
        socket = Client

    with peer(response(envelope() if status == 200 else b'rejected', status)) as (url, requests):
        target = module()
        monkeypatch.setattr(target, 'socket', SocketModule)
        adapter = target.OpenAICompatibleProvider(settings(url), resolver=NoDNS())
        try:
            raise LookupError('unrelated caller exception')
        except LookupError:
            with pytest.raises(ProviderError) as caught:
                adapter.generate(MESSAGES, SCHEMA, time.monotonic() + 3)
        assert caught.value.code == 'provider_failed' and caught.value.sent
        assert 'SYNTHETIC' not in str(caught.value)
        assert closes == [-1] and len(requests) == 1
