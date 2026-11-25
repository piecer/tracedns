"""Bounded, single-attempt Chat Completions transport; no SDK or discovery.

The caller owns prompt preparation, privacy checks and durable reservation.
Only the explicit before_send boundary admits application bytes. Configuration
is detached without network/thread/trust-store activity in the constructor.
"""

import re
import socket
import ssl
import time
from types import MappingProxyType

from local_ai.contracts import AIError
from local_ai.provider import (
    CONTENT_LIMIT,
    PROMPT_LIMIT,
    REQUEST_LIMIT,
    ProviderError,
    ProviderReply,
    _Budget,
    _Reader,
    _check_proxy,
    _decode,
    _encode,
    _json_shape,
    _text_size,
)
from local_ai.provider_outcomes import HTTP_REJECTION_CODES, ProviderRejected
from local_ai.provider_settings import normalize_settings, parse_openai_url
from local_ai.resolver import _snapshot


class OpenAICompatibleProvider:
    """A detached profile borrowing the service's shared ResolverOwner.

    One public snapshot and its first candidate only: no address fallback.
    TLS verifies the original authority while the socket dials a vetted IP.
    """

    def __init__(self, settings, *, resolver, clock=time.monotonic):
        try:
            config = normalize_settings(settings)
            if (
                config["provider"] != "openai_compatible"
                or not config["base_url"]
                or not config["model"]
                or (config["endpoint_policy"] == "public_https" and not config.get("api_key"))
            ):
                raise AIError("invalid_request")
            self._endpoint = parse_openai_url(config["base_url"], config["endpoint_policy"])
        except AIError:
            raise ProviderError("invalid_request") from None
        self._config = MappingProxyType(config)
        self._resolver = resolver
        self._clock = clock

    def _packet(self, messages):
        body = _encode(
            {
                "model": self._config["model"],
                "messages": messages,
                "stream": False,
                "n": 1,
                "store": False,
                "response_format": {"type": "json_object"},
                self._config["token_limit_field"]: 512,
            },
            REQUEST_LIMIT,
        )
        auth = "Authorization: Bearer " + self._config["api_key"] + "\r\n" if self._config.get("api_key") else ""
        packet = (
            f"POST {self._endpoint.path} HTTP/1.1\r\nHost: {self._endpoint.authority}\r\n"
            f"Content-Length: {len(body)}\r\nContent-Type: application/json\r\n"
            "Accept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n"
            f"{auth}\r\n"
        ).encode("ascii") + body
        if len(packet) > REQUEST_LIMIT:
            raise ProviderError("too_large")
        return packet

    def _reply(self, value):
        if (
            type(value) is not dict
            or value.get("object") != "chat.completion"
            or "error" in value
            or type(value.get("model")) is not str
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}", value["model"]) is None
            or type(value.get("choices")) is not list
            or len(value["choices"]) != 1
        ):
            raise ProviderError("provider_failed")
        choice = value["choices"][0]
        if (
            type(choice) is not dict
            or type(choice.get("index")) is not int
            or choice["index"] != 0
            or choice.get("finish_reason") not in ("stop", "length", "content_filter")
            or "delta" in choice
        ):
            raise ProviderError("provider_failed")
        message = choice.get("message")
        if (
            type(message) is not dict
            or message.get("role") != "assistant"
            or "content" not in message
            or message.keys() - {"role", "content", "refusal", "annotations", "audio", "function_call",
                                 "tool_calls", "reasoning", "reasoning_content"}
            or (message["content"] is not None and type(message["content"]) is not str)
            or (message.get("refusal") is not None and type(message["refusal"]) is not str)
            or (message.get("annotations") is not None and type(message["annotations"]) is not list)
            or any(message.get(key) is not None and type(message[key]) is not str
                   for key in ("reasoning", "reasoning_content"))
            or message.get("audio") is not None or message.get("function_call") is not None
            or (message.get("tool_calls") is not None
                and not (type(message["tool_calls"]) is list and not message["tool_calls"]))
        ):
            raise ProviderError("provider_failed")
        # Standard inactive action fields are not tool requests. Bounded
        # annotations/reasoning are deliberately ignored, never cited, followed,
        # executed or copied into the public application result/metadata.
        metadata = {
            "provider": "openai_compatible",
            "requested_model": self._config["model"],
            "reported_model": value["model"],
            "finish_reason": choice["finish_reason"],
            "response_format": "json_object",
        }
        usage = value.get("usage")
        if usage is not None:
            if type(usage) is not dict:
                raise ProviderError("provider_failed")
            for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
                if key in usage:
                    number = usage[key]
                    if type(number) is not int or not 0 <= number <= (1 << 63) - 1:
                        raise ProviderError("provider_failed")
                    metadata[key] = number
            if {"prompt_tokens", "completion_tokens", "total_tokens"} <= usage.keys() and usage[
                "prompt_tokens"
            ] + usage["completion_tokens"] != usage["total_tokens"]:
                raise ProviderError("provider_failed")
        metadata = MappingProxyType(metadata)
        content = message["content"]
        if content is not None:
            try:
                _text_size(content, CONTENT_LIMIT)
            except ProviderError as error:
                if error.code == "too_large":
                    return ProviderReply(None, metadata, "too_large")
                raise ProviderError("provider_failed") from None
        if not content or choice["finish_reason"] != "stop" or message.get("refusal") is not None:
            return ProviderReply(None, metadata, "invalid_model_output")
        return ProviderReply(content, metadata)

    def generate(self, messages, schema, deadline, *, before_send=None):
        """Return an on-time completion or the exact closed rejection receipt.

        The existing two-role prompt must already contain its JSON instruction
        and schema. It is never rewritten here. Packets are frozen before the
        synchronous latest pre-send callback; callback exceptions are unchanged.
        A returned refusal/length/empty-content receipt settles transport only,
        not application output. The configured origin is trusted to honor the
        explicit HTTP rejection statuses; other outcomes remain uncertain.
        """
        budget = _Budget(self._clock, deadline)
        _check_proxy()
        if before_send is not None and not callable(before_send):
            raise ProviderError("invalid_request")
        if type(messages) is not list or len(messages) != 2 or type(schema) is not dict:
            raise ProviderError("invalid_request")
        prompt_bytes = 0
        for message, role in zip(messages, ("system", "user")):
            if (
                type(message) is not dict
                or message.keys() != {"role", "content"}
                or type(message["role"]) is not str
                or message["role"] != role
            ):
                raise ProviderError("invalid_request")
            prompt_bytes += _text_size(message["content"])
        _json_shape(schema)
        if prompt_bytes + len(_encode(schema, PROMPT_LIMIT)) > PROMPT_LIMIT:
            raise ProviderError("too_large")
        packet = self._packet(messages)
        endpoint = self._endpoint
        sent = False
        admitting = False
        completed = False
        sock = None
        try:
            family = endpoint.family
            if family is None:
                rows = self._resolver.resolve(endpoint.host, endpoint.port, deadline)
                budget.remaining()
                rows = _snapshot(rows, endpoint.port)
                family, _, _, _, address = rows[0]
            else:
                host = "127.0.0.1" if endpoint.host == "localhost" else endpoint.host
                address = (host, endpoint.port) if family == socket.AF_INET else (host, endpoint.port, 0, 0)
            budget.remaining()
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(budget.remaining())
            sock.connect(address)
            budget.remaining()
            if endpoint.scheme == "https":
                context = ssl.create_default_context()
                if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                    raise ProviderError("provider_failed")
                context.set_alpn_protocols(["http/1.1"])
                sock.settimeout(budget.remaining())
                # EOF framing needs authenticated TLS shutdown. Complete length/
                # chunk framing returns without another read, even on ragged close.
                sock = context.wrap_socket(
                    sock, server_hostname=endpoint.host, do_handshake_on_connect=False,
                    suppress_ragged_eofs=False,
                )
                sock.settimeout(budget.remaining())
                sock.do_handshake()
            _check_proxy()
            budget.remaining()
            if before_send is not None:
                admitting = True
                before_send()
                admitting = False
            sent = True
            _check_proxy()
            sock.settimeout(budget.remaining())
            sock.sendall(packet)
            reader = _Reader(sock, budget)
            data = reader.response(_rejection_statuses=HTTP_REJECTION_CODES)
            budget.remaining()
            if reader.status in HTTP_REJECTION_CODES:
                rejected = ProviderRejected(reader.status)
                completed = True
                return rejected
            value = _decode(data)
            budget.remaining()
            reply = self._reply(value)
            budget.remaining()
            completed = True
            return reply
        except ProviderError as error:
            if admitting:
                raise
            error.sent = sent
            raise
        except TimeoutError:
            if admitting:
                raise
            raise ProviderError("deadline_exceeded", sent=sent) from None
        except OSError:
            if admitting:
                raise
            raise ProviderError("provider_failed", sent=sent) from None
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    # A secondary close failure must not replace an admission
                    # callback's original exception. Cleanup-only failure is
                    # still a fixed uncertain outcome, never a successful reply.
                    if completed:
                        raise ProviderError("provider_failed", sent=sent) from None
