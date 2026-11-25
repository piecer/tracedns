"""Bounded, synchronous native Ollama transport for one fixed local model.

No constructor I/O, DNS lookup, proxies, redirects, retries, downloads, tools,
unload requests or background transport workers. Each generate call checks the
local catalog, then admits exactly one native chat request. The service owns
durable settlement/quarantine; this adapter does not manage provider processes.

The prompt budget counts UTF-8 message text plus the compact schema JSON (even
though the schema is also sent as native format metadata). The request budget
includes HTTP framing. Response framing and decoded native JSON bytes have
separate bounds; compression, chunk extensions and trailers are unsupported.

Catalog identity is observed configuration provenance, not cryptographic
attestation of execution. The runtime owner must keep model/template immutable.
"""

import ipaddress
import json
import math
import os
import re
import socket
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

PROMPT_LIMIT = 16 * 1024
REQUEST_LIMIT = 64 * 1024
ENVELOPE_LIMIT = 64 * 1024
CONTENT_LIMIT = 16 * 1024
HEADER_LIMIT = 16 * 1024
JSON_DEPTH_LIMIT = 16
JSON_NODE_LIMIT = 4096
MAX_DEADLINE_SECONDS = 120


def _text_size(value, limit=PROMPT_LIMIT):
    if type(value) is not str:
        raise ProviderError("invalid_request")
    # Check character count BEFORE allocating its encoded representation.
    if len(value) > limit:
        raise ProviderError("too_large")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise ProviderError("invalid_request") from None
    if size > limit:
        raise ProviderError("too_large")
    return size


def _json_shape(value, scalar_limit=PROMPT_LIMIT):
    count = 0

    def visit(item, depth):
        nonlocal count
        count += 1
        if count > JSON_NODE_LIMIT or depth > JSON_DEPTH_LIMIT:
            raise ProviderError("too_large")
        kind = type(item)
        if kind is str:
            _text_size(item, scalar_limit)
        elif kind in (dict, list):
            if len(item) > JSON_NODE_LIMIT:
                raise ProviderError("too_large")
            if kind is dict:
                for key, child in item.items():
                    _text_size(key, scalar_limit)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
        elif kind is int:
            if item.bit_length() > 64:
                raise ProviderError("invalid_request")
        elif kind is float:
            if not math.isfinite(item):
                raise ProviderError("invalid_request")
        elif item is not None and kind is not bool:
            raise ProviderError("invalid_request")

    visit(value, 0)


def _encode(value, limit):
    # Shape/scalar admission must precede this bounded streaming serialization.
    output = bytearray()
    encoder = json.JSONEncoder(ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    for part in encoder.iterencode(value):
        data = part.encode("utf-8")
        if len(output) + len(data) > limit:
            raise ProviderError("too_large")
        output.extend(data)
    return bytes(output)


def _decode(data):
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    def reject_constant(_):
        raise ValueError

    # Bound nesting before the recursive stdlib decoder can allocate a deep tree.
    depth, quoted, escaped = 0, False, False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > JSON_DEPTH_LIMIT:
                raise ProviderError("provider_failed")
        elif byte in (93, 125):
            depth -= 1
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=reject_constant)
        _json_shape(value, ENVELOPE_LIMIT)
    except (ValueError, UnicodeError, RecursionError, ProviderError):
        raise ProviderError("provider_failed") from None
    return value


def _cloud_marker(value):
    if type(value) is dict:
        return any(
            "cloud" in key.lower() or key.lower().startswith("remote_") or _cloud_marker(child)
            for key, child in value.items()
        )
    if type(value) is list:
        return any(_cloud_marker(child) for child in value)
    return False


class ProviderError(Exception):
    """Fixed failure with conservative provider-settlement classification.

    sent=True means before_send returned successfully, NOT that bytes were
    acknowledged. Even a subsequent pre-write failure must retain the parent's
    reservation; no error is evidence that opaque provider work has stopped.
    """

    def __init__(self, code: str, *, sent: bool = False) -> None:
        if code not in {"invalid_request", "too_large", "model_unavailable", "provider_failed", "deadline_exceeded"}:
            code = "provider_failed"
        self.code = code
        self.sent = bool(sent)
        super().__init__(code)


def _origin(origin):
    if type(origin) is not str or len(origin) > 128:
        raise ProviderError("invalid_request")
    match = re.fullmatch(r"http://(localhost|[0-9.]+|\[[0-9a-fA-F:]+\]):([1-9][0-9]{0,4})", origin)
    if match is None or int(match[2]) > 65535:
        raise ProviderError("invalid_request")
    host = "127.0.0.1" if match[1] == "localhost" else match[1].strip("[]")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise ProviderError("invalid_request") from None
    if not address.is_loopback:
        raise ProviderError("invalid_request")
    return str(address), int(match[2]), socket.AF_INET if address.version == 4 else socket.AF_INET6


def _check_proxy():
    if any(value for key, value in os.environ.items() if key.lower() in {"http_proxy", "https_proxy", "all_proxy"}):
        raise ProviderError("provider_failed")


@dataclass(frozen=True)
class NativeReply:
    """Accepted done=True envelope; content is intentionally not JSON-decoded.

    This lets the service settle its interlock before validating model-authored
    JSON. metadata contains only configured identity and checked native counters.
    """

    content: str | None
    metadata: Mapping[str, str | int]
    content_error: str | None = None


# Exact type identity preserves the engine's native receipt admission.
ProviderReply = NativeReply


class _Reader:
    """One socket, bounded HTTP/1 framing, no makefile read-ahead or redirects."""

    def __init__(self, sock, budget):
        self.sock = sock
        self.budget = budget
        self.buffer = bytearray()
        self.framing_left = HEADER_LIMIT

    def receive(self, size):
        self.sock.settimeout(self.budget.remaining())
        data = self.sock.recv(size)
        self.budget.remaining()
        return data

    def line(self):
        while True:
            self.budget.remaining()
            end = self.buffer.find(b"\r\n")
            if end >= 0:
                size = end + 2
                self.charge(size)
                result = bytes(self.buffer[:end])
                del self.buffer[:size]
                return result
            if len(self.buffer) >= self.framing_left:
                raise ProviderError("too_large")
            data = self.receive(min(4096, self.framing_left - len(self.buffer)))
            if not data:
                raise ProviderError("provider_failed")
            self.buffer.extend(data)

    def charge(self, size):
        self.framing_left -= size
        if self.framing_left < 0:
            raise ProviderError("too_large")

    def exact(self, size):
        self.budget.remaining()
        result = bytearray(self.buffer[:size])
        del self.buffer[:size]
        while len(result) < size:
            data = self.receive(min(4096, size - len(result)))
            if not data:
                raise ProviderError("provider_failed")
            result.extend(data)
        return bytes(result)

    def to_eof(self):
        result = self.buffer
        self.buffer = bytearray()
        while True:
            if len(result) > ENVELOPE_LIMIT:
                raise ProviderError("too_large")
            data = self.receive(min(4096, ENVELOPE_LIMIT + 1 - len(result)))
            if not data:
                return bytes(result)
            result.extend(data)

    def response(self, *, _rejection_statuses=()):
        # Native callers retain the exact 2xx/body-only behavior. Compatible
        # callers may opt into complete framing for their closed rejection set.
        status = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3})(?: [\x20-\x7e]*)?", self.line())
        if status is None or not (200 <= int(status[1]) < 300 or int(status[1]) in _rejection_statuses):
            raise ProviderError("provider_failed")
        self.status = int(status[1])
        headers = {}
        while line := self.line():
            name, separator, value = line.partition(b":")
            if (
                not separator
                or re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) is None
                or re.fullmatch(rb"[\x09\x20-\x7e]*", value) is None
                or name.lower() in headers
            ):
                raise ProviderError("provider_failed")
            headers[name.lower()] = value.strip().lower()
        if (
            (
                self.status not in _rejection_statuses
                and headers.get(b"content-type") not in {b"application/json", b"application/json; charset=utf-8"}
            )
            or headers.get(b"content-encoding", b"identity") != b"identity"
        ):
            raise ProviderError("provider_failed")
        transfer = headers.get(b"transfer-encoding")
        length = headers.get(b"content-length")
        if transfer is not None:
            if transfer != b"chunked" or length is not None:
                raise ProviderError("provider_failed")
            result = bytearray()
            while True:
                line = self.line()
                if re.fullmatch(rb"[0-9a-fA-F]{1,8}", line) is None:
                    raise ProviderError("provider_failed")
                size = int(line, 16)
                if len(result) + size > ENVELOPE_LIMIT:
                    raise ProviderError("too_large")
                if size == 0:
                    # Native JSON has no trailers; refuse unvetted trailer semantics.
                    if self.line() != b"":
                        raise ProviderError("provider_failed")
                    return bytes(result)
                result.extend(self.exact(size))
                self.charge(2)
                if self.exact(2) != b"\r\n":
                    raise ProviderError("provider_failed")
        if length is not None:
            if re.fullmatch(rb"[0-9]{1,10}", length) is None:
                raise ProviderError("provider_failed")
            size = int(length)
            if size > ENVELOPE_LIMIT:
                raise ProviderError("too_large")
            return self.exact(size)
        return self.to_eof()


class _Budget:
    def __init__(self, clock, deadline):
        if type(deadline) not in (int, float):
            raise ProviderError("invalid_request")
        try:
            finite = math.isfinite(deadline)
        except OverflowError:
            finite = False
        if not finite:
            raise ProviderError("invalid_request")
        self.clock = clock
        self.deadline = deadline
        if self.remaining() > MAX_DEADLINE_SECONDS:
            raise ProviderError("invalid_request")

    def remaining(self):
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise ProviderError("deadline_exceeded")
        return remaining


class OllamaProvider:
    def __init__(
        self, origin: str, model: str, model_digest: str, *, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._host, self._port, self._family = _origin(origin)
        if (
            type(model) is not str
            or len(model) > 256
            or "cloud" in model.lower()
            or re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._/-]*:[a-zA-Z0-9][a-zA-Z0-9._-]*", model) is None
            or type(model_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", model_digest) is None
        ):
            raise ProviderError("model_unavailable")
        self._model = model
        self._digest = model_digest
        self._clock = clock

    def _catalog(self, value):
        if type(value) is not dict or "error" in value or type(value.get("models")) is not list:
            raise ProviderError("model_unavailable")
        if _cloud_marker({key: child for key, child in value.items() if key != "models"}):
            raise ProviderError("model_unavailable")
        matches = [
            entry
            for entry in value["models"]
            if type(entry) is dict and (entry.get("name") == self._model or entry.get("model") == self._model)
        ]
        if len(matches) != 1:
            raise ProviderError("model_unavailable")
        entry = matches[0]
        details = entry.get("details")
        if (
            entry.get("name") != self._model
            or entry.get("model") != self._model
            or entry.get("digest") != self._digest
            or type(details) is not dict
            or details.get("format") != "gguf"
            or details.get("family") != "qwen35"
            or details.get("families") != ["qwen35"]
            or _cloud_marker(entry)
        ):
            raise ProviderError("model_unavailable")

    def _reply(self, value):
        if (
            type(value) is not dict
            or value.get("done") is not True
            or value.get("model") != self._model
            or "error" in value
            or _cloud_marker(value)
            or any(key in value and value[key] != self._digest for key in ("digest", "model_digest"))
        ):
            raise ProviderError("provider_failed")
        message = value.get("message")
        if (
            type(message) is not dict
            or message.get("role") != "assistant"
            or type(message.get("content")) is not str
            or message.keys() - {"role", "content", "thinking"}
            or message.get("thinking", "") != ""
        ):
            raise ProviderError("provider_failed")
        metadata: dict[str, str | int] = {"model": self._model, "model_digest": self._digest}
        if "done_reason" in value:
            if value["done_reason"] not in ("stop", "length"):
                raise ProviderError("provider_failed")
            metadata["done_reason"] = value["done_reason"]
        for key in (
            "eval_count",
            "prompt_eval_count",
            "total_duration",
            "load_duration",
            "prompt_eval_duration",
            "eval_duration",
        ):
            if key in value:
                number = value[key]
                if type(number) is not int or not 0 <= number <= (1 << 63) - 1:
                    raise ProviderError("provider_failed")
                metadata[key] = number
        # Inner prose policy is not native settlement. Validate the entire
        # native envelope first, then discard oversized content explicitly.
        try:
            _text_size(message["content"], CONTENT_LIMIT)
        except ProviderError as error:
            if error.code != "too_large":
                raise
            return NativeReply(None, MappingProxyType(metadata), "too_large")
        return NativeReply(message["content"], MappingProxyType(metadata))

    def _packet(self, method, path, body):
        body = body or b""
        host = f"[{self._host}]" if self._family == socket.AF_INET6 else self._host
        packet = (
            f"{method} {path} HTTP/1.1\r\nHost: {host}:{self._port}\r\n"
            f"Content-Length: {len(body)}\r\nContent-Type: application/json\r\n"
            "Accept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
        ).encode() + body
        if len(packet) > REQUEST_LIMIT:
            raise ProviderError("too_large")
        return packet

    def _exchange(self, packet, budget, before_send=None):
        _check_proxy()
        budget.remaining()
        try:
            sock = socket.socket(self._family, socket.SOCK_STREAM)
        except OSError:
            raise ProviderError("provider_failed") from None
        try:
            try:
                sock.settimeout(budget.remaining())
                sock.connect((self._host, self._port))
            except TimeoutError:
                raise ProviderError("deadline_exceeded") from None
            except OSError:
                raise ProviderError("provider_failed") from None
            _check_proxy()
            budget.remaining()
            if before_send is not None:
                before_send()
            _check_proxy()
            try:
                sock.settimeout(budget.remaining())
                sock.sendall(packet)
                data = _Reader(sock, budget).response()
            except TimeoutError:
                raise ProviderError("deadline_exceeded") from None
            except OSError:
                raise ProviderError("provider_failed") from None
            budget.remaining()
            result = _decode(data)
            budget.remaining()
            return result
        finally:
            sock.close()

    def generate(
        self,
        messages: list[dict[str, str]],
        schema: dict[str, Any],
        deadline: float,
        *,
        before_send: Callable[[], None],
    ) -> NativeReply:
        """Use the caller's absolute monotonic deadline, never extending it.

        before_send is synchronous and runs after all preparation, catalog
        validation and connection setup, immediately before the inference write.
        It must perform the service's durable reservation and reauthorization.
        Its exceptions propagate unchanged; the service owns callback atomicity.
        """
        budget = _Budget(self._clock, deadline)
        _check_proxy()
        if not callable(before_send):
            raise ProviderError("invalid_request")
        if type(messages) is not list or not 1 <= len(messages) <= 16 or type(schema) is not dict:
            raise ProviderError("invalid_request")
        prompt_bytes = 0
        for message in messages:
            if (
                type(message) is not dict
                or message.keys() != {"role", "content"}
                or type(message["role"]) is not str
                or message["role"] not in {"system", "user", "assistant"}
            ):
                raise ProviderError("invalid_request")
            prompt_bytes += _text_size(message["content"])
            if prompt_bytes > PROMPT_LIMIT:
                raise ProviderError("too_large")
        _json_shape(schema)
        if prompt_bytes + len(_encode(schema, PROMPT_LIMIT)) > PROMPT_LIMIT:
            raise ProviderError("too_large")
        body = _encode(
            {
                "model": self._model,
                "messages": messages,
                "format": schema,
                "think": False,
                "stream": False,
                "options": {"num_gpu": 0, "num_thread": 4, "num_ctx": 32768, "num_predict": 512, "temperature": 0},
            },
            REQUEST_LIMIT,
        )
        packet = self._packet("POST", "/api/chat", body)
        budget.remaining()
        self._catalog(self._exchange(self._packet("GET", "/api/tags", None), budget))
        sent = False

        def admit():
            nonlocal sent
            before_send()
            sent = True

        try:
            result = self._reply(self._exchange(packet, budget, admit))
            budget.remaining()
            return result
        except ProviderError as error:
            error.sent = sent
            raise
