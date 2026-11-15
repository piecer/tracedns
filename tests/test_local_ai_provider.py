"""Native adapter contract; all HTTP peers are invocation-owned loopback fakes."""

import importlib
import json
import socket
import socketserver
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

MODEL = "qwen3.5:9b"
DIGEST = "6488c96fa5faab64bb65cbd30d4289e20e6130ef535a93ef9a49f42eda893ea7"
MESSAGES = [{"role": "system", "content": "Return JSON."}, {"role": "user", "content": "Synthetic evidence."}]
SCHEMA = {"type": "object", "additionalProperties": False}


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def catalog():
    return {
        "models": [
            {
                "name": MODEL,
                "model": MODEL,
                "digest": DIGEST,
                "size": 123,
                "details": {"format": "gguf", "family": "qwen35", "families": ["qwen35"]},
            }
        ]
    }


def envelope(content='{"ok":true}'):
    return {
        "model": MODEL,
        "message": {"role": "assistant", "content": content},
        "done": True,
        "done_reason": "stop",
        "eval_count": 7,
        "prompt_eval_count": 12,
    }


def http_response(body, *, status=200, headers=()):
    if not isinstance(body, bytes):
        body = encoded(body)
    fields = [("Content-Type", "application/json"), ("Content-Length", str(len(body))), *headers]
    return (f"HTTP/1.1 {status} Test\r\n" + "".join(f"{key}: {value}\r\n" for key, value in fields) + "\r\n").encode(
        "ascii"
    ) + body


@contextmanager
def peer(*, tags=None, chat=None, host="127.0.0.1"):
    """Own listener + every worker; teardown also interrupts adversarial drips."""
    stop = threading.Event()
    requests = []
    routes = {
        "/api/tags": http_response(catalog()) if tags is None else tags,
        "/api/chat": http_response(envelope()) if chat is None else chat,
    }

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            data = bytearray()
            try:
                while b"\r\n\r\n" not in data:
                    part = self.request.recv(4096)
                    if not part:
                        return
                    data.extend(part)
                    assert len(data) <= 100_000
                head, body = bytes(data).split(b"\r\n\r\n", 1)
                method, path, _ = head.split(b"\r\n", 1)[0].decode("ascii").split(" ")
                fields = dict(line.decode("ascii").split(": ", 1) for line in head.split(b"\r\n")[1:])
                length = int(fields.get("Content-Length", "0"))
                while len(body) < length:
                    part = self.request.recv(min(4096, length - len(body)))
                    if not part:
                        return
                    body += part
                requests.append({"method": method, "path": path, "headers": fields, "body": body})
                response = routes[path]
                if callable(response):
                    response(self.request, stop)
                else:
                    self.request.sendall(response)
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                pass

    class Server(socketserver.ThreadingTCPServer):
        address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
        allow_reuse_address = True
        daemon_threads = False
        block_on_close = True

    server = Server((host, 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    try:
        authority = f"[{host}]" if ":" in host else host
        yield f"http://{authority}:{server.server_address[1]}", requests, routes
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
        thread.join(2)
        assert not thread.is_alive()


@pytest.fixture(autouse=True)
def no_proxy(monkeypatch):
    # Deliberately remove proxy settings only inside this isolated test process.
    import os

    for name in list(os.environ):
        if name.lower().endswith("_proxy"):
            monkeypatch.delenv(name)


def adapter():
    try:
        module = importlib.import_module("local_ai.provider")
    except ModuleNotFoundError:
        pytest.fail("native bounded Ollama adapter is missing")
    assert Path(module.__file__).resolve() == Path(__file__).resolve().parents[1] / "local_ai" / "provider.py"
    return module


def test_native_exchange_preflights_before_admission_and_sends_fixed_policy():
    module = adapter()
    with peer() as (origin, requests, _):
        provider = module.OllamaProvider(origin, MODEL, DIGEST)
        assert requests == [], "constructor must never contact a provider"
        callbacks = []

        def admit():
            callbacks.append([row["path"] for row in requests])

        result = provider.generate(MESSAGES, SCHEMA, time.monotonic() + 2, before_send=admit)
        assert isinstance(result, module.NativeReply)
        assert result.content == '{"ok":true}'
        assert result.metadata["model"] == MODEL
        assert result.metadata["model_digest"] == DIGEST
        assert callbacks == [["/api/tags"]]
        assert [(row["method"], row["path"]) for row in requests] == [("GET", "/api/tags"), ("POST", "/api/chat")]
        payload = json.loads(requests[1]["body"])
        assert payload == {
            "model": MODEL,
            "messages": MESSAGES,
            "format": SCHEMA,
            "think": False,
            "stream": False,
            "options": {"num_gpu": 0, "num_thread": 4, "num_ctx": 32768, "num_predict": 512, "temperature": 0},
        }
        assert requests[1]["headers"]["Accept-Encoding"] == "identity"
        with pytest.raises(TypeError):
            result.metadata["model"] = "changed"


@pytest.mark.parametrize(
    "origin",
    [
        "http://example.invalid:11434",
        "http://192.0.2.1:11434",
        "http://0.0.0.0:11434",
        "http://127.1:11434",
        "http://2130706433:11434",
        "http://0177.0.0.1:11434",
        "http://[::ffff:127.0.0.1]:11434",
        "http://[::]:11434",
        "http://[::1%lo]:11434",
        "https://127.0.0.1:11434",
        "http://127.0.0.1",
        "http://127.0.0.1:0",
        "http://127.0.0.1:65536",
        "http://user:secret@127.0.0.1:11434",
        "http://127.0.0.1:11434/",
        "http://127.0.0.1:11434/api/chat",
        "http://127.0.0.1:11434?",
        "http://127.0.0.1:11434#",
        " http://127.0.0.1:11434",
        "http://127.0.0.1:\n11434",
        None,
        123,
    ],
)
def test_origin_validation_is_literal_closed_and_network_free(origin):
    module = adapter()
    with pytest.raises(Exception) as caught:
        module.OllamaProvider(origin, MODEL, DIGEST)
    assert type(caught.value).__name__ == "ProviderError"
    assert caught.value.code == "invalid_request"
    assert caught.value.sent is False
    assert str(caught.value) == "invalid_request"


def test_localhost_is_pinned_without_dns(monkeypatch):
    import socket

    module = adapter()
    with peer() as (origin, requests, _):

        def deny_dns(*args, **kwargs):
            pytest.fail("literal loopback transport must not resolve names")

        monkeypatch.setattr(socket, "getaddrinfo", deny_dns)
        provider = module.OllamaProvider(origin.replace("127.0.0.1", "localhost"), MODEL, DIGEST)
        reply = provider.generate(MESSAGES, SCHEMA, time.monotonic() + 2, before_send=lambda: None)
        assert reply.content == '{"ok":true}'
        assert len(requests) == 2


@pytest.mark.parametrize(
    "name", ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "HtTp_PrOxY"]
)
def test_proxy_environment_fails_closed_with_zero_sink_hits(monkeypatch, name):
    module = adapter()
    with peer() as (origin, requests, _), peer() as (sink, sink_requests, _):
        provider = module.OllamaProvider(origin, MODEL, DIGEST)
        monkeypatch.setenv(name, sink)
        callbacks = []
        with pytest.raises(Exception) as caught:
            provider.generate(MESSAGES, SCHEMA, time.monotonic() + 2, before_send=lambda: callbacks.append(1))
        assert type(caught.value).__name__ == "ProviderError"
        assert caught.value.code == "provider_failed"
        assert caught.value.sent is False
        assert requests == sink_requests == callbacks == []


@pytest.mark.parametrize(
    "model,digest",
    [
        ("qwen3.5:9b-cloud", DIGEST),
        ("qwen3.5:cloud", DIGEST),
        ("cloud/model:9b", DIGEST),
        ("qwen3.5\r\n:9b", DIGEST),
        (MODEL, "a" * 63),
        (MODEL, "A" * 64),
        (MODEL, "sha256:" + DIGEST),
        (None, DIGEST),
        (MODEL, None),
        ("x" * 257, DIGEST),
    ],
)
def test_bad_configured_identity_is_refused_without_network(model, digest):
    module = adapter()
    with pytest.raises(module.ProviderError, match="model_unavailable") as caught:
        module.OllamaProvider("http://127.0.0.1:11434", model, digest)
    assert caught.value.sent is False


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "digest",
        "model",
        "duplicate",
        "format",
        "family",
        "families",
        "remote_host",
        "remote_model",
        "cloud",
        "error",
        "bad_shape",
    ],
)
def test_catalog_failure_never_runs_admission_or_inference(fault):
    value = catalog()
    entry = value["models"][0]
    if fault == "missing":
        value["models"] = []
    elif fault == "digest":
        entry["digest"] = "b" * 64
    elif fault == "model":
        entry["model"] = "other:9b"
    elif fault == "duplicate":
        value["models"].append(dict(entry))
    elif fault in {"format", "family", "families"}:
        entry["details"][fault] = {"format": "safetensors", "family": "llama", "families": ["qwen35", "llama"]}[fault]
    elif fault == "error":
        value["error"] = "SYNTHETIC_SECRET_ERROR"
    elif fault == "bad_shape":
        value["models"] = {}
    else:
        entry[fault] = "SYNTHETIC_CLOUD_HOST"
    module = adapter()
    with peer(tags=http_response(value)) as (origin, requests, _):
        callbacks = []
        with pytest.raises(module.ProviderError) as caught:
            module.OllamaProvider(origin, MODEL, DIGEST).generate(
                MESSAGES, SCHEMA, time.monotonic() + 2, before_send=lambda: callbacks.append(1)
            )
        assert caught.value.code == "model_unavailable"
        assert caught.value.sent is False
        assert str(caught.value) == "model_unavailable"
        assert callbacks == []
        assert [row["path"] for row in requests] == ["/api/tags"]


def test_admission_refusal_is_propagated_without_inference():
    module = adapter()
    refusal = RuntimeError("parent admission declined")

    def decline():
        raise refusal

    with peer() as (origin, requests, _):
        with pytest.raises(RuntimeError) as caught:
            module.OllamaProvider(origin, MODEL, DIGEST).generate(
                MESSAGES, SCHEMA, time.monotonic() + 2, before_send=decline
            )
        assert caught.value is refusal
        assert [row["path"] for row in requests] == ["/api/tags"]


@pytest.mark.parametrize("extra", [0, 1])
@pytest.mark.parametrize("unit", ["a", "한"])
def test_complete_utf8_prompt_limit_includes_system_and_schema_text(extra, unit):
    # Schema is charged conservatively even though it is also native format metadata.
    room = 16 * 1024 - len(encoded(SCHEMA)) - len("instructions".encode())
    text = unit * (room // len(unit.encode())) + "x" * (room % len(unit.encode()) + extra)
    messages = [{"role": "system", "content": "instructions"}, {"role": "user", "content": text}]
    module = adapter()
    with peer() as (origin, requests, _):
        provider = module.OllamaProvider(origin, MODEL, DIGEST)
        callbacks = []
        if extra:
            with pytest.raises(module.ProviderError, match="too_large") as caught:
                provider.generate(messages, SCHEMA, time.monotonic() + 2, before_send=lambda: callbacks.append(1))
            assert caught.value.sent is False
            assert callbacks == requests == []
        else:
            assert provider.generate(
                messages, SCHEMA, time.monotonic() + 2, before_send=lambda: callbacks.append(1)
            ).content
            assert callbacks == [1]


@pytest.mark.parametrize("extra", [0, 1])
def test_http_request_has_separate_exact_byte_limit(extra):
    payload = {
        "model": MODEL,
        "messages": [{"role": "user", "content": ""}],
        "format": SCHEMA,
        "think": False,
        "stream": False,
        "options": {"num_gpu": 0, "num_thread": 4, "num_ctx": 32768, "num_predict": 512, "temperature": 0},
    }
    module = adapter()
    with peer() as (origin, requests, _):
        # The hard request cap covers HTTP framing too, not just JSON bytes.
        head = (
            f"POST /api/chat HTTP/1.1\r\nHost: {origin.removeprefix('http://')}\r\n"
            "Content-Length: 65536\r\nContent-Type: application/json\r\nAccept: application/json\r\n"
            "Accept-Encoding: identity\r\nConnection: close\r\n\r\n"
        ).encode()
        room = 64 * 1024 - len(head) - len(encoded(payload)) + extra
        payload["messages"][0]["content"] = "\x01" * (room // 6) + "x" * (room % 6)
        assert len(encoded(payload)) + len(head) == 64 * 1024 + extra
        provider = module.OllamaProvider(origin, MODEL, DIGEST)
        if extra:
            with pytest.raises(module.ProviderError, match="too_large") as caught:
                provider.generate(payload["messages"], SCHEMA, time.monotonic() + 2, before_send=lambda: None)
            assert caught.value.sent is False
            assert requests == []
        else:
            assert provider.generate(payload["messages"], SCHEMA, time.monotonic() + 2, before_send=lambda: None)
            assert len(requests[-1]["body"]) + len(head) == 64 * 1024


@pytest.mark.parametrize("unit", ["x", "한"])
def test_scalar_is_bounded_before_json_encoder(monkeypatch, unit):
    module = adapter()
    with peer() as (origin, requests, _):
        seen = []
        original = json.JSONEncoder.iterencode

        def observe(self, value, *args, **kwargs):
            seen.append(type(value).__name__)
            return original(self, value, *args, **kwargs)

        monkeypatch.setattr(json.JSONEncoder, "iterencode", observe)
        with pytest.raises(module.ProviderError, match="too_large"):
            module.OllamaProvider(origin, MODEL, DIGEST).generate(
                [{"role": "user", "content": unit * (16 * 1024 + 1)}],
                SCHEMA,
                time.monotonic() + 2,
                before_send=lambda: None,
            )
        assert seen == requests == []


@pytest.mark.parametrize(
    "messages,schema",
    [
        ([], SCHEMA),
        ({"role": "user", "content": "x"}, SCHEMA),
        ([{"role": "tool", "content": "x"}], SCHEMA),
        ([{"role": "user", "content": "x", "tools": []}], SCHEMA),
        ([{"role": "user", "content": 1}], SCHEMA),
        (MESSAGES, []),
        (MESSAGES, {"value": float("nan")}),
        (MESSAGES, {"value": float("inf")}),
        (MESSAGES, {1: "non-string key"}),
        (MESSAGES, {"value": object()}),
    ],
)
def test_request_shapes_fail_before_metadata_or_admission(messages, schema):
    module = adapter()
    with peer() as (origin, requests, _):
        callbacks = []
        with pytest.raises(module.ProviderError, match="invalid_request") as caught:
            module.OllamaProvider(origin, MODEL, DIGEST).generate(
                messages, schema, time.monotonic() + 2, before_send=lambda: callbacks.append(1)
            )
        assert caught.value.sent is False
        assert requests == callbacks == []


def test_nested_schema_is_refused_before_encoding(monkeypatch):
    module = adapter()
    schema = {}
    for _ in range(32):
        schema = {"nested": schema}
    with peer() as (origin, requests, _):
        with pytest.raises(module.ProviderError):
            module.OllamaProvider(origin, MODEL, DIGEST).generate(
                MESSAGES, schema, time.monotonic() + 2, before_send=lambda: pytest.fail("late admission")
            )
        assert requests == []


@pytest.mark.parametrize("content", ["NOT JSON", "{broken", '{"duplicate":1,"duplicate":2}', ""])
def test_complete_native_envelope_is_settled_even_when_content_is_invalid_json(content):
    module = adapter()
    with peer(chat=http_response(envelope(content))) as (origin, requests, _):
        result = module.OllamaProvider(origin, MODEL, DIGEST).generate(
            MESSAGES, SCHEMA, time.monotonic() + 2, before_send=lambda: None
        )
        assert isinstance(result, module.NativeReply)
        assert result.content == content
        assert result.metadata["eval_count"] == 7
        assert set(result.metadata) == {"model", "model_digest", "done_reason", "eval_count", "prompt_eval_count"}
        assert len(requests) == 2


@pytest.mark.parametrize(
    "fault",
    [
        "done_false",
        "done_missing",
        "done_integer",
        "message_missing",
        "role",
        "content_type",
        "model",
        "digest",
        "model_digest",
        "remote_host",
        "error",
        "tool_calls",
        "thinking",
        "eval_count",
        "done_reason",
    ],
)
def test_malformed_native_completion_is_unsettled(fault):
    value = envelope()
    if fault == "done_false":
        value["done"] = False
    elif fault == "done_missing":
        del value["done"]
    elif fault == "done_integer":
        value["done"] = 1
    elif fault == "message_missing":
        del value["message"]
    elif fault == "role":
        value["message"]["role"] = "tool"
    elif fault == "content_type":
        value["message"]["content"] = []
    elif fault == "model":
        value["model"] = "other:9b"
    elif fault in {"digest", "model_digest"}:
        value[fault] = "b" * 64
    elif fault == "tool_calls":
        value["message"]["tool_calls"] = [{"function": {"name": "bad"}}]
    elif fault == "thinking":
        value["message"]["thinking"] = "unexpected reasoning"
    elif fault == "eval_count":
        value["eval_count"] = True
    else:
        value[fault] = "SYNTHETIC_SECRET"
    module = adapter()
    with peer(chat=http_response(value)) as (origin, requests, _):
        callbacks = []
        with pytest.raises(module.ProviderError, match="provider_failed") as caught:
            module.OllamaProvider(origin, MODEL, DIGEST).generate(
                MESSAGES, SCHEMA, time.monotonic() + 2, before_send=lambda: callbacks.append(1)
            )
        assert caught.value.sent is True
        assert str(caught.value) == "provider_failed"
        assert callbacks == [1]
        assert len(requests) == 2


@pytest.mark.parametrize(
    "bad",
    [
        b'{"done":true,"done":false}',
        b'{"message":{"content":"a","content":"b"}}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":1e999}',
        b'{"value":"\\ud800"}',
        b'{"value":' + b"[" * 32 + b"0" + b"]" * 32 + b"}",
        b'{"incomplete":',
        b"\xff",
        b"[]",
    ],
)
@pytest.mark.parametrize("phase", ["tags", "chat"])
def test_strict_native_json_failure_never_leaks_raw_response(bad, phase, caplog, capsys):
    module = adapter()
    with peer(**{phase: http_response(bad)}) as (origin, requests, _):
        callbacks = []
        with pytest.raises(module.ProviderError) as caught:
            module.OllamaProvider(origin, MODEL, DIGEST).generate(
                MESSAGES, SCHEMA, time.monotonic() + 2, before_send=lambda: callbacks.append(1)
            )
        assert caught.value.sent is (phase == "chat")
        assert caught.value.code in {"provider_failed", "model_unavailable"}
        assert str(caught.value) == caught.value.code
        assert caught.value.__cause__ is None
        assert callbacks == ([1] if phase == "chat" else [])
        assert len(requests) == (2 if phase == "chat" else 1)
        assert caplog.text == ""
        assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("extra", [0, 1])
@pytest.mark.parametrize("unit", ["x", "한"])
def test_model_content_exact_utf8_bound(extra, unit):
    room = 16 * 1024
    content = unit * (room // len(unit.encode())) + "x" * (room % len(unit.encode()) + extra)
    module = adapter()
    with peer(chat=http_response(envelope(content))) as (origin, _, _):
        provider = module.OllamaProvider(origin, MODEL, DIGEST)
        if extra:
            reply = provider.generate(MESSAGES, SCHEMA, time.monotonic() + 2, before_send=lambda: None)
            assert isinstance(reply, module.NativeReply), "complete native done proof must not be discarded"
            assert reply.content is None, "oversized model prose must not be retained"
            assert reply.content_error == "too_large"
        else:
            assert (
                provider.generate(MESSAGES, SCHEMA, time.monotonic() + 2, before_send=lambda: None).content == content
            )


@pytest.mark.parametrize('change', [{'done': False}, {'eval_count': True}, {'model': 'wrong:tag'}])
def test_content_rejection_never_settles_an_invalid_native_envelope(change):
    module = adapter()
    value = {**envelope('x' * (16 * 1024 + 1)), **change}
    with peer(chat=http_response(value)) as (origin, _, _):
        with pytest.raises(module.ProviderError) as caught:
            module.OllamaProvider(origin, MODEL, DIGEST).generate(
                MESSAGES, SCHEMA, time.monotonic() + 2, before_send=lambda: None)
        assert caught.value.sent is True


@pytest.mark.parametrize("phase", ["tags", "chat"])
@pytest.mark.parametrize("status", [301, 302, 307, 308, 400, 500])
def test_http_failure_or_redirect_never_contacts_another_sink(phase, status):
    module = adapter()
    with peer() as (sink, sink_requests, _):
        body = catalog() if phase == "tags" else envelope()
        reply = http_response(body, status=status, headers=[("Location", sink + "/api/chat")])
        with peer(**{phase: reply}) as (origin, requests, _):
            callbacks = []
            with pytest.raises(module.ProviderError, match="provider_failed") as caught:
                module.OllamaProvider(origin, MODEL, DIGEST).generate(
                    MESSAGES, SCHEMA, time.monotonic() + 2, before_send=lambda: callbacks.append(1)
                )
            assert caught.value.sent is (phase == "chat")
            assert sink_requests == []
            assert callbacks == ([1] if phase == "chat" else [])
            assert len(requests) == (2 if phase == "chat" else 1)


@pytest.mark.parametrize("extra", [0, 1])
@pytest.mark.parametrize("phase", ["tags", "chat"])
@pytest.mark.parametrize("framing", ["length", "eof", "chunked"])
def test_native_envelope_exact_and_plus_one_byte_bounds(extra, phase, framing):
    body = encoded(catalog() if phase == "tags" else envelope())
    body += b" " * (64 * 1024 + extra - len(body))
    if framing == "length":
        reply = http_response(body)
    elif framing == "eof":
        reply = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n" + body
    else:
        reply = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
            + f"{len(body):x}\r\n".encode()
            + body
            + b"\r\n0\r\n\r\n"
        )
    module = adapter()
    with peer(**{phase: reply}) as (origin, _, _):
        provider = module.OllamaProvider(origin, MODEL, DIGEST)
        if extra:
            with pytest.raises(module.ProviderError, match="too_large") as caught:
                provider.generate(MESSAGES, SCHEMA, time.monotonic() + 2, before_send=lambda: None)
            assert caught.value.sent is (phase == "chat")
        else:
            assert provider.generate(MESSAGES, SCHEMA, time.monotonic() + 2, before_send=lambda: None).content


@pytest.mark.parametrize("extra", [0, 1])
def test_total_header_bytes_have_an_exact_limit(extra):
    body = encoded(envelope())
    prefix = (f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nX-Pad: ").encode()
    head = prefix + b"x" * (16 * 1024 + extra - len(prefix) - 4) + b"\r\n\r\n"
    assert len(head) == 16 * 1024 + extra
    module = adapter()
    with peer(chat=head + body) as (origin, _, _):
        provider = module.OllamaProvider(origin, MODEL, DIGEST)
        if extra:
            with pytest.raises(module.ProviderError, match="too_large") as caught:
                provider.generate(MESSAGES, SCHEMA, time.monotonic() + 2, before_send=lambda: None)
            assert caught.value.sent is True
        else:
            assert provider.generate(MESSAGES, SCHEMA, time.monotonic() + 2, before_send=lambda: None).content


@pytest.mark.parametrize(
    "fault",
    [
        "gzip",
        "br",
        "duplicate_length",
        "te_and_length",
        "bad_length",
        "fold",
        "bare_lf",
        "bad_status",
        "wrong_type",
        "truncated",
        "disconnected",
        "chunk_truncated",
        "chunk_huge",
        "chunk_trailer",
        "framing_overflow",
    ],
)
def test_http_framing_failure_cannot_settle_inference(fault):
    body = encoded(envelope())
    if fault in {"gzip", "br"}:
        reply = http_response(body, headers=[("Content-Encoding", fault)])
    elif fault == "duplicate_length":
        reply = http_response(body, headers=[("content-length", str(len(body)))])
    elif fault == "te_and_length":
        reply = http_response(body, headers=[("Transfer-Encoding", "chunked")])
    elif fault == "bad_length":
        reply = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: +1\r\n\r\n" + body
    elif fault == "fold":
        reply = http_response(body, headers=[("X-Test", "a\r\n folded")])
    elif fault == "bare_lf":
        reply = http_response(body).replace(b"\r\n", b"\n")
    elif fault == "bad_status":
        reply = b"SYNTHETIC_SECRET_STATUS\r\n\r\n" + body
    elif fault == "wrong_type":
        reply = http_response(body).replace(b"application/json", b"text/plain")
    elif fault == "truncated":
        reply = http_response(body)[:-3]
    elif fault == "disconnected":
        reply = b""
    else:
        reply = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
        if fault == "chunk_truncated":
            reply += f"{len(body):x}\r\n".encode() + body
        elif fault == "chunk_huge":
            reply += b"10001\r\n"
        elif fault == "chunk_trailer":
            reply += f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\nContent-Encoding: gzip\r\n\r\n"
        else:
            # Legal tiny chunks must not permit unlimited framing overhead.
            padded = body + b" " * 4000
            reply += b"".join(b"1\r\n" + bytes([byte]) + b"\r\n" for byte in padded) + b"0\r\n\r\n"
    module = adapter()
    with peer(chat=reply) as (origin, requests, _):
        with pytest.raises(module.ProviderError) as caught:
            module.OllamaProvider(origin, MODEL, DIGEST).generate(
                MESSAGES, SCHEMA, time.monotonic() + 2, before_send=lambda: None
            )
        assert caught.value.sent is True
        assert caught.value.code in {"provider_failed", "too_large"}
        assert str(caught.value) == caught.value.code
        assert len(requests) == 2


@pytest.mark.parametrize("phase", ["tags", "chat"])
@pytest.mark.parametrize("part", ["headers", "body"])
def test_total_deadline_stops_continuous_slow_drip(phase, part):
    body = encoded(catalog() if phase == "tags" else envelope())
    head = http_response(body)[: -len(body)]

    def drip(sock, stop):
        if part == "body":
            sock.sendall(head)
        stream = head if part == "headers" else body
        width = 4
        for index in range(0, len(stream), width):
            if stop.wait(0.02):
                return
            sock.sendall(stream[index : index + width])
        if part == "headers":
            sock.sendall(body)

    module = adapter()
    with peer(**{phase: drip}) as (origin, requests, _):
        callbacks = []
        start = time.monotonic()
        with pytest.raises(module.ProviderError, match="deadline_exceeded") as caught:
            module.OllamaProvider(origin, MODEL, DIGEST).generate(
                MESSAGES, SCHEMA, start + 0.15, before_send=lambda: callbacks.append(1)
            )
        elapsed = time.monotonic() - start
        assert elapsed < 0.6, "inactivity timeout must not replace the cumulative deadline"
        assert caught.value.sent is (phase == "chat")
        assert callbacks == ([1] if phase == "chat" else [])
        assert len(requests) == (2 if phase == "chat" else 1)


class Clock:
    value = 100.0

    def __call__(self):
        return self.value


@pytest.mark.parametrize("deadline", [None, True, "200", float("inf"), float("nan")])
def test_deadline_must_be_finite_before_any_network(deadline):
    module = adapter()
    with peer() as (origin, requests, _):
        with pytest.raises(module.ProviderError, match="invalid_request") as caught:
            module.OllamaProvider(origin, MODEL, DIGEST).generate(
                MESSAGES, SCHEMA, deadline, before_send=lambda: pytest.fail("late admission")
            )
        assert caught.value.sent is False
        assert requests == []


@pytest.mark.parametrize(
    "phase", ["entry", "preparation", "catalog_decode", "chat_connect", "admission", "reply_decode"]
)
def test_expiry_fences_preparation_admission_and_decoding(monkeypatch, phase):
    import socket

    module = adapter()
    clock = Clock()
    callbacks = []
    original_loads = json.loads
    original_encode = json.JSONEncoder.iterencode
    original_connect = socket.socket.connect
    connections = []

    def decode(data, *args, **kwargs):
        result = original_loads(data, *args, **kwargs)
        if (phase == "catalog_decode" and "models" in result) or (phase == "reply_decode" and "done" in result):
            clock.value = 201.0
        return result

    def encode(self, value, *args, **kwargs):
        yield from original_encode(self, value, *args, **kwargs)
        if phase == "preparation" and type(value) is dict and "model" in value:
            clock.value = 201.0

    def connect(sock, address):
        result = original_connect(sock, address)
        connections.append(address)
        if phase == "chat_connect" and len(connections) == 2:
            clock.value = 201.0
        return result

    def admit():
        callbacks.append(1)
        if phase == "admission":
            clock.value = 201.0

    with peer() as (origin, requests, _):
        monkeypatch.setattr(json, "loads", decode)
        monkeypatch.setattr(json.JSONEncoder, "iterencode", encode)
        monkeypatch.setattr(socket.socket, "connect", connect)
        if phase == "entry":
            clock.value = 201.0
        with pytest.raises(module.ProviderError, match="deadline_exceeded") as caught:
            module.OllamaProvider(origin, MODEL, DIGEST, clock=clock).generate(
                MESSAGES, SCHEMA, 200.0, before_send=admit
            )
        assert caught.value.sent is (phase in {"admission", "reply_decode"})
        assert callbacks == ([1] if phase in {"admission", "reply_decode"} else [])
        assert [row["path"] for row in requests] == {
            "entry": [],
            "preparation": [],
            "catalog_decode": ["/api/tags"],
            "chat_connect": ["/api/tags"],
            "admission": ["/api/tags"],
            "reply_decode": ["/api/tags", "/api/chat"],
        }[phase]


def test_proxy_change_at_admission_cannot_emit_inference(monkeypatch):
    module = adapter()
    with peer() as (origin, requests, _), peer() as (sink, sink_requests, _):
        callbacks = []

        def admit():
            callbacks.append(1)
            monkeypatch.setenv("http_proxy", sink)

        with pytest.raises(module.ProviderError, match="provider_failed") as caught:
            module.OllamaProvider(origin, MODEL, DIGEST).generate(
                MESSAGES, SCHEMA, time.monotonic() + 2, before_send=admit
            )
        assert caught.value.sent is True
        assert callbacks == [1]
        assert [row["path"] for row in requests] == ["/api/tags"]
        assert sink_requests == []


@pytest.mark.parametrize("fault", ["top_cloud", "top_remote", "conflicting_alias"])
def test_catalog_ambiguous_or_cloud_provenance_is_not_local(fault):
    value = catalog()
    if fault == "top_cloud":
        value["cloud"] = True
    elif fault == "top_remote":
        value["remote_host"] = "SYNTHETIC_SECRET"
    else:
        other = dict(value["models"][0])
        other["name"] = "different:tag"
        value["models"].append(other)
    module = adapter()
    with peer(tags=http_response(value)) as (origin, requests, _):
        with pytest.raises(module.ProviderError, match="model_unavailable") as caught:
            module.OllamaProvider(origin, MODEL, DIGEST).generate(
                MESSAGES, SCHEMA, time.monotonic() + 2, before_send=lambda: pytest.fail("late admission")
            )
        assert caught.value.sent is False
        assert [row["path"] for row in requests] == ["/api/tags"]


@pytest.mark.parametrize("before_send", [None, False, "callback"])
def test_missing_admission_callback_is_refused_before_network(before_send):
    module = adapter()
    with peer() as (origin, requests, _):
        with pytest.raises(module.ProviderError, match="invalid_request") as caught:
            module.OllamaProvider(origin, MODEL, DIGEST).generate(
                MESSAGES, SCHEMA, time.monotonic() + 2, before_send=before_send
            )
        assert caught.value.sent is False
        assert requests == []


def test_finite_but_unrepresentable_socket_deadline_is_a_fixed_error():
    module = adapter()
    with peer() as (origin, requests, _):
        with pytest.raises(module.ProviderError, match="invalid_request") as caught:
            module.OllamaProvider(origin, MODEL, DIGEST).generate(
                MESSAGES, SCHEMA, 1e300, before_send=lambda: pytest.fail("late admission")
            )
        assert caught.value.sent is False
        assert requests == []


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "::1"])
def test_real_literal_loopback_success_without_name_resolution(monkeypatch, host):
    import socket

    module = adapter()
    with peer(host=host) as (origin, requests, _):
        monkeypatch.setattr(socket, "getaddrinfo", lambda *args: pytest.fail("DNS must not run"))
        result = module.OllamaProvider(origin, MODEL, DIGEST).generate(
            MESSAGES, SCHEMA, time.monotonic() + 2, before_send=lambda: None
        )
        assert result.content == '{"ok":true}'
        assert requests[-1]["headers"]["Host"] == origin.removeprefix("http://")


@pytest.mark.parametrize("phase", ["tags", "chat"])
@pytest.mark.parametrize(
    "fault",
    [
        "duplicate",
        "nested_duplicate",
        "nan",
        "infinity",
        "overflow_float",
        "surrogate",
        "deep",
        "large_integer",
        "node_overflow",
    ],
)
def test_strict_json_guard_is_exercised_on_otherwise_valid_envelopes(phase, fault):
    body = encoded(catalog() if phase == "tags" else envelope())
    if fault == "duplicate":
        key = b'"models"' if phase == "tags" else b'"done"'
        first = b"[]" if phase == "tags" else b"false"
        body = b"{" + key + b":" + first + b"," + body[1:]
    elif fault == "nested_duplicate":
        old = b'"family":"qwen35"' if phase == "tags" else b'"role":"assistant"'
        body = body.replace(old, old + b"," + old)
    else:
        fragment = {
            "nan": b"NaN",
            "infinity": b"Infinity",
            "overflow_float": b"1e999",
            "surrogate": b'"\\udfff"',
            "deep": b"[" * 32 + b"0" + b"]" * 32,
            "large_integer": b"9" * 1000,
            "node_overflow": b"[" + b"0," * 4096 + b"0]",
        }[fault]
        body = body[:-1] + b',"unused":' + fragment + b"}"
    module = adapter()
    with peer(**{phase: http_response(body)}) as (origin, requests, _):
        with pytest.raises(module.ProviderError) as caught:
            module.OllamaProvider(origin, MODEL, DIGEST).generate(
                MESSAGES, SCHEMA, time.monotonic() + 2, before_send=lambda: None
            )
        assert caught.value.code == "provider_failed"
        assert caught.value.sent is (phase == "chat")
        assert len(requests) == (2 if phase == "chat" else 1)


@pytest.mark.parametrize("framing", ["length", "chunked"])
def test_done_payload_without_complete_http_frame_is_not_settled(framing):
    body = encoded(envelope())

    def stall(sock, stop):
        if framing == "length":
            head = (
                f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(body) + 1}\r\n\r\n"
            ).encode()
            sock.sendall(head + body)
        else:
            sock.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
                + f"{len(body):x}\r\n".encode()
                + body
                + b"\r\n"
            )
        stop.wait(2)

    module = adapter()
    with peer(chat=stall) as (origin, _, _):
        with pytest.raises(module.ProviderError, match="deadline_exceeded") as caught:
            module.OllamaProvider(origin, MODEL, DIGEST).generate(
                MESSAGES, SCHEMA, time.monotonic() + 0.15, before_send=lambda: None
            )
        assert caught.value.sent is True


def test_content_prose_is_not_cloud_configuration_and_metadata_is_allowlisted():
    value = envelope("Explain why the word cloud is not runtime metadata.")
    value["digest"] = value["model_digest"] = DIGEST
    value["unused"] = "SYNTHETIC_SECRET"
    value["message"]["thinking"] = ""
    value["done_reason"] = "length"
    tags = catalog()
    tags["models"].append({"name": "other:cloud", "remote_host": "cloud.invalid"})
    module = adapter()
    with peer(tags=http_response(tags), chat=http_response(value)) as (origin, _, _):
        result = module.OllamaProvider(origin, MODEL, DIGEST).generate(
            MESSAGES, SCHEMA, time.monotonic() + 2, before_send=lambda: None
        )
        assert result.content == value["message"]["content"]
        assert result.metadata["done_reason"] == "length"
        assert "SYNTHETIC_SECRET" not in repr(result.metadata)


@pytest.mark.parametrize("error_type", [ValueError, OSError, RuntimeError])
def test_parent_admission_errors_keep_identity_without_transport_wrapping(error_type):
    module = adapter()
    error = error_type("parent-only refusal")

    def refuse():
        raise error

    with peer() as (origin, requests, _):
        with pytest.raises(error_type) as caught:
            module.OllamaProvider(origin, MODEL, DIGEST).generate(
                MESSAGES, SCHEMA, time.monotonic() + 2, before_send=refuse
            )
        assert caught.value is error
        assert [row["path"] for row in requests] == ["/api/tags"]


@pytest.mark.parametrize("extra", [0, 1])
def test_policy_deadline_exact_and_plus_one_second(extra):
    module = adapter()
    with peer() as (origin, requests, _):
        provider = module.OllamaProvider(origin, MODEL, DIGEST, clock=Clock())
        if extra:
            with pytest.raises(module.ProviderError, match="invalid_request"):
                provider.generate(MESSAGES, SCHEMA, 220 + extra, before_send=lambda: None)
            assert requests == []
        else:
            assert provider.generate(MESSAGES, SCHEMA, 220, before_send=lambda: None).content


@pytest.mark.parametrize("fault", ["connect", "send", "none"])
def test_real_connections_are_closed_on_every_outcome(monkeypatch, fault, capsys, caplog):
    module = adapter()
    main = threading.current_thread()
    sockets = []
    original_connect = socket.socket.connect
    original_send = socket.socket.sendall

    def connect(sock, address):
        if threading.current_thread() is main:
            sockets.append(sock)
            if fault == "connect" and len(sockets) == 2:
                raise ConnectionRefusedError("SYNTHETIC_SECRET_URL")
        return original_connect(sock, address)

    def send(sock, data, *args, **kwargs):
        if threading.current_thread() is main and data.startswith(b"POST") and fault == "send":
            raise BrokenPipeError("SYNTHETIC_SECRET_SOCKET")
        return original_send(sock, data, *args, **kwargs)

    with peer() as (origin, requests, _):
        monkeypatch.setattr(socket.socket, "connect", connect)
        monkeypatch.setattr(socket.socket, "sendall", send)
        callbacks = []
        provider = module.OllamaProvider(origin, MODEL, DIGEST)
        if fault == "none":
            assert provider.generate(
                MESSAGES, SCHEMA, time.monotonic() + 2, before_send=lambda: callbacks.append(1)
            ).content
        else:
            with pytest.raises(module.ProviderError, match="provider_failed") as caught:
                provider.generate(MESSAGES, SCHEMA, time.monotonic() + 2, before_send=lambda: callbacks.append(1))
            assert caught.value.sent is (fault == "send")
            assert str(caught.value) == "provider_failed"
            assert caught.value.__cause__ is None
        assert callbacks == ([] if fault == "connect" else [1])
        assert len(sockets) == 2
        assert all(sock.fileno() == -1 for sock in sockets)
        assert len(requests) == (2 if fault == "none" else 1)
        assert caplog.text == ""
        assert capsys.readouterr() == ("", "")


def test_request_snapshot_cannot_be_changed_by_admission_callback():
    messages = json.loads(encoded(MESSAGES))
    schema = dict(SCHEMA)

    def admit():
        messages[0]["content"] = "changed after preparation"
        schema["unsafe"] = "changed after preparation"

    module = adapter()
    with peer() as (origin, requests, _):
        assert (
            module.OllamaProvider(origin, MODEL, DIGEST)
            .generate(messages, schema, time.monotonic() + 2, before_send=admit)
            .content
        )
        body = json.loads(requests[-1]["body"])
        assert body["messages"] == MESSAGES
        assert body["format"] == SCHEMA
