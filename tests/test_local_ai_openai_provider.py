"""Compatible transport acceptance: synthetic peers, never a real provider."""

import importlib
import json
import os
import socket
import socketserver
import ssl
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from types import MappingProxyType

import pytest

from local_ai.provider import NativeReply, ProviderError

MESSAGES = [
    {"role": "system", "content": "Return JSON with the checked schema."},
    {"role": "user", "content": "Synthetic evidence only."},
]
SCHEMA = {"type": "object"}
KEY = "SYNTHETIC-opaque!+/=:TOKEN"


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def envelope(content='{"ok":true}'):
    return {
        "object": "chat.completion",
        "model": "reported/alias-2026",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5},
        "id": "IGNORED-ID",
        "created": 42,
        "extra": "NOT-METADATA",
    }


def response(body, status=200, headers=None):
    body = body if type(body) is bytes else encoded(body)
    if headers is None:
        headers = [("Content-Type", "application/json"), ("Content-Length", str(len(body)))]
    return (f"HTTP/1.1 {status} Test\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers) + "\r\n").encode() + body


@contextmanager
def peer(reply=None, *, host="127.0.0.1", tls_context=None, accepted=None, connected=None):
    requests, errors = [], []
    stop = threading.Event()

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            try:
                if accepted is not None:
                    accepted.append(True)
                if connected is not None:
                    connected.set()
                if tls_context is not None:
                    self.request = tls_context.wrap_socket(self.request, server_side=True)
                data = bytearray()
                while b"\r\n\r\n" not in data:
                    part = self.request.recv(4096)
                    if not part:
                        return
                    data.extend(part)
                    assert len(data) <= 100_000
                head, body = bytes(data).split(b"\r\n\r\n", 1)
                method, path, version = head.split(b"\r\n", 1)[0].decode().split(" ")
                fields = dict(line.decode().split(": ", 1) for line in head.split(b"\r\n")[1:])
                length = int(fields["Content-Length"])
                while len(body) < length:
                    part = self.request.recv(min(4096, length - len(body)))
                    if not part:
                        return
                    body += part
                requests.append(
                    {
                        "method": method,
                        "path": path,
                        "version": version,
                        "headers": fields,
                        "body": body,
                        "packet": head + b"\r\n\r\n" + body,
                    }
                )
                if callable(reply):
                    reply(self.request, stop)
                else:
                    self.request.sendall(response(envelope()) if reply is None else reply)
            except (BrokenPipeError, ConnectionResetError, TimeoutError, ssl.SSLError):
                pass
            except Exception as error:
                errors.append(error)
            finally:
                self.request.close()

    class Server(socketserver.ThreadingTCPServer):
        address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
        daemon_threads = False
        block_on_close = True

    server = Server((host, 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    try:
        authority = f"[{host}]" if ":" in host else host
        yield f"http://{authority}:{server.server_address[1]}", requests
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
        thread.join(3)
        assert not thread.is_alive()
        assert not errors


@pytest.fixture(autouse=True)
def no_proxy(monkeypatch):
    for name in list(os.environ):
        if name.lower().endswith("_proxy"):
            monkeypatch.delenv(name)


def adapter():
    try:
        module = importlib.import_module("local_ai.openai_provider")
    except ModuleNotFoundError:
        pytest.fail("bounded compatible transport is missing")
    assert Path(module.__file__).resolve() == Path(__file__).resolve().parents[1] / "local_ai/openai_provider.py"
    return module


class NoDNS:
    def resolve(self, *args):
        pytest.fail("literal/localhost must not resolve")


def settings(base_url, **extra):
    return {
        "enabled": True,
        "provider": "openai_compatible",
        "base_url": base_url,
        "model": "requested/alias",
        "endpoint_policy": "loopback",
        "api_key": KEY,
        **extra,
    }


@pytest.mark.parametrize("token_field", ["max_tokens", "max_completion_tokens"])
def test_real_http_one_post_exact_profile_and_immutable_metadata(token_field):
    module = adapter()
    from local_ai.provider import ProviderReply

    assert ProviderReply is NativeReply
    with peer() as (url, requests):
        provider = module.OpenAICompatibleProvider(
            settings(url + "/prefix/v1/", token_limit_field=token_field), resolver=NoDNS()
        )
        assert requests == []
        assert KEY not in repr(provider)
        calls = []
        reply = provider.generate(
            MESSAGES, SCHEMA, time.monotonic() + 2, before_send=lambda: calls.append(len(requests))
        )
        assert calls == [0]
        assert len(requests) == 1
        request = requests[0]
        assert (request["method"], request["path"], request["version"]) == (
            "POST",
            "/prefix/v1/chat/completions",
            "HTTP/1.1",
        )
        assert request["headers"] == {
            "Host": url.removeprefix("http://"),
            "Content-Length": str(len(request["body"])),
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Connection": "close",
            "Authorization": "Bearer " + KEY,
        }
        assert json.loads(request["body"]) == {
            "model": "requested/alias",
            "messages": MESSAGES,
            "stream": False,
            "n": 1,
            "store": False,
            "response_format": {"type": "json_object"},
            token_field: 512,
        }
        assert KEY.encode() not in request["body"]
        assert type(reply) is NativeReply
        assert reply.content == '{"ok":true}' and reply.content_error is None
        assert type(reply.metadata) is MappingProxyType
        assert dict(reply.metadata) == {
            "provider": "openai_compatible",
            "requested_model": "requested/alias",
            "reported_model": "reported/alias-2026",
            "finish_reason": "stop",
            "response_format": "json_object",
            "prompt_tokens": 2,
            "completion_tokens": 3,
            "total_tokens": 5,
        }
        with pytest.raises(TypeError):
            reply.metadata["provider"] = "changed"


@pytest.mark.parametrize("status", [400, 401, 403, 404, 422, 429])
@pytest.mark.parametrize("framing", ["length", "chunked", "eof"])
def test_complete_bounded_rejection_discards_opaque_body(status, framing, caplog, capsys):
    from local_ai.provider_outcomes import ProviderRejected

    body = b"SYNTHETIC-UPSTREAM-ERROR " + KEY.encode()
    if framing == "chunked":
        wire = response(
            f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n",
            status,
            [("Transfer-Encoding", "chunked"), ("Content-Type", "text/plain")],
        )
    elif framing == "eof":
        wire = response(body, status, [])
    else:
        wire = response(body, status, [("Content-Length", str(len(body))), ("Content-Type", "text/plain")])
    with peer(wire) as (url, requests):
        reply = (
            adapter()
            .OpenAICompatibleProvider(settings(url), resolver=NoDNS())
            .generate(MESSAGES, SCHEMA, time.monotonic() + 2)
        )
        assert type(reply) is ProviderRejected and reply.http_status == status
        assert vars(reply) == {"http_status": status}
        assert len(requests) == 1
        assert KEY not in repr(reply)
    captured = capsys.readouterr()
    assert KEY not in captured.out + captured.err + caplog.text
    assert "SYNTHETIC-UPSTREAM-ERROR" not in captured.out + captured.err + caplog.text


@pytest.mark.parametrize("status", [100, 301, 302, 307, 308, 402, 408, 409, 418, 500, 503, 600])
def test_unknown_status_is_uncertain_and_never_followed(status):
    with (
        peer() as (sink, sink_requests),
        peer(response(envelope(), status, [("Location", sink + "/sink"), ("Content-Length", "0")])) as (url, requests),
    ):
        with pytest.raises(ProviderError) as caught:
            adapter().OpenAICompatibleProvider(settings(url), resolver=NoDNS()).generate(
                MESSAGES, SCHEMA, time.monotonic() + 2
            )
        assert caught.value.code == "provider_failed" and caught.value.sent
        assert len(requests) == 1 and sink_requests == []


@pytest.mark.parametrize(
    "wire,code",
    [
        (response(b"x", 401, [("Content-Length", "2")]), "provider_failed"),
        (response(b"", 401, [("Content-Length", "65537")]), "too_large"),
        (response(b"1\r\nx\r\n", 401, [("Transfer-Encoding", "chunked")]), "provider_failed"),
        (response(b"0\r\nX: trailer\r\n\r\n", 401, [("Transfer-Encoding", "chunked")]), "provider_failed"),
        (response(b"0;ext=a\r\n\r\n", 401, [("Transfer-Encoding", "chunked")]), "provider_failed"),
        (response(b"", 401, [("Content-Length", "0"), ("Content-Length", "0")]), "provider_failed"),
        (response(b"", 401, [("Content-Length", "0"), ("Transfer-Encoding", "chunked")]), "provider_failed"),
        (response(b"", 401, [("Content-Length", "0"), ("Content-Encoding", "gzip")]), "provider_failed"),
    ],
)
def test_incomplete_or_ambiguous_rejection_is_not_a_receipt(wire, code):
    with peer(wire) as (url, requests):
        with pytest.raises(ProviderError) as caught:
            adapter().OpenAICompatibleProvider(settings(url), resolver=NoDNS()).generate(
                MESSAGES, SCHEMA, time.monotonic() + 2
            )
        assert caught.value.sent and caught.value.code == code
        assert len(requests) == 1


@pytest.mark.parametrize(
    "content,reason,refusal,error",
    [
        ("", "stop", None, "invalid_model_output"),
        (None, "stop", "Cannot comply", "invalid_model_output"),
        ("partial", "length", None, "invalid_model_output"),
        (None, "content_filter", None, "invalid_model_output"),
        ("{}", "stop", "Refused", "invalid_model_output"),
        ("x" * 16384, "stop", None, None),
        ("x" * 16385, "stop", None, "too_large"),
        ("é" * 8192, "stop", None, None),
        ("é" * 8193, "stop", None, "too_large"),
    ],
)
def test_terminal_content_receipt_is_distinct_from_usable_output(content, reason, refusal, error):
    value = envelope(content)
    value["choices"][0]["finish_reason"] = reason
    value["choices"][0]["message"]["refusal"] = refusal
    with peer(response(value)) as (url, requests):
        result = (
            adapter()
            .OpenAICompatibleProvider(settings(url), resolver=NoDNS())
            .generate(MESSAGES, SCHEMA, time.monotonic() + 2)
        )
        assert type(result) is NativeReply
        assert result.content_error == error
        assert result.content == (content if error is None else None)
        assert result.metadata["finish_reason"] == reason
        assert len(requests) == 1


@pytest.mark.parametrize(
    "mutation",
    [
        lambda v: v.update(object="chat.completion.chunk"),
        lambda v: v.pop("object"),
        lambda v: v.update(error={"message": "UPSTREAM-SECRET"}),
        lambda v: v.update(model="bad model"),
        lambda v: v.update(model="x" * 257),
        lambda v: v.update(model="é"),
        lambda v: v.update(choices=[]),
        lambda v: v["choices"].append(v["choices"][0].copy()),
        lambda v: v["choices"][0].update(index=True),
        lambda v: v["choices"][0].update(index=1),
        lambda v: v["choices"][0].pop("index"),
        lambda v: v["choices"][0].update(finish_reason=None),
        lambda v: v["choices"][0].update(finish_reason="tool_calls"),
        lambda v: v["choices"][0].update(finish_reason="function_call"),
        lambda v: v["choices"][0].update(delta={}),
        lambda v: v["choices"][0]["message"].update(role="user"),
        lambda v: v["choices"][0]["message"].pop("content"),
        lambda v: v["choices"][0]["message"].update(content=[]),
        lambda v: v["choices"][0]["message"].update(refusal={}),
        lambda v: v["choices"][0]["message"].update(tool_calls=[{"type": "function"}]),
        lambda v: v["choices"][0]["message"].update(function_call={"name": "never_call"}),
        lambda v: v["choices"][0]["message"].update(audio={}),
    ],
)
def test_malformed_completion_is_uncertain(mutation):
    value = envelope()
    mutation(value)
    with peer(response(value)) as (url, requests):
        with pytest.raises(ProviderError) as caught:
            adapter().OpenAICompatibleProvider(settings(url), resolver=NoDNS()).generate(
                MESSAGES, SCHEMA, time.monotonic() + 2
            )
        assert caught.value.sent and caught.value.code == "provider_failed"
        assert "UPSTREAM-SECRET" not in str(caught.value)
        assert len(requests) == 1


@pytest.mark.parametrize(
    "usage,expected",
    [
        (None, {}),
        ({}, {}),
        ({"prompt_tokens": 0}, {"prompt_tokens": 0}),
        ({"completion_tokens": (1 << 63) - 1}, {"completion_tokens": (1 << 63) - 1}),
        (
            {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3, "details": {"ignored": 10}},
            {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
        ),
    ],
)
def test_usage_is_optional_exact_and_closed(usage, expected):
    value = envelope()
    value["usage"] = usage
    with peer(response(value)) as (url, _):
        result = (
            adapter()
            .OpenAICompatibleProvider(settings(url), resolver=NoDNS())
            .generate(MESSAGES, SCHEMA, time.monotonic() + 2)
        )
        assert {k: v for k, v in result.metadata.items() if k.endswith("_tokens")} == expected
        assert set(result.metadata) == {
            "provider",
            "requested_model",
            "reported_model",
            "finish_reason",
            "response_format",
        } | set(expected)


@pytest.mark.parametrize(
    "usage",
    [
        True,
        1,
        [],
        "bad",
        {"prompt_tokens": True},
        {"prompt_tokens": 1.0},
        {"completion_tokens": "2"},
        {"total_tokens": -1},
        {"total_tokens": None},
        {"prompt_tokens": 1 << 63},
        {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 4},
    ],
)
def test_malformed_usage_prevents_completion_even_for_terminal_refusal(usage):
    value = envelope(None)
    value["choices"][0]["message"]["refusal"] = "Refused"
    value["usage"] = usage
    with peer(response(value)) as (url, _):
        with pytest.raises(ProviderError) as caught:
            adapter().OpenAICompatibleProvider(settings(url), resolver=NoDNS()).generate(
                MESSAGES, SCHEMA, time.monotonic() + 2
            )
        assert caught.value.sent and caught.value.code == "provider_failed"


def tls_contexts(tmp_path, name="localhost"):
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Invocation-owned test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    ca_path, cert_path, key_path = (tmp_path / f for f in ("ca.pem", "leaf.pem", "leaf-key.pem"))
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    key_path.chmod(0o600)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert_path, key_path)
    client = ssl.create_default_context(cafile=str(ca_path))
    assert client.check_hostname and client.verify_mode == ssl.CERT_REQUIRED
    return server, client


def test_real_tls_original_host_sni_and_latest_pre_send_admission(tmp_path, monkeypatch):
    module = adapter()
    server, client = tls_contexts(tmp_path)
    sni, calls, accepted = [], [], []
    server.set_servername_callback(lambda sock, name, context: sni.append(name))
    monkeypatch.setattr(ssl, "create_default_context", lambda: client)
    with peer(tls_context=server, accepted=accepted) as (url, requests):
        url = url.replace("http://127.0.0.1", "https://localhost")
        provider = module.OpenAICompatibleProvider(settings(url), resolver=NoDNS())
        result = provider.generate(
            MESSAGES, SCHEMA, time.monotonic() + 2, before_send=lambda: calls.append((list(sni), len(requests)))
        )
        assert result.content == '{"ok":true}'
        assert calls == [(["localhost"], 0)]
        assert accepted == [True] and len(requests) == 1
        assert requests[0]["headers"]["Host"] == url.removeprefix("https://")


@pytest.mark.parametrize("fault", ["untrusted", "hostname"])
def test_bad_tls_never_sends_credentials_or_downgrades(tmp_path, monkeypatch, fault):
    module = adapter()
    server, client = tls_contexts(tmp_path, "elsewhere.invalid" if fault == "hostname" else "localhost")
    if fault == "hostname":
        monkeypatch.setattr(ssl, "create_default_context", lambda: client)
    calls, accepted = [], []
    with peer(tls_context=server, accepted=accepted) as (url, requests):
        url = url.replace("http://127.0.0.1", "https://localhost")
        with pytest.raises(ProviderError) as caught:
            module.OpenAICompatibleProvider(settings(url), resolver=NoDNS()).generate(
                MESSAGES, SCHEMA, time.monotonic() + 2, before_send=lambda: calls.append(True)
            )
        assert caught.value.code == "provider_failed" and not caught.value.sent
        assert calls == [] and requests == []
        assert accepted == [True], "one failed verified handshake, no downgrade/retry"


def public_answer(ip, port):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return (
        family,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port),
    )


def test_public_dns_resolved_once_all_vetted_one_ip_dial_original_tls_identity(tmp_path, monkeypatch):
    from local_ai.resolver import ResolverOwner

    module = adapter()
    server, client = tls_contexts(tmp_path, "Example.invalid")
    sni, lookups, dials = [], [], []
    server.set_servername_callback(lambda sock, name, context: sni.append(name))
    monkeypatch.setattr(ssl, "create_default_context", lambda: client)
    real_connect = socket.socket.connect
    with peer(tls_context=server) as (url, requests):
        port = int(url.rsplit(":", 1)[1])

        def connect(sock, address):
            dials.append(address)
            assert address == ("8.8.8.8", port)
            return real_connect(sock, ("127.0.0.1", port))

        def lookup(host, target_port):
            lookups.append((host, target_port))
            return [public_answer("8.8.8.8", port), public_answer("1.1.1.1", port)]

        monkeypatch.setattr(socket.socket, "connect", connect)
        owner = ResolverOwner(lookup=lookup)
        try:
            provider = module.OpenAICompatibleProvider(
                settings(f"https://Example.invalid:{port}/v1", endpoint_policy="public_https"), resolver=owner
            )
            assert lookups == [] and dials == []
            reply = provider.generate(MESSAGES, SCHEMA, time.monotonic() + 2)
            assert type(reply) is NativeReply
            assert lookups == [("Example.invalid", port)] and dials == [("8.8.8.8", port)]
            assert sni == ["Example.invalid"]
            assert len(requests) == 1
            assert requests[0]["headers"]["Host"] == f"Example.invalid:{port}"
        finally:
            assert owner.close(time.monotonic() + 1)


@pytest.mark.parametrize(
    "ips",
    [[], ["8.8.8.8"] * 9, ["8.8.8.8", "127.0.0.1"], ["8.8.8.8", "10.0.0.1"], ["::ffff:8.8.8.8"], ["2002:0808:0808::"]],
)
def test_public_dns_denial_is_zero_dial_even_for_injected_resolver(ips, monkeypatch):
    module = adapter()
    calls = []

    class Resolver:
        def resolve(self, host, port, deadline):
            calls.append((host, port, deadline))
            return tuple(public_answer(ip, port) for ip in ips)

    def no_socket(*args, **kwargs):
        pytest.fail("a refused DNS snapshot must not create a socket")

    monkeypatch.setattr(socket, "socket", no_socket)
    deadline = time.monotonic() + 1
    with pytest.raises(ProviderError) as caught:
        module.OpenAICompatibleProvider(
            settings("https://example.invalid", endpoint_policy="public_https"), resolver=Resolver()
        ).generate(MESSAGES, SCHEMA, deadline)
    assert caught.value.code == "provider_failed" and not caught.value.sent
    assert calls == [("example.invalid", 443, deadline)]


def test_failed_first_candidate_is_never_retried(monkeypatch):
    from local_ai.resolver import ResolverOwner

    module = adapter()
    dials = []
    owner = ResolverOwner(lookup=lambda host, port: [public_answer("8.8.8.8", port), public_answer("1.1.1.1", port)])

    def fail_connect(sock, address):
        dials.append(address)
        raise OSError("SYNTHETIC-PRIVATE-ERROR")

    monkeypatch.setattr(socket.socket, "connect", fail_connect)
    try:
        with pytest.raises(ProviderError) as caught:
            module.OpenAICompatibleProvider(
                settings("https://example.invalid", endpoint_policy="public_https"), resolver=owner
            ).generate(MESSAGES, SCHEMA, time.monotonic() + 1)
        assert dials == [("8.8.8.8", 443)]
        assert not caught.value.sent and str(caught.value) == "provider_failed"
    finally:
        assert owner.close(time.monotonic() + 1)


@pytest.mark.parametrize(
    "messages,schema,code",
    [
        (None, SCHEMA, "invalid_request"),
        ([], SCHEMA, "invalid_request"),
        ([MESSAGES[0]], SCHEMA, "invalid_request"),
        ([MESSAGES[1], MESSAGES[0]], SCHEMA, "invalid_request"),
        ([MESSAGES[0], {"role": "assistant", "content": "x"}], SCHEMA, "invalid_request"),
        ([MESSAGES[0], {"role": "user", "content": 1}], SCHEMA, "invalid_request"),
        ([MESSAGES[0], {"role": "user", "content": "x", "extra": True}], SCHEMA, "invalid_request"),
        ([MESSAGES[0], {"role": "user", "content": "x" * 16385}], SCHEMA, "too_large"),
        (MESSAGES, [], "invalid_request"),
        (MESSAGES, {"custom": object()}, "invalid_request"),
        (MESSAGES, {"large": "x" * 16385}, "too_large"),
        (MESSAGES, {"wide": [0] * 4097}, "too_large"),
    ],
)
def test_request_admission_precedes_socket_dns_and_callback(messages, schema, code, monkeypatch):
    module = adapter()
    provider = module.OpenAICompatibleProvider(settings("http://localhost:12345"), resolver=NoDNS())

    def forbidden(*args, **kwargs):
        pytest.fail("invalid input must not reach I/O/admission")

    monkeypatch.setattr(socket, "socket", forbidden)
    with pytest.raises(ProviderError) as caught:
        provider.generate(messages, schema, time.monotonic() + 1, before_send=forbidden)
    assert not caught.value.sent and caught.value.code == code


def test_constructor_is_network_thread_and_trust_store_free_and_detaches_settings(monkeypatch):
    module = adapter()
    original = settings("https://example.invalid", endpoint_policy="public_https")

    def forbidden(*args, **kwargs):
        pytest.fail("constructor must be pure")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(threading.Thread, "start", forbidden)
    monkeypatch.setattr(ssl, "create_default_context", forbidden)
    provider = module.OpenAICompatibleProvider(original, resolver=NoDNS())
    original["api_key"] = "MUTATED"
    assert KEY not in repr(provider) and "MUTATED" not in repr(provider)
    assert provider._config["api_key"] == KEY


@pytest.mark.parametrize(
    "changes",
    [
        {"base_url": ""},
        {"model": ""},
        {"api_key": ""},
        {"api_key": "bad key"},
        {"base_url": "http://example.invalid"},
        {"token_limit_field": "other"},
    ],
)
def test_constructor_requires_complete_profile_even_if_disabled(changes):
    value = settings("https://example.invalid", endpoint_policy="public_https", enabled=False)
    value.update(changes)
    with pytest.raises(ProviderError) as caught:
        adapter().OpenAICompatibleProvider(value, resolver=NoDNS())
    assert caught.value.code == "invalid_request" and not caught.value.sent


@pytest.mark.parametrize(
    "error",
    [
        OSError("admission failure"),
        TimeoutError("admission timeout"),
        ProviderError("model_unavailable", sent=True),
        ValueError("admission value"),
    ],
)
def test_callback_failure_propagates_identical_and_no_application_bytes(error):
    accepted = []
    connected = threading.Event()
    with peer(accepted=accepted, connected=connected) as (url, requests):
        provider = adapter().OpenAICompatibleProvider(settings(url), resolver=NoDNS())

        def refuse():
            # Connect completion is not peer accept scheduling. Observe the
            # real accepted connection before teardown can stop the listener.
            assert connected.wait(1)
            raise error

        with pytest.raises(type(error)) as caught:
            provider.generate(MESSAGES, SCHEMA, time.monotonic() + 1, before_send=refuse)
        assert caught.value is error
        if type(error) is ProviderError:
            assert error.sent is True, "callback's own failure must not be rewritten"
    assert requests == [] and accepted == [True]


@pytest.mark.parametrize("boundary", ["deadline", "proxy", "send"])
def test_successful_callback_reserves_even_if_no_bytes_are_sent(boundary, monkeypatch):
    module = adapter()
    now = [100.0]
    callbacks = []
    with peer() as (url, requests):
        provider = module.OpenAICompatibleProvider(settings(url), resolver=NoDNS(), clock=lambda: now[0])

        def admitted():
            callbacks.append(True)
            if boundary == "deadline":
                now[0] = 101.0
            elif boundary == "proxy":
                monkeypatch.setenv("https_proxy", "SYNTHETIC-PROXY")
            else:

                def failed_send(sock, packet, *args):
                    raise OSError("SYNTHETIC-TRANSPORT-SECRET")

                monkeypatch.setattr(socket.socket, "sendall", failed_send)

        with pytest.raises(ProviderError) as caught:
            provider.generate(MESSAGES, SCHEMA, 101.0, before_send=admitted)
        assert caught.value.sent and callbacks == [True]
        assert caught.value.code == ("deadline_exceeded" if boundary == "deadline" else "provider_failed")
    assert requests == []


def test_packet_is_frozen_before_callback_and_schema_is_never_appended():
    messages = [dict(message) for message in MESSAGES]
    schema = dict(SCHEMA)
    with peer() as (url, requests):
        provider = adapter().OpenAICompatibleProvider(settings(url), resolver=NoDNS())

        def mutate():
            messages[0]["content"] = "MUTATED-AFTER-PRIVACY"
            schema["hidden"] = "NEVER-SEND-SCHEMA"

        provider.generate(messages, schema, time.monotonic() + 1, before_send=mutate)
        assert json.loads(requests[0]["body"])["messages"] == MESSAGES
        assert b"MUTATED" not in requests[0]["packet"] and b"NEVER-SEND-SCHEMA" not in requests[0]["packet"]


@pytest.mark.parametrize("framing", ["length", "chunked", "eof"])
@pytest.mark.parametrize("status", [200, 401])
@pytest.mark.parametrize("extra", [0, 1])
def test_whole_body_exact_64k_boundary(framing, status, extra):
    if status == 200:
        value = envelope()
        value["padding"] = ""
        value["padding"] = "x" * (65536 + extra - len(encoded(value)))
        body = encoded(value)
    else:
        body = b"x" * (65536 + extra)
    assert len(body) == 65536 + extra
    headers = [("Content-Type", "application/json")]
    if framing == "length":
        headers.append(("Content-Length", str(len(body))))
    elif framing == "chunked":
        headers.append(("Transfer-Encoding", "chunked"))
        body = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
    with peer(response(body, status, headers)) as (url, _):
        provider = adapter().OpenAICompatibleProvider(settings(url), resolver=NoDNS())
        if extra:
            with pytest.raises(ProviderError) as caught:
                provider.generate(MESSAGES, SCHEMA, time.monotonic() + 2)
            assert caught.value.sent and caught.value.code == "too_large"
        else:
            result = provider.generate(MESSAGES, SCHEMA, time.monotonic() + 2)
            assert result.content == '{"ok":true}' if status == 200 else result.http_status == 401


@pytest.mark.parametrize("extra", [0, 1])
@pytest.mark.parametrize("framing", ["length", "chunked"])
def test_aggregate_http_framing_exact_16k(framing, extra):
    body = encoded(envelope())
    headers = [("Content-Type", "application/json"), ("X-Padding", "")]
    chunk_framing = 0
    if framing == "length":
        headers.append(("Content-Length", str(len(body))))
    else:
        headers.append(("Transfer-Encoding", "chunked"))
        chunk_head = f"{len(body):x}\r\n".encode()
        chunk_framing = len(chunk_head) + len(b"\r\n0\r\n\r\n")
        body = chunk_head + body + b"\r\n0\r\n\r\n"
    initial_headers = len(response(b"", headers=headers))
    headers[1] = ("X-Padding", "x" * (16384 + extra - initial_headers - chunk_framing))
    with peer(response(body, headers=headers)) as (url, _):
        provider = adapter().OpenAICompatibleProvider(settings(url), resolver=NoDNS())
        if extra:
            with pytest.raises(ProviderError) as caught:
                provider.generate(MESSAGES, SCHEMA, time.monotonic() + 2)
            assert caught.value.sent and caught.value.code == "too_large"
        else:
            assert provider.generate(MESSAGES, SCHEMA, time.monotonic() + 2).content == '{"ok":true}'


@pytest.mark.parametrize("extra", [0, 1])
def test_whole_packet_including_bearer_exact_64k(extra):
    with peer() as (url, requests):
        messages = [dict(message) for message in MESSAGES]
        messages[1]["content"] = "\x01" * 10000

        def expected_packet():
            body = encoded(
                {
                    "model": "requested/alias",
                    "messages": messages,
                    "stream": False,
                    "n": 1,
                    "store": False,
                    "response_format": {"type": "json_object"},
                    "max_completion_tokens": 512,
                }
            )
            return (
                f"POST /chat/completions HTTP/1.1\r\nHost: {url.removeprefix('http://')}\r\n"
                f"Content-Length: {len(body)}\r\nContent-Type: application/json\r\n"
                "Accept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n"
                f"Authorization: Bearer {KEY}\r\n\r\n"
            ).encode() + body

        messages[1]["content"] += "x" * (65536 + extra - len(expected_packet()))
        assert len(expected_packet()) == 65536 + extra
        provider = adapter().OpenAICompatibleProvider(settings(url), resolver=NoDNS())
        if extra:
            with pytest.raises(ProviderError) as caught:
                provider.generate(messages, SCHEMA, time.monotonic() + 2)
            assert caught.value.code == "too_large" and not caught.value.sent and requests == []
        else:
            provider.generate(messages, SCHEMA, time.monotonic() + 2)
            assert requests[0]["packet"] == expected_packet()


@pytest.mark.parametrize(
    "body",
    [
        b'{"object":"chat.completion","object":"other"}',
        b'{"bad":NaN}',
        b'{"bad":Infinity}',
        b"\xff",
        b"[" * 17 + b"0" + b"]" * 17,
        b"{} trailing",
        b'{"wide":[' + b"0," * 4096 + b"0]}",
        b"[]",
    ],
)
def test_outer_json_admission_is_strict_before_completion(body):
    with peer(response(body)) as (url, _):
        with pytest.raises(ProviderError) as caught:
            adapter().OpenAICompatibleProvider(settings(url), resolver=NoDNS()).generate(
                MESSAGES, SCHEMA, time.monotonic() + 2
            )
        assert caught.value.sent and caught.value.code == "provider_failed"


@pytest.mark.parametrize("status", [200, 401])
@pytest.mark.parametrize("phase", ["headers", "body"])
def test_slow_frames_expire_original_deadline_not_idle_timeout(status, phase):
    started = threading.Event()

    def slow(sock, stop):
        started.set()
        data = response(envelope(), status)
        if phase == "body":
            head, data = data.split(b"\r\n\r\n", 1)
            sock.sendall(head + b"\r\n\r\n")
        for byte in data:
            sock.sendall(bytes([byte]))
            if stop.wait(0.01):
                break

    with peer(slow) as (url, requests):
        start = time.monotonic()
        with pytest.raises(ProviderError) as caught:
            adapter().OpenAICompatibleProvider(settings(url), resolver=NoDNS()).generate(MESSAGES, SCHEMA, start + 0.08)
        assert caught.value.sent and caught.value.code == "deadline_exceeded"
        assert started.is_set() and len(requests) == 1
        assert time.monotonic() - start < 0.5


def test_decode_and_reply_checks_cannot_extend_deadline(monkeypatch):
    module = adapter()
    now = [10.0]
    decode = module._decode

    def late(data):
        result = decode(data)
        now[0] = 11.0
        return result

    monkeypatch.setattr(module, "_decode", late)
    with peer() as (url, _):
        with pytest.raises(ProviderError) as caught:
            module.OpenAICompatibleProvider(settings(url), resolver=NoDNS(), clock=lambda: now[0]).generate(
                MESSAGES, SCHEMA, 11.0
            )
        assert caught.value.sent and caught.value.code == "deadline_exceeded"


def test_nonbuiltin_role_is_rejected_before_custom_comparison(monkeypatch):
    module = adapter()

    class Role(str):
        def __eq__(self, other):
            pytest.fail("custom role comparison must not execute")

        def __ne__(self, other):
            pytest.fail("custom role comparison must not execute")

    messages = [{"role": Role("system"), "content": "Return JSON"}, MESSAGES[1]]
    with pytest.raises(ProviderError) as caught:
        module.OpenAICompatibleProvider(settings("http://localhost:12345"), resolver=NoDNS()).generate(
            messages, SCHEMA, time.monotonic() + 1
        )
    assert caught.value.code == "invalid_request" and not caught.value.sent


def test_late_connect_does_not_start_tls_trust_load(monkeypatch):
    module = adapter()
    now = [10.0]
    connect = socket.socket.connect

    def late(sock, address):
        result = connect(sock, address)
        now[0] = 11.0
        return result

    def forbidden():
        pytest.fail("expired connect must not enter trust loading")

    with peer() as (url, requests):
        monkeypatch.setattr(socket.socket, "connect", late)
        monkeypatch.setattr(ssl, "create_default_context", forbidden)
        with pytest.raises(ProviderError) as caught:
            module.OpenAICompatibleProvider(
                settings(url.replace("http:", "https:")), resolver=NoDNS(), clock=lambda: now[0]
            ).generate(MESSAGES, SCHEMA, 11.0)
        assert caught.value.code == "deadline_exceeded" and not caught.value.sent
    assert requests == []


def test_late_decode_does_not_enter_completion_validation(monkeypatch):
    module = adapter()
    now = [10.0]
    decode = module._decode

    def late(data):
        result = decode(data)
        now[0] = 11.0
        return result

    def forbidden(self, value):
        pytest.fail("expired decode must not enter completion validation")

    monkeypatch.setattr(module, "_decode", late)
    monkeypatch.setattr(module.OpenAICompatibleProvider, "_reply", forbidden)
    with peer() as (url, _):
        with pytest.raises(ProviderError) as caught:
            module.OpenAICompatibleProvider(settings(url), resolver=NoDNS(), clock=lambda: now[0]).generate(
                MESSAGES, SCHEMA, 11.0
            )
        assert caught.value.sent and caught.value.code == "deadline_exceeded"


def test_retained_dns_capacity_survives_adapter_replacements_without_late_dial(monkeypatch):
    from local_ai.resolver import ResolverOwner

    module = adapter()
    release = threading.Event()
    workers, calls = [], []

    def lookup(host, port):
        calls.append((host, port))
        workers.append(threading.current_thread())
        assert release.wait(3)
        return [public_answer("8.8.8.8", port)]

    def no_socket(*args, **kwargs):
        pytest.fail("expired DNS must not cause any late or replacement dial")

    monkeypatch.setattr(socket, "socket", no_socket)
    owner = ResolverOwner(lookup=lookup)
    try:
        for index in range(12):
            provider = module.OpenAICompatibleProvider(
                settings(
                    "https://example.invalid", endpoint_policy="public_https", api_key=f"SYNTHETIC-GENERATION-{index}"
                ),
                resolver=owner,
            )
            with pytest.raises(ProviderError) as caught:
                provider.generate(MESSAGES, SCHEMA, time.monotonic() + 0.03)
            assert caught.value.code == ("deadline_exceeded" if index == 0 else "provider_failed")
            assert not caught.value.sent
        assert calls == [("example.invalid", 443)] and owner.retained_workers() == 1
        assert not owner.close(time.monotonic() + 0.01)
    finally:
        release.set()
        for thread in workers:
            thread.join(1)
            assert not thread.is_alive()
        assert owner.close(time.monotonic() + 1)


def test_stalled_real_tls_handshake_has_no_http_or_admission():
    accepted, calls = [], []
    # This plain peer consumes ClientHello but never answers a TLS handshake.
    with peer(accepted=accepted) as (url, requests):
        start = time.monotonic()
        with pytest.raises(ProviderError) as caught:
            adapter().OpenAICompatibleProvider(settings(url.replace("http:", "https:")), resolver=NoDNS()).generate(
                MESSAGES, SCHEMA, start + 0.12, before_send=lambda: calls.append(True)
            )
        assert caught.value.code == "deadline_exceeded" and not caught.value.sent
        assert calls == [] and requests == [] and accepted == [True]
        assert time.monotonic() - start < 0.6


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "::1"])
def test_loopback_literals_and_localhost_never_dns_and_allow_anonymous(host):
    with peer(host="::1" if host == "::1" else "127.0.0.1") as (url, requests):
        if host == "localhost":
            url = url.replace("127.0.0.1", "localhost")
        value = settings(url)
        del value["api_key"]
        result = (
            adapter().OpenAICompatibleProvider(value, resolver=NoDNS()).generate(MESSAGES, SCHEMA, time.monotonic() + 1)
        )
        assert type(result) is NativeReply and len(requests) == 1
        assert "Authorization" not in requests[0]["headers"]
        assert requests[0]["headers"]["Host"] == url.removeprefix("http://")


@pytest.mark.parametrize("variable", ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy"])
def test_inherited_proxy_fails_before_io_without_reflecting_value(variable, monkeypatch):
    module = adapter()
    monkeypatch.setenv(variable, "http://SYNTHETIC-SECRET@proxy.invalid")
    calls = []
    with peer() as (url, requests):
        with pytest.raises(ProviderError) as caught:
            module.OpenAICompatibleProvider(settings(url), resolver=NoDNS()).generate(
                MESSAGES, SCHEMA, time.monotonic() + 1, before_send=lambda: calls.append(True)
            )
        assert not caught.value.sent and str(caught.value) == "provider_failed"
        assert calls == [] and requests == []


@pytest.mark.parametrize(
    "deadline,code",
    [
        (True, "invalid_request"),
        (None, "invalid_request"),
        (float("nan"), "invalid_request"),
        (float("inf"), "invalid_request"),
        (0, "deadline_exceeded"),
        (1000, "invalid_request"),
    ],
)
def test_deadline_admission_never_resets_or_starts_io(deadline, code, monkeypatch):
    module = adapter()

    def no_socket(*args, **kwargs):
        pytest.fail("invalid/expired budget must not enter socket creation")

    monkeypatch.setattr(socket, "socket", no_socket)
    with pytest.raises(ProviderError) as caught:
        module.OpenAICompatibleProvider(
            settings("http://localhost:12345"), resolver=NoDNS(), clock=lambda: 10
        ).generate(MESSAGES, SCHEMA, deadline)
    assert not caught.value.sent and caught.value.code == code


def test_untrusted_factory_cannot_disable_verification(tmp_path, monkeypatch):
    module = adapter()
    server, client = tls_contexts(tmp_path)
    client.check_hostname = False
    client.verify_mode = ssl.CERT_NONE
    monkeypatch.setattr(ssl, "create_default_context", lambda: client)
    calls = []
    with peer(tls_context=server) as (url, requests):
        with pytest.raises(ProviderError) as caught:
            module.OpenAICompatibleProvider(settings(url.replace("http:", "https:")), resolver=NoDNS()).generate(
                MESSAGES, SCHEMA, time.monotonic() + 1, before_send=lambda: calls.append(True)
            )
        assert caught.value.code == "provider_failed" and not caught.value.sent
    assert requests == [] and calls == []
