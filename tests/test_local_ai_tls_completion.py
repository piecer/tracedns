"""Real verified TLS framing -> authenticated application -> durable admission.

BT-1 regressions use only invocation-owned CA/peers and ordinary repo fixtures.
No provider, reader, reservation or settlement result is replaced.
"""

import importlib
import json
import socket
import ssl
import threading
import time
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from http_api.local_ai_schema import JOB_SCHEMA
from local_ai.openai_provider import OpenAICompatibleProvider
from local_ai.provider import ProviderError, ProviderReply
from local_ai.provider_outcomes import ProviderRejected
from security.store import SecurityStore
from test_ai_settings_api import app as app_fixture
from test_local_ai_application import wait_job
from test_local_ai_openai_provider import (
    KEY, MESSAGES, SCHEMA, NoDNS, encoded, envelope, no_proxy as no_proxy, peer, response, settings, tls_contexts,
)

app = app_fixture
ROOT = Path(__file__).resolve().parents[1]
OPAQUE = "SYNTHETIC-TLS-ERROR-BODY"
REQUEST = {"kind": "delivery", "language": "en"}


def save(app, patch):
    status, loaded = app.client.call("GET", "/ai/settings")
    assert status == 200
    status, saved = app.client.call(
        "POST", "/ai/settings", {"revision": loaded["revision"], "settings": patch}
    )
    assert status == 200, saved
    return saved


def shutdown_tls(sock, *, clean):
    if clean:
        try:
            raw = sock.unwrap()  # Sends close_notify before waiting for its peer.
        except (ssl.SSLError, OSError):
            pass
        else:
            raw.close()
    else:
        # SSLSocket.close alone is not an authenticated TLS EOF.
        with socket.socket(fileno=sock.detach()) as raw:
            raw.shutdown(socket.SHUT_WR)


def assert_origins():
    for name in (
        "local_ai.openai_provider", "local_ai.provider", "local_ai.resolver",
        "local_ai.engine", "local_ai.service", "security.store", "http_api.local_ai",
    ):
        filename = importlib.import_module(name).__file__
        assert filename is not None
        assert Path(filename).resolve() == ROOT / (name.replace(".", "/") + ".py")


def test_ragged_eof_rejection_remains_durable_after_readmission_and_toggle(app, tmp_path, monkeypatch, caplog, capsys):
    assert_origins()
    server, client = tls_contexts(tmp_path)
    assert client.check_hostname and client.verify_mode == ssl.CERT_REQUIRED
    monkeypatch.setattr(ssl, "create_default_context", lambda: client)
    body = (OPAQUE + " " + KEY).encode()
    wire = response(body, 401, [("Content-Type", "text/plain"), ("Connection", "close")])

    def answer(sock, stop):
        sock.sendall(wire)
        shutdown_tls(sock, clean=False)

    with peer(answer, tls_context=server) as (url, requests):
        saved = save(app, settings(url.replace("http://127.0.0.1", "https://localhost") + "/v1"))
        assert requests == [] and app.native_requests == []
        status, admitted = app.client.call("POST", "/ai/jobs", REQUEST)
        assert status == 202, admitted
        terminal = wait_job(app.client, "/ai/jobs/" + admitted["job_id"])
        assert terminal is not None
        state = SecurityStore(app.store.path).llm_provider_state()
        status, availability = app.client.call("GET", "/ai/status")
        assert status == 200
        second_status, second = app.client.call("POST", "/ai/jobs", REQUEST)
        second_terminal = None
        if second_status == 202:
            second_terminal = wait_job(app.client, "/ai/jobs/" + second["job_id"])
        save(app, {"enabled": False})
        disabled_state = SecurityStore(app.store.path).llm_provider_state()
        save(app, {"enabled": True})
        toggled_state = SecurityStore(app.store.path).llm_provider_state()
        toggle_status, toggled = app.client.call("POST", "/ai/jobs", REQUEST)
        toggle_terminal = None
        if toggle_status == 202:
            toggle_terminal = wait_job(app.client, "/ai/jobs/" + toggled["job_id"])
        audits = app.store.audit_list(action="llm.provider")["events"]
        observed = {
            "first_terminal": terminal, "reopened_state": state, "availability": availability,
            "second_status": second_status, "second_terminal": second_terminal,
            "disabled_state": disabled_state, "toggled_state": toggled_state,
            "toggle_status": toggle_status, "toggle_terminal": toggle_terminal,
            "requests": len(requests), "native_requests": len(app.native_requests),
            "provider_audits": [{key: event[key] for key in ("job_id", "outcome", "status")} for event in audits],
            "check_hostname": client.check_hostname, "verify_mode": int(client.verify_mode),
        }
        # Keep the actual RED observations too; never infer success from JUnit presence.
        (tmp_path / "tls-application.json").write_text(json.dumps(observed, indent=2) + "\n")
        assert state["blocked"] and second_status == 503 and len(requests) == 1, (
            "TLS framing must remain incomplete without a declared full body or authenticated EOF", state, second_status
        )
        assert state == {"blocked": True, "job_id": admitted["job_id"], "outcome": "started"}
        assert terminal["status"] == "failed" and terminal["error"] == "provider_failed"
        assert terminal["result"] is None and terminal["audit_status"] == "success"
        Draft202012Validator(JOB_SCHEMA).validate(terminal)
        assert availability["provider_state"] == "unsettled" and availability["accepting"] is False
        assert second["code"] == "provider_unsettled"
        assert disabled_state == toggled_state == state
        assert toggle_status == 503 and toggled["code"] == "provider_unsettled"
        assert [(event["job_id"], event["outcome"]) for event in audits] == [(admitted["job_id"], "started")]
        assert app.native_requests == [] and len(requests) == 1
        assert app.client.call("GET", "/auth/me")[0] == 200
        public = json.dumps([observed, saved, second, toggled, app.store.audit_list(limit=1000)])
        captured = capsys.readouterr()
        for secret in (KEY, OPAQUE):
            assert secret not in public + captured.out + captured.err + caplog.text


FRAMING_CONTROLS = [
    pytest.param("eof", True, True, id="clean-eof"),
    pytest.param("length", False, True, id="ragged-complete-length"),
    pytest.param("chunked", False, True, id="ragged-complete-chunked"),
    pytest.param("short-length", False, False, id="ragged-short-length"),
    pytest.param("short-chunk-data", False, False, id="ragged-short-chunk-data"),
    pytest.param("missing-chunk-terminal", False, False, id="ragged-missing-chunk-terminal"),
]


def framed_response(status, framing):
    body = encoded(envelope()) if status == 200 else (OPAQUE + " " + KEY).encode()
    headers = [("Content-Type", "application/json" if status == 200 else "text/plain"), ("Connection", "close")]
    if framing in ("length", "short-length"):
        headers.append(("Content-Length", str(len(body) + (9 if framing == "short-length" else 0))))
    elif framing in ("chunked", "short-chunk-data", "missing-chunk-terminal"):
        headers.append(("Transfer-Encoding", "chunked"))
        declared = len(body) + (9 if framing == "short-chunk-data" else 0)
        body = f"{declared:x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
        if framing == "missing-chunk-terminal":
            body = body[:-2]  # The final empty trailer line is mandatory.
    else:
        assert framing == "eof"
    return response(body, status, headers)


@pytest.mark.parametrize("framing,clean,complete", FRAMING_CONTROLS)
def test_tls_rejection_framing_controls_real_durable_readmission(
    app, tmp_path, monkeypatch, framing, clean, complete, caplog, capsys
):
    assert_origins()
    server, client = tls_contexts(tmp_path)
    monkeypatch.setattr(ssl, "create_default_context", lambda: client)
    sni = []
    server.set_servername_callback(lambda sock, name, context: sni.append(name))

    def answer(sock, stop):
        sock.sendall(framed_response(401, framing))
        shutdown_tls(sock, clean=clean)

    with peer(answer, tls_context=server) as (url, requests):
        https = url.replace("http://127.0.0.1", "https://localhost")
        save(app, settings(https + "/v1"))
        assert requests == [] and app.native_requests == []
        status, admitted = app.client.call("POST", "/ai/jobs", REQUEST)
        assert status == 202, admitted
        terminal = wait_job(app.client, "/ai/jobs/" + admitted["job_id"])
        assert terminal is not None
        state = SecurityStore(app.store.path).llm_provider_state()
        status, availability = app.client.call("GET", "/ai/status")
        assert status == 200
        second_status, second = app.client.call("POST", "/ai/jobs", REQUEST)
        second_terminal = None
        if second_status == 202:
            second_terminal = wait_job(app.client, "/ai/jobs/" + second["job_id"])
        audits = app.store.audit_list(action="llm.provider")["events"]
        first_audits = [event for event in audits if event["job_id"] == admitted["job_id"]]
        expected_error = "provider_auth_failed" if complete else "provider_failed"
        expected_state = {"blocked": not complete, "job_id": admitted["job_id"],
                          "outcome": "http_rejected" if complete else "started"}
        observed = {
            "framing": framing, "clean_shutdown": clean, "first_terminal": terminal,
            "reopened_state": state, "availability": availability, "second_status": second_status,
            "second_terminal": second_terminal, "requests": len(requests), "native_requests": len(app.native_requests),
            "provider_audits": [{key: event[key] for key in ("job_id", "outcome", "status")} for event in audits],
            "check_hostname": client.check_hostname, "verify_mode": int(client.verify_mode), "sni": sni,
        }
        (tmp_path / "tls-application.json").write_text(json.dumps(observed, indent=2) + "\n")
        assert state == expected_state
        assert terminal["status"] == "failed" and terminal["error"] == expected_error
        assert terminal["audit_status"] == "success" and terminal["result"] is None
        Draft202012Validator(JOB_SCHEMA).validate(terminal)
        assert client.check_hostname and client.verify_mode == ssl.CERT_REQUIRED
        assert app.native_requests == []
        assert sni == ["localhost"] * len(requests)
        assert all(r["headers"]["Host"] == https.removeprefix("https://") for r in requests)
        if complete:
            assert second_status == 202 and len(requests) == 2
            assert second_terminal is not None and second_terminal["error"] == "provider_auth_failed"
            assert second_terminal["audit_status"] == "success" and second_terminal["result"] is None
            assert availability["provider_state"] == "ready" and availability["accepting"] is True
            assert sorted(event["outcome"] for event in first_audits) == ["http_rejected", "started"]
            assert [event["status"] for event in first_audits if event["outcome"] == "http_rejected"] == [401]
        else:
            assert second_status == 503 and second["code"] == "provider_unsettled" and len(requests) == 1
            assert availability["provider_state"] == "unsettled" and availability["accepting"] is False
            assert [event["outcome"] for event in first_audits] == ["started"]
        public = json.dumps([observed, second, app.store.audit_list(limit=1000)])
        captured = capsys.readouterr()
        for secret in (KEY, OPAQUE):
            assert secret not in public + captured.out + captured.err + caplog.text


@pytest.mark.parametrize("status", [200, 401])
@pytest.mark.parametrize("framing,clean,complete", [
    pytest.param("eof", False, False, id="ragged-eof"), *FRAMING_CONTROLS,
])
def test_actual_tls_transport_completion_and_owned_socket(
    tmp_path, monkeypatch, status, framing, clean, complete, caplog, capsys
):
    server, client = tls_contexts(tmp_path)
    monkeypatch.setattr(ssl, "create_default_context", lambda: client)
    wrapped, wrap_arguments, callbacks, sni = [], [], [], []
    wrap = client.wrap_socket
    shutdown_done = threading.Event()
    server.set_servername_callback(lambda sock, name, context: sni.append(name))

    def observed_wrap(sock, *args, **kwargs):
        secure = wrap(sock, *args, **kwargs)
        wrapped.append(secure)
        wrap_arguments.append(kwargs)
        return secure

    monkeypatch.setattr(client, "wrap_socket", observed_wrap)

    def answer(sock, stop):
        sock.sendall(framed_response(status, framing))
        shutdown_tls(sock, clean=clean)
        shutdown_done.set()

    with peer(answer, tls_context=server) as (url, requests):
        https = url.replace("http://127.0.0.1", "https://localhost")
        provider = OpenAICompatibleProvider(settings(https), resolver=NoDNS())
        deadline = time.monotonic() + 2
        error = None
        if complete:
            reply = provider.generate(MESSAGES, SCHEMA, deadline, before_send=lambda: callbacks.append(len(requests)))
            if status == 200:
                assert type(reply) is ProviderReply and reply.content == '{"ok":true}'
                assert reply.content_error is None
            else:
                assert type(reply) is ProviderRejected and reply.http_status == 401
        else:
            with pytest.raises(ProviderError) as caught:
                provider.generate(MESSAGES, SCHEMA, deadline, before_send=lambda: callbacks.append(len(requests)))
            assert caught.value.code == "provider_failed" and caught.value.sent is True
            assert str(caught.value) == "provider_failed" and caught.value.__cause__ is None
            assert caught.value.__suppress_context__ is True
            error = {"type": type(caught.value).__name__, "code": caught.value.code, "sent": caught.value.sent}
        assert shutdown_done.wait(1), "the peer must actually perform its declared shutdown"
        assert len(requests) == 1 and callbacks == [0] and sni == ["localhost"]
        assert requests[0]["headers"]["Host"] == https.removeprefix("https://")
        assert requests[0]["headers"]["Authorization"] == "Bearer " + KEY
        assert wrap_arguments == [{"server_hostname": "localhost", "do_handshake_on_connect": False,
                                   "suppress_ragged_eofs": False}]
        assert len(wrapped) == 1 and wrapped[0].fileno() == -1
        assert wrapped[0].suppress_ragged_eofs is False
        assert client.check_hostname and client.verify_mode == ssl.CERT_REQUIRED
        observed = {"status": status, "framing": framing, "clean_shutdown": clean, "complete": complete,
                    "error": error, "requests": len(requests), "callbacks": callbacks, "sni": sni,
                    "wrap_arguments": wrap_arguments, "owned_socket_fd": wrapped[0].fileno(),
                    "check_hostname": client.check_hostname, "verify_mode": int(client.verify_mode),
                    "shutdown_done": shutdown_done.is_set()}
        (tmp_path / "tls-transport.json").write_text(json.dumps(observed, indent=2) + "\n")
        captured = capsys.readouterr()
        for secret in (KEY, OPAQUE):
            assert secret not in json.dumps(observed) + captured.out + captured.err + caplog.text


@pytest.mark.parametrize("clean", [True, False], ids=["close-notify", "ragged-eof"])
def test_installed_strict_ssl_distinguishes_the_same_shutdown(tmp_path, clean):
    server, client = tls_contexts(tmp_path)
    assert issubclass(ssl.SSLEOFError, OSError)
    assert client.check_hostname and client.verify_mode == ssl.CERT_REQUIRED

    def answer(sock, stop):
        sock.sendall(framed_response(401, "eof"))
        shutdown_tls(sock, clean=clean)

    with peer(answer, tls_context=server) as (url, requests):
        port = int(url.rsplit(":", 1)[1])
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
            raw.settimeout(2)
            raw.connect(("127.0.0.1", port))
            with client.wrap_socket(raw, server_hostname="localhost", suppress_ragged_eofs=False) as secure:
                secure.sendall(b"POST /control HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
                received = b""
                error = None
                try:
                    while data := secure.recv(4096):
                        received += data
                except ssl.SSLEOFError as exc:
                    error = type(exc).__name__
                assert received.startswith(b"HTTP/1.1 401")
                assert error == (None if clean else "SSLEOFError")
                assert len(requests) == 1
        observed = {"clean_shutdown": clean, "error": error, "received_bytes": len(received),
                    "openssl": ssl.OPENSSL_VERSION, "check_hostname": client.check_hostname,
                    "verify_mode": int(client.verify_mode), "ssleof_is_oserror": issubclass(ssl.SSLEOFError, OSError)}
        (tmp_path / "tls-oracle.json").write_text(json.dumps(observed, indent=2) + "\n")


@pytest.mark.parametrize("status", [200, 401])
def test_tls_eof_wait_keeps_the_original_deadline(tmp_path, monkeypatch, status):
    server, client = tls_contexts(tmp_path)
    monkeypatch.setattr(ssl, "create_default_context", lambda: client)
    callbacks = []

    def answer(sock, stop):
        sock.sendall(framed_response(status, "eof"))
        stop.wait(2)  # No close_notify/EOF; fixture exit releases the owned peer.

    with peer(answer, tls_context=server) as (url, requests):
        provider = OpenAICompatibleProvider(
            settings(url.replace("http://127.0.0.1", "https://localhost")), resolver=NoDNS()
        )
        started = time.monotonic()
        with pytest.raises(ProviderError) as caught:
            provider.generate(MESSAGES, SCHEMA, started + 0.08, before_send=lambda: callbacks.append(len(requests)))
        elapsed = time.monotonic() - started
        assert caught.value.code == "deadline_exceeded" and caught.value.sent
        assert elapsed < 0.5 and len(requests) == 1 and callbacks == [0]
        (tmp_path / "tls-deadline.json").write_text(json.dumps({
            "status": status, "elapsed": elapsed, "original_budget": 0.08,
            "code": caught.value.code, "sent": caught.value.sent, "requests": len(requests),
        }, indent=2) + "\n")
