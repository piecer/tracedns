"""Real loopback MISP HTTPS with a private CA; no mocked HTTP/TLS transport.

The fixture is a minimal MISP protocol sink, not a deployed MISP instance.
Certificates and keys are invocation-owned and never use ambient credentials.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ssl
import subprocess
import threading
from types import SimpleNamespace

import pytest

from monitor.delivery_adapters import DestinationRegistry


@pytest.fixture(scope="module")
def misp_certificates(tmp_path_factory):
    root = tmp_path_factory.mktemp("misp-private-ca")

    def openssl(*args):
        subprocess.run(["openssl", *args], cwd=root, check=True,
                       capture_output=True, timeout=15)

    for name in ("trusted", "untrusted"):
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", f"/CN=TraceDNS fixture {name} CA",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout", f"{name}.key", "-out", f"{name}.pem")
    openssl("req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-subj", "/CN=127.0.0.1", "-keyout", "server.key", "-out", "server.csr")
    (root / "server.ext").write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n"
    )
    openssl("x509", "-req", "-in", "server.csr", "-CA", "trusted.pem",
            "-CAkey", "trusted.key", "-set_serial", "2", "-days", "1",
            "-extfile", "server.ext", "-out", "server.pem")
    return root


@pytest.fixture
def misp_https(misp_certificates):
    root = misp_certificates
    sink = SimpleNamespace(requests=[])
    attribute = {"id": "34", "event_id": "12", "type": "ip-src", "value": "192.0.2.1"}

    class MISP(BaseHTTPRequestHandler):
        def respond(self, payload):
            raw = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def record(self, body=None):
            sink.requests.append({"method": self.command, "path": self.path,
                                  "authorization": self.headers.get("Authorization"), "body": body})

        def do_GET(self):
            self.record()
            if self.path == "/private-endpoint-marker/events/view/12":
                self.respond({"Event": {"id": "12", "Attribute": []}})
            else:
                self.send_error(404)

        def do_POST(self):
            length = int(self.headers["Content-Length"])
            assert 0 < length < 4096
            body = json.loads(self.rfile.read(length))
            self.record(body)
            if self.path == "/private-endpoint-marker/attributes/add/12":
                self.respond({"Attribute": attribute})
            elif self.path == "/private-endpoint-marker/attributes/restSearch":
                self.respond({"response": {"Attribute": [attribute]}})
            else:
                self.send_error(404)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), MISP)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(root / "server.pem"), str(root / "server.key"))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    sink.url = f"https://127.0.0.1:{server.server_port}/private-endpoint-marker"
    sink.ca = {name: str(root / f"{name}.pem") for name in ("trusted", "untrusted")}
    try:
        yield sink
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def misp_config(sink, ca):
    return {"misp_url": sink.url, "api_key": "private-api-key-marker", "push_event_id": 12,
            "misp_ca_bundle": sink.ca[ca]}


def bound_claim(sink, ca):
    registry = DestinationRegistry(b"k" * 32)
    registry.apply(misp_config(sink, ca), revision=1)
    descriptor = registry.descriptors()["misp"]
    assert descriptor["ready"] and descriptor["error"] is None
    binding = descriptor["binding_id"]
    adapter = registry.capture("misp", binding, "Added", revision=1)
    claim = {"claim_id": "fixture-claim", "attempt_token": "fixture-attempt", "channel": "misp",
             "binding_id": binding, "action": "Added", "attempt": 1, "provider_calls": 1,
             "progress": {}, "payload": {"entries": [["192.0.2.1", "fixture.example", "A"]]},
             "observation_hook_consumed": False}
    return adapter, claim


def test_misp_registry_private_ca_reads_and_adds_over_real_https(misp_https):
    adapter, claim = bound_claim(misp_https, "trusted")
    read = adapter.execute_step(claim)
    assert read["state"] == "continue", read
    assert read["progress"] == {"phase": "add"}
    assert read["diagnostic"]["operation"] == "misp_read"
    added = adapter.execute_step(dict(claim, progress=read["progress"], provider_calls=2))
    assert added["state"] == "acked", added
    assert added["diagnostic"]["operation"] == "misp_add"
    for outcome in (read, added):
        assert outcome["diagnostic"]["tls_verify"] is True
        assert outcome["diagnostic"]["http_status"] == 200
    assert misp_https.requests == [
        {"method": "GET", "path": "/private-endpoint-marker/events/view/12",
         "authorization": "private-api-key-marker", "body": None},
        {"method": "POST", "path": "/private-endpoint-marker/attributes/add/12",
         "authorization": "private-api-key-marker",
         "body": {"type": "ip-src", "value": "192.0.2.1", "comment": "NST-2-1 fixture.example"}},
    ]


def assert_sanitized(outcome, sink, capsys, caplog):
    captured = capsys.readouterr()
    surfaced = json.dumps(outcome) + captured.out + captured.err + caplog.text
    for marker in (sink.url, "private-endpoint-marker", "private-api-key-marker",
                   sink.ca["untrusted"], "untrusted.pem", "192.0.2.1", "fixture.example"):
        assert marker not in surfaced


@pytest.mark.parametrize("phase", ["read", "add"])
def test_misp_registry_wrong_ca_rejects_without_accepted_requests(
        misp_https, phase, capsys, caplog):
    # The wrong CA is valid PEM, so readiness succeeds; the real handshake fails.
    adapter, claim = bound_claim(misp_https, "untrusted")
    outcome = adapter.execute_step(dict(claim, progress={"phase": phase}))
    assert outcome["state"] == "blocked", outcome
    assert outcome["reason"] == "tls_error"
    assert outcome["provider_calls"] == 1
    assert outcome["diagnostic"]["tls_verify"] is True
    assert outcome["diagnostic"]["tls_kind"] == "certificate_verify"
    assert outcome["diagnostic"]["http_status"] is None
    assert misp_https.requests == []
    assert_sanitized(outcome, misp_https, capsys, caplog)


@pytest.fixture
def misp_search_api(tmp_path):
    from http_server import ThreadingHTTPServer as AppServer, make_handler
    from security.store import SecurityStore
    from test_http_auth_integration import Client

    store = SecurityStore(tmp_path / "private" / "auth.sqlite", create=True)
    store.bootstrap("root", "test-password-123")
    config = {"domains": [], "servers": [], "interval": 60}
    handler = make_handler(config, threading.RLock(), "", str(tmp_path), {}, {},
                           security_store=store, insecure_http=True)
    server = AppServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield Client(server.server_port), config
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()
        for service in handler.background_services:
            service.close()


@pytest.mark.parametrize("prefix", ["", "/api/v1"])
@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize("ca", ["trusted", "untrusted"])
def test_misp_search_api_uses_real_private_ca_https(
        misp_https, misp_search_api, prefix, method, ca, capsys, caplog):
    client, config = misp_search_api
    config["alerts"] = misp_config(misp_https, ca)
    assert client.login()[0] == 200
    path = prefix + "/misp/search"
    if method == "GET":
        code, outcome = client.call(method, path + "?value=192.0.2.1")
    else:
        code, outcome = client.call(method, path, {"value": "192.0.2.1"})
    if ca == "untrusted":
        assert code == 500, outcome
        assert outcome["error"] == "Service unavailable"
        assert isinstance(outcome["request_id"], str) and outcome["request_id"]
        assert set(outcome) == {"error", "request_id"}
        assert misp_https.requests == []
        assert_sanitized(outcome, misp_https, capsys, caplog)
    else:
        assert code == 200, outcome
        assert outcome["status"] == "ok"
        assert outcome["count"] == 1
        assert outcome["attributes"][0]["value"] == "192.0.2.1"
        assert misp_https.requests == [{
            "method": "POST", "path": "/private-endpoint-marker/attributes/restSearch",
            "authorization": "private-api-key-marker",
            "body": {"value": "192.0.2.1", "returnFormat": "json",
                     "type": ["ip-src", "ip-dst", "ip-src|port", "ip-dst|port"]},
        }]
