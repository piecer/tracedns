"""Tests for http_api/config_post.py and http_api/decoder_crud.py (P1-6)."""
from __future__ import annotations

import io
import json
import threading
import unittest

from http_api.context import HttpContext
from http_api.config_post import (
    handle_analyze,
    handle_config_post,
    handle_ip,
    handle_resolve,
    handle_verify,
    get_handler as get_config_handler,
)
from http_api.decoder_crud import (
    handle_decoders_custom_post,
    handle_decoders_custom_preview,
    get_handler as get_decoder_handler,
)


class FakeHandler:
    """Minimal stand-in for the real BaseHTTPRequestHandler."""
    def __init__(self, body: bytes = b''):
        self._body = body
        self.wfile = io.BytesIO()
        self.rfile = io.BytesIO(body)
        self._responses = []
        self.headers = {"Content-Length": str(len(body))}

    def rfile_read(self, n):
        return self._body[:n]

    def send_response(self, code, message=None):
        self._responses.append(code)

    def send_header(self, key, val):
        pass

    def end_headers(self):
        pass

    def _send_json(self, data, code=200):
        payload = json.dumps(data).encode()
        self.send_response(code)
        self.end_headers()
        self.wfile.write(payload)
        return payload

    def get_code(self):
        return self._responses[-1] if self._responses else None

    def get_body(self):
        return json.loads(self.wfile.getvalue().decode()) if self.wfile.getvalue() else None


def make_ctx(**overrides) -> HttpContext:
    defaults = {
        "frontend_html": "test-html",
        "shared_config": {
            "domains": [{"name": "example.com"}],
            "servers": ["8.8.8.8"],
            "interval": 30,
            "custom_decoders": [],
            "custom_a_decoders": [],
        },
        "config_lock": threading.RLock(),
        "config_path": "/tmp/test_config.json",
        "history_dir": "/tmp",
        "current_results": {},
        "history": {},
        "purge_removed_domains_state": lambda *a, **kw: None,
    }
    defaults.update(overrides)
    return HttpContext(**defaults)


class TestConfigPostRouter(unittest.TestCase):
    def test_get_handler_returns_callable(self):
        for path in ("/config", "/resolve", "/ip", "/analyze", "/verify"):
            h = get_config_handler(path)
            self.assertTrue(callable(h), f"{path} handler not callable")

    def test_get_handler_unknown_path_raises(self):
        with self.assertRaises(ValueError):
            get_config_handler("/unknown")


class TestHandleConfigPost(unittest.TestCase):
    def test_config_post_empty_body_ok(self):
        ctx = make_ctx()
        h = FakeHandler(b'{}')
        handle_config_post(ctx, h)
        body = h.get_body()
        self.assertEqual(body["status"], "ok")
        self.assertIn("config", body)

    def test_config_post_invalid_json(self):
        ctx = make_ctx()
        h = FakeHandler(b"not-json")
        handle_config_post(ctx, h)
        body = h.get_body()
        self.assertEqual(body["error"], "invalid json")
        self.assertEqual(h.get_code(), 400)

    def test_config_post_update_domains(self):
        ctx = make_ctx()
        payload = json.dumps({"domains": ["a.com", "b.com"]}).encode()
        h = FakeHandler(payload)
        handle_config_post(ctx, h)
        body = h.get_body()
        self.assertEqual(body["status"], "ok")
        domains = [d["name"] if isinstance(d, dict) else d for d in ctx.shared_config.get("domains", [])]
        self.assertIn("a.com", domains)

    def test_config_post_updates_ens_and_sns_endpoints(self):
        ctx = make_ctx(config_path="")
        payload = json.dumps({
            "ens_rpc_url": "https://rpc.example",
            "DEFAULT_SNS_PROXY_HOSTS": ["https://sns.example"],
        }).encode()

        handle_config_post(ctx, FakeHandler(payload))

        self.assertEqual(ctx.shared_config["ens_rpc_url"], "https://rpc.example")
        self.assertEqual(
            ctx.shared_config["DEFAULT_SNS_PROXY_HOSTS"],
            ["https://sns.example"],
        )


class TestHandleResolve(unittest.TestCase):
    def test_resolve_sets_force_resolve(self):
        ctx = make_ctx(shared_config={
            "domains": [{"name": "example.com"}],
            "servers": ["1.1.1.1"],
        })
        payload = json.dumps({"domain": "example.com", "servers": ["1.1.1.1"]}).encode()
        h = FakeHandler(payload)
        handle_resolve(ctx, h)
        body = h.get_body()
        self.assertEqual(body["status"], "ok")
        self.assertTrue(body["requested"])
        queue = ctx.shared_config.get("_force_resolve_queue", [])
        self.assertIn("domains", queue[0])
        self.assertEqual(queue[0]["servers"], ["1.1.1.1"])

    def test_resolve_no_domain(self):
        ctx = make_ctx()
        h = FakeHandler(b'{"servers": ["1.1.1.1"]}')
        handle_resolve(ctx, h)
        body = h.get_body()
        self.assertEqual(body["error"], "domain or domains required")
        self.assertEqual(h.get_code(), 400)

    def test_resolve_requests_are_queued_without_overwrite(self):
        ctx = make_ctx(shared_config={
            "domains": [
                {"name": "first.example"},
                {"name": "second.example"},
            ],
            "servers": ["8.8.8.8"],
        })
        handle_resolve(ctx, FakeHandler(b'{"domain": "first.example"}'))
        handle_resolve(ctx, FakeHandler(b'{"domain": "second.example"}'))

        queue = ctx.shared_config.get("_force_resolve_queue", [])
        self.assertEqual(
            [item["domains"][0]["name"] for item in queue],
            ["first.example", "second.example"],
        )

    def test_resolve_rejects_unconfigured_domains(self):
        ctx = make_ctx()
        h = FakeHandler(b'{"domain": "unconfigured.example"}')
        handle_resolve(ctx, h)
        self.assertEqual(h.get_code(), 400)
        self.assertEqual(h.get_body()["error"], "domains must be configured")
        self.assertNotIn("_force_resolve_queue", ctx.shared_config)

    def test_resolve_rejects_too_many_domains(self):
        domains = [{"name": f"d{i}.example"} for i in range(65)]
        ctx = make_ctx(shared_config={"domains": domains, "servers": ["8.8.8.8"]})
        h = FakeHandler(json.dumps({"domains": domains}).encode())
        handle_resolve(ctx, h)
        self.assertEqual(h.get_code(), 400)
        self.assertEqual(h.get_body()["error"], "domains must contain at most 64 entries")


class TestHandleIp(unittest.TestCase):
    def test_ip_missing(self):
        ctx = make_ctx()
        h = FakeHandler(b'{}')
        handle_ip(ctx, h)
        body = h.get_body()
        self.assertEqual(body.get("error"), "ip required")
        self.assertEqual(h.get_code(), 400)

    def test_ip_found_in_current_results(self):
        ctx = make_ctx(
            current_results={
                "example.com": {
                    "type": "A",
                    "values": ["1.2.3.4"],
                    "decoded_ips": [],
                }
            }
        )
        payload = json.dumps({"ip": "1.2.3.4"}).encode()
        h = FakeHandler(payload)
        handle_ip(ctx, h)
        body = h.get_body()
        self.assertEqual(body.get("status"), "found")
        self.assertEqual(body.get("domain"), "example.com")

    def test_ip_not_found(self):
        ctx = make_ctx()
        payload = json.dumps({"ip": "9.9.9.9"}).encode()
        h = FakeHandler(payload)
        handle_ip(ctx, h)
        body = h.get_body()
        self.assertEqual(body.get("status"), "ok")


class TestHandleAnalyze(unittest.TestCase):
    def test_analyze_missing_domain(self):
        ctx = make_ctx()
        h = FakeHandler(b'{"txt": "abc"}')
        handle_analyze(ctx, h)
        body = h.get_body()
        self.assertEqual(body.get("error"), "domain and txt required")
        self.assertEqual(h.get_code(), 400)

    def test_analyze_returns_analysis(self):
        ctx = make_ctx()
        payload = json.dumps({"domain": "example.com", "txt": "deadbeef"}).encode()
        h = FakeHandler(payload)
        handle_analyze(ctx, h)
        body = h.get_body()
        self.assertIn("domain", body)
        self.assertIn("sample", body)


class TestHandleVerify(unittest.TestCase):
    def test_verify_with_empty_domains(self):
        ctx = make_ctx(shared_config={"domains": []})
        h = FakeHandler(b'{}')
        handle_verify(ctx, h)
        body = h.get_body()
        self.assertIn("results", body)
        self.assertEqual(body["results"], {})


class TestDecoderCrudRouter(unittest.TestCase):
    def test_get_handler_returns_callable(self):
        for path in ("/decoders/custom", "/decoders/custom/preview"):
            h = get_decoder_handler(path)
            self.assertTrue(callable(h), f"{path} handler not callable")

    def test_get_handler_unknown_path_raises(self):
        with self.assertRaises(ValueError):
            get_decoder_handler("/unknown")


class TestHandleDecodersCustomPost(unittest.TestCase):
    def test_missing_name(self):
        ctx = make_ctx()
        payload = json.dumps({"steps": ["xor32"]}).encode()
        h = FakeHandler(payload)
        handle_decoders_custom_post(ctx, h)
        body = h.get_body()
        self.assertIn("error", body)
        self.assertEqual(h.get_code(), 400)

    def test_invalid_json(self):
        ctx = make_ctx()
        h = FakeHandler(b"not-json")
        handle_decoders_custom_post(ctx, h)
        body = h.get_body()
        self.assertEqual(body["error"], "invalid json")

    def test_missing_steps(self):
        ctx = make_ctx()
        payload = json.dumps({"name": "my_decoder"}).encode()
        h = FakeHandler(payload)
        handle_decoders_custom_post(ctx, h)
        body = h.get_body()
        self.assertIn("error", body)


class TestHandleDecodersCustomPreview(unittest.TestCase):
    def test_missing_name(self):
        ctx = make_ctx()
        payload = json.dumps({"steps": ["xor32"], "sample": "deadbeef"}).encode()
        h = FakeHandler(payload)
        handle_decoders_custom_preview(ctx, h)
        body = h.get_body()
        self.assertIn("error", body)


class TestDoPostDelegation(unittest.TestCase):
    """Verify that attach_api_handlers wires do_POST to the new handler modules."""

    def test_attach_api_handlers_wires_do_post(self):
        from http_api_handlers import attach_api_handlers
        import http.server

        class TestHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

        ctx = make_ctx(config_path="")
        attach_api_handlers(
            TestHandler,
            frontend_html="<html></html>",
            shared_config=ctx.shared_config,
            config_lock=ctx.config_lock,
            config_path=ctx.config_path,
            history_dir=ctx.history_dir,
            current_results=ctx.current_results,
            history=ctx.history,
            purge_removed_domains_state=ctx.purge_removed_domains_state,
        )
        self.assertTrue(hasattr(TestHandler, "do_POST"))
        self.assertTrue(hasattr(TestHandler, "do_PUT"))
        self.assertTrue(hasattr(TestHandler, "do_DELETE"))
        self.assertTrue(hasattr(TestHandler, "_handle_ip_query"))

        settings = FakeHandler(b'{"alerts": {}}')
        setattr(settings, "path", "/settings")
        getattr(TestHandler, "do_POST")(settings)
        self.assertEqual(settings.get_code(), 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
