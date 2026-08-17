"""Regression tests for ``http_api.request_limits`` (P0-2).

The HTTP server previously read ``Content-Length`` verbatim and passed it to
``rfile.read()``, allowing a remote client to claim an absurd body size and
exhaust server memory. ``get_request_body`` enforces a configurable limit
(resolved from ``TRACEDNS_MAX_BODY_BYTES`` or ``DEFAULT_MAX_BODY_BYTES``)
and rejects oversized bodies with HTTP 413.

These tests cover:

* ``resolve_max_body_length`` — env var override path, invalid-value path,
  hard-cap ceiling, and the default path.
* ``get_request_body`` — happy path (body <= limit), rejection (body > limit
  emits 413 and no read), and the explicit override path.
* Handler wiring — the handler class produced by ``attach_api_handlers``
  exposes ``max_body_bytes`` so handlers can read it without threading it
  through every call, and the default resolves to
  ``DEFAULT_MAX_BODY_BYTES`` when no override is passed.
"""

import os
import threading
import unittest
from unittest import mock

import http_api.request_limits as request_limits  # noqa: F401  (imported for patching)
from http_api.request_limits import (
    DEFAULT_MAX_BODY_BYTES,
    MAX_BODY_BYTES_HARD_CAP,
    BodyTooLargeError,
    get_request_body,
    resolve_max_body_length,
)


class _FakeRfile:
    """Minimal stand-in for the handler's ``rfile`` socket file object.

    Records how many bytes were requested by ``read()`` so tests can assert
    that no unbounded read happened for the oversized-body path.
    """

    def __init__(self, data: bytes) -> None:
        self._data = data
        self.read_lengths = []

    def read(self, size: int) -> bytes:
        self.read_lengths.append(size)
        return self._data[:size]


class _FakeHandler:
    """Minimal stand-in for the concrete HTTP request handler.

    Only the attributes touched by ``request_limits`` are implemented:
    ``headers`` (a dict), ``rfile``, ``wfile`` (a buffer), the
    ``send_response``/``send_header``/``end_headers`` trio, and
    ``close_connection``.
    """

    def __init__(self, content_length: int | None = None, body: bytes = b"") -> None:
        self.headers = {"Content-Length": str(content_length)} if content_length is not None else {}
        self.rfile = _FakeRfile(body)
        self._buf = b""
        self.sent_status = None
        self.sent_headers = []
        self.close_connection = False

    # BaseHTTPRequestHandler-style response API.
    def send_response(self, code: int) -> None:
        self.sent_status = code

    def send_header(self, name: str, value: str) -> None:
        self.sent_headers.append((name, value))

    def end_headers(self) -> None:
        pass

    class _Wfile:
        def __init__(self, parent: "_FakeHandler") -> None:
            self._p = parent

        def write(self, chunk: bytes) -> None:
            self._p._buf += chunk

    @property
    def wfile(self) -> "_FakeHandler._Wfile":
        return _FakeHandler._Wfile(self)


class ResolveMaxBodyLengthTests(unittest.TestCase):
    def test_defaults_to_5_mib_when_env_unset(self) -> None:
        env = {}
        self.assertEqual(resolve_max_body_length(env), DEFAULT_MAX_BODY_BYTES)

    def test_env_override_is_used_when_valid(self) -> None:
        env = {"TRACEDNS_MAX_BODY_BYTES": "12345"}
        self.assertEqual(resolve_max_body_length(env), 12345)

    def test_env_override_is_capped_at_hard_cap(self) -> None:
        env = {"TRACEDNS_MAX_BODY_BYTES": str(MAX_BODY_BYTES_HARD_CAP * 10)}
        self.assertEqual(resolve_max_body_length(env), MAX_BODY_BYTES_HARD_CAP)

    def test_env_override_non_numeric_falls_back_to_default(self) -> None:
        env = {"TRACEDNS_MAX_BODY_BYTES": "not-a-number"}
        self.assertEqual(resolve_max_body_length(env), DEFAULT_MAX_BODY_BYTES)

    def test_env_override_non_positive_falls_back_to_default(self) -> None:
        env = {"TRACEDNS_MAX_BODY_BYTES": "0"}
        self.assertEqual(resolve_max_body_length(env), DEFAULT_MAX_BODY_BYTES)
        env["TRACEDNS_MAX_BODY_BYTES"] = "-5"
        self.assertEqual(resolve_max_body_length(env), DEFAULT_MAX_BODY_BYTES)


class GetRequestBodyTests(unittest.TestCase):
    def test_read_body_when_within_limit(self) -> None:
        handler = _FakeHandler(content_length=10, body=b"{" + b"x" * 8 + b"}")
        body, sent_error = get_request_body(handler, max_length=100)
        self.assertFalse(sent_error)
        self.assertEqual(body, b"{" + b"x" * 8 + b"}")
        self.assertIsNone(handler.sent_status, "no 413 expected for a valid body")
        self.assertEqual(handler.rfile.read_lengths, [10])

    def test_read_empty_body_when_no_content_length(self) -> None:
        handler = _FakeHandler(content_length=None, body=b"")
        body, sent_error = get_request_body(handler, max_length=100)
        self.assertFalse(sent_error)
        self.assertEqual(body, b"")
        self.assertEqual(handler.rfile.read_lengths, [], "no read expected when CL absent")

    def test_reject_oversized_body_with_413(self) -> None:
        handler = _FakeHandler(content_length=10 * 1024 * 1024, body=b"")
        body, sent_error = get_request_body(handler, max_length=5 * 1024 * 1024)
        self.assertTrue(sent_error, "oversized body must set sent_error")
        self.assertEqual(body, b"")
        self.assertEqual(handler.sent_status, 413)
        self.assertEqual(handler.rfile.read_lengths, [], "no read must occur on rejection")
        self.assertTrue(
            any(name == "Content-Type" and "text/plain" in value
                for name, value in handler.sent_headers),
            f"expected text/plain response, got {handler.sent_headers}",
        )

    def test_reject_when_declared_length_exceeds_limit_even_if_body_is_empty(self) -> None:
        # Regression: an attacker can claim a huge Content-Length with no body
        # to force the server to attempt a multi-gigabyte read. The limit is
        # evaluated before any ``rfile.read`` call.
        handler = _FakeHandler(content_length=2 * 1024 * 1024 * 1024, body=b"")
        body, sent_error = get_request_body(handler, max_length=5 * 1024 * 1024)
        self.assertTrue(sent_error)
        self.assertEqual(handler.sent_status, 413)
        self.assertEqual(handler.rfile.read_lengths, [], "no read must happen for the oversized claim")

    def test_body_length_equal_to_limit_is_allowed(self) -> None:
        limit = 8
        handler = _FakeHandler(content_length=limit, body=b"12345678")
        body, sent_error = get_request_body(handler, max_length=limit)
        self.assertFalse(sent_error)
        self.assertEqual(body, b"12345678")

    def test_body_length_one_over_limit_is_rejected(self) -> None:
        limit = 8
        handler = _FakeHandler(content_length=limit + 1, body=b"123456789")
        body, sent_error = get_request_body(handler, max_length=limit)
        self.assertTrue(sent_error)
        self.assertEqual(handler.sent_status, 413)

    def test_resolve_max_body_length_respected_when_max_length_is_none(self) -> None:
        # When the handler does not pass an explicit limit, we resolve from
        # env. Use an isolated env dict to keep this test hermetic:
        # TRACEDNS_MAX_BODY_BYTES=16 declares a 16-byte limit; a body that
        # declares 32 bytes must be rejected with 413.
        isolated_env = {"TRACEDNS_MAX_BODY_BYTES": "16"}
        handler = _FakeHandler(content_length=32, body=b"")
        with mock.patch.dict(os.environ, isolated_env, clear=False):
            body, sent_error = get_request_body(handler)
        self.assertTrue(sent_error)
        self.assertEqual(handler.sent_status, 413)


class HandlerWiringTests(unittest.TestCase):
    def test_handler_class_exposes_max_body_bytes_default(self) -> None:
        import http_server as hs

        handler_cls = hs.make_handler(
            shared_config={"domains": [], "servers": ["8.8.8.8"], "interval": 60},
            config_lock=threading.Lock(),
            config_path=None,
            history_dir=None,
            current_results={},
            history={},
        )
        # No explicit override -> module default.
        self.assertEqual(handler_cls.max_body_bytes, DEFAULT_MAX_BODY_BYTES)

    def test_handler_class_exposes_max_body_bytes_override(self) -> None:
        import http_server as hs

        handler_cls = hs.make_handler(
            shared_config={"domains": [], "servers": ["8.8.8.8"], "interval": 60},
            config_lock=threading.Lock(),
            config_path=None,
            history_dir=None,
            current_results={},
            history={},
            max_body_bytes=12345,
        )
        self.assertEqual(handler_cls.max_body_bytes, 12345)


class BodyTooLargeErrorTests(unittest.TestCase):
    def test_carries_length_and_limit(self) -> None:
        err = BodyTooLargeError(length=42, limit=10)
        self.assertEqual(err.length, 42)
        self.assertEqual(err.limit, 10)
        self.assertIn("42", str(err))
        self.assertIn("10", str(err))


if __name__ == "__main__":
    unittest.main()
