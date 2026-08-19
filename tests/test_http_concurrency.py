import threading
import unittest
from socketserver import ThreadingMixIn
from typing import Any, cast
from unittest import mock

from http_server import ThreadingHTTPServer as BoundedThreadingHTTPServer


class TestHttpConcurrencyLimit(unittest.TestCase):
    def test_process_request_rejects_when_worker_slots_are_full(self):
        server = object.__new__(BoundedThreadingHTTPServer)
        server._request_slots = threading.BoundedSemaphore(1)
        server._request_slots.acquire()
        server.request_timeout = 5
        entered_parent = threading.Event()

        request = mock.Mock()

        def parent_process(_server, _request, _address):
            entered_parent.set()

        with mock.patch.object(ThreadingMixIn, "process_request", parent_process):
            server.process_request(request, ("127.0.0.1", 12345))

        self.assertFalse(entered_parent.is_set())
        request.sendall.assert_called_once()
        self.assertIn(b"503 Service Unavailable", request.sendall.call_args.args[0])
        request.settimeout.assert_called_once_with(5)

    def test_worker_slot_is_released_after_request(self):
        server = object.__new__(BoundedThreadingHTTPServer)
        server._request_slots = threading.BoundedSemaphore(1)
        server._request_slots.acquire()

        with mock.patch.object(ThreadingMixIn, "process_request_thread"):
            server.process_request_thread(cast(Any, object()), ("127.0.0.1", 12345))

        self.assertTrue(server._request_slots.acquire(blocking=False))


if __name__ == "__main__":
    unittest.main()
