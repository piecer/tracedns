import threading
import unittest
from socketserver import ThreadingMixIn
from typing import Any, cast
from unittest import mock

from http_server import ThreadingHTTPServer as BoundedThreadingHTTPServer


class TestHttpConcurrencyLimit(unittest.TestCase):
    def test_process_request_waits_until_worker_slot_is_available(self):
        server = object.__new__(BoundedThreadingHTTPServer)
        server._request_slots = threading.BoundedSemaphore(1)
        server._request_slots.acquire()
        entered_parent = threading.Event()

        def parent_process(_server, _request, _address):
            entered_parent.set()

        with mock.patch.object(ThreadingMixIn, "process_request", parent_process):
            thread = threading.Thread(
                target=server.process_request,
                args=(object(), ("127.0.0.1", 12345)),
            )
            thread.start()
            self.assertFalse(entered_parent.wait(0.05))
            server._request_slots.release()
            thread.join(timeout=1)

        self.assertFalse(thread.is_alive())
        self.assertTrue(entered_parent.is_set())

    def test_worker_slot_is_released_after_request(self):
        server = object.__new__(BoundedThreadingHTTPServer)
        server._request_slots = threading.BoundedSemaphore(1)
        server._request_slots.acquire()

        with mock.patch.object(ThreadingMixIn, "process_request_thread"):
            server.process_request_thread(cast(Any, object()), ("127.0.0.1", 12345))

        self.assertTrue(server._request_slots.acquire(blocking=False))


if __name__ == "__main__":
    unittest.main()
