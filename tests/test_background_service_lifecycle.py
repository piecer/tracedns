"""Server binding owns background-service admission and cleanup."""
from http.server import BaseHTTPRequestHandler
from unittest.mock import Mock

from http_server import ThreadingHTTPServer


def test_background_services_start_after_binding_and_close_once():
    service = Mock()
    service.close.return_value = {'running': 0, 'queued': 0, 'remaining': 0}

    class Handler(BaseHTTPRequestHandler):
        background_services = (service,)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    try:
        service.start.assert_called_once_with()
    finally:
        server.server_close()
        server.server_close()
    service.stop_admission.assert_called_once_with()
    service.close.assert_called_once()
    assert 0 <= service.close.call_args.kwargs['timeout'] <= 1


def test_failed_bind_never_starts_background_services():
    service = Mock()

    class Handler(BaseHTTPRequestHandler):
        background_services = (service,)

    occupied = ThreadingHTTPServer(('127.0.0.1', 0), BaseHTTPRequestHandler)
    try:
        try:
            ThreadingHTTPServer(occupied.server_address, Handler)
        except OSError:
            pass
        else:
            raise AssertionError('duplicate port bind unexpectedly succeeded')
        service.start.assert_not_called()
    finally:
        occupied.server_close()
