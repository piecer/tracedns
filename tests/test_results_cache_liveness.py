"""A slow cached response must not own the shared read-cache lock."""
import io
import threading
from concurrent.futures import ThreadPoolExecutor

from http_api_handlers import attach_api_handlers


class Handler:
    def __init__(self, writer=None):
        self.wfile = writer if writer is not None else io.BytesIO()
        self.status = None

    def send_response(self, status):
        self.status = status

    def send_header(self, *args):
        pass

    def end_headers(self):
        pass


def test_cached_results_write_does_not_block_results_or_ip_cache():
    entered = threading.Event()
    release = threading.Event()

    class SlowWriter:
        def write(self, data):
            entered.set()
            if not release.wait(5):
                raise TimeoutError('test writer was not released')
            return len(data)

    class Attached(Handler):
        pass

    attach_api_handlers(
        Attached, frontend_html='', shared_config={}, config_lock=threading.RLock(),
        config_path='', history_dir='', current_results={}, history={},
        purge_removed_domains_state=lambda *args: None,
    )
    Attached()._handle_results({'aggregate': ['1']})
    with ThreadPoolExecutor(max_workers=3) as executor:
        first = executor.submit(Attached(SlowWriter())._handle_results, {'aggregate': ['1']})
        assert entered.wait(2)
        result_done = threading.Event()
        ips_done = threading.Event()

        def results():
            handler = Attached()
            handler._handle_results({'aggregate': ['1']})
            result_done.set()
            return handler.status

        def ips():
            value = Attached()._gather_ip_rows()
            ips_done.set()
            return value

        second = executor.submit(results)
        ip_read = executor.submit(ips)
        try:
            assert result_done.wait(1), 'cached writer holds the lock needed by another results request'
            assert ips_done.wait(1), 'cached writer holds the lock needed by IP aggregation'
        finally:
            release.set()
        first.result(timeout=2)
        assert second.result(timeout=2) == 200
        assert ip_read.result(timeout=2) == []
