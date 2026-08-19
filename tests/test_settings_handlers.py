import io
import json
import threading
import unittest
from unittest import mock

from http_api.context import HttpContext
from http_api.settings_handlers import handle_settings_post


class FakeHandler:
    def __init__(self, payload):
        self.headers = {"Content-Length": str(len(payload))}
        self.rfile = io.BytesIO(payload)
        self.wfile = io.BytesIO()
        self.status = None

    def send_response(self, status, message=None):
        self.status = status

    def send_header(self, key, value):
        pass

    def end_headers(self):
        pass


class TestSettingsPersistence(unittest.TestCase):
    def test_save_failure_returns_500_without_mutating_runtime_settings(self):
        original = {"vt_cache_ttl_days": 7}
        shared = {"alerts": dict(original)}
        ctx = HttpContext(
            frontend_html="",
            shared_config=shared,
            config_lock=threading.RLock(),
            config_path="/tmp/settings.json",
            history_dir="/tmp",
            current_results={},
            history={},
            purge_removed_domains_state=lambda *args: None,
        )
        handler = FakeHandler(json.dumps({"alerts": {"vt_cache_ttl_days": 30}}).encode())

        with mock.patch("http_api.settings_handlers.read_config", return_value={}), \
                mock.patch("http_api.settings_handlers.write_config", side_effect=OSError("disk full")):
            handle_settings_post(ctx, handler)

        self.assertEqual(handler.status, 500)
        self.assertEqual(shared["alerts"], original)
        self.assertIn("config save failed", json.loads(handler.wfile.getvalue())["error"])


if __name__ == "__main__":
    unittest.main()
