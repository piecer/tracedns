import os
import tempfile
import unittest
import sys
import threading
import json


HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import http_server as hs
from monitor.runtime_state import bump_state_version, get_state_version


class TestHttpServerDomainPurge(unittest.TestCase):
    def test_purge_removed_domains_state(self):
        with tempfile.TemporaryDirectory() as td:
            hist_file = os.path.join(td, "removed.example.json")
            with open(hist_file, "w", encoding="utf-8") as f:
                f.write("{}")

            current_results = {
                "removed.example": {"8.8.8.8": {"type": "A", "values": ["1.2.3.4"]}},
                "keep.example": {"8.8.8.8": {"type": "A", "values": ["5.6.7.8"]}},
            }
            history = {
                "removed.example": {"meta": {}, "events": [], "current": {}},
                "keep.example": {"meta": {}, "events": [], "current": {}},
            }

            hs.purge_removed_domains_state(
                current_results=current_results,
                history=history,
                history_dir=td,
                removed_domains=["removed.example"],
            )

            self.assertNotIn("removed.example", current_results)
            self.assertNotIn("removed.example", history)
            self.assertIn("keep.example", current_results)
            self.assertIn("keep.example", history)
            self.assertFalse(os.path.exists(hist_file))

    def test_purge_removed_domains_state_bumps_state_version(self):
        current_results = {
            "removed.example": {"8.8.8.8": {"type": "A", "values": ["1.2.3.4"]}},
        }
        history = {
            "removed.example": {"meta": {}, "events": [], "current": {}},
        }
        before = get_state_version()
        hs.purge_removed_domains_state(
            current_results=current_results,
            history=history,
            history_dir=None,
            removed_domains=["removed.example"],
        )
        after = get_state_version()
        self.assertGreater(after, before)
        self.assertNotIn("removed.example", current_results)
        self.assertNotIn("removed.example", history)

    def test_domain_analysis_returns_all_domains(self):
        shared_config = {
            "domains": [
                {"name": "alpha.example", "type": "A"},
                {"name": "beta.example", "type": "A"},
            ],
            "servers": ["8.8.8.8"],
            "interval": 60,
        }
        lock = threading.Lock()
        current_results = {
            "alpha.example": {
                "8.8.8.8": {
                    "type": "A",
                    "values": ["1.2.3.4"],
                    "decoded_ips": [],
                    "ts": 1700000001,
                }
            },
            "gamma.example": {
                "8.8.8.8": {
                    "type": "A",
                    "values": ["5.6.7.8"],
                    "decoded_ips": [],
                    "ts": 1700000002,
                }
            },
        }
        history = {
            "beta.example": {
                "meta": {"nxdomain_active": True, "nxdomain_since": 1700000000},
                "events": [],
                "current": {},
            }
        }

        handler_cls = hs.make_handler(
            shared_config=shared_config,
            config_lock=lock,
            config_path=None,
            history_dir=None,
            current_results=current_results,
            history=history,
        )
        captured = {}
        handler = object.__new__(handler_cls)
        handler._send_json = lambda obj, code=200: captured.update({"obj": obj, "code": code})

        handler_cls._handle_domain_analysis(handler, {"include_vt": ["0"]})

        payload = captured.get("obj") or {}
        names = {d.get("domain") for d in (payload.get("domains") or [])}
        self.assertIn("alpha.example", names)
        self.assertIn("beta.example", names)
        self.assertIn("gamma.example", names)
        self.assertGreaterEqual(len(names), 3)

    def test_results_handler_cache_refreshes_after_state_change(self):
        shared_config = {
            "domains": [{"name": "alpha.example", "type": "A"}],
            "servers": ["8.8.8.8"],
            "interval": 60,
        }
        lock = threading.Lock()
        current_results = {
            "alpha.example": {
                "8.8.8.8": {
                    "type": "A",
                    "values": ["1.2.3.4"],
                    "decoded_ips": [],
                    "ts": 1700000001,
                }
            }
        }
        history = {
            "alpha.example": {
                "meta": {"nxdomain_active": False},
                "events": [],
                "current": {},
            }
        }

        handler_cls = hs.make_handler(
            shared_config=shared_config,
            config_lock=lock,
            config_path=None,
            history_dir=None,
            current_results=current_results,
            history=history,
        )

        class _Writer:
            def __init__(self):
                self.data = b""

            def write(self, chunk):
                self.data = chunk

        handler = object.__new__(handler_cls)
        handler.send_response = lambda code: None
        handler.send_header = lambda *args, **kwargs: None
        handler.end_headers = lambda: None

        handler.wfile = _Writer()
        handler_cls._handle_results(handler, {"aggregate": ["1"]})
        first = json.loads(handler.wfile.data.decode("utf-8"))
        self.assertEqual(first["results_agg"]["alpha.example"]["values"], ["1.2.3.4"])

        current_results["alpha.example"]["8.8.8.8"]["values"] = ["5.6.7.8"]
        bump_state_version()

        handler.wfile = _Writer()
        handler_cls._handle_results(handler, {"aggregate": ["1"]})
        second = json.loads(handler.wfile.data.decode("utf-8"))
        self.assertEqual(second["results_agg"]["alpha.example"]["values"], ["5.6.7.8"])


if __name__ == "__main__":
    unittest.main()
