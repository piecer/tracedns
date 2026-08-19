import threading
import unittest

from monitor.stores import ConfigStore


class TestConfigStore(unittest.TestCase):
    def test_force_resolve_queue_is_drained_in_order(self):
        shared = {
            "domains": [],
            "servers": [],
            "_force_resolve_queue": [
                {"domains": [{"name": "first.example", "type": "A"}]},
                {"domains": [{"name": "second.example", "type": "A"}]},
            ],
        }
        store = ConfigStore(shared, threading.Lock())

        first = store.snapshot().force_req
        second = store.snapshot().force_req

        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        assert first is not None
        assert second is not None
        self.assertEqual(first["domains"][0]["name"], "first.example")
        self.assertEqual(second["domains"][0]["name"], "second.example")
        self.assertNotIn("_force_resolve_queue", shared)


    def test_malformed_numeric_settings_fall_back_without_crashing(self):
        shared = {
            "domains": [],
            "servers": [],
            "interval": "invalid",
            "max_workers": None,
        }
        snapshot = ConfigStore(shared, threading.Lock()).snapshot()
        self.assertEqual(snapshot.interval, 60)
        self.assertEqual(snapshot.max_workers, 8)

    def test_numeric_settings_are_bounded(self):
        shared = {
            "domains": [],
            "servers": [],
            "interval": 999999,
            "max_workers": 999999,
        }
        snapshot = ConfigStore(shared, threading.Lock()).snapshot()
        self.assertEqual(snapshot.interval, 86400)
        self.assertEqual(snapshot.max_workers, 64)


if __name__ == "__main__":
    unittest.main()
