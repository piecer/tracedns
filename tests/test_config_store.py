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


if __name__ == "__main__":
    unittest.main()
