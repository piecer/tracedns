import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

import vt_lookup


class TestVirusTotalCaching(unittest.TestCase):
    def setUp(self):
        self.old_cache = dict(vt_lookup._CACHE)
        self.old_key = vt_lookup._GLOBAL_API_KEY
        self.old_dirty = vt_lookup._CACHE_DIRTY
        vt_lookup._CACHE.clear()
        vt_lookup._CACHE_INFLIGHT.clear()
        vt_lookup._CACHE_DIRTY = False
        vt_lookup.set_api_key("test-api-key")

    def tearDown(self):
        vt_lookup._CACHE.clear()
        vt_lookup._CACHE.update(self.old_cache)
        vt_lookup._GLOBAL_API_KEY = self.old_key
        vt_lookup._CACHE_INFLIGHT.clear()
        vt_lookup._CACHE_DIRTY = self.old_dirty

    def test_failed_lookup_is_not_cached_for_full_ttl(self):
        with (
            mock.patch.object(vt_lookup, "_fetch_from_vt", return_value=None) as fetch,
            mock.patch.object(vt_lookup, "flush_cache"),
        ):
            self.assertIsNone(vt_lookup.get_ip_report("192.0.2.1"))
            self.assertIsNone(vt_lookup.get_ip_report("192.0.2.1"))

        self.assertEqual(fetch.call_count, 2)
        self.assertNotIn("192.0.2.1", vt_lookup._CACHE)


    def test_concurrent_misses_share_one_network_lookup(self):
        entered = threading.Event()
        second_started = threading.Event()
        release = threading.Event()
        report = {"malicious": 0}

        def fetch(_ip, _key):
            entered.set()
            release.wait(1)
            return report

        with (
            mock.patch.object(vt_lookup, "_fetch_from_vt", side_effect=fetch) as fetch_mock,
            mock.patch.object(vt_lookup, "flush_cache"),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            first = executor.submit(vt_lookup.get_ip_report, "192.0.2.2")
            self.assertTrue(entered.wait(1))
            def second_lookup():
                second_started.set()
                return vt_lookup.get_ip_report("192.0.2.2")

            second = executor.submit(second_lookup)
            self.assertTrue(second_started.wait(1))
            time.sleep(0.05)
            release.set()
            self.assertEqual(first.result(timeout=1), report)
            self.assertEqual(second.result(timeout=1), report)

        self.assertEqual(fetch_mock.call_count, 1)

    def test_failed_cache_flush_remains_dirty_for_retry(self):
        vt_lookup._CACHE_DIRTY = True
        with mock.patch.object(vt_lookup, "_save_cache_locked", return_value=False):
            self.assertFalse(vt_lookup.flush_cache(force=True))
        self.assertTrue(vt_lookup._CACHE_DIRTY)


if __name__ == "__main__":
    unittest.main()
