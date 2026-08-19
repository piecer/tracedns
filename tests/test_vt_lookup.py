import unittest
from unittest import mock

import vt_lookup


class TestVirusTotalCaching(unittest.TestCase):
    def setUp(self):
        self.old_cache = dict(vt_lookup._CACHE)
        self.old_key = vt_lookup._GLOBAL_API_KEY
        vt_lookup._CACHE.clear()
        vt_lookup.set_api_key("test-api-key")

    def tearDown(self):
        vt_lookup._CACHE.clear()
        vt_lookup._CACHE.update(self.old_cache)
        vt_lookup._GLOBAL_API_KEY = self.old_key

    def test_failed_lookup_is_not_cached_for_full_ttl(self):
        with (
            mock.patch.object(vt_lookup, "_fetch_from_vt", return_value=None) as fetch,
            mock.patch.object(vt_lookup, "flush_cache"),
        ):
            self.assertIsNone(vt_lookup.get_ip_report("192.0.2.1"))
            self.assertIsNone(vt_lookup.get_ip_report("192.0.2.1"))

        self.assertEqual(fetch.call_count, 2)
        self.assertNotIn("192.0.2.1", vt_lookup._CACHE)


if __name__ == "__main__":
    unittest.main()
