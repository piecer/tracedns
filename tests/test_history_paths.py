import os
import tempfile
import unittest

from history_manager import load_history_files, persist_history_entry
from http_server import purge_removed_domains_state


class TestHistoryPaths(unittest.TestCase):
    def test_domain_key_cannot_escape_history_directory(self):
        with tempfile.TemporaryDirectory() as root:
            history_dir = os.path.join(root, "history")
            os.makedirs(history_dir)
            domain = "../outside"
            value = {"meta": {}, "events": [], "current": {}}

            persist_history_entry(history_dir, domain, value)

            self.assertFalse(os.path.exists(os.path.join(root, "outside.json")))
            self.assertEqual(load_history_files(history_dir)[domain], value)
            purge_removed_domains_state({}, {domain: value}, history_dir, [domain])
            self.assertNotIn(domain, load_history_files(history_dir))


if __name__ == "__main__":
    unittest.main()
