import os
import tempfile
import unittest
from unittest import mock

from config_manager import write_config


class TestWriteConfig(unittest.TestCase):
    def test_replace_failure_is_reported_and_original_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            with open(path, "w", encoding="utf-8") as stream:
                stream.write('{"old": true}')

            with mock.patch("config_manager.os.replace", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    write_config(path, {"new": True})

            with open(path, "r", encoding="utf-8") as stream:
                self.assertEqual(stream.read(), '{"old": true}')


if __name__ == "__main__":
    unittest.main()