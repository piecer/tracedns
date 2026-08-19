import io
import json
import unittest
from unittest import mock

from http_api import relationship_handlers


class FakeHandler:
    def __init__(self, payload):
        self.headers = {"Content-Length": str(len(payload))}
        self.rfile = io.BytesIO(payload)
        self.shared_config = {}
        self.response = None
        self.code = None

    def _send_json(self, obj, code=200):
        self.response = obj
        self.code = code


class TestRelationshipBooleanParsing(unittest.TestCase):
    def test_string_false_disables_virustotal_lookup(self):
        payload = json.dumps({
            "ips": ["8.8.8.8"],
            "include_vt": "false",
        }).encode()
        handler = FakeHandler(payload)

        with mock.patch.object(relationship_handlers, "get_ip_report") as get_ip_report:
            relationship_handlers.handle_ip_relationship_analysis(handler)

        self.assertEqual(handler.code, 200)
        get_ip_report.assert_not_called()
        response = handler.response
        assert response is not None
        self.assertEqual(response["vt_attempted"], 0)


if __name__ == "__main__":
    unittest.main()
