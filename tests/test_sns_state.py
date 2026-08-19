import unittest

from dns_monitor import restore_current_results
from http_api.basic_handlers import _build_results_payload
from monitor.runtime_state import clone_snapshot


SNS_SNAPSHOT = {
    "type": "SNS",
    "values": ["encoded"],
    "decoded_ips": ["1.2.3.4"],
    "ts": 123,
    "ens_text_key": "IPFS",
    "sns_decode": "ROL3210_decode",
    "sns_options": {"xor_byte": "0xA5"},
}


class TestSnsStateMetadata(unittest.TestCase):
    def test_runtime_snapshot_clone_preserves_sns_metadata(self):
        cloned = clone_snapshot(SNS_SNAPSHOT)
        self.assertEqual(cloned["sns_decode"], "ROL3210_decode")
        self.assertEqual(cloned["sns_options"], {"xor_byte": "0xA5"})

    def test_results_payload_reports_sns_method_metadata(self):
        payload = _build_results_payload(
            {"name.sol [SNS:IPFS]": {"proxy": SNS_SNAPSHOT}},
            {},
            include_raw=True,
        )
        raw = payload["results"]["name.sol [SNS:IPFS]"]["proxy"]
        aggregate = payload["results_agg"]["name.sol [SNS:IPFS]"]
        self.assertEqual(raw["sns_decode"], "ROL3210_decode")
        self.assertEqual(raw["sns_options"], {"xor_byte": "0xA5"})
        self.assertEqual(aggregate["sns_decodes"], ["ROL3210_decode"])
        self.assertIn("SNS:IPFS", aggregate["method_summary"])

    def test_history_restore_preserves_sns_metadata(self):
        restored = restore_current_results({
            "name.sol [SNS:IPFS]": {
                "meta": {},
                "events": [],
                "current": {"proxy": SNS_SNAPSHOT},
            },
        })
        self.assertEqual(restored["name.sol [SNS:IPFS]"]["proxy"]["sns_decode"], "ROL3210_decode")
        self.assertEqual(restored["name.sol [SNS:IPFS]"]["proxy"]["sns_options"], {"xor_byte": "0xA5"})


if __name__ == "__main__":
    unittest.main()
