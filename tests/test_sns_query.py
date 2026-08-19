import unittest
from unittest import mock

import sns_query
from models import DomainSpec
from monitor import collect


class TestSnsRecordQueries(unittest.TestCase):
    def test_record_key_is_url_encoded(self):
        response = mock.Mock(text="value")
        response.raise_for_status.return_value = None
        with mock.patch.object(sns_query.requests, "get", return_value=response) as get:
            result = sns_query.fetch_sns_record(
                "https://proxy.example",
                "name.sol",
                "IPFS/path",
            )

        self.assertEqual(result, "value")
        self.assertEqual(
            get.call_args.args[0],
            "https://proxy.example/record-v2/name.sol/IPFS%2Fpath",
        )

    def test_name_is_canonicalized_and_url_encoded(self):
        response = mock.Mock(text="value")
        response.raise_for_status.return_value = None
        with mock.patch.object(sns_query.requests, "get", return_value=response) as get:
            sns_query.fetch_sns_record(
                "https://proxy.example",
                "Alice/Team.SOL",
                "TXT",
            )

        self.assertEqual(
            get.call_args.args[0],
            "https://proxy.example/record-v2/alice%2Fteam.sol/TXT",
        )

    def test_collection_passes_configured_record_key(self):
        domain = DomainSpec(
            name="name.sol",
            type="SNS",
            ens_text_key="IPFS",
            sns_decode="ROL3210_decode",
        )
        with mock.patch.object(collect, "fetch_sns_record", return_value="raw") as fetch:
            result = collect.collect_snapshot(domain, "https://proxy.example")

        self.assertIsNotNone(result.snapshot)
        fetch.assert_called_once_with(
            "https://proxy.example",
            "name.sol",
            "IPFS",
            timeout=15,
            verify_tls=True,
        )


if __name__ == "__main__":
    unittest.main()
