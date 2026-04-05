import unittest
import os
import sys
from unittest import mock

HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import ens_query as eq
from models import DomainSpec
from monitor import collect as collect_mod


class TestEnsErrorHandling(unittest.TestCase):
    def test_fetch_requires_rpc_url(self):
        with self.assertRaises(eq.EnsQueryError) as cm:
            eq.fetch_ens_text_record("", "example.eth", "ipv6")
        self.assertEqual(cm.exception.code, "invalid_rpc_url")

    def test_fetch_reports_dependency_missing(self):
        with mock.patch.object(eq, "Web3", None):
            with self.assertRaises(eq.EnsQueryError) as cm:
                eq.fetch_ens_text_record("https://rpc.example", "example.eth", "ipv6")
        self.assertEqual(cm.exception.code, "dependency_missing")

    def test_collect_snapshot_propagates_structured_error(self):
        err = eq.EnsQueryError(
            "rpc_not_connected",
            "failed to connect to Ethereum RPC",
            rpc_url="https://rpc.example/v3/secret",
            ens_name="sample.eth",
            key="ipv6",
        )
        with mock.patch.object(collect_mod, "fetch_ens_text_record", side_effect=err):
            domain = DomainSpec(name="sample.eth", type="ENS", ens_text_key="ipv6", ens_decode="ipv6_5to8_xor")
            out = collect_mod.collect_snapshot(domain, "https://rpc.example/v3/secret")
        self.assertEqual(out.query.status, "error")
        self.assertIn("rpc_not_connected", str(out.query.error or ""))
        self.assertIn("sample.eth", str(out.query.error or ""))


if __name__ == "__main__":
    unittest.main()
