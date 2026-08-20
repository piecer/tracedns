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

    def test_fetch_validates_raw_target_before_loading_web3(self):
        with mock.patch.object(eq, "Web3", None):
            with self.assertRaises(eq.EnsQueryError) as cm:
                eq.fetch_ens_text_record(
                    "https://rpc.example",
                    "",
                    "node",
                    ens_node="0x1234",
                    resolver_address="0X" + "ab" * 20,
                )
        self.assertEqual(cm.exception.code, "nodehash_invalid")

    def test_fetch_queries_direct_resolver_with_raw_node(self):
        calls = []
        raw_node = "0x" + "07" * 32
        resolver = "0X" + "ab" * 20

        class FakeCall:
            def call(self):
                return "2001:db8:12e7:13d7::1"

        class FakeFunctions:
            def text(self, node, key):
                calls.append(("text", node, key))
                return FakeCall()

        class FakeContract:
            functions = FakeFunctions()

        class FakeEth:
            def contract(self, *, address, abi):
                calls.append(("contract", address, abi))
                return FakeContract()

        class FakeWeb3:
            HTTPProvider = staticmethod(lambda url, request_kwargs: (url, request_kwargs))
            to_checksum_address = staticmethod(lambda address: address)

            def __init__(self, provider):
                self.provider = provider
                self.eth = FakeEth()

            def is_connected(self):
                return True

        with mock.patch.object(eq, "Web3", FakeWeb3):
            value = eq.fetch_ens_text_record(
                "https://rpc.example",
                "",
                "node",
                ens_node=raw_node,
                resolver_address=resolver,
            )

        self.assertEqual(value, "2001:db8:12e7:13d7::1")
        self.assertEqual(calls[0][0:2], ("contract", "0x" + "ab" * 20))
        self.assertEqual(calls[1], ("text", bytes.fromhex("07" * 32), "node"))
        self.assertEqual(len(calls), 2)

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



    def test_collect_snapshot_passes_raw_node_and_resolver(self):
        with mock.patch.object(collect_mod, "fetch_ens_text_record", return_value="2001:db8:12e7:13d7::1") as fetch_mock:
            domain = DomainSpec(
                name="sample.eth",
                type="ENS",
                ens_text_key="node",
                ens_decode="ROL3210_decode",
                ens_node="0x" + "07" * 32,
                ens_resolver="0xF29100983E058B709F3D539b0c765937B804AC15",
            )
            out = collect_mod.collect_snapshot(domain, "https://rpc.example")
        self.assertEqual(out.query.status, "ok")
        fetch_mock.assert_called_once_with(
            "https://rpc.example",
            "sample.eth",
            "node",
            ens_node="0x" + "07" * 32,
            resolver_address="0xF29100983E058B709F3D539b0c765937B804AC15",
        )
        self.assertEqual(out.snapshot.ens_node, "0x" + "07" * 32)
        self.assertEqual(out.snapshot.ens_resolver, "0xF29100983E058B709F3D539b0c765937B804AC15")

if __name__ == "__main__":
    unittest.main()
