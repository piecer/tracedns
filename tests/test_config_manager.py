import unittest
import os
import sys

HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import config_manager as cm
from models import coerce_domains


class TestConfigManager(unittest.TestCase):
    def test_normalize_domains_preserves_a_decoder_fields(self):
        value = [{
            "name": "example.com",
            "type": "A",
            "a_decode": "xor32_ipv4",
            "a_xor_key": "E7708E59",
        }]
        out = cm.normalize_domains(value)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].get("name"), "example.com")
        self.assertEqual(out[0].get("type"), "A")
        self.assertEqual(out[0].get("a_decode"), "xor32_ipv4")
        self.assertEqual(out[0].get("a_xor_key"), "E7708E59")

    def test_normalize_domains_preserves_ens_decoder_fields(self):
        value = [{
            "name": "example.eth",
            "type": "ENS",
            "ens_text_key": "ipv6",
            "ens_decode": "ipv6_5to8_xor",
            "ens_options": {"xor_byte": "0xA5"},
        }]
        out = cm.normalize_domains(value)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].get("name"), "example.eth")
        self.assertEqual(out[0].get("type"), "ENS")
        self.assertEqual(out[0].get("ens_text_key"), "ipv6")
        self.assertEqual(out[0].get("ens_decode"), "ipv6_5to8_xor")
        self.assertEqual(out[0].get("ens_options"), {"xor_byte": "0xA5"})

    def test_normalize_domains_preserves_sns_decoder_fields(self):
        value = [{
            "name": "example.sol",
            "type": "SNS",
            "ens_text_key": "IPFS",
            "sns_decode": "custom_sns_decode",
            "sns_options": {"xor_byte": "0xB6"},
        }]
        out = cm.normalize_domains(value)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].get("name"), "example.sol")
        self.assertEqual(out[0].get("type"), "SNS")
        self.assertEqual(out[0].get("ens_text_key"), "IPFS")
        self.assertEqual(out[0].get("sns_decode"), "custom_sns_decode")
        self.assertEqual(out[0].get("sns_options"), {"xor_byte": "0xB6"})
        self.assertNotIn("ens_decode", out[0])
        self.assertNotIn("ens_options", out[0])

    def test_normalize_domains_migrates_legacy_ens_xor_byte_to_options(self):
        value = [{
            "name": "legacy.eth",
            "type": "ENS",
            "ens_text_key": "ipv6",
            "ens_decode": "ipv6_5to8_xor",
            "ens_xor_byte": "0xB6",
        }]
        out = cm.normalize_domains(value)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].get("ens_options"), {"xor_byte": "0xB6"})


    def test_normalize_domains_preserves_raw_ens_node_and_resolver(self):
        value = [{
            "name": "example.eth",
            "type": "ENS",
            "ens_text_key": "node",
            "ens_decode": "ROL3210_decode",
            "ens_node": "0x" + "07" * 32,
            "ens_resolver": "0xF29100983E058B709F3D539b0c765937B804AC15",
        }]
        out = cm.normalize_domains(value)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].get("ens_node"), "0x" + "07" * 32)
        self.assertEqual(out[0].get("ens_resolver"), "0xF29100983E058B709F3D539b0c765937B804AC15")

    def test_normalize_domains_allows_same_ens_key_with_different_nodes(self):
        value = [
            {"name": "example.eth", "type": "ENS", "ens_text_key": "node", "ens_node": "0x" + "01" * 32},
            {"name": "example.eth", "type": "ENS", "ens_text_key": "node", "ens_node": "0x" + "02" * 32},
        ]
        out = cm.normalize_domains(value)
        self.assertEqual(len(out), 2)

    def test_ens_identity_distinguishes_resolvers_and_storage_uses_full_target(self):
        node_a = "0x" + "01" * 32
        node_b = "0x" + "01" * 31 + "02"
        resolver_a = "0x" + "aa" * 20
        resolver_b = "0x" + "bb" * 20
        targets = [
            {"name": "example.eth", "type": "ENS", "ens_text_key": "node", "ens_node": node_a, "ens_resolver": resolver_a},
            {"name": "example.eth", "type": "ENS", "ens_text_key": "node", "ens_node": node_a, "ens_resolver": resolver_b},
            {"name": "example.eth", "type": "ENS", "ens_text_key": "node", "ens_node": node_b, "ens_resolver": resolver_a},
        ]

        self.assertEqual(len(cm.normalize_domains(targets)), 3)
        self.assertEqual(len(coerce_domains(targets)), 3)
        storage_names = {cm.domain_storage_name(target) for target in targets}
        self.assertEqual(len(storage_names), 3)
        self.assertTrue(all(target["ens_node"] in cm.domain_storage_name(target) for target in targets))
        self.assertTrue(all(target["ens_resolver"] in cm.domain_storage_name(target) for target in targets))

    def test_normalize_domains_allows_same_ens_name_with_different_records(self):
        value = [
            {"name": "example.eth", "type": "ENS", "ens_text_key": "ipv6", "ens_decode": "ipv6_5to8_xor"},
            {"name": "example.eth", "type": "ENS", "ens_text_key": "network", "ens_decode": "ROL3210_decode"},
        ]
        out = cm.normalize_domains(value)
        self.assertEqual(len(out), 2)
        self.assertEqual([x.get("ens_text_key") for x in out], ["ipv6", "network"])

    def test_normalize_domains_dedupes_same_ens_record_identity(self):
        value = [
            {"name": "example.eth", "type": "ENS", "ens_text_key": "ipv6", "ens_decode": "ipv6_5to8_xor"},
            {"name": "example.eth.", "type": "ENS", "ens_text_key": "IPv6", "ens_decode": "ROL3210_decode"},
        ]
        out = cm.normalize_domains(value)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].get("ens_decode"), "ipv6_5to8_xor")

    def test_ens_and_sns_with_same_name_and_key_remain_distinct(self):
        value = [
            {"name": "same.name", "type": "ENS", "ens_text_key": "ipv6"},
            {"name": "same.name", "type": "SNS", "ens_text_key": "ipv6"},
        ]

        out = cm.normalize_domains(value)

        self.assertEqual(len(out), 2)
        self.assertNotEqual(cm.domain_identity(out[0]), cm.domain_identity(out[1]))
        self.assertNotEqual(cm.domain_storage_name(out[0]), cm.domain_storage_name(out[1]))


if __name__ == "__main__":
    unittest.main()
