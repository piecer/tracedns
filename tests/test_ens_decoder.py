import unittest
import os
import sys
import ipaddress
import json
from pathlib import Path

HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import ens_decoder


class TestEnsDecoder(unittest.TestCase):
    def test_ipv6_5to8_xor_default(self):
        # bytes[4:8] = 0x12 0x34 0x56 0x78, XOR 0xA5 => b7 91 f3 dd
        rec = "2001:db8:1234:5678::1"
        out = ens_decoder.decode_ens_hidden_ips(rec, method="ipv6_5to8_xor")
        self.assertEqual(out, ["183.145.243.221"])

    def test_ipv6_5to8_xor_custom_byte(self):
        rec = "2001:db8:1234:5678::1"
        out = ens_decoder.decode_ens_hidden_ips(rec, method="ipv6_5to8_xor", xor_byte="0x00")
        self.assertEqual(out, ["18.52.86.120"])

    def test_ipv6_5to8_xor_with_ens_options(self):
        rec = "2001:db8:1234:5678::1"
        out = ens_decoder.decode_ens_hidden_ips(
            rec,
            method="ipv6_5to8_xor",
            ens_options={"xor_byte": "0x00"},
        )
        self.assertEqual(out, ["18.52.86.120"])

    def test_parse_ens_options_from_json_text(self):
        opts = ens_decoder.parse_ens_options('{"xor_byte":"0xA5","segment":"5to8"}', strict=True)
        self.assertEqual(opts.get("xor_byte"), "0xA5")
        self.assertEqual(opts.get("segment"), "5to8")

    def test_ROL3210_decode_decodes_prefixed_raw_record(self):
        rec = "network\x02%2001:db8:6547:cae0::1"
        out = ens_decoder.decode_ens_hidden_ips(rec, method="ROL3210_decode")
        self.assertEqual(out, ["43.157.149.8"])

    def test_betavpn_network_full_alias_decodes_prefixed_raw_record(self):
        rec = "network\x02%2001:db8:6547:cae0::1"
        out = ens_decoder.decode_ens_hidden_ips(rec, method="betavpn_network_full")
        self.assertEqual(out, ["43.157.149.8"])

    def test_ipv4_literals_decodes_plain_host_record(self):
        out = ens_decoder.decode_ens_hidden_ips(
            "Host=94.154.43.176|http://95.135.208.173:9000/path",
            method="ipv4_literals",
        )
        self.assertEqual(out, ["94.154.43.176", "95.135.208.173"])

    def test_ipv4_literals_accepts_sentence_and_root_dot_boundaries(self):
        out = ens_decoder.decode_ens_hidden_ips(
            "Current host is 94.154.43.176. Mirror: https://95.135.208.173./path",
            method="ipv4_literals",
        )
        self.assertEqual(out, ["94.154.43.176", "95.135.208.173"])

    def test_ipv4_literals_rejects_versions_and_malformed_addresses(self):
        out = ens_decoder.decode_ens_hidden_ips(
            "agent-v1.2.3.4beta|999.1.1.1|1.2.3.4.5|valid=162.141.92.3",
            method="ipv4_literals",
        )
        self.assertEqual(out, ["162.141.92.3"])

    def test_ROL3210_decode_matches_preserved_corpus(self):
        artifact_path = Path(ROOT) / "docs" / "ens" / "betavpn-network-full-decoder.json"
        self.assertTrue(artifact_path.exists(), "decoder corpus artifact must be tracked")
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        for entry in artifact["mappings"]:
            packed = ipaddress.IPv6Address(entry["network_value"]).packed[4:8].hex()
            out = ens_decoder.decode_ens_hidden_ips(entry["network_value"], method="ROL3210_decode")
            self.assertEqual(
                out,
                [entry["decoded_ipv4"]],
                msg=f"failed to decode {entry['network_value']} from {packed}",
            )


    def test_ROL3210_decode_key_option(self):
        rec = "2001:db8:1234:5678::1"
        out = ens_decoder.decode_ens_hidden_ips(rec, method="ROL3210_decode", ens_options={"key_u32": "0x00000000"})
        self.assertEqual(out, ["144.208.172.120"])

    def test_ROL3210_decode_can_use_last_four_bytes(self):
        rec = "[536b:a4ac:5a3f:abd4::2676:155a]:15850"
        out = ens_decoder.decode_ens_hidden_ips(
            rec,
            method="ROL3210_decode",
            ens_options={"segment": "last4", "key_u32": "0x80408454"},
        )
        self.assertEqual(out, ["49.217.50.98"])

    def test_ipv6_last4_xor32_decodes_last_four_bytes_with_configured_key(self):
        rec = "[536b:a4ac:5a3f:abd4::d233:1927|f00d::2676:155a]:20391"
        out = ens_decoder.decode_ens_hidden_ips(
            rec,
            method="ipv6_last4_xor32",
            ens_options={"key_u32": "0x6B9E3F2A"},
        )
        self.assertEqual(out, ["185.173.38.13", "77.232.42.112"])

    def test_ipv6_last4_xor32_optionally_passes_through_plain_ipv4(self):
        rec = "[185.173.38.13|77.232.42.112|185.173.38.13]:319"
        out = ens_decoder.decode_ens_hidden_ips(
            rec,
            method="ipv6_last4_xor32",
            ens_options={"key_u32": "0x6B9E3F2A", "plain_ipv4": True},
        )
        self.assertEqual(out, ["185.173.38.13", "77.232.42.112"])

    def test_ipv6_last4_xor32_matches_preserved_known_plaintext_corpus(self):
        artifact_path = Path(ROOT) / "docs" / "ens" / "ipv6-last4-xor32-decoder.json"
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        self.assertEqual(artifact["runtime_method_name"], "ipv6_last4_xor32")
        self.assertEqual(artifact["known_plaintext_evidence"]["set_match_count"], 19)
        self.assertFalse(artifact["suffix_semantics"]["is_endpoint_port"])
        mappings = artifact["mappings"]
        self.assertEqual(len(mappings), 19)
        self.assertEqual(len({entry["encoded_tail_hex"] for entry in mappings}), 19)
        self.assertEqual(len({entry["decoded_ipv4"] for entry in mappings}), 19)
        for entry in mappings:
            tail = entry["encoded_tail_hex"]
            token = f"f00d::{tail[:4]}:{tail[4:]}"
            out = ens_decoder.decode_ens_hidden_ips(
                token,
                method="ipv6_last4_xor32",
                ens_options=artifact["decoder_options"],
            )
            self.assertEqual(out, [entry["decoded_ipv4"]], msg=f"failed to decode {tail}")

    def test_decode_ens_endpoints_can_disable_suffix_port_promotion(self):
        rec = "[536b:a4ac:5a3f:abd4::2676:155a]:20391"
        decoded = ens_decoder.decode_ens_hidden_ips(
            rec,
            method="ipv6_last4_xor32",
            ens_options={"key_u32": "0x6B9E3F2A"},
        )
        endpoints = ens_decoder.decode_ens_endpoints(rec, decoded, suffix_is_port=False)
        self.assertEqual(endpoints, [])

    def test_decode_ens_endpoints_preserves_common_bracketed_record_port(self):
        rec = "[536b:a4ac:5a3f:abd4::2676:155a|f00d::2676:155a]:15850"
        endpoints = ens_decoder.decode_ens_endpoints(rec, ["49.217.50.98"])
        self.assertEqual(endpoints, ["49.217.50.98:15850"])

    def test_decode_ens_endpoints_rejects_missing_or_invalid_port(self):
        self.assertEqual(ens_decoder.decode_ens_endpoints("536b:a4ac::2676:155a", ["49.217.50.98"]), [])
        self.assertEqual(ens_decoder.decode_ens_endpoints("[536b:a4ac::2676:155a]:70000", ["49.217.50.98"]), [])

    def test_unknown_method_returns_empty(self):
        out = ens_decoder.decode_ens_hidden_ips("2001:db8:1234:5678::1", method="unknown")
        self.assertEqual(out, [])


if __name__ == "__main__":
    unittest.main()
