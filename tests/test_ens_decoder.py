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

    def test_ROL3210_decode_matches_preserved_corpus(self):
        artifact_path = Path(ROOT) / "docs" / "ens" / "betavpn-network-full-decoder.json"
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        for entry in artifact["mappings"]:
            packed = ipaddress.IPv6Address(entry["network_value"]).packed[4:8].hex()
            out = ens_decoder.decode_ens_hidden_ips(entry["network_value"], method="ROL3210_decode")
            self.assertEqual(
                out,
                [entry["decoded_ipv4"]],
                msg=f"failed to decode {entry['network_value']} from {packed}",
            )

    def test_unknown_method_returns_empty(self):
        out = ens_decoder.decode_ens_hidden_ips("2001:db8:1234:5678::1", method="unknown")
        self.assertEqual(out, [])


if __name__ == "__main__":
    unittest.main()
