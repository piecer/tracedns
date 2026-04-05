import unittest

from tracedns import ens_decoder


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

    def test_unknown_method_returns_empty(self):
        out = ens_decoder.decode_ens_hidden_ips("2001:db8:1234:5678::1", method="unknown")
        self.assertEqual(out, [])


if __name__ == "__main__":
    unittest.main()
