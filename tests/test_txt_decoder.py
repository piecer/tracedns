import os
import sys
import unittest

HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import txt_decoder


class TestTxtDecoder(unittest.TestCase):
    def test_rot13_xor0x30_method_registered(self):
        self.assertIn("ROT13_XOR0x30", txt_decoder.TXT_DECODE_METHODS)

    def test_rot13_xor0x30_decodes_datasurge_txt_wrapper(self):
        value = "XHgwNFx4MDVceDFFXHgwMVx4MDNceDAxXHgxRVx4MDZceDA1XHgxRVx4MDdceDA0"
        out = txt_decoder.decode_txt_hidden_ips([value], method="ROT13_XOR0x30")
        self.assertEqual(out, ["45.131.65.74"])

    def test_rot13_xor0x30_dedupes_split_tokens(self):
        value = "XHgwNFx4MDVceDFFXHgwMVx4MDNceDAxXHgxRVx4MDZceDA1XHgxRVx4MDdceDA0"
        out = txt_decoder.decode_txt_hidden_ips([f'"{value}; {value}"'], method="ROT13_XOR0x30")
        self.assertEqual(out, ["45.131.65.74"])


if __name__ == "__main__":
    unittest.main()
