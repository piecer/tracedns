import base64
import unittest

from txt_decoder import decode_txt_btea_variant


class TestBteaVariantDecoder(unittest.TestCase):
    def test_preserves_plaintext_ipv4(self):
        token = base64.b64encode(b"1.2.3.4").decode("ascii")
        decoded = decode_txt_btea_variant([token])
        self.assertIn("1.2.3.4", decoded)


if __name__ == "__main__":
    unittest.main()
