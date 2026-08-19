import unittest
import os
import sys

HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import ens_static_mapping as esm


class TestEnsStaticMapping(unittest.TestCase):
    def test_load_betavpn_network_full_artifact(self):
        artifact = esm.load_betavpn_network_full_artifact()
        self.assertTrue(artifact.get("static_only"))
        self.assertEqual(artifact.get("runtime_method_name"), "ROL3210_decode")
        self.assertIn("betavpn_network_full", artifact.get("runtime_method_aliases", []))
        self.assertEqual(artifact.get("mapping_count"), 25)
        self.assertEqual(len(artifact.get("source_artifact_paths", [])), 2)

    def test_extract_ipv6_tokens_strips_control_prefix(self):
        tokens = esm.extract_ipv6_tokens("network\x02%2001:db8:f4d1:a71b::1|2001:db8:6547:cae0::1")
        self.assertEqual(tokens, ["2001:db8:f4d1:a71b::1", "2001:db8:6547:cae0::1"])

    def test_map_betavpn_network_full_record(self):
        rows = esm.map_betavpn_network_full_record(
            "network\x02%2001:db8:f4d1:a71b::1|2001:db8:ffff:ffff::1|2001:db8:6547:cae0::1"
        )
        self.assertEqual(rows, [
            {"network_value": "2001:db8:f4d1:a71b::1", "decoded_ipv4": "167.71.79.163"},
            {"network_value": "2001:db8:6547:cae0::1", "decoded_ipv4": "43.157.149.8"},
        ])

    def test_get_betavpn_network_full_iocs(self):
        iocs = esm.get_betavpn_network_full_iocs()
        self.assertEqual(len(iocs), 25)
        self.assertIn("139.162.113.188", iocs)
        self.assertIn("47.122.119.232", iocs)


if __name__ == "__main__":
    unittest.main()
