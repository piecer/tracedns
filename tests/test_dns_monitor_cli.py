import unittest

import dns_monitor


class TestDnsMonitorCli(unittest.TestCase):
    def test_http_host_defaults_to_loopback_and_can_be_overridden(self):
        parser = dns_monitor.build_arg_parser()

        self.assertEqual(parser.parse_args([]).http_host, "127.0.0.1")
        self.assertEqual(
            parser.parse_args(["--http-host", "0.0.0.0"]).http_host,
            "0.0.0.0",
        )


if __name__ == "__main__":
    unittest.main()
