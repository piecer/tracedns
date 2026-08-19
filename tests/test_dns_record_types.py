import unittest
from unittest import mock

from models import DomainSpec
from monitor import collect as collect_mod
import dns_query


class _Record:
    def __init__(self, text):
        self.text = text

    def __str__(self):
        return self.text


class TestDnsRecordTypes(unittest.TestCase):
    def test_query_uses_requested_record_type(self):
        resolver = mock.Mock()
        resolver.resolve.return_value = [_Record("2001:db8::1")]
        with mock.patch("dns_query.dns.resolver.Resolver", return_value=resolver):
            result = dns_query.query_dns("8.8.8.8", "example.com", "AAAA", with_meta=True)

        resolver.resolve.assert_called_once_with("example.com", "AAAA")
        self.assertEqual(result, {"values": ["2001:db8::1"], "status": "ok"})

    def test_collection_preserves_non_a_record_type(self):
        with mock.patch.object(
            collect_mod,
            "query_dns",
            return_value={"values": ["mail.example.com."], "status": "ok"},
        ):
            result = collect_mod.collect_snapshot(
                DomainSpec(name="example.com", type="MX"),
                "8.8.8.8",
            )

        self.assertEqual(result.query.rtype, "MX")
        snapshot = result.snapshot
        assert snapshot is not None
        self.assertEqual(snapshot.type, "MX")
        self.assertEqual(snapshot.values, ["mail.example.com."])


if __name__ == "__main__":
    unittest.main()
