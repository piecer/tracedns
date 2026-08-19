import tempfile
import unittest
from unittest import mock

from models import DomainSpec, QueryResult, Snapshot
from monitor.collect import Collected
from monitor.engine import run_domain_cycle


class TestMonitorDeletionRace(unittest.TestCase):
    def test_domain_removed_during_query_is_not_recreated(self):
        current = {}
        history = {}

        def collect_after_removal(domain, server):
            current.pop(domain.name, None)
            history.pop(domain.name, None)
            return Collected(
                query=QueryResult(
                    server=server,
                    domain=domain.name,
                    rtype="A",
                    status="ok",
                    values=["1.2.3.4"],
                ),
                snapshot=Snapshot(type="A", values=["1.2.3.4"], ts=1),
            )

        with tempfile.TemporaryDirectory() as history_dir, \
                mock.patch("monitor.engine.collect_snapshot", side_effect=collect_after_removal):
            result = run_domain_cycle(
                domain=DomainSpec(name="removed.example", type="A"),
                servers=["8.8.8.8"],
                current_results=current,
                history=history,
                history_dir=history_dir,
                query_fail_counts={},
                max_workers=1,
            )

        self.assertEqual(result, [])
        self.assertNotIn("removed.example", current)
        self.assertNotIn("removed.example", history)


if __name__ == "__main__":
    unittest.main()
