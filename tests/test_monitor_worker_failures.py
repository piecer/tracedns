import tempfile
import unittest
from unittest import mock

from models import DomainSpec
from monitor.engine import run_domain_cycle


class TestMonitorWorkerFailures(unittest.TestCase):
    def test_unexpected_worker_failure_does_not_abort_cycle(self):
        current_results = {}
        history = {}
        fail_counts = {}
        with tempfile.TemporaryDirectory() as history_dir, mock.patch(
            "monitor.engine.collect_snapshot", side_effect=RuntimeError("worker bug")
        ):
            result = run_domain_cycle(
                domain=DomainSpec(name="example.com", type="A"),
                servers=["1.1.1.1"],
                current_results=current_results,
                history=history,
                history_dir=history_dir,
                query_fail_counts=fail_counts,
                max_workers=1,
            )
        self.assertEqual(result, [])
        self.assertEqual(fail_counts[("example.com", "1.1.1.1", "A")], 1)


if __name__ == "__main__":
    unittest.main()
