import unittest
import os
import sys
from unittest import mock

HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from monitor import engine


class TestAlertBatching(unittest.TestCase):
    def test_run_full_cycle_sends_added_alert_once_per_cycle(self):
        domains_raw = [
            {'name': 'a.example', 'type': 'A'},
            {'name': 'b.example', 'type': 'TXT'},
        ]
        current_results = {}
        history = {}
        query_fail_counts = {}

        with mock.patch.object(
            engine,
            'run_domain_cycle',
            side_effect=[
                [('1.1.1.1', 'a.example', 'A')],
                [('2.2.2.2', 'b.example', 'TXT')],
            ],
        ) as mocked_cycle, mock.patch.object(
            engine,
            '_dedupe_alert',
            side_effect=lambda _action, entries: list(entries),
        ), mock.patch.object(
            engine,
            'alert_new_ips',
        ) as mocked_alert:
            out = engine.run_full_cycle(
                domains_raw=domains_raw,
                servers=['8.8.8.8', '1.1.1.1'],
                current_results=current_results,
                history=history,
                history_dir='/tmp',
                query_fail_counts=query_fail_counts,
                max_workers=4,
                force_req=None,
                ens_rpc_url=None,
            )

        self.assertEqual(mocked_cycle.call_count, 2)
        self.assertEqual(mocked_alert.call_count, 1)
        sent_entries = mocked_alert.call_args.args[0]
        self.assertEqual(len(sent_entries), 2)
        self.assertIn(('1.1.1.1', 'a.example', 'A'), sent_entries)
        self.assertIn(('2.2.2.2', 'b.example', 'TXT'), sent_entries)
        context = mocked_alert.call_args.kwargs.get('context') or {}
        self.assertEqual(context.get('scan_scope'), 'full')
        self.assertEqual(context.get('domain_targets'), 2)
        self.assertEqual(context.get('server_targets'), 2)
        self.assertIsInstance(out, dict)


if __name__ == '__main__':
    unittest.main()
