import tempfile
import unittest
from unittest import mock

from history_manager import load_history_files
from monitor import engine
from monitor.removal_grace import IpRemovalGraceTracker


class TestIpRemovalGrace(unittest.TestCase):
    def setUp(self):
        engine._ALERT_DEDUPE.clear()

    def tearDown(self):
        engine._ALERT_DEDUPE.clear()

    def test_removal_alert_waits_for_full_grace_period(self):
        clock = [1_000]
        tracker = IpRemovalGraceTracker(grace_seconds=86_400, now_fn=lambda: clock[0])

        with mock.patch.object(engine, "alert_removed_ips") as alert_removed:
            baseline = engine.reconcile_removed_ips(
                {"1.2.3.4": {"c2.example"}},
                {},
                removal_tracker=tracker,
            )
            self.assertEqual(baseline, {})
            alert_removed.assert_not_called()

            clock[0] += 86_399
            engine.reconcile_removed_ips(baseline, {}, removal_tracker=tracker)
            alert_removed.assert_not_called()

            clock[0] += 1
            engine.reconcile_removed_ips(baseline, {}, removal_tracker=tracker)

        alert_removed.assert_called_once_with(
            [("1.2.3.4", "c2.example", "A")],
            context=None,
        )
        self.assertEqual(tracker.pending_ips(), set())

    def test_reappearance_cancels_removal_and_suppresses_addition(self):
        clock = [2_000]
        tracker = IpRemovalGraceTracker(grace_seconds=86_400, now_fn=lambda: clock[0])
        engine.reconcile_removed_ips(
            {"1.2.3.4": {"c2.example"}},
            {},
            removal_tracker=tracker,
        )

        with mock.patch.object(
            engine,
            "run_domain_cycle",
            return_value=[
                ("1.2.3.4", "c2.example", "A"),
                ("5.6.7.8", "c2.example", "A"),
            ],
        ), mock.patch.object(
            engine,
            "_dedupe_alert",
            side_effect=lambda _action, entries: list(entries),
        ), mock.patch.object(engine, "alert_new_ips") as alert_new:
            engine.run_full_cycle(
                domains_raw=[{"name": "c2.example", "type": "A"}],
                servers=["1.1.1.1"],
                current_results={},
                history={},
                history_dir="/tmp",
                query_fail_counts={},
                suppressed_added_ips=tracker.pending_ips(),
            )

        alert_new.assert_called_once()
        self.assertEqual(
            alert_new.call_args.args[0],
            [("5.6.7.8", "c2.example", "A")],
        )

        with mock.patch.object(engine, "alert_removed_ips") as alert_removed:
            engine.reconcile_removed_ips(
                {},
                {"1.2.3.4": {"c2.example"}},
                removal_tracker=tracker,
            )
            clock[0] += 86_400
            engine.reconcile_removed_ips(
                {"1.2.3.4": {"c2.example"}},
                {"1.2.3.4": {"c2.example"}},
                removal_tracker=tracker,
            )

        alert_removed.assert_not_called()
        self.assertEqual(tracker.pending_ips(), set())

    def test_pending_state_survives_restart(self):
        clock = [3_000]
        with tempfile.TemporaryDirectory() as history_dir:
            tracker = IpRemovalGraceTracker.from_history_dir(
                history_dir,
                grace_seconds=86_400,
                now_fn=lambda: clock[0],
            )
            tracker.reconcile({"9.9.9.9": {"persist.example"}}, {})

            restored = IpRemovalGraceTracker.from_history_dir(
                history_dir,
                grace_seconds=86_400,
                now_fn=lambda: clock[0],
            )

            self.assertEqual(restored.pending_ips(), {"9.9.9.9"})
            self.assertEqual(
                restored.pending_snapshot()["9.9.9.9"],
                {"missing_since": 3_000, "labels": ["persist.example"]},
            )
            self.assertEqual(load_history_files(history_dir), {})

    def test_no_tracker_keeps_immediate_compatibility_behavior(self):
        with mock.patch.object(engine, "alert_removed_ips") as alert_removed:
            engine.reconcile_removed_ips(
                {"4.3.2.1": {"legacy.example"}},
                {},
            )

        alert_removed.assert_called_once_with(
            [("4.3.2.1", "legacy.example", "A")],
            context=None,
        )


if __name__ == "__main__":
    unittest.main()
