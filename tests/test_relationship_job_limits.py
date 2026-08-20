import unittest
from concurrent.futures import Future
from typing import cast
from unittest import mock

from http_api import relationship_handlers as rh


class PendingExecutor:
    def __init__(self):
        self.futures = []
        self.submissions = []

    def submit(self, *args, **kwargs):
        future = Future()
        self.futures.append(future)
        self.submissions.append((args, kwargs))
        return future


class LockAwareCancelableFuture:
    def __init__(self, *, cancellable=True):
        self.cancellable = cancellable
        self.cancel_called_outside_lock = False

    def cancel(self):
        acquired = rh._IP_REL_JOB_LOCK.acquire(blocking=False)
        self.cancel_called_outside_lock = acquired
        if acquired:
            rh._IP_REL_JOB_LOCK.release()
        return acquired and self.cancellable


class FailIfCancelledFuture:
    def cancel(self):
        raise AssertionError("cancel must not be called for terminal jobs")


class TestRelationshipJobLimit(unittest.TestCase):
    def setUp(self):
        self.original_jobs = rh._IP_REL_JOBS
        self.original_executor = rh._IP_REL_JOB_EXECUTOR
        rh._IP_REL_JOBS = {}
        rh._IP_REL_JOB_EXECUTOR = PendingExecutor()

    def tearDown(self):
        rh._IP_REL_JOBS = self.original_jobs
        rh._IP_REL_JOB_EXECUTOR = self.original_executor

    def test_rejects_submission_when_all_pending_slots_are_used(self):
        with mock.patch.object(rh, "_IP_REL_JOB_MAX_PENDING", 2):
            rh.start_ip_relationship_job({"ips": ["1.1.1.1"]})
            rh.start_ip_relationship_job({"ips": ["8.8.8.8"]})
            with self.assertRaises(rh.RelationshipJobCapacityError):
                rh.start_ip_relationship_job({"ips": ["9.9.9.9"]})

        self.assertEqual(len(rh._IP_REL_JOBS), 2)
        executor = cast(PendingExecutor, rh._IP_REL_JOB_EXECUTOR)
        self.assertEqual(len(executor.futures), 2)

    def test_submission_snapshots_current_vt_runtime_config_for_worker(self):
        config = {"api_key": "rotated-key", "cache_ttl": 12345}

        with mock.patch.object(rh, "get_vt_runtime_config", return_value=config):
            rh.start_ip_relationship_job({"ips": ["1.1.1.1"]})

        executor = cast(PendingExecutor, rh._IP_REL_JOB_EXECUTOR)
        args, kwargs = executor.submissions[0]
        self.assertEqual(kwargs, {})
        self.assertEqual(args[3], config)

    def assert_request_rejected_before_submit(self, data):
        with self.assertRaises(rh.RelationshipRequestError) as caught:
            rh.start_ip_relationship_job(data)

        self.assertEqual(caught.exception.status_code, 400)
        executor = cast(PendingExecutor, rh._IP_REL_JOB_EXECUTOR)
        self.assertEqual(executor.futures, [])
        self.assertEqual(rh._IP_REL_JOBS, {})

    def test_rejects_non_object_payload_before_submit(self):
        self.assert_request_rejected_before_submit(["1.1.1.1"])

    def test_rejects_invalid_ips_type_before_submit(self):
        self.assert_request_rejected_before_submit({"ips": {"ip": "1.1.1.1"}})

    def test_rejects_empty_input_before_submit(self):
        self.assert_request_rejected_before_submit({"ips": ""})

    def test_rejects_invalid_only_input_before_submit(self):
        self.assert_request_rejected_before_submit({"ips": ["not-an-ip", "also-bad"]})

    def test_rejects_malformed_bucket_max_before_submit(self):
        with self.assertRaises(rh.RelationshipRequestError) as ctx:
            rh.start_ip_relationship_job({"ips": ["8.8.8.8"], "bucket_max": "bad"})

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.payload["error"], "bucket_max must be an integer")
        executor = cast(PendingExecutor, rh._IP_REL_JOB_EXECUTOR)
        self.assertEqual(executor.futures, [])

    def test_rejects_more_than_20000_tokens_before_submit(self):
        self.assert_request_rejected_before_submit({"ips": " ".join(["bad"] * 20001)})

    def test_rejects_more_than_10000_unique_valid_ips_before_submit(self):
        ips = [f"2001:db8::{index:x}" for index in range(10001)]
        self.assert_request_rejected_before_submit({"ips": ips})

    def test_cleanup_keeps_active_jobs_past_ttl(self):
        rh._IP_REL_JOBS["active"] = {
            "status": "running",
            "created_at": 100,
            "done_at": None,
        }
        with mock.patch.object(rh, "_IP_REL_JOB_TTL_SECONDS", 300):
            rh._cleanup_ip_rel_jobs(now=401)
        self.assertIn("active", rh._IP_REL_JOBS)

    def test_shutdown_releases_executor_without_waiting_for_running_jobs(self):
        executor = mock.Mock()
        rh._IP_REL_JOB_EXECUTOR = executor

        rh.shutdown_ip_relationship_jobs(wait=False)

        self.assertIsNone(rh._IP_REL_JOB_EXECUTOR)
        executor.shutdown.assert_called_once_with(wait=False, cancel_futures=True)

    def test_cleanup_removes_only_expired_terminal_jobs(self):
        rh._IP_REL_JOBS["done"] = {
            "status": "completed",
            "created_at": 10,
            "done_at": 100,
        }
        with mock.patch.object(rh, "_IP_REL_JOB_TTL_SECONDS", 300):
            rh._cleanup_ip_rel_jobs(now=401)
        self.assertNotIn("done", rh._IP_REL_JOBS)

    def test_cleanup_bounds_terminal_jobs_by_count_and_result_bytes(self):
        for index, result_bytes in enumerate((40, 40, 40), start=1):
            rh._IP_REL_JOBS[f"done-{index}"] = {
                "status": "completed",
                "created_at": index,
                "done_at": index,
                "result_bytes": result_bytes,
            }
        rh._IP_REL_JOBS["active"] = {
            "status": "running",
            "created_at": 0,
            "done_at": None,
        }

        with (
            mock.patch.object(rh, "_IP_REL_JOB_MAX_TERMINAL", 2),
            mock.patch.object(rh, "_IP_REL_JOB_MAX_RESULT_BYTES", 70),
        ):
            rh._cleanup_ip_rel_jobs(now=10)

        self.assertEqual(set(rh._IP_REL_JOBS), {"active", "done-3"})

    def test_cancel_calls_future_outside_job_lock(self):
        future = LockAwareCancelableFuture()
        rh._IP_REL_JOBS["pending"] = {
            "job_id": "pending",
            "status": "running",
            "future": future,
            "done_at": None,
        }

        payload, status = rh.cancel_ip_relationship_job("pending")

        self.assertEqual(status, 200)
        self.assertTrue(payload["cancelled"])
        self.assertTrue(future.cancel_called_outside_lock)

    def test_cancel_pending_future_sets_terminal_cancelled_status(self):
        future = Future()
        rh._IP_REL_JOBS["pending"] = {
            "job_id": "pending",
            "status": "running",
            "future": future,
            "done_at": None,
        }
        future.add_done_callback(
            lambda completed: rh._ip_rel_job_done("pending", completed)
        )

        payload, status = rh.cancel_ip_relationship_job("pending")
        job_payload, job_status = rh.get_ip_relationship_job("pending")

        self.assertEqual(status, 200)
        self.assertEqual(
            payload,
            {"status": "cancelled", "job_id": "pending", "cancelled": True},
        )
        self.assertEqual(job_status, 200)
        self.assertEqual(job_payload["status"], "cancelled")
        self.assertIsNotNone(job_payload["done_at"])

    def test_cancel_missing_job_returns_not_found(self):
        payload, status = rh.cancel_ip_relationship_job("missing")

        self.assertEqual(status, 404)
        self.assertEqual(payload, {"error": "job not found"})

    def test_cancel_already_cancelled_job_is_idempotent(self):
        rh._IP_REL_JOBS["cancelled"] = {
            "job_id": "cancelled",
            "status": "cancelled",
            "future": FailIfCancelledFuture(),
            "done_at": 123,
        }

        payload, status = rh.cancel_ip_relationship_job("cancelled")

        self.assertEqual(status, 200)
        self.assertEqual(
            payload,
            {"status": "cancelled", "job_id": "cancelled", "cancelled": True},
        )

    def test_completion_callback_does_not_overwrite_terminal_cancelled_status(self):
        future = Future()
        future.set_result({"status_code": 200, "payload": {"status": "ok"}})
        rh._IP_REL_JOBS["cancelled"] = {
            "job_id": "cancelled",
            "status": "cancelled",
            "done_at": 123,
        }

        rh._ip_rel_job_done("cancelled", future)

        self.assertEqual(rh._IP_REL_JOBS["cancelled"]["status"], "cancelled")
        self.assertEqual(rh._IP_REL_JOBS["cancelled"]["done_at"], 123)

    def test_cancel_running_job_returns_conflict_and_reason(self):
        future = LockAwareCancelableFuture(cancellable=False)
        rh._IP_REL_JOBS["running"] = {
            "job_id": "running",
            "status": "running",
            "future": future,
            "done_at": None,
        }

        payload, status = rh.cancel_ip_relationship_job("running")

        self.assertEqual(status, 409)
        self.assertEqual(
            payload,
            {
                "status": "running",
                "job_id": "running",
                "cancelled": False,
                "reason": "already_running",
            },
        )
        self.assertTrue(future.cancel_called_outside_lock)

    def test_cancel_completed_or_failed_job_returns_finished_conflict(self):
        for terminal_status in ("completed", "failed"):
            with self.subTest(status=terminal_status):
                rh._IP_REL_JOBS[terminal_status] = {
                    "job_id": terminal_status,
                    "status": terminal_status,
                    "future": FailIfCancelledFuture(),
                    "done_at": 123,
                }

                payload, status = rh.cancel_ip_relationship_job(terminal_status)

                self.assertEqual(status, 409)
                self.assertEqual(
                    payload,
                    {
                        "status": terminal_status,
                        "job_id": terminal_status,
                        "cancelled": False,
                        "reason": "already_finished",
                    },
                )

    def test_get_job_reports_not_found_and_only_includes_terminal_result_on_request(self):
        payload, status = rh.get_ip_relationship_job("missing", include_result=True)
        self.assertEqual((payload, status), ({"error": "job not found"}, 404))

        rh._IP_REL_JOBS["done"] = {
            "job_id": "done",
            "status": "completed",
            "created_at": 10,
            "done_at": rh.time.time(),
            "status_code": 200,
            "error": None,
            "result": {"status": "ok"},
        }
        without_result, status = rh.get_ip_relationship_job("done")
        with_result, _ = rh.get_ip_relationship_job("done", include_result=True)

        self.assertEqual(status, 200)
        self.assertNotIn("result", without_result)
        self.assertEqual(with_result["result"], {"status": "ok"})

    def test_done_callback_maps_success_http_failure_exception_and_cancellation(self):
        cases = []

        success = Future()
        success.set_result({"status_code": 200, "payload": {"status": "ok"}})
        cases.append(("success", success, "completed", 200, None))

        http_failure = Future()
        http_failure.set_result({"status_code": 400, "payload": {"error": "bad"}})
        cases.append(("http-failure", http_failure, "failed", 400, None))

        exception = Future()
        exception.set_exception(RuntimeError("worker failed"))
        cases.append(("exception", exception, "failed", 500, "relationship analysis failed"))

        cancelled = Future()
        cancelled.cancel()
        cases.append(("cancelled-future", cancelled, "cancelled", None, None))

        for job_id, future, expected_status, expected_code, expected_error in cases:
            with self.subTest(job_id=job_id):
                rh._IP_REL_JOBS[job_id] = {
                    "job_id": job_id,
                    "status": "running",
                    "done_at": None,
                }
                rh._ip_rel_job_done(job_id, future)
                job = rh._IP_REL_JOBS[job_id]
                self.assertEqual(job["status"], expected_status)
                self.assertIsNotNone(job["done_at"])
                if expected_code is not None:
                    self.assertEqual(job["status_code"], expected_code)
                if expected_error is not None:
                    self.assertEqual(job["error"], expected_error)

        self.assertEqual(rh._IP_REL_JOBS["success"]["result"], {"status": "ok"})
        self.assertEqual(rh._IP_REL_JOBS["http-failure"]["result"], {"error": "bad"})
        failed_payload, failed_status = rh.get_ip_relationship_job("exception")
        self.assertEqual(failed_status, 200)
        self.assertNotIn("worker failed", str(failed_payload))

    def test_done_callback_ignores_job_removed_before_completion(self):
        future = Future()
        future.set_result({"status_code": 200, "payload": {"status": "ok"}})

        rh._ip_rel_job_done("removed", future)

        self.assertNotIn("removed", rh._IP_REL_JOBS)

    def test_submission_failure_removes_provisional_job(self):
        class BrokenExecutor:
            def submit(self, *_args, **_kwargs):
                raise RuntimeError("executor unavailable")

        rh._IP_REL_JOB_EXECUTOR = BrokenExecutor()

        with self.assertRaisesRegex(RuntimeError, "executor unavailable"):
            rh.start_ip_relationship_job({"ips": ["1.1.1.1"]})

        self.assertEqual(rh._IP_REL_JOBS, {})

    def test_cancel_without_future_truthfully_reports_running(self):
        rh._IP_REL_JOBS["queued"] = {
            "job_id": "queued",
            "status": "queued",
            "future": None,
            "done_at": None,
        }

        payload, status = rh.cancel_ip_relationship_job("queued")

        self.assertEqual(status, 409)
        self.assertEqual(payload, {
            "status": "queued",
            "job_id": "queued",
            "cancelled": False,
            "reason": "already_running",
        })

    def test_worker_payload_returns_public_analysis_response(self):
        result = rh._run_ip_relationship_analysis_payload({
            "ips": ["1.1.1.1"],
            "include_vt": False,
        })

        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["payload"]["status"], "ok")
        self.assertEqual(result["payload"]["valid_count"], 1)

    def test_worker_applies_vt_runtime_snapshot_before_analysis(self):
        config = {"api_key": "rotated-key", "cache_ttl": 12345}

        with mock.patch.object(rh, "apply_vt_runtime_config") as apply_config:
            rh._run_ip_relationship_analysis_payload(
                {"ips": ["1.1.1.1"], "include_vt": False},
                vt_runtime_config=config,
            )

        apply_config.assert_called_once_with(config)


if __name__ == "__main__":
    unittest.main()
