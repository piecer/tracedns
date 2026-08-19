import unittest
from concurrent.futures import Future
from typing import cast
from unittest import mock

from http_api import relationship_handlers as rh


class PendingExecutor:
    def __init__(self):
        self.futures = []

    def submit(self, *_args, **_kwargs):
        future = Future()
        self.futures.append(future)
        return future


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
            rh.start_ip_relationship_job({})
            rh.start_ip_relationship_job({})
            with self.assertRaises(rh.RelationshipJobCapacityError):
                rh.start_ip_relationship_job({})

        self.assertEqual(len(rh._IP_REL_JOBS), 2)
        executor = cast(PendingExecutor, rh._IP_REL_JOB_EXECUTOR)
        self.assertEqual(len(executor.futures), 2)


    def test_cleanup_keeps_active_jobs_past_ttl(self):
        rh._IP_REL_JOBS["active"] = {
            "status": "running",
            "created_at": 100,
            "done_at": None,
        }
        with mock.patch.object(rh, "_IP_REL_JOB_TTL_SECONDS", 300):
            rh._cleanup_ip_rel_jobs(now=401)
        self.assertIn("active", rh._IP_REL_JOBS)

    def test_cleanup_removes_only_expired_terminal_jobs(self):
        rh._IP_REL_JOBS["done"] = {
            "status": "completed",
            "created_at": 10,
            "done_at": 100,
        }
        with mock.patch.object(rh, "_IP_REL_JOB_TTL_SECONDS", 300):
            rh._cleanup_ip_rel_jobs(now=401)
        self.assertNotIn("done", rh._IP_REL_JOBS)


if __name__ == "__main__":
    unittest.main()
