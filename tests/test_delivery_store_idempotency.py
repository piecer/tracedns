import json
import sqlite3

from test_delivery_store_atomic import AUTH, BINDINGS, obs, rows, store_at
from test_delivery_store_claims import result
from test_delivery_worker_execution import worker_for


def test_committed_consumed_operation_repeat_during_busy_is_idempotent(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    observation = obs([])
    store.record_domain(observation, AUTH, BINDINGS)
    blocker = sqlite3.connect(tmp_path / "delivery.sqlite", isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    answer = store.record_domain(observation, AUTH, BINDINGS)
    assert answer["ledger_committed"] and answer["missed_receipts"] == 0
    blocker.rollback()
    blocker.close()
    store.close(clean=True)


def test_removal_cleanup_hook_after_confirmed_absence_only(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {"1.1.1.1": {"labels": ["x"], "missing_since": 1}}, AUTH)
    store.reconcile_full(AUTH, {}, 86401, BINDINGS)
    seen = []
    class Adapter:
        def execute_step(self, claim):
            return result(observation_hook={"kind": "remove_sightings", "ip": "1.1.1.1"})
    worker = worker_for(store, Adapter(), observation_hook=seen.append)
    worker.run_pass()
    assert seen == [{"kind": "remove_sightings", "ip": "1.1.1.1"}]
    assert store.health_snapshot()["acked_total"] == 1
    worker.stop()
    store.close(clean=True)


def test_recovery_overdue_reason_is_recovery_gap_not_capacity(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {"1.1.1.1": {"labels": ["x"], "missing_since": 1}}, AUTH)
    store.enter_gap("delivery_storage", {})
    store.recover_gap(AUTH, {}, {"active_map": {}, "completed_at": 86401, "bindings": BINDINGS}, None)
    control = json.loads(rows(tmp_path, "control")[0]["data"])
    assert control["missed_by_reason"]["recovery_gap"]["misp"] == 1
    store.close(clean=True)
