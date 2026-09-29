import json
import sqlite3
import threading

from test_delivery_store_atomic import AUTH, BINDINGS, obs, rows, store_at
from test_delivery_store_claims import result
from test_delivery_worker_execution import worker_for


def test_unknown_commit_resolved_before_recovery_and_never_counted_twice(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    original = store._read_control
    def unreadable():
        raise sqlite3.OperationalError("readback unavailable")
    store._read_control = unreadable
    def after(point):
        if point == "after_commit":
            raise sqlite3.OperationalError("commit acknowledgement unavailable")
    store._fault = after
    assert store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)["outcome"] == "gap"
    assert store.health_snapshot()["missed_unpersisted"] == 0
    assert len(rows(tmp_path, "receipt")) == 1
    store._fault = lambda _: None
    assert not store.recover_gap(AUTH, {}, {"active_map": {}, "completed_at": 100}, None)["ready"]
    store._read_control = original
    assert store.recover_gap(AUTH, {}, {"active_map": {}, "completed_at": 100}, None)["ready"]
    assert store.health_snapshot()["missed_total"] == 0
    store.close(clean=True)


def test_same_operation_retry_does_not_mutate_consumed_unit(tmp_path):
    store = store_at(tmp_path, limits={"receipts": 1})
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    candidate = obs(["2.2.2.2"])
    assert store.record_domain(candidate, AUTH, BINDINGS)["missed_receipts"] == 1
    replay = {**candidate, "managed_ips": ["3.3.3.3"]}
    assert store.record_domain(replay, AUTH, BINDINGS)["admitted_receipts"] == 0
    assert store.health_snapshot()["missed_total"] == 1
    assert json.loads(rows(tmp_path, "cursor")[0]["ips"]) == ["2.2.2.2"]
    store.close(clean=True)


def test_health_read_never_waits_for_transaction_and_codes_are_closed(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    claim = store.claim_next(BINDINGS[0], 100)
    store.finish_step(claim, result("blocked", reason="secret-webhook-url"), 100)
    assert "secret" not in json.dumps(store.health_snapshot())
    assert store.claim_next(BINDINGS[0], 101) is None  # same config cannot spin a blocked response
    barrier = threading.Event()
    with store._lock:
        thread = threading.Thread(target=lambda: (store.health_snapshot(), barrier.set()))
        thread.start()
        assert barrier.wait(.5)
    thread.join()
    assert store.health_snapshot()["status"] == "blocked"
    store.close(clean=True)


def test_corrupt_envelope_never_acks_and_worker_thread_lifecycle(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    called = threading.Event()
    class Adapter:
        def execute_step(self, claim):
            called.set()
            return {"state": "acked", "provider_calls": 99, "reason": "private"}
    worker = worker_for(store, Adapter())
    assert worker.start()
    assert called.wait(2)
    assert worker.stop()["stopped"]
    assert store.health_snapshot()["acked_total"] == 0
    assert not worker.start()
    store.close(clean=False)


def test_private_binding_key_persists_and_target_retirement_keeps_receipt(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    key = store.binding_key()
    assert isinstance(key, bytes) and len(key) == 32
    store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    incarnation = rows(tmp_path, "cursor")[0]["incarnation"]
    assert store.retire_target_cursor(incarnation)["ledger_committed"]
    assert rows(tmp_path, "cursor") == []
    assert len(rows(tmp_path, "receipt")) == 1
    store.close(clean=True)
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    assert store.binding_key() == key
    assert key.hex() not in json.dumps(store.health_snapshot())
    store.close(clean=True)
