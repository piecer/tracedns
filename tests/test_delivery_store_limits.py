import json
import sqlite3

from test_delivery_store_atomic import AUTH, BINDINGS, obs, rows, store_at
from test_delivery_store_claims import result
from test_delivery_store_tracking import projection
from test_delivery_worker_execution import worker_for


def test_prequery_bootstrap_cursor_survives_terminal_gc_and_60_seconds(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    store.finish_step(store.claim_next(BINDINGS[0], 100), result(), 100)
    store.close(clean=True)
    store = store_at(tmp_path)
    store.bootstrap(projection([]), {}, AUTH)  # disk history is still older
    assert store.record_domain(obs(["1.1.1.1"], observed_at=1000), AUTH, BINDINGS)["admitted_receipts"] == 0
    assert not rows(tmp_path, "receipt")
    store.close(clean=True)


def test_bounded_metadata_never_inserts_unbounded_operation_id(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    value = store.record_domain(obs(["1.1.1.1"], op="x" * 100000), AUTH, BINDINGS)
    assert value["outcome"] == "gap"
    assert not rows(tmp_path, "receipt")
    assert not rows(tmp_path, "cursor")
    store.close(clean=False)


def test_recovery_open_failure_can_attach_healthy_owner_later(tmp_path):
    first = store_at(tmp_path)
    first.bootstrap({}, {}, AUTH)
    second = store_at(tmp_path)
    assert not second.bootstrap({}, {}, AUTH)["ready"]
    first.close(clean=True)
    assert second.recover_gap(AUTH, {}, {"active_map": {}, "completed_at": 100}, None)["ready"]
    assert second.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)["admitted_receipts"] == 1
    second.close(clean=True)


def test_claim_config_generation_not_latest_finish_generation_controls_block(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    claim = store.claim_next(BINDINGS[0], 100)
    store.configuration_applied()  # key repaired while old immutable HTTP runs
    store.finish_step(claim, result("blocked", reason="provider_auth"), 100)
    assert store.claim_next(BINDINGS[0], 101) is not None
    store.close(clean=False)


def test_no_sighting_http_after_ack_persistence_halts_outbound(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    calls = []
    class Adapter:
        def execute_step(self, claim):
            def fail(point):
                if point == "before_commit":
                    raise sqlite3.OperationalError("injected returned I/O")
            store._fault = fail
            return result()
    def sighting():
        calls.append(1)
        return {"provider_calls": 1, "has_more": False}
    worker = worker_for(store, Adapter(), sightings_step=sighting)
    worker.run_pass()
    assert calls == []
    worker.stop()
    store._fault = lambda _: None
    store.close(clean=False)


def test_counter_saturation_is_sticky_and_terminal_retention_bounded(tmp_path):
    store = store_at(tmp_path, limits={"terminal_items": 1})
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1", "2.2.2.2"]), AUTH, BINDINGS)
    for _ in range(2):
        store.finish_step(store.claim_next(BINDINGS[0], 100), result(), 100)
    assert len(rows(tmp_path, "terminal")) == 1
    assert store.health_snapshot()["acked_total"] == 2
    with store._lock:
        store._control["missed_total"] = (1 << 63) - 1
        store._save_control()
    store.enter_gap("delivery_storage", {"misp": 1})
    store.recover_gap(AUTH, projection(["1.1.1.1", "2.2.2.2"]),
                      {"active_map": {}, "completed_at": 100}, None)
    assert store.health_snapshot()["missed_total"] == (1 << 63) - 1
    assert not store.health_snapshot()["accounting_complete"]
    assert len(json.dumps(store.health_snapshot()).encode()) <= 4096
    store.close(clean=True)
