import sqlite3

from test_delivery_store_atomic import AUTH, BINDINGS, obs, rows, store_at
from test_delivery_store_tracking import projection


def test_completed_baseline_independent_of_domain_and_exact_clean_grace(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap(projection(["1.1.1.1"]), {}, AUTH)
    store.record_domain(obs([]), AUTH, BINDINGS)
    assert rows(tmp_path, "baseline")[0]["ip"] == "1.1.1.1"
    result = store.reconcile_full(AUTH, {}, 100, BINDINGS)
    assert result["source_valid"] and result["ledger_committed"]
    assert rows(tmp_path, "grace")[0]["missing_since"] == 100
    store.close(clean=True)
    store = store_at(tmp_path)
    store.bootstrap(projection([]), {}, AUTH)
    assert store.reconcile_full(AUTH, {}, 86499, BINDINGS)["admitted_receipts"] == 0
    assert store.reconcile_full(AUTH, {}, 86500, BINDINGS)["admitted_receipts"] == 1
    assert not rows(tmp_path, "grace")
    store.close(clean=True)


def test_expiry_rollback_then_gap_counts_without_replay(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {"1.1.1.1": {"labels": ["x"], "missing_since": 1}}, AUTH)
    def fail(point):
        if point == "before_commit":
            raise sqlite3.OperationalError("injected I/O error")
    store._fault = fail
    assert not store.reconcile_full(AUTH, {}, 86401, BINDINGS)["ledger_committed"]
    assert len(rows(tmp_path, "grace")) == 1
    assert not rows(tmp_path, "receipt")
    store._fault = lambda _: None
    store.recover_gap(AUTH, {}, {"active_map": {}, "completed_at": 86402, "bindings": BINDINGS}, None)
    assert not rows(tmp_path, "grace")
    assert store.health_snapshot()["missed_total"] == 1
    assert not rows(tmp_path, "receipt")
    store.close(clean=True)


def test_expiry_at_capacity_retires_once_force_only_cancels_fresh(tmp_path):
    store = store_at(tmp_path, limits={"receipts": 1})
    store.bootstrap({}, {"1.1.1.1": {"labels": ["x"], "missing_since": 1},
                         "2.2.2.2": {"labels": ["x"], "missing_since": 1}}, AUTH)
    store.record_domain(obs(["3.3.3.3"]), AUTH, BINDINGS)
    assert not store.cancel_force_positive({**AUTH, "valid": False}, ["1.1.1.1"])["source_valid"]
    store.cancel_force_positive(AUTH, ["1.1.1.1"])
    assert [r["ip"] for r in rows(tmp_path, "grace")] == ["2.2.2.2"]
    assert store.reconcile_full(AUTH, {}, 86401, BINDINGS)["missed_receipts"] == 1
    assert store.reconcile_full(AUTH, {}, 86402, BINDINGS)["missed_receipts"] == 0
    assert len(rows(tmp_path, "receipt")) == 1
    store.close(clean=True)


def test_unclean_restart_rebaselines_additions_and_holds_grace(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap(projection(["1.1.1.1"]), {"2.2.2.2": {"labels": ["x"], "missing_since": 1}}, AUTH)
    store.close(clean=False)
    store = store_at(tmp_path)
    assert store.bootstrap(projection(["1.1.1.1"]), {}, AUTH)["rebaseline_required"]
    result = store.record_domain(obs(["3.3.3.3"]), AUTH, BINDINGS)
    assert result["admitted_receipts"] == 0
    full = {"active_map": {"3.3.3.3": ["x"]}, "completed_at": 100, "bindings": BINDINGS}
    store.recover_gap(AUTH, projection(["3.3.3.3"]), full, None)
    grace = {r["ip"]: r for r in rows(tmp_path, "grace")}
    assert grace["1.1.1.1"]["missing_since"] == 100
    assert grace["2.2.2.2"]["missing_since"] == 1
    assert grace["2.2.2.2"]["not_before"] == 86500
    assert store.health_snapshot()["missed_total"] == 1
    store.close(clean=True)


def test_tracking_overflow_preserves_existing_grace_and_reseeds_baseline(tmp_path):
    store = store_at(tmp_path, limits={"baseline_items": 1, "grace_items": 1})
    store.bootstrap(projection(["1.1.1.1"]), {}, AUTH)
    store.reconcile_full(AUTH, {"2.2.2.2": ["x"], "3.3.3.3": ["x"]}, 10, BINDINGS)
    assert not store.health_snapshot()["tracking_complete"]
    store.reconcile_full(AUTH, {"4.4.4.4": ["x"]}, 11, BINDINGS)
    assert not rows(tmp_path, "grace")
    assert [r["ip"] for r in rows(tmp_path, "baseline")] == ["4.4.4.4"]
    store.close(clean=True)
