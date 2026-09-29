"""Store boundary tests: source authority is supplied by the core owner."""
import importlib.util
import json
import sqlite3
import uuid


AUTH = {"valid": True, "revision": 1, "signature": "configured-v1"}
BINDINGS = [{"channel": "misp", "binding_id": "a" * 64, "enabled": True,
             "ready": True, "allow_removed": True, "error": None}]


def store_at(path, **kwargs):
    assert importlib.util.find_spec("monitor.delivery_store"), "delivery store missing"
    from monitor.delivery_store import DeliveryStore
    return DeliveryStore(path, **kwargs)


def obs(ips, *, target="example.test", op=None, cycle="cycle1", **extra):
    return {"target": target, "managed_ips": ips, "before_ips": [],
            "projection_signature": "dns-v1", "source_operation_id": op or str(uuid.uuid4()),
            "cycle_id": cycle, "observed_at": 100, "label": target,
            "source_type": "A", **extra}


def rows(path, table):
    with sqlite3.connect(path / "delivery.sqlite") as db:
        db.row_factory = sqlite3.Row
        return [dict(r) for r in db.execute("SELECT * FROM " + table).fetchmany(256)]


def test_atomic_admission_survives_independent_reopen(tmp_path):
    store = store_at(tmp_path)
    assert store.bootstrap({}, {}, AUTH)["ready"]
    observation = obs(["1.2.3.4"])
    result = store.record_domain(observation, AUTH, BINDINGS)
    assert result["outcome"] == "admitted"
    assert result["admitted_receipts"] == 1
    assert result["ledger_committed"]
    assert len(rows(tmp_path, "receipt")) == 1
    assert json.loads(rows(tmp_path, "cursor")[0]["ips"]) == ["1.2.3.4"]
    store.close(clean=True)
    reopened = store_at(tmp_path)
    assert reopened.bootstrap({}, {}, AUTH)["ready"]
    assert reopened.record_domain(observation, AUTH, BINDINGS)["admitted_receipts"] == 0
    assert len(rows(tmp_path, "receipt")) == 1
    assert reopened.health_snapshot()["accounting_complete"] is False
    reopened.close(clean=True)


def test_capacity_consumes_whole_unit_without_eviction_or_replay(tmp_path):
    store = store_at(tmp_path, limits={"receipts": 2})
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    both = BINDINGS + [{**BINDINGS[0], "channel": "teams", "binding_id": "b" * 64}]
    candidate = obs(["1.1.1.1", "2.2.2.2"])
    result = store.record_domain(candidate, AUTH, both)
    assert result["outcome"] == "missed"
    assert result["missed_receipts"] == 2
    assert len(rows(tmp_path, "receipt")) == 1
    assert store.health_snapshot()["missed_total"] == 2
    assert store.record_domain(candidate, AUTH, both)["missed_receipts"] == 0
    store.close(clean=True)


def test_encoded_whole_unit_limits_and_disabled_consumption(tmp_path):
    store = store_at(tmp_path, limits={"unit_items": 1, "label_bytes": 4})
    store.bootstrap({}, {}, AUTH)
    result = store.record_domain(obs(["1.1.1.1", "2.2.2.2"], label="x"), AUTH, BINDINGS)
    assert result["missed_receipts"] == 2
    result = store.record_domain(obs(["3.3.3.3"], label="雪雪"), AUTH, BINDINGS)
    assert result["missed_receipts"] == 1
    assert rows(tmp_path, "receipt") == []
    store.record_domain(obs(["4.4.4.4"], label="x"), AUTH, [])
    assert store.record_domain(obs(["4.4.4.4"], label="x"), AUTH, BINDINGS)["admitted_receipts"] == 0
    store.close(clean=True)
