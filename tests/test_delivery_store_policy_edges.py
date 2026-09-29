import json

from test_delivery_store_atomic import AUTH, BINDINGS, obs, rows, store_at
from test_delivery_store_claims import result


def test_grace_suppresses_addition_without_loss_or_early_cancel(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {"1.1.1.1": {"labels": ["x"], "missing_since": 1}}, AUTH)
    admission = store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    assert admission["admitted_receipts"] == admission["missed_receipts"] == 0
    assert len(rows(tmp_path, "grace")) == 1
    store.cancel_force_positive(AUTH, ["1.1.1.1"])
    assert not rows(tmp_path, "grace")
    store.close(clean=True)


def test_recent_capacity_whole_unit_and_fixed_reason_channel_counters(tmp_path):
    store = store_at(tmp_path, limits={"recent_items": 1})
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    value = store.record_domain(obs(["2.2.2.2", "3.3.3.3"]), AUTH, BINDINGS)
    assert value["missed_receipts"] == 2
    assert len(rows(tmp_path, "receipt")) == 1
    control = json.loads(rows(tmp_path, "control")[0]["data"])
    assert control["missed_by_reason"]["delivery_capacity"]["misp"] == 2
    store.close(clean=True)


def test_force_fail_gap_does_not_count_grace_suppressed_return_as_missed(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {"1.1.1.1": {"labels": ["x"], "missing_since": 1}}, AUTH)
    store.enter_gap("delivery_storage", {})
    store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    assert store.health_snapshot()["missed_unpersisted"] == 0
    assert not store.health_snapshot()["accounting_complete"]
    store.close(clean=False)


def test_same_binding_repair_releases_block_without_reset(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    claim = store.claim_next(BINDINGS[0], 100)
    store.finish_step(claim, result("blocked", reason="provider_auth"), 100)
    assert store.health_snapshot()["channels"]["misp"]["last_error"] == "provider_auth"
    assert store.claim_next(BINDINGS[0], 200) is None
    store.configuration_applied()
    assert store.claim_next(BINDINGS[0], 200)["attempt"] == 2
    store.close(clean=False)


def test_readonly_error_is_observation_gap_not_false_durable_count(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    with store._lock:
        store._execute("PRAGMA query_only=ON")
    outcome = store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    assert outcome["outcome"] == "gap"
    assert store.health_snapshot()["missed_total"] == 0
    assert store.health_snapshot()["missed_unpersisted"] == 1
    assert not rows(tmp_path, "receipt")
    store.close(clean=False)


def test_provider_step_secret_extra_fields_not_persisted_in_control(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    descriptor = {**BINDINGS[0], "endpoint": "secret-webhook"}
    assert store.claim_next(descriptor, 100) is None
    assert "secret-webhook" not in json.dumps(rows(tmp_path, "control"))
    store.close(clean=True)


def test_real_crash_after_remote_success_before_ack_retries_claim(tmp_path):
    import os
    import subprocess
    import sys
    store = store_at(tmp_path, clock=lambda: 100)
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    store.close(clean=True)
    code = '''
import json, os, sys
from pathlib import Path
from monitor.delivery_store import DeliveryStore
from monitor.delivery_worker import DeliveryWorker
s = DeliveryStore(sys.argv[1], clock=lambda:100)
s.bootstrap({}, {}, {"valid":True,"revision":1,"signature":"configured-v1"})
b = {"channel":"misp","binding_id":"a"*64,"enabled":True,"ready":True,"allow_removed":True,"error":None}
class Adapter:
 def execute_step(self, claim):
  Path(sys.argv[1], "remote-success").write_text("fake remote accepted")
  os._exit(24)
def admit(now):
 c=s.claim_next(b, now)
 return (c, Adapter()) if c else None
DeliveryWorker(s, claim_admission=admit, clock=lambda:100).run_pass()
'''
    child = subprocess.run([sys.executable, "-c", code, str(tmp_path)],
                           env={**os.environ, "PYTHONPATH": os.getcwd()}, timeout=10)
    assert child.returncode == 24
    assert (tmp_path / "remote-success").exists()
    assert rows(tmp_path, "receipt")[0]["state"] == "in_flight"
    store = store_at(tmp_path, clock=lambda: 100)
    store.bootstrap({}, {}, AUTH)
    claim = store.claim_next(BINDINGS[0], 130)
    assert claim["attempt"] == 2 and claim["provider_calls"] == 2
    assert store.health_snapshot()["acked_total"] == 0
    store.close(clean=False)
