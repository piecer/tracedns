import json

from test_delivery_store_atomic import AUTH, BINDINGS, obs, rows, store_at
from test_delivery_store_batch import TEAMS
from test_delivery_store_claims import result
from test_delivery_store_tracking import projection


def test_bootstrap_orphan_cleanup_never_cascades_admitted_work(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    store.close(clean=True)
    store = store_at(tmp_path)
    store.bootstrap({}, {}, {**AUTH, "revision": 2})
    assert not rows(tmp_path, "cursor")
    assert len(rows(tmp_path, "receipt")) == 1
    assert store.health_snapshot()["coverage"] == "rebaselining"
    store.close(clean=True)
    assert not json.loads(rows(tmp_path, "control")[0]["data"])["clean"]


def test_malformed_render_retained_seal_and_restart_still_opens(tmp_path):
    def broken(entries, action, created):
        raise RuntimeError("renderer unavailable")
    store = store_at(tmp_path, render=broken)
    store.bootstrap({}, {}, AUTH)
    assert store.record_domain(obs(["1.1.1.1"]), AUTH, TEAMS)["ledger_committed"]
    assert not store.seal_cycle("cycle1")["ledger_committed"]
    store.close(clean=True)
    store = store_at(tmp_path, render=broken)
    assert store.bootstrap(projection([]), {}, AUTH)["ready"]
    assert len(rows(tmp_path, "receipt")) == 1
    store.close(clean=True)


def test_batch_finish_requires_exact_leader_not_member_with_copied_token(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1", "2.2.2.2"]), AUTH, TEAMS)
    store.seal_cycle("cycle1")
    claim = store.claim_next(TEAMS[0], 100)
    member = rows(tmp_path, "receipt")[1]["id"]
    assert not store.finish_step({**claim, "claim_id": "b:" + str(member)}, result(), 100)["applied"]
    assert store.finish_step(claim, result(), 100)["applied"]
    assert store.health_snapshot()["acked_total"] == 2
    store.close(clean=True)


def test_recovery_repeated_healthy_call_does_not_extend_hold(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {"1.1.1.1": {"labels": ["x"], "missing_since": 1}}, AUTH)
    store.enter_gap("delivery_storage", {})
    store.recover_gap(AUTH, {}, {"active_map": {}, "completed_at": 100}, None)
    original = rows(tmp_path, "grace")[0]["not_before"]
    store.recover_gap(AUTH, {}, {"active_map": {}, "completed_at": 200}, None)
    assert rows(tmp_path, "grace")[0]["not_before"] == original
    store.close(clean=True)


def test_source_operation_cas_stale_does_not_consume_projection(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    first = obs(["1.1.1.1"])
    store.record_domain(first, AUTH, BINDINGS)
    assert store.cursor_incarnation("example.test") == rows(tmp_path, "cursor")[0]["incarnation"]
    second = obs(["2.2.2.2"], expected_operation_id="obsolete")
    assert store.record_domain(second, AUTH, BINDINGS)["outcome"] == "stale"
    assert len(rows(tmp_path, "receipt")) == 1
    store.close(clean=True)
