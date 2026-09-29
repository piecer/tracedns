from test_delivery_store_atomic import AUTH, BINDINGS, obs, rows, store_at


def projection(ips, target="example.test"):
    return {target: {"ips": ips, "signature": "dns-v1", "label": target}}


def test_enrollment_and_stale_authority_and_projection_rebase(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap(projection(["1.1.1.1"]), {}, AUTH)
    assert store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)["admitted_receipts"] == 0
    assert store.record_domain(obs(["2.2.2.2"]), {**AUTH, "valid": False}, BINDINGS)["outcome"] == "stale"
    assert store.record_domain(obs(["1.1.1.1"], before_ips=[], projection_signature="dns-v2"),
                               AUTH, BINDINGS)["admitted_receipts"] == 1
    store.close(clean=True)


def test_cursor_overflow_reenrolls_without_old_delta_replay(tmp_path):
    store = store_at(tmp_path, limits={"target_ips": 1})
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    result = store.record_domain(obs(["1.1.1.1", "2.2.2.2"], before_ips=["1.1.1.1"]), AUTH, BINDINGS)
    assert result["missed_receipts"] == 1
    assert not store.health_snapshot()["tracking_complete"]
    assert len(rows(tmp_path, "receipt")) == 1
    result = store.record_domain(obs(["3.3.3.3"]), AUTH, BINDINGS)
    assert result["admitted_receipts"] == 0
    result = store.record_domain(obs(["4.4.4.4"]), AUTH, BINDINGS)
    assert result["admitted_receipts"] == 1
    store.close(clean=True)


def test_recent_suppression_is_not_ack_or_loss(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1"], observed_at=10), AUTH, BINDINGS)
    store.record_domain(obs([], observed_at=20), AUTH, BINDINGS)
    result = store.record_domain(obs(["1.1.1.1"], observed_at=30), AUTH, BINDINGS)
    assert result["admitted_receipts"] == 0
    assert result["missed_receipts"] == 0
    assert store.health_snapshot()["acked_total"] == 0
    store.record_domain(obs([], observed_at=40), AUTH, BINDINGS)
    assert store.record_domain(obs(["1.1.1.1"], observed_at=71), AUTH, BINDINGS)["admitted_receipts"] == 1
    store.close(clean=True)


def test_gap_checkpoint_rebases_live_projection_without_replay(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    store.enter_gap("delivery_storage", {"misp": 2})
    result = store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    assert result["outcome"] == "gap"
    assert not rows(tmp_path, "receipt")
    recovered = store.recover_gap(AUTH, projection(["1.1.1.1"]),
                                  {"active_map": {"1.1.1.1": ["example.test"]}, "completed_at": 100}, None)
    assert recovered["ready"]
    assert store.health_snapshot()["missed_total"] == 3
    assert store.health_snapshot()["missed_unpersisted"] == 0
    store.recover_gap(AUTH, projection(["1.1.1.1"]),
                      {"active_map": {"1.1.1.1": ["example.test"]}, "completed_at": 101}, None)
    assert store.health_snapshot()["missed_total"] == 3
    assert store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)["admitted_receipts"] == 0
    assert not store.health_snapshot()["accounting_complete"]
    store.close(clean=True)
