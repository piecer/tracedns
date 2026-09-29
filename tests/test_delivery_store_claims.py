from test_delivery_store_atomic import AUTH, BINDINGS, obs, rows, store_at


def result(state="acked", **extra):
    return {"state": state, "reason": None, "progress": {}, "retry_after": None,
            "provider_calls": 1, "observation_hook": None, **extra}


def test_opaque_claim_finish_cas_and_terminal_gc_no_replay(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    candidate = obs(["1.1.1.1"])
    store.record_domain(candidate, AUTH, BINDINGS)
    claim = store.claim_next(BINDINGS[0], 100)
    assert claim["attempt"] == 1 and claim["attempt_token"]
    assert not store.finish_step({**claim, "attempt_token": "forged"}, result(), 100)["applied"]
    assert store.finish_step(claim, result(), 100)["applied"]
    assert not store.finish_step(claim, result(), 100)["applied"]
    assert store.health_snapshot()["acked_total"] == 1
    assert not rows(tmp_path, "receipt")
    assert store.record_domain(candidate, AUTH, BINDINGS)["admitted_receipts"] == 0
    store.close(clean=True)


def test_retry_attempts_due_and_crash_interrupted_claim_never_reset(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    now = 100
    for attempt in range(1, 9):
        claim = store.claim_next(BINDINGS[0], now)
        assert claim["attempt"] == attempt
        assert store.finish_step(claim, result("retry", reason="provider_transient", retry_after=35), now)["applied"]
        if attempt < 8:
            delay = max(35, 30 * 2 ** (attempt - 1))
            assert store.claim_next(BINDINGS[0], now + delay - 1) is None
            now += delay
            store.close(clean=True)
            store = store_at(tmp_path)
            store.bootstrap({}, {}, AUTH)
    assert store.health_snapshot()["failed_total"] == 1
    assert store.health_snapshot()["missed_total"] == 0
    assert store.claim_next(BINDINGS[0], now + 10000) is None
    store.close(clean=True)


def test_fifo_across_sources_and_binding_block_then_resume(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {"1.1.1.1": {"labels": ["x"], "missing_since": 1}}, AUTH)
    store.reconcile_full(AUTH, {}, 86401, BINDINGS)
    first = store.claim_next(BINDINGS[0], 86401)
    assert first["action"] == "Removed"
    store.finish_step(first, result("retry"), 86401)
    store.record_domain(obs(["1.1.1.1"], target="other", observed_at=86402), AUTH, BINDINGS)
    store.record_domain(obs(["2.2.2.2"], target="third", observed_at=86402), AUTH, BINDINGS)
    unrelated = store.claim_next(BINDINGS[0], 86402)
    assert unrelated["payload"]["entries"][0][0] == "2.2.2.2"
    store.finish_step(unrelated, result(), 86402)
    assert store.claim_next(BINDINGS[0], 86402) is None
    assert store.claim_next({**BINDINGS[0], "binding_id": "b" * 64}, 86500) is None
    assert store.health_snapshot()["blocked"] == 2
    resumed = store.claim_next(BINDINGS[0], 86500)
    assert resumed["attempt"] == 2 and resumed["action"] == "Removed"
    store.finish_step(resumed, result(), 86500)
    assert store.claim_next(BINDINGS[0], 86500)["action"] == "Added"
    store.close(clean=False)


def test_continue_one_workflow_attempt_and_persisted_call_cap(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    first = store.claim_next(BINDINGS[0], 100)
    store.finish_step(first, result("continue", progress={"phase": "read"}), 100)
    second = store.claim_next(BINDINGS[0], 100)
    assert second["attempt"] == 1 and second["provider_calls"] == 2
    assert not store.finish_step(first, result(), 100)["applied"]
    store.close(clean=False)
    store = store_at(tmp_path, clock=lambda: 100)
    store.bootstrap({}, {}, AUTH)
    assert store.claim_next(BINDINGS[0], 129) is None
    third = store.claim_next(BINDINGS[0], 130)
    assert third["attempt"] == 2 and third["provider_calls"] == 3
    store.finish_step(third, result("continue"), 130)
    with store._lock:
        store._execute("UPDATE receipt SET provider_calls=4096")
    assert store.claim_next(BINDINGS[0], 130) is None
    assert store.health_snapshot()["failed_total"] == 1
    store.close(clean=True)
