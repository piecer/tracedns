import json
import sqlite3

from test_delivery_store_atomic import AUTH, BINDINGS, obs, rows, store_at
from test_delivery_store_batch import TEAMS
from test_delivery_store_claims import result
from test_delivery_store_tracking import projection
from test_delivery_worker_execution import worker_for


def test_recovery_gap_compares_durable_cursor_not_newer_history(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap(projection(["1.1.1.1"]), {}, AUTH)
    store.close(clean=False)
    store = store_at(tmp_path)
    store.bootstrap(projection(["2.2.2.2"]), {}, AUTH)
    candidate = obs(["2.2.2.2"], before_ips=["2.2.2.2"])
    store.record_domain(candidate, AUTH, BINDINGS)
    store.record_domain(obs(["2.2.2.2"], before_ips=["2.2.2.2"]), AUTH, BINDINGS)
    assert store.health_snapshot()["missed_total"] == 1
    assert store.health_snapshot()["missed_unpersisted"] == 0
    assert not rows(tmp_path, "receipt")
    store.close(clean=False)


def test_refresh_read_failure_does_not_turn_committed_intent_into_loss(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    original = store._refresh
    def broken():
        raise sqlite3.OperationalError("health read unavailable")
    store._refresh = broken
    result = store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    assert result["ledger_committed"]
    assert result["admitted_receipts"] == 1
    assert store.health_snapshot()["counts_stale"]
    assert store.health_snapshot()["missed_unpersisted"] == 0
    store._refresh = original
    store.close(clean=False)


def test_byte_admission_reserve_and_full_chunk_seal_early(tmp_path):
    store = store_at(tmp_path, limits={"payload_bytes": 20000})
    store.bootstrap({}, {}, AUTH)
    assert store.record_domain(obs(["1.1.1.1"]), AUTH, TEAMS)["missed_receipts"] == 1
    assert not rows(tmp_path, "receipt")
    store.close(clean=True)
    other = tmp_path / "other"
    store = store_at(other)
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["10.0.0." + str(i) for i in range(1, 62)]), AUTH, TEAMS)
    assert len(rows(other, "batch")) == 1
    assert len([r for r in rows(other, "receipt") if r["state"] == "unsealed"]) == 1
    store.seal_cycle("cycle1")
    assert len(rows(other, "batch")) == 2
    store.close(clean=True)


def test_ack_error_recovery_retries_interrupted_claim_without_reset(tmp_path):
    store = store_at(tmp_path, clock=lambda: 100)
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    claim = store.claim_next(BINDINGS[0], 100)
    def fail(point):
        if point == "before_commit":
            raise sqlite3.OperationalError("failed ACK")
    store._fault = fail
    assert not store.finish_step(claim, result(), 100)["applied"]
    store._fault = lambda _: None
    assert store.recover_gap(AUTH, projection(["1.1.1.1"]),
                             {"active_map": {"1.1.1.1": ["x"]}, "completed_at": 100}, None)["ready"]
    retried = store.claim_next(BINDINGS[0], 130)
    assert retried["attempt"] == 2 and retried["attempt_token"] != claim["attempt_token"]
    assert not store.finish_step(claim, result(), 130)["applied"]
    store.close(clean=False)


def test_sighting_flush_shares_actual_pass_budget(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    calls = []
    class Adapter:
        def execute_step(self, claim):
            raise AssertionError("no attribute work")
    def sighting():
        calls.append("HTTP")
        return {"provider_calls": 1, "has_more": len(calls) < 40}
    worker = worker_for(store, Adapter(), sightings_step=sighting)
    assert worker.run_pass()["provider_calls"] == 32
    assert len(calls) == 32
    worker.stop()
    store.close(clean=True)


def test_257_item_loss_exact_and_default_pragmas_private_files(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    candidate = obs(["10.0.%d.%d" % (i // 250, i % 250 + 1) for i in range(257)])
    assert store.record_domain(candidate, AUTH, BINDINGS + TEAMS)["missed_receipts"] == 514
    assert not rows(tmp_path, "receipt")
    with store._lock:
        assert store._one("PRAGMA max_page_count")[0] == 16384
        assert store._one("PRAGMA journal_mode")[0] == "delete"
        assert store._one("PRAGMA synchronous")[0] == 2
        assert store._one("PRAGMA busy_timeout")[0] == 50
    assert (tmp_path / "delivery.sqlite").stat().st_mode & 0o777 == 0o600
    assert len(json.dumps(store.health_snapshot()).encode()) <= 4096
    store.close(clean=True)
