import json
import sqlite3

from test_delivery_store_atomic import AUTH, BINDINGS, obs, rows, store_at
from test_delivery_store_claims import result

TEAMS = [{**BINDINGS[0], "channel": "teams"}]


def test_small_cycle_one_frozen_batch_and_channels_independent(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1"], target="first"), AUTH, TEAMS + BINDINGS)
    store.record_domain(obs(["2.2.2.2"], target="second"), AUTH, TEAMS + BINDINGS)
    assert store.claim_next(TEAMS[0], 100) is None
    assert store.seal_cycle("cycle1")["sealed_batches"] == 1
    claim = store.claim_next(TEAMS[0], 100)
    assert len(claim["payload"]["entries"]) == 2
    body = claim["payload"]["body"]
    store.finish_step(claim, result("retry"), 100)
    claim = store.claim_next(TEAMS[0], 130)
    assert claim["payload"]["body"] == body
    store.finish_step(claim, result(), 130)
    assert store.health_snapshot()["acked_total"] == 2
    assert len(rows(tmp_path, "receipt")) == 2
    assert store.claim_next(TEAMS[0], 200) is None
    store.close(clean=True)


def test_chunking_61_and_restart_unsealed_without_recollection(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["10.0.0." + str(i) for i in range(1, 62)]), AUTH, TEAMS)
    store.close(clean=False)
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    sizes = []
    while True:
        claim = store.claim_next(TEAMS[0], 100)
        if not claim:
            break
        sizes.append(len(claim["payload"]["entries"]))
        assert len(json.dumps(claim["payload"]["body"], ensure_ascii=False).encode()) <= 24 * 1024
        store.finish_step(claim, result(), 100)
    assert sizes == [60, 1]
    assert store.health_snapshot()["acked_total"] == 61
    store.close(clean=True)


def test_seal_error_keeps_capacity_and_encoded_body_chunks(tmp_path):
    def render(entries, action, created):
        return {"title": action, "text": "|".join(e[1] for e in entries)}
    store = store_at(tmp_path, render=render, limits={"batch_bytes": 150})
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1", "2.2.2.2", "3.3.3.3"], label="雪" * 20), AUTH, TEAMS)
    def fail(point):
        if point == "before_commit":
            raise sqlite3.OperationalError("seal unavailable")
    store._fault = fail
    assert not store.seal_cycle("cycle1")["ledger_committed"]
    assert store.health_snapshot()["capacity"]["used_receipts"] == 3
    store._fault = lambda _: None
    # Compact UTF-8 fits two items (not ASCII-escaped one-item chunks).
    # One full prefix sealed early; the remaining singleton seals now.
    assert store.seal_cycle("cycle1")["sealed_batches"] == 1
    assert len(rows(tmp_path, "batch")) == 2
    claim = store.claim_next(TEAMS[0], 100)
    assert len(claim["payload"]["entries"]) == 2
    store.close(clean=False)
