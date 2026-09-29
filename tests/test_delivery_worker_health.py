import time

from test_delivery_store_atomic import AUTH, BINDINGS, obs, store_at
from test_delivery_worker_execution import worker_for


def test_idle_daemon_remains_running_in_cached_health_until_stop(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    class Adapter:
        def execute_step(self, claim):
            raise AssertionError("no work")
    worker = worker_for(store, Adapter())
    assert worker.start()
    time.sleep(.05)
    assert store.health_snapshot()["worker_running"]
    assert worker.stop()["stopped"]
    assert not store.health_snapshot()["worker_running"]
    store.close(clean=True)


def test_binding_block_health_explains_old_binding_and_zero_epoch_age(tmp_path):
    store = store_at(tmp_path, clock=lambda: 100)
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1"], observed_at=0), AUTH, BINDINGS)
    assert store.health_snapshot()["oldest_pending_age_seconds"] == 100
    assert store.claim_next({**BINDINGS[0], "binding_id": "b" * 64}, 100) is None
    assert store.health_snapshot()["channels"]["misp"]["last_error"] == "old_binding_blocked"
    store.close(clean=True)
