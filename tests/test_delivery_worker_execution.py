import importlib.util
import sqlite3
import threading

from test_delivery_store_atomic import AUTH, BINDINGS, obs, rows, store_at
from test_delivery_store_claims import result


def worker_for(store, adapter, **kwargs):
    assert importlib.util.find_spec("monitor.delivery_worker"), "delivery worker missing"
    from monitor.delivery_worker import DeliveryWorker
    def admit(now):
        claim = store.claim_next(BINDINGS[0], now)
        return (claim, adapter) if claim else None
    return DeliveryWorker(store, claim_admission=admit, clock=lambda: 100, **kwargs)


def test_pass_counts_every_http_step_outside_sql_lock(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    class Adapter:
        calls = 0
        def execute_step(self, claim):
            self.calls += 1
            # An independent writer can enter while the network operation runs.
            with sqlite3.connect(tmp_path / "delivery.sqlite", timeout=.01) as db:
                db.execute("BEGIN IMMEDIATE")
            return result("continue", progress={"phase": "read"})
    adapter = Adapter()
    worker = worker_for(store, adapter)
    report = worker.run_pass(max_provider_calls=1000)
    assert report["provider_calls"] == adapter.calls == 32
    assert rows(tmp_path, "receipt")[0]["provider_calls"] == 32
    assert rows(tmp_path, "receipt")[0]["attempt"] == 1
    assert worker.stop()["stopped"]
    assert store.close(clean=True)


def test_stop_live_callback_false_close_preserves_inflight(tmp_path):
    entered, release = threading.Event(), threading.Event()
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    class Adapter:
        def execute_step(self, claim):
            entered.set()
            assert release.wait(5)
            return result()
    worker = worker_for(store, Adapter())
    thread = threading.Thread(target=worker.run_pass)
    thread.start()
    assert entered.wait(2)
    assert not worker.stop(join_seconds=.01)["stopped"]
    assert store.close(clean=True) is False
    release.set()
    thread.join(2)
    assert not thread.is_alive()
    assert rows(tmp_path, "receipt")[0]["state"] == "in_flight"
    assert worker.stop()["stopped"]
    assert store.close(clean=True)
    assert not __import__("json").loads(rows(tmp_path, "control")[0]["data"])["clean"]


def test_hook_flag_commits_before_local_hook_and_no_retry_hook(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    hooks = []
    class Adapter:
        calls = 0
        def execute_step(self, claim):
            self.calls += 1
            return result("continue" if self.calls == 1 else "acked",
                          observation_hook={"kind": "sighting", "ip": "1.1.1.1"})
    def hook(value):
        assert rows(tmp_path, "receipt")[0]["hook"] == 1
        hooks.append(value)
        raise RuntimeError("secret must not escape")
    worker = worker_for(store, Adapter(), observation_hook=hook)
    worker.run_pass()
    assert len(hooks) == 1
    assert store.health_snapshot()["acked_total"] == 1
    worker.stop()
    store.close(clean=True)


def test_ack_write_failure_halts_claims_without_stopping_observation(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    store.record_domain(obs(["1.1.1.1", "2.2.2.2"]), AUTH, BINDINGS)
    class Adapter:
        calls = 0
        def execute_step(self, claim):
            self.calls += 1
            def fail(point):
                if point == "before_commit":
                    raise sqlite3.OperationalError("ACK unavailable")
            store._fault = fail
            return result()
    adapter = Adapter()
    worker = worker_for(store, adapter)
    worker.run_pass()
    assert adapter.calls == 1
    store._fault = lambda _: None
    assert store.record_domain(obs(["3.3.3.3"], before_ips=["1.1.1.1", "2.2.2.2"]), AUTH, BINDINGS)["outcome"] == "gap"
    assert len(rows(tmp_path, "receipt")) == 2
    assert store.health_snapshot()["acked_total"] == 0
    worker.stop()
    store.close(clean=False)
