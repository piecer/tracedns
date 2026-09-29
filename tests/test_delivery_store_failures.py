import json
import os
import sqlite3
import subprocess
import sys
import time

import pytest

from test_delivery_store_atomic import AUTH, BINDINGS, obs, rows, store_at


def test_busy_is_gap_not_exception_and_known_loss_is_volatile(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    blocker = sqlite3.connect(tmp_path / "delivery.sqlite", isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    started = time.monotonic()
    result = store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    assert time.monotonic() - started < 1
    assert result["outcome"] == "gap"
    assert not result["ledger_committed"]
    assert store.health_snapshot()["missed_unpersisted"] == 1
    assert store.health_snapshot()["counts_stale"]
    blocker.rollback()
    blocker.close()
    store.close(clean=False)


def test_owner_sentinel_and_missing_established_db(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    second = store_at(tmp_path)
    assert not second.bootstrap({}, {}, AUTH)["ready"]
    second.close(clean=False)
    assert (tmp_path / "delivery.initialized").stat().st_mode & 0o777 == 0o600
    store.close(clean=True)
    (tmp_path / "delivery.sqlite").rename(tmp_path / "saved.sqlite")
    lost = store_at(tmp_path)
    assert not lost.bootstrap({}, {}, AUTH)["ready"]
    assert not (tmp_path / "delivery.sqlite").exists()
    assert lost.health_snapshot()["last_error"] == "delivery_storage"
    lost.close(clean=False)


@pytest.mark.parametrize("boundary,expected", [("before_commit", 0), ("after_commit", 1)])
def test_real_process_exit_transaction_boundary(tmp_path, boundary, expected):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    store.close(clean=True)
    code = '''
import os, sys
from monitor.delivery_store import DeliveryStore
s = DeliveryStore(sys.argv[1])
s.bootstrap({}, {}, {"valid":True,"revision":1,"signature":"configured-v1"})
s._fault = lambda point: os._exit(23) if point == sys.argv[2] else None
s.record_domain({"target":"t", "managed_ips":["1.1.1.1"], "before_ips":[],
"projection_signature":"s", "source_operation_id":"op", "cycle_id":"c", "observed_at":1,
"label":"t","source_type":"A"}, {"valid":True,"revision":1,"signature":"configured-v1"},
[{"channel":"misp","binding_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
"enabled":True,"ready":True,"allow_removed":True,"error":None}])
'''
    child = subprocess.run([sys.executable, "-c", code, str(tmp_path), boundary],
                           env={**os.environ, "PYTHONPATH": os.getcwd()}, timeout=10)
    assert child.returncode == 23
    assert len(rows(tmp_path, "receipt")) == expected
    assert len(rows(tmp_path, "cursor")) == expected
    reopened = store_at(tmp_path)
    assert reopened.bootstrap({}, {}, AUTH)["ready"]
    reopened.close(clean=True)


def test_ambiguous_commit_readback_does_not_double_count(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    def fault(point):
        if point == "after_commit":
            raise sqlite3.OperationalError("injected commit return error")
    store._fault = fault
    result = store.record_domain(obs(["1.1.1.1"]), AUTH, BINDINGS)
    assert result["ledger_committed"]
    assert result["admitted_receipts"] == 1
    assert store.health_snapshot()["missed_unpersisted"] == 0
    assert len(rows(tmp_path, "receipt")) == 1
    store._fault = lambda _: None
    store.close(clean=True)


def test_actual_sqlite_full_rolls_back_unit_and_reports_gap(tmp_path):
    store = store_at(tmp_path)
    store.bootstrap({}, {}, AUTH)
    with store._lock:
        count = store._db.execute("PRAGMA page_count").fetchone()[0]
        store._db.execute("PRAGMA max_page_count=" + str(count))
    result = store.record_domain(obs(["10.0.0." + str(i) for i in range(1, 120)], label="x" * 500),
                                 AUTH, BINDINGS)
    assert result["outcome"] == "gap"
    assert rows(tmp_path, "receipt") == []
    assert rows(tmp_path, "cursor") == []
    assert store.health_snapshot()["missed_unpersisted"] == 119
    assert len(json.dumps(store.health_snapshot()).encode()) <= 4096
    store.close(clean=False)
