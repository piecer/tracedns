"""Bounded, worker-only enrichment lifecycle contracts."""
import importlib
import importlib.util
import itertools
import json

import pytest
import threading
import time
from unittest import mock


IP = "8.8.8.8"
REAL_MONOTONIC = time.monotonic


def service_type():
    spec = importlib.util.find_spec("http_api.enrichment")
    assert spec is not None, "BackgroundEnrichment service is missing"
    return importlib.import_module("http_api.enrichment").BackgroundEnrichment


def eventually(check):
    deadline = REAL_MONOTONIC() + 2
    while REAL_MONOTONIC() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.002)
    raise AssertionError("background transition did not complete")


def test_explicit_start_nonblocking_lookup_and_pending_deduplication():
    entered, release = threading.Event(), threading.Event()
    calls = []

    def lookup(ip):
        calls.append((ip, threading.current_thread().daemon))
        entered.set()
        release.wait(2)
        return {"malicious": 0}

    with mock.patch("threading.Thread.start") as start:
        service = service_type()(lookup)
        assert start.call_count == 0
        reports, meta = service.request([IP])
        assert reports == {} and meta["pending"] == 0
    service.start()
    try:
        before = time.monotonic()
        reports, meta = service.request([IP, IP], owner="private-owner")
        assert time.monotonic() - before < 0.1
        assert reports == {}
        assert meta["status"] == "pending"
        assert meta["requested"] == meta["pending"] == 1
        assert "private-owner" not in str(meta)
        assert entered.wait(1)
        before = time.monotonic()
        _, again = service.request([IP], owner="other")
        assert time.monotonic() - before < 0.1
        assert again["pending"] == 1
        assert calls == [(IP, True)]
        release.set()
        ready = eventually(lambda: (r := service.request([IP]))[1]["status"] == "ready" and r)
        assert ready[0][IP]["malicious"] == 0
        assert ready[0][IP]["fetched_at"] > 0
        assert ready[0][IP]["stale"] is False
        assert ready[1]["cached"] == 1
        assert ready[1]["version"] > meta["version"]
    finally:
        release.set()
        assert service.close() == {"remaining": 0, "running": 0, "queued": 0}


def test_atomic_capacity_budget_and_owner_limits():
    release = threading.Event()
    service = service_type()(lambda ip: release.wait(2), workers=1, capacity=3, per_owner=2)
    service.start()
    try:
        _, first = service.request([IP, "1.1.1.1", "9.9.9.9"], owner="a")
        assert (first["pending"], first["deferred"]) == (2, 1)
        _, second = service.request([IP, "4.2.2.1", "4.2.2.2"], owner="b", budget=1)
        assert (second["pending"], second["deferred"]) == (2, 1)
        _, third = service.request(["4.2.2.3"], owner="c")
        assert third["deferred"] == 1
    finally:
        release.set()
        service.close()


def test_input_is_public_canonical_unique_and_bounded():
    service = service_type()(None)
    _, meta = service.request([IP, IP, "invalid", "10.1.2.3", "127.0.0.1",
                               "169.254.1.1", "224.0.0.1", "::1", "fc00::1",
                               "100.64.0.1", "2001:4860:4860::8888",
                               "2001:4860:4860:0:0:0:0:8888", None, 123])
    assert meta["requested"] == 2
    assert meta["status"] == "disabled"
    consumed = []

    def ips():
        for value in itertools.repeat(IP, 5001):
            consumed.append(value)
            assert len(consumed) <= 5000, "caller-controlled input exceeded scan bound"
            yield value

    assert service.request(ips())[1]["requested"] == 1
    assert len(consumed) == 5000
    unique = (f"8.9.{n // 256}.{n % 256}" for n in range(6000))
    assert service.request(unique)[1]["requested"] == 5000


@pytest.mark.parametrize("failure", [None, RuntimeError("private backend detail"), {}])
def test_failure_cooldown_retries_only_on_later_request(failure):
    clock = [100.0]
    calls = []

    def lookup(ip):
        calls.append(ip)
        if isinstance(failure, Exception):
            raise failure
        return failure

    with mock.patch("http_api.enrichment.time.monotonic", side_effect=lambda: clock[0]):
        service = service_type()(lookup, retry_after=30)
        service.start()
        try:
            service.request([IP])
            eventually(lambda: service.request([IP], budget=0)[1]["pending"] == 0)
            for _ in range(20):
                reports, meta = service.request([IP])
                assert reports == {}
                assert meta["status"] == "unavailable"
                assert meta["cached"] == meta["pending"] == 0
                assert meta["deferred"] == 1
                assert "private backend detail" not in str(meta)
            assert len(calls) == 1
            clock[0] += 31
            assert len(calls) == 1  # no retry timers
            assert service.request([IP])[1]["pending"] == 1
            eventually(lambda: len(calls) == 2)
        finally:
            service.close(timeout=0)
    service.close()


def test_stale_success_is_retained_through_failed_refresh():
    clock = [100.0]
    calls = []
    entered, release = threading.Event(), threading.Event()

    def lookup(ip):
        calls.append(ip)
        if len(calls) == 1:
            return {"asn": 15169}
        entered.set()
        release.wait(2)
        raise RuntimeError("failed refresh")

    with mock.patch("http_api.enrichment.time.monotonic", side_effect=lambda: clock[0]):
        service = service_type()(lookup, ttl=10, retry_after=30)
        service.start()
        try:
            service.request([IP])
            fresh = eventually(lambda: (r := service.request([IP]))[0] and r)
            fresh_at = fresh[0][IP]["fetched_at"]
            clock[0] += 11
            reports, meta = service.request([IP])
            assert reports[IP]["stale"] is True
            assert reports[IP]["fetched_at"] == fresh_at
            assert meta["status"] == "partial"
            assert meta["cached"] == 0 and meta["pending"] == meta["stale"] == 1
            assert entered.wait(1)
            release.set()
            eventually(lambda: service.request([IP], budget=0)[1]["pending"] == 0)
            reports, meta = service.request([IP])
            assert reports[IP]["asn"] == 15169
            assert reports[IP]["stale"] is True
            assert meta["status"] == "partial" and meta["deferred"] == 1
            assert len(calls) == 2
        finally:
            release.set()
            service.close(timeout=0)
    service.close()


def test_projection_bounds_text_numbers_and_retained_entry_count():
    raw = {"raw": {"blob": "x" * 1_000_000}, "malicious": 0, "suspicious": -1,
           "harmless": True, "undetected": 1 << 10000, "last_analysis_date": 123,
           "asn": 15169, "as_owner": "😀" * 10000, "country": "U" * 10000,
           "unexpected": "secret", "fetched_at": -100, "stale": True}
    service = service_type()(lambda ip: raw, max_entries=2)
    service.start()
    try:
        for ip in [IP, "1.1.1.1", "9.9.9.9"]:
            service.request([ip])
            eventually(lambda: service.request([ip], budget=0)[1]["cached"] == 1)
        reports, meta = service.request([IP, "1.1.1.1", "9.9.9.9"], budget=0)
        assert len(reports) == meta["cached"] == 2
        assert IP not in reports
        report = reports["9.9.9.9"]
        assert set(report) <= {"malicious", "suspicious", "harmless", "undetected",
                               "last_analysis_date", "asn", "as_owner", "country",
                               "fetched_at", "stale"}
        assert report["malicious"] == 0 and report["asn"] == 15169
        assert report.get("suspicious") is None
        assert report.get("harmless") is None
        assert report.get("undetected") is None
        assert len(report["as_owner"]) <= 256
        assert len(report["country"]) <= 8
        assert len(json.dumps(report).encode()) <= 4096
        report["asn"] = 7
        assert service.request(["9.9.9.9"])[0]["9.9.9.9"]["asn"] == 15169
    finally:
        service.close()


def test_report_projection_cannot_hold_the_admission_lock():
    entered, release = threading.Event(), threading.Event()

    class SlowReport(dict):
        def get(self, *args):
            entered.set()
            release.wait(2)
            return super().get(*args)

    service = service_type()(lambda ip: SlowReport(asn=1), workers=1)
    service.start()
    try:
        service.request([IP])
        assert entered.wait(1), "report projection did not inspect allowed fields"
        before = REAL_MONOTONIC()
        assert service.request([IP, "1.1.1.1"])[1]["pending"] == 2
        assert REAL_MONOTONIC() - before < 0.1
    finally:
        release.set()
        service.close()


@pytest.mark.parametrize("option,value", [("workers", 0), ("workers", 5),
    ("capacity", 257), ("max_entries", 0), ("max_entries", 2049),
    ("per_owner", 65), ("ttl", -1), ("retry_after", float("inf")),
    ("ttl", float("nan")), ("workers", True)])
def test_configuration_cannot_remove_hard_bounds(option, value):
    with pytest.raises(ValueError):
        service_type()(lambda ip: None, **{option: value})


def test_close_discards_queue_but_accounts_running_until_actual_return():
    entered, release = threading.Event(), threading.Event()
    calls = []

    def lookup(ip):
        calls.append(ip)
        entered.set()
        release.wait(2)
        return {"malicious": 0}

    service = service_type()(lookup, workers=1)
    service.start()
    service.start()
    try:
        _, initial = service.request([IP, "1.1.1.1", "9.9.9.9"])
        assert entered.wait(1)
        before = REAL_MONOTONIC()
        assert service.close(timeout=0.01) == {"remaining": 1, "running": 1, "queued": 0}
        assert REAL_MONOTONIC() - before < 0.2
        assert service.close(timeout=0) == {"remaining": 1, "running": 1, "queued": 0}
        service.start()  # close is permanent
        _, stopped = service.request([IP, "1.1.1.1", "9.9.9.9"])
        assert stopped["pending"] == 1 and stopped["deferred"] == 2
        assert stopped["version"] > initial["version"]
        assert calls == [IP]
        release.set()
        eventually(lambda: service.close(timeout=0)["remaining"] == 0)
        assert service.close() == {"remaining": 0, "running": 0, "queued": 0}
        assert calls == [IP]
    finally:
        release.set()
        service.close()


def test_default_workers_and_global_capacity_under_concurrent_owners():
    release = threading.Event()
    four_running = threading.Event()
    lock = threading.Lock()
    active = []

    def lookup(ip):
        with lock:
            active.append(ip)
            if len(active) == 4:
                four_running.set()
        release.wait(2)
        return None

    service = service_type()(lookup)
    service.start()
    try:
        results = []
        barrier = threading.Barrier(9)

        def request(index):
            barrier.wait()
            ips = [f"8.{index + 1}.0.{n}" for n in range(100)]
            results.append(service.request(ips, owner=str(index))[1])

        threads = [threading.Thread(target=request, args=(i,)) for i in range(8)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(1)
            assert not thread.is_alive()
        assert sum(m["pending"] for m in results) == 256
        assert all(m["pending"] <= 64 for m in results)
        assert four_running.wait(1)
        assert service.close(timeout=0) == {"remaining": 4, "running": 4, "queued": 0}
        assert len(active) == 4
    finally:
        release.set()
        service.close()


def test_start_failure_is_closed_and_joinable_without_orphan_admission():
    service = service_type()(lambda ip: {"asn": 1})
    original = threading.Thread.start
    started = []

    def start(thread):
        if started:
            raise RuntimeError("thread creation failed")
        started.append(thread)
        return original(thread)

    with mock.patch("threading.Thread.start", side_effect=start, autospec=True):
        with pytest.raises(RuntimeError, match="thread creation failed"):
            service.start()
    try:
        assert service.request([IP])[1]["pending"] == 0
        assert service.close() == {"remaining": 0, "running": 0, "queued": 0}
        assert not started[0].is_alive()
    finally:
        service.stop_admission()
        started[0].join(1)


@pytest.mark.parametrize("owner", ["x" * 257, [], None])
def test_owner_identifiers_are_bounded_before_admission(owner):
    service = service_type()(lambda ip: None)
    with pytest.raises(ValueError):
        service.request([IP], owner=owner)


def test_owner_quota_is_released_after_completion():
    service = service_type()(lambda ip: {"asn": 1}, workers=1, per_owner=1)
    service.start()
    try:
        service.request([IP])
        eventually(lambda: service.request([IP], budget=0)[1]["cached"] == 1)
        assert service.request(["1.1.1.1"])[1]["pending"] == 1
    finally:
        service.close()
