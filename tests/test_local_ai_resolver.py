"""One physical DNS slot: injected blocking libc boundary, no external DNS."""

import importlib
import socket
import threading
import time
from pathlib import Path

import pytest

from local_ai.provider import ProviderError


def resolver_module():
    try:
        module = importlib.import_module("local_ai.resolver")
    except ModuleNotFoundError:
        pytest.fail("retained resolver owner is missing")
    assert Path(module.__file__).resolve() == Path(__file__).resolve().parents[1] / "local_ai/resolver.py"
    return module


def answer(ip="8.8.8.8", port=443):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sockaddr = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)


def test_expired_caller_keeps_one_real_worker_and_close_is_truthful():
    module = resolver_module()
    entered, release = threading.Event(), threading.Event()
    calls, workers = [], []

    def lookup(host, port):
        calls.append((host, port))
        workers.append(threading.current_thread())
        entered.set()
        assert release.wait(3)
        return [answer()]

    owner = module.ResolverOwner(lookup=lookup)
    assert not owner.busy() and owner.retained_workers() == 0 and calls == []
    try:
        start = time.monotonic()
        with pytest.raises(ProviderError) as caught:
            owner.resolve("example.invalid", 443, start + 0.08)
        assert caught.value.code == "deadline_exceeded" and not caught.value.sent
        assert entered.is_set() and time.monotonic() - start < 0.5
        assert owner.busy() and owner.retained_workers() == 1
        for _ in range(12):
            with pytest.raises(ProviderError) as caught:
                owner.resolve("other.invalid", 443, time.monotonic() + 1)
            assert caught.value.code == "provider_failed" and not caught.value.sent
        assert calls == [("example.invalid", 443)] and len(workers) == 1
        assert not owner.close(time.monotonic() + 0.02)
        assert owner.retained_workers() == 1
    finally:
        release.set()
        for thread in workers:
            thread.join(2)
            assert not thread.is_alive()
        assert owner.close(time.monotonic() + 1)
    assert not owner.busy() and owner.retained_workers() == 0
    with pytest.raises(ProviderError):
        owner.resolve("example.invalid", 443, time.monotonic() + 1)
    assert len(calls) == 1, "close is a permanent stop latch, not a generation reset"


def test_vetted_snapshot_detaches_and_default_lookup_has_fixed_tcp_flags(monkeypatch):
    module = resolver_module()
    rows = [answer(), answer("2606:4700:4700::1111")]
    calls = []

    def lookup(host, port, **kwargs):
        calls.append((host, port, kwargs))
        return rows

    monkeypatch.setattr(socket, "getaddrinfo", lookup)
    owner = module.ResolverOwner()
    assert calls == []
    try:
        snapshot = owner.resolve("example.invalid", 443, time.monotonic() + 1)
        assert type(snapshot) is tuple and snapshot == tuple(rows)
        rows.clear()
        assert len(snapshot) == 2
        assert calls == [("example.invalid", 443, {"type": socket.SOCK_STREAM, "proto": socket.IPPROTO_TCP})]
        assert not owner.busy() and owner.retained_workers() == 0
    finally:
        assert owner.close(time.monotonic() + 1)


@pytest.mark.parametrize(
    "rows",
    [
        [],
        [answer()] * 9,
        [answer(), answer("127.0.0.1")],
        [answer("10.1.2.3")],
        [answer("169.254.1.2")],
        [answer("224.0.0.1")],
        [answer("0.0.0.0")],
        [answer("::1")],
        [answer("::ffff:8.8.8.8")],
        [answer("2002:0808:0808::")],
        [answer("64:ff9b::808:808")],
        [answer("fe80::1")],
        [answer("fc00::1")],
        [answer(port=80)],
        [answer("bad")],
        [(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))],
        [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("2606:4700:4700::1111", 443, 0, 1))],
        [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", True))],
        [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443, 0, 0))],
        [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 443))],
    ],
)
def test_every_answer_is_vetted_before_publication(rows):
    owner = resolver_module().ResolverOwner(lookup=lambda host, port: rows)
    try:
        with pytest.raises(ProviderError) as caught:
            owner.resolve("example.invalid", 443, time.monotonic() + 1)
        assert caught.value.code == "provider_failed" and not caught.value.sent
    finally:
        assert owner.close(time.monotonic() + 1)


def test_eight_answers_accepted_but_lazy_or_custom_snapshots_never_iterated():
    module = resolver_module()
    calls = []

    def lazy():
        calls.append(True)
        yield answer()

    owner = module.ResolverOwner(lookup=lambda host, port: [answer()] * 8)
    try:
        assert len(owner.resolve("example.invalid", 443, time.monotonic() + 1)) == 8
    finally:
        assert owner.close(time.monotonic() + 1)
    owner = module.ResolverOwner(lookup=lambda host, port: lazy())
    try:
        with pytest.raises(ProviderError):
            owner.resolve("example.invalid", 443, time.monotonic() + 1)
        assert calls == []
    finally:
        assert owner.close(time.monotonic() + 1)


@pytest.mark.parametrize(
    "host,port",
    [
        (None, 443),
        ("x" * 254, 443),
        ("bad host", 443),
        ("example.invalid", True),
        ("example.invalid", 0),
        ("example.invalid", 65536),
        ("example.invalid", "443"),
    ],
)
def test_lookup_inputs_bounded_before_thread_creation(host, port):
    calls = []
    owner = resolver_module().ResolverOwner(lookup=lambda *args: calls.append(args) or [answer()])
    try:
        with pytest.raises(ProviderError) as caught:
            owner.resolve(host, port, time.monotonic() + 1)
        assert caught.value.code == "invalid_request" and not caught.value.sent
        assert calls == [] and owner.retained_workers() == 0
    finally:
        assert owner.close(time.monotonic() + 1)


def test_slot_recovers_only_after_worker_return_and_discards_late_result():
    release = threading.Event()
    workers, calls = [], []

    def lookup(host, port):
        workers.append(threading.current_thread())
        calls.append(host)
        if len(calls) == 1:
            assert release.wait(3)
            return [answer("1.1.1.1")]
        return [answer()]

    owner = resolver_module().ResolverOwner(lookup=lookup)
    try:
        with pytest.raises(ProviderError):
            owner.resolve("first.invalid", 443, time.monotonic() + 0.03)
        assert owner.retained_workers() == 1
        release.set()
        workers[0].join(1)
        assert not workers[0].is_alive()
        assert owner.resolve("second.invalid", 443, time.monotonic() + 1) == (answer(),)
        assert calls == ["first.invalid", "second.invalid"]
    finally:
        release.set()
        assert owner.close(time.monotonic() + 1)


def test_concurrent_callers_never_queue_or_spawn_replacements():
    release, entered = threading.Event(), threading.Event()
    barrier = threading.Barrier(12)
    calls, outcomes, workers = [], [], []

    def lookup(host, port):
        calls.append((host, port))
        workers.append(threading.current_thread())
        entered.set()
        assert release.wait(3)
        return [answer()]

    owner = resolver_module().ResolverOwner(lookup=lookup)

    def caller():
        barrier.wait(2)
        try:
            owner.resolve("example.invalid", 443, time.monotonic() + 0.1)
        except ProviderError as error:
            outcomes.append(error.code)

    callers = [threading.Thread(target=caller) for _ in range(12)]
    try:
        for thread in callers:
            thread.start()
        assert entered.wait(1)
        for thread in callers:
            thread.join(1)
            assert not thread.is_alive()
        assert sorted(outcomes) == ["deadline_exceeded"] + ["provider_failed"] * 11
        assert len(calls) == 1 and owner.retained_workers() == 1
    finally:
        release.set()
        for thread in callers + workers:
            thread.join(2)
            assert not thread.is_alive()
        assert owner.close(time.monotonic() + 1)


def test_lookup_exception_is_sanitized_and_slot_is_reusable(capsys, caplog):
    calls = []

    def lookup(host, port):
        calls.append(True)
        if len(calls) == 1:
            raise OSError("SYNTHETIC-RESOLVER-SECRET")
        return [answer()]

    owner = resolver_module().ResolverOwner(lookup=lookup)
    try:
        with pytest.raises(ProviderError) as caught:
            owner.resolve("example.invalid", 443, time.monotonic() + 1)
        assert str(caught.value) == "provider_failed" and not caught.value.sent
        assert not owner.busy()
        assert owner.resolve("example.invalid", 443, time.monotonic() + 1) == (answer(),)
    finally:
        assert owner.close(time.monotonic() + 1)
    capture = capsys.readouterr()
    assert "SYNTHETIC-RESOLVER-SECRET" not in capture.out + capture.err + caplog.text


def test_failed_thread_start_does_not_leave_a_phantom_slot(monkeypatch):
    owner = resolver_module().ResolverOwner(lookup=lambda host, port: [answer()])

    def fail_start(thread):
        raise RuntimeError("SYNTHETIC-START-SECRET")

    with monkeypatch.context() as patcher:
        patcher.setattr(threading.Thread, "start", fail_start)
        with pytest.raises(ProviderError) as caught:
            owner.resolve("example.invalid", 443, time.monotonic() + 1)
        assert str(caught.value) == "provider_failed" and owner.retained_workers() == 0
    try:
        assert owner.resolve("example.invalid", 443, time.monotonic() + 1) == (answer(),)
    finally:
        assert owner.close(time.monotonic() + 1)
