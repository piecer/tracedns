"""DNS wire fixture admission must own both transports before serving."""
import contextlib
import errno
import socket
import threading

import pytest

import test_pr2_dns_wire_integration as dns_wire
from dns_query import query_dns


@pytest.mark.parametrize('repeat_blocked_port', [False, True], ids=['single-collision', 'repeated-collision'])
@pytest.mark.parametrize(('mode', 'rtype', 'expected', 'transports'), [
    ('txt', 'TXT', ['hello world'], ['udp']),
    ('truncated', 'A', ['192.0.2.42'], ['udp', 'tcp']),
])
def test_dns_fixture_recovers_real_tcp_port_collision(
        monkeypatch, mode, rtype, expected, transports, repeat_blocked_port):
    original_socket = socket.socket
    created = []
    collided = []
    repeated = []
    with contextlib.ExitStack() as cleanup:
        class CollisionSocket(original_socket):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                created.append(self)
                cleanup.callback(self.close)

            def bind(self, address):
                if self.type == socket.SOCK_DGRAM and repeat_blocked_port and collided and not repeated:
                    # A later UDP allocation may select the still-TCP-blocked port.
                    result = super().bind(collided[0].getsockname())
                    repeated.append(self.getsockname())
                    return result
                if self.type == socket.SOCK_STREAM and not collided:
                    blocker = cleanup.enter_context(original_socket(socket.AF_INET, socket.SOCK_STREAM))
                    blocker.bind(address)
                    blocker.listen(1)
                    collided.append(blocker)
                return super().bind(address)

        # Only fixture allocation is intercepted; DNS uses unmodified real sockets.
        with monkeypatch.context() as allocation_patch:
            allocation_patch.setattr(socket, 'socket', CollisionSocket)
            with dns_wire._dns_fixture(monkeypatch, mode) as seen:
                allocation_patch.undo()
                assert len(collided) == 1
                assert collided[0].fileno() >= 0
                assert repeated == ([collided[0].getsockname()] if repeat_blocked_port else [])
                assert (6 if repeat_blocked_port else 4) <= len(created) <= 32
                assert all(sock.fileno() == -1 for sock in created[:-2])
                assert created[-2].getsockname() == created[-1].getsockname()
                assert created[-2].getsockname() != collided[0].getsockname()
                result = query_dns('127.0.0.1', 'fixture.test', rtype, timeout=0.2, with_meta=True)
                assert result == {'values': expected, 'status': 'ok'}
                assert seen == transports
        assert all(sock.fileno() == -1 for sock in created)
        assert collided[0].fileno() >= 0  # The fixture must not close another owner.


@pytest.fixture
def socket_tracker(monkeypatch):
    original_socket = socket.socket
    created = []

    class TrackedSocket(original_socket):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            created.append(self)

    monkeypatch.setattr(socket, 'socket', TrackedSocket)
    try:
        yield TrackedSocket, created
    finally:
        # Preserve cleanup even when testing a broken predecessor.
        for sock in created:
            sock.close()


def test_dns_fixture_bounds_collision_retries(monkeypatch, socket_tracker):
    socket_class, created = socket_tracker
    original_bind = socket_class.bind
    failures = []

    def always_busy(sock, address):
        if sock.type == socket.SOCK_STREAM:
            assert len(failures) < 16, 'fixture retried beyond its allocation budget'
            error = OSError(errno.EADDRINUSE, 'occupied TCP candidate')
            failures.append(error)
            raise error
        return original_bind(sock, address)

    monkeypatch.setattr(socket_class, 'bind', always_busy)
    with pytest.raises(OSError) as caught:
        with dns_wire._dns_fixture(monkeypatch, 'a'):
            pytest.fail('an unbound fixture must never serve requests')
    assert len(failures) == 16
    assert caught.value is failures[-1]
    assert len(created) == 32
    assert all(sock.fileno() == -1 for sock in created)


@pytest.mark.parametrize('stage', ['udp-bind', 'tcp-create', 'tcp-bind', 'listen', 'timeout'])
def test_dns_fixture_does_not_retry_other_setup_errors(monkeypatch, socket_tracker, stage):
    socket_class, created = socket_tracker
    error = OSError(errno.EACCES, 'fixture setup denied')
    calls = []
    original_init = socket_class.__init__
    original_bind = socket_class.bind

    def fail():
        calls.append(stage)
        raise error

    def create(sock, family, kind):
        if stage == 'tcp-create' and kind == socket.SOCK_STREAM:
            fail()
        original_init(sock, family, kind)

    def bind(sock, address):
        if (stage == 'udp-bind' and sock.type == socket.SOCK_DGRAM or
                stage == 'tcp-bind' and sock.type == socket.SOCK_STREAM):
            fail()
        original_bind(sock, address)

    monkeypatch.setattr(socket_class, '__init__', create)
    monkeypatch.setattr(socket_class, 'bind', bind)
    if stage == 'listen':
        monkeypatch.setattr(socket_class, 'listen', lambda *args: fail())
    if stage == 'timeout':
        monkeypatch.setattr(socket_class, 'settimeout', lambda *args: fail())
    with pytest.raises(OSError) as caught:
        with dns_wire._dns_fixture(monkeypatch, 'a'):
            pytest.fail('incomplete fixture setup must not be accepted')
    assert caught.value is error
    assert calls == [stage]
    assert len(created) == (1 if stage in ('udp-bind', 'tcp-create') else 2)
    assert all(sock.fileno() == -1 for sock in created)


@pytest.mark.parametrize('fail_at', [0, 1])
def test_dns_fixture_cleans_up_partial_thread_start(monkeypatch, socket_tracker, fail_at):
    _, created = socket_tracker
    original_start = threading.Thread.start
    threads = []
    error = RuntimeError('fixture thread start failed')

    def start(thread):
        threads.append(thread)
        if len(threads) == fail_at + 1:
            raise error
        original_start(thread)

    monkeypatch.setattr(threading.Thread, 'start', start)
    with pytest.raises(RuntimeError) as caught:
        with dns_wire._dns_fixture(monkeypatch, 'a'):
            pytest.fail('partially started fixture must not be accepted')
    assert caught.value is error
    assert len(threads) == fail_at + 1
    assert all(not thread.is_alive() for thread in threads)
    assert len(created) == 2
    assert all(sock.fileno() == -1 for sock in created)


@pytest.mark.parametrize('error', [AssertionError('body failed'), OSError(errno.EADDRINUSE, 'body failed')])
def test_dns_fixture_never_retries_test_body(monkeypatch, socket_tracker, error):
    _, created = socket_tracker
    entered = []
    with pytest.raises(type(error)) as caught:
        with dns_wire._dns_fixture(monkeypatch, 'a'):
            entered.append(True)
            raise error
    assert caught.value is error
    assert entered == [True]
    assert len(created) == 2
    assert all(sock.fileno() == -1 for sock in created)
