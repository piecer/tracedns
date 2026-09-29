"""Real-main startup ownership and deterministic start/stop interleavings."""
import json
import sys
import threading

import pytest

import dns_monitor
from monitor import delivery_runtime
from security.store import SecurityStore
from test_delivery_adapters_steps import Transport


@pytest.fixture
def main_owners(tmp_path, monkeypatch):
    security = SecurityStore(tmp_path / 'auth' / 'auth.sqlite', create=True)
    security.bootstrap('root', 'test-password-123')
    config = tmp_path / 'config.json'
    config.write_text(json.dumps({'domains': [], 'servers': [], 'alerts': {}}))
    owners = {}
    runtime_type = delivery_runtime.DeliveryRuntime
    server_type = dns_monitor.ThreadingHTTPServer

    def runtime(*args, **kw):
        owners['runtime'] = runtime_type(*args, **kw, transport=Transport())
        return owners['runtime']

    def server(*args, **kw):
        owners['server'] = server_type(*args, **kw)
        return owners['server']

    monkeypatch.setattr(delivery_runtime, 'DeliveryRuntime', runtime)
    monkeypatch.setattr(dns_monitor, 'ThreadingHTTPServer', server)
    monkeypatch.setattr(sys, 'argv', ['dns_monitor.py', '--config', str(config), '--security-db',
        str(tmp_path / 'auth' / 'auth.sqlite'), '--insecure-http', '--http-port', '0'])
    yield owners
    if 'runtime' in owners:
        owner = owners['runtime']
        thread = owner.worker._thread
        if thread is not None and thread.ident is None:
            owner.worker._thread = None  # seed-RED fixture cleanup only
        delivery_runtime_stop = runtime_type.stop
        delivery_runtime_stop(owner)
    if 'server' in owners:
        owners['server'].server_close()


def test_actual_main_thread_start_failure_preserves_error_and_closes(main_owners, monkeypatch):
    original = threading.Thread.start
    error = RuntimeError('synthetic thread resource exhaustion')

    def start(thread):
        if thread.name == 'delivery-worker':
            raise error
        return original(thread)

    monkeypatch.setattr(threading.Thread, 'start', start)
    with pytest.raises(RuntimeError) as failure:
        dns_monitor.main()
    owner = main_owners['runtime']
    assert failure.value is error
    assert owner.store._closed
    assert main_owners['server'].socket.fileno() == -1
    assert not owner.store.health_snapshot()['worker_running']
    assert owner.worker._thread is None


@pytest.mark.parametrize('primary', [True, False])
def test_actual_main_secondary_stop_error_continues_cleanup(main_owners, monkeypatch, primary):
    import security.startup
    stopped = threading.Event()
    closed = []
    original_error = RuntimeError('original scan failure')
    secondary = RuntimeError('secondary stop failure')
    monkeypatch.setattr(security.startup, 'start_housekeeping', lambda _: stopped)
    bridge_type = dns_monitor.SignalStopBridge

    class Bridge(bridge_type):
        def close(self, timeout=1.0):
            result = super().close(timeout=timeout)
            closed.append(result)
            return result

    monkeypatch.setattr(dns_monitor, 'SignalStopBridge', Bridge)

    def next_scan(_):
        def failed_stop(**kw):
            raise secondary
        main_owners['runtime'].stop = failed_stop
        if primary:
            raise original_error
        return None

    monkeypatch.setattr(dns_monitor.MonitorScheduler, 'next_scan', next_scan)
    with pytest.raises(RuntimeError) as failure:
        dns_monitor.main()
    assert failure.value is (original_error if primary else secondary)
    assert stopped.is_set()
    assert closed == [True]
    assert main_owners['server'].socket.fileno() == -1
    # A failed stop is NOT evidence that the owner is safe to close.
    assert not main_owners['runtime'].store._closed


@pytest.mark.parametrize('fail_start', [False, True])
def test_actual_main_stop_during_thread_start_never_closes_early(main_owners, monkeypatch, fail_start):
    original = threading.Thread.start
    entered, release = threading.Event(), threading.Event()
    results, errors = [], []
    error = RuntimeError('start fault after barrier')

    def start(thread):
        if thread.name == 'delivery-worker':
            entered.set()
            assert release.wait(5)
            if fail_start:
                raise error
        return original(thread)

    def stopper():
        try:
            assert entered.wait(5)
            owner = main_owners['runtime']
            results.append(owner.stop(join_seconds=.03))
            assert not owner.store._closed
            assert not owner.store.health_snapshot()['worker_running']
        except BaseException as exc:
            errors.append(exc)
        finally:
            release.set()

    monkeypatch.setattr(threading.Thread, 'start', start)
    monkeypatch.setattr(dns_monitor.MonitorScheduler, 'next_scan', lambda _: None)
    controller = threading.Thread(target=stopper)
    controller.start()
    try:
        if fail_start:
            with pytest.raises(RuntimeError) as failure:
                dns_monitor.main()
            assert failure.value is error
        else:
            dns_monitor.main()
    finally:
        release.set()
        controller.join(5)
    assert not controller.is_alive()
    assert not errors
    assert results[0]['stopped'] is False
    assert results[0]['closed'] is False
    assert main_owners['runtime'].store._closed
    assert main_owners['server'].socket.fileno() == -1


def test_actual_main_sync_pass_before_idle_publication_fences_close(main_owners, monkeypatch):
    from monitor.delivery_worker import DeliveryWorker
    entered, release = threading.Event(), threading.Event()
    pass_results = []

    def start(worker):
        owner = main_owners['runtime']
        enter = owner.store.worker_enter

        def paused_enter():
            entered.set()
            assert release.wait(5)
            return enter()

        monkeypatch.setattr(owner.store, 'worker_enter', paused_enter)
        thread = threading.Thread(target=lambda: pass_results.append(worker.run_pass()))
        thread.start()
        try:
            assert entered.wait(5)
            # _idle is still set: only the shared gate proves pending admission.
            assert worker._idle.is_set()
            result = owner.stop(join_seconds=.02)
            assert result['stopped'] is False and result['closed'] is False
            assert not owner.store._closed
        finally:
            release.set()
            thread.join(5)
        assert not thread.is_alive()
        return False

    monkeypatch.setattr(DeliveryWorker, 'start', start)
    monkeypatch.setattr(dns_monitor.MonitorScheduler, 'next_scan', lambda _: None)
    dns_monitor.main()
    assert pass_results == [{'provider_calls': 0, 'steps': 0, 'stopped': True}]
    assert main_owners['runtime'].store._closed
    assert main_owners['server'].socket.fileno() == -1
