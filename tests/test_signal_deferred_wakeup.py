"""Real main wiring must wake an already-waiting scheduler after contention."""
from contextlib import ExitStack
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from unittest.mock import Mock, patch

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _main_child(mode, scratch):
    sys.path.insert(0, str(ROOT))
    import dns_monitor
    from monitor.scheduler import MonitorScheduler

    waiting = threading.Event()
    wait_returned = threading.Event()
    stop_returned = threading.Event()
    scan_returned = threading.Event()
    audit_release = threading.Event()
    captured, results, errors = {}, [], []
    real_stop = MonitorScheduler.stop
    real_next = MonitorScheduler.next_scan
    previous = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}

    def observed_stop(scheduler):
        result = real_stop(scheduler)
        if threading.current_thread() is captured['config']['_signal_stop']._thread:
            results.append(result)
            print(f'COORDINATOR_STOP_RETURNED={result}', flush=True)
            stop_returned.set()
        return result

    def observed_next(scheduler, **kwargs):
        result = real_next(scheduler, **kwargs)
        if result is None:
            scan_returned.set()
        return result

    def handler(shared, lock, *args, **kwargs):
        captured.update(config=shared, lock=lock, repo=kwargs['state_repository'])
        condition = shared['_monitor_condition']
        real_wait = condition.wait

        def observed_wait(timeout):
            waiting.set()
            result = real_wait(timeout)
            wait_returned.set()
            return result

        condition.wait = observed_wait
        return Mock()

    def saturate_audit():
        from security.jobs import finish_force

        lookup = captured['repo'].lookup_runtime
        entered = threading.Event()
        audit = Mock()

        def blocked(*args, **kwargs):
            entered.set()
            assert audit_release.wait(5), 'audit fixture was not released'

        audit.audit.side_effect = blocked
        jobs = [{'actor': {'id': 1}, '_security_store': audit, 'job_id': str(i),
                 'request_id': str(i), 'source_ip': 'fixture', 'domains': [],
                 '_target_leases': {}} for i in range(lookup.audit.CAPACITY + 1)]
        captured.update(jobs=jobs, audit=audit)
        captured['config']['_force_resolve_queue'] = list(jobs)
        for job in jobs[:-1]:
            assert lookup.scheduler.active_force().force_req is job
            finish_force(job, 'failure')
        assert entered.wait(2)
        assert lookup.audit.status()['pending'] == lookup.audit.CAPACITY
        assert captured['config']['_force_resolve_queue'] == [jobs[-1]]
        print('AUDIT_SATURATED_WITH_ORIGINAL_QUEUE_BACKLOG', flush=True)

    def control():
        held = False
        try:
            assert waiting.wait(2), 'main never reached the scheduler condition wait'
            lock = captured['lock']
            assert lock.acquire(timeout=2), 'main never released the condition lock'
            held = True
            # Entered Condition.wait AND acquired its released lock in another
            # thread: a pre-wait signal cannot accidentally cover this schedule.
            assert not wait_returned.is_set()
            assert not scan_returned.is_set()
            print('SCHEDULER_WAIT_RELEASED_CONFIG_LOCK', flush=True)
            if mode == 'audit-saturated':
                saturate_audit()
            if mode != 'contended':
                lock.release()
                held = False
            os.kill(os.getpid(), signal.SIGTERM)
            assert stop_returned.wait(2), 'stop blocked on a contending config reader'
            assert results == [mode == 'uncontended']
            assert captured['config']['_monitor_stopped']
            assert captured['repo'].lookup_runtime.stopping
            assert captured['repo'].lookup_runtime.audit.stopping
            if held:
                assert not wait_returned.is_set()
                lock.release()
                held = False
            print('CONFIG_READER_RELEASED_WITHOUT_NOTIFY', flush=True)
            assert scan_returned.wait(1), 'missing deferred scheduler wake after lock release'
            print('SCHEDULER_WOKE_WITHOUT_RESCUE', flush=True)
            if mode == 'audit-saturated':
                bridge = captured['config']['_signal_stop']
                bridge._thread.join(.5)
                assert not bridge._thread.is_alive(), 'coordinator waited for pending audit completion'
                assert not audit_release.is_set()
                assert captured['repo'].lookup_runtime.audit.status()['pending'] > 0
                assert captured['config']['_force_resolve_queue'] == [captured['jobs'][-1]]
                print('COORDINATOR_EXITED_BEFORE_AUDIT_RELEASE', flush=True)
        except BaseException as error:
            errors.append(str(error))
            print(f'CONTROL_FAILURE: {error}', flush=True)
        finally:
            if held:
                captured['lock'].release()
            audit_release.set()
            # No rescue notification: the parent kills a failed/hung child.

    controller = threading.Thread(target=control, name='contending-config-reader', daemon=True)
    with ExitStack() as stack:
        stack.enter_context(patch('sys.argv', ['dns_monitor.py', '--config', str(scratch / 'config')]))
        stack.enter_context(patch('security.startup.open_security', return_value=Mock()))
        stack.enter_context(patch('security.startup.start_housekeeping', return_value=threading.Event()))
        stack.enter_context(patch('dns_monitor.read_config', return_value={
            'domains': [], 'servers': [], 'interval': 3600}))
        stack.enter_context(patch('dns_monitor.alerts_init', return_value=False))
        stack.enter_context(patch('dns_monitor.make_handler', side_effect=handler))
        stack.enter_context(patch('dns_monitor.ThreadingHTTPServer', return_value=Mock()))
        stack.enter_context(patch.object(MonitorScheduler, 'stop', observed_stop))
        stack.enter_context(patch.object(MonitorScheduler, 'next_scan', observed_next))
        controller.start()
        dns_monitor.main()
    controller.join(2)
    assert not controller.is_alive()
    assert not errors, errors
    assert scan_returned.is_set()
    bridge = captured['config']['_signal_stop']
    assert bridge.requested and not bridge._thread.is_alive()
    assert bridge.close(timeout=0)
    assert bridge._closed
    for fd in (bridge._read, bridge._write):
        with pytest.raises(OSError):
            os.fstat(fd)
    assert all(signal.getsignal(s) == handler for s, handler in previous.items())
    assert captured['repo'].lookup_runtime.status()['stopped']
    assert captured['repo'].delivery_runtime.store._closed
    if mode == 'audit-saturated':
        jobs = captured['jobs']
        calls = captured['audit'].audit.call_args_list
        assert len(calls) == len(jobs)
        assert {call.kwargs['job_id'] for call in calls} == {job['job_id'] for job in jobs}
        assert all(job.get('_terminal_audit_done') for job in jobs)
        assert all(job['_terminal_outcome'] == 'failure' for job in jobs)
    print('MAIN_CLEANUP_COMPLETE', flush=True)


def _run_child(tmp_path, mode):
    process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), mode, str(tmp_path)],
                               cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        try:
            out, err = process.communicate(timeout=6)
        except subprocess.TimeoutExpired:
            process.kill()
            out, err = process.communicate(timeout=2)
            pytest.fail(f'{mode}: no bounded signal shutdown; stdout={out}; stderr={err}')
        assert process.returncode == 0, (out, err)
        return out
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=2)


@pytest.mark.parametrize('mode', ['contended', 'uncontended', 'audit-saturated'])
def test_main_signal_wakes_after_config_reader_releases(tmp_path, mode):
    out = _run_child(tmp_path, mode)
    assert 'SCHEDULER_WAIT_RELEASED_CONFIG_LOCK' in out
    assert 'SCHEDULER_WOKE_WITHOUT_RESCUE' in out
    assert 'MAIN_CLEANUP_COMPLETE' in out
    if mode == 'audit-saturated':
        assert 'COORDINATOR_EXITED_BEFORE_AUDIT_RELEASE' in out


def _close_child(scratch):
    sys.path.insert(0, str(ROOT))
    from monitor.lookup_runtime import LookupRuntime
    from monitor.repository import MonitorStateRepository
    from monitor.scheduler import MonitorScheduler
    from monitor.signal_stop import SignalStopBridge
    from monitor.stores import ConfigStore

    lock = threading.RLock()
    repo = MonitorStateRepository({}, {}, str(scratch))
    store = ConfigStore({'domains': [], 'servers': []}, lock, state_repository=repo)
    scheduler = MonitorScheduler(store)
    lookup = LookupRuntime(repo, scheduler=scheduler)
    held, release, attempted = threading.Event(), threading.Event(), threading.Event()
    results = []
    real_stop = scheduler.stop
    previous = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}

    def stop():
        result = real_stop()
        results.append(result)
        attempted.set()
        return result

    def reader():
        with lock:
            held.set()
            release.wait(5)

    holder = threading.Thread(target=reader, daemon=True)
    bridge = SignalStopBridge(scheduler.stop_and_wake)
    try:
        with patch.object(scheduler, 'stop', stop):
            bridge.start()
            holder.start()
            assert held.wait(1)
            os.kill(os.getpid(), signal.SIGTERM)
            assert attempted.wait(1), 'ordinary stop waited for the config reader'
            assert results == [False]
            assert store.stop_requested and lookup.stopping and lookup.audit.stopping
            begin = time.monotonic()
            assert bridge.close(timeout=.01) is False
            assert time.monotonic() - begin < .5
            assert bridge._thread.is_alive() and not bridge._closed
            assert not release.is_set()
            assert all(signal.getsignal(s) == handler for s, handler in previous.items())
            for fd in (bridge._read, bridge._write):
                os.fstat(fd)
            release.set()
            holder.join(1)
            assert bridge.close(timeout=1)
            assert bridge.close(timeout=0)
            assert not bridge._thread.is_alive() and not holder.is_alive()
            for fd in (bridge._read, bridge._write):
                with pytest.raises(OSError):
                    os.fstat(fd)
            assert results == [False], 'coordinator retried audit retirement'
    finally:
        release.set()
        if holder.ident is not None:
            holder.join(1)
        bridge.close(timeout=1)
        scheduler.stop()
        assert lookup.stop(join_seconds=1)['stopped']
    print('BOUNDED_CLOSE_THEN_DEFERRED_WAKE_CLEANUP_COMPLETE', flush=True)


def test_signal_bridge_close_is_bounded_during_deferred_wake(tmp_path):
    out = _run_child(tmp_path, 'bounded-close')
    assert 'BOUNDED_CLOSE_THEN_DEFERRED_WAKE_CLEANUP_COMPLETE' in out


if __name__ == '__main__':
    if sys.argv[1] == 'bounded-close':
        _close_child(Path(sys.argv[2]))
    else:
        _main_child(sys.argv[1], Path(sys.argv[2]))
