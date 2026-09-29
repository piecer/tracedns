"""Real-signal regressions: asynchronous handlers never acquire app locks."""
from contextlib import ExitStack
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _signal_child(mode, scratch):
    sys.path.insert(0, str(ROOT))
    import dns_monitor
    import monitor.engine as engine
    from models import QueryResult, Snapshot
    from monitor.collect import Collected
    from monitor.runtime_state import state_lock
    captured = {}
    cfg_locked = threading.Event()
    signalled = False
    snapshot = engine._snapshot_dict
    real_thread = threading.Thread
    audit = Mock()
    pending = [{'actor': {'id': n}, '_security_store': audit, 'job_id': f'pending-{n}',
                'request_id': f'request-{n}', 'source_ip': 'fixture', 'domains': []}
               for n in range(2)]

    def handler(shared, lock, *args, **kwargs):
        captured.update(config=shared, lock=lock, repo=kwargs['state_repository'])
        if mode == 'lost-wake':
            condition = shared['_monitor_condition']
            wait = condition.wait

            def before_wait(timeout):
                nonlocal signalled
                if not signalled:
                    signalled = True
                    shared['_force_resolve_queue'] = list(pending)
                    print('SIGNAL_BEFORE_WAIT', flush=True)
                    os.kill(os.getpid(), signal.SIGTERM)
                return wait(timeout)

            condition.wait = before_wait
        else:
            shared['_force_resolve_queue'] = list(pending)
        return Mock()

    def writer():
        with captured['lock']:
            cfg_locked.set()
            captured['repo'].configure(captured['config'])

    def during_snapshot(value):
        nonlocal signalled
        if mode == 'lock-inversion' and not signalled:
            signalled = True
            assert getattr(state_lock(), '_is_owned')()
            real_thread(target=writer, daemon=True).start()
            assert cfg_locked.wait(2)
            print('SIGNAL_WHILE_STATE_OWNED', flush=True)
            os.kill(os.getpid(), signal.SIGTERM)
        return snapshot(value)

    def collect(domain, server):
        return Collected(QueryResult(server, domain.name, 'A', 'ok', ['192.0.2.5']),
                         Snapshot(type='A', values=['192.0.2.5'], ts=1))

    with ExitStack() as stack:
        stack.enter_context(patch('sys.argv', ['dns_monitor.py', '--config', str(scratch / 'config')]))
        stack.enter_context(patch('security.startup.open_security', return_value=Mock()))
        stack.enter_context(patch('security.startup.start_housekeeping', return_value=threading.Event()))
        stack.enter_context(patch('dns_monitor.read_config', return_value={
            'domains': ['a.example'], 'servers': ['fixture'], 'interval': 86400}))
        stack.enter_context(patch('dns_monitor.alerts_init', return_value=False))
        stack.enter_context(patch('dns_monitor.make_handler', side_effect=handler))
        stack.enter_context(patch('dns_monitor.ThreadingHTTPServer', return_value=Mock()))
        stack.enter_context(patch('dns_monitor.threading', SimpleNamespace(
            RLock=threading.RLock, Thread=lambda *args, **kwargs: Mock())))
        stack.enter_context(patch('monitor.engine.collect_snapshot', side_effect=collect))
        stack.enter_context(patch('monitor.engine._snapshot_dict', side_effect=during_snapshot))
        stack.enter_context(patch('monitor.engine.alert_new_ips'))
        dns_monitor.main()
    assert signalled
    calls = audit.audit.call_args_list
    assert len(calls) == 2
    assert {call.args[0]['id'] for call in calls} == {0, 1}
    assert all(call.kwargs['outcome'] == 'failure' for call in calls)
    assert captured['config']['_monitor_stopped']
    assert not captured['config'].get('_force_resolve_queue')
    print('NORMAL_EXIT_PENDING_AUDITED_ONCE', flush=True)


@pytest.mark.parametrize('mode', ['lock-inversion', 'lost-wake'])
def test_real_signal_shutdown_cannot_invert_locks_or_lose_wakeup(tmp_path, mode):
    process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), mode, str(tmp_path)],
                               cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        out, err = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        out, err = process.communicate()
        pytest.fail(f'{mode}: signal stop did not exit within 5 seconds; stdout={out}; stderr={err}')
    assert process.returncode == 0, (out, err)
    assert 'NORMAL_EXIT_PENDING_AUDITED_ONCE' in out


if __name__ == '__main__':
    _signal_child(sys.argv[1], Path(sys.argv[2]))
