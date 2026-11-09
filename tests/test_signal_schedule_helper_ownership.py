"""Application-free real-child controls for the signal supervisor's ownership."""
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time

import pytest

import signal_retirement_schedule as helper


STUB = """import json, os, sys, time
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
    'pid': os.getpid(), 'sys_executable': sys.executable, 'argv': sys.argv,
    'application_modules': [n for n in sys.modules if n == 'dns_monitor'
        or n.split('.')[0] in ('monitor', 'security')]}))
print('STUB_READY', flush=True)
time.sleep(60)
"""


def write_receipt(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


@pytest.fixture
def real_child(monkeypatch, tmp_path):
    """Own rescue separately; observations must precede this finalizer."""
    real_popen = subprocess.Popen
    real_identity = helper.identity
    children = []
    receipt = {'children': []}
    failed = False

    def spawn(requested, **kwargs):
        nonlocal failed
        assert requested[0] == sys.executable
        assert Path(requested[1]).resolve() == Path(helper.__file__).resolve()
        assert kwargs['start_new_session'] is True
        assert kwargs['stdout'] == subprocess.PIPE
        assert kwargs['stderr'] == subprocess.PIPE
        stub_receipt = tmp_path / 'stub-origin.json'
        argv = [sys.executable, '-I', '-S', '-c', STUB, str(stub_receipt)]
        entry = {'actual_argv': argv, 'requested_argv': requested}
        process = real_popen(argv, cwd=tmp_path, env={}, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, start_new_session=True)
        # Cleanup authority and its entry do not depend on receipt publication.
        children.append((process, process.kill, process.wait, entry))
        try:
            receipt['children'].append(entry)
            assert select.select([process.stdout], [], [], 2)[0], 'stub readiness timeout'
            assert process.stdout.readline() == 'STUB_READY\n'
            origin = json.loads(stub_receipt.read_text())
            assert origin['application_modules'] == []
            assert origin['sys_executable'] == sys.executable
            assert origin['pid'] == process.pid
            entry.update(identity=real_identity(process.pid), origin=origin)
            return process
        except BaseException:
            failed = True
            raise

    monkeypatch.setattr(helper.subprocess, 'Popen', spawn)
    try:
        yield children, receipt, real_identity
    except BaseException:
        failed = True
        raise
    finally:
        errors = []
        for process, kill, wait, entry in children:
            # Baseline leaks are contained, but never credited to the helper.
            try:
                entry['before_fixture_rescue'] = real_identity(process.pid)
                entry['returncode_before_rescue'] = process.returncode
                entry['pipes_closed_before_rescue'] = [process.stdout.closed, process.stderr.closed]
            except BaseException as error:
                errors.append(error)
            try:
                if process.poll() is None:
                    kill()
            except BaseException as error:
                errors.append(error)
            try:
                wait(timeout=2)
            except BaseException as error:
                errors.append(error)
            for stream in (process.stdout, process.stderr):
                try:
                    type(stream).close(stream)
                except BaseException as error:
                    errors.append(error)
            try:
                entry['after_fixture_rescue'] = real_identity(process.pid)
                assert entry['after_fixture_rescue'] is None
            except BaseException as error:
                errors.append(error)
        try:
            receipt['cleanup_errors'] = [type(error).__name__ for error in errors]
            write_receipt(tmp_path / 'process-release-control.json', receipt)
        except BaseException as error:
            errors.append(error)
        if errors and not failed:
            raise errors[0]


@pytest.mark.parametrize('fault', [
    'identity', 'identity_none', 'identity_session', 'launch_receipt',
    'launch_interrupt', 'wait_error', 'wait_interrupt', 'timeout_receipt',
    'cleanup_identity', 'cleanup_signal', 'cleanup_wait', 'cleanup_pipe',
])
def test_postspawn_failure_releases_real_child(monkeypatch, tmp_path, real_child, fault):
    children, receipt, real_identity = real_child
    primary = KeyboardInterrupt('primary') if fault.endswith('interrupt') else OSError('primary')
    fired = []
    waits = []
    real_save = helper.save
    real_spawn = helper.subprocess.Popen
    identity_calls = 0

    def observed_identity(pid):
        nonlocal identity_calls
        identity_calls += 1
        if fault == 'identity' or (fault == 'cleanup_identity' and identity_calls > 1):
            fired.append('identity')
            raise primary if fault == 'identity' else RuntimeError('secondary identity')
        if fault == 'identity_none' and identity_calls == 1:
            fired.append('identity_none')
            return None
        result = real_identity(pid)
        if fault == 'identity_session' and identity_calls == 1:
            fired.append('identity_session')
            return dict(result, sid=-1)
        return result

    def fail_save(name, value):
        if (name == 'launch.json' and (fault.startswith('launch_') or fault.startswith('cleanup_'))
                or name == 'timeout-cleanup.json' and fault == 'timeout_receipt'):
            fired.append(name)
            raise primary
        return real_save(name, value)

    def spawn(*args, **kwargs):
        process = real_spawn(*args, **kwargs)
        communicate = process.communicate
        wait = process.wait
        close = process.stdout.close
        wait_calls = 0

        def fail_communicate(*args, **kwargs):
            waits.append(kwargs['timeout'])
            if fault == 'timeout_receipt':
                fired.append('timeout')
                raise subprocess.TimeoutExpired(process.args, kwargs['timeout'])
            if fault in ('wait_error', 'wait_interrupt'):
                fired.append('wait')
                raise primary
            return communicate(*args, **kwargs)

        def fail_wait(*args, **kwargs):
            nonlocal wait_calls
            wait_calls += 1
            if fault == 'cleanup_wait' and wait_calls == 1:
                fired.append('secondary_wait')
                raise RuntimeError('secondary wait')
            return wait(*args, **kwargs)

        def fail_close():
            close()
            fired.append('secondary_pipe')
            raise RuntimeError('secondary pipe')

        monkeypatch.setattr(process, 'communicate', fail_communicate)
        monkeypatch.setattr(process, 'wait', fail_wait)
        if fault == 'cleanup_pipe':
            monkeypatch.setattr(process.stdout, 'close', fail_close)
        return process

    real_killpg = os.killpg

    def fail_signal(pgid, sig):
        assert pgid == children[0][0].pid
        assert sig == signal.SIGKILL
        if fault == 'cleanup_signal':
            fired.append('secondary_signal')
            raise RuntimeError('secondary signal')
        return real_killpg(pgid, sig)

    monkeypatch.setattr(helper, 'identity', observed_identity)
    monkeypatch.setattr(helper, 'save', fail_save)
    monkeypatch.setattr(helper.subprocess, 'Popen', spawn)
    monkeypatch.setattr(helper.os, 'killpg', fail_signal)
    started = time.monotonic()
    error = None
    try:
        helper.run_schedule(tmp_path / 'schedule')
    except BaseException as caught:
        error = caught
    elapsed = time.monotonic() - started
    process = children[0][0]
    # No poll/wait/rescue before the mechanism's reap/absence assertions.
    receipt.update(fault=fault, fired=fired, elapsed_seconds=elapsed,
                   primary_preserved=error is primary, wait_timeouts=waits,
                   helper_returncode=process.returncode,
                   helper_absence=real_identity(process.pid) is None,
                   helper_pipes_closed=[process.stdout.closed, process.stderr.closed])
    assert fired, 'failure injection did not fire'
    if fault in ('identity_none', 'identity_session'):
        assert isinstance(error, AssertionError)
    else:
        assert error is primary, 'primary exception object was replaced'
    assert process.returncode is not None, 'helper did not reap its real child'
    assert real_identity(process.pid) is None, 'child still exists before fixture rescue'
    assert process.stdout.closed and process.stderr.closed, 'helper left pipes open'
    assert elapsed < 3, 'exception cleanup exceeded separate two-second budget plus startup margin'
    assert not (tmp_path / 'schedule/classification.json').exists(), 'failed attempt classified'
    if fault in ('wait_error', 'wait_interrupt', 'timeout_receipt'):
        assert waits[0] == 5, 'application wait budget changed'
    if fault.startswith('cleanup_') and fault != 'cleanup_identity':
        assert 'secondary_' + fault.removeprefix('cleanup_') in fired


def test_child_metadata_omits_environment_values(monkeypatch, tmp_path):
    # Replace, rather than inspect, the caller environment: only fake data enters
    # the baseline receipt. Stop before even loading the original fixture module.
    sentinel = 'FAKE_SECRET_VALUE_helper_control_7e4f9'
    stop = RuntimeError('metadata boundary reached')
    reached = []
    out = tmp_path / 'metadata'
    out.mkdir()
    monkeypatch.setattr(helper, 'OUT', out)
    monkeypatch.setattr(helper.os, 'environ', {'SENSITIVE_FAKE_TOKEN': sentinel})

    def stop_before_fixture():
        reached.append(True)
        raise stop

    monkeypatch.setattr(helper, 'source_check', stop_before_fixture)
    with pytest.raises(RuntimeError) as raised:
        helper.child(time.monotonic() + 5)
    assert raised.value is stop and reached == [True]
    receipts = list(out.iterdir())
    assert [p.name for p in receipts] == ['child-start.json']
    metadata = json.loads(receipts[0].read_bytes())
    assert metadata['sys_executable'] == sys.executable
    assert metadata['argv'] == sys.argv
    assert all(sentinel.encode() not in path.read_bytes() for path in receipts), 'environment value leaked'
    assert 'environment' not in metadata, 'environment must not be serialized'
    assert all(b'SENSITIVE_FAKE_TOKEN' not in path.read_bytes() for path in receipts)


def test_cleanup_only_error_is_not_hidden_by_callers_exception(monkeypatch, tmp_path, real_child):
    # Compatibility control: a harmless child exits itself; no application ledger
    # is fabricated. A cleanup failure must escape before classification work.
    monkeypatch.setattr(sys.modules[__name__], 'STUB', STUB.replace('time.sleep(60)', 'time.sleep(0)'))
    children, receipt, real_identity = real_child
    real_spawn = helper.subprocess.Popen
    close_error = OSError('cleanup-only pipe failure')
    fired = []

    def spawn(*args, **kwargs):
        process = real_spawn(*args, **kwargs)
        close = process.stdout.close
        calls = 0

        def fail_final_close():
            nonlocal calls
            calls += 1
            close()
            if calls == 2:
                fired.append('final_close')
                raise close_error

        monkeypatch.setattr(process.stdout, 'close', fail_final_close)
        return process

    monkeypatch.setattr(helper.subprocess, 'Popen', spawn)
    error = None
    try:
        raise ValueError('unrelated caller exception')
    except ValueError:
        try:
            helper.run_schedule(tmp_path / 'schedule')
        except BaseException as caught:
            error = caught
    process = children[0][0]
    receipt.update(fired=fired, cleanup_error_preserved=error is close_error,
                   helper_absence=real_identity(process.pid) is None,
                   helper_pipes_closed=[process.stdout.closed, process.stderr.closed])
    assert fired == ['final_close']
    assert error is close_error, 'cleanup-only failure was swallowed by ambient exception state'
    assert process.returncode == 0 and real_identity(process.pid) is None
    assert process.stdout.closed and process.stderr.closed
    assert not (tmp_path / 'schedule/classification.json').exists()


@pytest.mark.parametrize('fault', [
    'readiness', 'origin_read', 'receipt_identity', 'receipt_append',
    'finalizer_identity', 'readiness_diagnostic', 'readiness_receipt', 'pipe_close',
])
def test_fixture_failure_retains_ownership(monkeypatch, tmp_path, fault):
    """Invoke the actual fixture; an independent owner contains RED only afterward."""
    module = sys.modules[__name__]
    popen = subprocess.Popen
    identity = helper.identity
    select_ready = select.select
    read_text = Path.read_text
    save = write_receipt
    primary = OSError('fixture setup primary')
    secondary = RuntimeError('fixture diagnostic secondary')
    owned = []
    fired = []
    phase = 'setup'
    inject = False
    setup_error = teardown_error = None
    generator = None
    evidence = {'fault': fault, 'boot_id': read_text(Path('/proc/sys/kernel/random/boot_id')).strip()}
    setup_fault = fault not in ('finalizer_identity', 'pipe_close')

    def capture(*args, **kwargs):
        process = popen(*args, **kwargs)
        # Independent rescue authority exists before any observer can fail.
        item = {'process': process, 'kill': process.kill, 'wait': process.wait,
                'pipes': (process.stdout, process.stderr)}
        owned.append(item)
        item['identity'] = identity(process.pid)
        assert select_ready([process.stdout], [], [], 2)[0]
        item['origin'] = json.loads(read_text(tmp_path / 'stub-origin.json'))
        item['actual_argv'] = process.args
        assert item['origin']['pid'] == process.pid
        assert item['origin']['application_modules'] == []
        assert item['origin']['sys_executable'] == sys.executable
        return process

    def fail_select(*args, **kwargs):
        if inject and fault.startswith('readiness'):
            fired.append('readiness')
            raise primary
        return select_ready(*args, **kwargs)

    def fail_read(path, *args, **kwargs):
        if inject and fault == 'origin_read' and path == tmp_path / 'stub-origin.json':
            fired.append('origin_read')
            raise primary
        return read_text(path, *args, **kwargs)

    def fail_identity(pid):
        if inject and phase == 'setup' and fault == 'receipt_identity':
            fired.append('receipt_identity')
            raise primary
        if phase == 'finalizer' and fault in ('finalizer_identity', 'readiness_diagnostic'):
            fired.append('finalizer_identity')
            raise secondary
        return identity(pid)

    def fail_receipt(path, value):
        if phase == 'finalizer' and fault == 'readiness_receipt':
            fired.append('receipt_write')
            raise secondary
        return save(path, value)

    class BrokenAppend(list):
        def append(self, value):
            fired.append('receipt_append')
            raise primary

    class BrokenClose:
        def __init__(self, stream):
            self.stream = stream

        @property
        def closed(self):
            return self.stream.closed

        def close(self):
            self.stream.close()
            fired.append('pipe_close')
            raise secondary

    def request():
        return helper.subprocess.Popen(
            [sys.executable, str(Path(helper.__file__).resolve())],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(subprocess, 'Popen', capture)
            patch.setattr(select, 'select', fail_select)
            patch.setattr(Path, 'read_text', fail_read)
            patch.setattr(helper, 'identity', fail_identity)
            patch.setattr(module, 'write_receipt', fail_receipt)
            generator = real_child.__wrapped__(patch, tmp_path)
            children, receipt, _ = next(generator)
            if fault != 'readiness':
                request()  # A sibling with complete metadata must also be retired.
            if fault == 'receipt_append':
                receipt['children'] = BrokenAppend(receipt['children'])
            inject = True
            try:
                request()
            except BaseException as caught:
                setup_error = caught
            evidence['receipt_entries_before_finalizer'] = len(receipt['children'])
            evidence['owned_children_before_finalizer'] = len(children)
            if fault == 'pipe_close':
                owned[0]['process'].stdout = BrokenClose(owned[0]['pipes'][0])
            phase = 'finalizer'
            started = time.monotonic()
            try:
                next(generator)
            except StopIteration:
                pass
            except BaseException as caught:
                teardown_error = caught
            evidence['finalizer_elapsed_seconds'] = time.monotonic() - started
            observations = [
                {'identity': item['identity'], 'origin': item['origin'],
                 'actual_argv': item['actual_argv'],
                 'before_outer_rescue': identity(item['process'].pid),
                 'returncode_before_outer_rescue': item['process'].returncode,
                 'pipes_closed_before_outer_rescue': [stream.closed for stream in item['pipes']]}
                for item in owned]
            evidence.update(children=observations, fired=list(fired),
                            setup_error_type=type(setup_error).__name__,
                            teardown_error_type=type(teardown_error).__name__,
                            primary_preserved=setup_error is primary)
            verdict = {
                'injection_fired': bool(fired),
                'setup_outcome': setup_error is primary if setup_fault else setup_error is None,
                'teardown_outcome': teardown_error is None if setup_fault else teardown_error is secondary,
                'all_reaped': all(item['returncode_before_outer_rescue'] is not None for item in observations),
                'all_absent': all(item['before_outer_rescue'] is None for item in observations),
                'both_pipes_closed': all(all(item['pipes_closed_before_outer_rescue']) for item in observations),
                'bounded': evidence['finalizer_elapsed_seconds'] < 5,
                'no_classification': not (tmp_path / 'classification.json').exists(),
            }
            if fault in ('finalizer_identity', 'readiness_diagnostic'):
                verdict['diagnostic_fired'] = 'finalizer_identity' in fired
            if fault == 'readiness_receipt':
                verdict['receipt_write_fired'] = 'receipt_write' in fired
            evidence['verdict_before_outer_rescue'] = verdict
            assert all(verdict.values()), evidence
    finally:
        # Assertions/verdict precede this independent rescue. Never helper GREEN.
        for item in owned:
            process = item['process']
            try:
                if process.poll() is None:
                    item['kill']()
            finally:
                try:
                    item['wait'](timeout=2)
                finally:
                    for stream in item['pipes']:
                        type(stream).close(stream)
            item['released'] = identity(process.pid) is None
            item['pipes_released'] = [stream.closed for stream in item['pipes']]
        evidence['outer_release'] = [
            {'identity': item['identity'], 'absent': item['released'],
             'pipes_closed': item['pipes_released']} for item in owned]
        save(tmp_path / 'fixture-ownership-control.json', evidence)
        assert all(item['released'] and all(item['pipes_released']) for item in owned)
        if generator is not None:
            generator.close()
