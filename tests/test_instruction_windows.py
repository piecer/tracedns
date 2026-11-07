"""Instruction windows retain hook ownership, exact sites and thread locality."""
import pytest

from tests.test_instrumentation_helpers import run_child


@pytest.mark.parametrize('worker', [False, True])
@pytest.mark.parametrize('has_prior', [False, True])
@pytest.mark.parametrize('exit_path', ['normal', 'body_error', 'callback_error'])
def test_instruction_window_controls(worker, has_prior, exit_path):
    result = run_child('''
        import dis
        import sys
        import threading
        import pytest
        from tests.instrumentation_helpers import temporary_opcodes

        worker, has_prior, exit_path = sys.argv[1:]
        failures, finished = [], []
        def check():
            def probe():
                value = 40
                return value + 2
            site = next(i.offset for i in dis.get_instructions(probe) if i.opname == 'LOAD_CONST')
            events = []
            def prior(frame, event, arg):
                if frame.f_code is probe.__code__:
                    events.append(event)
                return prior
            expected = prior if has_prior == 'True' else None
            saved_trace, saved_profile = sys.gettrace(), sys.getprofile()
            sys.settrace(expected)
            sys.setprofile(expected)
            monitor = getattr(sys, 'monitoring', None)
            def snapshot():
                return None if monitor is None else [
                    (monitor.get_tool(i), monitor.get_events(i),
                     monitor.get_local_events(i, probe.__code__)) for i in range(6)]
            before = snapshot()
            fired, other_results = [], []
            owner = threading.get_ident()
            def callback(frame, event, arg):
                assert threading.get_ident() == owner
                assert frame.f_code is probe.__code__ and event == 'opcode'
                if frame.f_lasti == site:
                    fired.append(site)
                    if exit_path == 'callback_error':
                        raise MemoryError('instruction callback failed')
            try:
                try:
                    with temporary_opcodes(probe.__code__, callback):
                        other = threading.Thread(target=lambda: other_results.append(probe()))
                        other.start()
                        other.join(5)
                        assert not other.is_alive() and other_results == [42]
                        assert fired == []
                        if exit_path == 'callback_error':
                            with pytest.raises(MemoryError, match='instruction callback failed'):
                                probe()
                        else:
                            assert probe() == 42
                            if exit_path == 'body_error':
                                raise ValueError('instruction body failed')
                except ValueError as exc:
                    assert exit_path == 'body_error' and str(exc) == 'instruction body failed'
                assert fired == [site]
                assert snapshot() == before
                assert sys.gettrace() is expected and sys.getprofile() is expected
                assert probe() == 42 and fired == [site]
                assert bool(events) is (has_prior == 'True')
                reused = []
                with temporary_opcodes(probe.__code__, lambda f, e, a: reused.append(f.f_lasti)):
                    assert probe() == 42
                assert site in reused and fired == [site]
                assert snapshot() == before
                assert sys.gettrace() is expected and sys.getprofile() is expected
            finally:
                sys.settrace(saved_trace)
                sys.setprofile(saved_profile)
            finished.append(True)
        def run():
            try:
                check()
            except BaseException as exc:
                failures.append(exc)
        if worker == 'True':
            thread = threading.Thread(target=run)
            thread.start()
            thread.join(5)
            assert not thread.is_alive()
        else:
            run()
        assert not failures, failures
        assert finished == [True]
        print('instruction-control-complete')
    ''', str(worker), str(has_prior), exit_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'instruction-control-complete' in result.stdout


@pytest.mark.parametrize('failure', ['none', 'register_callback', 'set_local_events'])
def test_instruction_window_preserves_other_tools_and_setup_cleanup(failure):
    result = run_child('''
        import sys
        from unittest.mock import patch
        import pytest
        from tests.instrumentation_helpers import temporary_opcodes

        def check():
            monitor = getattr(sys, 'monitoring', None)
            if monitor is None:
                return  # The legacy backend is covered by the controls above.
            def probe():
                value = 40
                return value + 2
            other_events = []
            monitor.use_tool_id(5, 'existing-observer')
            observer = lambda code, offset: other_events.append(offset)
            monitor.register_callback(5, monitor.events.LINE, observer)
            monitor.set_local_events(5, probe.__code__, monitor.events.LINE)
            def snapshot():
                return [(monitor.get_tool(i), monitor.get_events(i),
                         monitor.get_local_events(i, probe.__code__)) for i in range(6)]
            before = snapshot()
            callback_events = []
            failure = sys.argv[1]
            try:
                if failure == 'none':
                    with temporary_opcodes(probe.__code__, lambda f, e, a: callback_events.append(f.f_lasti)):
                        assert probe() == 42
                    assert callback_events and other_events
                else:
                    original = getattr(monitor, failure)
                    attempts = []
                    def fail_once(*args):
                        attempts.append(args)
                        if len(attempts) == 1:
                            raise MemoryError('setup allocation failed')
                        return original(*args)
                    with patch.object(monitor, failure, fail_once):
                        with pytest.raises(MemoryError, match='setup allocation failed'):
                            with temporary_opcodes(probe.__code__, lambda f, e, a: None):
                                raise AssertionError('failed setup admitted body')
                    assert attempts
                assert snapshot() == before
                count = len(other_events)
                assert probe() == 42 and len(other_events) > count
                assert monitor.register_callback(5, monitor.events.LINE, observer) is observer
            finally:
                monitor.set_local_events(5, probe.__code__, 0)
                monitor.register_callback(5, monitor.events.LINE, None)
                monitor.free_tool_id(5)
        check()
        print('monitor-ownership-complete')
    ''', failure)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'monitor-ownership-complete' in result.stdout


def test_instruction_window_refuses_exhausted_tools_without_stealing():
    result = run_child('''
        import sys
        import pytest
        from tests.instrumentation_helpers import temporary_opcodes
        monitor = getattr(sys, 'monitoring', None)
        if monitor is not None:
            names = [f'existing-{i}' for i in range(6)]
            acquired = []
            try:
                for i, name in enumerate(names):
                    monitor.use_tool_id(i, name)
                    acquired.append(i)
                def probe():
                    return 42
                with pytest.raises(RuntimeError, match='no monitoring tool available'):
                    with temporary_opcodes(probe.__code__, lambda f, e, a: None):
                        raise AssertionError('exhausted tools admitted body')
                assert [monitor.get_tool(i) for i in range(6)] == names
                assert all(monitor.get_events(i) == 0 for i in range(6))
            finally:
                for i in acquired:
                    monitor.free_tool_id(i)
        print('monitor-exhaustion-complete')
    ''')
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'monitor-exhaustion-complete' in result.stdout


@pytest.mark.parametrize('global_events', [False, True])
def test_instruction_window_refuses_conflicting_instruction_owner(global_events):
    # CPython 3.12 can lose an existing instruction observer when a second tool
    # instruments the same code. Refuse before changing either tool's events.
    result = run_child('''
        import sys
        import pytest
        from tests.instrumentation_helpers import temporary_opcodes
        m = getattr(sys, 'monitoring', None)
        if m is not None:
            def probe():
                value = 40
                return value + 2
            events = []
            m.use_tool_id(5, 'existing-instruction-owner')
            observer = lambda code, offset: events.append(offset) if code is probe.__code__ else None
            m.register_callback(5, m.events.INSTRUCTION, observer)
            if sys.argv[1] == 'True':
                m.set_events(5, m.events.INSTRUCTION)
            else:
                m.set_local_events(5, probe.__code__, m.events.INSTRUCTION)
            try:
                assert probe() == 42 and events
                before = [(m.get_tool(i), m.get_events(i), m.get_local_events(i, probe.__code__))
                          for i in range(6)]
                with pytest.raises(RuntimeError, match='instruction events already owned'):
                    with temporary_opcodes(probe.__code__, lambda f, e, a: None):
                        raise AssertionError('conflicting owner admitted body')
                assert [(m.get_tool(i), m.get_events(i), m.get_local_events(i, probe.__code__))
                        for i in range(6)] == before
                count = len(events)
                assert probe() == 42 and len(events) > count
                assert m.register_callback(5, m.events.INSTRUCTION, observer) is observer
            finally:
                m.set_events(5, 0)
                m.set_local_events(5, probe.__code__, 0)
                m.register_callback(5, m.events.INSTRUCTION, None)
                m.free_tool_id(5)
        print('instruction-conflict-refused')
    ''', str(global_events))
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'instruction-conflict-refused' in result.stdout
