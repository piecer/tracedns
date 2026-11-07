"""Regression isolation: earlier tracing must not prime fault injection."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import threading

import pytest

from tests.instrumentation_helpers import temporary_profile, temporary_trace


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('kind', ['trace', 'profile'])
@pytest.mark.parametrize('exit_path', ['normal', 'body_error', 'callback_error'])
@pytest.mark.parametrize('has_prior', [False, True])
@pytest.mark.parametrize('worker', [False, True])
def test_hook_restoration_even_when_callback_disables_it(kind, exit_path, has_prior, worker):
    # These controls deliberately remove/replace the caller's trace hook.
    # Keep them out of the coverage collector's process: CPython 3.12 can crash
    # when a removed native CTracer and opcode seeding meet in a new thread.
    # Actual lifecycle windows still exercise retained CTracer hooks below.
    result = run_child(f'''
        import sys
        import threading
        from tests.test_instrumentation_helpers import _check_hook_restoration
        assert sys.gettrace() is None and threading.gettrace() is None
        _check_hook_restoration({kind!r}, {exit_path!r}, {has_prior!r}, {worker!r})
        print('hook-control-complete')
    ''')
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'hook-control-complete' in result.stdout


def _check_hook_restoration(kind, exit_path, has_prior, worker):
    errors = []
    finished = []

    def check():
        get_hook = getattr(sys, 'get' + kind)
        set_hook = getattr(sys, 'set' + kind)
        saved = get_hook()
        events = []

        def prior(frame, event, arg):
            if frame.f_code is probe.__code__:
                events.append(event)
            return prior

        def probe():
            return 42

        def callback(frame, event, arg):
            if exit_path == 'callback_error' and event == 'call' and frame.f_code is probe.__code__:
                raise MemoryError('instrumentation callback failed')
            return callback

        expected = prior if has_prior else None
        try:
            set_hook(expected)
            guard = temporary_trace(callback, opcodes=True) if kind == 'trace' else temporary_profile(callback)
            with guard:
                assert get_hook() is callback
                if exit_path == 'callback_error':
                    with pytest.raises(MemoryError, match='instrumentation callback failed'):
                        probe()
                    assert get_hook() is None  # CPython disabled the failing hook.
                elif exit_path == 'body_error':
                    raise ValueError('body failed')
                else:
                    assert probe() == 42
        except ValueError as exc:
            assert exit_path == 'body_error' and str(exc) == 'body failed'
        finally:
            try:
                assert get_hook() is expected
                assert probe() == 42
                assert bool(events) is has_prior
            finally:
                set_hook(saved)
        finished.append(True)

    def run():
        try:
            check()
        except BaseException as exc:
            errors.append(exc)

    if worker:
        thread = threading.Thread(target=run)
        thread.start()
        thread.join(5)
        assert not thread.is_alive()
    else:
        run()
    assert not errors, errors
    assert finished == [True]


@pytest.mark.parametrize('initial_opcodes', [False, True])
def test_opcode_seed_restores_its_frame_flag(initial_opcodes):
    # Restoring a frame flag cannot undo CPython 3.12's interpreter-wide opcode
    # switch. Exercise these legacy controls without contaminating later work.
    result = run_child(f'''
        from tests.test_instrumentation_helpers import _check_opcode_seed_frame_flag
        _check_opcode_seed_frame_flag({initial_opcodes!r})
        print('opcode-frame-control-complete')
    ''')
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'opcode-frame-control-complete' in result.stdout


def _check_opcode_seed_frame_flag(initial_opcodes):
    guard = temporary_trace(lambda frame, event, arg: None, opcodes=True)
    frame = guard.gen.gi_frame
    frame.f_trace_opcodes = initial_opcodes
    try:
        with guard:
            assert frame.f_trace_opcodes
        assert frame.f_trace_opcodes is initial_opcodes
    finally:
        del frame


def run_child(code, *args, cwd=ROOT, env=None):
    child_env = os.environ.copy()
    # Do not inherit coverage startup or an unrelated checkout's import path.
    for key in ('PYTHONPATH', 'PYTHONSTARTUP', 'COVERAGE_PROCESS_START', 'PYTEST_ADDOPTS'):
        child_env.pop(key, None)
    child_env['PYTHONPATH'] = str(ROOT)
    if env:
        child_env.update(env)
    return subprocess.run([sys.executable, '-c', textwrap.dedent(code), *args],
                          cwd=cwd, env=child_env, text=True, capture_output=True, timeout=90)


def test_capture_opcode_fault_on_first_trace_in_fresh_process():
    result = run_child('''
        import sys
        from tests.test_derived_capture_lifecycle import (
            FAULTS, test_single_fault_transition_retires_aliases_before_bridge_debit,
        )
        assert sys.gettrace() is None
        test_single_fault_transition_retires_aliases_before_bridge_debit('capture')
        assert len(FAULTS) == 1 and FAULTS[0]['fired'] == 1
        assert FAULTS[0]['marker'] == 'self._buffer.extend(blob)'
        assert FAULTS[0]['opcode'] == 'CALL'
        assert sys.gettrace() is None
        assert sys.getprofile() is None
        print('first-install capture fault fired once; lifecycle assertions passed')
    ''')
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'first-install capture fault fired once' in result.stdout


@pytest.mark.parametrize('helper,args', [
    ('_initializer_entry_failure', ('encode',)),
    ('_constructor_diagnostic_failure', ('encode', 'partial')),
])
def test_constructor_opcode_fault_on_first_trace_in_fresh_process(helper, args):
    result = run_child(f'''
        import sys
        from tests import test_stage4_redaction_lifecycle as target
        assert sys.gettrace() is None
        target.{helper}(*{args!r})
        assert target.CONSTRUCTOR_RECEIPTS[-1]['fired'] == 1
        assert sys.gettrace() is None
        assert sys.getprofile() is None
    ''')
    assert result.returncode == 0, result.stdout + result.stderr


# One entry per instrumentation window; parametrization covers both normal and
# exception-disabled tracing, including the worker-thread barrier helpers.
HOOK_CASES = [
    'test_derived_capture_lifecycle.py::test_continuous_real_plan_capture_decode_admission_custody',
    'test_derived_capture_lifecycle.py::test_single_fault_transition_retires_aliases_before_bridge_debit',
    'test_derived_capture_lifecycle.py::test_bridge_controller_refused_before_capture_allocation',
    'test_derived_capture_lifecycle.py::test_shared_original_deadline_after_wait_or_action',
    'test_derived_capture.py::test_actual_inner_work_single_phase_and_complete_progress',
    'test_stage4_redaction_cleanup.py::test_pin_cleanup_fault_preserves_reachable_transfer',
    'test_stage4_redaction_failures.py::test_active_owner_quiescence',
    'test_stage4_redaction_failures.py::test_allocation_at_internal_materialization_is_terminal',
    'test_stage4_redaction_failures.py::test_operation_bookkeeping_allocation_failure_is_terminal',
    'test_stage4_redaction_lifecycle.py::test_encoding_initializer_entry_is_effect_free',
    'test_stage4_redaction_lifecycle.py::test_encoding_partial_initializer_has_safe_diagnostics',
    'test_stage4_redaction_lifecycle.py::test_initial_capacity_refusal_has_safe_diagnostics',
    'test_stage4_redaction_lifecycle.py::test_rejected_admission_fault_retires_lease_and_active',
    'test_stage4_redaction_lifecycle.py::test_public_drop_keeps_last_pin_charge_and_never_holds_locks',
    'test_stage4_redaction_lifecycle.py::test_postcommit_frame_retirement_revocation_keeps_delivered_handle',
]


def test_pytest_cov_sentinel_after_instrumented_lifecycle_tests(tmp_path):
    if importlib.util.find_spec('pytest_cov') is None:
        pytest.skip('optional instrumentation integration requires pytest-cov')
    sentinel = tmp_path / 'instrumentation_sentinel.py'
    sentinel.write_text('def after_helpers():\n    value = 40\n    return value + 2\n')
    (tmp_path / 'test_after_helpers.py').write_text(
        'from instrumentation_sentinel import after_helpers\n'
        'def test_sentinel():\n    assert after_helpers() == 42\n')
    # Check identity separately from coverage: merely reinstalling an arbitrary
    # trace function is not restoration of the caller's instrumentation.
    (tmp_path / 'hook_observer.py').write_text(textwrap.dedent('''
        import sys
        import pytest
        import threading

        def prior_profile(frame, event, arg):
            pass

        def pytest_sessionstart(session):
            session.saved_profile = sys.getprofile()
            session.saved_thread_profile = threading.getprofile()
            sys.setprofile(prior_profile)
            threading.setprofile(prior_profile)

        @pytest.hookimpl(hookwrapper=True)
        def pytest_runtest_call(item):
            trace, profile = sys.gettrace(), sys.getprofile()
            assert trace is not None, 'pytest-cov must be tracing this process'
            yield
            assert sys.gettrace() is trace, item.nodeid
            assert sys.getprofile() is profile, item.nodeid

        def pytest_sessionfinish(session):
            sys.setprofile(session.saved_profile)
            threading.setprofile(session.saved_thread_profile)
    '''))
    report = tmp_path / 'coverage.json'
    result = run_child('''
        import sys
        import pytest
        raise SystemExit(pytest.main(sys.argv[1:]))
    ''', '-q', '-p', 'pytest_cov', '-p', 'hook_observer',
        f'--junitxml={tmp_path / "pytest.xml"}',
        '--cov=instrumentation_sentinel', f'--cov-report=json:{report}',
        *[str(ROOT / 'tests' / node) for node in HOOK_CASES],
        str(tmp_path / 'test_after_helpers.py'), cwd=tmp_path,
        env={'PYTHONPATH': os.pathsep.join((str(ROOT), str(tmp_path))),
             'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1', 'COVERAGE_CORE': 'ctrace',
             'COVERAGE_FILE': str(tmp_path / '.coverage')})
    (tmp_path / 'pytest.log').write_text(result.stdout + result.stderr)
    assert result.returncode == 0, result.stdout + result.stderr
    data = json.loads(report.read_text())
    measured = [value for name, value in data['files'].items()
                if Path(name).name == sentinel.name]
    assert len(measured) == 1
    assert {2, 3} <= set(measured[0]['executed_lines']), measured
