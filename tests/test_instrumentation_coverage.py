"""Intrusive hook controls must not corrupt their caller's native coverage."""
import json
from itertools import product
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]


def _native_cases(tmp_path, nodes, expected):
    sentinel = tmp_path / 'matrix_coverage_sentinel.py'
    sentinel.write_text('def after_controls():\n    value = 40\n    return value + 2\n')
    final_test = tmp_path / 'test_matrix_coverage_sentinel.py'
    final_test.write_text(
        'from matrix_coverage_sentinel import after_controls\n'
        'def test_matrix_coverage_sentinel():\n    assert after_controls() == 42\n')
    env = os.environ.copy()
    for name in ('PYTEST_ADDOPTS', 'PYTHONSTARTUP', 'COVERAGE_PROCESS_START', 'PYTHONPATH'):
        env.pop(name, None)
    env.update(PYTHONPATH=os.pathsep.join((str(ROOT), str(tmp_path))),
               PYTEST_DISABLE_PLUGIN_AUTOLOAD='1', COVERAGE_CORE='ctrace',
               COVERAGE_FILE=str(tmp_path / '.coverage'))
    result = subprocess.run(
        [sys.executable, '-m', 'coverage', 'run', '--branch',
         '--source=matrix_coverage_sentinel', '-m', 'pytest', '-q', '-p', 'no:cacheprovider',
         *[str(ROOT / 'tests' / node) for node in nodes], str(final_test),
         f'--junitxml={tmp_path / "controls.xml"}'],
        cwd=ROOT, env=env, text=True, capture_output=True, timeout=90)
    (tmp_path / 'controls.log').write_text(result.stdout + result.stderr)
    assert result.returncode == 0, result.stdout + result.stderr
    cases = list(ET.parse(tmp_path / 'controls.xml').getroot().iter('testcase'))
    expected = expected | {'test_matrix_coverage_sentinel'}
    assert len(cases) == len(expected)
    assert {case.get('name') for case in cases} == expected
    assert all(case.find(outcome) is None for case in cases
               for outcome in ('failure', 'error', 'skipped')), 'all hook controls must execute and pass'
    report = tmp_path / 'coverage.json'
    result = subprocess.run(
        [sys.executable, '-m', 'coverage', 'json', '-o', str(report)],
        cwd=ROOT, env=env, text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    data = json.loads(report.read_text())
    measured = [entry for name, entry in data['files'].items()
                if Path(name).name == sentinel.name]
    assert len(measured) == 1
    assert {2, 3} <= set(measured[0]['executed_lines']), measured


def test_hook_controls_preserve_native_coverage(tmp_path):
    expected = {
        f'test_hook_restoration_even_when_callback_disables_it[{worker}-{prior}-{path}-{kind}]'
        for worker, prior, path, kind in product(
            (False, True), (False, True), ('normal', 'body_error', 'callback_error'), ('trace', 'profile'))
    }
    _native_cases(tmp_path,
                  ['test_instrumentation_helpers.py::test_hook_restoration_even_when_callback_disables_it'],
                  expected)


def test_opcode_windows_preserve_later_work_and_native_coverage(tmp_path):
    nodes = [
        'test_instrumentation_helpers.py::test_opcode_seed_restores_its_frame_flag[False]',
        'test_instrumentation_helpers.py::test_opcode_seed_restores_its_frame_flag[True]',
        'test_derived_capture_lifecycle.py::test_single_fault_transition_retires_aliases_before_bridge_debit[capture]',
        'test_stage4_redaction_lifecycle.py::test_encoding_initializer_entry_is_effect_free',
        'test_stage4_redaction_lifecycle.py::test_projector_initializer_entry_is_effect_free',
        'test_stage4_redaction_lifecycle.py::test_sliced_admission_initializer_entry_is_effect_free',
        'test_stage4_redaction_lifecycle.py::test_encoding_partial_initializer_has_safe_diagnostics',
        'test_stage4_redaction_lifecycle.py::test_projector_partial_initializer_drops_control_storage',
        'test_stage4_redaction_lifecycle.py::test_builder_partial_initializer_has_safe_diagnostics',
        'test_stage4_redaction_lifecycle.py::test_sliced_admission_partial_initializer_has_safe_diagnostics',
        'test_stage4_redaction_lifecycle.py::test_sliced_admission_initial_and_later_refusal[later]',
        'test_stage4_redaction_plan.py::test_1101_recovered_shape',
    ]
    _native_cases(tmp_path, nodes, {node.split('::', 1)[1] for node in nodes})


def test_full_collection_predecessors_preserve_constructor_faults_and_native_coverage(tmp_path):
    # Collection imports are part of this regression: direct-node collection did
    # not establish the predecessor A -> B -> eight-constructor failure mode.
    nodes = [
        'tests/test_derived_capture_lifecycle.py::test_final_transfer_call_entry_fault_has_no_ghost_or_lost_output',
        'tests/test_stage4_redaction_failures.py::test_each_growing_reservation_failure_cleans_the_composition[capacity]',
        'tests/test_stage4_redaction_lifecycle.py::test_encoding_initializer_entry_is_effect_free',
        'tests/test_stage4_redaction_lifecycle.py::test_projector_initializer_entry_is_effect_free',
        'tests/test_stage4_redaction_lifecycle.py::test_sliced_admission_initializer_entry_is_effect_free',
        'tests/test_stage4_redaction_lifecycle.py::test_encoding_partial_initializer_has_safe_diagnostics',
        'tests/test_stage4_redaction_lifecycle.py::test_projector_partial_initializer_drops_control_storage',
        'tests/test_stage4_redaction_lifecycle.py::test_builder_partial_initializer_has_safe_diagnostics',
        'tests/test_stage4_redaction_lifecycle.py::test_sliced_admission_partial_initializer_has_safe_diagnostics',
        'tests/test_stage4_redaction_lifecycle.py::test_sliced_admission_initial_and_later_refusal[later]',
    ]
    enclosing = ('tests/test_instrumentation_coverage.py::'
                 'test_full_collection_predecessors_preserve_constructor_faults_and_native_coverage')
    sentinel = tmp_path / 'order_coverage_sentinel.py'
    sentinel.write_text('def after_constructors():\n    value = 40\n    return value + 2\n')
    final_test = tmp_path / 'test_order_coverage_sentinel.py'
    final_test.write_text(
        'from order_coverage_sentinel import after_constructors\n'
        'def test_order_coverage_sentinel():\n    assert after_constructors() == 42\n')
    selection = {'nodes': nodes, 'enclosing': enclosing, 'sentinel': str(final_test),
                 'args': [str(ROOT / 'tests'), str(final_test)]}
    (tmp_path / 'order_selection.json').write_text(json.dumps(selection))
    (tmp_path / 'order_observer.py').write_text(textwrap.dedent('''
        import json
        from pathlib import Path
        import sys
        import threading

        import coverage
        from coverage.tracer import CTracer
        import pytest

        HERE = Path(__file__).resolve().parent
        PLAN = json.loads((HERE / 'order_selection.json').read_text())
        RECORD = {'body_order': [], 'checks': []}

        def pytest_sessionstart(session):
            session.order_trace = sys.gettrace()
            assert isinstance(session.order_trace, CTracer)
            assert coverage.Coverage.current().config.branch is True
            session.order_profile = sys.getprofile()
            session.order_thread_profile = threading.getprofile()
            # Do not install a new profile: the reproduced collection/order
            # scenario inherits its caller's hooks without changing them.

        @pytest.hookimpl(trylast=True)
        def pytest_collection_modifyitems(config, items):
            assert config.args == PLAN['args'], config.args
            collected = [item.nodeid for item in items]
            assert len(collected) == len(set(collected)), 'duplicate collected nodeids'
            # An external sentinel can have an empty module prefix in its
            # nodeid. Resolve that single exact file/name, then select solely
            # by exact nodeid, just like all ten repository cases.
            sentinels = [item.nodeid for item in items
                         if item.path == Path(PLAN['sentinel'])
                         and item.name == 'test_order_coverage_sentinel']
            assert len(sentinels) == 1, sentinels
            expected = PLAN['nodes'] + sentinels
            assert len(expected) == len(set(expected))
            assert all(collected.count(node) == 1 for node in expected), collected
            assert collected.count(PLAN['enclosing']) == 1
            selected = [item for item in items if item.nodeid in expected]
            deselected = [item for item in items if item.nodeid not in expected]
            assert [item.nodeid for item in selected] == expected
            assert PLAN['enclosing'] in [item.nodeid for item in deselected]
            config.hook.pytest_deselected(items=deselected)
            items[:] = selected
            RECORD.update(collected=collected, expected=expected,
                          deselected=[item.nodeid for item in deselected],
                          enclosing_deselected=True)

        def pytest_collection_finish(session):
            assert [item.nodeid for item in session.items] == RECORD['expected']
            RECORD['selected'] = [item.nodeid for item in session.items]

        def pytest_runtest_call(item):
            RECORD['body_order'].append(item.nodeid)

        @pytest.hookimpl(hookwrapper=True, tryfirst=True)
        def pytest_runtest_protocol(item):
            trace, profile = sys.gettrace(), sys.getprofile()
            assert trace is item.session.order_trace
            assert isinstance(trace, CTracer)
            assert coverage.Coverage.current().config.branch is True
            assert profile is item.session.order_profile
            assert threading.getprofile() is item.session.order_thread_profile
            yield
            check = {'nodeid': item.nodeid, 'ctracer': isinstance(sys.gettrace(), CTracer),
                     'branch': coverage.Coverage.current().config.branch is True,
                     'trace_restored': sys.gettrace() is trace,
                     'profile_restored': sys.getprofile() is profile,
                     'thread_profile_restored': threading.getprofile() is item.session.order_thread_profile}
            RECORD['checks'].append(check)
            assert all(value is True for key, value in check.items() if key != 'nodeid'), check

        def pytest_sessionfinish(session):
            (HERE / 'order_receipt.json').write_text(json.dumps(RECORD, indent=2))
    '''))
    env = os.environ.copy()
    for name in ('PYTEST_ADDOPTS', 'PYTHONSTARTUP', 'COVERAGE_PROCESS_START', 'PYTHONPATH'):
        env.pop(name, None)
    env.update(PYTHONPATH=os.pathsep.join((str(ROOT), str(tmp_path))),
               PYTEST_DISABLE_PLUGIN_AUTOLOAD='1', COVERAGE_CORE='ctrace',
               COVERAGE_FILE=str(tmp_path / '.coverage'))
    result = subprocess.run(
        [sys.executable, '-m', 'coverage', 'run', '--branch',
         '--source=order_coverage_sentinel', '-m', 'pytest', '-q', '-p', 'no:cacheprovider',
         '-p', 'order_observer', f'--rootdir={ROOT}', *selection['args'],
         f'--basetemp={tmp_path / "child_tmp"}', f'--junitxml={tmp_path / "order.xml"}'],
        cwd=ROOT, env=env, text=True, capture_output=True, timeout=90)
    (tmp_path / 'order.log').write_text(result.stdout + result.stderr)
    assert result.returncode == 0, result.stdout + result.stderr
    receipt = json.loads((tmp_path / 'order_receipt.json').read_text())
    expected = receipt['expected']
    assert expected[:-1] == nodes and len(expected) == len(nodes) + 1
    assert expected[-1].split('::', 1)[1] == 'test_order_coverage_sentinel'
    assert receipt['selected'] == receipt['body_order'] == expected
    assert receipt['enclosing_deselected'] is True
    assert enclosing in receipt['deselected'] and enclosing not in expected
    assert len(receipt['collected']) == len(expected) + len(receipt['deselected'])
    assert [check['nodeid'] for check in receipt['checks']] == expected
    assert all(value is True for check in receipt['checks']
               for key, value in check.items() if key != 'nodeid')
    cases = list(ET.parse(tmp_path / 'order.xml').getroot().iter('testcase'))
    expected_cases = [(node.split('::', 1)[0].removesuffix('.py').replace('/', '.'),
                       node.split('::', 1)[1]) for node in expected]
    assert [(case.get('classname'), case.get('name')) for case in cases] == expected_cases
    assert len(cases) == len(set(expected_cases)) == len(nodes) + 1
    assert all(case.find(outcome) is None for case in cases
               for outcome in ('failure', 'error', 'skipped')), 'all ordered cases must execute and pass'
    report = tmp_path / 'coverage.json'
    result = subprocess.run(
        [sys.executable, '-m', 'coverage', 'json', '-o', str(report)],
        cwd=ROOT, env=env, text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    data = json.loads(report.read_text())
    assert data['meta']['branch_coverage'] is True
    measured = [entry for name, entry in data['files'].items()
                if Path(name).name == sentinel.name]
    assert len(measured) == 1
    assert {2, 3} <= set(measured[0]['executed_lines']), measured
