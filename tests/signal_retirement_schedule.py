"""Two bounded legal-schedule gates around the unchanged real-signal fixture."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = None
FIXTURE_SHA256 = 'b8eba148389d209d6a52aafea8e939b3dc7b6a25e5556ff5930f8aaadc7d871e'
TEST = ROOT / 'tests/test_monitor_signal_shutdown.py'
SELECTORS = {
    ('tests/test_monitor_signal_shutdown.py', '_signal_child'),
    ('tests/test_monitor_signal_shutdown.py', 'during_snapshot'),
    ('tests/test_monitor_signal_shutdown.py', 'writer'),
    ('monitor/scheduler.py', 'active_force'),
    ('monitor/scheduler.py', 'stop'),
    ('monitor/lookup_runtime.py', '_controller'),
    ('monitor/signal_stop.py', '_request'),
    ('monitor/signal_stop.py', '_coordinate'),
    ('dns_monitor.py', 'main'),
    ('monitor/repository.py', 'capture'),
}
ABS_SELECTORS = {(str(ROOT / path), name) for path, name in SELECTORS}
EXPECTED_LINES = {
    'tests/test_monitor_signal_shutdown.py': {
        24: 'captured = {}', 55: "with captured['lock']:", 56: 'cfg_locked.set()',
        63: "assert getattr(state_lock(), '_is_owned')()",
        64: 'real_thread(target=writer, daemon=True).start()',
        65: 'assert cfg_locked.wait(2)',
        66: "print('SIGNAL_WHILE_STATE_OWNED', flush=True)",
        67: 'os.kill(os.getpid(), signal.SIGTERM)',
        104: 'out, err = process.communicate(timeout=5)',
    },
    'monitor/lookup_runtime.py': {281: 'work.error = error', 282: "work.kwargs['cycle_quality'].append(False)"},
    'monitor/repository.py': {197: 'with self._coord, state_lock():', 198: 'root_sizes = (len(self.current), len(self.history))'},
    'monitor/signal_stop.py': {33: 'self.requested = True', 47: 'self._stop()'},
    'dns_monitor.py': {350: 'shutdown_deadline = time.monotonic() + 3'},
}


def save(name, value):
    with (OUT / name).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def identity(pid):
    try:
        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        return {'pid': pid, 'start_ticks': fields[19], 'state': fields[0],
                'ppid': int(fields[1]), 'pgid': int(fields[2]), 'sid': int(fields[3])}
    except FileNotFoundError:
        return None


def group_members(pgid):
    members = []
    for entry in Path('/proc').iterdir():
        if entry.name.isdecimal():
            item = identity(int(entry.name))
            if item and item['pgid'] == pgid:
                members.append(item)
    return members


def source_check():
    assert digest(TEST) == FIXTURE_SHA256, 'original signal fixture changed'
    for path, lines in EXPECTED_LINES.items():
        text = (ROOT / path).read_text().splitlines()
        for number, expected in lines.items():
            assert text[number - 1].strip() == expected, (path, number)
    path = ROOT / 'monitor/scheduler.py'
    tree = ast.parse(path.read_text())
    active = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'active_force')
    def select(statement):
        hits = [n.lineno for n in ast.walk(active) if isinstance(n, ast.stmt) and ast.unparse(n) == statement]
        assert len(hits) == 1, (statement, hits)
        return hits[0]
    lines = {'dequeue': select('job = self._dequeue()'),
             'snapshot': select('snapshot = self.store._snapshot_locked()')}
    retire = [n for n in active.body if isinstance(n, ast.Expr)
              and ast.unparse(n) == "finish_force(job, 'failure')"]
    if retire:
        assert len(retire) == 1
        lines['retire'] = retire[0].lineno
    return lines

LINES = source_check()

class Observer:
    """Filtered events; no helper threads, no application lock acquisition."""
    def __init__(self, deadline, ledger):
        self.deadline = deadline
        self.fd = os.open(ledger, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND, 0o600)
        self.main = threading.get_ident()
        self.state_held = threading.Event()
        self.pump_has_config = threading.Event()
        self.seen = set()
        self.main_calls = 0
        self.gated_main = False
        self.worker = None
        self.disabled = False
        self.old_sys = sys.gettrace()
        self.old_threading = threading.gettrace()

    def emit(self, phase, **values):
        if phase in self.seen or len(self.seen) >= 64:
            return
        self.seen.add(phase)
        row = {'phase': phase, 'monotonic_ns': time.monotonic_ns(),
               'time_ns': time.time_ns(), 'thread_id': threading.get_ident(),
               'native_tid': threading.get_native_id(), **values}
        data = (json.dumps(row, sort_keys=True) + '\n').encode()
        if len(data) > 2048:
            raise RuntimeError('observer_record_bound')
        os.write(self.fd, data)

    def gate_wait(self, event, phase):
        started = time.monotonic_ns()
        seconds = min(0.5, max(0.0, self.deadline - time.monotonic()))
        ready = event.wait(seconds)
        self.emit(phase, ready=ready, cap_seconds=seconds,
                  elapsed_ns=time.monotonic_ns() - started)

    def install(self):
        if self.old_sys is not None or self.old_threading is not None:
            raise RuntimeError('ambient_trace_conflict')
        threading.settrace(self.trace)
        sys.settrace(self.trace)
        self.emit('observer_installed')

    def close(self):
        self.disabled = True
        sys.settrace(self.old_sys)
        threading.settrace(self.old_threading)
        self.emit('observer_hooks_restored', sys_restored=sys.gettrace() is self.old_sys,
                  threading_restored=threading.gettrace() is self.old_threading)
        os.close(self.fd)

    def trace(self, frame, event, arg):
        if self.disabled:
            return None
        key = (frame.f_code.co_filename, frame.f_code.co_name)
        if key not in ABS_SELECTORS:
            return None
        try:
            self.observe(frame, event, arg)
        except Exception as error:
            # Observer faults are receipts, never application exceptions.
            self.emit('observer_error', exception_type=type(error).__name__)
            self.state_held.set()
            self.pump_has_config.set()
            self.disabled = True
        return self.trace if not self.disabled else None

    def origins(self, phase):
        names = ['dns_monitor', 'monitor.engine', 'monitor.scheduler',
                 'monitor.lookup_runtime', 'monitor.signal_stop', 'monitor.runtime_state',
                 'monitor.repository', 'monitor.stores', 'monitor.terminal_audit', 'security.jobs']
        origins = {}
        for name in names:
            module = sys.modules.get(name)
            path = getattr(module, '__file__', None)
            if path:
                actual = Path(path).resolve()
                expected = ROOT / (name.replace('.', '/') + '.py')
                origins[name] = {'path': str(actual), 'expected': str(expected),
                                 'matched': actual == expected, 'sha256': digest(actual)}
        save(phase + '.json', {'modules': origins, 'all_matched': all(x['matched'] for x in origins.values())})
        self.emit(phase, all_matched=all(x['matched'] for x in origins.values()), count=len(origins))

    def observe(self, frame, event, arg):
        name = frame.f_code.co_name
        line = frame.f_lineno
        main = threading.get_ident() == self.main
        if name == '_signal_child':
            if event == 'call':
                self.emit('target_body_entry')
            elif event == 'line' and line == 24:
                self.origins('origins_after_fixture_imports')
        elif name == 'active_force' and main:
            if event == 'call':
                self.main_calls += 1
            elif event == 'line' and line == LINES['dequeue'] and self.main_calls == 2 and not self.gated_main:
                self.gated_main = True
                store = frame.f_locals['self'].store
                queue = store.raw.get('_force_resolve_queue')
                owned = store.condition._is_owned()
                remaining_one = type(queue) is list and len(queue) == 1
                missing_lease = remaining_one and queue[0].get('_target_leases') is None
                self.emit('main_config_gate', config_owned=owned,
                          remaining_one=remaining_one, missing_lease=missing_lease, invocation=2)
                if owned and remaining_one and missing_lease:
                    self.pump_has_config.set()
                    self.gate_wait(self.state_held, 'main_gate_wait_end')
                else:
                    self.emit('main_gate_invalid')
            elif event == 'line' and line == LINES['snapshot'] and self.main_calls == 2:
                self.emit('main_real_snapshot_entry', config_owned=frame.f_locals['self'].store.condition._is_owned())
            elif event == 'line' and line == LINES.get('retire'):
                self.emit('missing_retirement_entry', config_owned=frame.f_locals['self'].store.condition._is_owned())
            elif event == 'return' and self.main_calls == 2:
                self.emit('second_active_force_return', config_owned=frame.f_locals['self'].store.condition._is_owned(),
                          returned_none=arg is None)
        elif name == 'during_snapshot':
            if event == 'line' and line == 63 and self.worker is None:
                self.worker = threading.get_ident()
                owned = sys.modules['monitor.runtime_state']._STATE_LOCK._is_owned()
                self.emit('worker_state_gate', state_owned=owned, not_main=not main)
                if owned and not main:
                    self.state_held.set()
                    self.gate_wait(self.pump_has_config, 'worker_gate_wait_end')
                else:
                    self.emit('worker_gate_invalid')
            elif event == 'line' and line == 65:
                self.emit('native_readiness_wait_entry', configured_wait_seconds=2,
                          event_set=frame.f_locals['cfg_locked'].is_set())
            elif event == 'exception' and line == 65:
                self.emit('native_readiness_exception', exception_type=arg[0].__name__)
            elif event == 'line' and line == 66:
                self.emit('marker_print_entry')
            elif event == 'line' and line == 67:
                self.emit('original_sigterm_dispatch_entry')
        elif name == 'writer':
            if event == 'line' and line == 55:
                self.emit('writer_config_acquire_entry', pump_gate_published=self.pump_has_config.is_set())
            elif event == 'line' and line == 56:
                self.emit('writer_config_acquired', config_owned=frame.f_locals['captured']['lock']._is_owned())
        elif name == '_controller':
            if event == 'line' and line == 281:
                self.emit('controller_error_assignment_entry', exception_type=type(frame.f_locals['error']).__name__)
            elif event == 'line' and line == 282:
                self.emit('controller_work_error_assigned', exception_type=type(frame.f_locals['work'].error).__name__)
        elif name == 'capture' and main and self.gated_main:
            if event == 'line' and line == 197:
                self.emit('main_capture_lock_entry')
            elif event == 'line' and line == 198:
                self.emit('main_capture_lock_acquired')
        elif name == '_request' and event in ('call', 'return'):
            self.emit('bridge_request_' + event)
        elif name == '_coordinate' and event == 'line' and line == 47:
            self.emit('coordinator_stop_entry')
        elif name == '_coordinate' and event == 'return':
            self.emit('coordinator_return')
        elif name == 'stop' and event in ('call', 'return'):
            self.emit('scheduler_stop_' + event)
        elif name == 'main' and event == 'line':
            if line == 318 and 'origins_before_scan' not in self.seen:
                self.origins('origins_before_scan')
            elif line == 350:
                self.emit('actual_cleanup_entry', primary_exception_type=type(frame.f_locals.get('primary_error')).__name__)


def child(deadline):
    save('child-start.json', {'identity': identity(os.getpid()), 'argv': sys.argv,
         'sys_executable': sys.executable, 'sys_prefix': sys.prefix, 'version': sys.version,
         'cwd': os.getcwd(), 'deadline_monotonic': deadline,
         'time_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns()})
    assert source_check() == LINES
    spec = importlib.util.spec_from_file_location('signal_fixture_original', TEST)
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    save('fixture-origin.json', {'path': fixture.__file__, 'sha256': digest(fixture.__file__),
         'code_filename': fixture._signal_child.__code__.co_filename,
         'first_line': fixture._signal_child.__code__.co_firstlineno})
    observer = Observer(deadline, OUT / 'ledger.jsonl')
    observer.install()
    try:
        fixture._signal_child('lock-inversion', OUT / 'state')
    finally:
        observer.close()
        save('child-finally.json', {'hooks_restored': sys.gettrace() is None and threading.gettrace() is None,
             'observer_helper_threads': 0, 'time_ns': time.time_ns()})


def _kill_owned_group(process, owned):
    # An unreaped direct child pins its PID; a historical group number does not.
    if process.poll() is not None:
        return
    current = identity(process.pid)
    assert owned and current
    assert all(current[key] == owned[key] for key in ('pid', 'start_ticks', 'pgid', 'sid'))
    assert current['pid'] == current['pgid'] == current['sid'] == process.pid
    os.killpg(process.pid, signal.SIGKILL)


def _retire_failed_child(process, owned, deadline):
    """Best-effort unwind under one separate budget, never replace the cause."""
    try:
        _kill_owned_group(process, owned)
    except BaseException:
        # Even failed initial /proc capture leaves Popen's direct-child authority.
        # Do not infer group ownership from an unverified or stale numeric PID.
        try:
            process.kill()
        except BaseException:
            pass
    try:
        process.wait(timeout=max(0.0, deadline - time.monotonic()))
    except BaseException:
        # A single interruption of wait must not strand an already killed child.
        # This is the same cleanup deadline, not a fresh allowance.
        try:
            process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except BaseException:
            pass


def _close_child_pipes(process, preserve_error):
    first_error = None
    for stream in (process.stdout, process.stderr):
        try:
            if stream is not None:
                stream.close()
        except BaseException as error:
            if first_error is None:
                first_error = error
    if first_error is not None and not preserve_error:
        raise first_error


def run_schedule(out):
    global OUT
    OUT = Path(out)
    OUT.mkdir()
    (OUT / 'state').mkdir()
    before = {p: digest(ROOT / p) for p in sorted({p for p, _ in SELECTORS})}
    save('source-before.json', before)
    save('selectors.json', LINES)
    started = time.monotonic()
    argv = [sys.executable, str(Path(__file__).resolve()), str(OUT), repr(started + 5)]
    save('admission.json', {'argv': argv, 'one_child': True, 'gate_cap': .5,
         'native_readiness_seconds': 2, 'communicate_seconds': 5})
    owned = None
    cleanup_deadline = None
    timed_out = False
    failed = False
    process = subprocess.Popen(argv, cwd=ROOT, env=dict(os.environ), stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        owned = identity(process.pid)
        assert owned and owned['pid'] == owned['pgid'] == owned['sid'] == process.pid
        save('launch.json', {'identity': owned, 'argv': argv})
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            timed_out = True
            cleanup_deadline = time.monotonic() + 2
            current = identity(process.pid)
            assert current and all(current[key] == owned[key]
                                   for key in ('pid', 'start_ticks', 'pgid', 'sid'))
            save('timeout-cleanup.json', {'identity': current, 'signal': 'SIGKILL'})
            _kill_owned_group(process, owned)
            stdout, stderr = process.communicate(timeout=max(0.0, cleanup_deadline - time.monotonic()))
    except BaseException:
        failed = True
        try:
            if cleanup_deadline is None:
                cleanup_deadline = time.monotonic() + 2
            _retire_failed_child(process, owned, cleanup_deadline)
        except BaseException:
            pass  # Cleanup must never replace the primary exception object.
        raise
    finally:
        _close_child_pipes(process, preserve_error=failed)
    (OUT / 'stdout.txt').write_text(stdout)
    (OUT / 'stderr.txt').write_text(stderr)
    remaining = group_members(process.pid)
    released = identity(process.pid) is None and not remaining
    save('runtime-release.json', {'runtime_released': released, 'identity': owned,
         'remaining': remaining, 'returncode': process.returncode, 'rescue_signals': 0})
    after = {p: digest(ROOT / p) for p in before}
    save('source-after.json', after)
    rows = [json.loads(row) for row in (OUT / 'ledger.jsonl').read_text().splitlines()]
    phases = {row['phase']: row for row in rows}
    def event(name, key):
        return phases.get(name, {}).get(key) is True
    legal = (event('main_config_gate', 'config_owned') and event('main_config_gate', 'remaining_one')
             and event('main_config_gate', 'missing_lease') and event('worker_state_gate', 'state_owned')
             and event('worker_state_gate', 'not_main') and event('main_gate_wait_end', 'ready')
             and event('worker_gate_wait_end', 'ready') and 'observer_error' not in phases
             and 'main_gate_invalid' not in phases and 'worker_gate_invalid' not in phases)
    origins = all(json.loads((OUT / (p + '.json')).read_text())['all_matched']
                  for p in ('origins_after_fixture_imports', 'origins_before_scan'))
    green = (legal and origins and before == after and released and not timed_out and process.returncode == 0
             and 'main_real_snapshot_entry' not in phases and 'native_readiness_exception' not in phases
             and 'SIGNAL_WHILE_STATE_OWNED' in stdout and 'NORMAL_EXIT_PENDING_AUDITED_ONCE' in stdout
             and 'bridge_request_call' in phases and 'original_sigterm_dispatch_entry' in phases
             and phases.get('missing_retirement_entry', {}).get('config_owned') is False
             and phases.get('second_active_force_return', {}).get('config_owned') is False
             and event('second_active_force_return', 'returned_none')
             and 'actual_cleanup_entry' in phases)
    red = (legal and timed_out and process.returncode == -9
           and phases.get('native_readiness_exception', {}).get('exception_type') == 'AssertionError'
           and phases.get('controller_work_error_assigned', {}).get('exception_type') == 'AssertionError'
           and event('main_real_snapshot_entry', 'config_owned')
           and 'bridge_request_call' not in phases and 'SIGNAL_WHILE_STATE_OWNED' not in stdout)
    classification = 'GREEN' if green else ('REPRODUCED_RED' if red else 'INCONCLUSIVE_SCHEDULE')
    result = {'classification': classification, 'legal_schedule': legal, 'timeout': timed_out,
              'returncode': process.returncode, 'released': released, 'source_unchanged': before == after,
              'origins_matched': origins, 'elapsed_seconds': time.monotonic() - started}
    save('classification.json', result)
    assert released
    return result


if __name__ == '__main__':
    OUT = Path(sys.argv[1])
    child(float(sys.argv[2]))
