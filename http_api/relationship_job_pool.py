"""Bounded drainage of an exclusively owned CPython process executor.

Python 3.10 has no public ProcessPoolExecutor terminate/kill API. Isolate its
private ownership handles here, before shutdown clears them; never enumerate
multiprocessing.active_children or signal process IDs. Pools must not configure
max_tasks_per_child (which can replace workers during drainage).
"""
import threading
import time


class ProcessPoolDrain:
    def __init__(self, executor):
        state = vars(executor)
        processes = state.get('_processes')
        self.supported = isinstance(processes, dict)
        self.processes = tuple(processes.values()) if isinstance(processes, dict) else ()
        self.manager = state.get('_executor_manager_thread')
        self.executor = executor
        self.started = False

    def close(self, deadline, *, before_terminate):
        signal_errors = []
        now = time.monotonic()
        remaining = max(0.0, deadline - now)
        drain_deadline = now + remaining * .5
        terminate_deadline = now + remaining * .75
        if not self.started:
            self.started = True
            self.executor.shutdown(wait=False, cancel_futures=True)
        self._join_manager(drain_deadline)
        survivors = self._survivors()
        terminated = len(survivors)
        if survivors:
            before_terminate()
            for process in survivors:
                self._signal(process, "terminate", signal_errors)
            self._join_processes(survivors, terminate_deadline)
        survivors = self._survivors()
        killed = len(survivors)
        for process in survivors:
            # multiprocessing.Process.kill is present on supported Python 3.10.
            self._signal(process, "kill", signal_errors)
        self._join_processes(self.processes, deadline)
        self._join_manager(deadline)
        survivors = self._survivors()
        manager_alive = isinstance(self.manager, threading.Thread) and self.manager.is_alive()
        return {
            'closed': self.supported and not survivors and not manager_alive,
            'surviving_workers': len(survivors),
            'manager_alive': manager_alive,
            'ownership_supported': self.supported,
            'terminate_attempts': terminated,
            'kill_attempts': killed,
            'signal_errors': signal_errors,
        }

    @staticmethod
    def _signal(process, method, errors):
        try:
            getattr(process, method)()
        except OSError as exc:
            # A worker can exit concurrently, or the OS can deny a signal.
            # Continue with other owned workers; final liveness is authoritative.
            errors.append({"operation": method, "error": type(exc).__name__})

    def _survivors(self):
        return [process for process in self.processes if process.is_alive()]

    @staticmethod
    def _join_processes(processes, deadline):
        for process in processes:
            process.join(timeout=max(0.0, deadline - time.monotonic()))

    def _join_manager(self, deadline):
        if isinstance(self.manager, threading.Thread):
            self.manager.join(timeout=max(0.0, deadline - time.monotonic()))
