"""Transfer asynchronous signal requests to a normal stopping thread.

A Python signal can interrupt code holding the observation lock. Its handler
must not acquire the configuration lock, audit, or notify a Condition directly.
A nonblocking self-pipe preserves wakeups until the coordinator can own the
configuration lock normally, including signals just before Condition.wait.
"""
import os
import signal
import threading


class SignalStopBridge:
    def __init__(self, stop):
        self.requested = False
        self._closed = False
        self._stop = stop
        self._read, self._write = os.pipe()
        os.set_blocking(self._write, False)
        self._previous = {}
        self._thread = threading.Thread(target=self._coordinate, name='monitor-signal-stop', daemon=True)
        self._started = False

    def start(self, signals=(signal.SIGINT, signal.SIGTERM)):
        self._thread.start()
        self._started = True
        for signum in signals:
            self._previous[signum] = signal.getsignal(signum)
            signal.signal(signum, self._request)

    def _request(self, signum, frame):
        # Plain assignment and nonblocking fd write only: no application locks.
        self.requested = True
        self._wake(b's')

    def _wake(self, value):
        if not self._closed:
            try:
                os.write(self._write, value)
            except BlockingIOError:
                # A full pipe already contains a pending wakeup.
                pass

    def _coordinate(self):
        value = os.read(self._read, 1)
        if value == b's':
            self._stop()

    def close(self, timeout=1.0):
        if self._closed:
            return not self._thread.is_alive()
        for signum, previous in self._previous.items():
            if signal.getsignal(signum) == self._request:
                signal.signal(signum, previous)
        self._wake(b'q')
        if self._started:
            self._thread.join(timeout=max(0.0, timeout))
        if self._thread.is_alive():
            return False
        self._closed = True
        os.close(self._read)
        os.close(self._write)
        return True
