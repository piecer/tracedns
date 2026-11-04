"""One metered dispatcher. Provider/config ownership stays in injected callbacks."""
from __future__ import annotations

from dataclasses import replace
import threading
import time

from monitor.delivery_types import provider_result
from monitor.delivery_progress import Progress, counter


class DeliveryWorker:
    def __init__(self, store, *, claim_admission, observation_hook=None, sightings_step=None,
                 maintenance=None, clock=time.time, monotonic=time.monotonic):
        self.store = store
        self._claim_admission = claim_admission
        self._observation_hook = observation_hook
        self._sightings_step = sightings_step
        self._maintenance = maintenance
        self._clock = clock
        self._monotonic = monotonic
        self._progress = Progress()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._idle = threading.Event()
        self._idle.set()
        self._gate = threading.Lock()
        self._thread = None
        # Retained across passes: a one-call allowance must not starve either
        # stream. Start with receipts so their first failed ACK fences flushing.
        self._sighting_turn = False

    def progress_snapshot(self):
        return self._progress.project(self._monotonic(), self._stop.is_set())

    def _begin(self, operation, channel=None):
        old = self._progress
        attempts = list(old.attempts)
        if channel is not None and operation in ('provider_step', 'sightings_step'):
            attempts[('teams', 'misp').index(channel)] = counter(self._clock())
        self._progress = replace(old, state='active', operation=operation, channel=channel,
                                 started=self._monotonic(), attempts=tuple(attempts))

    def _complete(self, state='idle'):
        self._progress = replace(self._progress, state=state, operation=None, channel=None,
                                 started=None, completed=self._monotonic(), completed_wall=counter(self._clock()))

    def run_pass(self, *, max_provider_calls=32):
        calls = steps = 0
        if self._progress.state == 'failed':
            return {'provider_calls': 0, 'steps': 0, 'stopped': self._stop.is_set()}
        if not self._gate.acquire(blocking=False):
            return {"provider_calls": 0, "steps": 0, "stopped": self._stop.is_set()}
        try:
            self._begin('recover_storage')
            if not self._stop.is_set() and self._maintenance is not None:
                maintenance = self._maintenance(self._clock())
                if maintenance['state'] != 'ready':
                    self._complete('recovering')
                    return {"provider_calls": 0, "steps": 0, "stopped": self._stop.is_set()}
            if self._stop.is_set() or not self.store.worker_enter():
                return {"provider_calls": 0, "steps": 0, "stopped": True}
            self._complete()
            self._idle.clear()
            try:
                if self.store.dispatch_available():
                    self._begin('seal_batches')
                    self.store.seal_due_batches(self._clock())
                    self._complete()
                budget = min(32, max(0, int(max_provider_calls)))
                receipts_available = True
                sightings_available = self._sightings_step is not None
                # Alternate eligible streams, including across one-call passes.
                # Zero-HTTP callbacks also consume the finite step allowance.
                while (calls < budget and steps < 256 and not self._stop.is_set()
                       and self.store.dispatch_available()):
                    if sightings_available and (self._sighting_turn or not receipts_available):
                        steps += 1
                        self._sighting_turn = False
                        try:
                            self._begin('sightings_step', 'misp')
                            sighting = self._sightings_step()
                            count = sighting["provider_calls"]
                            if type(count) is not int or count not in (0, 1):
                                calls += 1
                                sightings_available = False
                            else:
                                calls += count
                                sightings_available = bool(sighting.get("has_more"))
                        except Exception:
                            calls += 1
                            sightings_available = False
                        self._complete()
                        continue
                    if not receipts_available:
                        break
                    self._begin('claim')
                    admitted = self._claim_admission(self._clock())
                    self._complete()
                    if not admitted:
                        receipts_available = False
                        continue
                    claim, adapter = admitted
                    if self._stop.is_set():
                        break  # persisted claim remains recoverable
                    steps += 1
                    self._sighting_turn = True
                    self._begin('provider_step', claim['channel'])
                    try:
                        outcome = adapter.execute_step(claim)
                    except Exception:
                        outcome = {"state": "retry", "reason": "provider_transient", "progress": {},
                                   "retry_after": None, "provider_calls": 1, "observation_hook": None}
                    self._complete()
                    outcome = provider_result(outcome)
                    calls += outcome["provider_calls"]
                    if self._stop.is_set():
                        break  # no late publication after shutdown fence
                    self._begin('finish_step', claim['channel'])
                    finish = self.store.finish_step(claim, outcome, self._clock())
                    self._complete()
                    if not finish.get("applied"):
                        break  # no other stream may run after failed ACK CAS/write
                    hook = finish.get("observation_hook")
                    if hook is not None and self._observation_hook is not None:
                        self._begin('observation_hook', claim['channel'])
                        try:
                            self._observation_hook(hook)
                        except Exception:
                            pass  # explicitly local best effort; no response/log text
                        self._complete()
            except Exception:
                self._progress = replace(self._progress, state='failed', started=None)
                raise
            finally:
                self.store.worker_exit()
                self._idle.set()
                if self._progress.state != 'failed':
                    self._complete()
        except Exception:
            self._progress = replace(self._progress, state='failed', started=None)
            raise
        finally:
            self._gate.release()
        return {"provider_calls": calls, "steps": steps, "stopped": self._stop.is_set()}

    def wake(self):
        """Coalesce work notification; never clear after the work it authorizes."""
        self._wake.set()

    def start(self):
        if self._stop.is_set() or self._progress.state == 'failed':
            return False
        with self._gate:
            if self._stop.is_set() or self._thread is not None or self._progress.state == 'failed':
                return False
            def run():
                # Startup publication must precede even an immediate stop/exit.
                with self._gate:
                    pass
                try:
                    while not self._stop.is_set():
                        self._wake.clear()
                        try:
                            self.run_pass()
                        except Exception as error:
                            self._progress = replace(self._progress, state='failed', started=None)
                            self.store.worker_failed(error)
                            break
                        if not self._stop.is_set():
                            self._wake.wait(.25)
                finally:
                    self.store.set_worker_thread_running(False)
            # Do not publish an unstarted thread or phantom health on failure.
            try:
                thread = threading.Thread(target=run, name="delivery-worker", daemon=True)
                thread.start()
            except Exception:
                self._progress = replace(self._progress, state='failed', started=None)
                raise
            self._complete()
            self._thread = thread
            self.store.set_worker_thread_running(True)
            return True

    def stop(self, *, join_seconds=3.0):
        self._stop.set()
        self.store.fence_claims()
        self._wake.set()
        deadline = time.monotonic() + min(3.0, max(0.0, join_seconds))
        # The pass gate also covers Thread.start and its publication. Idle alone
        # cannot prove quiescence while either start or worker_enter is pending.
        stopped = self._gate.acquire(timeout=max(0, deadline - time.monotonic()))
        if stopped:
            thread = self._thread
            self._gate.release()
            if thread is not None:
                thread.join(max(0, deadline - time.monotonic()))
                stopped = not thread.is_alive()
        if stopped and self._progress.state != 'failed':
            self._complete('stopped')
        return {"stopped": stopped, "worker_running": not stopped, "in_flight_preserved": not stopped}
