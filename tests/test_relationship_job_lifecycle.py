"""Real process and loopback regressions for relationship job ownership."""
import http.client
import json
import multiprocessing
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import threading
import unittest
from concurrent.futures import Future
from unittest import mock

import vt_lookup
from http_api import relationship_handlers as rh


class RelationshipHttpLifecycleTests(unittest.TestCase):
    def test_server_reserves_one_three_second_budget_for_owned_process_drain(self):
        from http.server import BaseHTTPRequestHandler
        from http_server import ThreadingHTTPServer

        clock = [100.0]
        calls = []

        class Service:
            def __init__(self, name):
                self.name = name

            def start(self):
                pass

            def stop_admission(self):
                pass

            def close(self, timeout):
                calls.append((self.name, timeout))
                clock[0] += timeout
                return {'closed': True}

        jobs, other = Service('jobs'), Service('other')

        class Handler(BaseHTTPRequestHandler):
            relationship_jobs = jobs
            background_services = (other, jobs)

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        with mock.patch('http_server.time.monotonic', side_effect=lambda: clock[0]):
            server.server_close()
        self.assertEqual(calls, [('jobs', 3.0), ('other', 0.0)])


    def test_late_prepared_http_request_cannot_recreate_pool_after_close(self):
        from http_server import make_handler, ThreadingHTTPServer

        class Store:
            def authenticate(self, token):
                return {'id': 'operator', 'role': 'operator'}

            def audit(self, *args, **kwargs):
                pass

        entered, release = threading.Event(), threading.Event()

        def gather(handler):
            entered.set()
            if not release.wait(5):
                raise AssertionError('preparation barrier timed out')
            return {}

        handler = make_handler({}, threading.RLock(), '', '', {}, {},
                               security_store=Store(), insecure_http=True)
        handler._gather_ip_map = gather
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
        serving = threading.Thread(target=server.serve_forever, daemon=True)
        serving.start()
        response = {}

        def call():
            try:
                conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
                conn.request('GET', '/auth/csrf')
                csrf = json.loads(conn.getresponse().read())['csrf_token']
                conn.close()
                conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
                conn.request('POST', '/api/v1/ip-relationship-jobs',
                             body=json.dumps({'ips': ['192.0.2.1'], 'include_vt': False}),
                             headers={'Origin': f'http://127.0.0.1:{server.server_port}',
                                      'X-CSRF-Token': csrf})
                result = conn.getresponse()
                response.update(status=result.status, body=json.loads(result.read()))
                conn.close()
            except Exception as exc:
                response['exception'] = repr(exc)

        request = threading.Thread(target=call, daemon=True)
        with mock.patch.object(rh, 'ProcessPoolExecutor') as factory:
            try:
                request.start()
                self.assertTrue(entered.wait(2))
                server.shutdown()
                server.server_close()
                release.set()
                request.join(3)
                self.assertFalse(request.is_alive())
                self.assertEqual(response.get('status'), 503, response)
                factory.assert_not_called()
            finally:
                release.set()
                request.join(3)
                server.shutdown()
                server.server_close()
                serving.join(2)


class RelationshipServiceTests(unittest.TestCase):
    def test_server_owners_do_not_share_jobs_or_shutdown_fences(self):
        from http_server import make_handler

        first = make_handler({}, threading.RLock(), '', '', {}, {}).relationship_jobs
        second = make_handler({}, threading.RLock(), '', '', {}, {}).relationship_jobs
        first.executor = mock.Mock()
        second.executor = mock.Mock()
        first.executor.submit.side_effect = lambda *args: Future()
        second.executor.submit.side_effect = lambda *args: Future()
        job_id = rh.start_ip_relationship_job({'ips': ['192.0.2.1']}, service=first)['job_id']
        self.assertEqual(rh.get_ip_relationship_job(job_id, service=second)[1], 404)
        self.assertEqual(rh.cancel_ip_relationship_job(job_id, service=second)[1], 404)
        first.close(timeout=0)
        first.start()
        with self.assertRaises(rh.RelationshipJobStoppedError):
            rh.ensure_ip_relationship_job_capacity(service=first)
        with self.assertRaises(rh.RelationshipJobStoppedError):
            rh.start_ip_relationship_job({'ips': ['192.0.2.1']}, service=first)
        other_id = rh.start_ip_relationship_job({'ips': ['192.0.2.1']}, service=second)['job_id']
        self.assertEqual(rh.get_ip_relationship_job(other_id, service=second)[1], 200)
        second.close(timeout=0)

    def test_blocked_submit_returns_incomplete_close_with_permanent_fence(self):
        entered, release, closed = threading.Event(), threading.Event(), threading.Event()
        service = rh.RelationshipJobService()
        future = Future()
        results = []

        class Executor:
            def submit(self, *args):
                entered.set()
                release.wait(3)
                return future

            def shutdown(self, **kwargs):
                future.cancel()

        service.executor = Executor()
        submitting = threading.Thread(target=lambda: rh.start_ip_relationship_job(
            {'ips': ['192.0.2.1']}, service=service))
        closing = threading.Thread(target=lambda: (results.append(service.close(timeout=.1)), closed.set()))
        try:
            submitting.start()
            self.assertTrue(entered.wait(1))
            closing.start()
            self.assertTrue(closed.wait(.5), 'in-flight submit exceeded the close deadline')
            self.assertFalse(results[0]['closed'])
            self.assertTrue(results[0]['submission_in_progress'])
            self.assertTrue(service.stopped)
        finally:
            release.set()
            submitting.join(2)
            closing.join(2)
            service.close(timeout=.1)

    def test_shutdown_cannot_detach_between_reservation_and_submit(self):
        entered, release, closed = threading.Event(), threading.Event(), threading.Event()
        service = rh.RelationshipJobService()
        future = Future()
        submitted = []
        close_result = []

        class Executor:
            def submit(self, *args):
                entered.set()
                if not release.wait(3):
                    raise AssertionError('submit barrier timed out')
                submitted.append(True)
                return future

            def shutdown(self, **kwargs):
                assert submitted, 'executor detached during reservation'
                future.cancel()

        service.executor = Executor()
        submitting = threading.Thread(target=lambda: rh.start_ip_relationship_job(
            {'ips': ['192.0.2.1']}, service=service))
        closing = threading.Thread(target=lambda: (close_result.append(service.close(timeout=.5)), closed.set()))
        try:
            submitting.start()
            self.assertTrue(entered.wait(1))
            closing.start()
            self.assertFalse(closed.wait(.05))
            release.set()
            submitting.join(2)
            closing.join(2)
            self.assertTrue(closed.is_set())
            self.assertTrue(service.stopped)
            self.assertIsNone(service.executor)
            self.assertEqual(len(service.jobs), 1)
            job = next(iter(service.jobs.values()))
            self.assertEqual(job['status'], 'cancelled')
            self.assertNotIn('future', job)
        finally:
            release.set()
            submitting.join(2)
            closing.join(2)

    def test_signal_failure_does_not_skip_other_owned_workers(self):
        from http_api.relationship_job_pool import ProcessPoolDrain

        denied = mock.Mock()
        denied.is_alive.return_value = True
        denied.terminate.side_effect = PermissionError('test denied')
        denied.kill.side_effect = PermissionError('test denied')
        other = mock.Mock()
        other.is_alive.return_value = True
        executor = mock.Mock()
        executor._processes = {1: denied, 2: other}
        drain = ProcessPoolDrain(executor)
        result = drain.close(time.monotonic(), before_terminate=lambda: None)
        self.assertFalse(result['closed'])
        self.assertEqual(result['surviving_workers'], 2)
        other.terminate.assert_called_once()
        other.kill.assert_called_once()
        self.assertEqual(len(result['signal_errors']), 2)

    def test_survivors_are_reported_when_owned_process_cannot_be_reaped(self):
        from http_api.relationship_job_pool import ProcessPoolDrain

        class Process:
            def __init__(self):
                self.signals = []

            def is_alive(self):
                return True

            def terminate(self):
                self.signals.append('terminate')

            def kill(self):
                self.signals.append('kill')

            def join(self, timeout):
                self.signals.append(('join', timeout))

        process = Process()
        executor = mock.Mock()
        executor._processes = {123: process}
        drain = ProcessPoolDrain(executor)
        result = drain.close(time.monotonic(), before_terminate=lambda: None)
        self.assertFalse(result['closed'])
        self.assertEqual(result['surviving_workers'], 1)
        self.assertEqual(result['kill_attempts'], 1)
        self.assertIn('terminate', process.signals)
        self.assertIn('kill', process.signals)
        self.assertTrue(all(item[1] == 0 for item in process.signals if isinstance(item, tuple)))


    def test_stop_during_started_audit_fences_submission_without_blocking(self):
        entered, release, closed = threading.Event(), threading.Event(), threading.Event()
        errors = []

        class Store:
            def audit(self, *args, **kwargs):
                if kwargs.get('outcome') == 'started':
                    entered.set()
                    release.wait(3)

        service = rh.RelationshipJobService()

        def submit():
            try:
                rh.start_ip_relationship_job({'ips': ['192.0.2.1']}, service=service, security_store=Store())
            except rh.RelationshipJobStoppedError:
                errors.append('stopped')

        submitting = threading.Thread(target=submit)
        closing = threading.Thread(target=lambda: (service.close(timeout=.1), closed.set()))
        with mock.patch.object(rh, 'ProcessPoolExecutor') as factory:
            try:
                submitting.start()
                self.assertTrue(entered.wait(1))
                closing.start()
                self.assertTrue(closed.wait(.5), 'started audit blocked the shutdown deadline')
                release.set()
                submitting.join(2)
                self.assertEqual(errors, ['stopped'])
                factory.assert_not_called()
            finally:
                release.set()
                submitting.join(2)
                closing.join(2)


    def test_blocked_completion_audit_does_not_block_process_close(self):
        entered, release, closed = threading.Event(), threading.Event(), threading.Event()

        class Store:
            def audit(self, *args, **kwargs):
                if kwargs.get('outcome') == 'success':
                    entered.set()
                    release.wait(3)

        future = Future()
        service = rh.RelationshipJobService()
        service.executor = mock.Mock()
        service.executor.submit.return_value = future
        rh.start_ip_relationship_job({'ips': ['192.0.2.1']}, service=service, security_store=Store())
        completing = threading.Thread(target=lambda: future.set_result({'payload': {'ok': True}}))
        closing = threading.Thread(target=lambda: (service.close(timeout=.1), closed.set()))
        try:
            completing.start()
            self.assertTrue(entered.wait(1))
            closing.start()
            self.assertTrue(closed.wait(.5), 'terminal audit blocked the shutdown deadline')
        finally:
            release.set()
            completing.join(2)
            closing.join(2)


class RelationshipProcessTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'SIGTERM escalation probe requires POSIX')
    def test_close_kills_only_owned_sigterm_ignoring_worker_and_exits(self):
        with tempfile.TemporaryDirectory() as directory:
            child = subprocess.Popen(
                [sys.executable, __file__, '--exit-probe', directory],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env={**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1])},
                start_new_session=True,
            )
            try:
                out, err = child.communicate(timeout=5)
                self.assertEqual(child.returncode, 0, out + err)
                result = json.loads(out)
                self.assertLess(result['elapsed'], 1.4)
                self.assertEqual(result['survivors'], 0)
                self.assertTrue(result['unrelated_alive'])
                self.assertEqual(result['job_status'], 'failed')
                self.assertEqual(result['job_error'], 'relationship analysis stopped during shutdown')
            finally:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.communicate(timeout=2)

    def test_worker_does_not_inherit_parent_cache_lock(self):
        locked, release = threading.Event(), threading.Event()

        def hold_lock():
            with vt_lookup._CACHE_LOCK:
                locked.set()
                release.wait(10)

        owner = threading.Thread(target=hold_lock)
        owner.start()
        self.assertTrue(locked.wait(2))
        service = rh.RelationshipJobService()
        try:
            job_id = rh.start_ip_relationship_job(
                {'ips': ['192.0.2.1'], 'include_vt': True, 'vt_budget': 0},
                service=service,
            )['job_id']
            deadline = time.monotonic() + 3
            payload = {'status': 'timeout'}
            while time.monotonic() < deadline:
                payload, _ = rh.get_ip_relationship_job(job_id, include_result=True, service=service)
                if payload['status'] in ('completed', 'failed'):
                    break
                time.sleep(.01)
            self.assertEqual(payload['status'], 'completed', 'analysis inherited the locked parent VT cache')
            self.assertEqual(payload['result']['valid_count'], 1)
            self.assertFalse(release.is_set())
        finally:
            release.set()
            owner.join(2)
            result = service.close(timeout=1)
            self.assertTrue(result['closed'], result)


def _unrelated_worker(ready, release):
    ready.set()
    release.wait(10)


def _blocked_analysis(data, *args):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    Path(data['marker']).write_text(str(os.getpid()))
    threading.Event().wait(10)
    return {'status_code': 200, 'payload': {'status': 'ok'}}


def _exit_probe(directory):
    context = multiprocessing.get_context('spawn')
    ready, release = context.Event(), context.Event()
    unrelated = context.Process(target=_unrelated_worker, args=(ready, release))
    unrelated.start()
    service = rh.RelationshipJobService()
    owned = []
    audits = []

    class Store:
        def audit(self, actor, action, **kwargs):
            audits.append({'actor': actor, **kwargs})

    try:
        assert ready.wait(2)
        marker = str(Path(directory) / 'entered')
        with mock.patch.object(rh, '_run_ip_relationship_analysis_payload', _blocked_analysis):
            job = rh.start_ip_relationship_job(
                {'ips': ['192.0.2.1'], 'marker': marker}, service=service,
                security_store=Store(), principal={'id': 'owner', 'role': 'operator'},
                request_id='bounded-exit', source_ip='127.0.0.1',
            )
        owned = list(service.executor._processes.values())
        deadline = time.monotonic() + 2
        while not Path(marker).exists() and time.monotonic() < deadline:
            time.sleep(.01)
        assert Path(marker).exists(), 'worker never reached blocking analysis'
        # User cancellation must not claim a running task stopped.
        cancelled, code = rh.cancel_ip_relationship_job(job['job_id'], service=service)
        assert code == 409 and not cancelled['cancelled']
        before = time.monotonic()
        evidence = service.close(timeout=.8)
        elapsed = time.monotonic() - before
        survivors = sum(process.is_alive() for process in owned)
        assert survivors == 0, 'close left a running process behind'
        assert evidence['closed'] and evidence['surviving_workers'] == survivors, evidence
        assert len(audits) == 2 and audits[-1]['outcome'] == 'failed', audits
        assert audits[-1]['actor']['id'] == 'owner'
        assert audits[-1]['request_id'] == 'bounded-exit'
        assert audits[-1]['source_ip'] == '127.0.0.1'
        assert 'future' not in service.jobs[job['job_id']]
        payload, _ = rh.get_ip_relationship_job(job['job_id'], service=service)
        print(json.dumps({'elapsed': elapsed, 'survivors': survivors, 'evidence': evidence,
                          'unrelated_alive': unrelated.is_alive(),
                          'job_status': payload['status'], 'job_error': payload['error']}), flush=True)
    finally:
        release.set()
        unrelated.join(2)
        for process in owned:
            if process.is_alive():
                process.kill()
            process.join(2)
        if service.executor is not None:
            service.executor.shutdown(wait=True, cancel_futures=True)


if __name__ == '__main__' and '--exit-probe' in sys.argv:
    _exit_probe(sys.argv[-1])
