"""Bounded, session-owned local AI lifecycle; no constructor network I/O."""
import json
import math
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass

from . import contracts
from .contracts import AIError
from .provider import NativeReply, OllamaProvider, ProviderError

DEADLINE_SECONDS = 120
ENVELOPE_BYTES = 32768
RETAINED_BYTES = 1048576
TERMINAL_COUNT = 32
RETENTION_SECONDS = 600
SWEEP_INTERVAL = .1
SWEEP_BATCH = 8
CHECK_SECONDS = .25
TERMINAL = frozenset(('completed', 'failed', 'cancelled'))


@dataclass(eq=False)
class _Job:
    job_id: str
    kind: str
    language: str
    actor: dict
    task: object
    created_at: int
    deadline_at: int
    deadline: float
    request_id: str
    source_ip: str
    status: str = 'queued'
    audit_status: str = 'pending'
    error: str | None = None
    result: bytes | None = None
    cancel_requested: bool = False
    finishing: bool = False
    terminal_at: float | None = None
    called: bool = False
    reserved: bool = False
    retired_error: str | None = None


def _encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')


def _request(value):
    """Admission precedes encoding: no unbounded strings/trees/custom objects."""
    count = 0
    chars = 0

    def visit(item, depth):
        nonlocal count, chars
        count += 1
        if count > 4096 or depth > 16:
            raise AIError('too_large')
        kind = type(item)
        if kind is str:
            chars += len(item)
            if chars > contracts.MAX_REQUEST_BYTES:
                raise AIError('too_large')
        elif kind in (dict, list):
            if len(item) > 4096:
                raise AIError('too_large')
            if kind is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise AIError('invalid_request')
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
        elif kind is int:
            if item.bit_length() > 64:
                raise AIError('invalid_request')
        elif kind is float:
            if not math.isfinite(item):
                raise AIError('invalid_request')
        elif item is not None and kind is not bool:
            raise AIError('invalid_request')

    visit(value, 0)
    try:
        data = bytearray()
        for part in json.JSONEncoder(ensure_ascii=False, separators=(',', ':'), allow_nan=False).iterencode(value):
            encoded = part.encode('utf-8')
            if len(data) + len(encoded) > contracts.MAX_REQUEST_BYTES:
                raise AIError('too_large')
            data.extend(encoded)
    except (UnicodeError, TypeError, RecursionError):
        raise AIError('invalid_request') from None
    return contracts.load_request(bytes(data))


class LocalAIService:
    def __init__(self, settings, security_store, engine, *, provider=None):
        if (type(settings) is not dict or settings.keys() - {'enabled', 'origin', 'model', 'model_digest'}
                or type(settings.get('enabled', False)) is not bool):
            raise AIError('invalid_request')
        self._enabled = settings.get('enabled', False)
        validated = None
        if self._enabled or settings.keys() - {'enabled'}:
            try:
                validated = OllamaProvider(settings['origin'], settings['model'], settings['model_digest'])
            except (KeyError, ProviderError):
                raise AIError('invalid_request') from None
        self._store = security_store
        self._engine = engine
        self._provider = provider if provider is not None else validated
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._jobs = {}
        self._users = {}
        self._preparing = set()
        self._queue = deque()
        self._active = None
        self._worker = None
        self._maintenance_worker = None
        self._maintenance_stop = threading.Event()
        self._sweep_cursor = 0
        self._started = False
        self._starting = False
        self._accepting = False
        self._closing = False
        self._audit_broken = False

    def start(self):
        if not self._enabled:
            return
        with self._lock:
            if self._started or self._closing:
                return
            self._started = True
            self._starting = True
        try:
            self._store.ensure_llm_interlock()
        except Exception:
            with self._lock:
                self._starting = False
                self._audit_broken = True
            raise AIError('audit_unavailable') from None
        with self._condition:
            self._starting = False
            if self._closing:
                return
            self._accepting = True
            self._worker = threading.Thread(target=self._work, name='local-ai-worker', daemon=True)
            self._worker.start()
            self._maintenance_worker = threading.Thread(target=self._maintenance, name='local-ai-maintenance', daemon=True)
            self._maintenance_worker.start()

    def stop_admission(self):
        with self._condition:
            self._accepting = False
            self._condition.notify_all()

    def close(self, timeout=1.0):
        deadline = time.monotonic() + max(0, timeout)
        self.stop_admission()
        with self._condition:
            self._closing = True
            worker = self._worker
            maintenance = self._maintenance_worker
            self._maintenance_stop.set()
            self._condition.notify_all()
        for thread in (maintenance, worker):
            if thread and thread is not threading.current_thread():
                thread.join(max(0, deadline - time.monotonic()))
        retained = sum(int(t is not None and t.is_alive()) for t in (maintenance, worker))
        with self._lock:
            complete = not retained and not self._preparing and not self._starting
        return {'complete': complete, 'retained_workers': retained}

    @staticmethod
    def _roles(kind):
        return ('admin',) if kind == 'decoder_suggest' else ('admin', 'operator')

    def _authorize(self, actor, kind='delivery'):
        if type(actor) is not dict:
            raise AIError('source_revoked')
        try:
            principal = self._store.authorize_session(actor.get('session_id'), actor.get('id'), self._roles(kind))
        except Exception:
            raise AIError('audit_unavailable') from None
        if principal is None:
            raise AIError('source_revoked')
        return principal

    @staticmethod
    def _deadline(deadline):
        if time.monotonic() >= deadline:
            raise AIError('deadline_exceeded')

    def _check(self, job):
        with self._lock:
            if job.retired_error:
                raise AIError(job.retired_error)
            if job.cancel_requested:
                raise AIError('stopped')
            task = job.task
        self._deadline(job.deadline)
        self._authorize(job.actor, job.kind)
        if task is None:
            raise AIError('source_revoked')
        task.check(job.deadline)
        self._authorize(job.actor, job.kind)
        self._deadline(job.deadline)

    def _envelope(self, job):
        # Called under the registry lock. All contents are server-owned scalars
        # or independently decoded bounded immutable result bytes.
        return {'job_id': job.job_id, 'kind': job.kind, 'language': job.language,
                'status': job.status, 'created_at': job.created_at, 'deadline_at': job.deadline_at,
                'audit_status': job.audit_status, 'error': job.error,
                'result': json.loads(job.result) if job.result is not None and job.audit_status == 'success' else None,
                'cancel_requested': job.cancel_requested}

    def status(self, actor):
        principal = self._authorize(actor)
        if not self._enabled:
            return {'enabled': False, 'accepting': False, 'provider_state': 'disabled',
                    'queued': 0, 'active_job': None}
        with self._lock:
            owned = self._users.get(principal['id'])
            revoke = (isinstance(owned, _Job) and owned.actor['session_id'] == principal['session_id']
                      and principal['role'] not in self._roles(owned.kind))
        if revoke:
            self._invalidate(owned, 'source_revoked')
        unavailable = False
        try:
            provider_state = self._store.llm_provider_state()
        except Exception:
            provider_state = {'blocked': True, 'job_id': None}
            unavailable = True
        with self._lock:
            owned = (self._active is not None and self._active.job_id == provider_state['job_id']
                     and self._active.status in ('running', 'cancel_pending'))
            blocked = provider_state['blocked'] and not owned
            state = 'unsettled' if blocked else ('busy' if self._active else 'ready')
            if unavailable or self._audit_broken:
                state = 'unavailable' if not blocked or unavailable else 'unsettled'
            if not self._accepting:
                state = 'stopped'
            active = next((j for j in self._jobs.values() if j.actor['id'] == actor['id']
                           and j.actor['session_id'] == actor['session_id']
                           and not j.retired_error and principal['role'] in self._roles(j.kind)
                           and (j.status not in TERMINAL or j.audit_status == 'pending')), None)
            return {'enabled': True, 'accepting': self._accepting and not blocked and not unavailable
                    and not self._audit_broken and len(self._users) < 3,
                    'provider_state': state, 'queued': len(self._queue),
                    'active_job': ({'job_id': active.job_id, 'kind': active.kind, 'status': active.status}
                                   if active else None)}

    def _provider_ready(self):
        with self._lock:
            if self._audit_broken:
                raise AIError('audit_unavailable')
        try:
            state = self._store.llm_provider_state()
        except Exception:
            raise AIError('audit_unavailable') from None
        with self._lock:
            owned_call = (self._active is not None and self._active.job_id == state['job_id']
                          and self._active.status in ('running', 'cancel_pending'))
        if state['blocked'] and not owned_call:
            raise AIError('provider_unsettled')

    def submit(self, request, actor, *, request_id='', source_ip=''):
        if not self._enabled:
            raise AIError('disabled')
        request = _request(request)
        principal = self._authorize(actor, request['kind'])
        self._provider_ready()
        self._prune()
        deadline = time.monotonic() + DEADLINE_SECONDS
        created = int(time.time() * 1000)
        reservation = object()
        user_id = principal['id']
        with self._lock:
            if not self._accepting:
                raise AIError('stopped')
            if user_id in self._users or len(self._users) >= 3:
                raise AIError('busy')
            self._users[user_id] = reservation
            self._preparing.add(user_id)
        task = None
        job = None
        intent = False
        try:
            self._deadline(deadline)
            task = self._engine.prepare(request, principal, deadline)
            with self._lock:
                if not self._accepting:
                    raise AIError('stopped')
            self._deadline(deadline)
            if type(task.retained_bytes) is not int or not 0 <= task.retained_bytes <= 65536:
                raise AIError('too_large')
            self._authorize(principal, request['kind'])
            task.check(deadline)
            self._deadline(deadline)
            job = _Job(secrets.token_hex(16), request['kind'], request['language'], principal, task,
                       created, created + int(DEADLINE_SECONDS * 1000), deadline, request_id, source_ip)
            try:
                intent = self._store.audit_llm_lifecycle(job.job_id, principal, kind=job.kind, outcome='started',
                                                        request_id=request_id, source_ip=source_ip)
                if not intent:
                    raise AIError('audit_unavailable')
            except Exception:
                with self._lock:
                    self._audit_broken = True
                raise AIError('audit_unavailable') from None
            self._check(job)
            with self._condition:
                if not self._accepting:
                    raise AIError('stopped')
                self._jobs[job.job_id] = job
                self._users[user_id] = job
                if self._active is None:
                    self._active = job  # Reserved physical slot, even before run.
                else:
                    self._queue.append(job)
                result = self._envelope(job)
                self._condition.notify_all()
                return result
        except Exception as exc:
            code = exc.code if isinstance(exc, AIError) else 'source_unavailable'
            if intent:
                self._finish(job, 'failed', error=code)
            if task is not None:
                task.dispose()
            raise AIError(code) from None
        finally:
            with self._condition:
                self._preparing.discard(user_id)
                if self._users.get(user_id) is reservation:
                    del self._users[user_id]
                self._condition.notify_all()

    def _lookup(self, job_id, actor):
        self._prune()
        with self._lock:
            job = self._jobs.get(job_id) if type(job_id) is str else None
            if not job or type(actor) is not dict or any(job.actor[k] != actor.get(k) for k in ('id', 'session_id')):
                raise AIError('not_found')
        try:
            self._authorize(job.actor, job.kind)
        except AIError as error:
            self._invalidate(job, error.code)
            raise
        return job

    def get(self, job_id, actor):
        job = self._lookup(job_id, actor)
        with self._lock:
            task = job.task
        if task is not None:
            try:
                self._observe_source(job)
            except AIError as error:
                with self._lock:
                    cancelled = job.cancel_requested
                if not cancelled:
                    self._invalidate(job, error.code)
                    if error.code != 'deadline_exceeded':
                        raise
        with self._lock:
            if self._jobs.get(job_id) is not job:
                raise AIError('not_found')
            return self._envelope(job)

    def _dispose(self, job):
        with self._lock:
            task, job.task = job.task, None
            job.result = None
        if task is not None:
            task.dispose()

    def _trim_locked(self):
        """Only pure bounded registry work here; disposal is caller-owned I/O."""
        now = time.monotonic()
        terminal = sorted((j for j in self._jobs.values() if j.terminal_at is not None),
                          key=lambda j: j.terminal_at)
        total = sum(len(_encode(self._envelope(j))) for j in self._jobs.values())
        remaining = len(terminal)
        dispose = []
        for job in terminal:
            if (now - job.terminal_at < RETENTION_SECONDS and remaining <= TERMINAL_COUNT
                    and total <= RETAINED_BYTES):
                break
            total -= len(_encode(self._envelope(job)))
            remaining -= 1
            del self._jobs[job.job_id]
            if job.task is not None:
                dispose.append(job.task)
            job.task, job.result = None, None
        return dispose

    def _prune(self):
        with self._lock:
            dispose = self._trim_locked()
        for task in dispose:
            task.dispose()

    def _observe_source(self, job):
        """A fresh short read budget is not a renewed work/generation lease."""
        deadline = time.monotonic() + CHECK_SECONDS
        with self._lock:
            task = job.task
            if job.status not in TERMINAL:
                deadline = min(deadline, job.deadline)
        self._deadline(deadline)
        self._authorize(job.actor, job.kind)
        if task is not None:
            try:
                task.check(deadline)
            except Exception as exc:
                with self._lock:
                    # A concurrent terminal/cancel/eviction disposer already
                    # retired this exact source. Its stale check cannot revoke
                    # the newer fixed terminal outcome or publish any result.
                    if job.task is not task:
                        return
                code = exc.code if isinstance(exc, AIError) else 'source_unavailable'
                raise AIError(code) from None
        self._authorize(job.actor, job.kind)
        self._deadline(deadline)

    def _remove_waiting_locked(self, job):
        if job in self._queue:
            self._queue.remove(job)
            return True
        if job is self._active and job.status == 'queued':
            self._active = self._queue.popleft() if self._queue else None
            self._condition.notify_all()
            return True
        return False

    def _invalidate(self, job, code):
        with self._condition:
            if job.retired_error:
                return
            job.retired_error = code
            queued = self._remove_waiting_locked(job)
            if job.terminal_at is not None:
                self._jobs.pop(job.job_id, None)
        self._dispose(job)
        if queued:
            self._finish(job, 'failed', error=code)
            with self._lock:
                if self._users.get(job.actor['id']) is job:
                    del self._users[job.actor['id']]

    def _maintenance(self):
        while not self._maintenance_stop.wait(SWEEP_INTERVAL):
            self._prune()
            with self._lock:
                jobs = list(self._jobs.values())
                if not jobs:
                    continue
                start = self._sweep_cursor % len(jobs)
                selected = (jobs[start:] + jobs[:start])[:SWEEP_BATCH]
                self._sweep_cursor = start + len(selected)
            for job in selected:
                if self._maintenance_stop.is_set():
                    break
                with self._lock:
                    check = job.task is not None
                if check:
                    try:
                        self._observe_source(job)
                    except AIError as error:
                        self._invalidate(job, error.code)
            job = None
            jobs = selected = None
        # Shutdown cleanup belongs to an owned worker, not to close's bounded
        # joining caller. A blocked source/disposer remains truthfully retained.
        with self._lock:
            jobs = list(self._jobs.values())
            for job in jobs:
                if job.status not in TERMINAL and not job.cancel_requested:
                    job.retired_error = job.retired_error or 'stopped'
        for job in jobs:
            self._dispose(job)

    def cancel(self, job_id, actor):
        job = self._lookup(job_id, actor)
        with self._condition:
            queued = False
            retire = job.status not in TERMINAL
            if retire:
                job.cancel_requested = True
                queued = self._remove_waiting_locked(job)
                job.status = 'cancel_pending'
        if retire:
            self._dispose(job)
        if queued:
            self._finish(job, 'cancelled')
            with self._lock:
                if self._users.get(job.actor['id']) is job:
                    del self._users[job.actor['id']]
        with self._lock:
            return {**self._envelope(job), 'cancellation_requested': job.cancel_requested,
                    'cancellation_confirmed': job.status == 'cancelled'}

    def _generate(self, job, messages, schema):
        self._check(job)
        self._provider_ready()
        with self._lock:
            if job.called:
                raise AIError('verification_failed')
            job.called = True

        def before_send():
            self._check(job)
            try:
                job.reserved = self._store.begin_llm_provider(job.job_id, job.actor,
                    request_id=job.request_id, source_ip=job.source_ip)
            except Exception:
                # A wrapper/fsync acknowledgement can fail AFTER commit. The
                # provider's sent flag cannot establish reservation atomicity.
                try:
                    state = self._store.llm_provider_state()
                    job.reserved = state['blocked'] and state['job_id'] == job.job_id
                except Exception:
                    job.reserved = True  # Unknown is never cancellation proof.
                with self._lock:
                    self._audit_broken = True
                raise AIError('audit_unavailable') from None
            if not job.reserved:
                raise AIError('provider_unsettled')
            self._check(job)

        reply = self._provider.generate(messages, schema, job.deadline, before_send=before_send)
        if not isinstance(reply, NativeReply):
            raise AIError('provider_failed')
        try:
            settled = self._store.settle_llm_provider(job.job_id, actor=job.actor)
        except Exception:
            with self._lock:
                self._audit_broken = True
            raise AIError('audit_unavailable') from None
        if not settled:
            raise AIError('provider_unsettled')
        job.reserved = False
        if reply.content_error is not None:
            raise AIError('invalid_model_output')
        self._check(job)
        return reply

    def _finish(self, job, status, *, result=None, error=None):
        with self._lock:
            if job.finishing or job.audit_status != 'pending':
                return
            if job.retired_error:
                status, result, error = 'failed', None, job.retired_error
            elif job.cancel_requested and not job.reserved:
                status, result, error = 'cancelled', None, None
            job.finishing = True
            job.status = status
            job.error = error
        try:
            ok = self._store.audit_llm_lifecycle(job.job_id, job.actor, kind=job.kind, outcome=status, error=error,
                                               request_id=job.request_id, source_ip=job.source_ip)
            if not ok:
                raise AIError('audit_unavailable')
        except Exception:
            status, result, error, audit_status = 'failed', None, 'audit_unavailable', 'failed'
            with self._lock:
                self._audit_broken = True
        else:
            audit_status = 'success'
            if status == 'completed':
                try:
                    self._check(job)
                except AIError as exc:
                    status, result, error = 'failed', None, exc.code
                except Exception:
                    status, result, error = 'failed', None, 'source_unavailable'
        if status != 'completed':
            self._dispose(job)
        with self._lock:
            if status == 'completed' and (job.retired_error or job.task is None or self._closing):
                status, result = 'failed', None
                error = job.retired_error or ('stopped' if self._closing else 'source_revoked')
            job.status, job.error, job.result = status, error, result
            job.audit_status = audit_status
            job.terminal_at = time.monotonic()
            dispose = self._trim_locked()
        for task in dispose:
            task.dispose()

    def _work(self):
        while True:
            with self._condition:
                while self._active is None and not self._closing:
                    self._condition.wait()
                if self._active is None:
                    return
                job = self._active
                job.status = 'running'
            try:
                with self._lock:
                    if self._closing and not job.cancel_requested:
                        job.retired_error = job.retired_error or 'stopped'
                self._check(job)
                self._provider_ready()
                result = job.task.run(job.deadline, lambda messages, schema: self._generate(job, messages, schema))
                value = contracts.parse_object(result, limit=ENVELOPE_BYTES, code='invalid_model_output')
                with self._lock:
                    envelope = {**self._envelope(job), 'status': 'completed', 'audit_status': 'success',
                                'result': value, 'cancellation_requested': False, 'cancellation_confirmed': False}
                if len(_encode(envelope)) > ENVELOPE_BYTES:
                    raise AIError('too_large')
                self._check(job)
                self._finish(job, 'completed', result=result)
            except (AIError, ProviderError) as exc:
                self._finish(job, 'failed', error=exc.code)
            except Exception:
                self._finish(job, 'failed', error='verification_failed')
            finally:
                with self._condition:
                    self._active = self._queue.popleft() if self._queue else None
                    if self._users.get(job.actor['id']) is job:
                        del self._users[job.actor['id']]
                    self._condition.notify_all()
                # A waiting thread frame must not become an unaccounted result
                # cache after registry eviction/disposal.
                job = result = value = envelope = None
