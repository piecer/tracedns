"""Internal bounded redaction foundation; NOT a publication capability.

All owners of one attempt use one explicit RedactionBudget and absolute deadline.
Handles are exclusive lifetime leases: value is a borrowed view, not a detached
copy. Callers must not mutate admitted input or use borrowed views after close.
Capture/decode and HTTP publication integration deliberately live elsewhere.
Conservative logical charges are not Python heap or RSS measurements.
"""
import hashlib
import json
import math
import threading
import time
from dataclasses import dataclass

from http_api.read_model import BackgroundReadModel
from monitor.config_service import ConfigService
from monitor.projection_authority import security_projection_revision
from security.redaction import SECRET_KEYS

VISITS = 16384
DEPTH = 32
SECRETS = 256
SECRET_BYTES = 65536
METADATA = 1048576
WORKER = 16777216
HEADER = 106728
SLICE = .002
ACQUIRE = .020
_MINT = object()


class _SliceFull(Exception):
    """Internal yield: source references unwind before the next scheduler call."""


class Reject(Exception):
    """Finite failure code only; never source data."""


class _UniqueOwner:
    """Lifetime ownership cannot be duplicated by copy or serialization."""

    def __copy__(self):
        raise TypeError('unique owner')

    def __deepcopy__(self, memo):
        raise TypeError('unique owner')

    def __reduce_ex__(self, protocol):
        raise TypeError('unique owner')


def _is(kind, *allowed):
    # A source class can have a metaclass with poisoned __eq__/__hash__.
    return any(kind is item for item in allowed)


class RedactionBudget(_UniqueOwner):
    """One trusted attempt ledger. Reservations are atomic; expiry never resets."""

    def __init__(self, *, deadline, metadata_capacity=METADATA, worker_capacity=WORKER):
        if type(deadline) not in (int, float) or not math.isfinite(deadline):
            raise ValueError('deadline')
        for value, maximum in ((metadata_capacity, METADATA), (worker_capacity, WORKER)):
            if type(value) is not int or not 0 <= value <= maximum:
                raise ValueError('capacity')
        self._deadline = deadline
        self._metadata_capacity = metadata_capacity
        self._worker_capacity = worker_capacity
        self._worker = self._metadata = self._peak_worker = self._peak_metadata = 0
        self._hold_worker = self._hold_metadata = 0
        self.visits = 0
        self._active = None
        self._closed = False
        self._lock = threading.RLock()

    @property
    def deadline(self):
        return self._deadline

    @property
    def worker_capacity(self):
        return self._worker_capacity

    @property
    def metadata_capacity(self):
        return self._metadata_capacity

    def check(self):
        if self._closed:
            raise Reject('invalid')
        if time.monotonic() >= self._deadline:
            raise Reject('deadline')

    def reserve(self, *, worker=0, metadata=0, _owner=None):
        """Provisional capacity precedes materialization; peaks publish at mint."""
        self._validate(worker, metadata)
        acquire, release = self._lock.acquire, self._lock.release
        held = locked = False
        lease = None
        code = None
        allocation = False
        try:
            worker = worker + HEADER
            metadata = metadata + HEADER
            acquire()
            locked = True
            self.check()
            hw = self._hold_worker + worker
            hm = self._hold_metadata + metadata
            if self._worker + hw > self._worker_capacity or self._metadata + hm > self._metadata_capacity:
                raise Reject('capacity')
            self._hold_worker = hw
            self._hold_metadata = hm
            held = True
            release()
            locked = False
            lease = _Lease(self, worker, metadata, _MINT)
            if _owner is not None:
                _owner._initialize_control()
            acquire()
            locked = True
            self.check()
            new_worker = self._worker + worker
            new_metadata = self._metadata + metadata
            hw = self._hold_worker - worker
            hm = self._hold_metadata - metadata
            peak_worker = self._peak_worker if self._peak_worker >= new_worker else new_worker
            peak_metadata = self._peak_metadata if self._peak_metadata >= new_metadata else new_metadata
            if _owner is not None:
                _owner._lease = lease
            self._worker = new_worker
            self._metadata = new_metadata
            self._peak_worker = peak_worker
            self._peak_metadata = peak_metadata
            self._hold_worker = hw
            self._hold_metadata = hm
            held = False
            lease.closed = False
            release()
            return lease
        except (MemoryError, Reject) as exc:
            allocation = type(exc) is MemoryError
            code = 'invalid' if allocation else exc.args[0]
            exc.__traceback__ = exc.__context__ = exc.__cause__ = None
        if locked:
            release()
        lease = None
        attempt = False
        while True:
            if not held:
                break
            locked = False
            try:
                acquire()
                locked = True
                hw = self._hold_worker - worker
                hm = self._hold_metadata - metadata
                self._hold_worker = hw
                self._hold_metadata = hm
                held = False
            except MemoryError as exc:
                allocation = True
                exc.__traceback__ = exc.__context__ = exc.__cause__ = None
            finally:
                if locked:
                    release()
            if attempt:
                break
            attempt = True
        if held:
            raise RuntimeError('two-fault unreturned hold')
        _owner = None
        if allocation:
            raise MemoryError('redaction allocation') from None
        raise Reject(code) from None

    @staticmethod
    def _validate(worker, metadata):
        if type(worker) is not int or type(metadata) is not int or min(worker, metadata) < 0:
            raise ValueError('reservation')

    def enter(self, owner):
        acquire, release = self._lock.acquire, self._lock.release
        acquire()
        try:
            self.check()
            if self._active is not None:
                raise Reject('lock_busy')
            self._active = owner
        finally:
            release()

    def leave(self, owner):
        acquire, release = self._lock.acquire, self._lock.release
        acquire()
        if self._active is owner:
            self._active = None
        release()

    def visit(self, n=1):
        if type(n) is not int or n < 0:
            raise ValueError('visits')
        with self._lock:
            self.check()
            if self.visits + n > VISITS:
                raise Reject('capacity')
            self.visits += n

    def close(self):
        """Revoke new work, not charges for still-live handles."""
        with self._lock:
            self._closed = True

    def counters(self):
        with self._lock:
            return {'worker_bytes': self._worker, 'worker_peak': self._peak_worker,
                    'metadata_bytes': self._metadata, 'metadata_peak': self._peak_metadata,
                    'visits': self.visits, 'active': self._active is not None,
                    'closed': self._closed, 'hold_worker_bytes': self._hold_worker,
                    'hold_metadata_bytes': self._hold_metadata}


class _Lease(_UniqueOwner):
    def __init__(self, budget, worker, metadata, mint):
        if mint is not _MINT:
            raise TypeError('private lease')
        self.budget = budget
        self.worker = worker
        self.metadata = metadata
        self.closed = True

    def reserve(self, *, worker=0, metadata=0):
        b = self.budget
        if type(worker) is not int or type(metadata) is not int or min(worker, metadata) < 0:
            raise ValueError('reservation')
        acquire, release = b._lock.acquire, b._lock.release
        acquire()
        try:
            b.check()
            if self.closed:
                raise Reject('invalid')
            new_worker = self.worker + worker
            new_metadata = self.metadata + metadata
            budget_worker = b._worker + worker
            budget_metadata = b._metadata + metadata
            if budget_worker + b._hold_worker > b._worker_capacity or budget_metadata + b._hold_metadata > b._metadata_capacity:
                raise Reject('capacity')
            peak_worker = b._peak_worker if b._peak_worker >= budget_worker else budget_worker
            peak_metadata = b._peak_metadata if b._peak_metadata >= budget_metadata else budget_metadata
            self.worker = new_worker
            self.metadata = new_metadata
            b._worker = budget_worker
            b._metadata = budget_metadata
            b._peak_worker = peak_worker
            b._peak_metadata = peak_metadata
        finally:
            release()

    def release(self, *, worker=0, metadata=0):
        if type(worker) is not int or type(metadata) is not int or min(worker, metadata) < 0:
            raise ValueError('reservation')
        acquire, release = self.budget._lock.acquire, self.budget._lock.release
        acquire()
        try:
            if self.closed or self.worker - worker < HEADER or self.metadata - metadata < HEADER:
                raise Reject('invalid')
            new_worker = self.worker - worker
            new_metadata = self.metadata - metadata
            budget_worker = self.budget._worker - worker
            budget_metadata = self.budget._metadata - metadata
            self.worker = new_worker
            self.metadata = new_metadata
            self.budget._worker = budget_worker
            self.budget._metadata = budget_metadata
        finally:
            release()

    def close(self):
        acquire, release = self.budget._lock.acquire, self.budget._lock.release
        acquire()
        try:
            if not self.closed:
                budget_worker = self.budget._worker - self.worker
                budget_metadata = self.budget._metadata - self.metadata
                self.budget._worker = budget_worker
                self.budget._metadata = budget_metadata
                self.worker = self.metadata = 0
                self.closed = True
        finally:
            release()


class _Owned(_UniqueOwner):
    def __init__(self, value, lease, mint=None):
        if mint is not _MINT:
            raise TypeError('handles are minted by their owner')
        self._value = value
        self._lease = lease
        self._closed = False
        self._pins = 0

    def _pin(self, tickets, index):
        b = self._lease.budget
        acquire, release = b._lock.acquire, b._lock.release
        acquire()
        try:
            self.value
            pins = self._pins + 1
            self._pins = pins
            tickets[index] = self
        finally:
            release()

    @property
    def value(self):
        if self._closed or self._lease.closed:
            raise Reject('invalid')
        self._lease.budget.check()
        return self._value

    @property
    def budget(self):
        return self._lease.budget

    def close(self):
        b = self._lease.budget
        acquire, release = b._lock.acquire, b._lock.release
        local = None
        acquire()
        if self._closed == 1 or self._lease.closed:
            release()
            return
        if not self._closed:
            self._closed = 1
            local = self._value
            self._value = None
        release()
        del local
        attempt = False
        while True:
            locked = False
            try:
                acquire()
                locked = True
                if self._pins == 0:
                    lease = self._lease
                    worker = b._worker - lease.worker
                    metadata = b._metadata - lease.metadata
                    b._worker = worker
                    b._metadata = metadata
                    lease.worker = lease.metadata = 0
                    lease.closed = True
                self._closed = 2
                release()
                locked = False
                return
            except MemoryError as exc:
                exc.__traceback__ = exc.__context__ = exc.__cause__ = None
            finally:
                if locked:
                    release()
            if attempt:
                break
            attempt = True
        self._closed = 2


class OwnedPlan(_Owned):
    """Immutable complete plan, charged until close."""


@dataclass(frozen=True)
class Plan:
    authority: tuple
    replacements: tuple
    visits: int
    secret_bytes: int
    metadata_charge: int


def _serialized(method):
    """One custodian through work, retirement, final eligibility and transfer."""
    from functools import wraps
    taking = method.__name__ == 'take'
    discarding = method.__name__ == 'discard'
    sealing = method.__name__ == 'seal_slice'

    @wraps(method)
    def invoke(self):
        b = self.budget
        acquire, release = b._lock.acquire, b._lock.release
        shell = None
        acquire()
        if self._running:
            if discarding:
                self._cancelled = True
            release()
            return None if taking or discarding else 'lock_busy'
        if self._lease is None:
            release()
            return None if taking or discarding else self.status
        if taking and self.status != 'done':
            release()
            return None
        self._running = True
        release()
        fault = False
        try:
            if discarding:
                if self.status in ('more', 'captured', 'done'):
                    self._cancelled = True
            else:
                b.enter(self)
                shell = method(self)
        except (MemoryError, Reject, _SliceFull, ValueError, UnicodeError, KeyError, IndexError) as exc:
            if type(exc) is MemoryError:
                fault = True
            else:
                self.status = exc.args[0] if type(exc) is Reject else 'deadline' if type(exc) is _SliceFull else 'invalid'
            exc.__traceback__ = exc.__context__ = exc.__cause__ = None
        attempt = False
        while True:
            locked = False
            try:
                acquire()
                locked = True
                code = self.status
                if self._cancelled:
                    code = 'stopped'
                elif fault:
                    code = 'invalid'
                elif code in ('more', 'captured', 'done'):
                    if b._closed or (self._dependencies and self._dependencies[0]._closed) or (len(self._dependencies) == 2 and self._dependencies[1]._closed):
                        code = 'invalid'
                    elif time.monotonic() >= b._deadline:
                        code = 'deadline'
                self.status = code
                if code in ('more', 'captured', 'done') and not discarding:
                    if taking:
                        shell._lease = self._lease
                        self._lease = None
                        self.result = None
                        self._phase = 2
                        self.status = 'taken'
                        self._dependencies = ()
                        if b._active is self:
                            b._active = None
                        self._running = False
                        release()
                        return shell
                    code = 'more' if sealing and code == 'captured' else code
                    if b._active is self:
                        b._active = None
                    self._running = False
                    release()
                    return code
                release()
                locked = False
                shell = None
                self._dispose()
                break
            except MemoryError as exc:
                fault = True
                exc.__traceback__ = exc.__context__ = exc.__cause__ = None
            finally:
                if locked and self._running:
                    release()
            if attempt:
                break
            attempt = True
        pending = True
        attempt = False
        while True:
            try:
                pending = self._lease is not None or any(self._pinned)
                break
            except MemoryError as exc:
                fault = True
                exc.__traceback__ = exc.__context__ = exc.__cause__ = None
            if attempt:
                break
            attempt = True
        if pending:
            raise RuntimeError('two-fault cleanup pending')
        acquire()
        if self._cancelled:
            self.status = 'stopped'
        elif fault:
            self.status = 'invalid'
        code = None if taking or discarding else self.status
        if b._active is self:
            b._active = None
        self._running = False
        release()
        return code
    return invoke


class _SerialOwner(_UniqueOwner):
    @_serialized
    def discard(self):
        pass

    def _retire(self, index):
        handle = self._pinned[index]
        if handle is None:
            return
        b = self.budget
        acquire, release = b._lock.acquire, b._lock.release
        acquire()
        try:
            pins = handle._pins - 1
            if pins < 0:
                raise Reject('invalid')
            closing = pins == 0 and handle._closed == 2
            if closing:
                lease = handle._lease
                budget_worker = b._worker - lease.worker
                budget_metadata = b._metadata - lease.metadata
            handle._pins = pins
            if closing:
                b._worker = budget_worker
                b._metadata = budget_metadata
                lease.worker = lease.metadata = 0
                lease.closed = True
            self._pinned[index] = None
        finally:
            release()

    def _unwind(self):
        attempt = False
        while True:
            try:
                self._dispose()
                return
            except MemoryError as exc:
                self.status = 'invalid'
                exc.__traceback__ = exc.__context__ = exc.__cause__ = None
            if attempt:
                break
            attempt = True
        raise RuntimeError('two-fault constructor cleanup')


class Builder(_SerialOwner):
    """Sliced config discovery; retained paths never contain mutable source refs."""

    def __init__(self, config, lock, model, *, budget, quantum=512):
        if type(config) is not dict or type(model) is not BackgroundReadModel:
            raise TypeError('trusted owners required')
        if type(lock) not in (type(threading.Lock()), type(threading.RLock())):
            raise TypeError('trusted config lock required')
        if type(budget) is not RedactionBudget:
            raise TypeError('budget required')
        if type(quantum) is not int or not 1 <= quantum <= 512:
            raise ValueError('quantum')
        self.budget = budget
        self._lease = None
        self._running = self._cancelled = False
        self.status = 'more'
        self.config = self.lock = self.model = None
        self.frames = self.found = self._pinned = self._dependencies = ()
        self.catalog = self.pending = self.plan = self.finalize_gen = self.result = None
        self.secret_bytes = self.visits = 0
        self.slices = self.max_slice_steps = self.hash_bytes = self.root_scans = 0
        self.max_slice_s = self.metadata_peak = self.max_slice_visits = 0
        try:
            budget.reserve(worker=2097152, metadata=4096, _owner=self)
            self.config, self.lock, self.model = config, lock, model
            self.quantum = quantum
            self.metadata_peak = self._lease.metadata
            config = lock = model = None
            return
        except (Reject, MemoryError) as exc:
            self.status = exc.args[0] if type(exc) is Reject else 'invalid'
            exc.__traceback__ = exc.__context__ = exc.__cause__ = None
        config = lock = model = None
        if self._lease is not None:
            retry = False
            try:
                self._unwind()
            except MemoryError as exc:
                self.status = 'invalid'
                exc.__traceback__ = exc.__context__ = exc.__cause__ = None
                retry = True
            if retry:
                self._unwind()

    def _initialize_control(self):
        try:
            self._dependencies = ()
            self._pinned = []
            self._phase = 0
            self.result = self.finalize_gen = self.catalog = None
            self.frames = [((), 0, False, False)]
            self.found = set()
            self.token = self.pending = self.plan = None
            self.steps = 0
            self._slice_visits = self._progress = 0
            self._prepared = False
        except MemoryError:
            self._pinned = self.frames = self.found = ()
            raise

    def visit(self, n=1):
        if self._slice_visits + n > 512:
            raise _SliceFull()
        self.budget.visit(n)
        self.visits += n
        self._slice_visits += n
        self.max_slice_visits = max(self.max_slice_visits, self._slice_visits)

    def authority(self):
        revision = self.config.get('_config_revision', self.config.get('config_revision', 0))
        if type(revision) is not int or not 0 <= revision <= 9007199254740991:
            raise Reject('invalid')
        service = self.config.get('_config_service')
        if service is not None:
            if type(service) is not ConfigService:
                raise Reject('invalid')
            if service.read_model is not self.model:
                raise Reject('mutation')
        if self.model._stopped:
            raise Reject('stopped')
        epoch = self.model._epoch
        if type(epoch) is not int or not 0 <= epoch <= 9007199254740991:
            raise Reject('invalid')
        return revision, security_projection_revision(self.config), id(self.model), epoch

    def own_key(self, key):
        if type(key) is not str:
            raise Reject('invalid')
        self._lease.reserve(metadata=128 + 8 * len(key))
        self.metadata_peak = max(self.metadata_peak, self._lease.metadata)
        data = bytearray()
        for i in range(0, len(key), 1024):
            # The catalog/path key visit covers its first chunk only.
            if i:
                self.visit()
            if time.monotonic() >= self.slice_end:
                raise Reject('deadline')
            data.extend(key[i:i + 1024].encode('utf8'))
        return data.decode('utf8')

    def roots(self):
        if len(self.config) > 512 - self._slice_visits:
            raise Reject('deadline')
        if len(self.config) > VISITS - self.budget.visits:
            raise Reject('capacity')
        self.root_scans += 1
        if self.catalog is None:
            keys = []
            for key in self.config:
                if time.monotonic() >= self.slice_end:
                    raise Reject('deadline')
                self.visit()
                keys.append(self.own_key(key))
            self.catalog = tuple(keys)
        else:
            if len(self.config) != len(self.catalog):
                raise Reject('mutation')
            for index, key in enumerate(self.config):
                if time.monotonic() >= self.slice_end:
                    raise Reject('deadline')
                self.visit()
                if type(key) is not str:
                    raise Reject('invalid')
                if len(key) != len(self.catalog[index]) or key != self.catalog[index]:
                    raise Reject('mutation')
        if time.monotonic() >= self.slice_end:
            raise Reject('deadline')

    def resolve(self, path):
        value = self.config
        ids = {id(value)}
        self.visit()
        for part in path:
            if type(value) is dict and value is not self.config:
                # Items traversal never hashes a query against unadmitted keys.
                for key, child in value.items():
                    self.visit()
                    if time.monotonic() >= self.slice_end:
                        raise Reject('deadline')
                    if type(key) is not str:
                        raise Reject('invalid')
                    if key == part:
                        value = child
                        break
                else:
                    raise Reject('mutation')
            elif _is(type(value), dict, list, tuple):
                value = value[part]
            else:
                raise Reject('invalid')
            self.visit()
            if _is(type(value), dict, list, tuple):
                if id(value) in ids:
                    raise Reject('invalid')
                ids.add(id(value))
        return value

    def finish_secret(self):
        _, _, data = self.pending
        text = data.decode('utf8')
        if text and text not in self.found:
            if len(self.found) >= SECRETS or self.secret_bytes + len(data) > SECRET_BYTES:
                raise Reject('capacity')
            self._lease.reserve(metadata=512 + 8 * len(data))
            self.metadata_peak = max(self.metadata_peak, self._lease.metadata)
            self.found.add(text)
            self.secret_bytes += len(data)
        self.pending = None

    def walk_locked(self):
        cache = {(): self.config}
        while self.frames and self.steps < self.quantum and time.monotonic() < self.slice_end:
            # Each traversal/copy iteration consumes the same allowance as
            # root/path validation; inner enumerations charge additionally.
            self.visit()
            self.steps += 1
            path, index, sensitive, entered = self.frames[-1]
            if len(path) > DEPTH:
                raise Reject('capacity')
            if path not in cache:
                cache[path] = self.resolve(path)
            value = cache[path]
            kind = type(value)
            if not entered:
                if not _is(kind, dict, list, tuple, str) and issubclass(kind, (dict, list, tuple, str)):
                    raise Reject('invalid')
                self.frames[-1] = (path, index, sensitive, True)
                self._progress += 1
                if _is(kind, dict, list, tuple):
                    if len(value) > VISITS - self.budget.visits:
                        raise Reject('capacity')
                elif kind is str and sensitive and value:
                    if len(value) > SECRET_BYTES:
                        raise Reject('capacity')
                    self.pending = (path, 0, bytearray())
                else:
                    self.frames.pop()
                    cache.pop(path, None)
                    continue
            if kind is str:
                p, offset, data = self.pending
                chunk = value[offset:offset + 1024].encode('utf8')
                if len(data) + len(chunk) > SECRET_BYTES:
                    raise Reject('capacity')
                data.extend(chunk)
                offset += min(1024, len(value) - offset)
                self.pending = (p, offset, data)
                self._progress += 1
                if offset == len(value):
                    self.finish_secret()
                    self.frames.pop()
                    cache.pop(path, None)
                continue
            if index == len(value):
                self._progress += 1
                self.frames.pop()
                cache.pop(path, None)
                continue
            if kind is dict:
                if not path:
                    key = self.catalog[index]
                    self.visit()
                    child = value[key]
                else:
                    for j, (key, child) in enumerate(value.items()):
                        if time.monotonic() >= self.slice_end:
                            raise Reject('deadline')
                        self.visit()
                        if j == index:
                            break
                    key = self.own_key(key)
                child_sensitive = sensitive or key in SECRET_KEYS
                part = key
            else:
                part, child, child_sensitive = index, value[index], sensitive
            if _is(type(child), dict, list, tuple) and any(child is cache.get(p) for p, _, _, _ in self.frames):
                raise Reject('invalid')
            self.frames[-1] = (path, index + 1, sensitive, True)
            self._progress += 1
            child_path = path + (part,)
            self.frames.append((child_path, 0, child_sensitive, False))
            cache[child_path] = child
        cache.clear()

    def cleanup(self, abort=True):
        gen = getattr(self, 'finalize_gen', None)
        if gen is not None:
            gen.close()
            self.finalize_gen = None
        self.frames.clear()
        self.catalog = self.pending = self.plan = None
        self.found.clear()
        self.config = self.model = self.lock = None
        if abort:
            self.result = None
            if self._lease is not None:
                self._lease.close()
                self._lease = None

    _dispose = cleanup

    @_serialized
    def slice(self):
        if self.status != 'more':
            return
        acquired = condition = False
        start = time.monotonic()
        self.steps = 0
        self._slice_visits = 0
        try:
            acquired = self.lock.acquire(timeout=min(ACQUIRE, max(0, self.budget._deadline - time.monotonic())))
            if not acquired:
                raise Reject('lock_busy')
            self.budget.check()
            condition = self.model._condition.acquire(False)
            if not condition:
                raise Reject('lock_busy')
            self.slice_end = min(time.monotonic() + SLICE, self.budget._deadline)
            self.roots()
            token = self.authority()
            if self.token is None:
                self.token = token
            elif token != self.token:
                raise Reject('mutation')
            progress = self._progress
            try:
                self.walk_locked()
            except _SliceFull as exc:
                exc.__traceback__ = exc.__context__ = exc.__cause__ = None
            if self.frames and self._progress == progress:
                raise Reject('deadline')
            if not self.frames:
                self.status = 'captured'
        finally:
            if condition:
                self.model._condition.release()
            if acquired:
                self.lock.release()
        self.slices += 1
        self.max_slice_s = max(self.max_slice_s, time.monotonic() - start)
        self.max_slice_steps = max(self.max_slice_steps, self.steps)

    def prepare(self):
        rows = []
        for secret in sorted(self.found, key=len, reverse=True):
            digest = hashlib.sha256()
            for i in range(0, len(secret), 1024):
                data = secret[i:i + 1024].encode('utf8')
                digest.update(data)
                self.hash_bytes += len(data)
                yield None
            rows.append((secret, 'redacted-' + digest.hexdigest()[:12]))
        return tuple(rows)

    def fence(self):
        """Called with the shared operation slot, fresh config/model ownership."""
        acquired = condition = False
        try:
            self.budget.check()
            acquired = self.lock.acquire(timeout=min(ACQUIRE, max(0, self.budget._deadline - time.monotonic())))
            if not acquired:
                raise Reject('lock_busy')
            self.budget.check()
            condition = self.model._condition.acquire(False)
            if not condition:
                raise Reject('lock_busy')
            self.slice_end = min(time.monotonic() + SLICE, self.budget._deadline)
            self.roots()
            if self.authority() != self.token:
                raise Reject('mutation')
        finally:
            if condition:
                self.model._condition.release()
            if acquired:
                self.lock.release()

    @_serialized
    def seal_slice(self):
        if self.status != 'captured':
            return
        self._slice_visits = 0
        self.fence()
        # A completed digest may await its fresh final fence in the next call.
        if not self._prepared:
            if self.finalize_gen is None:
                self.finalize_gen = self.prepare()
            before = self._slice_visits
            end = min(time.monotonic() + SLICE, self.budget._deadline)
            for _ in range(min(self.quantum, 512 - self._slice_visits)):
                self.budget.check()
                if time.monotonic() >= end:
                    break
                self.visit()
                try:
                    next(self.finalize_gen)
                except StopIteration as done:
                    self.result = done.value
                    self.finalize_gen = None
                    self._prepared = True
                    done.__traceback__ = done.__context__ = done.__cause__ = None
                    break
            if self._slice_visits == before:
                raise Reject('deadline')
            if not self._prepared or len(self.catalog) > 512 - self._slice_visits:
                return
            self.fence()
        self.plan = Plan(self.token, self.result, self.visits, self.secret_bytes, self.metadata_peak)
        self.result = None
        self.status = 'done'

    @_serialized
    def take(self):
        self._slice_visits = 0
        self.fence()
        plan = Plan(self.token, self.plan.replacements, self.visits, self.secret_bytes, self.metadata_peak)
        handle = OwnedPlan(plan, None, _MINT)
        self.result = handle
        self._phase = 1
        plan = None
        self.cleanup(False)
        return handle

    def counters(self):
        return {key: getattr(self, key) for key in ('visits', 'secret_bytes', 'slices', 'max_slice_s',
                'max_slice_steps', 'max_slice_visits', 'hash_bytes', 'root_scans', 'metadata_peak', 'status')}


class OwnedPayload(_Owned):
    """An exclusively owned, preflighted builtin graph; admission does not clone.

    The caller relinquishes mutation rights. This is not the future bounded
    capture decoder: that producer must pre-admit its allocations in this ledger.
    """

    @property
    def output_cap(self):
        """Serialization ceiling, carried across projection ownership transfers."""
        return getattr(self, '_output_cap', 1048576)

    @classmethod
    def admit_sliced(cls, value, *, budget):
        """Preflight an already owned graph cooperatively, not capture/decode.

        The scheduler calls slice until done, then take once. The historical
        synchronous admit remains for callers explicitly choosing that contract.
        """
        if cls is not OwnedPayload or type(budget) is not RedactionBudget:
            raise TypeError('budget required')
        return _Admission(value, budget)

    @classmethod
    def admit(cls, value, *, budget):
        if type(budget) is not RedactionBudget or cls is not OwnedPayload:
            raise TypeError('budget required')
        owner = object()
        lease = shell = preflight = active = None
        code = None
        entered = False
        acquire, release = budget._lock.acquire, budget._lock.release
        try:
            budget.enter(owner)
            entered = True
            lease = budget.reserve(worker=16384, metadata=8192)
            nodes = 0
            active = set()

            def preflight(item, depth):
                nonlocal nodes
                budget.check()
                nodes += 1
                if nodes > 4096 or depth > DEPTH:
                    raise Reject('capacity')
                kind = type(item)
                lease.reserve(metadata=32)
                if kind is str:
                    if len(item) > 1048576:
                        raise Reject('capacity')
                    lease.reserve(worker=128 + 4 * len(item))
                    for i in range(0, len(item), 1024):
                        budget.check()
                        item[i:i + 1024].encode('utf8')
                elif _is(kind, dict, list, tuple):
                    if id(item) in active:
                        raise Reject('invalid')
                    if len(item) > 4096 - nodes:
                        raise Reject('capacity')
                    lease.reserve(worker=256 + 128 * len(item))
                    active.add(id(item))
                    if kind is dict:
                        for key, child in item.items():
                            if type(key) is not str:
                                raise Reject('invalid')
                            preflight(key, depth + 1)
                            preflight(child, depth + 1)
                    else:
                        for child in item:
                            preflight(child, depth + 1)
                    active.remove(id(item))
                elif _is(kind, type(None), bool, int, float):
                    if kind is int and item.bit_length() > 128:
                        raise Reject('invalid')
                    if kind is float and not math.isfinite(item):
                        raise Reject('invalid')
                    lease.reserve(worker=128)
                else:
                    raise Reject('invalid')

            preflight(value, 0)
            shell = cls(value, None, _MINT)
            preflight = active = None
            acquire()
            try:
                budget.check()
            except BaseException:
                release()
                raise
            shell._lease = lease
            lease = value = None
            budget._active = None
            entered = False
            release()
            return shell
        except (Reject, UnicodeError, MemoryError) as exc:
            code = exc.args[0] if type(exc) is Reject else 'invalid'
            exc.__traceback__ = exc.__context__ = exc.__cause__ = None
        value = preflight = active = shell = None
        attempt = False
        while True:
            try:
                if lease is not None:
                    lease.close()
                    lease = None
                break
            except MemoryError as exc:
                code = 'invalid'
                exc.__traceback__ = exc.__context__ = exc.__cause__ = None
            if attempt:
                break
            attempt = True
        if lease is not None:
            raise RuntimeError('two-fault unreturned admission')
        acquire()
        if entered and budget._active is owner:
            budget._active = None
        release()
        owner = None
        raise Reject(code) from None


class _Operation(_SerialOwner):
    """Sliced operations retain their output lease until a single-use take."""

    def _initialize(self, budget):
        # Effect-free bootstrap only; acquisition belongs to the caller's guard.
        self.budget = budget
        self._running = self._cancelled = False
        self._lease = None
        self.status = 'more'
        self.steps = self.slices = 0
        self.max_slice_s = 0

    def _initialize_control(self):
        try:
            self._dependencies = ()
            self._pinned = [None, None] if type(self) is Projector else [None]
            self._phase = 0
            self.result = None
            self.gen = None
            self.output_cap = 1048576
            if type(self) is Projector:
                self.nodes = 0
                self.preflights = []
            else:
                self.record_json = False
        except MemoryError:
            # Retire partial control storage before reserve releases its hold.
            self._pinned = ()
            raise

    def _check_dependencies(self):
        for handle in self._dependencies:
            handle.value

    def _clear(self, abort=True):
        if self.gen is not None:
            self.gen.close()
            self.gen = None
        if abort:
            self.result = None
        if self._pinned:
            self._retire(0)
            if len(self._pinned) == 2:
                self._retire(1)
        if abort:
            self._dependencies = ()
            if self._lease is not None:
                self._lease.close()
                self._lease = None

    _dispose = _clear

    @_serialized
    def slice(self):
        if self.status != 'more':
            return
        start = time.monotonic()
        before = self.steps
        self._check_dependencies()
        for _ in range(512):
            self.budget.check()
            if time.monotonic() - start >= SLICE:
                break
            try:
                next(self.gen)
                self.steps += 1
            except StopIteration as done:
                self.result = done.value
                self.gen = None
                self.status = 'done'
                done.__traceback__ = done.__context__ = done.__cause__ = None
                break
        if self.status == 'more' and self.steps == before:
            raise Reject('deadline')
        self.slices += 1
        self.max_slice_s = max(self.max_slice_s, time.monotonic() - start)

    @_serialized
    def take(self):
        self._check_dependencies()
        handle = self._output_type(self.result, None, _MINT)
        if type(handle) is OwnedPayload:
            handle._output_cap = self.output_cap
        self.result = handle
        self._phase = 1
        self._clear(False)
        return handle

    def counters(self):
        return {'steps': self.steps, 'slices': self.slices, 'max_slice_s': self.max_slice_s,
                'status': self.status, **self.budget.counters()}


class _Admission(_Operation):
    """Owned resumable validation state; never borrows mutable config roots."""
    _output_type = OwnedPayload

    def __init__(self, value, budget):
        self._initialize(budget)
        try:
            budget.reserve(worker=16384, metadata=8192, _owner=self)
            self.gen = self.run(value)
            value = None
            return
        except (Reject, MemoryError) as exc:
            self.status = exc.args[0] if type(exc) is Reject else 'invalid'
            exc.__traceback__ = exc.__context__ = exc.__cause__ = None
        value = None
        if self._lease is not None:
            retry = False
            try:
                self._unwind()
            except MemoryError as exc:
                self.status = 'invalid'
                exc.__traceback__ = exc.__context__ = exc.__cause__ = None
                retry = True
            if retry:
                self._unwind()

    def _initialize_control(self):
        self._dependencies = ()
        self._pinned = []
        self._phase = 0
        self.result = self.gen = None
        self.steps = self.slices = self.nodes = 0
        self.max_slice_s = 0
        self.output_cap = 1048576

    def run(self, value):
        yield from self.preflight(value, 0, set())
        return value

    def preflight(self, item, depth, active):
        self.nodes += 1
        if self.nodes > 4096 or depth > DEPTH:
            raise Reject('capacity')
        self._lease.reserve(metadata=32)
        yield None
        kind = type(item)
        if kind is str:
            if len(item) > 1048576:
                raise Reject('capacity')
            self._lease.reserve(worker=128 + 4 * len(item))
            for i in range(0, len(item), 1024):
                item[i:i + 1024].encode('utf8')
                yield None
        elif _is(kind, dict, list, tuple):
            if id(item) in active:
                raise Reject('invalid')
            if len(item) > 4096 - self.nodes:
                raise Reject('capacity')
            self._lease.reserve(worker=256 + 128 * len(item))
            active.add(id(item))
            if kind is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise Reject('invalid')
                    yield from self.preflight(key, depth + 1, active)
                    yield from self.preflight(child, depth + 1, active)
            else:
                for child in item:
                    yield from self.preflight(child, depth + 1, active)
            active.remove(id(item))
        elif _is(kind, type(None), bool, int, float):
            if kind is int and item.bit_length() > 128:
                raise Reject('invalid')
            if kind is float and not math.isfinite(item):
                raise Reject('invalid')
            self._lease.reserve(worker=128)
        else:
            raise Reject('invalid')


def _arguments(budget, output_cap, handles):
    if type(budget) is not RedactionBudget:
        raise TypeError('budget required')
    if type(output_cap) is not int or not 1 <= output_cap <= 1048576:
        raise ValueError('output cap')
    for handle, kind in handles:
        if type(handle) is not kind:
            raise TypeError('owned handle required')
        if handle.budget is not budget:
            raise ValueError('cross-budget handle')
        handle.value


class Projector(_Operation):
    """Exactly one sequential legacy projection of an admitted owned unit."""

    _output_type = OwnedPayload

    def __init__(self, owned_plan, owned_payload, *, budget, output_cap=1048576):
        _arguments(budget, output_cap, ((owned_plan, OwnedPlan), (owned_payload, OwnedPayload)))
        self._initialize(budget)
        try:
            budget.reserve(worker=16384, metadata=8192, _owner=self)
            self.output_cap = min(output_cap, owned_payload.output_cap)
            self._dependencies = (owned_plan, owned_payload)
            owned_plan._pin(self._pinned, 0)
            owned_payload._pin(self._pinned, 1)
            self.gen = self.project(owned_payload.value, owned_plan.value.replacements, 0, set())
            owned_plan = owned_payload = None
            return
        except (Reject, MemoryError) as exc:
            self.status = exc.args[0] if type(exc) is Reject else 'invalid'
            exc.__traceback__ = exc.__context__ = exc.__cause__ = None
        owned_plan = owned_payload = None
        if self._lease is not None:
            retry = False
            try:
                self._unwind()
            except MemoryError as exc:
                self.status = 'invalid'
                exc.__traceback__ = exc.__context__ = exc.__cause__ = None
                retry = True
            if retry:
                self._unwind()

    def utf8size(self, text):
        total = 0
        for i in range(0, len(text), 1024):
            total += len(text[i:i + 1024].encode('utf8'))
            yield None
        return total

    def matches(self, text, secret):
        pos = 0
        while pos <= len(text) - len(secret):
            end = min(len(text), pos + 1024 + len(secret) - 1)
            hit = text.find(secret, pos, end)
            yield hit
            pos = hit + len(secret) if hit >= 0 else pos + 1024

    def string(self, text, replacements):
        current_charge = 128 + 4 * len(text)
        self._lease.reserve(worker=current_charge)
        nbytes = yield from self.utf8size(text)
        for secret, replacement in replacements:
            if len(secret) < 4 and text != secret:
                continue
            count = 0
            for hit in self.matches(text, secret):
                count += hit >= 0
                yield None
            if not count:
                continue
            secret_bytes = yield from self.utf8size(secret)
            new_chars = len(text) + count * (len(replacement) - len(secret))
            new_bytes = nbytes + count * (len(replacement) - secret_bytes)
            charge = 256 + new_bytes + 4 * new_chars + 8192
            if len(self.preflights) == 16:
                self.preflights.pop(0)
            self.preflights.append({'input_bytes': nbytes, 'output_bytes': new_bytes,
                                    'required': self.budget.counters()['worker_bytes'] + charge,
                                    'limit': self.budget.worker_capacity})
            self._lease.reserve(worker=charge)
            out = bytearray(new_bytes)
            cursor = begin = 0
            for hit in self.matches(text, secret):
                if hit >= 0:
                    for i in range(begin, hit, 1024):
                        chunk = text[i:min(i + 1024, hit)].encode('utf8')
                        out[cursor:cursor + len(chunk)] = chunk
                        cursor += len(chunk)
                        yield None
                    chunk = replacement.encode('utf8')
                    out[cursor:cursor + len(chunk)] = chunk
                    cursor += len(chunk)
                    begin = hit + len(secret)
                yield None
            for i in range(begin, len(text), 1024):
                chunk = text[i:i + 1024].encode('utf8')
                out[cursor:cursor + len(chunk)] = chunk
                cursor += len(chunk)
                yield None
            assert cursor == new_bytes
            new = out.decode('utf8')
            del out
            new_charge = 128 + 4 * len(new)
            # Keep the new result's charge continuously, never release then
            # re-reserve a slot that a sibling could acquire.
            text = new
            chunk = None
            self._lease.release(worker=current_charge + charge - new_charge)
            current_charge = new_charge
            nbytes = new_bytes
        return text

    def project(self, value, replacements, depth, active):
        self.nodes += 1
        if self.nodes > 4096 or depth > DEPTH:
            raise Reject('capacity')
        self._lease.reserve(metadata=32)
        yield None
        kind = type(value)
        if kind is str:
            return (yield from self.string(value, replacements))
        if _is(kind, dict, list, tuple):
            if id(value) in active:
                raise Reject('invalid')
            if len(value) > 4096 - self.nodes:
                raise Reject('capacity')
            self._lease.reserve(worker=256 + 128 * len(value))
            active.add(id(value))
            if kind is dict:
                out = {}
                for key, child in value.items():
                    if type(key) is not str:
                        raise Reject('invalid')
                    projected_key = yield from self.project(key, replacements, depth + 1, active)
                    projected_value = yield from self.project(child, replacements, depth + 1, active)
                    out[projected_key] = projected_value
            else:
                out = []
                for child in value:
                    out.append((yield from self.project(child, replacements, depth + 1, active)))
            active.remove(id(value))
            return out
        if not _is(kind, type(None), bool, int, float):
            raise Reject('invalid')
        if kind is int and value.bit_length() > 128:
            raise Reject('invalid')
        if kind is float and not math.isfinite(value):
            raise Reject('invalid')
        self._lease.reserve(worker=128)
        return value


class OwnedBytes(_Owned):
    """Encoded immutable bytes; not an HTTP write permission."""


class Encoding(_Operation):
    """Compact UTF8 JSON with charged bounded escapes and transfer duplication.

    record_json encodes the JSON text a second time. It never sanitizes again.
    """

    _output_type = OwnedBytes

    def __init__(self, owned_projected_payload, *, budget, output_cap=1048576, record_json=False):
        if type(record_json) is not bool:
            raise TypeError('record_json')
        _arguments(budget, output_cap, ((owned_projected_payload, OwnedPayload),))
        self._initialize(budget)
        self.assemblies = self.output_bytes = self.emitted_bytes = 0
        try:
            budget.reserve(worker=16384, metadata=8192, _owner=self)
            self.output_cap = min(output_cap, owned_projected_payload.output_cap)
            self.record_json = record_json
            self._dependencies = (owned_projected_payload,)
            owned_projected_payload._pin(self._pinned, 0)
            self.gen = self.run(owned_projected_payload.value)
            owned_projected_payload = None
            return
        except (Reject, MemoryError) as exc:
            self.status = exc.args[0] if type(exc) is Reject else 'invalid'
            exc.__traceback__ = exc.__context__ = exc.__cause__ = None
        owned_projected_payload = None
        if self._lease is not None:
            retry = False
            try:
                self._unwind()
            except MemoryError as exc:
                self.status = 'invalid'
                exc.__traceback__ = exc.__context__ = exc.__cause__ = None
                retry = True
            if retry:
                self._unwind()

    def emit(self, value):
        kind = type(value)
        if kind is str:
            yield b'"'
            for i in range(0, len(value), 1024):
                yield json.dumps(value[i:i + 1024], ensure_ascii=False)[1:-1].encode('utf8')
            yield b'"'
        elif kind is dict:
            yield b'{'
            for i, (key, child) in enumerate(value.items()):
                if i:
                    yield b','
                yield from self.emit(key)
                yield b':'
                yield from self.emit(child)
            yield b'}'
        elif _is(kind, list, tuple):
            yield b'['
            for i, child in enumerate(value):
                if i:
                    yield b','
                yield from self.emit(child)
            yield b']'
        elif _is(kind, type(None), bool, int, float):
            yield json.dumps(value, allow_nan=False, separators=(',', ':')).encode('utf8')
        else:
            raise Reject('invalid')

    def assemble(self, value):
        # Includes bytearray overallocation, transfer copy, and worst-case
        # 1024-codepoint UCS4/escaped JSON/UTF8 scratch BEFORE any chunk allocation.
        charge = 4 * self.output_cap + 65536
        self._lease.reserve(worker=charge)
        self.assemblies += 1
        out = bytearray()
        for chunk in self.emit(value):
            if len(out) + len(chunk) > self.output_cap:
                raise Reject('capacity')
            out.extend(chunk)
            self.emitted_bytes += len(chunk)
            yield None
        result = bytes(out)
        del out
        chunk = None
        self._lease.release(worker=charge - (128 + len(result)))
        return result

    def run(self, value):
        inner = yield from self.assemble(value)
        if self.record_json:
            self._lease.reserve(worker=128 + 4 * len(inner))
            result = yield from self.assemble(inner.decode('utf8'))
        else:
            result = inner
        self.output_bytes = len(result)
        return result

    def counters(self):
        return {**super().counters(), 'assemblies': self.assemblies,
                'output_bytes': self.output_bytes, 'emitted_bytes': self.emitted_bytes}
