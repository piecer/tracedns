"""Sliced, selected capture. This module is not an HTTP publication capability.

Frames contain owned paths/offsets, never borrowed nested graphs. All source
access occurs under config -> state -> publication ownership. The approved
stored-key scan precedes *every* hashed source lookup. Complete-path validation
retains only bounded owned paths/counts under the attempt's fresh authority;
config and selected metadata are freshly scanned. Output transfers once.
"""
from dataclasses import dataclass
from functools import wraps
import json
import math
import threading
import time

from http_api.read_model import BackgroundReadModel
from monitor.config_service import ConfigService
from monitor.projection_authority import security_projection_revision
from monitor.runtime_state import get_state_version, state_lock
from security.derived_redaction import HEADER, RedactionBudget, Reject

_META = (('nxdomain_active', False), ('nxdomain_since', 0),
         ('nxdomain_first_seen', 0), ('nxdomain_cleared_ts', 0),
         ('dns_error_only_active', False))
_LIMITS = dict(visits=262144, descriptors=16384, nodes=4096, depth=32,
               dict_members=128, list_members=4096, slice_visits=512,
               slice_bytes=16384, slice_steps=512, workspace=16 * 1024 * 1024)
_LOCK_TYPES = (type(threading.Lock()), type(threading.RLock()))


class _Stop(Exception):
    """Finite internal reason only; never exported or retained."""


class _Yield(Exception):
    pass


def _key(key):
    if type(key) is not str:
        raise _Stop('invalid')
    if len(key) > 256:
        raise _Stop('capacity')
    # Exact str, <=256 codepoints: encoding is bounded before allocation.
    data = key.encode('utf-8')
    if len(data) > 1024:
        raise _Stop('capacity')
    return data.decode('utf-8')


def _argument_key(key):
    try:
        return _key(key)
    except (_Stop, UnicodeError):
        raise ValueError('invalid key') from None


@dataclass(frozen=True)
class CaptureOwners:
    config: dict
    lock: object
    current: dict
    history: dict
    model: object

    def __post_init__(self):
        if type(self.lock) not in _LOCK_TYPES or type(self.model) is not BackgroundReadModel:
            raise TypeError('trusted application lock/model required')


class CaptureBudget:
    """One single-threaded attempt; unit release never refunds work or time."""

    def __init__(self, kind='prepared', clock=time.monotonic, *, ledger=None):
        if type(kind) is not str or kind not in ('prepared', 'search'):
            raise ValueError('invalid capture kind')
        if not callable(clock):
            raise TypeError('clock must be callable')
        if ledger is not None and type(ledger) is not RedactionBudget:
            raise TypeError('exact ledger required')
        self.ledger, self._lease = ledger, None
        self.kind, self.clock = kind, clock
        self.status = 'more'
        self._closed = False
        self.deadline = self.now() + 5 if ledger is None else ledger.deadline
        self.visits = self.descriptors = self.examined_bytes = self.workspace = 0
        self.peak_workspace = 0
        self._unit = self._running = self._authority = self._owners = None
        self._controller = None
        self._cancelled = False
        self.limits = self._validated_roots = ()
        if ledger is None:
            self._initialize_control()
        else:
            try:
                ledger.reserve(worker=32768, metadata=32768, _owner=self)
            except (Reject, MemoryError) as exc:
                self.status = exc.args[0] if type(exc) is Reject else 'capacity'
                exc.__traceback__ = exc.__context__ = exc.__cause__ = None
                self._closed = self._cancelled = True

    def _initialize_control(self):
        try:
            self.limits = dict(_LIMITS, examined_bytes=(64 if self.kind == 'prepared' else 32) * 1024 * 1024)
            self._validated_roots = set()
        except MemoryError:
            self.limits = self._validated_roots = ()
            raise

    @classmethod
    def for_test(cls, *, kind='prepared', clock=time.monotonic, ledger=None, **limits):
        """Explicit lower-only test seam. Production constructors have no knobs."""
        result = cls(kind, clock, ledger=ledger)
        for name, value in limits.items():
            if name not in result.limits or type(value) is not int or not 1 <= value <= result.limits[name]:
                raise ValueError('test limits may only lower production ceilings')
            result.limits[name] = value
        return result

    def now(self):
        value = self.clock() if self.ledger is None else time.monotonic()
        try:
            finite = type(value) in (int, float) and math.isfinite(value)
        except OverflowError:
            finite = False
        if not finite:
            raise ValueError('invalid clock')
        return value

    def cancel(self):
        self._cancelled = True

    def check(self):
        if self._cancelled:
            raise _Stop('stopped')
        if self.ledger is not None:
            try:
                self.ledger.check()
            except Reject as exc:
                raise _Stop(exc.args[0]) from None
        if self.now() >= self.deadline:
            raise _Stop('deadline')

    def close(self):
        self._closed = self._cancelled = True
        if self._running is not None or self._controller is not None:
            return
        if self._unit is not None:
            self._unit.discard()
        self._authority = self._owners = None
        if self._validated_roots:
            self._validated_roots.clear()
        if self._lease is not None:
            self._lease.close()
            self._lease = None

    def counters(self):
        return dict(visits=self.visits, descriptors=self.descriptors,
                    examined_bytes=self.examined_bytes, workspace=self.workspace,
                    peak_workspace=self.peak_workspace, deadline=self.deadline)


def _shared_call(method):
    """Shared-mode lifetime guard; standalone capture retains its contract."""
    @wraps(method)
    def call(self):
        b = self.budget
        if b.ledger is None:
            return method(self)
        taking = method.__name__ in ('take', 'next_key')
        discarding = method.__name__ == 'discard'
        with b.ledger._lock:
            if b._controller is not None:
                if discarding and b._controller is self:
                    self._cancelled = True
                return None if taking else 'lock_busy'
            b._controller = self
        result = None
        try:
            try:
                result = method(self)
            except (MemoryError, Reject) as exc:
                self.status = exc.args[0] if type(exc) is Reject else 'capacity'
                exc.__traceback__ = exc.__context__ = exc.__cause__ = None
            retry = False
            while True:
                try:
                    if self._cancelled or b._cancelled:
                        self.status = 'stopped'
                        result = None
                    if self._retiring or self.status not in ('more', 'done'):
                        self._clear()
                    break
                except MemoryError as exc:
                    self.status = 'capacity'
                    result = None
                    exc.__traceback__ = exc.__context__ = exc.__cause__ = None
                if retry:
                    raise RuntimeError('two-fault capture cleanup')
                retry = True
        finally:
            with b.ledger._lock:
                if b.ledger._active is self:
                    b.ledger._active = None
                b._controller = None
            if b._closed:
                b.close()
        return result if taking else self.status
    return call


class Capture:
    @staticmethod
    def validate(owners, root_name, path, *, budget, unit_bytes=65536,
                 skip_fields=(), projection='complete'):
        if type(owners) is not CaptureOwners or type(budget) is not CaptureBudget:
            raise TypeError('capture owners/budget required')
        if type(root_name) is not str or root_name not in ('current', 'history', 'config'):
            raise ValueError('invalid root')
        if type(path) is not tuple or not 1 <= len(path) <= 32:
            raise ValueError('invalid path')
        for part in path:
            if type(part) is str:
                _argument_key(part)
            elif type(part) is not int or part < 0 or part.bit_length() > 128:
                raise ValueError('invalid path part')
        if type(path[0]) is not str:
            raise ValueError('root key required')
        if type(unit_bytes) is not int or not 1 <= unit_bytes <= 1024 * 1024 - 16384:
            raise ValueError('invalid unit byte ceiling')
        if type(skip_fields) not in (set, frozenset, tuple) or len(skip_fields) > 128:
            raise ValueError('invalid skip fields')
        for key in skip_fields:
            _argument_key(key)
        if skip_fields and budget.kind == 'search':
            raise ValueError('search requires complete units')
        if type(projection) is not str or projection not in ('complete', 'prepared_meta'):
            raise ValueError('invalid projection')
        allowed = (root_name == 'current' or root_name == 'config' and path[0] == 'domains'
                   or root_name == 'history' and len(path) >= 2 and path[1] == 'events')
        if projection == 'prepared_meta':
            allowed = root_name == 'history' and len(path) == 2 and path[1] == 'meta' and not skip_fields
        if not allowed:
            raise ValueError('unsupported projection path')
        if budget._unit is not None:
            raise ValueError('another unit owns this budget')

    def __init__(self, owners, root_name, path, *, budget, unit_bytes=65536,
                 skip_fields=(), projection='complete'):
        self.validate(owners, root_name, path, budget=budget, unit_bytes=unit_bytes,
                      skip_fields=skip_fields, projection=projection)
        self.owners, self.root_name, self.budget = owners, root_name, budget
        self.path, self.skip_fields = (), frozenset()
        self.unit_bytes, self.projection = unit_bytes, projection
        self.status, self._sealed = 'more', False
        self._cancelled = self._retiring = False
        self._lease = None
        self._frames = self._buffer = self._checked = self._validated_paths = ()
        self._progress = 0
        self.visits = self.nodes = self.bytes = self.slices = 0
        self.max_slice_visits = self.max_slice_bytes = self.max_depth = 0
        self.max_slice_seconds = self.max_wait_seconds = self.peak_workspace = 0
        self._sv = self._sb = self._workspace = 0
        self._root_cursor = None
        self._meta_key_high_water = 0
        budget._unit = self
        try:
            self._reserve(1)
            self._frames = []
            self._buffer = bytearray()
            self._checked = set()
            self._validated_paths = {}
            self.path = tuple(_argument_key(p) if type(p) is str else p for p in path)
            self.skip_fields = frozenset(_argument_key(key) for key in skip_fields)
            self._frames.append(('value', self.path, 0))
        except (_Stop, Reject, MemoryError) as exc:
            self.status = 'capacity'
            exc.__traceback__ = exc.__context__ = exc.__cause__ = None
        if self.status != 'more':
            owners = path = skip_fields = None
            retry = False
            while True:
                try:
                    self._clear()
                    break
                except MemoryError as exc:
                    exc.__traceback__ = exc.__context__ = exc.__cause__ = None
                if retry:
                    raise RuntimeError('two-fault capture constructor')
                retry = True

    def _visit(self, count=1):
        if self.budget.visits + count > self.budget.limits['visits']:
            raise _Stop('capacity')
        if self._sv + count > self.budget.limits['slice_visits']:
            raise _Yield
        self.budget.visits += count
        self.visits += count
        self._sv += count

    def _keys(self, value, path=None):
        if type(value) is not dict:
            raise _Stop('invalid')
        # Stable-root certificates belong to the unchanged attempt authority.
        # Config must be checked first on EVERY ownership, even through aliases.
        if value is not self.owners.config:
            for name in self.budget._validated_roots:
                if value is getattr(self.owners, name):
                    return
        if id(value) in self._checked:
            return
        if len(value) > self.budget.limits['dict_members']:
            raise _Stop('capacity')
        # Constructor grammar limits complete paths to current, history events,
        # and config domains. Actual repository/engine observation publication
        # and ConfigService/ConfigStore fence their changes before unlock.
        # These certificates are local to this unit and its unchanged authority,
        # never shared by object id. Private config and prepared_meta (including
        # its entry/ignored keys) are freshly scanned, not presumed fenced.
        if path and self.projection == 'complete' and value is not self.owners.config:
            self._path_keys(value, path)
            self._checked.add(id(value))
            return
        # Charge every source iterator advance (including exhaustion) and
        # stored-key validation, not merely an outer Python loop iteration.
        self._visit(2 * len(value) + 1)
        for key in value:
            _key(key)
        self._checked.add(id(value))

    def _path_keys(self, value, path):
        size = len(value)
        length, offset = self._validated_paths.get(path, (size, 0))
        if length != size:
            offset = 0
        if offset == size and path in self._validated_paths and length == size:
            return
        # Reconstruct a LOCAL iterator. Replayed nexts are charged, but only
        # new validations advance the owned certificate. Never keep the source.
        room = self.budget.limits['slice_visits'] - self._sv
        count = min(size - offset, max(0, (room - offset - 1) // 2))
        if not count and offset < size:
            raise _Yield
        self._reserve(len(self._frames) + 2, len(self._validated_paths) + (path not in self._validated_paths))
        self._visit(offset + 2 * count + (offset + count == size))
        iterator = iter(value)
        for _ in range(offset):
            next(iterator)
        for _ in range(count):
            _key(next(iterator))
        offset += count
        if offset == size:
            next(iterator, None)
        self._validated_paths[path] = (size, offset)
        self._progress += 1
        if offset != size:
            raise _Yield

    def _lookup(self, value, key, default=None, path=None):
        self._keys(value, path)
        self._visit()
        return value.get(key, default)

    def _authority(self):
        config, model = self.owners.config, self.owners.model
        self._keys(config)
        self._visit(3)
        revision = config.get('_config_revision', 0)
        if type(revision) is not int or revision < 0 or revision.bit_length() > 128:
            raise _Stop('invalid')
        private = security_projection_revision(config)
        service = config.get('_config_service')
        if service is not None:
            if type(service) is not ConfigService or service.read_model is not model:
                raise _Stop('mutation' if type(service) is ConfigService else 'invalid')
        if model._stopped:
            raise _Stop('stopped')
        token = (get_state_version(), revision, private, id(model), model._epoch, model._stopped)
        budget = self.budget
        if budget._authority is None:
            budget._authority, budget._owners = token, self.owners
        elif budget._authority != token or budget._owners is not self.owners:
            raise _Stop('mutation')

    def _resolve(self, path):
        value = getattr(self.owners, self.root_name)
        if self.projection == 'prepared_meta':
            entry = self._lookup(value, path[0])
            meta = self._lookup(entry, 'meta') if type(entry) is dict else None
            if type(meta) is dict and len(meta):
                if len(meta) > self.budget.limits['dict_members']:
                    raise _Stop('capacity')
                self._keys(meta)
                extra = max(0, len(meta) - self._meta_key_high_water)
                if self.nodes + extra > self.budget.limits['nodes']:
                    raise _Stop('capacity')
                # These names include ignored metadata, so unlike ordinary
                # output members they would otherwise escape node admission.
                self.nodes += extra
                self._meta_key_high_water += extra
                self._visit(5)
                value = {key: meta.get(key, default) for key, default in _META}
            else:
                value = {}
            path = path[2:]
        for index, part in enumerate(path):
            if type(value) is dict and type(part) is str:
                sentinel = self
                value = self._lookup(value, part, sentinel, path[:index])
                if value is sentinel:
                    raise _Stop('invalid')
            elif type(value) in (list, tuple) and type(part) is int:
                self._visit()
                if not 0 <= part < len(value):
                    raise _Stop('invalid')
                value = value[part]
            else:
                raise _Stop('invalid')
        return value

    def _reserve(self, frames, certificates=None):
        # Conservative logical private workspace, not heap/RSS: frame/path/key
        # margins, slice-local key validation, buffer growth + transfer overlap,
        # and bounded escaping/encoding temporaries. Each of at most 32 active
        # ancestry certificates reserves another 64KiB for its <=32 owned keys,
        # path tuple, counters and mapping/temporary overlap. No source keylist.
        # Reserve BEFORE allocation.
        if certificates is None:
            certificates = len(self._validated_paths)
        amount = 262144 + (frames + certificates) * 65536 + 3 * self.unit_bytes + 32768
        if self.budget.workspace - self._workspace + amount > self.budget.limits['workspace']:
            raise _Stop('capacity')
        if self.budget.ledger is not None:
            # Original workspace remains occupied. Controls and certificates
            # additionally consume the independent metadata allowance.
            worker = amount + 65536
            metadata = 65536 + 8192 + 4096 * (frames + certificates)
            if self._lease is None:
                self._lease = self.budget.ledger.reserve(worker=worker, metadata=metadata)
            else:
                self._lease.reserve(worker=max(0, worker + HEADER - self._lease.worker),
                                    metadata=max(0, metadata + HEADER - self._lease.metadata))
        self.budget.workspace += amount - self._workspace
        self._workspace = amount
        self.peak_workspace = max(self.peak_workspace, amount)
        self.budget.peak_workspace = max(self.budget.peak_workspace, self.budget.workspace)

    def _emit(self, blob):
        size = len(blob)
        if self.bytes + size > self.unit_bytes or self.budget.examined_bytes + size > self.budget.limits['examined_bytes']:
            raise _Stop('capacity')
        if self._sb + size > self.budget.limits['slice_bytes']:
            raise _Yield
        self._buffer.extend(blob)
        self.bytes += size
        self._sb += size
        self.budget.examined_bytes += size

    def _step(self):
        kind, path, pos = self._frames[-1]
        # DFS needs only the active ancestry, not all previously visited paths.
        self._validated_paths = {p: state for p, state in self._validated_paths.items()
                                 if path[:len(p)] == p}
        self._visit()
        self._reserve(len(self._frames) + 2)
        value = self._resolve(path)
        typ = type(value)
        frames, nodes = [], 0
        if kind == 'value':
            nodes = 1
            if len(path) > self.budget.limits['depth']:
                raise _Stop('capacity')
            self.max_depth = max(self.max_depth, len(path))
            if type(path[-1]) is str and path[-1] in self.skip_fields:
                blob = b'[]'
            elif typ in (dict, list, tuple):
                limit = self.budget.limits['dict_members' if typ is dict else 'list_members']
                if len(value) > limit:
                    raise _Stop('capacity')
                if len(path) >= self.budget.limits['depth'] and len(value):
                    raise _Stop('capacity')
                blob = b'{' if typ is dict else b'['
                frames = [('members', path, 0)]
            elif typ is str:
                if len(value) + self.bytes + 2 > self.unit_bytes:
                    raise _Stop('capacity')
                blob, frames = b'"', [('string', path, 0)]
            elif value is None or typ in (bool, int, float):
                if typ is int and value.bit_length() > 128:
                    raise _Stop('capacity')
                if typ is float and not math.isfinite(value):
                    raise _Stop('invalid')
                blob = json.dumps(value, allow_nan=False).encode('ascii')
            else:
                raise _Stop('invalid')
        elif kind == 'string':
            if typ is not str:
                raise _Stop('invalid')
            if pos == len(value):
                blob = b'"'
            else:
                # <=1023 codepoints => each intermediate JSON string <=6140
                # encoded bytes including quotes. No whole-source str encoder.
                count = min(1023, len(value) - pos)
                if self._sb + 6 * count > self.budget.limits['slice_bytes']:
                    if self._sb:
                        raise _Yield
                    count = min(count, self.budget.limits['slice_bytes'] // 6)
                    if not count:
                        raise _Stop('capacity')
                blob = json.dumps(value[pos:pos + count], ensure_ascii=False)[1:-1].encode('utf-8')
                frames = [('string', path, pos + count)]
        else:
            if typ not in (dict, list, tuple):
                raise _Stop('invalid')
            if pos == len(value):
                blob = b'}' if typ is dict else b']'
            else:
                if typ is dict:
                    self._keys(value, path)
                    self._visit(pos + 1)
                    iterator = iter(value)
                    for _ in range(pos + 1):
                        key = next(iterator)
                    key = _key(key)
                    nodes = 1  # emitted JSON member name
                    blob = json.dumps(key, ensure_ascii=False).encode('utf-8') + b':'
                else:
                    self._visit()
                    key, blob = pos, b''
                if pos:
                    blob = b',' + blob
                frames = [('members', path, pos + 1), ('value', path + (key,), 0)]
        if self.nodes + nodes > self.budget.limits['nodes']:
            raise _Stop('capacity')
        self._emit(blob)
        self.nodes += nodes
        self._frames.pop()
        self._frames.extend(frames)
        self._progress += 1

    def _work(self):
        steps = 0
        while self._frames:
            self.budget.check()
            if steps and (steps >= self.budget.limits['slice_steps'] or self.budget.now() - self._start >= .002):
                break
            self._step()
            steps += 1
        return 'more' if self._frames else 'done'

    def _run(self, action):
        if self.budget._running is not None:
            self.status = 'invalid'
            self._clear()
            return None
        self._sv = self._sb = 0
        progress = self._progress
        acquired_config = acquired_state = acquired_publication = False
        result = None
        hold = None
        entered = False
        self.budget._running = self
        try:
            try:
                wait = time.monotonic()
                if self.budget.ledger is not None:
                    self.budget.ledger.enter(self)
                    entered = True
                self.budget.check()
                self._reserve(len(self._frames) + 2)
                # Resolve lock identities before acquisition; mandatory unwind
                # must not allocate another state_lock() helper frame.
                config = self.owners.lock
                state = state_lock()
                publication = self.owners.model._condition
                acquired_config = config.acquire(timeout=min(.02, max(0, self.budget.deadline - self.budget.now())))
                if not acquired_config:
                    raise _Stop('lock_busy')
                acquired_state = state.acquire(blocking=False)
                if not acquired_state:
                    raise _Stop('lock_busy')
                acquired_publication = publication.acquire(blocking=False)
                if not acquired_publication:
                    raise _Stop('lock_busy')
                self.budget.check()
                hold = time.monotonic()
                self.max_wait_seconds = max(self.max_wait_seconds, hold - wait)
                self._start = self.budget.now()
                self._authority()
                result = action()
                self.budget.check()
            except _Yield:
                # Only new validated keys, a root cursor/certificate, or
                # committed output/frame transitions count as progress.
                if self._progress == progress:
                    self.status = 'capacity'
            except (_Stop, Reject) as exc:
                self.status = exc.args[0]
                exc.__traceback__ = exc.__context__ = exc.__cause__ = None
            except (ValueError, TypeError, UnicodeError, KeyError, IndexError, RuntimeError):
                self.status = 'invalid'
            except MemoryError as exc:
                self.status = 'capacity'
                exc.__traceback__ = exc.__context__ = exc.__cause__ = None
            finally:
                try:
                    self._checked.clear()
                    if hold is not None:
                        self.max_slice_seconds = max(self.max_slice_seconds, time.monotonic() - hold)
                    self.slices += 1
                    self.max_slice_visits = max(self.max_slice_visits, self._sv)
                    self.max_slice_bytes = max(self.max_slice_bytes, self._sb)
                except MemoryError as exc:
                    self.status = 'capacity'
                    exc.__traceback__ = exc.__context__ = exc.__cause__ = None
                finally:
                    # Diagnostics cannot bypass release of any acquired lock.
                    if acquired_publication:
                        publication.release()
                    if acquired_state:
                        state.release()
                    if acquired_config:
                        config.release()
                    if self.budget._running is self:
                        self.budget._running = None
            if self.status not in ('more', 'done'):
                result = None
                self._clear()
            return result
        finally:
            # Also covers cleanup/helper entry failure for a nested cursor,
            # whose active identity differs from the enclosing controller.
            if entered:
                with self.budget.ledger._lock:
                    if self.budget.ledger._active is self:
                        self.budget.ledger._active = None

    def _bootstrap_root(self):
        root = getattr(self.owners, self.root_name)
        if type(root) is not dict:
            raise _Stop('invalid')
        if (len(root) > self.budget.limits['dict_members']
                or 2 * len(root) + 1 > self.budget.limits['slice_visits'] - self._sv):
            self._root_cursor = RootCursor(self.owners, self.root_name, budget=self.budget)
            if self._root_cursor.status != 'more':
                raise _Stop(self._root_cursor.status)
            self._progress += 1
            return
        # Small roots can be validated in this same critical section, retaining
        # the original callback-poison boundary without forcing a metadata-only
        # preliminary slice. Roots exceeding the remaining headroom use the
        # same RootCursor as large roots. Descriptors follow actual validation.
        if self.budget.descriptors + len(root) > self.budget.limits['descriptors']:
            raise _Stop('capacity')
        self._keys(root)
        self.budget.descriptors += len(root)
        self.budget._validated_roots.add(self.root_name)
        self._progress += 1
        if self.projection == 'prepared_meta':
            self._resolve(self.path)  # borrowed selected values die before unlock

    @_shared_call
    def slice(self):
        if self.status == 'more':
            if self.root_name != 'config' and self.root_name not in self.budget._validated_roots:
                if self._root_cursor is None:
                    self._run(self._bootstrap_root)
                    return self.status
                cursor = self._root_cursor
                before = cursor.visits
                cursor._run(cursor._validate_batch)
                self.visits += cursor.visits - before
                self.slices += 1
                self.max_slice_visits = max(self.max_slice_visits, cursor._sv)
                self.max_slice_seconds = max(self.max_slice_seconds, cursor.max_slice_seconds)
                if cursor.status not in ('more', 'done'):
                    self.status = cursor.status
                    self._clear()
                elif cursor.status == 'done':
                    cursor._clear()
                    self._root_cursor = None
                return self.status
            result = self._run(self._work)
            if result is not None:
                self.status = result
        return self.status

    @_shared_call
    def seal(self):
        if self.status == 'done':
            if self._run(lambda: True):
                self._sealed = True
        return self.status

    @_shared_call
    def take(self):
        if self.status != 'done' or not self._sealed:
            return None
        result = self._run(lambda: bytes(self._buffer))
        if result is not None:
            self.status = 'taken'
            self._clear()
        return result

    def _clear(self):
        if self.budget.ledger is not None and self.budget._running is self:
            self._retiring = True
            return
        if self._root_cursor is not None:
            self._root_cursor._clear()
            self._root_cursor = None
        if self._frames:
            self._frames.clear()
        if self._buffer:
            self._buffer.clear()
        if self._validated_paths:
            self._validated_paths.clear()
        self.path, self.skip_fields = (), frozenset()
        self._sealed = False
        if self.budget.ledger is not None:
            self.owners = None
            self._checked = ()
            self._retiring = False
        self.budget.workspace -= self._workspace
        self._workspace = 0
        if self.budget._unit is self:
            self.budget._unit = None
        if self._lease is not None:
            self._lease.close()
            self._lease = None

    @_shared_call
    def discard(self):
        if self.status in ('more', 'done'):
            self.status = 'invalid' if self.budget.ledger is None else 'stopped'
        self._clear()
        return self.status

    def counters(self):
        return dict(status=self.status, visits=self.visits, nodes=self.nodes, bytes=self.bytes,
                    slices=self.slices, max_slice_visits=self.max_slice_visits,
                    max_slice_bytes=self.max_slice_bytes, max_depth=self.max_depth,
                    max_slice_seconds=self.max_slice_seconds, max_wait_seconds=self.max_wait_seconds,
                    workspace=self._workspace, peak_workspace=self.peak_workspace)


class RootCursor(Capture):
    """A bounded iterator over a stable application root, never a nested graph.

    Exhaustion certifies callback-free root hashing for this attempt. Capture
    uses the same cursor for sliced validation, without keeping a root keylist.
    Public next_key returns at most one owned key, including the final key when
    status becomes done. Constructors do not traverse source or acquire locks.
    """

    def __init__(self, owners, root_name, *, budget):
        if type(owners) is not CaptureOwners or type(budget) is not CaptureBudget:
            raise TypeError('capture owners/budget required')
        if type(root_name) is not str or root_name not in ('current', 'history'):
            raise ValueError('only stable application roots may be iterated')
        self.owners, self.root_name, self.budget = owners, root_name, budget
        self.status, self._sealed = 'more', False
        self._lease = None
        self._iterator = self._root_cursor = None
        self._cancelled = self._retiring = False
        self._offset = 0
        self._frames = self._buffer = self._checked = self._validated_paths = ()
        self._progress = 0
        self.unit_bytes = 0
        self.visits = self.nodes = self.bytes = self.slices = 0
        self.max_slice_visits = self.max_slice_bytes = self.max_depth = 0
        self.max_slice_seconds = self.max_wait_seconds = self.peak_workspace = 0
        self._sv = self._sb = self._workspace = 0
        try:
            self._reserve(0)
            self._frames, self._buffer, self._checked = [], bytearray(), set()
            self._validated_paths = {}
        except (_Stop, Reject, MemoryError):
            self.status = 'capacity'
            self._clear()

    def slice(self):
        return self.status

    def seal(self):
        return self.status

    def take(self):
        return None

    def _next(self):
        root = getattr(self.owners, self.root_name)
        if type(root) is not dict:
            raise _Stop('invalid')
        if self._offset == len(root):
            self.status = 'done'
            self.budget._validated_roots.add(self.root_name)
            self._clear()
            return None
        if self.budget.descriptors >= self.budget.limits['descriptors']:
            raise _Stop('capacity')
        self._visit(2)  # iterator advance and admitted owned root key
        if self._iterator is None:
            self._iterator = iter(root)
        key = _key(next(self._iterator))
        self.budget.descriptors += 1
        self._offset += 1
        self._progress += 1
        if self._offset == len(root):
            self.status = 'done'
            self.budget._validated_roots.add(self.root_name)
            self._clear()
        return key

    def _validate_batch(self):
        steps = 0
        while self.status == 'more':
            self.budget.check()
            if steps and (steps >= self.budget.limits['slice_steps'] or self.budget.now() - self._start >= .002):
                break
            self._next()
            steps += 1

    @_shared_call
    def next_key(self):
        if self.status != 'more':
            return None
        return self._run(self._next)

    def _clear(self):
        self._iterator = None
        super()._clear()

    close = Capture.discard
