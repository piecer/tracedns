"""Secret-free JSON checks, not a source/session publication capability.

Callers supply a small, newly owned projection and relinquish mutation rights
until this call returns. Never pass raw history, results or config as payload.
"""
from contextlib import ExitStack
import json
import math
import threading
import time

from http_api.read_model import BackgroundReadModel
from security.derived_redaction import Builder, Encoding, OwnedPayload, Projector, RedactionBudget

_LOCK = type(threading.Lock())
_RLOCK = type(threading.RLock())


class PrivacyError(ValueError):
    """Fixed public codes only; no source values or dependency exceptions."""

    def __init__(self, code='privacy_failed'):
        self.code = 'sensitive_input' if type(code) is str and code == 'sensitive_input' else 'privacy_failed'
        super().__init__(self.code)


def _register(stack, owner, *, operation=False):
    """A failed cleanup registration must not orphan its newly minted owner."""
    try:
        stack.callback(owner.discard if operation else owner.close)
    except BaseException:
        if operation:
            owner.discard()
        else:
            owner.close()
        raise


def _take(operation, stack, *, builder=False):
    _register(stack, operation, operation=True)
    for _ in range(16384):
        operation.budget.check()
        if operation.status == 'more':
            operation.slice()
        elif builder and operation.status == 'captured':
            operation.seal_slice()
        else:
            break
    if operation.status != 'done':
        raise PrivacyError()
    handle = operation.take()
    if handle is None:
        raise PrivacyError()
    _register(stack, handle)
    return handle


def _preflight(payload, budget, max_bytes):
    """Validate before copying/sorting; encode only bounded scalar chunks."""
    nodes = size = 0
    active = set()

    def add(amount):
        nonlocal size
        size += amount
        if size > max_bytes:
            raise PrivacyError()

    def walk(value, depth):
        nonlocal nodes
        budget.visit()
        nodes += 1
        if nodes > 4096 or depth > 32:
            raise PrivacyError()
        kind = type(value)
        if kind is str:
            if len(value) > max_bytes - size - 2:
                raise PrivacyError()
            add(2)
            for offset in range(0, len(value), 1024):
                budget.visit()
                add(len(json.dumps(value[offset:offset + 1024], ensure_ascii=False)[1:-1].encode('utf8')))
        elif kind is dict or kind is list:
            if id(value) in active:
                raise PrivacyError()
            children = len(value) * (2 if kind is dict else 1)
            if children > 4096 - nodes:
                raise PrivacyError()
            add(2 + max(0, len(value) - 1) + (len(value) if kind is dict else 0))
            active.add(id(value))
            if kind is dict:
                for key, child in value.items():
                    if type(key) is not str:
                        raise PrivacyError()
                    walk(key, depth + 1)
                    walk(child, depth + 1)
            else:
                for child in value:
                    walk(child, depth + 1)
            active.remove(id(value))
        elif kind is int or kind is float or kind is bool or value is None:
            if kind is int and value.bit_length() > 128:
                raise PrivacyError()
            if kind is float and not math.isfinite(value):
                raise PrivacyError()
            add(len(json.dumps(value, allow_nan=False)))
        else:
            raise PrivacyError()

    walk(payload, 0)


def _ordered(value, budget):
    budget.visit()
    if type(value) is dict:
        return {key: _ordered(value[key], budget) for key in sorted(value)}
    if type(value) is list:
        return [_ordered(child, budget) for child in value]
    return value


def _check(payload, config, config_lock, read_model, deadline, max_bytes):
    if type(max_bytes) is not int or not 1 <= max_bytes <= 32768:
        raise PrivacyError()
    if type(deadline) is not int and type(deadline) is not float:
        raise PrivacyError()
    if not math.isfinite(deadline):
        raise PrivacyError()
    if type(config) is not dict or type(read_model) is not BackgroundReadModel:
        raise PrivacyError()
    if type(config_lock) is not _LOCK and type(config_lock) is not _RLOCK:
        raise PrivacyError()
    with ExitStack() as stack:
        budget = RedactionBudget(deadline=deadline)
        _register(stack, budget)
        # Conservative simultaneous control/sort/copy/chunk/detachment charge.
        # Input is already caller-owned; this is not raw source capture.
        work = budget.reserve(worker=65536 + 512 * min(4096, max_bytes) + 8 * max_bytes,
                              metadata=8192)
        _register(stack, work)
        _preflight(payload, budget, max_bytes)
        canonical = OwnedPayload.admit(_ordered(payload, budget), budget=budget)
        _register(stack, canonical)
        before = _take(Encoding(canonical, budget=budget, output_cap=max_bytes), stack)
        plan = _take(Builder(config, config_lock, read_model, budget=budget), stack, builder=True)
        projected = _take(Projector(plan, canonical, budget=budget, output_cap=max_bytes), stack)
        after = _take(Encoding(projected, budget=budget, output_cap=max_bytes), stack)
        if before.value != after.value:
            raise PrivacyError('sensitive_input')
        result = memoryview(after.value).tobytes()
        # Retire large intermediates before the final bounded authority read.
        canonical.close()
        projected.close()
        before.close()
        after.close()
        # Reuse the real builder's locked key validation and authority checks,
        # not unchecked config lookups or an invented model/service base class.
        # One slice is enough to read authority; no second secret plan is minted.
        fence = Builder(config, config_lock, read_model, budget=budget)
        _register(stack, fence, operation=True)
        if fence.slice() not in ('more', 'captured') or fence.token != plan.value.authority:
            raise PrivacyError()
        budget.check()
    if time.monotonic() >= deadline:
        raise PrivacyError()
    return result


def require_secret_free(payload, config, config_lock, read_model, deadline, *, max_bytes=8192):
    """Return detached compact, sorted-key UTF8 JSON, or fail without repair.

    Accept exact JSON builtins only, at most 4096 nodes (including object keys),
    depth 32, finite numbers and integers of at most 128 bits. ``max_bytes`` is
    an integer from 1 through 32768, measured after JSON escaping and UTF8.
    The shared foundation's discovery/work limits can refuse a check too.

    ``sensitive_input`` means the configured-secret projection changed bytes;
    all other ordinary refusals use ``privacy_failed`` without source details.
    This follows the existing configured-credential substitution policy (short
    secrets match whole strings); it is not a general sensitive-data detector.
    Canonical here means compact sorted-key JSON, not RFC 8785 normalization.

    Config/session/source authority must be revalidated by the calling owner
    before transmission and publication; these bytes grant no such authority.
    Config writers must obey the existing lock and revision/epoch protocol.
    """
    code = None
    try:
        return _check(payload, config, config_lock, read_model, deadline, max_bytes)
    except Exception as exc:
        code = exc.code if type(exc) is PrivacyError else 'privacy_failed'
        exc.__traceback__ = exc.__context__ = exc.__cause__ = None
    finally:
        payload = config = config_lock = read_model = None
    raise PrivacyError(code) from None
