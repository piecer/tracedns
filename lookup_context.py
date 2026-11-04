"""Worker-local lookup authority shared by collectors and native transports."""
from contextlib import contextmanager
from contextvars import ContextVar


_lookup_context = ContextVar('lookup_context', default=None)


def owned_lookup():
    return _lookup_context.get() is not None


@contextmanager
def lookup_scope(cancelled, remaining):
    token = _lookup_context.set((cancelled, remaining))
    try:
        yield
    finally:
        _lookup_context.reset(token)


def checkpoint():
    context = _lookup_context.get()
    if context is not None and context[0]():
        raise TimeoutError('lookup_cancelled')
    if context is not None and context[1]() <= 0:
        raise TimeoutError('lookup_deadline')


def transport_timeout(default):
    checkpoint()
    context = _lookup_context.get()
    timeout = min(default, context[1]()) if context is not None else default
    if context is not None and timeout <= 0:
        raise TimeoutError('lookup_deadline')
    return timeout
