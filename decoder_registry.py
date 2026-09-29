"""Synchronized TXT/A mappings and lock-free, explicitly pinned scan views.

Lock order: configuration -> registry. Never execute callables under either lock.
Context variables do not propagate into executor threads: enter use_registry(view)
inside EACH worker, using a view captured alongside its configuration and lease.
"""
from collections.abc import Callable, Mapping, MutableMapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from threading import RLock
from types import MappingProxyType

lock = RLock()
_pinned = ContextVar('decoder_registry_view', default=None)


@dataclass(frozen=True)
class RegistryView:
    txt: Mapping[str, Callable]
    a: Mapping[str, Callable]


class DecoderMap(MutableMapping):
    """Stable imported identity; all iteration uses a private coherent snapshot."""

    def __init__(self, kind):
        self.kind = kind
        self._data = {}

    def _snapshot(self):
        pinned = _pinned.get()
        if pinned is not None:
            return getattr(pinned, self.kind)
        with lock:
            return dict(self._data)

    def __getitem__(self, key):
        return self._snapshot()[key]

    def __iter__(self):
        return iter(self._snapshot())

    def __len__(self):
        return len(self._snapshot())

    def items(self):
        return self._snapshot().items()

    def keys(self):
        return self._snapshot().keys()

    def values(self):
        return self._snapshot().values()

    def __setitem__(self, key, value):
        with lock:
            self._data[key] = value

    def __delitem__(self, key):
        with lock:
            del self._data[key]


TXT_METHODS = DecoderMap('txt')
A_METHODS = DecoderMap('a')


def snapshot_registry():
    """Capture LIVE callables. Caller holds config lock when pairing config/leases."""
    # Ensure builtin registration is complete before capture.
    import txt_decoder  # noqa: F401
    import a_decoder  # noqa: F401
    with lock:
        return RegistryView(MappingProxyType(dict(TXT_METHODS._data)),
                            MappingProxyType(dict(A_METHODS._data)))


def publish(view):
    """Publish two prepared maps together without replacing imported aliases."""
    with lock:
        TXT_METHODS._data = dict(view.txt)
        A_METHODS._data = dict(view.a)


@contextmanager
def use_registry(view):
    """Select a captured view in this worker, holding no lock during decoding."""
    token = _pinned.set(view)
    try:
        yield view
    finally:
        _pinned.reset(token)
