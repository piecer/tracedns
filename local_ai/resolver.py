"""Service-lifetime single-slot resolver; caller expiry never cancels libc.

No queue or replacement of retained workers. Threads are created only on
resolve; the slot remains owned until Thread.is_alive() is false, including
post-lookup cleanup. A stuck libc call is daemonized but remains observable and
makes close incomplete. Only host/port cross into the lookup worker.
"""

import ipaddress
import socket
import threading
import time

from local_ai.provider import ProviderError, _Budget
from local_ai.provider_settings import _dns_name, _public_literal


def _snapshot(rows, port):
    """Immutable getaddrinfo 5-tuples, with canonical name discarded.

    Each row is (AF_INET|AF_INET6, SOCK_STREAM, IPPROTO_TCP, '', sockaddr).
    sockaddr is (canonical_ip, port), or (canonical_ip, port, 0, 0).
    Reject the raw answer count before traversal; never truncate/deduplicate
    away a blocked answer. This bounds our retained data, not libc allocation.
    """
    if type(rows) not in (list, tuple) or not 1 <= len(rows) <= 8:
        raise ProviderError("provider_failed")
    output = []
    for row in rows:
        if type(row) is not tuple or len(row) != 5:
            raise ProviderError("provider_failed")
        family, kind, protocol, canonical, sockaddr = row
        if (
            type(family) not in (int, socket.AddressFamily)
            or family not in (socket.AF_INET, socket.AF_INET6)
            or type(kind) not in (int, socket.SocketKind)
            or kind != socket.SOCK_STREAM
            or type(protocol) is not int
            or protocol != socket.IPPROTO_TCP
            or type(canonical) is not str
            or len(canonical) > 253
            or type(sockaddr) is not tuple
            or len(sockaddr) != (2 if family == socket.AF_INET else 4)
        ):
            raise ProviderError("provider_failed")
        ip, service = sockaddr[:2]
        if (
            type(ip) is not str
            or len(ip) > 45
            or "%" in ip
            or type(service) is not int
            or service != port
            or any(type(number) is not int or number != 0 for number in sockaddr[2:])
        ):
            raise ProviderError("provider_failed")
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            raise ProviderError("provider_failed") from None
        if str(address) != ip or (address.version == 4) != (family == socket.AF_INET) or not _public_literal(address):
            raise ProviderError("provider_failed")
        output.append((family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", tuple(sockaddr)))
    return tuple(output)


def _lookup(host, port):
    return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)


class ResolverOwner:
    def __init__(self, *, clock=time.monotonic, lookup=None):
        self._clock = clock
        self._lookup = _lookup if lookup is None else lookup
        self._lock = threading.Lock()
        self._thread = None
        self._closed = False

    def busy(self):
        return self.retained_workers() != 0

    def retained_workers(self):
        with self._lock:
            return int(self._thread is not None and self._thread.is_alive())

    def resolve(self, host, port, deadline):
        if (
            type(host) is not str
            or len(host) > 253
            or not host.isascii()
            or not _dns_name(host)
            or type(port) is not int
            or not 1 <= port <= 65535
        ):
            raise ProviderError("invalid_request")
        budget = _Budget(self._clock, deadline)
        result = []
        abandoned = threading.Event()

        def work():
            try:
                snapshot = _snapshot(self._lookup(host, port), port)
                if not abandoned.is_set():
                    result.append(snapshot)
            except Exception:
                # No native error/address/hostname is retained or reflected.
                pass

        with self._lock:
            if self._closed or (self._thread is not None and self._thread.is_alive()):
                raise ProviderError("provider_failed")
            budget.remaining()
            thread = threading.Thread(target=work, name="local-ai-dns", daemon=True)
            self._thread = thread
            try:
                thread.start()
            except RuntimeError:
                self._thread = None
                raise ProviderError("provider_failed") from None
        try:
            thread.join(budget.remaining())
            budget.remaining()
            with self._lock:
                if self._closed or thread.is_alive() or not result:
                    raise ProviderError("provider_failed")
            return result[0]
        finally:
            abandoned.set()
            result.clear()

    def close(self, deadline):
        with self._lock:
            self._closed = True
            thread = self._thread
        if thread is None or not thread.is_alive():
            return True
        try:
            budget = _Budget(self._clock, deadline)
            thread.join(budget.remaining())
        except ProviderError as error:
            if error.code != "deadline_exceeded":
                raise
        return not thread.is_alive()
