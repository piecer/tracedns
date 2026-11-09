"""Real loopback DNS transport; only the resolver's destination port is replaced."""
import contextlib
import socket
import struct
import threading
import time

import dns.flags
import dns.message
import dns.rcode
import dns.resolver
import dns.rrset
import pytest

from dns_query import query_dns


def _chain_response(query, hops=256):
    """Small bounded reproducer: an A owner traverses pointers in opaque NULL data."""
    question = query.to_wire()[12:]
    packet = bytearray(struct.pack('!6H', query.id, 0x8180, 1, 2, 0, 0) + question)
    packet.extend(b'\xc0\x0c' + struct.pack('!HHIH', 10, 1, 60, hops * 2))
    target = 12
    for _ in range(hops):
        offset = len(packet)
        packet.extend(struct.pack('!H', 0xc000 | target))
        target = offset
    packet.extend(struct.pack('!H', 0xc000 | target))
    packet.extend(struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton('192.0.2.42'))
    return bytes(packet)


@contextlib.contextmanager
def _dns_fixture(monkeypatch, mode):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('127.0.0.1', 0))
    port = udp.getsockname()[1]
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(('127.0.0.1', port))
    tcp.listen(2)
    udp.settimeout(0.05)
    tcp.settimeout(0.05)
    stop = threading.Event()
    seen = []
    errors = []

    def response(wire, transport):
        query = dns.message.from_wire(wire)
        seen.append(transport)
        if mode == 'silent':
            return None
        if mode == 'chain':
            return _chain_response(query)
        if mode == 'malformed':
            return struct.pack('!6H', query.id, 0x8180, 1, 1, 0, 0) + b'\xc0\x0c'
        reply = dns.message.make_response(query)
        if mode == 'truncated' and transport == 'udp':
            reply.flags |= dns.flags.TC
        elif mode == 'nxdomain':
            reply.set_rcode(dns.rcode.NXDOMAIN)
        elif mode != 'nodata':
            kind, data = ('TXT', '"hello" " world"') if mode == 'txt' else ('A', '192.0.2.42')
            reply.answer.append(dns.rrset.from_text(query.question[0].name, 60, 'IN', kind, data))
        return reply.to_wire()

    def receive_exact(connection, count):
        value = b''
        while len(value) < count:
            chunk = connection.recv(count - len(value))
            if not chunk:
                raise EOFError('short DNS TCP query')
            value += chunk
        return value

    def serve(sock, transport):
        try:
            while not stop.is_set():
                try:
                    if transport == 'udp':
                        wire, peer = sock.recvfrom(65535)
                        answer = response(wire, transport)
                        if answer is not None:
                            sock.sendto(answer, peer)
                    else:
                        connection, _ = sock.accept()
                        with connection:
                            connection.settimeout(1)
                            count, = struct.unpack('!H', receive_exact(connection, 2))
                            answer = response(receive_exact(connection, count), transport)
                            if answer is not None:
                                connection.sendall(struct.pack('!H', len(answer)) + answer)
                except socket.timeout:
                    continue
        except Exception as exc:
            errors.append(exc)

    original = dns.resolver.Resolver

    def local_resolver(*args, **kwargs):
        resolver = original(*args, **kwargs)
        resolver.port = port
        return resolver

    monkeypatch.setattr(dns.resolver, 'Resolver', local_resolver)
    threads = [threading.Thread(target=serve, args=(sock, transport))
               for sock, transport in ((udp, 'udp'), (tcp, 'tcp'))]
    for thread in threads:
        thread.start()
    try:
        yield seen
    finally:
        stop.set()
        for thread in threads:
            thread.join(2)
        udp.close()
        tcp.close()
        assert not any(thread.is_alive() for thread in threads)
        assert errors == []


def test_dns_rejects_excessive_compression_chain(monkeypatch):
    with _dns_fixture(monkeypatch, 'chain') as seen:
        started = time.monotonic()
        result = query_dns('127.0.0.1', 'fixture.test', timeout=0.2, with_meta=True)
        elapsed = time.monotonic() - started
        assert seen
        assert result == {'values': [], 'status': 'error'}
        # Resolver retry scheduling has overhead beyond its 0.2s lifetime.
        assert elapsed < 0.8


@pytest.mark.parametrize(('mode', 'rtype', 'expected'), [
    ('a', 'A', {'values': ['192.0.2.42'], 'status': 'ok'}),
    ('txt', 'TXT', {'values': ['hello world'], 'status': 'ok'}),
    ('nxdomain', 'A', {'values': [], 'status': 'nxdomain'}),
    ('nodata', 'A', {'values': [], 'status': 'nodata'}),
    ('truncated', 'A', {'values': ['192.0.2.42'], 'status': 'ok'}),
    ('malformed', 'A', {'values': [], 'status': 'error'}),
    ('silent', 'A', {'values': [], 'status': 'error'}),
])
def test_dns_loopback_transport_contract(monkeypatch, mode, rtype, expected):
    with _dns_fixture(monkeypatch, mode) as seen:
        started = time.monotonic()
        result = query_dns('127.0.0.1', 'fixture.test', rtype, timeout=0.2, with_meta=True)
        elapsed = time.monotonic() - started
        assert result == expected
        assert elapsed < 0.8
        assert seen == (['udp', 'tcp'] if mode == 'truncated' else ['udp'])
