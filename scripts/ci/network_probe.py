"""Fail before tests unless the kernel namespace has loopback only.

No routable destination is probed until the interface census passes. Reserved
addresses are used for negative controls; a namespace with only lo has no path
for these packets. Both TCP and UDP are checked (UDP covers DNS/RPC traffic).
"""
import errno
import socket


def check_network():
    if {name for _, name in socket.if_nameindex()} != {"lo"}:
        raise SystemExit("network guard requires only loopback; refusing tests")
    for family, local, external in (
        (socket.AF_INET, "127.0.0.1", "192.0.2.1"),
        (socket.AF_INET6, "::1", "2001:db8::1"),
    ):
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            with socket.socket(family, kind) as server, socket.socket(family, kind) as client:
                server.settimeout(2)
                client.settimeout(2)
                server.bind((local, 0))
                if kind == socket.SOCK_STREAM:
                    server.listen(1)
                client.connect(server.getsockname())
                client.sendall(b"loopback-control")
                if kind == socket.SOCK_STREAM:
                    connection, _ = server.accept()
                    with connection:
                        connection.settimeout(2)
                        assert connection.recv(64) == b"loopback-control"
                else:
                    assert server.recv(64) == b"loopback-control"
            with socket.socket(family, kind) as blocked:
                blocked.settimeout(2)
                try:
                    blocked.connect((external, 443))
                except OSError as exc:
                    if exc.errno not in (errno.ENETUNREACH, errno.EHOSTUNREACH):
                        raise SystemExit(f"unexpected negative-control failure: {exc}") from exc
                else:
                    raise SystemExit("external negative control connected; refusing tests")
    print("network guard: loopback TCP/UDP IPv4/IPv6 passed; non-loopback blocked", flush=True)


if __name__ == "__main__":
    check_network()
