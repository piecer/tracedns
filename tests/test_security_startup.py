"""Startup never opens an anonymous service; incomplete intents remain visible."""
import pytest
from dns_monitor import build_arg_parser
from security.store import SecurityStore
from security.startup import open_security


def test_startup_requires_admin_and_safe_transport(tmp_path):
    args = build_arg_parser().parse_args(['--security-db', str(tmp_path / 'private' / 'auth.db'), '--insecure-http'])
    with pytest.raises(ValueError):
        open_security(args)
    store = SecurityStore(args.security_db, create=True)
    with pytest.raises(ValueError):
        open_security(args)
    user = store.bootstrap('root', 'test-password-123')
    store.audit(user, 'post:/config', outcome='started', request_id='interrupted')
    opened = open_security(args)
    assert opened.audit_list(outcome='unknown')['total'] == 1
    assert opened.reconcile_intents() == 0
    args.http_host = '0.0.0.0'
    with pytest.raises(ValueError):
        open_security(args)


@pytest.mark.parametrize('args', [
    ['--security-db', '/tmp/a', '--insecure-http', '--http-host', '0.0.0.0'],
    ['--security-db', '/tmp/a', '--insecure-http', '--audit-retention-days', '0'],
    ['--security-db', '/tmp/a', '--insecure-http', '--session-idle-minutes', '0'],
])
def test_startup_rejects_unsafe_options(args):
    with pytest.raises(ValueError):
        open_security(build_arg_parser().parse_args(args))


def test_housekeeping_logs_and_continues_after_retention_failure(monkeypatch):
    from security import startup
    calls = []
    class Event:
        def wait(self, _seconds):
            calls.append('wait')
            return len(calls) > 1
        def set(self):
            calls.append('stop')
    class Store:
        def prune_audit(self):
            calls.append('prune')
            raise OSError('full')
    monkeypatch.setattr(startup, '_new_stop_event', Event)
    stop = startup.start_housekeeping(Store())
    stop_thread = getattr(stop, 'set')
    import time
    for _ in range(100):
        if 'prune' in calls: break
        time.sleep(.001)
    stop_thread()
    assert calls[:2] == ['wait', 'prune']


def test_existing_public_directory_is_not_chmodded(tmp_path):
    public = tmp_path / 'public'
    public.mkdir(mode=0o755)
    with pytest.raises(Exception):
        SecurityStore(public / 'auth.db', create=True)
    assert public.stat().st_mode & 0o777 == 0o755


def test_explicit_flag_allows_insecure_remote_bind(tmp_path):
    db_path = tmp_path / 'private' / 'auth.sqlite'
    store = SecurityStore(db_path, create=True)
    store.bootstrap('root', 'test-password-123')
    args = build_arg_parser().parse_args([
        '--security-db', str(db_path), '--insecure-http',
        '--http-host', '10.0.0.2', '--allow-insecure-remote-http',
        '--public-origin', 'http://10.0.0.2:8000',
    ])
    assert open_security(args) is not None


def test_remote_http_flag_requires_insecure_mode(tmp_path):
    args = build_arg_parser().parse_args([
        '--security-db', str(tmp_path / 'auth.sqlite'),
        '--allow-insecure-remote-http',
    ])
    with pytest.raises(ValueError, match='requires --insecure-http'):
        open_security(args)


def test_remote_http_flag_requires_explicit_http_origin(tmp_path):
    db_path = tmp_path / 'private' / 'auth.sqlite'
    store = SecurityStore(db_path, create=True)
    store.bootstrap('root', 'test-password-123')
    args = build_arg_parser().parse_args([
        '--security-db', str(db_path), '--insecure-http',
        '--http-host', '10.0.0.2', '--allow-insecure-remote-http',
    ])
    with pytest.raises(ValueError, match='requires an http --public-origin'):
        open_security(args)


def test_remote_transport_still_needs_the_explicit_override():
    from types import SimpleNamespace
    from security.http import HttpSecurity
    from security.store import SecurityError
    handler = SimpleNamespace(client_address=('10.0.0.1', 1234),
                              server=SimpleNamespace(server_port=8000),
                              headers={'Host': '127.0.0.1:8000'})
    with pytest.raises(SecurityError):
        HttpSecurity(None, insecure=True).transport(handler)
    HttpSecurity(None, insecure=True, allow_insecure_remote_http=True).transport(handler)